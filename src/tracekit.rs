//! Offline helpers for the run-loop tracing tools (`debug_trace_*`, `debug_coverage`,
//! `coverage_diff`): a small tolerant ELF import parser (standard `PT_DYNAMIC` and
//! Orbis `PT_SCE_DYNLIBDATA`), PLT-stub and syscall-wrapper byte scanners, an
//! `.eh_frame` FDE enumerator, a syscall name table, the `ps4wb-blocks-v1` /
//! `ps4wb-coverage-v1` formats, a drcov v2 writer and coverage diffs.
//!
//! Nothing here touches the console; the live engine is `debugger::trace`.

use crate::Result;
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};

// ---- ELF / Orbis dynamic structures -----------------------------------------
//
// Standard ELF64 values: System V gABI (PT_DYNAMIC = 2, DT_* tags, Elf64_Rela) and
// the x86-64 psABI (R_X86_64_JUMP_SLOT = 7). Orbis `PT_SCE_DYNLIBDATA` (0x61000000)
// and the `DT_SCE_*` tags, whose values are *offsets into the dynlibdata segment*
// rather than virtual addresses, follow the public PS4 loaders (shadPS4
// `src/core/loader/elf.h`, psdevwiki "ELF/SELF" pages).

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_SCE_DYNLIBDATA: u32 = 0x6100_0000;

const DT_NULL: u64 = 0;
const DT_PLTRELSZ: u64 = 2;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_STRSZ: u64 = 10;
const DT_JMPREL: u64 = 23;
const DT_SCE_JMPREL: u64 = 0x6100_0029;
const DT_SCE_PLTRELSZ: u64 = 0x6100_002d;
const DT_SCE_STRTAB: u64 = 0x6100_0035;
const DT_SCE_STRSZ: u64 = 0x6100_0037;
const DT_SCE_SYMTAB: u64 = 0x6100_0039;
const DT_SCE_SYMTABSZ: u64 = 0x6100_003f;
const R_X86_64_JUMP_SLOT: u32 = 7;

const MAX_DYNAMIC: usize = 1024;
const MAX_RELOCS: usize = 65_536;
const MAX_TABLE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}
fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
fn le64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// ELF64 little-endian program headers, when `bytes` starts with a complete
/// header and program-header table. `None` for anything else.
pub fn program_headers(bytes: &[u8]) -> Option<Vec<Segment>> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return None;
    }
    let phoff = le64(bytes, 32)? as usize;
    let phentsize = le16(bytes, 54)? as usize;
    let phnum = le16(bytes, 56)? as usize;
    if phentsize < 56 || phnum == 0 || phnum > 256 {
        return None;
    }
    let mut result = Vec::with_capacity(phnum);
    for index in 0..phnum {
        let at = phoff.checked_add(index * phentsize)?;
        result.push(Segment {
            p_type: le32(bytes, at)?,
            flags: le32(bytes, at + 4)?,
            offset: le64(bytes, at + 8)?,
            vaddr: le64(bytes, at + 16)?,
            filesz: le64(bytes, at + 32)?,
            memsz: le64(bytes, at + 40)?,
        });
    }
    Some(result)
}

/// Lowest `PT_LOAD` virtual address (the static image base).
pub fn image_base(segments: &[Segment]) -> u64 {
    segments
        .iter()
        .filter(|segment| segment.p_type == PT_LOAD)
        .map(|segment| segment.vaddr)
        .min()
        .unwrap_or(0)
}

/// `(tag, value)` pairs up to `DT_NULL`, bounded.
pub fn dynamic_entries(bytes: &[u8]) -> Vec<(u64, u64)> {
    let mut entries = Vec::new();
    for index in 0..(bytes.len() / 16).min(MAX_DYNAMIC) {
        let (Some(tag), Some(value)) = (le64(bytes, index * 16), le64(bytes, index * 16 + 8)) else {
            break;
        };
        if tag == DT_NULL {
            break;
        }
        entries.push((tag, value));
    }
    entries
}

/// One PLT import: a `R_X86_64_JUMP_SLOT` relocation and its symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    /// Relocation index in the PLT relocation table (matches a lazy stub's `push N`).
    pub index: usize,
    /// GOT slot address relative to the static image base.
    pub got_rva: u64,
    /// Raw symbol name (Orbis: `NID#lib#module`).
    pub symbol: String,
    pub nid: Option<String>,
    pub library: Option<String>,
    /// Demangled name: NID lookup for Orbis names, else the raw symbol.
    pub name: Option<String>,
}

impl ImportEntry {
    pub fn display(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.symbol.clone())
    }
}

/// Which table space a dynamic-tag value lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableSpace {
    /// Orbis: offset into the `PT_SCE_DYNLIBDATA` segment.
    DynlibData,
    /// Standard ELF: virtual address.
    Vaddr,
}

/// Decode PLT imports from a dynamic table. `fetch(space, value, length)` returns
/// the bytes of a table; any missing table yields an empty list plus a note.
/// `static_base` converts `r_offset` (a static vaddr) into an RVA.
pub fn imports_from_dynamic(
    entries: &[(u64, u64)],
    static_base: u64,
    mut fetch: impl FnMut(TableSpace, u64, usize) -> Option<Vec<u8>>,
) -> (Vec<ImportEntry>, Vec<String>) {
    let mut notes = Vec::new();
    let get = |tag: u64| entries.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v);
    let orbis = get(DT_SCE_JMPREL).is_some();
    let (space, jmprel, pltrelsz, strtab, strsz, symtab, symtabsz) = if orbis {
        (
            TableSpace::DynlibData,
            get(DT_SCE_JMPREL),
            get(DT_SCE_PLTRELSZ),
            get(DT_SCE_STRTAB),
            get(DT_SCE_STRSZ),
            get(DT_SCE_SYMTAB),
            get(DT_SCE_SYMTABSZ),
        )
    } else {
        (
            TableSpace::Vaddr,
            get(DT_JMPREL),
            get(DT_PLTRELSZ),
            get(DT_STRTAB),
            get(DT_STRSZ),
            get(DT_SYMTAB),
            None,
        )
    };
    let (Some(jmprel), Some(pltrelsz), Some(strtab), Some(symtab)) = (jmprel, pltrelsz, strtab, symtab) else {
        notes.push(format!(
            "{} dynamic table lacks JMPREL/PLTRELSZ/STRTAB/SYMTAB",
            if orbis { "Orbis" } else { "Standard" }
        ));
        return (Vec::new(), notes);
    };
    let count = (pltrelsz as usize / 24).min(MAX_RELOCS);
    let Some(relocs) = fetch(space, jmprel, count * 24) else {
        notes.push("PLT relocation table not readable".into());
        return (Vec::new(), notes);
    };
    let strsz = strsz.unwrap_or(65_536).min(MAX_TABLE_BYTES as u64) as usize;
    let strings = fetch(space, strtab, strsz).unwrap_or_default();
    if strings.is_empty() {
        notes.push("Dynamic string table not readable; names unavailable".into());
    }
    let mut parsed = Vec::new();
    let mut max_symbol = 0usize;
    for index in 0..count {
        let at = index * 24;
        let (Some(offset), Some(info)) = (le64(&relocs, at), le64(&relocs, at + 8)) else {
            break;
        };
        if info as u32 != R_X86_64_JUMP_SLOT {
            continue;
        }
        let symbol = (info >> 32) as usize;
        max_symbol = max_symbol.max(symbol);
        parsed.push((index, offset, symbol));
    }
    let symbol_bytes = match symtabsz {
        Some(size) => (size as usize).min(MAX_TABLE_BYTES),
        None => ((max_symbol + 1) * 24).min(MAX_TABLE_BYTES),
    };
    let symbols = fetch(space, symtab, symbol_bytes).unwrap_or_default();
    let mut imports = Vec::with_capacity(parsed.len());
    for (index, offset, symbol) in parsed {
        let raw = le32(&symbols, symbol * 24)
            .map(|name| cstr(&strings, name as usize))
            .unwrap_or_default();
        let raw = if raw.is_empty() { format!("import_{index}") } else { raw };
        let orbis_name = crate::nid::split_orbis_symbol(&raw);
        let name = match orbis_name {
            Some(_) => crate::nid::lookup_nid(&raw, None).map(str::to_owned),
            None => Some(raw.clone()),
        };
        imports.push(ImportEntry {
            index,
            got_rva: offset.wrapping_sub(static_base),
            nid: orbis_name.map(|(nid, _, _)| nid.to_owned()),
            library: orbis_name.and_then(|(_, library, _)| library.map(str::to_owned)),
            symbol: raw,
            name,
        });
    }
    (imports, notes)
}

fn cstr(bytes: &[u8], at: usize) -> String {
    bytes
        .get(at..)
        .map(|rest| String::from_utf8_lossy(rest.split(|byte| *byte == 0).next().unwrap_or_default()).into_owned())
        .unwrap_or_default()
}

/// Parse imports from a complete ELF file (e.g. a decrypted `eboot.bin`): tables
/// are located through file offsets of `PT_DYNAMIC` / `PT_SCE_DYNLIBDATA` / `PT_LOAD`.
/// Returns `(static_base, imports, notes)`.
pub fn imports_from_elf_file(file: &[u8]) -> Result<(u64, Vec<ImportEntry>, Vec<String>)> {
    let segments = program_headers(file).context("Not an ELF64 little-endian file with program headers")?;
    let base = image_base(&segments);
    let slice = |offset: u64, length: u64| -> Option<Vec<u8>> {
        let end = offset.checked_add(length)?;
        file.get(offset as usize..(end as usize).min(file.len())).map(<[u8]>::to_vec)
    };
    let dynamic = segments
        .iter()
        .find(|segment| segment.p_type == PT_DYNAMIC)
        .and_then(|segment| slice(segment.offset, segment.filesz))
        .context("ELF has no readable PT_DYNAMIC segment")?;
    let dynlib = segments
        .iter()
        .find(|segment| segment.p_type == PT_SCE_DYNLIBDATA)
        .and_then(|segment| slice(segment.offset, segment.filesz));
    let loads: Vec<Segment> = segments.iter().filter(|s| s.p_type == PT_LOAD).copied().collect();
    let entries = dynamic_entries(&dynamic);
    let (imports, notes) = imports_from_dynamic(&entries, base, |space, value, length| match space {
        TableSpace::DynlibData => {
            let data = dynlib.as_ref()?;
            let start = value as usize;
            data.get(start..start.checked_add(length)?.min(data.len())).map(<[u8]>::to_vec)
        }
        TableSpace::Vaddr => {
            let load = loads.iter().find(|load| load.vaddr <= value && value < load.vaddr + load.filesz)?;
            let offset = load.offset + (value - load.vaddr);
            let available = load.filesz - (value - load.vaddr);
            slice(offset, (length as u64).min(available))
        }
    });
    Ok((base, imports, notes))
}

// ---- byte scanners ----------------------------------------------------------

/// A PLT-style indirect jump `jmp qword ptr [rip+disp32]` (`FF 25 disp32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PltStub {
    pub address: u64,
    pub got: u64,
    /// `push imm32` index of a lazy stub (`FF 25 d32 68 i32 E9 r32`), if present.
    pub lazy_index: Option<u32>,
}

/// Every `FF 25 disp32` in `code` mapped at `address`. Callers keep only stubs
/// whose GOT slot is a known import (or `lazy_index` for unnamed heuristics).
pub fn find_plt_stubs(code: &[u8], address: u64) -> Vec<PltStub> {
    let mut stubs = Vec::new();
    for index in 0..code.len().saturating_sub(5) {
        if code[index] != 0xff || code[index + 1] != 0x25 {
            continue;
        }
        let displacement = i32::from_le_bytes(code[index + 2..index + 6].try_into().unwrap()) as i64;
        let stub = address + index as u64;
        let got = (stub as i64).wrapping_add(6).wrapping_add(displacement) as u64;
        let lazy_index = (code.get(index + 6) == Some(&0x68) && code.get(index + 11) == Some(&0xe9))
            .then(|| le32(code, index + 7))
            .flatten();
        stubs.push(PltStub { address: stub, got, lazy_index });
    }
    stubs
}

/// A `syscall` (`0F 05`) site and the probe address used to trace it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallSite {
    /// Breakpoint address: the `mov rax/eax, imm32` that starts a recognised
    /// wrapper, or the `syscall` instruction itself for unrecognised sites.
    pub probe: u64,
    pub syscall_instruction: u64,
    /// Statically derived number (`mov rax, N` / `mov eax, N`).
    pub number: Option<u64>,
    /// The probe looks like a function entry (16-byte aligned or preceded by
    /// `ret`/`int3`/`nop` padding), so `[rsp]` at the probe is a return address.
    pub entry_like: bool,
    /// `mov r10, rcx` precedes the syscall (arg 4 still lives in `rcx` at the probe).
    pub moves_rcx_to_r10: bool,
}

/// Recognises the wrapper shapes `mov rax, imm32` (`48 C7 C0 i32`) or `mov eax,
/// imm32` (`B8 i32`), optionally followed by `mov r10, rcx` (`49 89 CA`), then
/// `syscall`. With `include_unrecognized`, other `0F 05` byte pairs are returned
/// with `number: None` (they may be false positives inside other instructions).
pub fn find_syscall_sites(code: &[u8], address: u64, include_unrecognized: bool) -> Vec<SyscallSite> {
    let mut sites = Vec::new();
    for index in 0..code.len().saturating_sub(1) {
        if code[index] != 0x0f || code[index + 1] != 0x05 {
            continue;
        }
        let r10 = index >= 3 && code[index - 3..index] == [0x49, 0x89, 0xca];
        let before = if r10 { index - 3 } else { index };
        let mov = if before >= 7 && code[before - 7..before - 4] == [0x48, 0xc7, 0xc0] {
            Some((before - 7, le32(code, before - 4)))
        } else if before >= 5 && code[before - 5] == 0xb8 {
            Some((before - 5, le32(code, before - 4)))
        } else {
            None
        };
        match mov {
            Some((start, Some(number))) => {
                let probe = address + start as u64;
                let previous = start.checked_sub(1).map(|at| code[at]);
                sites.push(SyscallSite {
                    probe,
                    syscall_instruction: address + index as u64,
                    number: Some(number as u64),
                    entry_like: probe.is_multiple_of(16) || matches!(previous, Some(0xc3 | 0xcc | 0x90)),
                    moves_rcx_to_r10: r10,
                });
            }
            _ if include_unrecognized => sites.push(SyscallSite {
                probe: address + index as u64,
                syscall_instruction: address + index as u64,
                number: None,
                entry_like: false,
                moves_rcx_to_r10: r10,
            }),
            _ => {}
        }
    }
    sites
}

/// 16-byte aligned `[endbr64;] push rbp; mov rbp, rsp` prologues (heuristic
/// function entries when no `.eh_frame` is available).
pub fn prologue_entries(code: &[u8], address: u64, limit: usize) -> Vec<u64> {
    let mut entries = Vec::new();
    let mut index = ((16 - (address % 16)) % 16) as usize;
    while index + 4 <= code.len() && entries.len() < limit {
        let window = &code[index..(index + 16).min(code.len())];
        if matches!(window[0], 0x55 | 0xf3) && crate::disasm::has_frame_prologue(window, address + index as u64) {
            entries.push(address + index as u64);
        }
        index += 16;
    }
    entries
}

// ---- .eh_frame FDE enumeration -----------------------------------------------
// Format: LSB "Exception Frame" (`.eh_frame`) / DWARF CFI; pointer encodings
// `DW_EH_PE_*` from the LSB Core specification.

fn uleb(data: &[u8], pos: &mut usize) -> Option<u64> {
    let (mut value, mut shift) = (0u64, 0u32);
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            value |= u64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
}

fn sleb(data: &[u8], pos: &mut usize) -> Option<i64> {
    let (mut value, mut shift) = (0i64, 0u32);
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            value |= i64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= -1i64 << shift;
            }
            return Some(value);
        }
    }
}

/// Read a `DW_EH_PE_*` encoded pointer at `pos` (field address `field_va`).
fn encoded_pointer(data: &[u8], pos: &mut usize, encoding: u8, field_va: u64) -> Option<u64> {
    if encoding == 0xff {
        return Some(0);
    }
    let raw: i128 = match encoding & 0x0f {
        0x00 | 0x04 => {
            let value = le64(data, *pos)?;
            *pos += 8;
            value as i128
        }
        0x01 => uleb(data, pos)? as i128,
        0x02 => {
            let value = le16(data, *pos)?;
            *pos += 2;
            value as i128
        }
        0x03 => {
            let value = le32(data, *pos)?;
            *pos += 4;
            value as i128
        }
        0x09 => sleb(data, pos)? as i128,
        0x0a => {
            let value = le16(data, *pos)? as i16;
            *pos += 2;
            value as i128
        }
        0x0b => {
            let value = le32(data, *pos)? as i32;
            *pos += 4;
            value as i128
        }
        0x0c => {
            let value = le64(data, *pos)? as i64;
            *pos += 8;
            value as i128
        }
        _ => return None,
    };
    let value = match encoding & 0x70 {
        0x00 => raw,
        0x10 => field_va as i128 + raw,
        _ => return None,
    };
    Some(value as u64)
}

/// `(initial_location, address_range)` of every FDE in a raw `.eh_frame` mapped at
/// `section_va`, bounded by `limit`.
pub fn fde_ranges(eh_frame: &[u8], section_va: u64, limit: usize) -> Vec<(u64, u64)> {
    let mut encodings: HashMap<usize, (u8, bool)> = HashMap::new();
    let mut ranges = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= eh_frame.len() && ranges.len() < limit {
        let record = pos;
        let Some(length) = le32(eh_frame, pos) else { break };
        pos += 4;
        if length == 0 {
            break;
        }
        if length == 0xffff_ffff {
            break; // 64-bit DWARF records are not produced for x86-64 .eh_frame
        }
        let length = length as usize;
        if pos + length > eh_frame.len() || length < 4 {
            break;
        }
        let body = &eh_frame[pos..pos + length];
        let id = le32(body, 0).unwrap_or(0);
        if id == 0 {
            if let Some(info) = cie_pointer_encoding(body) {
                encodings.insert(record, info);
            }
        } else if let Some(cie) = pos.checked_sub(id as usize)
            && let Some(&(encoding, _)) = encodings.get(&cie)
        {
            let mut cursor = 4usize;
            let field = section_va + (pos + cursor) as u64;
            if let Some(start) = encoded_pointer(body, &mut cursor, encoding, field)
                && let Some(size) = encoded_pointer(body, &mut cursor, encoding & 0x0f, 0)
                && start != 0
                && size > 0
            {
                ranges.push((start, size));
            }
        }
        pos += length;
    }
    ranges
}

/// FDE pointer encoding (`R` augmentation, default absptr) of a CIE body.
fn cie_pointer_encoding(body: &[u8]) -> Option<(u8, bool)> {
    let mut pos = 4usize;
    let version = *body.get(pos)?;
    pos += 1;
    let augmentation_start = pos;
    while *body.get(pos)? != 0 {
        pos += 1;
    }
    let augmentation = body[augmentation_start..pos].to_vec();
    pos += 1;
    uleb(body, &mut pos)?; // code alignment
    sleb(body, &mut pos)?; // data alignment
    if version == 1 {
        pos += 1;
    } else {
        uleb(body, &mut pos)?;
    }
    let mut encoding = 0u8;
    if augmentation.first() == Some(&b'z') {
        uleb(body, &mut pos)?;
        for character in &augmentation[1..] {
            match character {
                b'R' => {
                    encoding = *body.get(pos)?;
                    pos += 1;
                }
                b'L' => pos += 1,
                b'P' => {
                    let personality = *body.get(pos)?;
                    pos += 1;
                    encoded_pointer(body, &mut pos, personality & 0x7f, 0)?;
                }
                b'S' => {}
                _ => return None,
            }
        }
    }
    Some((encoding, augmentation.first() == Some(&b'z')))
}

// ---- syscall names ------------------------------------------------------------

/// FreeBSD 9.x native syscall numbers (`sys/kern/syscalls.master`, the
/// releng/9.x branch; Orbis OS is FreeBSD 9 derived). Compatibility (`o*`,
/// `freebsd4_*`, ...) and obsolete slots are omitted and print as `sys_<n>`.
/// Orbis may repurpose slots; treat names as a hint, not ground truth.
const FREEBSD9: &[(u64, &str)] = &[
    (1, "exit"), (2, "fork"), (3, "read"), (4, "write"), (5, "open"), (6, "close"), (7, "wait4"),
    (9, "link"), (10, "unlink"), (12, "chdir"), (13, "fchdir"), (14, "mknod"), (15, "chmod"),
    (16, "chown"), (17, "break"), (20, "getpid"), (21, "mount"), (22, "unmount"), (23, "setuid"),
    (24, "getuid"), (25, "geteuid"), (26, "ptrace"), (27, "recvmsg"), (28, "sendmsg"),
    (29, "recvfrom"), (30, "accept"), (31, "getpeername"), (32, "getsockname"), (33, "access"),
    (34, "chflags"), (35, "fchflags"), (36, "sync"), (37, "kill"), (39, "getppid"), (41, "dup"),
    (42, "pipe"), (43, "getegid"), (44, "profil"), (45, "ktrace"), (47, "getgid"), (49, "getlogin"),
    (50, "setlogin"), (51, "acct"), (53, "sigaltstack"), (54, "ioctl"), (55, "reboot"), (56, "revoke"),
    (57, "symlink"), (58, "readlink"), (59, "execve"), (60, "umask"), (61, "chroot"), (65, "msync"),
    (66, "vfork"), (69, "sbrk"), (70, "sstk"), (72, "vadvise"), (73, "munmap"), (74, "mprotect"),
    (75, "madvise"), (78, "mincore"), (79, "getgroups"), (80, "setgroups"), (81, "getpgrp"),
    (82, "setpgid"), (83, "setitimer"), (85, "swapon"), (86, "getitimer"), (89, "getdtablesize"),
    (90, "dup2"), (92, "fcntl"), (93, "select"), (95, "fsync"), (96, "setpriority"), (97, "socket"),
    (98, "connect"), (100, "getpriority"), (104, "bind"), (105, "setsockopt"), (106, "listen"),
    (116, "gettimeofday"), (117, "getrusage"), (118, "getsockopt"), (120, "readv"), (121, "writev"),
    (122, "settimeofday"), (123, "fchown"), (124, "fchmod"), (126, "setreuid"), (127, "setregid"),
    (128, "rename"), (131, "flock"), (132, "mkfifo"), (133, "sendto"), (134, "shutdown"),
    (135, "socketpair"), (136, "mkdir"), (137, "rmdir"), (138, "utimes"), (140, "adjtime"),
    (147, "setsid"), (148, "quotactl"), (154, "nlm_syscall"), (155, "nfssvc"), (160, "lgetfh"),
    (161, "getfh"), (165, "sysarch"), (166, "rtprio"), (169, "semsys"), (170, "msgsys"),
    (171, "shmsys"), (175, "setfib"), (176, "ntp_adjtime"), (181, "setgid"), (182, "setegid"),
    (183, "seteuid"), (188, "stat"), (189, "fstat"), (190, "lstat"), (191, "pathconf"),
    (192, "fpathconf"), (194, "getrlimit"), (195, "setrlimit"), (196, "getdirentries"),
    (198, "__syscall"), (202, "__sysctl"), (203, "mlock"), (204, "munlock"), (205, "undelete"),
    (206, "futimes"), (207, "getpgid"), (209, "poll"), (221, "semget"), (222, "semop"),
    (225, "msgget"), (226, "msgsnd"), (227, "msgrcv"), (228, "shmat"), (230, "shmdt"), (231, "shmget"),
    (232, "clock_gettime"), (233, "clock_settime"), (234, "clock_getres"), (235, "ktimer_create"),
    (236, "ktimer_delete"), (237, "ktimer_settime"), (238, "ktimer_gettime"),
    (239, "ktimer_getoverrun"), (240, "nanosleep"), (248, "ntp_gettime"), (250, "minherit"),
    (251, "rfork"), (252, "openbsd_poll"), (253, "issetugid"), (254, "lchown"), (255, "aio_read"),
    (256, "aio_write"), (257, "lio_listio"), (272, "getdents"), (274, "lchmod"),
    (275, "netbsd_lchown"), (276, "lutimes"), (277, "netbsd_msync"), (278, "nstat"), (279, "nfstat"),
    (280, "nlstat"), (289, "preadv"), (290, "pwritev"), (298, "fhopen"), (299, "fhstat"),
    (300, "modnext"), (301, "modstat"), (302, "modfnext"), (303, "modfind"), (304, "kldload"),
    (305, "kldunload"), (306, "kldfind"), (307, "kldnext"), (308, "kldstat"), (309, "kldfirstmod"),
    (310, "getsid"), (311, "setresuid"), (312, "setresgid"), (314, "aio_return"),
    (315, "aio_suspend"), (316, "aio_cancel"), (317, "aio_error"), (321, "yield"), (324, "mlockall"),
    (325, "munlockall"), (326, "__getcwd"), (327, "sched_setparam"), (328, "sched_getparam"),
    (329, "sched_setscheduler"), (330, "sched_getscheduler"), (331, "sched_yield"),
    (332, "sched_get_priority_max"), (333, "sched_get_priority_min"),
    (334, "sched_rr_get_interval"), (335, "utrace"), (337, "kldsym"), (338, "jail"),
    (340, "sigprocmask"), (341, "sigsuspend"), (343, "sigpending"), (345, "sigtimedwait"),
    (346, "sigwaitinfo"), (347, "__acl_get_file"), (348, "__acl_set_file"), (349, "__acl_get_fd"),
    (350, "__acl_set_fd"), (351, "__acl_delete_file"), (352, "__acl_delete_fd"),
    (353, "__acl_aclcheck_file"), (354, "__acl_aclcheck_fd"), (355, "extattrctl"),
    (356, "extattr_set_file"), (357, "extattr_get_file"), (358, "extattr_delete_file"),
    (359, "aio_waitcomplete"), (360, "getresuid"), (361, "getresgid"), (362, "kqueue"),
    (363, "kevent"), (371, "extattr_set_fd"), (372, "extattr_get_fd"), (373, "extattr_delete_fd"),
    (374, "__setugid"), (376, "eaccess"), (378, "nmount"), (384, "__mac_get_proc"),
    (385, "__mac_set_proc"), (386, "__mac_get_fd"), (387, "__mac_get_file"), (388, "__mac_set_fd"),
    (389, "__mac_set_file"), (390, "kenv"), (391, "lchflags"), (392, "uuidgen"), (393, "sendfile"),
    (394, "mac_syscall"), (395, "getfsstat"), (396, "statfs"), (397, "fstatfs"), (398, "fhstatfs"),
    (400, "ksem_close"), (401, "ksem_post"), (402, "ksem_wait"), (403, "ksem_trywait"),
    (404, "ksem_init"), (405, "ksem_open"), (406, "ksem_unlink"), (407, "ksem_getvalue"),
    (408, "ksem_destroy"), (409, "__mac_get_pid"), (410, "__mac_get_link"), (411, "__mac_set_link"),
    (412, "extattr_set_link"), (413, "extattr_get_link"), (414, "extattr_delete_link"),
    (415, "__mac_execve"), (416, "sigaction"), (417, "sigreturn"), (421, "getcontext"),
    (422, "setcontext"), (423, "swapcontext"), (424, "swapoff"), (425, "__acl_get_link"),
    (426, "__acl_set_link"), (427, "__acl_delete_link"), (428, "__acl_aclcheck_link"),
    (429, "sigwait"), (430, "thr_create"), (431, "thr_exit"), (432, "thr_self"), (433, "thr_kill"),
    (434, "_umtx_lock"), (435, "_umtx_unlock"), (436, "jail_attach"), (437, "extattr_list_fd"),
    (438, "extattr_list_file"), (439, "extattr_list_link"), (441, "ksem_timedwait"),
    (442, "thr_suspend"), (443, "thr_wake"), (444, "kldunloadf"), (445, "audit"), (446, "auditon"),
    (447, "getauid"), (448, "setauid"), (449, "getaudit"), (450, "setaudit"),
    (451, "getaudit_addr"), (452, "setaudit_addr"), (453, "auditctl"), (454, "_umtx_op"),
    (455, "thr_new"), (456, "sigqueue"), (457, "kmq_open"), (458, "kmq_setattr"),
    (459, "kmq_timedreceive"), (460, "kmq_timedsend"), (461, "kmq_notify"), (462, "kmq_unlink"),
    (463, "abort2"), (464, "thr_set_name"), (465, "aio_fsync"), (466, "rtprio_thread"),
    (471, "sctp_peeloff"), (472, "sctp_generic_sendmsg"), (473, "sctp_generic_sendmsg_iov"),
    (474, "sctp_generic_recvmsg"), (475, "pread"), (476, "pwrite"), (477, "mmap"), (478, "lseek"),
    (479, "truncate"), (480, "ftruncate"), (481, "thr_kill2"), (482, "shm_open"),
    (483, "shm_unlink"), (484, "cpuset"), (485, "cpuset_setid"), (486, "cpuset_getid"),
    (487, "cpuset_getaffinity"), (488, "cpuset_setaffinity"), (489, "faccessat"), (490, "fchmodat"),
    (491, "fchownat"), (492, "fexecve"), (493, "fstatat"), (494, "futimesat"), (495, "linkat"),
    (496, "mkdirat"), (497, "mkfifoat"), (498, "mknodat"), (499, "openat"), (500, "readlinkat"),
    (501, "renameat"), (502, "symlinkat"), (503, "unlinkat"), (504, "posix_openpt"),
    (505, "gssd_syscall"), (506, "jail_get"), (507, "jail_set"), (508, "jail_remove"),
    (509, "closefrom"), (510, "__semctl"), (511, "msgctl"), (512, "shmctl"), (513, "lpathconf"),
];

/// Orbis-specific additions with public, widely reproduced sources: the dynlib
/// syscalls used by the open PS4 payload SDKs (e.g. ps4-payload-sdk / OpenOrbis
/// `sys_dynlib_*` wrappers) and listed on psdevwiki "Syscalls".
const ORBIS: &[(u64, &str)] = &[
    (589, "dynlib_dlopen"),
    (590, "dynlib_dlclose"),
    (591, "dynlib_dlsym"),
    (592, "dynlib_get_list"),
    (593, "dynlib_get_info"),
    (594, "dynlib_load_prx"),
    (595, "dynlib_unload_prx"),
];

/// Name for a syscall number: user dictionary, then Orbis additions, then
/// FreeBSD 9 natives, else `sys_<n>`.
pub fn syscall_name(number: u64, user: Option<&HashMap<u64, String>>) -> String {
    if let Some(name) = user.and_then(|map| map.get(&number)) {
        return name.clone();
    }
    ORBIS
        .iter()
        .chain(FREEBSD9)
        .find(|(n, _)| *n == number)
        .map(|(_, name)| (*name).to_owned())
        .unwrap_or_else(|| format!("sys_{number}"))
}

/// Source label for [`syscall_name`]'s answer.
pub fn syscall_name_source(number: u64, user: Option<&HashMap<u64, String>>) -> &'static str {
    if user.is_some_and(|map| map.contains_key(&number)) {
        "user_dictionary"
    } else if ORBIS.iter().any(|(n, _)| *n == number) {
        "orbis_public"
    } else if FREEBSD9.iter().any(|(n, _)| *n == number) {
        "freebsd9"
    } else {
        "unknown"
    }
}

/// Every known `(number, name)` (user dictionary entries override).
pub fn syscall_table(user: Option<&HashMap<u64, String>>) -> BTreeMap<u64, String> {
    let mut table: BTreeMap<u64, String> =
        FREEBSD9.iter().chain(ORBIS).map(|(n, name)| (*n, (*name).to_owned())).collect();
    if let Some(user) = user {
        table.extend(user.iter().map(|(n, name)| (*n, name.clone())));
    }
    table
}

/// User dictionary artifact: JSON object `{"<number>": "name"}` (decimal or 0x hex keys).
pub fn parse_syscall_dictionary(data: &[u8]) -> Result<HashMap<u64, String>> {
    ensure!(data.len() <= 4 * 1024 * 1024, "Syscall dictionary exceeds 4 MiB");
    let value: Value = serde_json::from_slice(data).context("Syscall dictionary must be JSON")?;
    let object = value.as_object().context("Syscall dictionary must be a JSON object {number: name}")?;
    ensure!(object.len() <= 65_536, "Syscall dictionary has too many entries");
    let mut map = HashMap::new();
    for (key, name) in object {
        let number = parse_number(key).with_context(|| format!("Invalid syscall number key: {key}"))?;
        let name = name.as_str().context("Syscall dictionary values must be strings")?;
        ensure!(!name.is_empty() && name.len() <= 128, "Invalid syscall name for {key}");
        map.insert(number, name.to_owned());
    }
    Ok(map)
}

pub fn parse_number(text: &str) -> Option<u64> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

// ---- blocks / coverage formats -------------------------------------------------

pub const BLOCKS_FORMAT: &str = "ps4wb-blocks-v1";
pub const COVERAGE_FORMAT: &str = "ps4wb-coverage-v1";
pub const MAX_BLOCKS: usize = 200_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSet {
    pub module: Option<String>,
    pub module_sha256: Option<String>,
    pub image_base: u64,
    /// `(rva, size)` sorted and de-duplicated by RVA.
    pub blocks: Vec<(u64, u64)>,
    /// `basic_block` (from `blocks`) or `function_entry` (from `functions`).
    pub granularity: &'static str,
}

/// Parse a `ps4wb-blocks-v1` document. Without `blocks`, function starts from
/// `functions` become the block list (function-entry granularity).
pub fn parse_blocks(document: &Value) -> Result<BlockSet> {
    ensure!(document["format"] == BLOCKS_FORMAT, "Blocks artifact must have format {BLOCKS_FORMAT}");
    let hex = |value: &Value, what: &str| -> Result<u64> {
        value.as_str().and_then(parse_number).with_context(|| format!("Invalid {what}: {value}"))
    };
    let image_base = match &document["image_base"] {
        Value::Null => 0,
        value => hex(value, "image_base")?,
    };
    let mut blocks = BTreeMap::new();
    let mut granularity = "basic_block";
    if let Some(items) = document["blocks"].as_array().filter(|items| !items.is_empty()) {
        ensure!(items.len() <= MAX_BLOCKS, "Blocks artifact exceeds {MAX_BLOCKS} blocks");
        for item in items {
            let start = hex(&item["start"], "block start")?;
            let size = item["size"].as_u64().unwrap_or(1).max(1);
            blocks.entry(start).or_insert(size);
        }
    } else if let Some(items) = document["functions"].as_array() {
        granularity = "function_entry";
        ensure!(items.len() <= MAX_BLOCKS, "Blocks artifact exceeds {MAX_BLOCKS} functions");
        for item in items {
            let start = hex(&item["start"], "function start")?;
            let size = match &item["end"] {
                Value::Null => 1,
                end => hex(end, "function end")?.saturating_sub(start).max(1),
            };
            blocks.entry(start).or_insert(size);
        }
    }
    ensure!(!blocks.is_empty(), "Blocks artifact lists no blocks or functions");
    Ok(BlockSet {
        module: document["module"].as_str().map(str::to_owned),
        module_sha256: document["module_sha256"].as_str().map(str::to_owned),
        image_base,
        blocks: blocks.into_iter().collect(),
        granularity,
    })
}

/// drcov "format version 2" (DynamoRIO drcov; the format Lighthouse and
/// Cartographer load): text header, module table (`Columns: id, base, end, entry,
/// checksum, timestamp, path`) and a binary BB table of `{u32 start, u16 size,
/// u16 module_id}` little-endian entries. `blocks` are `(module offset, size)`.
pub fn drcov(module: &str, base: u64, end: u64, blocks: &[(u64, u64)]) -> Result<Vec<u8>> {
    ensure!(!module.contains('\n'), "Module name must be one line");
    let mut out = Vec::new();
    out.extend_from_slice(b"DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n");
    out.extend_from_slice(b"Module Table: version 2, count 1\n");
    out.extend_from_slice(b"Columns: id, base, end, entry, checksum, timestamp, path\n");
    out.extend_from_slice(
        format!(" 0, {base:#018x}, {end:#018x}, 0x0000000000000000, 0x00000000, 0x00000000, {module}\n").as_bytes(),
    );
    out.extend_from_slice(format!("BB Table: {} bbs\n", blocks.len()).as_bytes());
    for (offset, size) in blocks {
        let offset = u32::try_from(*offset).context("drcov block offset exceeds 32 bits")?;
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&((*size).clamp(1, 0xffff) as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
    }
    Ok(out)
}

/// Compare two `ps4wb-coverage-v1` documents: covered blocks only in A, only in
/// B, and in both (by RVA). Lists are capped at `limit` entries each.
pub fn coverage_diff(a: &Value, b: &Value, limit: usize) -> Result<Value> {
    let covered = |document: &Value, label: &str| -> Result<BTreeSet<u64>> {
        ensure!(document["format"] == COVERAGE_FORMAT, "Coverage {label} must have format {COVERAGE_FORMAT}");
        let mut set = BTreeSet::new();
        for block in document["blocks"].as_array().with_context(|| format!("Coverage {label} has no blocks"))? {
            if block["hits"].as_u64().unwrap_or(0) > 0 {
                let rva = block["rva"].as_str().and_then(parse_number).with_context(|| format!("Invalid rva in {label}"))?;
                set.insert(rva);
            }
        }
        Ok(set)
    };
    let (left, right) = (covered(a, "A")?, covered(b, "B")?);
    let render = |items: Vec<u64>| -> Value {
        json!(items.into_iter().take(limit).map(|rva| format!("{rva:#x}")).collect::<Vec<_>>())
    };
    let only_a: Vec<u64> = left.difference(&right).copied().collect();
    let only_b: Vec<u64> = right.difference(&left).copied().collect();
    let both: Vec<u64> = left.intersection(&right).copied().collect();
    let mut warnings = Vec::new();
    if a["module"] != b["module"] {
        warnings.push(format!("Different modules: {} vs {}", a["module"], b["module"]));
    }
    if a["module_sha256"].is_string() && b["module_sha256"].is_string() && a["module_sha256"] != b["module_sha256"] {
        warnings.push("Different module_sha256 values; RVAs may not correspond".to_owned());
    }
    if a["image_base"] != b["image_base"] {
        warnings.push(format!("Different image_base values: {} vs {}", a["image_base"], b["image_base"]));
    }
    let truncated = only_a.len() > limit || only_b.len() > limit || both.len() > limit;
    Ok(json!({
        "module": a["module"],
        "counts": {"covered_a": left.len(), "covered_b": right.len(), "only_a": only_a.len(),
            "only_b": only_b.len(), "both": both.len()},
        "only_a": render(only_a), "only_b": render(only_b), "both": render(both),
        "truncated": truncated, "warnings": warnings,
    }))
}

/// Validate a coverage document's basic shape (used before diffing artifacts).
pub fn require_coverage(document: &Value) -> Result<()> {
    if document["format"] != COVERAGE_FORMAT {
        bail!("Not a {COVERAGE_FORMAT} document");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Orbis-style dynamic data: JMPREL/STRTAB/SYMTAB offsets into dynlibdata.
    fn orbis_dynlib() -> (Vec<(u64, u64)>, Vec<u8>) {
        let mut data = vec![0u8; 0x100];
        // one JUMP_SLOT relocation at offset 0: r_offset 0x600, sym 1
        data[0..8].copy_from_slice(&0x600u64.to_le_bytes());
        data[8..16].copy_from_slice(&((1u64 << 32) | 7).to_le_bytes());
        // strtab at 0x40
        let name = b"\x001jfXLRVzisc#A#B\0";
        data[0x40..0x40 + name.len()].copy_from_slice(name);
        // symtab at 0x80: entry 0 null, entry 1 st_name = 1
        data[0x80 + 24..0x80 + 28].copy_from_slice(&1u32.to_le_bytes());
        let entries = vec![
            (DT_SCE_JMPREL, 0),
            (DT_SCE_PLTRELSZ, 24),
            (DT_SCE_STRTAB, 0x40),
            (DT_SCE_STRSZ, name.len() as u64),
            (DT_SCE_SYMTAB, 0x80),
            (DT_SCE_SYMTABSZ, 48),
        ];
        (entries, data)
    }

    #[test]
    fn orbis_dynlibdata_imports_resolve_nids() {
        let (entries, data) = orbis_dynlib();
        let (imports, notes) = imports_from_dynamic(&entries, 0, |space, value, length| {
            assert_eq!(space, TableSpace::DynlibData);
            data.get(value as usize..(value as usize + length).min(data.len())).map(<[u8]>::to_vec)
        });
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].got_rva, 0x600);
        assert_eq!(imports[0].nid.as_deref(), Some("1jfXLRVzisc"));
        assert_eq!(imports[0].library.as_deref(), Some("A"));
        assert_eq!(imports[0].display(), "sceKernelUsleep");
    }

    #[test]
    fn missing_tables_are_notes_not_errors() {
        let (imports, notes) = imports_from_dynamic(&[(DT_STRTAB, 0)], 0, |_, _, _| None);
        assert!(imports.is_empty());
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn plt_stub_and_syscall_wrapper_scanners() {
        // stub at 0x1000: jmp [rip+0x4fa] -> got 0x14fa; push 3; jmp ...
        let code = [0xff, 0x25, 0xfa, 0x04, 0, 0, 0x68, 3, 0, 0, 0, 0xe9, 0, 0, 0, 0];
        let stubs = find_plt_stubs(&code, 0x1000);
        assert_eq!(stubs, vec![PltStub { address: 0x1000, got: 0x1000 + 6 + 0x4fa, lazy_index: Some(3) }]);

        let mut code = vec![0xcc; 0x30];
        // 0x10: mov rax, 4; mov r10, rcx; syscall; ret
        code[0x10..0x1d].copy_from_slice(&[0x48, 0xc7, 0xc0, 4, 0, 0, 0, 0x49, 0x89, 0xca, 0x0f, 0x05, 0xc3]);
        // 0x20: mov eax, 591; syscall
        code[0x20..0x27].copy_from_slice(&[0xb8, 0x4f, 0x02, 0, 0, 0x0f, 0x05]);
        let sites = find_syscall_sites(&code, 0x8000, false);
        assert_eq!(sites.len(), 2);
        assert_eq!((sites[0].probe, sites[0].number, sites[0].entry_like, sites[0].moves_rcx_to_r10), (0x8010, Some(4), true, true));
        assert_eq!((sites[1].probe, sites[1].syscall_instruction, sites[1].number), (0x8020, 0x8025, Some(591)));
        assert_eq!(syscall_name(4, None), "write");
        assert_eq!(syscall_name(591, None), "dynlib_dlsym");
        assert_eq!(syscall_name(9999, None), "sys_9999");
        let user = parse_syscall_dictionary(br#"{"0x270F": "custom"}"#).unwrap();
        assert_eq!(syscall_name(9999, Some(&user)), "custom");
        assert_eq!(syscall_name_source(9999, Some(&user)), "user_dictionary");
    }

    #[test]
    fn fde_enumeration_reads_pcrel_sdata4_ranges() {
        let mut section = Vec::new();
        let cie = [0u8, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0x0c, 7, 8, 0x90, 1, 0, 0];
        section.extend((cie.len() as u32).to_le_bytes());
        section.extend(cie);
        let fde_pos = section.len();
        let section_va = 0x40_2000u64;
        let mut fde = Vec::new();
        fde.extend(((fde_pos + 4) as u32).to_le_bytes()); // CIE pointer back to offset 0
        let field_va = section_va + (fde_pos + 4 + 4) as u64;
        fde.extend(((0x40_1000i64 - field_va as i64) as i32).to_le_bytes());
        fde.extend(0x40u32.to_le_bytes());
        fde.extend([0, 0, 0, 0]);
        section.extend((fde.len() as u32).to_le_bytes());
        section.extend(fde);
        assert_eq!(fde_ranges(&section, section_va, 100), vec![(0x40_1000, 0x40)]);
    }

    #[test]
    fn drcov_layout_and_coverage_diff() {
        let bytes = drcov("eboot.bin", 0x40_0000, 0x50_0000, &[(0x10, 4), (0x2000, 70_000)]).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("DRCOV VERSION: 2\n"));
        assert!(text.contains("Module Table: version 2, count 1\n"));
        assert!(text.contains("BB Table: 2 bbs\n"));
        let table = bytes.len() - 16;
        assert_eq!(&bytes[table..table + 8], &[0x10, 0, 0, 0, 4, 0, 0, 0]);
        assert_eq!(&bytes[table + 8..], &[0, 0x20, 0, 0, 0xff, 0xff, 0, 0]);

        let doc = |hits: [u64; 3]| {
            json!({"format": COVERAGE_FORMAT, "module": "eboot.bin", "module_sha256": null, "image_base": "0x0",
                "blocks": [{"rva":"0x10","size":4,"hits":hits[0]},{"rva":"0x20","size":4,"hits":hits[1]},{"rva":"0x30","size":4,"hits":hits[2]}]})
        };
        let diff = coverage_diff(&doc([1, 1, 0]), &doc([0, 1, 1]), 100).unwrap();
        assert_eq!(diff["only_a"], json!(["0x10"]));
        assert_eq!(diff["only_b"], json!(["0x30"]));
        assert_eq!(diff["both"], json!(["0x20"]));
        assert!(coverage_diff(&json!({}), &doc([0, 0, 0]), 10).is_err());
    }

    #[test]
    fn blocks_document_parses_blocks_or_functions() {
        let set = parse_blocks(&json!({"format": BLOCKS_FORMAT, "module": "eboot.bin", "module_sha256": null,
            "image_base": "0x400000", "blocks": [{"start":"0x20","size":5},{"start":"0x10","size":3}], "functions": []}))
        .unwrap();
        assert_eq!(set.blocks, vec![(0x10, 3), (0x20, 5)]);
        assert_eq!(set.image_base, 0x40_0000);
        let set = parse_blocks(&json!({"format": BLOCKS_FORMAT, "module": null, "module_sha256": null,
            "image_base": "0x0", "blocks": [], "functions": [{"start":"0x100","end":"0x180","name":"f"}]}))
        .unwrap();
        assert_eq!(set.blocks, vec![(0x100, 0x80)]);
        assert!(parse_blocks(&json!({"format": "other"})).is_err());
    }
}
