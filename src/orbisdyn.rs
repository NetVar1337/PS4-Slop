//! Tolerant ELF64 / Orbis (PS4) dynamic-linking parser.
//!
//! Works on plain byte buffers (a file image or bytes read from a live process)
//! and never fails hard on malformed input: every inconsistency is recorded in
//! [`DynamicInfo::warnings`] and parsing continues with what is usable.
//!
//! Format sources (no decryption, keys or SELF/PKG handling here; input must be
//! an already-decrypted ELF image or memory that is already loaded):
//! * Generic ELF64 / SysV gABI and the FreeBSD `sys/sys/elf_common.h` constants
//!   for program-header types, `DT_*` tags, symbol and relocation layouts.
//! * Orbis-specific values (`PT_SCE_*`, `DT_SCE_*`, `ET_SCE_*`) as published by
//!   the OpenOrbis toolchain (`create-fself`, `orbis-elf` headers), the
//!   psdevwiki "SELF File Format"/"ELF" pages and the GhidraOrbis / IDA
//!   `ps4_module_loader` community loaders. In particular:
//!   - `DT_SCE_{HASH,STRTAB,SYMTAB,RELA,JMPREL}` values are byte offsets
//!     relative to the start of the `PT_SCE_DYNLIBDATA` segment's file data,
//!     not virtual addresses (OpenOrbis create-fself; GhidraOrbis).
//!   - `DT_SCE_PLTGOT` is a virtual address like the standard `DT_PLTGOT`.
//!   - `DT_SCE_NEEDED_MODULE` / `DT_SCE_MODULE_INFO` pack
//!     `name_offset:32 | version_minor:8 | version_major:8 | id:16` (low to high),
//!     `DT_SCE_IMPORT_LIB` / `DT_SCE_EXPORT_LIB` pack
//!     `name_offset:32 | version:16 | id:16`, and the `*_ATTR` tags pack
//!     `attr:48 | id:16` (OpenOrbis; ps4libdoc).
//!   - `.dynsym` names are `<11-char NID>#<library id>#<module id>`, ids encoded
//!     as big-endian base-64 digits in the NID alphabet (ps4libdoc; OpenOrbis).
//!
//! Because these Orbis details come from community reverse engineering, the
//! parser cross-checks every table against its bounds and reports anything
//! it had to skip instead of guessing.

use crate::Result;
use anyhow::{bail, ensure};
use serde_json::{Value, json};
use std::collections::HashMap;

// ---- program header types ------------------------------------------------
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
/// GNU extensions (FreeBSD elf_common.h).
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
/// Orbis segments (OpenOrbis create-fself; psdevwiki).
pub const PT_SCE_DYNLIBDATA: u32 = 0x6100_0000;
pub const PT_SCE_PROCPARAM: u32 = 0x6100_0001;
pub const PT_SCE_MODULEPARAM: u32 = 0x6100_0002;
pub const PT_SCE_RELRO: u32 = 0x6100_0010;
pub const PT_SCE_COMMENT: u32 = 0x6fff_ff00;
pub const PT_SCE_VERSION: u32 = 0x6fff_ff01;

// ---- ELF types (Orbis values: OpenOrbis create-fself / psdevwiki) ---------
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;
pub const ET_SCE_EXEC: u16 = 0xfe00;
pub const ET_SCE_REPLAY_EXEC: u16 = 0xfe01;
pub const ET_SCE_RELEXEC: u16 = 0xfe04;
pub const ET_SCE_STUBLIB: u16 = 0xfe0c;
pub const ET_SCE_DYNEXEC: u16 = 0xfe10;
pub const ET_SCE_DYNAMIC: u16 = 0xfe18;

// ---- standard dynamic tags (SysV gABI / FreeBSD elf_common.h) -------------
pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_PLTRELSZ: u64 = 2;
pub const DT_PLTGOT: u64 = 3;
pub const DT_HASH: u64 = 4;
pub const DT_STRTAB: u64 = 5;
pub const DT_SYMTAB: u64 = 6;
pub const DT_RELA: u64 = 7;
pub const DT_RELASZ: u64 = 8;
pub const DT_RELAENT: u64 = 9;
pub const DT_STRSZ: u64 = 10;
pub const DT_SYMENT: u64 = 11;
pub const DT_INIT: u64 = 12;
pub const DT_FINI: u64 = 13;
pub const DT_SONAME: u64 = 14;
pub const DT_PLTREL: u64 = 20;
pub const DT_DEBUG: u64 = 21;
pub const DT_TEXTREL: u64 = 22;
pub const DT_JMPREL: u64 = 23;
pub const DT_BIND_NOW: u64 = 24;
pub const DT_INIT_ARRAY: u64 = 25;
pub const DT_FINI_ARRAY: u64 = 26;
pub const DT_INIT_ARRAYSZ: u64 = 27;
pub const DT_FINI_ARRAYSZ: u64 = 28;
pub const DT_FLAGS: u64 = 30;
pub const DT_PREINIT_ARRAY: u64 = 32;
pub const DT_PREINIT_ARRAYSZ: u64 = 33;
pub const DT_RELACOUNT: u64 = 0x6fff_fff9;
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;

// ---- Orbis dynamic tags (OpenOrbis create-fself / ps4libdoc / GhidraOrbis) -
pub const DT_SCE_IDTABENTSZ: u64 = 0x6100_0005;
pub const DT_SCE_FINGERPRINT: u64 = 0x6100_0007;
pub const DT_SCE_ORIGINAL_FILENAME: u64 = 0x6100_0009;
pub const DT_SCE_MODULE_INFO: u64 = 0x6100_000d;
pub const DT_SCE_NEEDED_MODULE: u64 = 0x6100_000f;
pub const DT_SCE_MODULE_ATTR: u64 = 0x6100_0011;
pub const DT_SCE_EXPORT_LIB: u64 = 0x6100_0013;
pub const DT_SCE_IMPORT_LIB: u64 = 0x6100_0015;
pub const DT_SCE_EXPORT_LIB_ATTR: u64 = 0x6100_0017;
pub const DT_SCE_IMPORT_LIB_ATTR: u64 = 0x6100_0019;
pub const DT_SCE_STUB_MODULE_NAME: u64 = 0x6100_001d;
pub const DT_SCE_STUB_MODULE_VERSION: u64 = 0x6100_001f;
pub const DT_SCE_STUB_LIBRARY_NAME: u64 = 0x6100_0021;
pub const DT_SCE_STUB_LIBRARY_VERSION: u64 = 0x6100_0023;
pub const DT_SCE_HASH: u64 = 0x6100_0025;
pub const DT_SCE_PLTGOT: u64 = 0x6100_0027;
pub const DT_SCE_JMPREL: u64 = 0x6100_0029;
pub const DT_SCE_PLTREL: u64 = 0x6100_002b;
pub const DT_SCE_PLTRELSZ: u64 = 0x6100_002d;
pub const DT_SCE_RELA: u64 = 0x6100_002f;
pub const DT_SCE_RELASZ: u64 = 0x6100_0031;
pub const DT_SCE_RELAENT: u64 = 0x6100_0033;
pub const DT_SCE_STRTAB: u64 = 0x6100_0035;
pub const DT_SCE_STRSZ: u64 = 0x6100_0037;
pub const DT_SCE_SYMTAB: u64 = 0x6100_0039;
pub const DT_SCE_SYMENT: u64 = 0x6100_003b;
pub const DT_SCE_HASHSZ: u64 = 0x6100_003d;
pub const DT_SCE_SYMTABSZ: u64 = 0x6100_003f;

// ---- x86-64 relocation types (System V AMD64 psABI) -----------------------
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_TPOFF64: u32 = 18;

/// Caps that keep a hostile/corrupt image from exhausting memory.
pub const MAX_PHDRS: usize = 256;
pub const MAX_DYN_ENTRIES: usize = 8192;
pub const MAX_SYMBOLS: usize = 262_144;
pub const MAX_RELOCS: usize = 1_048_576;

/// NID / id alphabet (ps4libdoc; identical to `crate::nid`'s encoder alphabet).
const ID_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

pub fn rd16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at.checked_add(2)?)?.try_into().ok()?))
}
pub fn rd32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}
pub fn rd64(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

fn cstr(data: &[u8], at: usize) -> Option<String> {
    let tail = data.get(at..)?;
    let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len()).min(4096);
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

/// Decode an Orbis library/module id suffix (`A` = 0, `B` = 1, `BA` = 64 ...).
pub fn decode_id(text: &str) -> Option<u16> {
    if text.is_empty() || text.len() > 3 {
        return None;
    }
    let mut value: u32 = 0;
    for byte in text.bytes() {
        let digit = ID_ALPHABET.iter().position(|c| *c == byte)? as u32;
        value = value * 64 + digit;
    }
    u16::try_from(value).ok()
}

/// Inverse of [`decode_id`].
pub fn encode_id(mut id: u16) -> String {
    let mut digits = Vec::new();
    loop {
        digits.push(ID_ALPHABET[(id % 64) as usize]);
        id /= 64;
        if id == 0 {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).expect("ascii")
}

pub fn type_name(e_type: u16) -> &'static str {
    match e_type {
        ET_EXEC => "ET_EXEC",
        ET_DYN => "ET_DYN",
        ET_CORE => "ET_CORE",
        ET_SCE_EXEC => "ET_SCE_EXEC",
        ET_SCE_REPLAY_EXEC => "ET_SCE_REPLAY_EXEC",
        ET_SCE_RELEXEC => "ET_SCE_RELEXEC",
        ET_SCE_STUBLIB => "ET_SCE_STUBLIB",
        ET_SCE_DYNEXEC => "ET_SCE_DYNEXEC",
        ET_SCE_DYNAMIC => "ET_SCE_DYNAMIC",
        _ => "unknown",
    }
}

#[derive(Clone, Debug, Default)]
pub struct Phdr {
    pub index: usize,
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl Phdr {
    pub fn parse(data: &[u8], at: usize, index: usize) -> Option<Self> {
        Some(Self {
            index,
            p_type: rd32(data, at)?,
            flags: rd32(data, at + 4)?,
            offset: rd64(data, at + 8)?,
            vaddr: rd64(data, at + 16)?,
            paddr: rd64(data, at + 24)?,
            filesz: rd64(data, at + 32)?,
            memsz: rd64(data, at + 40)?,
            align: rd64(data, at + 48)?,
        })
    }

    pub fn encode(&self) -> [u8; 56] {
        let mut out = [0u8; 56];
        out[0..4].copy_from_slice(&self.p_type.to_le_bytes());
        out[4..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..16].copy_from_slice(&self.offset.to_le_bytes());
        out[16..24].copy_from_slice(&self.vaddr.to_le_bytes());
        out[24..32].copy_from_slice(&self.paddr.to_le_bytes());
        out[32..40].copy_from_slice(&self.filesz.to_le_bytes());
        out[40..48].copy_from_slice(&self.memsz.to_le_bytes());
        out[48..56].copy_from_slice(&self.align.to_le_bytes());
        out
    }

    pub fn type_label(&self) -> String {
        match self.p_type {
            PT_LOAD => "PT_LOAD".into(),
            PT_DYNAMIC => "PT_DYNAMIC".into(),
            PT_NOTE => "PT_NOTE".into(),
            PT_PHDR => "PT_PHDR".into(),
            PT_TLS => "PT_TLS".into(),
            PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME".into(),
            PT_GNU_STACK => "PT_GNU_STACK".into(),
            PT_GNU_RELRO => "PT_GNU_RELRO".into(),
            PT_SCE_DYNLIBDATA => "PT_SCE_DYNLIBDATA".into(),
            PT_SCE_PROCPARAM => "PT_SCE_PROCPARAM".into(),
            PT_SCE_MODULEPARAM => "PT_SCE_MODULEPARAM".into(),
            PT_SCE_RELRO => "PT_SCE_RELRO".into(),
            PT_SCE_COMMENT => "PT_SCE_COMMENT".into(),
            PT_SCE_VERSION => "PT_SCE_VERSION".into(),
            other => format!("{other:#x}"),
        }
    }
}

/// A parsed ELF64 little-endian image (file layout).
pub struct ElfFile<'a> {
    pub data: &'a [u8],
    pub e_type: u16,
    pub e_machine: u16,
    pub osabi: u8,
    pub entry: u64,
    pub phoff: u64,
    pub phentsize: u16,
    pub phdrs: Vec<Phdr>,
    pub shoff: u64,
    pub shnum: u16,
}

impl<'a> ElfFile<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        ensure!(data.len() >= 64 && &data[..4] == b"\x7fELF", "Not an ELF image");
        ensure!(data[4] == 2 && data[5] == 1, "Only ELF64 little-endian images are supported");
        let e_type = rd16(data, 16).unwrap_or(0);
        let e_machine = rd16(data, 18).unwrap_or(0);
        let entry = rd64(data, 24).unwrap_or(0);
        let phoff = rd64(data, 32).unwrap_or(0);
        let shoff = rd64(data, 40).unwrap_or(0);
        let phentsize = rd16(data, 54).unwrap_or(0);
        let phnum = rd16(data, 56).unwrap_or(0) as usize;
        let shnum = rd16(data, 60).unwrap_or(0);
        ensure!(phentsize >= 56, "Invalid program header entry size {phentsize}");
        ensure!(phnum <= MAX_PHDRS, "Too many program headers ({phnum})");
        let mut phdrs = Vec::with_capacity(phnum);
        for index in 0..phnum {
            let at = (phoff as usize)
                .checked_add(index * phentsize as usize)
                .filter(|at| at + 56 <= data.len());
            match at.and_then(|at| Phdr::parse(data, at, index)) {
                Some(phdr) => phdrs.push(phdr),
                None => bail!("Program header {index} lies outside the image"),
            }
        }
        Ok(Self { data, e_type, e_machine, osabi: data[7], entry, phoff, phentsize, phdrs, shoff, shnum })
    }

    pub fn loads(&self) -> impl Iterator<Item = &Phdr> {
        self.phdrs.iter().filter(|p| p.p_type == PT_LOAD)
    }

    pub fn find(&self, p_type: u32) -> Option<&Phdr> {
        self.phdrs.iter().find(|p| p.p_type == p_type)
    }

    pub fn min_vaddr(&self) -> u64 {
        self.loads().map(|p| p.vaddr).min().unwrap_or(0)
    }

    pub fn max_vaddr(&self) -> u64 {
        self.loads().map(|p| p.vaddr.saturating_add(p.memsz)).max().unwrap_or(0)
    }

    /// File offset of `va` if it lies in the file-backed part of a `PT_LOAD`.
    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        self.loads().find_map(|p| {
            (p.vaddr <= va && va < p.vaddr.saturating_add(p.filesz)).then(|| p.offset + (va - p.vaddr))
        })
    }

    /// Virtual address of file `offset` if it lies in the file part of a `PT_LOAD`.
    pub fn offset_to_va(&self, offset: u64) -> Option<u64> {
        self.loads().find_map(|p| {
            (p.offset <= offset && offset < p.offset.saturating_add(p.filesz))
                .then(|| p.vaddr + (offset - p.offset))
        })
    }

    pub fn file_slice(&self, offset: u64, len: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.data.get(start..end)
    }

    /// Bytes at `va..va+len`, only if fully inside one load's file data.
    pub fn va_slice(&self, va: u64, len: u64) -> Option<&'a [u8]> {
        let p = self.loads().find(|p| {
            p.vaddr <= va && va.checked_add(len).is_some_and(|end| end <= p.vaddr.saturating_add(p.filesz))
        })?;
        self.file_slice(p.offset + (va - p.vaddr), len)
    }

    pub fn segments_json(&self) -> Value {
        json!(self.phdrs.iter().map(|p| json!({
            "index": p.index, "type": p.type_label(), "flags": p.flags,
            "offset": format!("{:#x}", p.offset), "vaddr": format!("{:#x}", p.vaddr),
            "filesz": p.filesz, "memsz": p.memsz,
        })).collect::<Vec<_>>())
    }
}

#[derive(Clone, Debug, Default)]
pub struct ModuleRef {
    pub id: u16,
    pub name: String,
    pub version_major: u8,
    pub version_minor: u8,
}

#[derive(Clone, Debug, Default)]
pub struct LibRef {
    pub id: u16,
    pub name: String,
    pub version: u16,
    pub attr: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Symbol {
    pub index: u32,
    /// Name as stored in the string table (`NID#lib#mod` for Orbis).
    pub raw_name: String,
    /// Demangled name when the NID is known, otherwise `raw_name`.
    pub name: String,
    pub nid: Option<String>,
    pub known: bool,
    pub library: Option<String>,
    pub module: Option<String>,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}

impl Symbol {
    pub fn binding(&self) -> u8 {
        self.info >> 4
    }
    pub fn kind(&self) -> u8 {
        self.info & 0xf
    }
    pub fn is_defined(&self) -> bool {
        self.shndx != 0 && self.index != 0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rela {
    pub offset: u64,
    pub r_type: u32,
    pub sym: u32,
    pub addend: i64,
}

impl Rela {
    pub fn encode(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..8].copy_from_slice(&self.offset.to_le_bytes());
        let info = (u64::from(self.sym) << 32) | u64::from(self.r_type);
        out[8..16].copy_from_slice(&info.to_le_bytes());
        out[16..24].copy_from_slice(&self.addend.to_le_bytes());
        out
    }
}

pub fn reloc_type_name(r_type: u32) -> &'static str {
    match r_type {
        R_X86_64_NONE => "R_X86_64_NONE",
        R_X86_64_64 => "R_X86_64_64",
        R_X86_64_GLOB_DAT => "R_X86_64_GLOB_DAT",
        R_X86_64_JUMP_SLOT => "R_X86_64_JUMP_SLOT",
        R_X86_64_RELATIVE => "R_X86_64_RELATIVE",
        R_X86_64_DTPMOD64 => "R_X86_64_DTPMOD64",
        R_X86_64_DTPOFF64 => "R_X86_64_DTPOFF64",
        R_X86_64_TPOFF64 => "R_X86_64_TPOFF64",
        _ => "other",
    }
}

/// One imported symbol bound through a GOT slot (`r_offset`, static VA).
#[derive(Clone, Debug, Default)]
pub struct Import {
    pub slot: u64,
    pub r_type: u32,
    pub sym: u32,
    pub addend: i64,
    pub name: String,
    pub raw_name: String,
    pub nid: Option<String>,
    pub known: bool,
    pub library: Option<String>,
    pub module: Option<String>,
    pub plt: bool,
}

/// One defined (exported) dynamic symbol; `value` is a static VA.
#[derive(Clone, Debug, Default)]
pub struct Export {
    pub name: String,
    pub raw_name: String,
    pub nid: Option<String>,
    pub known: bool,
    pub library: Option<String>,
    pub value: u64,
    pub size: u64,
    pub kind: u8,
}

/// Where a dynamic table lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loc {
    /// Byte offset inside the `PT_SCE_DYNLIBDATA` blob.
    Dynlib(u64),
    /// Static virtual address.
    Va(u64),
}

#[derive(Clone, Debug, Default)]
pub struct DynamicInfo {
    pub entries: Vec<(u64, u64)>,
    pub orbis: bool,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub original_filename: Option<String>,
    pub fingerprint: Option<String>,
    pub module_info: Option<ModuleRef>,
    pub needed_modules: Vec<ModuleRef>,
    pub export_libs: Vec<LibRef>,
    pub import_libs: Vec<LibRef>,
    pub symbols: Vec<Symbol>,
    pub rela: Vec<Rela>,
    pub jmprel: Vec<Rela>,
    pub pltgot: Option<u64>,
    pub init: Option<u64>,
    pub fini: Option<u64>,
    pub init_array: Option<(u64, u64)>,
    pub fini_array: Option<(u64, u64)>,
    pub preinit_array: Option<(u64, u64)>,
    pub flags: Option<u64>,
    pub flags_1: Option<u64>,
    /// Raw SysV hash table bytes (`DT_HASH` / `DT_SCE_HASH`) when present.
    pub hash: Option<Vec<u8>>,
    pub warnings: Vec<String>,
}

/// Inputs for [`parse_dynamic`]: raw `Elf64_Dyn` bytes, the optional
/// `PT_SCE_DYNLIBDATA` blob, and a reader for VA-addressed standard tables.
pub struct DynSources<'a> {
    pub dynamic: &'a [u8],
    pub dynlib: Option<&'a [u8]>,
    pub va_reader: &'a mut dyn FnMut(u64, usize) -> Option<Vec<u8>>,
}

/// Plausibility check of an `Elf64_Dyn` array: must contain a `DT_NULL`
/// terminator and only tags from known ranges before it.
pub fn plausible_dynamic(bytes: &[u8]) -> bool {
    let mut saw_any = false;
    for entry in bytes.as_chunks::<16>().0.iter().take(MAX_DYN_ENTRIES) {
        let tag = u64::from_le_bytes(entry[..8].try_into().unwrap());
        if tag == DT_NULL {
            return saw_any;
        }
        let known = tag <= 0x40
            || (0x6000_0000..0x6100_0000).contains(&tag)
            || (0x6100_0000..0x6100_0100).contains(&tag)
            || (0x6fff_f000..=0x6fff_ffff).contains(&tag)
            || (0x7000_0000..=0x7fff_ffff).contains(&tag);
        if !known {
            return false;
        }
        saw_any = true;
    }
    false
}

fn symbol_at(symtab: &[u8], index: usize, strtab: &[u8]) -> Option<(String, u64, u64, u8, u8, u16)> {
    let at = index.checked_mul(24)?;
    let name_off = rd32(symtab, at)? as usize;
    let info = *symtab.get(at + 4)?;
    let other = *symtab.get(at + 5)?;
    let shndx = rd16(symtab, at + 6)?;
    let value = rd64(symtab, at + 8)?;
    let size = rd64(symtab, at + 16)?;
    let name = if name_off == 0 { String::new() } else { cstr(strtab, name_off).unwrap_or_default() };
    Some((name, value, size, info, other, shndx))
}

fn parse_relas(bytes: &[u8], entsize: usize, warnings: &mut Vec<String>, label: &str) -> Vec<Rela> {
    let entsize = if entsize == 0 { 24 } else { entsize };
    if entsize < 24 {
        warnings.push(format!("{label}: relocation entry size {entsize} < 24; skipped"));
        return Vec::new();
    }
    let count = (bytes.len() / entsize).min(MAX_RELOCS);
    if bytes.len() / entsize > MAX_RELOCS {
        warnings.push(format!("{label}: truncated to {MAX_RELOCS} relocations"));
    }
    (0..count)
        .filter_map(|i| {
            let at = i * entsize;
            let info = rd64(bytes, at + 8)?;
            Some(Rela {
                offset: rd64(bytes, at)?,
                r_type: (info & 0xffff_ffff) as u32,
                sym: (info >> 32) as u32,
                addend: rd64(bytes, at + 16)? as i64,
            })
        })
        .collect()
}

fn fetch_table(
    dynlib: Option<&[u8]>,
    reader: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>,
    loc: Loc,
    len: u64,
    label: &str,
    warnings: &mut Vec<String>,
) -> Option<Vec<u8>> {
    let len_usize = usize::try_from(len).ok().filter(|l| *l <= 256 * 1024 * 1024)?;
    let found = match loc {
        Loc::Dynlib(offset) => dynlib.and_then(|blob| {
            let start = usize::try_from(offset).ok()?;
            blob.get(start..start.checked_add(len_usize)?).map(<[u8]>::to_vec)
        }),
        Loc::Va(va) => reader(va, len_usize),
    };
    if found.is_none() {
        warnings.push(format!("{label}: {len} bytes at {loc:?} are not available in this image"));
    }
    found
}

/// Parse a dynamic section (standard and/or Orbis `DT_SCE_*` tags).
pub fn parse_dynamic(src: &mut DynSources<'_>, custom: Option<&HashMap<String, String>>) -> DynamicInfo {
    let mut info = DynamicInfo::default();
    let mut tags: Vec<(u64, u64)> = Vec::new();
    let mut terminated = false;
    for entry in src.dynamic.as_chunks::<16>().0.iter().take(MAX_DYN_ENTRIES) {
        let tag = u64::from_le_bytes(entry[..8].try_into().unwrap());
        let value = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        tags.push((tag, value));
    }
    if !terminated {
        info.warnings.push("Dynamic table has no DT_NULL terminator inside its bounds".into());
    }
    info.orbis = tags.iter().any(|(tag, _)| (0x6100_0000..0x6100_0100).contains(tag));
    let get = |wanted: u64| tags.iter().find(|(tag, _)| *tag == wanted).map(|(_, v)| *v);
    let all = |wanted: u64| tags.iter().filter(move |(tag, _)| *tag == wanted).map(|(_, v)| *v);

    let dynlib = src.dynlib;
    let reader = &mut *src.va_reader;
    let mut fetch = |loc: Loc, len: u64, label: &str, warnings: &mut Vec<String>| {
        fetch_table(dynlib, &mut *reader, loc, len, label, warnings)
    };

    // String table.
    let strtab = match (get(DT_SCE_STRTAB), get(DT_SCE_STRSZ), get(DT_STRTAB), get(DT_STRSZ)) {
        (Some(off), Some(size), _, _) => fetch(Loc::Dynlib(off), size, "DT_SCE_STRTAB", &mut info.warnings),
        (_, _, Some(va), Some(size)) => fetch(Loc::Va(va), size, "DT_STRTAB", &mut info.warnings),
        _ => None,
    }
    .unwrap_or_default();
    let string = |offset: u64| cstr(&strtab, offset as usize).filter(|s| !s.is_empty());

    info.needed = all(DT_NEEDED).filter_map(string).collect();
    info.soname = get(DT_SONAME).and_then(string);
    info.original_filename = get(DT_SCE_ORIGINAL_FILENAME).and_then(string);
    if let Some(offset) = get(DT_SCE_FINGERPRINT) {
        info.fingerprint = dynlib
            .and_then(|blob| blob.get(offset as usize..(offset as usize).checked_add(20)?))
            .map(hex::encode);
    }
    let module_ref = |value: u64| ModuleRef {
        id: (value >> 48) as u16,
        version_major: (value >> 40) as u8,
        version_minor: (value >> 32) as u8,
        name: string(value & 0xffff_ffff).unwrap_or_default(),
    };
    let lib_ref = |value: u64| LibRef {
        id: (value >> 48) as u16,
        version: (value >> 32) as u16,
        name: string(value & 0xffff_ffff).unwrap_or_default(),
        attr: None,
    };
    info.module_info = get(DT_SCE_MODULE_INFO).map(module_ref);
    info.needed_modules = all(DT_SCE_NEEDED_MODULE).map(module_ref).collect();
    info.export_libs = all(DT_SCE_EXPORT_LIB).map(lib_ref).collect();
    info.import_libs = all(DT_SCE_IMPORT_LIB).map(lib_ref).collect();
    for value in all(DT_SCE_IMPORT_LIB_ATTR) {
        let id = (value >> 48) as u16;
        if let Some(lib) = info.import_libs.iter_mut().find(|lib| lib.id == id) {
            lib.attr = Some(value & 0xffff_ffff_ffff);
        }
    }
    for value in all(DT_SCE_EXPORT_LIB_ATTR) {
        let id = (value >> 48) as u16;
        if let Some(lib) = info.export_libs.iter_mut().find(|lib| lib.id == id) {
            lib.attr = Some(value & 0xffff_ffff_ffff);
        }
    }

    info.pltgot = get(DT_SCE_PLTGOT).or_else(|| get(DT_PLTGOT));
    info.init = get(DT_INIT);
    info.fini = get(DT_FINI);
    info.flags = get(DT_FLAGS);
    info.flags_1 = get(DT_FLAGS_1);
    let pair = |a: u64, s: u64| Some((get(a)?, get(s).unwrap_or(0)));
    info.init_array = pair(DT_INIT_ARRAY, DT_INIT_ARRAYSZ);
    info.fini_array = pair(DT_FINI_ARRAY, DT_FINI_ARRAYSZ);
    info.preinit_array = pair(DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ);

    // Hash table (also tells the symbol count for standard images).
    let hash = match (get(DT_SCE_HASH), get(DT_SCE_HASHSZ), get(DT_HASH)) {
        (Some(off), Some(size), _) => fetch(Loc::Dynlib(off), size, "DT_SCE_HASH", &mut info.warnings),
        (_, _, Some(va)) => {
            let mut scratch = Vec::new();
            fetch(Loc::Va(va), 8, "DT_HASH header", &mut scratch)
                .and_then(|head| {
                    let nbucket = rd32(&head, 0)? as u64;
                    let nchain = rd32(&head, 4)? as u64;
                    let size = 8 + 4 * (nbucket + nchain);
                    (size <= 64 * 1024 * 1024).then_some(size)
                })
                .and_then(|size| fetch(Loc::Va(va), size, "DT_HASH", &mut info.warnings))
        }
        _ => None,
    };

    // Symbol table.
    let syment = get(DT_SCE_SYMENT).or_else(|| get(DT_SYMENT)).unwrap_or(24);
    if syment != 24 {
        info.warnings.push(format!("Unexpected symbol entry size {syment}; assuming 24"));
    }
    let symtab = if let (Some(off), Some(size)) = (get(DT_SCE_SYMTAB), get(DT_SCE_SYMTABSZ)) {
        fetch(Loc::Dynlib(off), size, "DT_SCE_SYMTAB", &mut info.warnings)
    } else if let Some(va) = get(DT_SYMTAB) {
        let count = hash
            .as_ref()
            .and_then(|h| rd32(h, 4))
            .map(u64::from)
            .or_else(|| {
                let strtab_va = get(DT_STRTAB)?;
                (strtab_va > va).then(|| (strtab_va - va) / 24)
            });
        match count {
            Some(count) => fetch(Loc::Va(va), count.min(MAX_SYMBOLS as u64) * 24, "DT_SYMTAB", &mut info.warnings),
            None => {
                info.warnings.push("DT_SYMTAB without DT_HASH: symbol count unknown; skipped".into());
                None
            }
        }
    } else {
        None
    };
    info.hash = hash;
    if let Some(symtab) = &symtab {
        let count = (symtab.len() / 24).min(MAX_SYMBOLS);
        for index in 0..count {
            let Some((raw, value, size, sym_info, other, shndx)) = symbol_at(symtab, index, &strtab) else {
                break;
            };
            let mut symbol = Symbol {
                index: index as u32,
                name: raw.clone(),
                raw_name: raw,
                value,
                size,
                info: sym_info,
                other,
                shndx,
                ..Default::default()
            };
            if let Some((nid, lib, module)) = crate::nid::split_orbis_symbol(&symbol.raw_name) {
                symbol.nid = Some(nid.to_owned());
                let defined = symbol.shndx != 0;
                let lib_id = lib.and_then(decode_id);
                let mod_id = module.and_then(decode_id);
                symbol.library = lib_id.and_then(|id| {
                    let libs = if defined { &info.export_libs } else { &info.import_libs };
                    libs.iter().find(|l| l.id == id).map(|l| l.name.clone())
                });
                symbol.module = mod_id.and_then(|id| {
                    if defined {
                        info.module_info.as_ref().filter(|m| m.id == id).map(|m| m.name.clone())
                    } else {
                        info.needed_modules.iter().find(|m| m.id == id).map(|m| m.name.clone())
                    }
                });
                if let Some(real) = crate::nid::lookup_nid(nid, custom) {
                    symbol.name = real.to_owned();
                    symbol.known = true;
                }
            }
            info.symbols.push(symbol);
        }
    }

    // Relocations.
    let relaent = get(DT_SCE_RELAENT).or_else(|| get(DT_RELAENT)).unwrap_or(24) as usize;
    if let (Some(off), Some(size)) = (get(DT_SCE_RELA), get(DT_SCE_RELASZ)) {
        if let Some(bytes) = fetch(Loc::Dynlib(off), size, "DT_SCE_RELA", &mut info.warnings) {
            info.rela = parse_relas(&bytes, relaent, &mut info.warnings, "rela");
        }
    } else if let (Some(va), Some(size)) = (get(DT_RELA), get(DT_RELASZ))
        && let Some(bytes) = fetch(Loc::Va(va), size, "DT_RELA", &mut info.warnings)
    {
        info.rela = parse_relas(&bytes, relaent, &mut info.warnings, "rela");
    }
    let pltrel = get(DT_SCE_PLTREL).or_else(|| get(DT_PLTREL)).unwrap_or(DT_RELA);
    if pltrel != DT_RELA {
        info.warnings.push(format!("PLT relocations use type {pltrel} (only DT_RELA is parsed)"));
    } else if let (Some(off), Some(size)) = (get(DT_SCE_JMPREL), get(DT_SCE_PLTRELSZ)) {
        if let Some(bytes) = fetch(Loc::Dynlib(off), size, "DT_SCE_JMPREL", &mut info.warnings) {
            info.jmprel = parse_relas(&bytes, 24, &mut info.warnings, "jmprel");
        }
    } else if let (Some(va), Some(size)) = (get(DT_JMPREL), get(DT_PLTRELSZ))
        && let Some(bytes) = fetch(Loc::Va(va), size, "DT_JMPREL", &mut info.warnings)
    {
        info.jmprel = parse_relas(&bytes, 24, &mut info.warnings, "jmprel");
    }
    let nsyms = info.symbols.len() as u32;
    let bad = info.rela.iter().chain(&info.jmprel).filter(|r| r.sym >= nsyms && r.sym != 0).count();
    if bad > 0 {
        info.warnings.push(format!("{bad} relocations reference symbols outside the symbol table"));
    }
    info.entries = tags;
    info
}

impl DynamicInfo {
    /// GOT-bound imports: every symbol-referencing JMPREL entry plus `GLOB_DAT`
    /// / `R_X86_64_64` relocations against undefined symbols.
    pub fn imports(&self) -> Vec<Import> {
        let mut out = Vec::new();
        let candidates = self.jmprel.iter().map(|r| (r, true)).chain(self.rela.iter().map(|r| (r, false)));
        for (rela, plt) in candidates {
            if rela.sym == 0 {
                continue;
            }
            if !plt && !matches!(rela.r_type, R_X86_64_GLOB_DAT | R_X86_64_64 | R_X86_64_JUMP_SLOT) {
                continue;
            }
            let Some(symbol) = self.symbols.get(rela.sym as usize) else { continue };
            if !plt && symbol.is_defined() {
                continue;
            }
            out.push(Import {
                slot: rela.offset,
                r_type: rela.r_type,
                sym: rela.sym,
                addend: rela.addend,
                name: symbol.name.clone(),
                raw_name: symbol.raw_name.clone(),
                nid: symbol.nid.clone(),
                known: symbol.known,
                library: symbol.library.clone(),
                module: symbol.module.clone(),
                plt,
            });
        }
        out
    }

    pub fn exports(&self) -> Vec<Export> {
        self.symbols
            .iter()
            .filter(|s| s.is_defined() && s.binding() != 0 && !s.raw_name.is_empty())
            .map(|s| Export {
                name: s.name.clone(),
                raw_name: s.raw_name.clone(),
                nid: s.nid.clone(),
                known: s.known,
                library: s.library.clone(),
                value: s.value,
                size: s.size,
                kind: s.kind(),
            })
            .collect()
    }

    pub fn summary_json(&self) -> Value {
        let imports = self.imports();
        let exports = self.exports();
        json!({
            "orbis_tags": self.orbis,
            "dynamic_entries": self.entries.len(),
            "needed": self.needed,
            "soname": self.soname,
            "original_filename": self.original_filename,
            "fingerprint": self.fingerprint,
            "module_info": self.module_info.as_ref().map(|m| json!({"id":m.id,"name":m.name,"version":format!("{}.{}",m.version_major,m.version_minor)})),
            "needed_modules": self.needed_modules.iter().map(|m| json!({"id":m.id,"name":m.name,"version":format!("{}.{}",m.version_major,m.version_minor)})).collect::<Vec<_>>(),
            "import_libraries": self.import_libs.iter().map(|l| json!({"id":l.id,"name":l.name,"version":l.version})).collect::<Vec<_>>(),
            "export_libraries": self.export_libs.iter().map(|l| json!({"id":l.id,"name":l.name,"version":l.version})).collect::<Vec<_>>(),
            "symbols": self.symbols.len(),
            "rela": self.rela.len(),
            "jmprel": self.jmprel.len(),
            "imports": imports.len(),
            "imports_named": imports.iter().filter(|i| i.known).count(),
            "exports": exports.len(),
            "exports_named": exports.iter().filter(|e| e.known).count(),
            "pltgot": self.pltgot.map(|v| format!("{v:#x}")),
            "warnings": self.warnings,
        })
    }
}

/// Where the dynamic data of a file image was found.
#[derive(Clone, Debug, Default)]
pub struct ImageDynamic {
    pub info: Option<DynamicInfo>,
    /// `(file offset, size)` of the `PT_SCE_DYNLIBDATA` blob used, if any.
    pub dynlib_range: Option<(u64, u64)>,
    /// `(file offset, size)` of the dynamic table used, if any.
    pub dynamic_range: Option<(u64, u64)>,
    pub source: &'static str,
    pub warnings: Vec<String>,
}

fn plausible_dynlib(blob: &[u8]) -> bool {
    !blob.starts_with(b"\x7fELF")
}

/// Locate and parse the dynamic information of a file image. Memory dumps
/// usually lack `PT_SCE_DYNLIBDATA` (it is not a loaded segment); that is
/// reported, not treated as an error.
pub fn parse_image(elf: &ElfFile<'_>, custom: Option<&HashMap<String, String>>) -> ImageDynamic {
    let mut out = ImageDynamic { source: "absent", ..Default::default() };
    let Some(dynamic_phdr) = elf.find(PT_DYNAMIC) else {
        out.warnings.push("No PT_DYNAMIC segment".into());
        return out;
    };
    // Prefer the file offset; fall back to the VA view when the offset is out of
    // range or implausible (memory dumps compact/move file offsets).
    let by_offset = elf
        .file_slice(dynamic_phdr.offset, dynamic_phdr.filesz)
        .filter(|b| plausible_dynamic(b))
        .map(|b| (b, dynamic_phdr.offset, "file_offset"));
    let by_va = (dynamic_phdr.vaddr != 0)
        .then(|| elf.va_slice(dynamic_phdr.vaddr, dynamic_phdr.filesz.max(dynamic_phdr.memsz)))
        .flatten()
        .filter(|b| plausible_dynamic(b))
        .map(|b| (b, elf.va_to_offset(dynamic_phdr.vaddr).unwrap_or(0), "loaded_segment"));
    let Some((dynamic, dyn_offset, source)) = by_offset.or(by_va) else {
        out.warnings.push(
            "PT_DYNAMIC data is not present (or not plausible) in this image; memory dumps only contain PT_LOAD data".into(),
        );
        return out;
    };
    out.dynamic_range = Some((dyn_offset, dynamic.len() as u64));
    out.source = source;
    let dynlib = elf.find(PT_SCE_DYNLIBDATA).and_then(|p| {
        let found = elf
            .file_slice(p.offset, p.filesz)
            .filter(|b| plausible_dynlib(b))
            .map(|b| (b, p.offset));
        if found.is_none() {
            out.warnings.push(format!(
                "PT_SCE_DYNLIBDATA ({:#x} bytes at file offset {:#x}) is not in this image; Orbis symbol/relocation tables unavailable",
                p.filesz, p.offset
            ));
        }
        found
    });
    out.dynlib_range = dynlib.map(|(b, off)| (off, b.len() as u64));
    let mut reader = |va: u64, len: usize| elf.va_slice(va, len as u64).map(<[u8]>::to_vec);
    let mut sources = DynSources { dynamic, dynlib: dynlib.map(|(b, _)| b), va_reader: &mut reader };
    out.info = Some(parse_dynamic(&mut sources, custom));
    out
}

/// SysV ELF hash (gABI).
pub fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in name {
        h = (h << 4).wrapping_add(u32::from(c));
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Build a SysV `DT_HASH` table for `names` (index 0 must be the null symbol).
pub fn build_sysv_hash(names: &[&str]) -> Vec<u8> {
    let nchain = names.len() as u32;
    let nbucket = (nchain / 2).max(1);
    let mut buckets = vec![0u32; nbucket as usize];
    let mut chains = vec![0u32; nchain as usize];
    for (index, name) in names.iter().enumerate().skip(1) {
        let bucket = (elf_hash(name.as_bytes()) % nbucket) as usize;
        chains[index] = buckets[bucket];
        buckets[bucket] = index as u32;
    }
    let mut out = Vec::with_capacity(8 + 4 * (buckets.len() + chains.len()));
    out.extend(nbucket.to_le_bytes());
    out.extend(nchain.to_le_bytes());
    for value in buckets.iter().chain(&chains) {
        out.extend(value.to_le_bytes());
    }
    out
}

/// Synthetic Orbis-style ELF images for offline tests across the dumping modules.
#[cfg(test)]
pub mod testelf {
    use super::*;

    pub struct Spec<'a> {
        pub e_type: u16,
        pub module_name: &'a str,
        /// `(symbol name, static VA)`; encoded as `NID#A#A`.
        pub exports: Vec<(&'a str, u64)>,
        /// `(symbol name, GOT slot VA)`; encoded as `NID#B#B` (JUMP_SLOT).
        pub imports: Vec<(&'a str, u64)>,
        /// `(slot VA, addend)` RELATIVE relocations.
        pub relative: Vec<(u64, u64)>,
        /// `(VA, u64 value)` stored in the image (e.g. runtime GOT contents).
        pub words: Vec<(u64, u64)>,
        pub needed_module: &'a str,
        pub import_lib: &'a str,
    }

    impl Default for Spec<'_> {
        fn default() -> Self {
            Self {
                e_type: ET_SCE_DYNEXEC,
                module_name: "fixture",
                exports: Vec::new(),
                imports: Vec::new(),
                relative: Vec::new(),
                words: Vec::new(),
                needed_module: "libkernel",
                import_lib: "libkernel",
            }
        }
    }

    pub const TEXT_END: u64 = 0x1000;
    pub const DATA_VA: u64 = 0x1000;
    pub const DYNLIB_OFF: u64 = 0x2000;
    pub const DYNAMIC_OFF: u64 = 0x3000;
    pub const IMAGE_SIZE: usize = 0x4000;
    pub const EH_HDR: u64 = 0x800;
    pub const EH_FRAME: u64 = 0x840;
    pub const INIT_ARRAY: u64 = 0x1800;

    /// Layout: header+text RX load [0,0x1000); RW load [0x1000,0x4000) file, memsz
    /// 0x4800 (bss tail). The dynlib blob (0x2000) and dynamic table (0x3000) sit
    /// inside the RW load so they survive `memory_elf_dump` and live parsing.
    pub fn build(spec: &Spec<'_>) -> Vec<u8> {
        let mut image = vec![0u8; IMAGE_SIZE];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        image[7] = 9; // ELFOSABI_FREEBSD
        image[16..18].copy_from_slice(&spec.e_type.to_le_bytes());
        image[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        image[20..24].copy_from_slice(&1u32.to_le_bytes());
        image[24..32].copy_from_slice(&0x400u64.to_le_bytes());
        image[32..40].copy_from_slice(&64u64.to_le_bytes());
        image[52..54].copy_from_slice(&64u16.to_le_bytes());
        image[54..56].copy_from_slice(&56u16.to_le_bytes());

        // --- dynlib blob: strtab @0, symtab @0x400, rela @0x800, jmprel @0xa00, hash @0xc00
        let mut strtab = vec![0u8];
        let mut add_str = |s: &str| {
            let at = strtab.len() as u64;
            strtab.extend(s.as_bytes());
            strtab.push(0);
            at
        };
        let needed_mod = add_str(spec.needed_module);
        let import_lib = add_str(spec.import_lib);
        let own_mod = add_str(spec.module_name);
        let needed_prx = add_str(&format!("{}.prx", spec.needed_module));
        let original = add_str(&format!("{}.elf", spec.module_name));
        let mut symtab = vec![0u8; 24];
        let mut push_sym = |name_off: u64, info: u8, shndx: u16, value: u64| {
            let mut sym = [0u8; 24];
            sym[0..4].copy_from_slice(&(name_off as u32).to_le_bytes());
            sym[4] = info;
            sym[6..8].copy_from_slice(&shndx.to_le_bytes());
            sym[8..16].copy_from_slice(&value.to_le_bytes());
            sym[16..24].copy_from_slice(&8u64.to_le_bytes());
            symtab.extend(sym);
        };
        let mut jmprel = Vec::new();
        for (index, (name, slot)) in (1u32..).zip(spec.imports.iter()) {
            let off = add_str(&format!("{}#B#B", crate::nid::encode_nid(name)));
            push_sym(off, 0x12, 0, 0);
            jmprel.extend(Rela { offset: *slot, r_type: R_X86_64_JUMP_SLOT, sym: index, addend: 0 }.encode());
        }
        for (name, value) in &spec.exports {
            let off = add_str(&format!("{}#A#A", crate::nid::encode_nid(name)));
            push_sym(off, 0x12, 9, *value);
        }
        let mut rela = Vec::new();
        for (slot, addend) in &spec.relative {
            rela.extend(Rela { offset: *slot, r_type: R_X86_64_RELATIVE, sym: 0, addend: *addend as i64 }.encode());
        }
        let blob = DYNLIB_OFF as usize;
        assert!(strtab.len() <= 0x400 && symtab.len() <= 0x400 && rela.len() <= 0x200 && jmprel.len() <= 0x200);
        image[blob..blob + strtab.len()].copy_from_slice(&strtab);
        image[blob + 0x400..blob + 0x400 + symtab.len()].copy_from_slice(&symtab);
        image[blob + 0x800..blob + 0x800 + rela.len()].copy_from_slice(&rela);
        image[blob + 0xa00..blob + 0xa00 + jmprel.len()].copy_from_slice(&jmprel);
        // fingerprint @0xe00
        image[blob + 0xe00..blob + 0xe14].copy_from_slice(&[0xab; 20]);

        let id_val = |name_off: u64, id: u64| name_off | (1u64 << 40) | (id << 48);
        let dynamic: Vec<(u64, u64)> = vec![
            (DT_NEEDED, needed_prx),
            (DT_SCE_ORIGINAL_FILENAME, original),
            (DT_SCE_FINGERPRINT, 0xe00),
            (DT_SCE_MODULE_INFO, id_val(own_mod, 0)),
            (DT_SCE_NEEDED_MODULE, id_val(needed_mod, 1)),
            (DT_SCE_EXPORT_LIB, own_mod | (1 << 32)),
            (DT_SCE_IMPORT_LIB, import_lib | (1 << 32) | (1 << 48)),
            (DT_SCE_STRTAB, 0),
            (DT_SCE_STRSZ, strtab.len() as u64),
            (DT_SCE_SYMTAB, 0x400),
            (DT_SCE_SYMENT, 24),
            (DT_SCE_SYMTABSZ, symtab.len() as u64),
            (DT_SCE_RELA, 0x800),
            (DT_SCE_RELASZ, rela.len() as u64),
            (DT_SCE_RELAENT, 24),
            (DT_SCE_JMPREL, 0xa00),
            (DT_SCE_PLTRELSZ, jmprel.len() as u64),
            (DT_SCE_PLTREL, DT_RELA),
            (DT_SCE_PLTGOT, DATA_VA),
            (DT_INIT_ARRAY, INIT_ARRAY),
            (DT_INIT_ARRAYSZ, 8),
            (DT_NULL, 0),
        ];
        let mut at = DYNAMIC_OFF as usize;
        for (tag, value) in &dynamic {
            image[at..at + 8].copy_from_slice(&tag.to_le_bytes());
            image[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
            at += 16;
        }
        let dynamic_size = (dynamic.len() * 16) as u64;

        // eh_frame_hdr: version 1, eh_frame_ptr pcrel|sdata4, fde_count udata4, table datarel|sdata4
        let eh = EH_HDR as usize;
        image[eh] = 1;
        image[eh + 1] = 0x1b;
        image[eh + 2] = 0x03;
        image[eh + 3] = 0x3b;
        let rel = (EH_FRAME as i64 - (EH_HDR as i64 + 4)) as i32;
        image[eh + 4..eh + 8].copy_from_slice(&rel.to_le_bytes());
        // eh_frame: one 0x14-byte CIE then terminator.
        let ef = EH_FRAME as usize;
        image[ef..ef + 4].copy_from_slice(&0x14u32.to_le_bytes());
        image[ef + 8] = 1; // version
        // code at entry
        image[0x400..0x406].copy_from_slice(&[0xb8, 0x07, 0, 0, 0, 0xc3]);
        for (va, value) in &spec.words {
            let at = *va as usize;
            image[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }

        let phdrs = [
            Phdr { p_type: PT_LOAD, flags: 5, offset: 0, vaddr: 0, filesz: TEXT_END, memsz: TEXT_END, align: 0x4000, ..Default::default() },
            Phdr { p_type: PT_LOAD, flags: 6, offset: 0x1000, vaddr: DATA_VA, filesz: 0x3000, memsz: 0x3800, align: 0x4000, ..Default::default() },
            Phdr { p_type: PT_DYNAMIC, flags: 6, offset: DYNAMIC_OFF, vaddr: DYNAMIC_OFF, filesz: dynamic_size, memsz: dynamic_size, align: 8, ..Default::default() },
            Phdr { p_type: PT_SCE_DYNLIBDATA, flags: 4, offset: DYNLIB_OFF, vaddr: 0, filesz: 0x1000, memsz: 0, align: 16, ..Default::default() },
            Phdr { p_type: PT_GNU_EH_FRAME, flags: 4, offset: EH_HDR, vaddr: EH_HDR, filesz: 0x10, memsz: 0x10, align: 4, ..Default::default() },
        ];
        image[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for (i, p) in phdrs.iter().enumerate() {
            let at = 64 + 56 * i;
            image[at..at + 56].copy_from_slice(&p.encode());
        }
        image
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip() {
        for id in [0u16, 1, 63, 64, 4095, 65535] {
            assert_eq!(decode_id(&encode_id(id)), Some(id));
        }
        assert_eq!(decode_id("A"), Some(0));
        assert_eq!(decode_id("B"), Some(1));
        assert_eq!(decode_id("BA"), Some(64));
        assert_eq!(decode_id("#"), None);
    }

    #[test]
    fn parses_orbis_dynamic_imports_exports() {
        let spec = testelf::Spec {
            exports: vec![("sceKernelUsleep", 0x400)],
            imports: vec![("sceKernelGetProcessTime", 0x1000), ("totallyUnknownSymbolXyz", 0x1008)],
            relative: vec![(testelf::INIT_ARRAY, 0x400)],
            ..Default::default()
        };
        let image = testelf::build(&spec);
        let elf = ElfFile::parse(&image).unwrap();
        assert_eq!(type_name(elf.e_type), "ET_SCE_DYNEXEC");
        let parsed = parse_image(&elf, None);
        let info = parsed.info.expect("dynamic info");
        assert!(info.orbis, "{:?}", info.warnings);
        assert_eq!(info.needed, vec!["libkernel.prx"]);
        assert_eq!(info.original_filename.as_deref(), Some("fixture.elf"));
        assert_eq!(info.fingerprint.as_deref(), Some("ab".repeat(20).as_str()));
        assert_eq!(info.needed_modules[0].name, "libkernel");
        assert_eq!(info.needed_modules[0].id, 1);
        assert_eq!(info.import_libs[0].name, "libkernel");
        assert_eq!(info.symbols.len(), 4);
        let imports = info.imports();
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].name, "sceKernelGetProcessTime");
        assert!(imports[0].known);
        assert_eq!(imports[0].library.as_deref(), Some("libkernel"));
        assert_eq!(imports[0].module.as_deref(), Some("libkernel"));
        assert_eq!(imports[0].slot, 0x1000);
        assert!(!imports[1].known);
        assert!(imports[1].raw_name.ends_with("#B#B"));
        let exports = info.exports();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name, "sceKernelUsleep");
        assert_eq!(exports[0].library.as_deref(), Some("fixture"));
        assert_eq!(info.rela.len(), 1);
        assert_eq!(info.rela[0].r_type, R_X86_64_RELATIVE);
        assert_eq!(info.pltgot, Some(0x1000));
        assert_eq!(info.init_array, Some((testelf::INIT_ARRAY, 8)));
    }

    #[test]
    fn tolerates_truncated_and_garbage_images() {
        let image = testelf::build(&testelf::Spec::default());
        // Truncate before the dynlib blob: PT_DYNAMIC also gone -> absent, no panic.
        let short = &image[..0x1800];
        let elf = ElfFile::parse(short).unwrap();
        let parsed = parse_image(&elf, None);
        assert!(parsed.info.is_none());
        assert!(!parsed.warnings.is_empty());
        assert!(ElfFile::parse(b"not an elf").is_err());
        // Garbage dynamic table is rejected.
        assert!(!plausible_dynamic(&[0xffu8; 64]));
        assert!(plausible_dynamic(&[&5u64.to_le_bytes()[..], &[0u8; 8], &[0u8; 16]].concat()));
    }

    #[test]
    fn sysv_hash_is_consistent() {
        assert_eq!(elf_hash(b"printf"), 0x077905a6);
        let table = build_sysv_hash(&["", "a", "b", "c"]);
        assert_eq!(rd32(&table, 4), Some(4));
    }
}
