//! FreeBSD-style ELF64 core files (`ET_CORE`) for offline gdb/IDA analysis.
//!
//! Layout follows FreeBSD `sys/kern/imgact_elf.c` (`__elfN(coredump)`):
//! ELF header, one `PT_NOTE`, then one `PT_LOAD` per dumped map. Notes use the
//! owner name `"FreeBSD"` and 4-byte padding of name and descriptor
//! (`ELF_NOTE_ROUNDSIZE` = 4 in imgact_elf.c). Note order mirrors FreeBSD:
//! `NT_PRPSINFO`, then per thread `NT_PRSTATUS`, `NT_FPREGSET`, `NT_THRMISC`
//! and (extra, as FreeBSD >= 9 does) `NT_X86_XSTATE`.
//!
//! Descriptor layouts (FreeBSD amd64, `sys/sys/procfs.h`, `sys/amd64/include/reg.h`):
//! * `struct reg` (176 bytes): r15 r14 r13 r12 r11 r10 r9 r8 rdi rsi rbp rbx rdx
//!   rcx rax (u64 each), trapno(u32) fs(u16) gs(u16) err(u32) es(u16) ds(u16),
//!   rip cs rflags rsp ss (u64 each). This is byte-for-byte the 176-byte block
//!   ps4debug returns for `CMD_DEBUG_GETREGS` (see `crate::debugger::registers`),
//!   so it is copied verbatim.
//! * `prstatus_t` (`PRSTATUS_VERSION` 1, 224 bytes): int pr_version; [pad 4];
//!   size_t pr_statussz; size_t pr_gregsetsz; size_t pr_fpregsetsz;
//!   int pr_osreldate; int pr_cursig; pid_t pr_pid (the LWP id); [pad 4];
//!   gregset_t pr_reg (struct reg).
//! * `prpsinfo_t` (`PRPSINFO_VERSION` 1, 120 bytes): int pr_version; [pad 4];
//!   size_t pr_psinfosz; char pr_fname[PRFNAMESZ+1 = 17];
//!   char pr_psargs[PRARGSZ+1 = 81]; [pad 2]; pid_t pr_pid.
//! * `struct fpreg` (amd64, 512 bytes) is the FXSAVE image; ps4debug returns a
//!   832-byte `savefpu_ymm` (FXSAVE 512 + XSAVE header 64 + YMM_Hi128 256) whose
//!   first 512 bytes are exactly that.
//! * `NT_X86_XSTATE` (0x202) carries the XSAVE area; gdb (`i386-fbsd-tdep.c`,
//!   `I386_FBSD_XSAVE_XCR0_OFFSET` = 464) reads XCR0 from the software-reserved
//!   bytes at offset 464, which we fill with the XSTATE_BV-derived mask.
//! * `struct thrmisc` (24 bytes): char pr_tname[MAXCOMLEN+1 = 20]; u_int _pad.
//!
//! Note type numbers: NT_PRSTATUS 1, NT_FPREGSET 2, NT_PRPSINFO 3, NT_THRMISC 7,
//! NT_X86_XSTATE 0x202 (FreeBSD `sys/sys/elf_common.h`).

use crate::Result;
use serde_json::{Value, json};
use std::io::Write;

pub const NT_PRSTATUS: u32 = 1;
pub const NT_FPREGSET: u32 = 2;
pub const NT_PRPSINFO: u32 = 3;
pub const NT_THRMISC: u32 = 7;
pub const NT_X86_XSTATE: u32 = 0x202;
pub const PRSTATUS_SIZE: usize = 224;
pub const PRPSINFO_SIZE: usize = 120;
pub const GREGSET_SIZE: usize = 176;
pub const FPREGSET_SIZE: usize = 512;
pub const XSTATE_SIZE: usize = 832;
const XCR0_OFFSET: usize = 464;
/// `e_ident[EI_OSABI]` = ELFOSABI_FREEBSD so gdb selects the FreeBSD core handler.
const ELFOSABI_FREEBSD: u8 = 9;
const PAGE: u64 = 0x1000;

#[derive(Clone, Debug, Default)]
pub struct CoreThread {
    pub lwpid: u32,
    pub name: String,
    /// 176-byte FreeBSD `struct reg`.
    pub gp: Vec<u8>,
    /// 832-byte `savefpu_ymm`, when available.
    pub fpu: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub struct CoreRegion {
    pub start: u64,
    pub size: u64,
    /// `VM_PROT_*` bits as reported by ps4debug maps (1 read, 2 write, 4 exec).
    pub protection: u64,
    pub name: String,
    /// `false` keeps the `PT_LOAD` (memsz only) without file data.
    pub include_data: bool,
}

#[derive(Clone, Debug, Default)]
pub struct CoreProcess {
    pub pid: u32,
    pub name: String,
    pub args: String,
}

pub fn note(name: &str, n_type: u32, desc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + name.len() + desc.len() + 8);
    let namesz = name.len() as u32 + 1;
    out.extend(namesz.to_le_bytes());
    out.extend((desc.len() as u32).to_le_bytes());
    out.extend(n_type.to_le_bytes());
    out.extend(name.as_bytes());
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend(desc);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn copy_cstr(dst: &mut [u8], text: &str) {
    let bytes = text.as_bytes();
    let n = bytes.len().min(dst.len().saturating_sub(1));
    dst[..n].copy_from_slice(&bytes[..n]);
}

pub fn prpsinfo(process: &CoreProcess) -> Vec<u8> {
    let mut out = vec![0u8; PRPSINFO_SIZE];
    out[0..4].copy_from_slice(&1i32.to_le_bytes());
    out[8..16].copy_from_slice(&(PRPSINFO_SIZE as u64).to_le_bytes());
    copy_cstr(&mut out[16..33], &process.name);
    copy_cstr(&mut out[33..114], &process.args);
    out[116..120].copy_from_slice(&process.pid.to_le_bytes());
    out
}

pub fn prstatus(thread: &CoreThread, cursig: i32) -> Vec<u8> {
    let mut out = vec![0u8; PRSTATUS_SIZE];
    out[0..4].copy_from_slice(&1i32.to_le_bytes());
    out[8..16].copy_from_slice(&(PRSTATUS_SIZE as u64).to_le_bytes());
    out[16..24].copy_from_slice(&(GREGSET_SIZE as u64).to_le_bytes());
    out[24..32].copy_from_slice(&(FPREGSET_SIZE as u64).to_le_bytes());
    // pr_osreldate (32..36) left 0: the Orbis kernel's osreldate is not exposed by ps4debug.
    out[36..40].copy_from_slice(&cursig.to_le_bytes());
    out[40..44].copy_from_slice(&thread.lwpid.to_le_bytes());
    let n = thread.gp.len().min(GREGSET_SIZE);
    out[48..48 + n].copy_from_slice(&thread.gp[..n]);
    out
}

pub fn thrmisc(name: &str) -> Vec<u8> {
    let mut out = vec![0u8; 24];
    copy_cstr(&mut out[..20], name);
    out
}

pub fn xstate(fpu: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; XSTATE_SIZE];
    let n = fpu.len().min(XSTATE_SIZE);
    out[..n].copy_from_slice(&fpu[..n]);
    // XSTATE_BV at 512; XCR0 = X87|SSE plus whatever components the header marks.
    let xstate_bv = u64::from_le_bytes(out[512..520].try_into().unwrap());
    let xcr0 = 0x3 | (xstate_bv & 0x7);
    out[XCR0_OFFSET..XCR0_OFFSET + 8].copy_from_slice(&xcr0.to_le_bytes());
    out
}

pub fn build_notes(process: &CoreProcess, threads: &[CoreThread], cursig: i32) -> Vec<u8> {
    let mut out = note("FreeBSD", NT_PRPSINFO, &prpsinfo(process));
    for thread in threads {
        out.extend(note("FreeBSD", NT_PRSTATUS, &prstatus(thread, cursig)));
        if let Some(fpu) = &thread.fpu {
            let mut fx = vec![0u8; FPREGSET_SIZE];
            let n = fpu.len().min(FPREGSET_SIZE);
            fx[..n].copy_from_slice(&fpu[..n]);
            out.extend(note("FreeBSD", NT_FPREGSET, &fx));
        }
        out.extend(note("FreeBSD", NT_THRMISC, &thrmisc(&thread.name)));
        if let Some(fpu) = &thread.fpu
            && fpu.len() >= XSTATE_SIZE
        {
            out.extend(note("FreeBSD", NT_X86_XSTATE, &xstate(fpu)));
        }
    }
    out
}

fn elf_flags(protection: u64) -> u32 {
    // VM_PROT_READ 1 / WRITE 2 / EXECUTE 4 -> PF_R 4 / PF_W 2 / PF_X 1.
    (if protection & 1 != 0 { 4 } else { 0 })
        | (if protection & 2 != 0 { 2 } else { 0 })
        | (if protection & 4 != 0 { 1 } else { 0 })
}

/// Precomputed file layout of a core.
pub struct CoreLayout {
    pub head: Vec<u8>,
    pub notes_offset: u64,
    pub notes: Vec<u8>,
    /// `(region, file offset)`; offset is meaningful only when `include_data`.
    pub segments: Vec<(CoreRegion, u64)>,
    pub total_size: u64,
}

pub fn layout(process: &CoreProcess, threads: &[CoreThread], regions: &[CoreRegion], cursig: i32) -> CoreLayout {
    let notes = build_notes(process, threads, cursig);
    let phnum = 1 + regions.len();
    let notes_offset = 64 + 56 * phnum as u64;
    let mut cursor = (notes_offset + notes.len() as u64).div_ceil(PAGE) * PAGE;
    let mut segments = Vec::with_capacity(regions.len());
    for region in regions {
        segments.push((region.clone(), cursor));
        if region.include_data {
            cursor += region.size.div_ceil(PAGE) * PAGE;
        }
    }
    let mut head = vec![0u8; notes_offset as usize];
    head[..4].copy_from_slice(b"\x7fELF");
    head[4] = 2;
    head[5] = 1;
    head[6] = 1;
    head[7] = ELFOSABI_FREEBSD;
    head[16..18].copy_from_slice(&4u16.to_le_bytes()); // ET_CORE
    head[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    head[20..24].copy_from_slice(&1u32.to_le_bytes());
    head[32..40].copy_from_slice(&64u64.to_le_bytes());
    head[52..54].copy_from_slice(&64u16.to_le_bytes());
    head[54..56].copy_from_slice(&56u16.to_le_bytes());
    head[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());
    head[58..60].copy_from_slice(&64u16.to_le_bytes());
    let note_phdr = crate::orbisdyn::Phdr {
        p_type: crate::orbisdyn::PT_NOTE,
        flags: 4,
        offset: notes_offset,
        filesz: notes.len() as u64,
        align: 4,
        ..Default::default()
    };
    head[64..120].copy_from_slice(&note_phdr.encode());
    for (index, (region, offset)) in segments.iter().enumerate() {
        let phdr = crate::orbisdyn::Phdr {
            p_type: crate::orbisdyn::PT_LOAD,
            flags: elf_flags(region.protection),
            offset: if region.include_data { *offset } else { 0 },
            vaddr: region.start,
            filesz: if region.include_data { region.size } else { 0 },
            memsz: region.size,
            align: PAGE,
            ..Default::default()
        };
        let at = 64 + 56 * (index + 1);
        head[at..at + 56].copy_from_slice(&phdr.encode());
    }
    CoreLayout { head, notes_offset, notes, segments, total_size: cursor }
}

/// Stream a core described by `layout` into `writer`, reading region data with
/// `read(address, length)` in `chunk`-sized pieces. Failed reads are zero-filled
/// and returned as `(address, length, error)` rows; they never abort the core.
pub fn write_core<W: Write>(
    writer: &mut W,
    layout: &CoreLayout,
    chunk: usize,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Vec<Value>> {
    let chunk = chunk.max(PAGE as usize);
    let mut written = 0u64;
    let mut failures = Vec::new();
    let pad_to = |writer: &mut W, written: &mut u64, target: u64| -> Result<()> {
        if target > *written {
            let zeros = vec![0u8; (target - *written).min(1 << 20) as usize];
            while *written < target {
                let n = ((target - *written) as usize).min(zeros.len());
                writer.write_all(&zeros[..n])?;
                *written += n as u64;
            }
        }
        Ok(())
    };
    writer.write_all(&layout.head)?;
    written += layout.head.len() as u64;
    writer.write_all(&layout.notes)?;
    written += layout.notes.len() as u64;
    for (region, offset) in &layout.segments {
        if !region.include_data {
            continue;
        }
        pad_to(writer, &mut written, *offset)?;
        let mut done = 0u64;
        while done < region.size {
            let ask = ((region.size - done) as usize).min(chunk);
            let address = region.start + done;
            let bytes = match read(address, ask) {
                Ok(bytes) if bytes.len() == ask => bytes,
                Ok(bytes) => {
                    failures.push(json!({"address":format!("{address:#x}"),"length":ask,"error":format!("short read ({} bytes)", bytes.len())}));
                    let mut padded = bytes;
                    padded.resize(ask, 0);
                    padded
                }
                Err(error) => {
                    failures.push(json!({"address":format!("{address:#x}"),"length":ask,"error":error.to_string()}));
                    vec![0u8; ask]
                }
            };
            writer.write_all(&bytes)?;
            written += ask as u64;
            done += ask as u64;
        }
    }
    pad_to(writer, &mut written, layout.total_size)?;
    Ok(failures)
}

/// Parsed note (for tests and validation tools).
#[derive(Debug, Clone)]
pub struct ParsedNote {
    pub name: String,
    pub n_type: u32,
    pub desc: Vec<u8>,
}

pub fn parse_notes(bytes: &[u8]) -> Vec<ParsedNote> {
    let mut notes = Vec::new();
    let mut at = 0usize;
    while at + 12 <= bytes.len() {
        let namesz = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let descsz = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        let n_type = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap());
        let name_start = at + 12;
        let desc_start = name_start + namesz.div_ceil(4) * 4;
        let end = desc_start + descsz.div_ceil(4) * 4;
        if desc_start + descsz > bytes.len() {
            break;
        }
        let name = String::from_utf8_lossy(&bytes[name_start..name_start + namesz.saturating_sub(1)]).into_owned();
        notes.push(ParsedNote { name, n_type, desc: bytes[desc_start..desc_start + descsz].to_vec() });
        at = end;
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_match_freebsd_sizes_and_offsets() {
        let mut gp = vec![0u8; 176];
        gp[136..144].copy_from_slice(&0x1234u64.to_le_bytes()); // rip
        let thread = CoreThread { lwpid: 101, name: "main".into(), gp, fpu: Some(vec![0u8; 832]) };
        let status = prstatus(&thread, 5);
        assert_eq!(status.len(), 224);
        assert_eq!(u32::from_le_bytes(status[40..44].try_into().unwrap()), 101);
        assert_eq!(u64::from_le_bytes(status[48 + 136..48 + 144].try_into().unwrap()), 0x1234);
        let info = prpsinfo(&CoreProcess { pid: 77, name: "eboot.bin.with.long.name".into(), args: "/app0/eboot.bin".into() });
        assert_eq!(info.len(), 120);
        assert_eq!(info[32], 0, "pr_fname NUL-terminated within 17 bytes");
        assert_eq!(&info[33..48], b"/app0/eboot.bin");
        let x = xstate(&[0u8; 832]);
        assert_eq!(u64::from_le_bytes(x[464..472].try_into().unwrap()), 3);
        let notes = build_notes(&CoreProcess::default(), &[thread], 0);
        let parsed = parse_notes(&notes);
        let types: Vec<u32> = parsed.iter().map(|n| n.n_type).collect();
        assert_eq!(types, vec![NT_PRPSINFO, NT_PRSTATUS, NT_FPREGSET, NT_THRMISC, NT_X86_XSTATE]);
        assert!(parsed.iter().all(|n| n.name == "FreeBSD"));
    }

    #[test]
    fn core_streams_with_partial_failures() {
        let regions = vec![
            CoreRegion { start: 0x10000, size: 0x2000, protection: 5, name: "text".into(), include_data: true },
            CoreRegion { start: 0x20000, size: 0x1000, protection: 3, name: "skipped".into(), include_data: false },
            CoreRegion { start: 0x30000, size: 0x1800, protection: 3, name: "heap".into(), include_data: true },
        ];
        let layout = layout(&CoreProcess { pid: 1, ..Default::default() }, &[], &regions, 0);
        let mut out = Vec::new();
        let failures = write_core(&mut out, &layout, 0x1000, |address, len| {
            anyhow::ensure!(address != 0x31000, "unreadable page");
            Ok(vec![0xcc; len])
        })
        .unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(out.len() as u64, layout.total_size);
        let elf = crate::orbisdyn::ElfFile::parse(&out).unwrap();
        assert_eq!(elf.e_type, 4);
        assert_eq!(elf.phdrs.len(), 4);
        assert_eq!(elf.phdrs[2].filesz, 0);
        assert_eq!(elf.phdrs[2].memsz, 0x1000);
        let heap = &elf.phdrs[3];
        assert_eq!(heap.flags, 6);
        let data = &out[heap.offset as usize..(heap.offset + heap.filesz) as usize];
        assert!(data[..0x1000].iter().all(|b| *b == 0xcc));
        assert!(data[0x1000..].iter().all(|b| *b == 0));
    }
}
