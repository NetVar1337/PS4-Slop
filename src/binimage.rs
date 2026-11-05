//! Address-mapped image abstraction for native static analysis.
//!
//! An [`Image`] is a set of segments (ELF `PT_LOAD`s, or live module segments
//! read from a process) plus whatever symbol / import / unwind metadata the
//! container provides. All parsing is bounds-checked and capped; nothing here
//! touches the console.

use anyhow::{anyhow, ensure};
use std::collections::BTreeMap;

use crate::Result;

/// `PF_X`.
pub const FLAG_EXEC: u32 = 1;
/// `PF_W`.
pub const FLAG_WRITE: u32 = 2;
/// `PF_R`.
pub const FLAG_READ: u32 = 4;

const MAX_SYMBOLS: usize = 500_000;
const MAX_RELOCATIONS: usize = 500_000;
const MAX_PHDRS: usize = 256;
const MAX_SECTIONS: usize = 4096;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const PT_SCE_DYNLIBDATA: u32 = 0x6100_0000;
const PT_SCE_RELRO: u32 = 0x6100_0010;

#[derive(Clone, Debug)]
pub struct Segment {
    pub vaddr: u64,
    pub memsz: u64,
    /// File-backed bytes (at most `memsz`); `bss` tails are not materialised.
    pub data: Vec<u8>,
    pub flags: u32,
}

impl Segment {
    pub fn exec(&self) -> bool {
        self.flags & FLAG_EXEC != 0
    }
    pub fn data_end(&self) -> u64 {
        self.vaddr + self.data.len() as u64
    }
}

#[derive(Clone, Debug)]
pub struct Symbol {
    /// Display name: NID-demangled when the built-in dictionary knows it.
    pub name: String,
    pub raw: String,
    pub value: u64,
    pub size: u64,
    pub kind: u8,
    pub defined: bool,
    pub table: &'static str,
    pub nid: Option<String>,
    pub library: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Image {
    pub base: u64,
    pub entry: Option<u64>,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    /// GOT / import slot VA -> imported symbol display name.
    pub imports: BTreeMap<u64, String>,
    /// `.eh_frame` location `(vaddr, size)`.
    pub eh_frame: Option<(u64, u64)>,
    /// `.eh_frame_hdr` location `(vaddr, size)` (used when no section headers).
    pub eh_frame_hdr: Option<(u64, u64)>,
    pub sha256: Option<String>,
    pub name: Option<String>,
    pub kind: &'static str,
    pub notes: Vec<String>,
}

fn le16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        data.get(at..at + 2).ok_or_else(|| anyhow!("ELF truncated at {at:#x}"))?.try_into()?,
    ))
}
fn le32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4).ok_or_else(|| anyhow!("ELF truncated at {at:#x}"))?.try_into()?,
    ))
}
fn le64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(at..at + 8).ok_or_else(|| anyhow!("ELF truncated at {at:#x}"))?.try_into()?,
    ))
}

fn cstr(data: &[u8], start: usize, end: usize) -> String {
    let end = end.min(data.len());
    if start >= end {
        return String::new();
    }
    let slice = &data[start..end];
    let len = slice.iter().position(|b| *b == 0).unwrap_or(slice.len()).min(4096);
    String::from_utf8_lossy(&slice[..len]).into_owned()
}

/// `(display name, nid, library)` for a raw (possibly `NID#lib#mod`) name.
pub fn demangle(raw: &str) -> (String, Option<String>, Option<String>) {
    match crate::nid::split_orbis_symbol(raw) {
        Some((nid, library, _)) => {
            let name = crate::nid::lookup_nid(raw, None)
                .map(str::to_owned)
                .unwrap_or_else(|| raw.to_owned());
            (name, Some(nid.to_owned()), library.map(str::to_owned))
        }
        None => (raw.to_owned(), None, None),
    }
}

impl Image {
    /// Flat (non-ELF) bytes mapped at `base` as one executable segment.
    pub fn from_raw(base: u64, data: Vec<u8>, name: Option<String>) -> Self {
        let sha256 = Some(crate::config::sha256_hex(&data));
        Image {
            base,
            segments: vec![Segment { vaddr: base, memsz: data.len() as u64, data, flags: FLAG_READ | FLAG_EXEC }],
            sha256,
            name,
            kind: "raw",
            ..Default::default()
        }
    }

    /// Live module: segments already read from process memory.
    pub fn from_segments(mut segments: Vec<Segment>, name: Option<String>) -> Self {
        segments.sort_by_key(|segment| segment.vaddr);
        let base = segments.first().map_or(0, |segment| segment.vaddr);
        Image { base, segments, name, kind: "live", ..Default::default() }
    }

    pub fn segment_at(&self, va: u64) -> Option<&Segment> {
        self.segments.iter().find(|segment| segment.vaddr <= va && va < segment.data_end())
    }

    /// Bytes from `va` to the end of its segment's file-backed data.
    pub fn bytes_from(&self, va: u64) -> Option<&[u8]> {
        let segment = self.segment_at(va)?;
        segment.data.get((va - segment.vaddr) as usize..)
    }

    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        self.bytes_from(va)?.get(..len)
    }

    pub fn is_exec(&self, va: u64) -> bool {
        self.segment_at(va).is_some_and(Segment::exec)
    }

    /// Whether `va` is inside any segment's mapped (`memsz`) extent.
    pub fn contains(&self, va: u64) -> bool {
        self.segments
            .iter()
            .any(|segment| segment.vaddr <= va && va < segment.vaddr.saturating_add(segment.memsz))
    }

    pub fn exec_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|segment| segment.exec())
    }

    /// Highest mapped address (exclusive).
    pub fn end(&self) -> u64 {
        self.segments.iter().map(|segment| segment.vaddr.saturating_add(segment.memsz)).max().unwrap_or(self.base)
    }

    /// Defined function symbols located in executable segments.
    pub fn function_symbols(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols
            .iter()
            .filter(|symbol| symbol.defined && (symbol.kind == 2 || symbol.kind == 10) && self.is_exec(symbol.value))
    }

    /// Parse a little-endian ELF64 image (standard or PS4 SCE-flavoured).
    pub fn from_elf(data: &[u8], name: Option<String>) -> Result<Self> {
        ensure!(data.len() >= 64 && data.starts_with(b"\x7fELF"), "Not an ELF image");
        ensure!(data[4] == 2 && data[5] == 1, "Only little-endian ELF64 is supported");
        let entry = le64(data, 24)?;
        let phoff = le64(data, 32)? as usize;
        let shoff = le64(data, 40)? as usize;
        let phentsize = le16(data, 54)? as usize;
        let phnum = le16(data, 56)? as usize;
        let shentsize = le16(data, 58)? as usize;
        let shnum = le16(data, 60)? as usize;
        let shstrndx = le16(data, 62)? as usize;
        ensure!(phentsize >= 56 && phnum <= MAX_PHDRS, "Invalid program header table");
        let mut image = Image {
            sha256: Some(crate::config::sha256_hex(data)),
            name,
            kind: "elf64",
            ..Default::default()
        };
        // (offset, filesz) of PT_DYNAMIC and PT_SCE_DYNLIBDATA.
        let mut dynamic = None;
        let mut dynlib = None;
        for index in 0..phnum {
            let at = phoff + index * phentsize;
            let p_type = le32(data, at)?;
            let flags = le32(data, at + 4)?;
            let offset = le64(data, at + 8)?;
            let vaddr = le64(data, at + 16)?;
            let filesz = le64(data, at + 32)?;
            let memsz = le64(data, at + 40)?;
            match p_type {
                PT_LOAD | PT_SCE_RELRO => {
                    let start = (offset as usize).min(data.len());
                    let end = (offset.saturating_add(filesz.min(memsz.max(filesz))) as usize).min(data.len());
                    image.segments.push(Segment {
                        vaddr,
                        memsz: memsz.max(filesz),
                        data: data[start..end].to_vec(),
                        flags,
                    });
                }
                PT_DYNAMIC => dynamic = Some((offset, filesz)),
                PT_GNU_EH_FRAME => image.eh_frame_hdr = Some((vaddr, memsz)),
                PT_SCE_DYNLIBDATA => dynlib = Some((offset, filesz)),
                _ => {}
            }
        }
        image.segments.sort_by_key(|segment| segment.vaddr);
        image.base = image.segments.first().map_or(0, |segment| segment.vaddr);
        image.entry = Some(entry).filter(|e| image.is_exec(*e));

        // Section headers: symbol tables, .eh_frame, .rela.plt.
        let mut sections: Vec<(String, u32, u64, u64, u64, u32)> = Vec::new();
        if shnum > 0 && shoff > 0 && shentsize >= 64 && shnum <= MAX_SECTIONS
            && shoff.saturating_add(shnum * shentsize) <= data.len()
        {
            let strtab = if shstrndx < shnum {
                let at = shoff + shstrndx * shentsize;
                Some((le64(data, at + 24)? as usize, le64(data, at + 32)? as usize))
            } else {
                None
            };
            for index in 0..shnum {
                let at = shoff + index * shentsize;
                let name_off = le32(data, at)? as usize;
                let section_name = strtab
                    .map(|(off, size)| cstr(data, off.saturating_add(name_off), off.saturating_add(size)))
                    .unwrap_or_default();
                sections.push((
                    section_name,
                    le32(data, at + 4)?,
                    le64(data, at + 16)?,
                    le64(data, at + 24)?,
                    le64(data, at + 32)?,
                    le32(data, at + 40)?,
                ));
            }
        } else if shnum > 0 {
            image.notes.push("Section header table ignored (out of bounds or oversized)".into());
        }
        let mut dynsym_from_sections: Option<(usize, usize, usize, usize)> = None;
        for (section_name, sh_type, addr, offset, size, link) in &sections {
            if section_name == ".eh_frame" && *addr != 0 {
                image.eh_frame = Some((*addr, *size));
            }
            if (*sh_type == 2 || *sh_type == 11)
                && let Some((_, 3, _, str_off, str_size, _)) = sections.get(*link as usize)
            {
                let table = if *sh_type == 11 { "dynsym" } else { "symtab" };
                image.parse_symbols(data, table, *offset as usize, *size as usize, *str_off as usize, *str_size as usize);
                if *sh_type == 11 {
                    dynsym_from_sections = Some((*offset as usize, *size as usize, *str_off as usize, *str_size as usize));
                }
            }
        }
        // Relocation sections that reference the dynamic symbol table.
        if let Some((sym_off, sym_size, str_off, str_size)) = dynsym_from_sections {
            for (_, sh_type, _, offset, size, _) in &sections {
                if *sh_type == 4 {
                    image.parse_relocations(data, *offset as usize, *size as usize, (sym_off, sym_size, str_off, str_size));
                }
            }
        }
        if image.imports.is_empty() || image.symbols.is_empty() {
            image.parse_dynamic(data, dynamic, dynlib);
        }
        Ok(image)
    }

    /// Bytes at `va` of length `len`, from segment copies.
    fn segment_bytes(&self, va: u64, len: usize) -> Option<Vec<u8>> {
        let segment = self.segment_at(va)?;
        let start = (va - segment.vaddr) as usize;
        let end = start.saturating_add(len).min(segment.data.len());
        Some(segment.data[start..end].to_vec())
    }

    fn parse_dynamic(&mut self, data: &[u8], dynamic: Option<(u64, u64)>, dynlib: Option<(u64, u64)>) {
        let Some((offset, size)) = dynamic else { return };
        let mut tags: BTreeMap<u64, u64> = BTreeMap::new();
        let count = ((size / 16) as usize).min(4096);
        for index in 0..count {
            let at = offset as usize + index * 16;
            let (Ok(tag), Ok(value)) = (le64(data, at), le64(data, at + 8)) else { break };
            if tag == 0 {
                break;
            }
            tags.entry(tag).or_insert(value);
        }
        // SCE layout: tables live in PT_SCE_DYNLIBDATA, values are offsets into it.
        if let Some((lib_off, lib_size)) = dynlib
            && let (Some(&symtab), Some(&symsz), Some(&strtab), Some(&strsz)) = (
                tags.get(&0x6100_0039),
                tags.get(&0x6100_003f),
                tags.get(&0x6100_0035),
                tags.get(&0x6100_0037),
            )
        {
            let lib_end = (lib_off.saturating_add(lib_size) as usize).min(data.len());
            let lib = data.get(lib_off as usize..lib_end).unwrap_or_default();
            let tables = (symtab as usize, symsz as usize, strtab as usize, strsz as usize);
            if self.symbols.is_empty() {
                self.parse_symbols(lib, "dynsym", tables.0, tables.1, tables.2, tables.3);
            }
            for (rel, relsz) in [(0x6100_0029u64, 0x6100_002du64), (0x6100_002f, 0x6100_0031)] {
                if let (Some(&at), Some(&len)) = (tags.get(&rel), tags.get(&relsz)) {
                    self.parse_relocations(lib, at as usize, len as usize, tables);
                }
            }
            if !self.imports.is_empty() {
                self.notes.push("Imports resolved from SCE dynlib data".into());
            }
            return;
        }
        // Standard layout: values are virtual addresses inside PT_LOADs.
        let (Some(&symtab), Some(&strtab)) = (tags.get(&6), tags.get(&5)) else { return };
        let strsz = tags.get(&10).copied().unwrap_or(0) as usize;
        let Some(strings) = self.segment_bytes(strtab, strsz.min(64 * 1024 * 1024)) else { return };
        let symsz = if strtab > symtab { (strtab - symtab) as usize } else { MAX_SYMBOLS * 24 };
        let Some(symbols) = self.segment_bytes(symtab, symsz.min(MAX_SYMBOLS * 24)) else { return };
        // Build a combined buffer so the shared parsers can index both tables.
        let mut buffer = symbols.clone();
        let str_off = buffer.len();
        buffer.extend_from_slice(&strings);
        let tables = (0usize, symbols.len(), str_off, strings.len());
        if self.symbols.is_empty() {
            self.parse_symbols(&buffer, "dynsym", 0, symbols.len(), str_off, strings.len());
        }
        for (rel, relsz) in [(23u64, 2u64), (7, 8)] {
            if let (Some(&at), Some(&len)) = (tags.get(&rel), tags.get(&relsz))
                && let Some(relocs) = self.segment_bytes(at, (len as usize).min(MAX_RELOCATIONS * 24))
            {
                let mut combined = buffer.clone();
                let rel_off = combined.len();
                combined.extend_from_slice(&relocs);
                self.parse_relocations(&combined, rel_off, relocs.len(), tables);
            }
        }
    }

    fn parse_symbols(&mut self, data: &[u8], table: &'static str, offset: usize, size: usize, str_off: usize, str_size: usize) {
        let end = offset.saturating_add(size).min(data.len());
        let str_end = str_off.saturating_add(str_size).min(data.len());
        let mut index = 1usize;
        while offset + (index + 1) * 24 <= end && self.symbols.len() < MAX_SYMBOLS {
            let at = offset + index * 24;
            index += 1;
            let Ok(name_off) = le32(data, at) else { break };
            if name_off == 0 {
                continue;
            }
            let info = data[at + 4];
            let shndx = le16(data, at + 6).unwrap_or(0);
            let value = le64(data, at + 8).unwrap_or(0);
            let size = le64(data, at + 16).unwrap_or(0);
            let raw = cstr(data, str_off.saturating_add(name_off as usize), str_end);
            if raw.is_empty() {
                continue;
            }
            let (name, nid, library) = demangle(&raw);
            self.symbols.push(Symbol {
                name,
                raw,
                value,
                size,
                kind: info & 0xf,
                defined: shndx != 0,
                table,
                nid,
                library,
            });
        }
    }

    /// `R_X86_64_GLOB_DAT` / `JUMP_SLOT` / `64` relocations naming a symbol become import slots.
    fn parse_relocations(&mut self, data: &[u8], offset: usize, size: usize, tables: (usize, usize, usize, usize)) {
        let (sym_off, sym_size, str_off, str_size) = tables;
        let end = offset.saturating_add(size).min(data.len());
        let str_end = str_off.saturating_add(str_size).min(data.len());
        let mut at = offset;
        let mut count = 0usize;
        while at + 24 <= end && count < MAX_RELOCATIONS {
            count += 1;
            let (Ok(r_offset), Ok(info)) = (le64(data, at), le64(data, at + 8)) else { break };
            at += 24;
            let kind = info & 0xffff_ffff;
            let symbol = (info >> 32) as usize;
            if !matches!(kind, 1 | 6 | 7) || symbol == 0 || (symbol + 1) * 24 > sym_size {
                continue;
            }
            let entry = sym_off + symbol * 24;
            let Ok(name_off) = le32(data, entry) else { continue };
            let raw = cstr(data, str_off.saturating_add(name_off as usize), str_end);
            if raw.is_empty() {
                continue;
            }
            self.imports.entry(r_offset).or_insert_with(|| demangle(&raw).0);
        }
    }
}

#[cfg(test)]
pub mod testelf {
    //! Synthetic ELF builder shared by the static-analysis tests.

    pub struct Builder {
        pub base: u64,
        pub text: Vec<u8>,
        pub data: Vec<u8>,
        pub symbols: Vec<(String, u64, u64)>,
        /// (GOT slot VA, import raw name)
        pub imports: Vec<(u64, String)>,
        pub eh_frame: Vec<u8>,
    }

    pub const TEXT_OFF: u64 = 0x1000;

    impl Builder {
        pub fn new(base: u64) -> Self {
            Builder { base, text: Vec::new(), data: Vec::new(), symbols: Vec::new(), imports: Vec::new(), eh_frame: Vec::new() }
        }
        pub fn text_va(&self) -> u64 {
            self.base + TEXT_OFF
        }
        /// Data segment VA (page after text).
        pub fn data_va(&self) -> u64 {
            self.base + TEXT_OFF + ((self.text.len() as u64 + 0xfff) & !0xfff).max(0x1000)
        }

        /// Layout: header+phdrs | text @0x1000 (r-x) | data (rw-) | .eh_frame | dynsym/dynstr/rela | shdrs.
        pub fn build(&self) -> Vec<u8> {
            let mut out = vec![0u8; TEXT_OFF as usize];
            out.extend_from_slice(&self.text);
            let data_off = self.data_va() - self.base;
            out.resize(data_off as usize, 0xcc);
            out.extend_from_slice(&self.data);
            let eh_off = (out.len() + 7) & !7;
            out.resize(eh_off, 0);
            out.extend_from_slice(&self.eh_frame);
            out.extend_from_slice(&[0, 0, 0, 0]);
            let data_end = out.len();
            // dynstr / dynsym / rela
            let mut dynstr = vec![0u8];
            let mut dynsym = vec![0u8; 24];
            let name_index = |raw: &str, dynstr: &mut Vec<u8>| {
                let at = dynstr.len() as u32;
                dynstr.extend_from_slice(raw.as_bytes());
                dynstr.push(0);
                at
            };
            for (name, value, size) in &self.symbols {
                let at = name_index(name, &mut dynstr);
                let mut entry = [0u8; 24];
                entry[..4].copy_from_slice(&at.to_le_bytes());
                entry[4] = 0x12;
                entry[6..8].copy_from_slice(&1u16.to_le_bytes());
                entry[8..16].copy_from_slice(&value.to_le_bytes());
                entry[16..24].copy_from_slice(&size.to_le_bytes());
                dynsym.extend_from_slice(&entry);
            }
            let mut rela = Vec::new();
            for (slot, raw) in &self.imports {
                let at = name_index(raw, &mut dynstr);
                let index = (dynsym.len() / 24) as u64;
                let mut entry = [0u8; 24];
                entry[..4].copy_from_slice(&at.to_le_bytes());
                entry[4] = 0x12;
                dynsym.extend_from_slice(&entry);
                rela.extend_from_slice(&slot.to_le_bytes());
                rela.extend_from_slice(&((index << 32) | 7).to_le_bytes());
                rela.extend_from_slice(&0u64.to_le_bytes());
            }
            let shstr = b"\0.text\0.eh_frame\0.dynsym\0.dynstr\0.rela.plt\0.shstrtab\0".to_vec();
            let place = |out: &mut Vec<u8>, bytes: &[u8]| {
                let at = (out.len() + 7) & !7;
                out.resize(at, 0);
                out.extend_from_slice(bytes);
                at
            };
            let dynstr_off = place(&mut out, &dynstr);
            let dynsym_off = place(&mut out, &dynsym);
            let rela_off = place(&mut out, &rela);
            let shstr_off = place(&mut out, &shstr);
            let shoff = (out.len() + 7) & !7;
            out.resize(shoff + 7 * 64, 0);
            let name = |n: &str| shstr.windows(n.len() + 1).position(|w| w == format!("{n}\0").as_bytes()).unwrap() as u32;
            let shdr = |out: &mut Vec<u8>, i: usize, nm: u32, ty: u32, addr: u64, off: usize, size: usize, link: u32| {
                let b = shoff + i * 64;
                out[b..b + 4].copy_from_slice(&nm.to_le_bytes());
                out[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes());
                out[b + 16..b + 24].copy_from_slice(&addr.to_le_bytes());
                out[b + 24..b + 32].copy_from_slice(&(off as u64).to_le_bytes());
                out[b + 32..b + 40].copy_from_slice(&(size as u64).to_le_bytes());
                out[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
            };
            shdr(&mut out, 1, name(".text"), 1, self.text_va(), TEXT_OFF as usize, self.text.len(), 0);
            shdr(&mut out, 2, name(".eh_frame"), 1, self.base + eh_off as u64, eh_off, self.eh_frame.len() + 4, 0);
            shdr(&mut out, 3, name(".dynstr"), 3, 0, dynstr_off, dynstr.len(), 0);
            shdr(&mut out, 4, name(".dynsym"), 11, 0, dynsym_off, dynsym.len(), 3);
            shdr(&mut out, 5, name(".rela.plt"), 4, 0, rela_off, rela.len(), 4);
            shdr(&mut out, 6, name(".shstrtab"), 3, 0, shstr_off, shstr.len(), 0);
            // ELF header
            out[..4].copy_from_slice(b"\x7fELF");
            out[4] = 2;
            out[5] = 1;
            out[6] = 1;
            out[16..18].copy_from_slice(&3u16.to_le_bytes());
            out[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
            out[24..32].copy_from_slice(&self.text_va().to_le_bytes());
            out[32..40].copy_from_slice(&64u64.to_le_bytes());
            out[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
            out[52..54].copy_from_slice(&64u16.to_le_bytes());
            out[54..56].copy_from_slice(&56u16.to_le_bytes());
            out[56..58].copy_from_slice(&2u16.to_le_bytes());
            out[58..60].copy_from_slice(&64u16.to_le_bytes());
            out[60..62].copy_from_slice(&7u16.to_le_bytes());
            out[62..64].copy_from_slice(&6u16.to_le_bytes());
            let phdr = |out: &mut Vec<u8>, i: usize, flags: u32, off: u64, va: u64, size: u64| {
                let b = 64 + i * 56;
                out[b..b + 4].copy_from_slice(&1u32.to_le_bytes());
                out[b + 4..b + 8].copy_from_slice(&flags.to_le_bytes());
                out[b + 8..b + 16].copy_from_slice(&off.to_le_bytes());
                out[b + 16..b + 24].copy_from_slice(&va.to_le_bytes());
                out[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
                out[b + 40..b + 48].copy_from_slice(&size.to_le_bytes());
            };
            phdr(&mut out, 0, 5, 0, self.base, data_off);
            phdr(&mut out, 1, 6, data_off, self.base + data_off, (data_end as u64) - data_off);
            out
        }
    }

    /// Minimal `.eh_frame`: one `zR` CIE (pcrel|sdata4) plus one FDE per range.
    pub fn eh_frame(section_va: u64, ranges: &[(u64, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        // CIE
        let cie_body: Vec<u8> = {
            let mut b = vec![0, 0, 0, 0, 1];
            b.extend_from_slice(b"zR\0");
            b.extend_from_slice(&[1, 0x78, 16, 1, 0x1b]);
            b.extend_from_slice(&[0x0c, 7, 8, 0x90, 1]);
            while (b.len() + 4) % 8 != 0 {
                b.push(0);
            }
            b
        };
        out.extend_from_slice(&(cie_body.len() as u32).to_le_bytes());
        out.extend_from_slice(&cie_body);
        for (start, len) in ranges {
            let record = out.len();
            let mut body = Vec::new();
            body.extend_from_slice(&((record + 4) as u32).to_le_bytes());
            let field_va = section_va + record as u64 + 8;
            body.extend_from_slice(&((*start as i64 - field_va as i64) as i32).to_le_bytes());
            body.extend_from_slice(&(*len as u32).to_le_bytes());
            body.push(0);
            while (body.len() + 4) % 8 != 0 {
                body.push(0);
            }
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testelf::*;
    use super::*;

    #[test]
    fn parses_segments_symbols_and_imports() {
        let mut builder = Builder::new(0x400000);
        builder.text = vec![0xc3; 16];
        builder.data = vec![0; 32];
        builder.symbols.push(("main".into(), builder.text_va(), 1));
        let slot = builder.data_va() + 8;
        builder.imports.push((slot, "1jfXLRVzisc#A#B".into()));
        let image = Image::from_elf(&builder.build(), None).unwrap();
        assert_eq!(image.base, 0x400000);
        assert!(image.is_exec(builder.text_va()));
        assert!(!image.is_exec(builder.data_va()));
        assert_eq!(image.function_symbols().next().unwrap().name, "main");
        assert_eq!(image.imports.get(&slot).unwrap(), "sceKernelUsleep");
        assert!(image.eh_frame.is_some());
    }
}
