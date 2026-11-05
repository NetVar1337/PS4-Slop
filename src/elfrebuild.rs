//! Rebuild an analyzer-friendly ELF64 from an Orbis image (file or memory dump).
//!
//! The input bytes are copied unchanged; everything new is appended:
//! * a standard (non-SCE) dynamic table with `.dynsym`/`.dynstr`/`.hash`/
//!   `.rela.dyn`/`.rela.plt` copies in a new read-only `PT_LOAD`, so IDA/Ghidra
//!   apply relocations and see imports without an Orbis plugin;
//! * section headers derived from `PT_LOAD` flags plus every table whose
//!   location is derivable (`.got.plt`, `.got`, `.init_array`, `.fini_array`,
//!   `.eh_frame_hdr`/`.eh_frame`, `.bss` tails), non-overlapping by construction;
//! * a `.symtab` with demangled exports and `__imp_<name>` GOT-slot labels;
//! * a new program header table (original entries + the new `PT_LOAD`).
//!
//! Sources for the formats: SysV gABI / FreeBSD `elf_common.h` (headers, dynamic
//! tags, section types), System V AMD64 psABI (relocations), the LSB
//! `.eh_frame_hdr` description (pointer encodings), and `crate::orbisdyn` for the
//! Orbis parts. Nothing here decrypts or signs anything.

use crate::Result;
use crate::orbisdyn::{self, DynamicInfo, ElfFile, Import, Phdr, Rela};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_HASH: u32 = 5;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;
const SHT_INIT_ARRAY: u32 = 14;
const SHT_FINI_ARRAY: u32 = 15;
const SHT_PREINIT_ARRAY: u32 = 16;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const SHF_INFO_LINK: u64 = 0x40;
const SHN_ABS: u16 = 0xfff1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
/// Upper bound on per-import detail rows kept in the inline summary.
const SUMMARY_IMPORT_ROWS: usize = 64;

#[derive(Clone, Debug, Default)]
pub struct RebuildOptions {
    /// Rebase the static view so the lowest `PT_LOAD` starts here.
    pub image_base: Option<u64>,
    /// Restore relocated slots to pre-relocation values (RELATIVE -> image base
    /// + addend, JUMP_SLOT/GLOB_DAT/64 -> 0) so analyzers re-apply relocations.
    pub restore_relocations: bool,
    /// Map `ET_SCE_*` types to `ET_EXEC`/`ET_DYN` for analyzers without Orbis support.
    pub normalize_type: bool,
    pub custom_nids: Option<HashMap<String, String>>,
}

/// One loaded module of the live process, for GOT unresolution.
#[derive(Clone, Debug, Default)]
pub struct LiveModule {
    pub name: String,
    pub base: u64,
    pub end: u64,
    /// Static VA of the module's lowest `PT_LOAD` (export VAs are relative to it).
    pub static_base: u64,
    /// Exports `static VA -> (name, NID known)`; `None` when unavailable.
    pub exports: Option<BTreeMap<u64, (String, bool)>>,
    pub exports_source: String,
}

#[derive(Clone, Debug, Default)]
pub struct LiveContext {
    pub pid: u32,
    /// Runtime address of this image's lowest `PT_LOAD`.
    pub runtime_base: u64,
    pub module_name: Option<String>,
    pub modules: Vec<LiveModule>,
    /// Live GOT slot values keyed by static slot VA (read from the process).
    pub got_values: HashMap<u64, u64>,
}

/// Result of mapping one GOT slot value to the module/export it points to.
#[derive(Clone, Debug)]
pub struct Binding {
    pub import: Import,
    pub value: Option<u64>,
    pub status: &'static str,
    pub target_module: Option<String>,
    pub target_offset: Option<u64>,
    pub target_export: Option<String>,
    pub consistent: Option<bool>,
}

impl Binding {
    pub fn json(&self) -> Value {
        json!({
            "slot": format!("{:#x}", self.import.slot),
            "type": orbisdyn::reloc_type_name(self.import.r_type),
            "name": self.import.name, "nid": self.import.nid, "nid_known": self.import.known,
            "library": self.import.library, "module": self.import.module,
            "runtime_value": self.value.map(|v| format!("{v:#x}")),
            "status": self.status,
            "target_module": self.target_module,
            "target_offset": self.target_offset.map(|v| format!("{v:#x}")),
            "target_export": self.target_export,
            "name_matches_export": self.consistent,
        })
    }
}

/// Map each import's GOT value to `module+offset` and, when the module's export
/// table is known, to the exporting symbol.
pub fn resolve_bindings(imports: &[Import], live: &LiveContext, image_value: impl Fn(u64) -> Option<u64>) -> Vec<Binding> {
    let self_module = live
        .modules
        .iter()
        .find(|m| m.base <= live.runtime_base && live.runtime_base < m.end)
        .map(|m| m.name.clone());
    imports
        .iter()
        .map(|import| {
            let value = live.got_values.get(&import.slot).copied().or_else(|| image_value(import.slot));
            let mut binding = Binding {
                import: import.clone(),
                value,
                status: "unread",
                target_module: None,
                target_offset: None,
                target_export: None,
                consistent: None,
            };
            let Some(value) = value else { return binding };
            if value == 0 {
                binding.status = "null";
                return binding;
            }
            let Some(module) = live.modules.iter().find(|m| m.base <= value && value < m.end) else {
                binding.status = "unmapped";
                return binding;
            };
            let offset = value - module.base;
            binding.target_module = Some(module.name.clone());
            binding.target_offset = Some(offset);
            if self_module.as_deref() == Some(module.name.as_str()) {
                // Lazy binding: slot still points back into this module's PLT.
                binding.status = "self_lazy_or_local";
                return binding;
            }
            binding.status = "module_only";
            if let Some(exports) = &module.exports
                && let Some((name, known)) = exports.get(&module.static_base.wrapping_add(offset))
            {
                binding.status = "resolved_export";
                binding.target_export = Some(name.clone());
                if import.known && *known {
                    binding.consistent = Some(*name == import.name);
                } else if let (Some(nid), Some((export_nid, _, _))) =
                    (&import.nid, crate::nid::split_orbis_symbol(name))
                {
                    binding.consistent = Some(nid == export_nid);
                }
            }
            binding
        })
        .collect()
}

#[derive(Clone, Debug)]
struct Section {
    name: String,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
}

impl Section {
    fn new(name: &str, sh_type: u32, flags: u64, addr: u64, offset: u64, size: u64) -> Self {
        Self { name: name.into(), sh_type, flags, addr, offset, size, link: 0, info: 0, align: 1, entsize: 0 }
    }
}

pub struct Rebuilt {
    pub bytes: Vec<u8>,
    pub summary: Value,
    /// Full per-import detail (may be large).
    pub imports_detail: Vec<Value>,
}

fn align(value: u64, to: u64) -> u64 {
    value.div_ceil(to) * to
}

fn pad_to(out: &mut Vec<u8>, to: u64) {
    let target = align(out.len() as u64, to) as usize;
    out.resize(target, 0);
}

/// Decode one `.eh_frame_hdr` encoded pointer (LSB 4.1 "DWARF Exception Header Encoding").
fn eh_pointer(elf: &ElfFile<'_>, field_va: u64, hdr_va: u64, encoding: u8) -> Option<u64> {
    if encoding == 0xff {
        return None;
    }
    let raw = match encoding & 0x0f {
        0x00 | 0x04 | 0x0c => orbisdyn::rd64(elf.va_slice(field_va, 8)?, 0)?,
        0x03 => u64::from(orbisdyn::rd32(elf.va_slice(field_va, 4)?, 0)?),
        0x0b => orbisdyn::rd32(elf.va_slice(field_va, 4)?, 0)? as i32 as i64 as u64,
        0x02 => u64::from(orbisdyn::rd16(elf.va_slice(field_va, 2)?, 0)?),
        0x0a => orbisdyn::rd16(elf.va_slice(field_va, 2)?, 0)? as i16 as i64 as u64,
        _ => return None,
    };
    match encoding & 0x70 {
        0x00 => Some(raw),
        0x10 => Some(field_va.wrapping_add(raw)),
        0x30 => Some(hdr_va.wrapping_add(raw)),
        _ => None,
    }
}

/// `(eh_frame VA, size)` from `PT_GNU_EH_FRAME`, walking CIE/FDE records to the
/// zero terminator (bounded by the containing load's file data).
fn eh_frame_range(elf: &ElfFile<'_>, hdr_va: u64) -> Option<(u64, u64)> {
    let head = elf.va_slice(hdr_va, 4)?;
    if head[0] != 1 {
        return None;
    }
    let start = eh_pointer(elf, hdr_va + 4, hdr_va, head[1])?;
    let load = elf.loads().find(|p| p.vaddr <= start && start < p.vaddr + p.filesz)?;
    let limit = load.vaddr + load.filesz;
    let mut pos = start;
    for _ in 0..1_000_000 {
        let Some(len) = elf.va_slice(pos, 4).and_then(|b| orbisdyn::rd32(b, 0)) else { break };
        if len == 0 {
            pos += 4;
            break;
        }
        let next = if len == 0xffff_ffff {
            let Some(len64) = elf.va_slice(pos + 4, 8).and_then(|b| orbisdyn::rd64(b, 0)) else { break };
            pos.checked_add(12)?.checked_add(len64)?
        } else {
            pos + 4 + u64::from(len)
        };
        if next > limit {
            break;
        }
        pos = next;
    }
    (pos > start).then_some((start, pos - start))
}

fn slot_span(slots: impl Iterator<Item = u64>) -> Option<(u64, u64)> {
    let mut min = u64::MAX;
    let mut max = 0u64;
    for slot in slots {
        min = min.min(slot);
        max = max.max(slot);
    }
    (min != u64::MAX).then(|| (min, max + 8))
}

/// Rebuild `data`. `live` enables GOT unresolution and must describe the same module.
pub fn rebuild(data: &[u8], options: &RebuildOptions, live: Option<&LiveContext>) -> Result<Rebuilt> {
    let elf = ElfFile::parse(data)?;
    let mut warnings: Vec<String> = Vec::new();
    let image_dyn = orbisdyn::parse_image(&elf, options.custom_nids.as_ref());
    warnings.extend(image_dyn.warnings.iter().cloned());
    let empty = DynamicInfo::default();
    let info = image_dyn.info.as_ref().unwrap_or(&empty);
    warnings.extend(info.warnings.iter().cloned());

    let min_va = elf.min_vaddr();
    let delta = options.image_base.map_or(0, |base| base.wrapping_sub(min_va));
    let shift = |va: u64| va.wrapping_add(delta);
    let in_load = |va: u64| elf.loads().any(|p| p.vaddr <= va && va < p.vaddr.saturating_add(p.memsz.max(p.filesz)));
    let mut out = data.to_vec();

    // ---- imports & live bindings -------------------------------------------
    let imports = info.imports();
    let image_value = |va: u64| elf.va_slice(va, 8).and_then(|b| orbisdyn::rd64(b, 0));
    let bindings = live.map(|ctx| resolve_bindings(&imports, ctx, image_value));
    let mut renamed: HashMap<u32, String> = HashMap::new();
    if let Some(bindings) = &bindings {
        for binding in bindings {
            if !binding.import.known
                && let Some(export) = &binding.target_export
                && crate::nid::split_orbis_symbol(export).is_none()
            {
                renamed.insert(binding.import.sym, export.clone());
            }
        }
    }
    let symbol_name = |index: u32| -> String {
        renamed
            .get(&index)
            .cloned()
            .or_else(|| info.symbols.get(index as usize).map(|s| s.name.clone()))
            .unwrap_or_default()
    };

    // ---- section plan for loaded data --------------------------------------
    let mut specials: Vec<(String, u32, u64, u64)> = Vec::new(); // (name, type, va, size)
    if let Some(eh) = elf.find(orbisdyn::PT_GNU_EH_FRAME) {
        specials.push((".eh_frame_hdr".into(), SHT_PROGBITS, eh.vaddr, eh.memsz.max(eh.filesz)));
        match eh_frame_range(&elf, eh.vaddr) {
            Some((va, size)) => specials.push((".eh_frame".into(), SHT_PROGBITS, va, size)),
            None => warnings.push("PT_GNU_EH_FRAME present but .eh_frame could not be located".into()),
        }
    }
    if let Some((va, size)) = info.preinit_array {
        specials.push((".preinit_array".into(), SHT_PREINIT_ARRAY, va, size));
    }
    if let Some((va, size)) = info.init_array {
        specials.push((".init_array".into(), SHT_INIT_ARRAY, va, size));
    }
    if let Some((va, size)) = info.fini_array {
        specials.push((".fini_array".into(), SHT_FINI_ARRAY, va, size));
    }
    if let Some((min, end)) = slot_span(info.jmprel.iter().map(|r| r.offset)) {
        let start = info.pltgot.filter(|p| *p <= min && min - *p <= 0x40).unwrap_or(min);
        specials.push((".got.plt".into(), SHT_PROGBITS, start, end - start));
    }
    if let Some((min, end)) = slot_span(
        info.rela.iter().filter(|r| r.r_type == orbisdyn::R_X86_64_GLOB_DAT).map(|r| r.offset),
    ) {
        specials.push((".got".into(), SHT_PROGBITS, min, end - min));
    }
    if let Some(dynamic) = elf.find(orbisdyn::PT_DYNAMIC)
        && dynamic.vaddr != 0
        && in_load(dynamic.vaddr)
    {
        let label = if info.orbis { ".sce_dynamic" } else { ".dynamic.orig" };
        specials.push((label.into(), SHT_PROGBITS, dynamic.vaddr, dynamic.filesz));
    }
    let mut dynlib_in_load = false;
    if let Some((offset, size)) = image_dyn.dynlib_range
        && let Some(va) = elf.offset_to_va(offset)
    {
        dynlib_in_load = true;
        specials.push((".sce_dynlibdata".into(), SHT_PROGBITS, va, size));
    }
    specials.sort_by_key(|s| (s.2, std::cmp::Reverse(s.3)));

    let mut sections: Vec<Section> = Vec::new();
    let mut name_counts: HashMap<String, usize> = HashMap::new();
    let mut unique = |base: &str| {
        let count = name_counts.entry(base.to_owned()).or_insert(0);
        *count += 1;
        if *count == 1 { base.to_owned() } else { format!("{base}.{}", *count - 1) }
    };
    let mut placed_specials = Vec::new();
    for load in elf.loads() {
        let available = (data.len() as u64).saturating_sub(load.offset);
        let filesz = load.filesz.min(available);
        if filesz < load.filesz {
            warnings.push(format!("PT_LOAD {} file data truncated ({filesz:#x} of {:#x} bytes present)", load.index, load.filesz));
        }
        let file_end = load.vaddr + filesz;
        let flags = SHF_ALLOC
            | if load.flags & PF_W != 0 { SHF_WRITE } else { 0 }
            | if load.flags & PF_X != 0 { SHF_EXECINSTR } else { 0 };
        let generic = if load.flags & PF_X != 0 {
            ".text"
        } else if load.flags & PF_W != 0 {
            ".data"
        } else {
            ".rodata"
        };
        let mut cursor = load.vaddr;
        let push = |sections: &mut Vec<Section>, name: String, sh_type: u32, va: u64, size: u64, unique_flags: u64| {
            if size == 0 {
                return;
            }
            let mut section = Section::new(&name, sh_type, unique_flags, shift(va), load.offset + (va - load.vaddr), size);
            section.align = if sh_type == SHT_PROGBITS && name.starts_with(".text") { 16 } else { 8 };
            if matches!(sh_type, SHT_INIT_ARRAY | SHT_FINI_ARRAY | SHT_PREINIT_ARRAY) {
                section.entsize = 8;
            }
            sections.push(section);
        };
        for (name, sh_type, va, size) in &specials {
            let end = va.saturating_add(*size);
            if *size == 0 || *va < cursor || end > file_end || *va < load.vaddr {
                continue;
            }
            if *va > cursor {
                let generic_name = unique(generic);
                push(&mut sections, generic_name, SHT_PROGBITS, cursor, va - cursor, flags);
            }
            let special_flags = if *sh_type == SHT_PROGBITS && name.starts_with(".eh_frame") {
                SHF_ALLOC | (flags & SHF_WRITE)
            } else {
                flags & !SHF_EXECINSTR
            };
            push(&mut sections, name.clone(), *sh_type, *va, *size, special_flags);
            placed_specials.push(name.clone());
            cursor = end;
        }
        if file_end > cursor {
            let generic_name = unique(generic);
            push(&mut sections, generic_name, SHT_PROGBITS, cursor, file_end - cursor, flags);
        }
        if load.memsz > filesz {
            let mut bss = Section::new(&unique(".bss"), SHT_NOBITS, flags, shift(file_end), load.offset + filesz, load.memsz - filesz);
            bss.align = 8;
            sections.push(bss);
        }
    }
    for (name, ..) in &specials {
        if !placed_specials.contains(name) {
            warnings.push(format!("{name} overlaps another table or lies outside loaded file data; no section emitted"));
        }
    }

    // Section index (1-based, after the null section) containing a shifted VA.
    let section_of = |sections: &[Section], va: u64| -> Option<u16> {
        sections
            .iter()
            .position(|s| s.flags & SHF_ALLOC != 0 && s.addr <= va && va < s.addr + s.size.max(1))
            .and_then(|i| u16::try_from(i + 1).ok())
    };

    // ---- relocation restore --------------------------------------------------
    let mut restored = json!({"relative":0,"symbolic":0,"skipped":0});
    if options.restore_relocations {
        let (mut relative, mut symbolic, mut skipped) = (0u64, 0u64, 0u64);
        for rela in info.rela.iter().chain(&info.jmprel) {
            let Some(offset) = elf.va_to_offset(rela.offset).map(|o| o as usize).filter(|o| o + 8 <= out.len()) else {
                skipped += 1;
                continue;
            };
            let value = match rela.r_type {
                orbisdyn::R_X86_64_RELATIVE => {
                    relative += 1;
                    (rela.addend as u64).wrapping_add(delta)
                }
                orbisdyn::R_X86_64_JUMP_SLOT | orbisdyn::R_X86_64_GLOB_DAT | orbisdyn::R_X86_64_64 => {
                    symbolic += 1;
                    0
                }
                _ => {
                    skipped += 1;
                    continue;
                }
            };
            out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        restored = json!({"relative":relative,"symbolic":symbolic,"skipped":skipped});
    }

    // ---- appended dynamic tables (new PT_LOAD) -------------------------------
    pad_to(&mut out, 0x1000);
    let blob_offset = out.len() as u64;
    let blob_va = align(shift(elf.max_vaddr()), 0x4000);
    let have_dynamic = image_dyn.info.is_some() && !info.symbols.is_empty();
    let mut new_dynamic: Option<(u64, u64)> = None; // (va, size)
    let mut dynsym_index = 0u32;
    if have_dynamic {
        let mut dynstr = vec![0u8];
        let mut add_str = |s: &str| {
            let at = dynstr.len() as u64;
            dynstr.extend(s.as_bytes());
            dynstr.push(0);
            at
        };
        let names: Vec<String> = (0..info.symbols.len() as u32).map(symbol_name).collect();
        let mut dynsym = Vec::with_capacity(names.len() * 24);
        for (symbol, name) in info.symbols.iter().zip(&names) {
            let name_off = if name.is_empty() { 0 } else { add_str(name) };
            let (value, shndx) = if symbol.is_defined() {
                let value = shift(symbol.value);
                (value, section_of(&sections, value).unwrap_or(SHN_ABS))
            } else {
                (symbol.value, 0)
            };
            let mut entry = [0u8; 24];
            entry[0..4].copy_from_slice(&(name_off as u32).to_le_bytes());
            entry[4] = symbol.info;
            entry[5] = symbol.other;
            entry[6..8].copy_from_slice(&shndx.to_le_bytes());
            entry[8..16].copy_from_slice(&value.to_le_bytes());
            entry[16..24].copy_from_slice(&symbol.size.to_le_bytes());
            dynsym.extend(entry);
        }
        let needed: Vec<u64> = info.needed.iter().map(|n| add_str(n)).collect();
        let soname = info.soname.as_deref().map(&mut add_str);
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let hash = orbisdyn::build_sysv_hash(&name_refs);
        let encode_relas = |relas: &[Rela]| -> Vec<u8> {
            relas
                .iter()
                .flat_map(|r| {
                    let mut r = *r;
                    r.offset = shift(r.offset);
                    if r.r_type == orbisdyn::R_X86_64_RELATIVE {
                        r.addend = r.addend.wrapping_add(delta as i64);
                    }
                    r.encode()
                })
                .collect()
        };
        let rela_dyn = encode_relas(&info.rela);
        let rela_plt = encode_relas(&info.jmprel);

        // Layout inside the blob: .dynamic first (size known from tag count).
        let mut tags: Vec<(u64, u64)> = needed.iter().map(|n| (orbisdyn::DT_NEEDED, *n)).collect();
        if let Some(soname) = soname {
            tags.push((orbisdyn::DT_SONAME, soname));
        }
        let fixed_tags = 5 + 3 * usize::from(!rela_dyn.is_empty()) + 3 * usize::from(!rela_plt.is_empty());
        let optional = [info.pltgot.is_some(), info.init.is_some(), info.fini.is_some()]
            .iter()
            .filter(|b| **b)
            .count()
            + 2 * [info.init_array, info.fini_array, info.preinit_array].iter().filter(|a| a.is_some()).count();
        let dynamic_size = ((tags.len() + fixed_tags + optional + 1) * 16) as u64;
        let mut cursor = 0u64;
        let mut place = |size: u64, align_to: u64| {
            cursor = align(cursor, align_to);
            let at = cursor;
            cursor += size;
            at
        };
        let dyn_at = place(dynamic_size, 8);
        let str_at = place(dynstr.len() as u64, 1);
        let sym_at = place(dynsym.len() as u64, 8);
        let hash_at = place(hash.len() as u64, 8);
        let rela_at = place(rela_dyn.len() as u64, 8);
        let plt_at = place(rela_plt.len() as u64, 8);
        let blob_len = cursor;
        let va = |at: u64| blob_va + at;

        tags.extend([
            (orbisdyn::DT_HASH, va(hash_at)),
            (orbisdyn::DT_STRTAB, va(str_at)),
            (orbisdyn::DT_SYMTAB, va(sym_at)),
            (orbisdyn::DT_STRSZ, dynstr.len() as u64),
            (orbisdyn::DT_SYMENT, 24),
        ]);
        if !rela_dyn.is_empty() {
            tags.extend([
                (orbisdyn::DT_RELA, va(rela_at)),
                (orbisdyn::DT_RELASZ, rela_dyn.len() as u64),
                (orbisdyn::DT_RELAENT, 24),
            ]);
        }
        if !rela_plt.is_empty() {
            tags.extend([
                (orbisdyn::DT_JMPREL, va(plt_at)),
                (orbisdyn::DT_PLTRELSZ, rela_plt.len() as u64),
                (orbisdyn::DT_PLTREL, orbisdyn::DT_RELA),
            ]);
        }
        for (tag, value) in [(orbisdyn::DT_PLTGOT, info.pltgot), (orbisdyn::DT_INIT, info.init), (orbisdyn::DT_FINI, info.fini)] {
            if let Some(value) = value {
                tags.push((tag, shift(value)));
            }
        }
        for (tag, size_tag, array) in [
            (orbisdyn::DT_INIT_ARRAY, orbisdyn::DT_INIT_ARRAYSZ, info.init_array),
            (orbisdyn::DT_FINI_ARRAY, orbisdyn::DT_FINI_ARRAYSZ, info.fini_array),
            (orbisdyn::DT_PREINIT_ARRAY, orbisdyn::DT_PREINIT_ARRAYSZ, info.preinit_array),
        ] {
            if let Some((start, size)) = array {
                tags.extend([(tag, shift(start)), (size_tag, size)]);
            }
        }
        tags.push((orbisdyn::DT_NULL, 0));
        debug_assert_eq!(tags.len() as u64 * 16, dynamic_size);

        let mut blob = vec![0u8; blob_len as usize];
        for (i, (tag, value)) in tags.iter().enumerate() {
            let at = dyn_at as usize + i * 16;
            blob[at..at + 8].copy_from_slice(&tag.to_le_bytes());
            blob[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        }
        for (at, bytes) in [(str_at, &dynstr), (sym_at, &dynsym), (hash_at, &hash), (rela_at, &rela_dyn), (plt_at, &rela_plt)] {
            blob[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        }
        out.extend(&blob);

        let base_index = sections.len() as u32 + 1;
        let (dyn_idx, str_idx, sym_idx) = (base_index, base_index + 1, base_index + 2);
        dynsym_index = sym_idx;
        let mut s = Section::new(".dynamic", SHT_DYNAMIC, SHF_ALLOC, va(dyn_at), blob_offset + dyn_at, dynamic_size);
        s.link = str_idx;
        s.align = 8;
        s.entsize = 16;
        sections.push(s);
        sections.push(Section::new(".dynstr", SHT_STRTAB, SHF_ALLOC, va(str_at), blob_offset + str_at, dynstr.len() as u64));
        let mut s = Section::new(".dynsym", SHT_DYNSYM, SHF_ALLOC, va(sym_at), blob_offset + sym_at, dynsym.len() as u64);
        s.link = str_idx;
        s.info = 1;
        s.align = 8;
        s.entsize = 24;
        sections.push(s);
        let mut s = Section::new(".hash", SHT_HASH, SHF_ALLOC, va(hash_at), blob_offset + hash_at, hash.len() as u64);
        s.link = sym_idx;
        s.align = 8;
        s.entsize = 4;
        sections.push(s);
        if !rela_dyn.is_empty() {
            let mut s = Section::new(".rela.dyn", SHT_RELA, SHF_ALLOC, va(rela_at), blob_offset + rela_at, rela_dyn.len() as u64);
            s.link = sym_idx;
            s.align = 8;
            s.entsize = 24;
            sections.push(s);
        }
        if !rela_plt.is_empty() {
            let got_plt = sections.iter().position(|s| s.name == ".got.plt").map_or(0, |i| i as u32 + 1);
            let mut s = Section::new(".rela.plt", SHT_RELA, SHF_ALLOC | if got_plt != 0 { SHF_INFO_LINK } else { 0 }, va(plt_at), blob_offset + plt_at, rela_plt.len() as u64);
            s.link = sym_idx;
            s.info = got_plt;
            s.align = 8;
            s.entsize = 24;
            sections.push(s);
        }
        let _ = dyn_idx;
        new_dynamic = Some((va(dyn_at), dynamic_size));
    } else {
        warnings.push("No usable dynamic symbol table: emitted load-derived sections only".into());
    }
    let blob_len = out.len() as u64 - blob_offset;

    // ---- non-alloc: original Orbis tables, .symtab/.strtab --------------------
    if let Some((offset, size)) = image_dyn.dynlib_range
        && !dynlib_in_load
    {
        sections.push(Section::new(".sce_dynlibdata", SHT_PROGBITS, 0, 0, offset, size));
    }
    if let Some((offset, size)) = image_dyn.dynamic_range
        && !placed_specials.iter().any(|n| n == ".sce_dynamic" || n == ".dynamic.orig")
    {
        sections.push(Section::new(if info.orbis { ".sce_dynamic" } else { ".dynamic.orig" }, SHT_PROGBITS, 0, 0, offset, size));
    }

    let mut strtab = vec![0u8];
    let mut symtab = vec![0u8; 24];
    let mut symbol_count = 0usize;
    let mut add_symbol = |strtab: &mut Vec<u8>, symtab: &mut Vec<u8>, name: &str, value: u64, size: u64, kind: u8, shndx: u16| {
        let name_off = strtab.len() as u32;
        strtab.extend(name.as_bytes());
        strtab.push(0);
        let mut entry = [0u8; 24];
        entry[0..4].copy_from_slice(&name_off.to_le_bytes());
        entry[4] = (1 << 4) | kind; // STB_GLOBAL
        entry[6..8].copy_from_slice(&shndx.to_le_bytes());
        entry[8..16].copy_from_slice(&value.to_le_bytes());
        entry[16..24].copy_from_slice(&size.to_le_bytes());
        symtab.extend(entry);
        symbol_count += 1;
    };
    for symbol in info.symbols.iter().filter(|s| s.is_defined() && !s.raw_name.is_empty()) {
        let value = shift(symbol.value);
        let shndx = section_of(&sections, value).unwrap_or(SHN_ABS);
        add_symbol(&mut strtab, &mut symtab, &symbol_name(symbol.index), value, symbol.size, symbol.kind(), shndx);
    }
    for import in &imports {
        let value = shift(import.slot);
        let shndx = section_of(&sections, value).unwrap_or(SHN_ABS);
        add_symbol(&mut strtab, &mut symtab, &format!("__imp_{}", symbol_name(import.sym)), value, 8, 1, shndx);
    }
    if elf.entry != 0 && in_load(elf.entry) {
        let value = shift(elf.entry);
        let shndx = section_of(&sections, value).unwrap_or(SHN_ABS);
        add_symbol(&mut strtab, &mut symtab, "_entry", value, 0, 2, shndx);
    }
    if symbol_count > 0 {
        pad_to(&mut out, 8);
        let symtab_index = sections.len() as u32 + 1;
        let symtab_offset = out.len() as u64;
        out.extend(&symtab);
        let strtab_offset = out.len() as u64;
        out.extend(&strtab);
        let mut s = Section::new(".symtab", SHT_SYMTAB, 0, 0, symtab_offset, symtab.len() as u64);
        s.link = symtab_index + 1;
        s.info = 1;
        s.align = 8;
        s.entsize = 24;
        sections.push(s);
        sections.push(Section::new(".strtab", SHT_STRTAB, 0, 0, strtab_offset, strtab.len() as u64));
    }

    // ---- .shstrtab and section header table ------------------------------------
    let mut shstrtab = vec![0u8];
    let mut name_offsets = Vec::with_capacity(sections.len() + 1);
    for name in sections.iter().map(|s| s.name.as_str()).chain([".shstrtab"]) {
        name_offsets.push(shstrtab.len() as u32);
        shstrtab.extend(name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_offset = out.len() as u64;
    out.extend(&shstrtab);
    sections.push(Section::new(".shstrtab", SHT_STRTAB, 0, 0, shstrtab_offset, shstrtab.len() as u64));
    pad_to(&mut out, 8);
    let shoff = out.len() as u64;
    out.extend([0u8; 64]);
    for (section, name_off) in sections.iter().zip(&name_offsets) {
        let mut entry = [0u8; 64];
        entry[0..4].copy_from_slice(&name_off.to_le_bytes());
        entry[4..8].copy_from_slice(&section.sh_type.to_le_bytes());
        entry[8..16].copy_from_slice(&section.flags.to_le_bytes());
        entry[16..24].copy_from_slice(&section.addr.to_le_bytes());
        entry[24..32].copy_from_slice(&section.offset.to_le_bytes());
        entry[32..40].copy_from_slice(&section.size.to_le_bytes());
        entry[40..44].copy_from_slice(&section.link.to_le_bytes());
        entry[44..48].copy_from_slice(&section.info.to_le_bytes());
        entry[48..56].copy_from_slice(&section.align.to_le_bytes());
        entry[56..64].copy_from_slice(&section.entsize.to_le_bytes());
        out.extend(entry);
    }
    let shnum = sections.len() + 1;

    // ---- new program header table ------------------------------------------------
    let mut phdrs: Vec<Phdr> = elf.phdrs.clone();
    let mut phdr_notes = Vec::new();
    for phdr in &mut phdrs {
        let shiftable = phdr.p_type == orbisdyn::PT_LOAD
            || (phdr.p_type != orbisdyn::PT_SCE_DYNLIBDATA && phdr.vaddr != 0 && in_load(phdr.vaddr));
        if shiftable {
            phdr.vaddr = shift(phdr.vaddr);
            phdr.paddr = shift(phdr.paddr);
        }
        if phdr.p_type == orbisdyn::PT_PHDR {
            phdr.p_type = 0;
            phdr_notes.push("PT_PHDR converted to PT_NULL (program headers moved)");
        }
        if phdr.p_type == orbisdyn::PT_DYNAMIC
            && let Some((va, size)) = new_dynamic
        {
            phdr.offset = blob_offset + (va - blob_va);
            phdr.vaddr = va;
            phdr.paddr = va;
            phdr.filesz = size;
            phdr.memsz = size;
            phdr.flags = PF_R | PF_W;
            phdr.align = 8;
        }
    }
    if blob_len > 0 {
        if let Some((va, size)) = new_dynamic
            && !phdrs.iter().any(|p| p.p_type == orbisdyn::PT_DYNAMIC)
        {
            phdrs.push(Phdr { p_type: orbisdyn::PT_DYNAMIC, flags: PF_R | PF_W, offset: blob_offset + (va - blob_va), vaddr: va, paddr: va, filesz: size, memsz: size, align: 8, ..Default::default() });
        }
        phdrs.push(Phdr { p_type: orbisdyn::PT_LOAD, flags: PF_R, offset: blob_offset, vaddr: blob_va, paddr: blob_va, filesz: blob_len, memsz: blob_len, align: 0x1000, ..Default::default() });
    }
    pad_to(&mut out, 8);
    let phoff = out.len() as u64;
    for phdr in &phdrs {
        out.extend(phdr.encode());
    }

    // ---- ELF header ----------------------------------------------------------
    let original_type = elf.e_type;
    let new_type = if options.normalize_type {
        match original_type {
            orbisdyn::ET_SCE_EXEC | orbisdyn::ET_SCE_REPLAY_EXEC => orbisdyn::ET_EXEC,
            orbisdyn::ET_SCE_DYNEXEC | orbisdyn::ET_SCE_DYNAMIC | orbisdyn::ET_SCE_RELEXEC | orbisdyn::ET_SCE_STUBLIB => {
                orbisdyn::ET_DYN
            }
            other => other,
        }
    } else {
        original_type
    };
    out[16..18].copy_from_slice(&new_type.to_le_bytes());
    if elf.entry != 0 && in_load(elf.entry) {
        out[24..32].copy_from_slice(&shift(elf.entry).to_le_bytes());
    }
    out[32..40].copy_from_slice(&phoff.to_le_bytes());
    out[40..48].copy_from_slice(&shoff.to_le_bytes());
    out[52..54].copy_from_slice(&64u16.to_le_bytes());
    out[54..56].copy_from_slice(&56u16.to_le_bytes());
    out[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
    out[58..60].copy_from_slice(&64u16.to_le_bytes());
    out[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
    out[62..64].copy_from_slice(&((shnum - 1) as u16).to_le_bytes());

    // ---- summary ---------------------------------------------------------------
    let section_rows: Vec<Value> = sections
        .iter()
        .map(|s| json!({"name":s.name,"type":s.sh_type,"address":format!("{:#x}",s.addr),"offset":format!("{:#x}",s.offset),"size":s.size}))
        .collect();
    let imports_detail: Vec<Value> = match &bindings {
        Some(bindings) => bindings.iter().map(Binding::json).collect(),
        None => imports
            .iter()
            .map(|i| json!({"slot":format!("{:#x}",i.slot),"type":orbisdyn::reloc_type_name(i.r_type),"name":i.name,"nid":i.nid,"nid_known":i.known,"library":i.library,"module":i.module}))
            .collect(),
    };
    let live_summary = bindings.as_ref().map(|bindings| {
        let count = |status: &str| bindings.iter().filter(|b| b.status == status).count();
        json!({
            "pid": live.map(|l| l.pid),
            "runtime_base": live.map(|l| format!("{:#x}", l.runtime_base)),
            "module": live.and_then(|l| l.module_name.clone()),
            "resolved_export": count("resolved_export"),
            "module_only": count("module_only"),
            "self_lazy_or_local": count("self_lazy_or_local"),
            "unmapped": count("unmapped"),
            "null": count("null"),
            "unread": count("unread"),
            "renamed_from_exports": renamed.len(),
            "name_mismatches": bindings.iter().filter(|b| b.consistent == Some(false)).count(),
            "modules": live.map(|l| l.modules.iter().map(|m| json!({"name":m.name,"base":format!("{:#x}",m.base),
                "exports": m.exports.as_ref().map(|e| e.len()),"exports_source":m.exports_source})).collect::<Vec<_>>()),
        })
    });
    warnings.extend(phdr_notes.iter().map(|s| (*s).to_owned()));
    let summary = json!({
        "format": "rebuilt_elf64",
        "original_type": orbisdyn::type_name(original_type),
        "output_type": orbisdyn::type_name(new_type),
        "static_base": format!("{min_va:#x}"),
        "image_base": format!("{:#x}", shift(min_va)),
        "dynamic_source": image_dyn.source,
        "dynamic": image_dyn.info.as_ref().map(DynamicInfo::summary_json),
        "sections_created": sections.len(),
        "sections": section_rows,
        "dynamic_tables_load": (blob_len > 0).then(|| json!({"vaddr":format!("{blob_va:#x}"),"offset":format!("{blob_offset:#x}"),"size":blob_len})),
        "dynsym_section": (dynsym_index != 0).then_some(dynsym_index),
        "imports": {
            "total": imports.len(),
            "nid_resolved": imports.iter().filter(|i| i.known).count(),
            "nid_unresolved": imports.iter().filter(|i| !i.known).count(),
            "rows": imports_detail.iter().take(SUMMARY_IMPORT_ROWS).cloned().collect::<Vec<_>>(),
            "rows_truncated": imports_detail.len() > SUMMARY_IMPORT_ROWS,
        },
        "live": live_summary,
        "relocations_restored": options.restore_relocations.then_some(restored),
        "symtab_symbols": symbol_count,
        "warnings": warnings,
    });
    Ok(Rebuilt { bytes: out, summary, imports_detail })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orbisdyn::testelf;

    fn sample() -> Vec<u8> {
        testelf::build(&testelf::Spec {
            exports: vec![("sceKernelUsleep", 0x400)],
            imports: vec![("sceKernelGetProcessTime", 0x1008), ("totallyUnknownSymbolXyz", 0x1010)],
            relative: vec![(testelf::INIT_ARRAY, 0x400)],
            words: vec![(0x1008, 0x8_0000_0100), (0x1010, 0x8_0000_0200), (testelf::INIT_ARRAY, 0x7_0000_0400)],
            ..Default::default()
        })
    }

    #[test]
    fn rebuild_produces_sections_symbols_and_standard_dynamic() {
        let image = sample();
        let rebuilt = rebuild(&image, &RebuildOptions { normalize_type: true, ..Default::default() }, None).unwrap();
        let info = crate::analysis::elf_info(&rebuilt.bytes).unwrap();
        let names: Vec<&str> = info["sections"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
        for expected in [".text", ".eh_frame_hdr", ".eh_frame", ".got.plt", ".init_array", ".data", ".bss", ".dynamic", ".dynsym", ".dynstr", ".hash", ".rela.dyn", ".rela.plt", ".symtab", ".strtab", ".shstrtab", ".sce_dynlibdata", ".sce_dynamic"] {
            assert!(names.contains(&expected), "missing {expected}: {names:?}");
        }
        assert_eq!(rebuilt.summary["output_type"], "ET_DYN");
        assert_eq!(rebuilt.summary["imports"]["total"], 2);
        assert_eq!(rebuilt.summary["imports"]["nid_resolved"], 1);
        // Alloc sections must not overlap.
        let elf = ElfFile::parse(&rebuilt.bytes).unwrap();
        let mut spans: Vec<(u64, u64)> = info["sections"].as_array().unwrap().iter()
            .filter(|s| u64::from_str_radix(s["flags"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap() & SHF_ALLOC != 0)
            .map(|s| { let a = u64::from_str_radix(s["address"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap(); (a, a + s["size"].as_u64().unwrap()) })
            .collect();
        spans.sort();
        for pair in spans.windows(2) {
            assert!(pair[0].1 <= pair[1].0, "overlap {pair:?}");
        }
        // Standard dynamic table now parses without Orbis tags and names are demangled.
        let reparsed = orbisdyn::parse_image(&elf, None).info.unwrap();
        assert!(!reparsed.orbis);
        assert_eq!(reparsed.needed, vec!["libkernel.prx"]);
        assert!(reparsed.symbols.iter().any(|s| s.raw_name == "sceKernelGetProcessTime"));
        assert!(reparsed.symbols.iter().any(|s| s.raw_name == "sceKernelUsleep" && s.is_defined()));
        assert_eq!(reparsed.jmprel.len(), 2);
        assert_eq!(reparsed.rela.len(), 1);
        // Original bytes are preserved verbatim up to the original length (except the ELF header).
        assert_eq!(&rebuilt.bytes[64..image.len()], &image[64..]);
    }

    #[test]
    fn image_base_and_restore_relocations() {
        let image = sample();
        let options = RebuildOptions { image_base: Some(0x40_0000), restore_relocations: true, normalize_type: false, custom_nids: None };
        let rebuilt = rebuild(&image, &options, None).unwrap();
        let elf = ElfFile::parse(&rebuilt.bytes).unwrap();
        assert_eq!(elf.min_vaddr(), 0x40_0000);
        assert_eq!(elf.entry, 0x40_0400);
        assert_eq!(orbisdyn::type_name(elf.e_type), "ET_SCE_DYNEXEC");
        let read = |va: u64| orbisdyn::rd64(elf.va_slice(va, 8).unwrap(), 0).unwrap();
        assert_eq!(read(0x40_0000 + testelf::INIT_ARRAY), 0x40_0400, "RELATIVE restored to image_base + addend");
        assert_eq!(read(0x40_1008), 0, "JUMP_SLOT restored to pre-relocation value");
        let reparsed = orbisdyn::parse_image(&elf, None).info.unwrap();
        assert_eq!(reparsed.rela[0].addend, 0x40_0400);
        assert_eq!(reparsed.jmprel[0].offset, 0x40_1008);
        assert_eq!(rebuilt.summary["relocations_restored"]["relative"], 1);
        assert_eq!(rebuilt.summary["relocations_restored"]["symbolic"], 2);
    }

    #[test]
    fn live_bindings_name_unknown_imports_from_exports() {
        let image = sample();
        let unknown_nid = crate::nid::encode_nid("totallyUnknownSymbolXyz");
        let mut exports = BTreeMap::new();
        exports.insert(0x100, ("sceKernelGetProcessTime".to_owned(), true));
        exports.insert(0x200, ("myRealExportName".to_owned(), false));
        let live = LiveContext {
            pid: 77,
            runtime_base: 0x1_0000_0000,
            module_name: Some("eboot.bin".into()),
            modules: vec![
                LiveModule { name: "eboot.bin".into(), base: 0x1_0000_0000, end: 0x1_0000_8000, ..Default::default() },
                LiveModule { name: "libkernel.sprx".into(), base: 0x8_0000_0000, end: 0x8_0001_0000, static_base: 0, exports: Some(exports), exports_source: "test".into() },
            ],
            got_values: HashMap::new(),
        };
        let rebuilt = rebuild(&image, &RebuildOptions::default(), Some(&live)).unwrap();
        let live_summary = &rebuilt.summary["live"];
        assert_eq!(live_summary["resolved_export"], 2, "{live_summary}");
        assert_eq!(live_summary["renamed_from_exports"], 1);
        assert_eq!(live_summary["name_mismatches"], 0);
        assert_eq!(rebuilt.imports_detail[1]["target_export"], "myRealExportName");
        assert_eq!(rebuilt.imports_detail[1]["nid"], unknown_nid);
        let elf = ElfFile::parse(&rebuilt.bytes).unwrap();
        let reparsed = orbisdyn::parse_image(&elf, None).info.unwrap();
        assert!(reparsed.symbols.iter().any(|s| s.raw_name == "myRealExportName"));
    }

    #[test]
    fn memory_only_image_without_dynamic_still_gets_sections() {
        let mut image = sample();
        image.truncate(0x1800); // dynlib/dynamic gone, like a dump of only the first pages
        let rebuilt = rebuild(&image, &RebuildOptions::default(), None).unwrap();
        assert!(rebuilt.summary["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("dynamic")));
        let info = crate::analysis::elf_info(&rebuilt.bytes);
        assert!(info.is_ok() || ElfFile::parse(&rebuilt.bytes).is_ok());
        let elf = ElfFile::parse(&rebuilt.bytes).unwrap();
        assert!(elf.shnum >= 3);
    }
}
