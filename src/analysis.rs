//! Local, offline analysis over contained artifacts.
//!
//! Native port of the network-free parts of `ps4_workbench/analysis.py`.
//! Debugger round-trips (process info, maps, memory reads) stay with the
//! caller; `snapshot_record` and `correlate_maps` take their results.

use anyhow::{anyhow, bail, ensure};
use serde_json::{Value, json};

use crate::Result;
use crate::artifacts::ArtifactStore;
use crate::config::{python_json_ordered, require_hash, sha256_hex};

/// Supported value types for `typed_value`.
pub const TYPES: [&str; 10] = [
    "u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "f32", "f64",
];
/// Python `diff` keeps at most this many changed ranges.
pub const MAX_DIFF_RANGES: usize = 256;
/// Python `scan_pattern` default result cap.
pub const DEFAULT_MAX_MATCHES: usize = 256;

fn float_value(value: f64) -> Value {
    if value.is_nan() {
        Value::from("nan")
    } else if value.is_infinite() {
        Value::from(if value > 0.0 { "inf" } else { "-inf" })
    } else {
        Value::from(value)
    }
}

/// Decode little-endian bytes as `value_type`; 64-bit integers and
/// non-finite floats are returned as strings to stay JSON-safe.
pub fn typed_value(data: &[u8], value_type: &str) -> Result<Value> {
    let size = match value_type {
        "u8" | "i8" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" => 8,
        _ => bail!("Unsupported value type"),
    };
    if data.len() != size {
        bail!("Byte count does not match requested value type");
    }
    let mut buffer = [0u8; 8];
    buffer[..size].copy_from_slice(data);
    let value = match value_type {
        "u8" => Value::from(data[0]),
        "i8" => Value::from(data[0] as i8),
        "u16" => Value::from(u16::from_le_bytes([data[0], data[1]])),
        "i16" => Value::from(i16::from_le_bytes([data[0], data[1]])),
        "u32" => Value::from(u32::from_le_bytes(buffer[..4].try_into()?)),
        "i32" => Value::from(i32::from_le_bytes(buffer[..4].try_into()?)),
        "u64" => Value::from(u64::from_le_bytes(buffer).to_string()),
        "i64" => Value::from(i64::from_le_bytes(buffer).to_string()),
        "f32" => float_value(f64::from(f32::from_le_bytes(buffer[..4].try_into()?))),
        _ => float_value(f64::from_le_bytes(buffer)),
    };
    Ok(
        json!({"type": value_type, "value": value, "endianness": "little", "hex": hex::encode(data)}),
    )
}

/// Whether Python `int(token, 16)` would accept `token`.
fn python_hex_int_accepts(token: &str) -> bool {
    let body = token.strip_prefix(['+', '-']).unwrap_or(token);
    let body = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .map(|rest| rest.strip_prefix('_').unwrap_or(rest))
        .unwrap_or(body);
    !body.is_empty()
        && !body.starts_with('_')
        && !body.ends_with('_')
        && !body.contains("__")
        && body.chars().all(|c| c.is_ascii_hexdigit() || c == '_')
}

fn parse_pattern(pattern: &str) -> Result<Vec<Option<u8>>> {
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    if !(1..=256).contains(&tokens.len()) {
        bail!("Pattern must have 1 to 256 space-separated hex bytes / ?? wildcards");
    }
    if tokens
        .iter()
        .any(|token| *token != "??" && !python_hex_int_accepts(token))
    {
        bail!("Invalid byte pattern");
    }
    tokens
        .iter()
        .map(|token| {
            if *token == "??" {
                return Ok(None);
            }
            if token.len() != 2 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("Pattern bytes must be exactly two hex characters");
            }
            Ok(Some(u8::from_str_radix(token, 16)?))
        })
        .collect()
}

/// Return the byte width of a validated `"48 8b ?? 05"` pattern.
pub fn pattern_len(pattern: &str) -> Result<usize> {
    Ok(parse_pattern(pattern)?.len())
}

/// Scan for a `"48 8b ?? 05"` style pattern; offsets are reported from 0.
pub fn scan_pattern(data: &[u8], pattern: &str, max_matches: usize) -> Result<Value> {
    scan_pattern_at(data, pattern, 0, max_matches)
}

/// `scan_pattern` with matches reported as `base + offset`.
pub fn scan_pattern_at(data: &[u8], pattern: &str, base: u64, max_matches: usize) -> Result<Value> {
    let signature = parse_pattern(pattern)?;
    let mut found = Vec::new();
    let mut truncated = false;
    if data.len() >= signature.len() {
        for offset in 0..=data.len() - signature.len() {
            let window = &data[offset..offset + signature.len()];
            if signature
                .iter()
                .zip(window)
                .all(|(want, have)| want.is_none_or(|byte| byte == *have))
            {
                if found.len() == max_matches {
                    truncated = true;
                    break;
                }
                found.push(Value::from(format!(
                    "{:#x}",
                    u128::from(base) + offset as u128
                )));
            }
        }
    }
    Ok(json!({"matches": found, "truncated": truncated, "scanned_bytes": data.len()}))
}

/// Offset comparison of two captures, each bounded by `memory_bytes`.
pub fn diff(store: &ArtifactStore, before: &str, after: &str) -> Result<Value> {
    let limit = store.profile.limit("memory_bytes");
    let left = store.read_bounded(before, limit)?;
    let right = store.read_bounded(after, limit)?;
    let length = left.len().max(right.len());
    let mut ranges = Vec::new();
    let mut begin: Option<usize> = None;
    let mut changed = 0usize;
    for offset in 0..length {
        if left.get(offset) != right.get(offset) {
            changed += 1;
            begin.get_or_insert(offset);
        } else if let Some(start) = begin.take()
            && ranges.len() < MAX_DIFF_RANGES
        {
            ranges.push(json!({"offset": start, "length": offset - start}));
        }
    }
    if let Some(start) = begin
        && ranges.len() < MAX_DIFF_RANGES
    {
        ranges.push(json!({"offset": start, "length": length - start}));
    }
    let truncated = ranges.len() == MAX_DIFF_RANGES;
    Ok(json!({
        "before_size": left.len(),
        "after_size": right.len(),
        "changed_bytes": changed,
        "ranges": ranges,
        "ranges_may_be_truncated": truncated,
        "warning": "Offset comparison only; ensure same process/module/range and application version",
    }))
}

/// Save a memory capture with provenance gathered by the caller from the
/// debugger (`process_info`, `maps`, runtime identity).
#[allow(clippy::too_many_arguments)]
pub fn snapshot_record(
    store: &ArtifactStore,
    content: &[u8],
    pid: u32,
    address: u64,
    length: usize,
    application_version: &str,
    module_sha256: &str,
    process: Value,
    maps: Value,
    runtime_identity: Value,
) -> Result<Value> {
    require_hash(module_sha256, "module_sha256")?;
    if content.len() != length {
        bail!("Captured byte count does not match requested length");
    }
    store.save(
        "memory",
        content,
        json!({
            "pid": pid, "address": address, "length": length,
            "application_version": application_version, "module_sha256": module_sha256,
            "process": process, "maps": maps, "runtime_identity": runtime_identity,
            "atomic_snapshot": false, "module_hash_source": "user_supplied",
        }),
        "bin",
    )
}

fn map_field(entry: &Value, name: &str) -> Result<u64> {
    entry
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Memory map entry lacks integer {name}"))
}

/// Correlate a runtime address with debugger maps (`start`, `end`,
/// `offset`, `name` entries) and estimate the image RVA.
pub fn correlate_maps(
    maps: &Value,
    pid: u32,
    address: u64,
    module_sha256: &str,
    application_version: &str,
) -> Result<Value> {
    require_hash(module_sha256, "module_sha256")?;
    let entries = maps
        .as_array()
        .ok_or_else(|| anyhow!("Memory maps must be a list"))?;
    let mut selected = None;
    for entry in entries {
        let (start, end) = (map_field(entry, "start")?, map_field(entry, "end")?);
        if start <= address && address < end {
            selected = Some((entry, start));
            break;
        }
    }
    let Some((entry, start)) = selected else {
        bail!("Address is not in the captured process maps");
    };
    let offset = map_field(entry, "offset")?;
    let base = i128::from(start) - i128::from(offset);
    let hex = |value: i128| {
        if value < 0 {
            format!("-{:#x}", -value)
        } else {
            format!("{value:#x}")
        }
    };
    Ok(json!({
        "pid": pid,
        "module_name": entry.get("name").cloned().unwrap_or(Value::Null),
        "module_sha256": module_sha256,
        "application_version": application_version,
        "absolute_address": format!("{address:#x}"),
        "mapping_base": format!("{start:#x}"),
        "mapping_relative_offset": format!("{:#x}", address - start),
        "estimated_image_base": hex(base),
        "estimated_rva": hex(i128::from(address) - base),
        "warning": "Image base is estimated from map offset; verify ELF PT_LOAD layout in Ghidra",
    }))
}

/// Save an evidence-backed module/RVA comment as an `annotation` artifact.
pub fn annotate(
    store: &ArtifactStore,
    artifact: &str,
    module_sha256: &str,
    rva: u64,
    text: &str,
    symbol: &str,
) -> Result<Value> {
    require_hash(module_sha256, "module_sha256")?;
    let source = store.read(artifact)?;
    let entry = python_json_ordered(
        &[
            ("artifact", Value::from(artifact)),
            ("artifact_sha256", Value::from(sha256_hex(&source))),
            ("module_sha256", Value::from(module_sha256)),
            ("rva", Value::from(format!("{rva:#x}"))),
            ("comment", Value::from(text)),
            ("symbol", Value::from(symbol)),
        ],
        2,
    );
    store.save("annotation", entry.as_bytes(), Value::Null, "json")
}

/// Bundle a raw artifact with Ghidra import instructions.
pub fn ghidra_export(
    store: &ArtifactStore,
    artifact: &str,
    image_base: u64,
    module_sha256: &str,
) -> Result<Value> {
    require_hash(module_sha256, "module_sha256")?;
    let content = store.read(artifact)?;
    let notes = python_json_ordered(
        &[
            ("artifact", Value::from(artifact)),
            ("sha256", Value::from(sha256_hex(&content))),
            ("module_sha256", Value::from(module_sha256)),
            (
                "requested_image_base",
                Value::from(format!("{image_base:#x}")),
            ),
            (
                "instruction",
                Value::from(
                    "Import as raw x86:LE:64:default if not ELF. Set image base explicitly. Dumps are not reconstructed ELF files.",
                ),
            ),
        ],
        2,
    );
    store.bundle(&[artifact.to_string()], &notes)
}


// ---- static container inspection (pure, local, bounded) ------------------
//
// Everything here parses bytes that were already extracted to the local
// artifact store; nothing touches the console. All reads are bounds-checked
// and all counts capped, so a hostile file cannot drive unbounded work.

fn le16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        data.get(at..at + 2)
            .ok_or_else(|| anyhow!("Container truncated at {at:#x}"))?
            .try_into()?,
    ))
}

fn le32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .ok_or_else(|| anyhow!("Container truncated at {at:#x}"))?
            .try_into()?,
    ))
}

fn le64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(at..at + 8)
            .ok_or_else(|| anyhow!("Container truncated at {at:#x}"))?
            .try_into()?,
    ))
}

fn elf_type_name(value: u16) -> String {
    match value {
        1 => "relocatable".to_owned(),
        2 => "executable".to_owned(),
        3 => "shared_object".to_owned(),
        4 => "core".to_owned(),
        other => format!("unknown({other})"),
    }
}

fn elf_machine_name(value: u16) -> String {
    match value {
        0x3e => "x86-64".to_owned(),
        0x28 => "arm".to_owned(),
        0xb7 => "aarch64".to_owned(),
        0x08 => "mips".to_owned(),
        other => format!("unknown({other:#x})"),
    }
}

fn segment_permissions(flags: u32) -> String {
    format!(
        "{}{}{}",
        if flags & 4 != 0 { 'r' } else { '-' },
        if flags & 2 != 0 { 'w' } else { '-' },
        if flags & 1 != 0 { 'x' } else { '-' }
    )
}

/// Dispatch on container magic: ELF64 gets a full structural parse, SCE
/// containers are identified but not decrypted.
pub fn artifact_info(data: &[u8]) -> Result<Value> {
    if data.starts_with(b"\x7fELF") {
        return elf_info(data);
    }
    if data.starts_with(b"\x4f\x15\x3d\x1d") {
        return Ok(json!({
            "kind": "ps4_self", "size": data.len(), "sha256": sha256_hex(data),
            "version": data.get(4).copied().unwrap_or(0),
            "note": "SCE SELF container; only magic and version are read here. Decrypt externally (e.g. ps4dec / make_fself) and re-run artifact_info on the embedded ELF.",
        }));
    }
    if data.starts_with(b"\x7fCNT") {
        return Ok(json!({
            "kind": "ps4_pkg", "size": data.len(), "sha256": sha256_hex(data),
            "note": "PS4 PKG container; extract with an external unpacker first.",
        }));
    }
    Ok(json!({
        "kind": "raw_binary", "size": data.len(), "sha256": sha256_hex(data),
        "note": "No known container magic; treated as a flat binary. Use artifact_disasm with an explicit base address.",
    }))
}

const MAX_PROGRAM_HEADERS: u16 = 256;
const MAX_SECTIONS: u16 = 1024;
const MAX_DYNAMIC_ENTRIES: usize = 512;
const MAX_NEEDED: usize = 64;
const MAX_SECTION_LIST: usize = 256;

const MAX_SYMBOL_LIST: usize = 512;

fn sym_binding_name(bind: u8) -> &'static str {
    match bind {
        0 => "LOCAL",
        1 => "GLOBAL",
        2 => "WEAK",
        _ => "OTHER",
    }
}

fn sym_type_name(ty: u8) -> &'static str {
    match ty {
        0 => "NOTYPE",
        1 => "OBJECT",
        2 => "FUNC",
        3 => "SECTION",
        4 => "FILE",
        6 => "TLS",
        10 => "IFUNC",
        _ => "OTHER",
    }
}

fn read_cstr(data: &[u8], table_offset: u64, table_size: u64, name_offset: u32) -> String {
    let cap = table_size.min(4 * 1024 * 1024) as usize;
    let end = (table_offset as usize).saturating_add(cap).min(data.len());
    let start = (table_offset as usize).saturating_add(name_offset as usize);
    if start >= end {
        return String::new();
    }
    let slice = &data[start..end];
    String::from_utf8_lossy(slice.split(|byte| *byte == 0).next().unwrap_or_default()).into_owned()
}

/// Structural parse of a little-endian ELF64 image: header, program headers
/// (loads + dynamic), section headers with names, symbol-table entries (with
/// Orbis OS NID demangling), and DT_NEEDED imports. Every offset is bounds-checked.
pub fn elf_info(data: &[u8]) -> Result<Value> {
    ensure!(data.len() >= 64, "Too small for an ELF64 header");
    ensure!(data[4] == 2, "Not a 64-bit ELF");
    ensure!(data[5] == 1, "Not a little-endian ELF");
    ensure!(data[6] == 1, "Unsupported ELF version");
    let e_type = le16(data, 16)?;
    let e_machine = le16(data, 18)?;
    let entry = le64(data, 24)?;
    let phoff = le64(data, 32)?;
    let shoff = le64(data, 40)?;
    let flags = le32(data, 48)?;
    let phentsize = le16(data, 54)?;
    let phnum = le16(data, 56)?;
    let shentsize = le16(data, 58)?;
    let shnum = le16(data, 60)?;
    let shstrndx = le16(data, 62)?;
    ensure!(phentsize >= 56, "Invalid program header entry size");
    if shnum > 0 {
        ensure!(shentsize >= 64, "Invalid section header entry size");
    }
    ensure!(
        phnum <= MAX_PROGRAM_HEADERS && shnum <= MAX_SECTIONS,
        "Header counts exceed supported caps"
    );
    ensure!(
        phoff as u128 + phnum as u128 * phentsize as u128 <= data.len() as u128,
        "Program header table extends past end of file"
    );

    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..phnum as usize {
        let base = phoff as usize + index * phentsize as usize;
        let p_type = le32(data, base)?;
        let p_flags = le32(data, base + 4)?;
        let p_offset = le64(data, base + 8)?;
        let p_vaddr = le64(data, base + 16)?;
        let p_filesz = le64(data, base + 32)?;
        let p_memsz = le64(data, base + 40)?;
        if p_type == 1 {
            loads.push(json!({
                "vaddr": format!("{p_vaddr:#x}"), "offset": format!("{p_offset:#x}"),
                "filesz": p_filesz, "memsz": p_memsz,
                "permissions": segment_permissions(p_flags),
            }));
        } else if p_type == 2 {
            dynamic = Some((p_offset, p_filesz));
        }
    }
    let image_base = loads
        .iter()
        .filter_map(|load| parse_hex_string(load["vaddr"].as_str()?))
        .min();

    let vaddr_to_file_offset = |vaddr: u64| -> Option<u64> {
        loads.iter().find_map(|load| {
            let v = parse_hex_string(load["vaddr"].as_str()?)?;
            let filesz = load["filesz"].as_u64()?;
            let off = parse_hex_string(load["offset"].as_str()?)?;
            (v <= vaddr && vaddr < v.saturating_add(filesz)).then_some(off + (vaddr - v))
        })
    };

    // Section headers and names via the section-header string table.
    let mut sections = Vec::new();
    let mut sections_truncated = false;
    let mut symtab = 0u64;
    let mut dynsym = 0u64;
    let mut section_spans: Vec<(u32, u64, u64, u32)> = Vec::new();
    if shnum > 0 && shoff > 0 {
        ensure!(
            shoff as u128 + shnum as u128 * shentsize as u128 <= data.len() as u128,
            "Section header table extends past end of file"
        );
        let strtab = if (shstrndx as usize) < shnum as usize {
            let base = shoff as usize + shstrndx as usize * shentsize as usize;
            Some((le64(data, base + 24)?, le64(data, base + 32)?))
        } else {
            None
        };
        for index in 0..shnum as usize {
            let base = shoff as usize + index * shentsize as usize;
            let sh_name = le32(data, base)?;
            let sh_type = le32(data, base + 4)?;
            let sh_flags = le64(data, base + 8)?;
            let sh_addr = le64(data, base + 16)?;
            let sh_offset = le64(data, base + 24)?;
            let sh_size = le64(data, base + 32)?;
            let sh_link = le32(data, base + 40)?;
            section_spans.push((sh_type, sh_offset, sh_size, sh_link));
            if sh_type == 2 {
                symtab = sh_size / 24;
            }
            if sh_type == 11 {
                dynsym = sh_size / 24;
            }
            if sections.len() < MAX_SECTION_LIST {
                let sec_name = strtab
                    .map(|(off, sz)| read_cstr(data, off, sz, sh_name))
                    .unwrap_or_default();
                sections.push(json!({
                    "name": sec_name, "type": sh_type,
                    "flags": format!("{sh_flags:#x}"), "address": format!("{sh_addr:#x}"),
                    "offset": format!("{sh_offset:#x}"), "size": sh_size,
                }));
            } else {
                sections_truncated = true;
            }
        }
    }

    // DT_NEEDED imports & dynamic string/symbol tables from PT_DYNAMIC.
    let mut needed = Vec::new();
    let mut notes = Vec::new();
    let mut dyn_str_span: Option<(u64, u64)> = None;
    let mut dyn_sym_vaddr: Option<u64> = None;
    let mut dyn_str_vaddr: Option<u64> = None;
    if let Some((offset, size)) = dynamic {
        let mut tags = Vec::new();
        let mut strtab_vaddr = None;
        let mut strtab_size = 0u64;
        let entries = ((size / 16) as usize).min(MAX_DYNAMIC_ENTRIES);
        ensure!(
            offset as u128 + entries as u128 * 16 <= data.len() as u128,
            "Dynamic table extends past end of file"
        );
        for index in 0..entries {
            let base = offset as usize + index * 16;
            let tag = le64(data, base)?;
            let value = le64(data, base + 8)?;
            if tag == 0 {
                break;
            }
            match tag {
                1 => tags.push(value),
                5 => strtab_vaddr = Some(value),
                6 => dyn_sym_vaddr = Some(value),
                10 => strtab_size = value,
                _ => {}
            }
        }
        dyn_str_vaddr = strtab_vaddr;
        if let Some(vaddr) = strtab_vaddr {
            if let Some(start) = vaddr_to_file_offset(vaddr) {
                dyn_str_span = Some((start, strtab_size));
                let end = (start as u128 + strtab_size.min(65536) as u128).min(data.len() as u128);
                for tag in tags.into_iter().take(MAX_NEEDED) {
                    let at = start as u128 + tag as u128;
                    if at >= end {
                        continue;
                    }
                    let slice = &data[at as usize..end as usize];
                    let text = String::from_utf8_lossy(
                        slice.split(|byte| *byte == 0).next().unwrap_or_default(),
                    );
                    if !text.is_empty() {
                        needed.push(text.into_owned());
                    }
                }
            } else {
                notes.push("DT_STRTAB virtual address is not backed by a PT_LOAD; imports not resolved");
            }
        }
    } else {
        notes.push("No PT_DYNAMIC segment; static or prelinked image");
    }
    if sections_truncated {
        notes.push("Section list truncated at the reporting cap");
    }

    // Parse symbol entries from .dynsym / .symtab sections (or PT_DYNAMIC fallback)
    // and demangle Orbis OS NIDs via the built-in NID dictionary.
    let mut symbol_entries = Vec::new();
    let mut symbols_truncated = false;
    let mut nid_resolved = 0usize;

    let mut parse_sym_region = |table_kind: &str,
                                sym_off: u64,
                                sym_size: u64,
                                str_off: u64,
                                str_size: u64| {
        if sym_off < 64 || str_off < 64 || sym_size < 24 || str_size == 0 {
            return;
        }
        let end_off = (sym_off as u128 + sym_size as u128).min(data.len() as u128) as usize;
        if sym_off as usize >= end_off {
            return;
        }
        let count = (end_off - sym_off as usize) / 24;
        for idx in 1..count {
            let at = sym_off as usize + idx * 24;
            let Ok(st_name) = le32(data, at) else { break };
            if st_name == 0 {
                continue;
            }
            let st_info = data[at + 4];
            let Ok(st_shndx) = le16(data, at + 6) else { break };
            let Ok(st_value) = le64(data, at + 8) else { break };
            let Ok(st_size) = le64(data, at + 16) else { break };
            let raw_name = read_cstr(data, str_off, str_size, st_name);
            if raw_name.is_empty() {
                continue;
            }
            if symbol_entries.len() >= MAX_SYMBOL_LIST {
                symbols_truncated = true;
                break;
            }
            let orbis = crate::nid::split_orbis_symbol(&raw_name);
            let resolved = crate::nid::lookup_nid(&raw_name, None);
            if resolved.is_some() {
                nid_resolved += 1;
            }
            symbol_entries.push(json!({
                "table": table_kind,
                "name": raw_name,
                "nid": orbis.map(|(nid, _, _)| nid),
                "library_tag": orbis.and_then(|(_, lib, _)| lib),
                "module_tag": orbis.and_then(|(_, _, m)| m),
                "resolved_name": resolved,
                "value": format!("{st_value:#x}"),
                "size": st_size,
                "binding": sym_binding_name(st_info >> 4),
                "type": sym_type_name(st_info & 0xf),
                "defined": st_shndx != 0,
            }));
        }
    };

    for &(sh_type, sh_offset, sh_size, sh_link) in &section_spans {
        if sh_type != 2 && sh_type != 11 {
            continue;
        }
        let str_span = if sh_link > 0 && (sh_link as usize) < section_spans.len() {
            let (link_ty, link_off, link_sz, _) = section_spans[sh_link as usize];
            (link_ty == 3).then_some((link_off, link_sz))
        } else if sh_type == 11 {
            dyn_str_span
        } else {
            None
        };
        if let Some((str_off, str_sz)) = str_span {
            let kind = if sh_type == 11 { "dynsym" } else { "symtab" };
            parse_sym_region(kind, sh_offset, sh_size, str_off, str_sz);
        }
    }

    // Sectionless ELF fallback (common in reconstructed in-memory PS4 dumps):
    if section_spans.is_empty()
        && let (Some(sym_vaddr), Some(str_vaddr), Some((str_off, str_sz))) =
            (dyn_sym_vaddr, dyn_str_vaddr, dyn_str_span)
        && sym_vaddr < str_vaddr
        && let Some(sym_off) = vaddr_to_file_offset(sym_vaddr)
    {
        let est_bytes = (str_vaddr - sym_vaddr).min((MAX_SYMBOL_LIST as u64 + 1) * 24);
        dynsym = (str_vaddr - sym_vaddr) / 24;
        parse_sym_region("dynsym", sym_off, est_bytes, str_off, str_sz);
    }

    Ok(json!({
        "kind": "elf64", "size": data.len(), "sha256": sha256_hex(data),
        "type": elf_type_name(e_type), "machine": elf_machine_name(e_machine),
        "entry": format!("{entry:#x}"), "flags": format!("{flags:#x}"),
        "image_base": image_base.map(|base| format!("{base:#x}")),
        "loads": loads,
        "section_count": shnum,
        "sections": sections,
        "symbols": {
            "symtab_entries": symtab,
            "dynsym_entries": dynsym,
            "nid_resolved": nid_resolved,
            "truncated": symbols_truncated,
            "entries": symbol_entries,
        },
        "dynamic_needed": needed,
        "notes": notes,
    }))
}

fn parse_hex_string(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

/// Linear x86-64 disassembly of an artifact range. `offset` is the file
/// offset, `address` the virtual address that offset is mapped at.
pub fn disassemble_artifact(data: &[u8], offset: usize, address: u64, count: usize) -> Result<Value> {
    ensure!(
        (1..=crate::disasm::MAX_INSTRUCTIONS).contains(&count),
        "Invalid instruction count"
    );
    let bytes = data
        .get(offset..)
        .ok_or_else(|| anyhow!("Offset {offset:#x} is past the end of the artifact"))?;
    let items = crate::disasm::decode(bytes, address, count);
    Ok(json!({
        "offset": format!("{offset:#x}"), "address": format!("{address:#x}"),
        "decoded": items.len(), "bytes_available": bytes.len(),
        "instructions": crate::disasm::to_json(&items),
    }))
}

/// Bounded printable-string extraction (x64dbg-style reference strings).
pub fn strings(data: &[u8], min_length: usize, max_results: usize) -> Result<Value> {
    ensure!(
        (4..=64).contains(&min_length),
        "min_length must be 4-64"
    );
    ensure!(
        (1..=4096).contains(&max_results),
        "max_results must be 1-4096"
    );
    let mut found = Vec::new();
    let mut start = None;
    let push = |start: usize, end: usize, found: &mut Vec<Value>| {
        if end - start >= min_length && found.len() < max_results {
            found.push(json!({
                "offset": format!("{start:#x}"), "length": end - start,
                "text": String::from_utf8_lossy(&data[start..end]),
            }));
        }
    };
    for (index, byte) in data.iter().enumerate() {
        if byte.is_ascii_graphic() || *byte == b' ' {
            if start.is_none() {
                start = Some(index);
            }
        } else if let Some(begin) = start.take() {
            push(begin, index, &mut found);
        }
    }
    if let Some(begin) = start.take() {
        push(begin, data.len(), &mut found);
    }
    Ok(json!({
        "count": found.len(), "truncated": found.len() == max_results,
        "scanned_bytes": data.len(), "strings": found,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::tests::test_profile;

    fn store() -> (tempfile::TempDir, ArtifactStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(&test_profile(directory.path())).unwrap();
        (directory, store)
    }

    #[test]
    fn typed_values() {
        assert_eq!(
            typed_value(&u64::MAX.to_le_bytes(), "u64").unwrap()["value"],
            json!("18446744073709551615")
        );
        assert_eq!(
            typed_value(&(-2i64).to_le_bytes(), "i64").unwrap()["value"],
            json!("-2")
        );
        assert_eq!(
            typed_value(&f32::NAN.to_le_bytes(), "f32").unwrap()["value"],
            json!("nan")
        );
        assert_eq!(
            typed_value(&f64::NEG_INFINITY.to_le_bytes(), "f64").unwrap()["value"],
            json!("-inf")
        );
        assert_eq!(
            typed_value(&1.5f32.to_le_bytes(), "f32").unwrap()["value"],
            json!(1.5)
        );
        let result = typed_value(&[0xfe, 0xff], "i16").unwrap();
        assert_eq!(
            result,
            json!({"type": "i16", "value": -2, "endianness": "little", "hex": "feff"})
        );
        assert!(typed_value(&[1, 2, 3], "u32").is_err());
        assert!(typed_value(&[1], "u128").is_err());
    }

    #[test]
    fn pattern_wildcards_and_result_limit() {
        let result = scan_pattern(b"\x01\x02\x01\x03\x01\x04", "01 ??", 2).unwrap();
        assert_eq!(result["matches"], json!(["0x0", "0x2"]));
        assert_eq!(result["truncated"], json!(true));
        let result = scan_pattern_at(b"\x01\x02\x01", "01   02", 0x1000, 8).unwrap();
        assert_eq!(result["matches"], json!(["0x1000"]));
        assert_eq!(result["truncated"], json!(false));
        assert_eq!(
            scan_pattern(b"a", "61 62", 8).unwrap()["matches"],
            json!([])
        );
    }

    #[test]
    fn pattern_invalid_tokens() {
        for pattern in ["", "-1", "+f", "100", "GG", "?", "0x1"] {
            assert!(scan_pattern(b"test", pattern, 8).is_err(), "{pattern:?}");
        }
        assert!(
            scan_pattern(b"test", "GG", 8)
                .unwrap_err()
                .to_string()
                .contains("Invalid byte pattern")
        );
        assert!(
            scan_pattern(b"test", "100", 8)
                .unwrap_err()
                .to_string()
                .contains("two hex")
        );
        assert!(scan_pattern(b"test", &"?? ".repeat(257), 8).is_err());
    }

    #[test]
    fn diff_ranges() {
        let (_directory, store) = store();
        let left = store.save("memory", b"abcde", Value::Null, "bin").unwrap();
        let right = store.save("memory", b"aXYde!", Value::Null, "bin").unwrap();
        let result = diff(
            &store,
            left["path"].as_str().unwrap(),
            right["path"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(result["changed_bytes"], json!(3));
        assert_eq!(
            result["ranges"],
            json!([{"offset": 1, "length": 2}, {"offset": 5, "length": 1}])
        );
        assert_eq!(result["ranges_may_be_truncated"], json!(false));
    }

    #[test]
    fn diff_caps_ranges() {
        let (_directory, store) = store();
        let left = store
            .save("memory", &[0u8; 1024], Value::Null, "bin")
            .unwrap();
        let alternating: Vec<u8> = (0..1024).map(|i| (i % 2) as u8).collect();
        let right = store
            .save("memory", &alternating, Value::Null, "bin")
            .unwrap();
        let result = diff(
            &store,
            left["path"].as_str().unwrap(),
            right["path"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(result["ranges"].as_array().unwrap().len(), MAX_DIFF_RANGES);
        assert_eq!(result["changed_bytes"], json!(512));
        assert_eq!(result["ranges_may_be_truncated"], json!(true));
    }

    #[test]
    fn annotation_and_ghidra_export() {
        let (_directory, store) = store();
        let memory = store.save("memory", b"hello", Value::Null, "bin").unwrap();
        let path = memory["path"].as_str().unwrap();
        assert!(annotate(&store, path, "bad", 1, "x", "").is_err());
        let note = annotate(&store, path, &"a".repeat(64), 0x1234, "evidence", "sym").unwrap();
        let saved: Value =
            serde_json::from_slice(&store.read(note["path"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(saved["rva"], json!("0x1234"));
        assert_eq!(saved["artifact_sha256"], json!(sha256_hex(b"hello")));
        let export = ghidra_export(&store, path, 0x400000, &"a".repeat(64)).unwrap();
        assert!(export["id"].as_str().unwrap().starts_with("experiment-"));
        assert_eq!(store.inventory().unwrap().as_array().unwrap().len(), 3);
    }

    #[test]
    fn correlation_and_snapshot() {
        let maps = json!([
            {"start": 0x1000, "end": 0x2000, "offset": 0, "protection": 5, "name": "a"},
            {"start": 0x4000, "end": 0x6000, "offset": 0x1000, "protection": 5, "name": "eboot.bin"},
        ]);
        let result = correlate_maps(&maps, 71, 0x4010, &"a".repeat(64), "01.00").unwrap();
        assert_eq!(result["module_name"], json!("eboot.bin"));
        assert_eq!(result["estimated_image_base"], json!("0x3000"));
        assert_eq!(result["estimated_rva"], json!("0x1010"));
        assert_eq!(result["mapping_relative_offset"], json!("0x10"));
        assert!(correlate_maps(&maps, 71, 0x3000, &"a".repeat(64), "01.00").is_err());

        let (_directory, store) = store();
        let record = snapshot_record(
            &store,
            b"abcd",
            71,
            0x4000,
            4,
            "01.00",
            &"a".repeat(64),
            json!({"pid": 71}),
            maps,
            json!(null),
        )
        .unwrap();
        assert_eq!(record["metadata"]["atomic_snapshot"], json!(false));
        assert_eq!(
            record["metadata"]["module_hash_source"],
            json!("user_supplied")
        );
    }

    fn build_minimal_elf() -> Vec<u8> {
        // ELF64 header + 2 phdrs (PT_LOAD, PT_DYNAMIC) + dynamic entries +
        // .dynstr + section headers with a string table.
        let mut d = vec![0u8; 64];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        d[5] = 1;
        d[6] = 1;
        d[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        d[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
        d[20..24].copy_from_slice(&1u32.to_le_bytes());
        d[24..32].copy_from_slice(&0x1000u64.to_le_bytes()); // entry
        d[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
        d[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
        d[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        d[56..58].copy_from_slice(&2u16.to_le_bytes()); // phnum
        d[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
        d[60..62].copy_from_slice(&4u16.to_le_bytes()); // shnum
        d[62..64].copy_from_slice(&1u16.to_le_bytes()); // shstrndx

        let dyn_off = 64 + 2 * 56; // 176
        let strtab_off = dyn_off + 4 * 16; // 240
        let needed = b"libSceX.so\0";
        let shstr_off = strtab_off + needed.len(); // 251
        let shstr = b"\0.shstrtab\0.dynsym\0.dynamic\0.text\0";
        let shoff = shstr_off + shstr.len();
        let shoff = (shoff + 7) & !7;
        let total = shoff + 4 * 64;
        d.resize(total, 0);
        d[40..48].copy_from_slice(&(shoff as u64).to_le_bytes()); // shoff

        let phdr = |d: &mut Vec<u8>, i: usize, ty: u32, flags: u32, off: u64, vaddr: u64, filesz: u64| {
            let base = 64 + i * 56;
            d[base..base + 4].copy_from_slice(&ty.to_le_bytes());
            d[base + 4..base + 8].copy_from_slice(&flags.to_le_bytes());
            d[base + 8..base + 16].copy_from_slice(&off.to_le_bytes());
            d[base + 16..base + 24].copy_from_slice(&vaddr.to_le_bytes());
            d[base + 32..base + 40].copy_from_slice(&filesz.to_le_bytes());
            d[base + 40..base + 48].copy_from_slice(&filesz.to_le_bytes());
        };
        phdr(&mut d, 0, 1, 5, 0, 0, total as u64); // PT_LOAD r-x, vaddr 0
        phdr(&mut d, 1, 2, 6, dyn_off as u64, dyn_off as u64, 4 * 16); // PT_DYNAMIC

        let dyn_entry = |d: &mut Vec<u8>, i: usize, tag: u64, value: u64| {
            let base = dyn_off + i * 16;
            d[base..base + 8].copy_from_slice(&tag.to_le_bytes());
            d[base + 8..base + 16].copy_from_slice(&value.to_le_bytes());
        };
        dyn_entry(&mut d, 0, 1, 0); // DT_NEEDED -> strtab+0
        dyn_entry(&mut d, 1, 5, strtab_off as u64); // DT_STRTAB (vaddr == offset here)
        dyn_entry(&mut d, 2, 10, needed.len() as u64); // DT_STRSZ
        dyn_entry(&mut d, 3, 0, 0); // DT_NULL
        d[strtab_off..strtab_off + needed.len()].copy_from_slice(needed);
        d[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

        // simpler: offsets within shstr
        let off = |name: &str| shstr.windows(name.len() + 1).position(|w| w == format!("{name}\0").as_bytes()).unwrap() as u32;
        let shdr = |d: &mut Vec<u8>, i: usize, name: u32, ty: u32, addr: u64, offset: u64, size: u64| {
            let base = shoff + i * 64;
            d[base..base + 4].copy_from_slice(&name.to_le_bytes());
            d[base + 4..base + 8].copy_from_slice(&ty.to_le_bytes());
            d[base + 8..base + 16].copy_from_slice(&2u64.to_le_bytes()); // SHF_ALLOC
            d[base + 16..base + 24].copy_from_slice(&addr.to_le_bytes());
            d[base + 24..base + 32].copy_from_slice(&offset.to_le_bytes());
            d[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
        };
        shdr(&mut d, 0, 0, 0, 0, 0, 0); // null
        shdr(&mut d, 1, off(".shstrtab"), 3, 0, shstr_off as u64, shstr.len() as u64);
        shdr(&mut d, 2, off(".dynsym"), 11, 0, 0, 48); // 2 dynsym entries
        shdr(&mut d, 3, off(".dynamic"), 6, dyn_off as u64, dyn_off as u64, 4 * 16);
        d
    }

    #[test]
    fn elf_info_parses_header_loads_sections_and_needed() {
        let info = artifact_info(&build_minimal_elf()).unwrap();
        assert_eq!(info["kind"], "elf64");
        assert_eq!(info["type"], "shared_object");
        assert_eq!(info["machine"], "x86-64");
        assert_eq!(info["entry"], "0x1000");
        assert_eq!(info["image_base"], "0x0");
        assert_eq!(info["loads"][0]["permissions"], "r-x");
        assert_eq!(info["section_count"], 4);
        assert_eq!(info["symbols"]["dynsym_entries"], 2);
        assert_eq!(info["dynamic_needed"], json!(["libSceX.so"]));
        let names: Vec<&str> = info["sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&".dynsym") && names.contains(&".dynamic"));
    }

    #[test]
    fn artifact_info_identifies_self_and_rejects_truncated_elf() {
        let self_file = artifact_info(b"\x4f\x15\x3d\x1d\x07rest").unwrap();
        assert_eq!(self_file["kind"], "ps4_self");
        assert_eq!(self_file["version"], 7);
        assert!(artifact_info(b"\x7fELF\x02\x01").is_err());
        let raw = artifact_info(b"\x90\x90\x90\x90bin").unwrap();
        assert_eq!(raw["kind"], "raw_binary");
    }

    #[test]
    fn disassemble_artifact_and_strings_are_bounded() {
        // push rbp; mov rbp,rsp; call +0x10; xor eax,eax; ret
        let code = [0x55u8, 0x48, 0x89, 0xe5, 0xe8, 0x10, 0x00, 0x00, 0x00, 0x31, 0xc0, 0xc3];
        let listing = disassemble_artifact(&code, 0, 0x400000, 8).unwrap();
        let items = listing["instructions"].as_array().unwrap();
        assert_eq!(items[0]["address"], "0x400000");
        assert_eq!(items[0]["text"], "push rbp");
        assert_eq!(items[2]["flow"], "call");
        assert_eq!(items[2]["branch_target"], "0x400019");
        assert!(disassemble_artifact(&code, 0, 0x400000, 0).is_err());
        assert!(disassemble_artifact(&code, 999, 0x400000, 4).is_err());

        let data = b"\x00\x00hi there\x00\x00ab\x00longer string here\x00";
        let found = strings(data, 4, 10).unwrap();
        let texts: Vec<&str> = found["strings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["text"].as_str().unwrap())
            .collect();
        assert_eq!(texts, vec!["hi there", "longer string here"]);
        assert!(strings(data, 3, 10).is_err());
    }

    #[test]
    fn elf_info_resolves_orbis_nid_symbols() {
        // Build an ELF64 with a real .dynsym + .dynstr containing an Orbis NID symbol.
        let mut d = vec![0u8; 64];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        d[5] = 1;
        d[6] = 1;
        d[16..18].copy_from_slice(&3u16.to_le_bytes());
        d[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        d[20..24].copy_from_slice(&1u32.to_le_bytes());
        d[32..40].copy_from_slice(&64u64.to_le_bytes());
        d[52..54].copy_from_slice(&64u16.to_le_bytes());
        d[54..56].copy_from_slice(&56u16.to_le_bytes());
        d[56..58].copy_from_slice(&1u16.to_le_bytes());
        d[58..60].copy_from_slice(&64u16.to_le_bytes());
        d[60..62].copy_from_slice(&4u16.to_le_bytes());
        d[62..64].copy_from_slice(&1u16.to_le_bytes());

        let shstr = b"\0.shstrtab\0.dynstr\0.dynsym\0";
        let dynstr = b"\01jfXLRVzisc#libkernel#libkernel\0";
        let shstr_off = 128usize;
        let dynstr_off = shstr_off + shstr.len();
        let dynsym_off = (dynstr_off + dynstr.len() + 7) & !7;
        let dynsym_sz = 48usize; // null + 1 symbol
        let shoff = (dynsym_off + dynsym_sz + 7) & !7;
        let total = shoff + 4 * 64;
        d.resize(total, 0);
        d[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());

        // PT_LOAD covering file
        let p = 64;
        d[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
        d[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        d[p + 32..p + 40].copy_from_slice(&(total as u64).to_le_bytes());
        d[p + 40..p + 48].copy_from_slice(&(total as u64).to_le_bytes());

        d[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);
        d[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(dynstr);

        // Symbol 1: st_name = 1, st_info = (STB_GLOBAL=1)<<4 | STT_FUNC=2 = 0x12, st_shndx = 0 (undef import)
        let sym1 = dynsym_off + 24;
        d[sym1..sym1 + 4].copy_from_slice(&1u32.to_le_bytes());
        d[sym1 + 4] = 0x12;

        let off = |name: &str| {
            shstr
                .windows(name.len() + 1)
                .position(|w| w == format!("{name}\0").as_bytes())
                .unwrap() as u32
        };
        let shdr = |d: &mut Vec<u8>, i: usize, name: u32, ty: u32, offset: usize, size: usize, link: u32| {
            let b = shoff + i * 64;
            d[b..b + 4].copy_from_slice(&name.to_le_bytes());
            d[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes());
            d[b + 24..b + 32].copy_from_slice(&(offset as u64).to_le_bytes());
            d[b + 32..b + 40].copy_from_slice(&(size as u64).to_le_bytes());
            d[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
        };
        shdr(&mut d, 0, 0, 0, 0, 0, 0);
        shdr(&mut d, 1, off(".shstrtab"), 3, shstr_off, shstr.len(), 0);
        shdr(&mut d, 2, off(".dynstr"), 3, dynstr_off, dynstr.len(), 0);
        shdr(&mut d, 3, off(".dynsym"), 11, dynsym_off, dynsym_sz, 2);

        let info = elf_info(&d).unwrap();
        assert_eq!(info["symbols"]["nid_resolved"], 1);
        let entry = &info["symbols"]["entries"][0];
        assert_eq!(entry["nid"], "1jfXLRVzisc");
        assert_eq!(entry["resolved_name"], "sceKernelUsleep");
        assert_eq!(entry["defined"], false);
    }
}
