//! Offline structure inference from `ps4wb-access-v1` access logs plus optional
//! object memory images. Pure functions: callers gather the evidence (artifacts,
//! optional read-only live samples) and this module emits `ps4wb-struct-v1`.
use crate::Result;
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const FORMAT: &str = "ps4wb-struct-v1";
pub const ACCESS_FORMAT: &str = "ps4wb-access-v1";
pub const MAX_STRUCT_SIZE: u64 = 0x10000;

/// One mapping `(start, end, protection bits r=1 w=2 x=4, name)`.
pub type MapEntry = (u64, u64, u64, String);

#[derive(Debug, Default, Clone)]
pub struct Evidence {
    /// Parsed `ps4wb-access-v1` documents.
    pub access_logs: Vec<Value>,
    /// Object images whose byte 0 is struct offset 0 (snapshots / live samples).
    pub images: Vec<Vec<u8>>,
    /// Process maps used to classify pointer values (may be empty).
    pub maps: Vec<MapEntry>,
}

#[derive(Debug, Default)]
struct Group {
    sizes: BTreeMap<u64, u64>,
    mnemonics: BTreeSet<String>,
    disasm: BTreeSet<String>,
    kinds: BTreeSet<String>,
    count: u64,
    values: Vec<u64>,
    evidence: Vec<String>,
}

fn parse_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => text.parse().ok(),
        },
        _ => None,
    }
}

/// First mnemonic token of an Intel-syntax line, skipping prefixes.
pub fn mnemonic(disasm: &str) -> String {
    disasm
        .split_whitespace()
        .find(|token| !matches!(*token, "lock" | "rep" | "repe" | "repne" | "repz" | "repnz" | "xacquire" | "xrelease" | "notrack" | "bnd"))
        .unwrap_or("")
        .to_ascii_lowercase()
}

const SCALAR_SINGLE: &[&str] = &[
    "movss", "addss", "subss", "mulss", "divss", "minss", "maxss", "sqrtss", "comiss", "ucomiss",
    "cvtss2sd", "cvtss2si", "cvttss2si", "rcpss", "rsqrtss", "roundss", "fld", "fstp", "fst",
];
const SCALAR_DOUBLE: &[&str] = &[
    "movsd", "addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd", "sqrtsd", "comisd", "ucomisd",
    "cvtsd2ss", "cvtsd2si", "cvttsd2si", "roundsd",
];
const PACKED_SINGLE: &[&str] = &["movaps", "movups", "addps", "subps", "mulps", "divps", "minps", "maxps", "shufps"];

fn base_mnemonic(mnemonic: &str) -> &str {
    // VEX forms: vmovss -> movss
    match mnemonic.strip_prefix('v') {
        Some(rest) if SCALAR_SINGLE.contains(&rest) || SCALAR_DOUBLE.contains(&rest) || PACKED_SINGLE.contains(&rest) => rest,
        _ => mnemonic,
    }
}

fn map_of(maps: &[MapEntry], address: u64) -> Option<&MapEntry> {
    maps.iter().find(|(start, end, _, _)| *start <= address && address < *end)
}

fn read_value(image: &[u8], offset: u64, size: u64) -> Option<u64> {
    let start = usize::try_from(offset).ok()?;
    let bytes = image.get(start..start.checked_add(size as usize)?)?;
    let mut padded = [0u8; 8];
    padded[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
    Some(u64::from_le_bytes(padded))
}

fn plausible_f32(raw: u64) -> bool {
    let value = f32::from_bits(raw as u32);
    value.is_finite() && (value == 0.0 || (1e-6..1e7).contains(&value.abs())) && (raw as u32) & 0x7f80_0000 != 0
}

fn plausible_f64(raw: u64) -> bool {
    let value = f64::from_bits(raw);
    value.is_finite() && (1e-9..1e12).contains(&value.abs()) && (raw >> 52) & 0x7ff != 0
}

struct TypeGuess {
    ty: String,
    confidence: &'static str,
    note: Option<String>,
}

fn guess_type(offset: u64, size: u64, group: &Group, maps: &[MapEntry]) -> TypeGuess {
    let mnemonics: Vec<&str> = group.mnemonics.iter().map(|m| base_mnemonic(m)).collect();
    let has = |set: &[&str]| mnemonics.iter().any(|m| set.contains(m));
    let disasm_has_xmm = group.disasm.iter().any(|text| text.contains("xmm") || text.contains("ymm") || text.starts_with("f"));
    let nonzero: Vec<u64> = group.values.iter().copied().filter(|value| *value != 0).collect();
    let guess = |ty: &str, confidence, note: Option<String>| TypeGuess { ty: ty.to_owned(), confidence, note };
    if size == 16 && has(PACKED_SINGLE) {
        return guess("float[4]", "medium", Some("packed single-precision SSE access".into()));
    }
    if size == 4 && has(SCALAR_SINGLE) && disasm_has_xmm || size == 4 && mnemonics.iter().any(|m| matches!(*m, "fld" | "fstp" | "fst")) {
        return guess("float", "high", Some("scalar single-precision instruction".into()));
    }
    if size == 8 && has(SCALAR_DOUBLE) && disasm_has_xmm {
        return guess("double", "high", Some("scalar double-precision instruction".into()));
    }
    if mnemonics.iter().any(|m| matches!(*m, "cvtsi2ss" | "cvtsi2sd")) {
        return guess(if size == 8 { "int64_t" } else { "int32_t" }, "medium", Some("integer converted to floating point".into()));
    }
    if size == 8 && mnemonics.iter().any(|m| matches!(*m, "call" | "jmp")) {
        return guess("void*", "high", Some("indirect call/jump through this slot (code pointer / vtable entry)".into()));
    }
    if size == 8 && !nonzero.is_empty() {
        let targets: Vec<Option<&MapEntry>> = nonzero.iter().map(|value| map_of(maps, *value)).collect();
        if !maps.is_empty() && targets.iter().all(|target| target.is_some_and(|entry| entry.2 & 1 != 0)) {
            let exec = targets.iter().all(|target| target.is_some_and(|entry| entry.2 & 4 != 0));
            let rodata = targets
                .iter()
                .all(|target| target.is_some_and(|entry| entry.2 & 6 == 0 && !entry.3.is_empty()));
            if exec {
                return guess("void*", "high", Some("values point into executable memory (code pointer)".into()));
            }
            if offset == 0 && rodata {
                return guess("void**", "medium", Some("offset 0 points into read-only module data (vtable-like)".into()));
            }
            return guess("void*", "high", Some("values point into mapped memory".into()));
        }
        if maps.is_empty() && nonzero.iter().all(|value| (0x10000..0x8000_0000_0000).contains(value) && value % 8 == 0) {
            return guess("void*", "low", Some("aligned user-space-looking values (no maps to confirm)".into()));
        }
        if nonzero.iter().all(|value| plausible_f64(*value)) && !mnemonics.iter().any(|m| m.starts_with("movsx") || matches!(*m, "inc" | "dec" | "add" | "sub")) {
            return guess("double", "low", Some("values decode as plausible doubles".into()));
        }
    }
    let signed = mnemonics.iter().any(|m| m.starts_with("movsx"));
    match size {
        1 => {
            if !group.values.is_empty() && group.values.iter().all(|value| *value <= 1) {
                guess("bool", "medium", Some("only 0/1 observed".into()))
            } else {
                guess(if signed { "int8_t" } else { "uint8_t" }, "medium", None)
            }
        }
        2 => guess(if signed { "int16_t" } else { "uint16_t" }, "medium", None),
        4 => {
            if !nonzero.is_empty() && nonzero.iter().all(|value| plausible_f32(*value)) && !disasm_has_xmm
                && mnemonics.iter().all(|m| matches!(*m, "mov" | "movd" | ""))
            {
                guess("float", "low", Some("values decode as plausible floats".into()))
            } else if signed || nonzero.iter().any(|value| *value as u32 >= 0xffff_0000) {
                guess("int32_t", "medium", Some("sign-extended or small negative values".into()))
            } else {
                guess("uint32_t", "medium", None)
            }
        }
        8 => guess("uint64_t", "low", None),
        16 => guess("uint8_t[16]", "low", Some("16-byte vector access".into())),
        _ => guess("uint8_t", "low", None),
    }
}

/// Element type and count from `float[4]`-style types.
fn split_array(ty: &str) -> (&str, Option<&str>) {
    match ty.find('[') {
        Some(index) => (&ty[..index], Some(&ty[index..])),
        None => (ty, None),
    }
}

fn c_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Infer a structure from evidence. `size` overrides the inferred size.
pub fn infer(name: &str, size: Option<u64>, evidence: &Evidence) -> Result<Value> {
    ensure!(c_identifier(name), "Struct name must be a C identifier");
    ensure!(!evidence.access_logs.is_empty() || !evidence.images.is_empty(), "No evidence supplied");
    let mut groups: BTreeMap<u64, Group> = BTreeMap::new();
    // instruction -> (size, offsets) for stride detection
    let mut by_instruction: BTreeMap<String, BTreeSet<(u64, u64)>> = BTreeMap::new();
    let mut span = 0u64;
    for log in &evidence.access_logs {
        ensure!(log["format"] == ACCESS_FORMAT, "Access log is not {ACCESS_FORMAT}");
        span = span.max(parse_u64(&log["span"]).or_else(|| parse_u64(&log["length"])).unwrap_or(0));
        for access in log["accesses"].as_array().context("Access log needs accesses")? {
            let Some(offset) = access["offset"].as_i64() else { continue };
            if offset < 0 || offset as u64 >= MAX_STRUCT_SIZE {
                continue;
            }
            let offset = offset as u64;
            let access_size = parse_u64(&access["size"]).unwrap_or(1).clamp(1, 64);
            let disasm = access["disasm"].as_str().unwrap_or("").to_owned();
            let count = parse_u64(&access["count"]).unwrap_or(1);
            let instruction = access["instruction"].as_str().unwrap_or("?").to_owned();
            let group = groups.entry(offset).or_default();
            *group.sizes.entry(access_size).or_default() += count;
            group.mnemonics.insert(mnemonic(&disasm));
            group.disasm.insert(disasm.clone());
            group.kinds.insert(access["kind"].as_str().unwrap_or("?").to_owned());
            group.count += count;
            if group.evidence.len() < 8 {
                group.evidence.push(format!(
                    "{} {}B by {} ({}): {} x{}",
                    access["kind"].as_str().unwrap_or("access"),
                    access_size,
                    instruction,
                    access["location"].as_str().unwrap_or("?"),
                    disasm,
                    count
                ));
            }
            let mask = if access_size >= 8 { u64::MAX } else { (1u64 << (access_size * 8)) - 1 };
            for sample in access["samples"].as_array().into_iter().flatten().take(16) {
                for key in ["old", "new", "value"] {
                    if let Some(value) = parse_u64(&sample[key]) {
                        group.values.push(value & mask);
                    }
                }
            }
            by_instruction.entry(instruction).or_default().insert((offset, access_size));
        }
    }
    // Strided arrays: one instruction touching >= 3 offsets at a constant stride == element size.
    let mut arrays: Vec<(u64, u64, u64, String)> = Vec::new(); // (start, stride, count, instruction)
    for (instruction, accesses) in &by_instruction {
        let offsets: Vec<(u64, u64)> = accesses.iter().copied().collect();
        if offsets.len() < 3 || offsets.iter().any(|(_, size)| *size != offsets[0].1) {
            continue;
        }
        let stride = offsets[1].0 - offsets[0].0;
        if stride == offsets[0].1 && offsets.windows(2).all(|pair| pair[1].0 - pair[0].0 == stride) {
            arrays.push((offsets[0].0, stride, offsets.len() as u64, instruction.clone()));
        }
    }
    let mut fields: Vec<Value> = Vec::new();
    let mut covered: Vec<(u64, u64, u64)> = Vec::new(); // (start, end, weight)
    let mut push_field = |field: Value, start: u64, end: u64, weight: u64, fields: &mut Vec<Value>| {
        if let Some(position) = covered.iter().position(|(s, e, _)| start < *e && *s < end) {
            let note = format!("overlapping access at offset {start:#x} size {} (union or sub-field)", end - start);
            if covered[position].2 >= weight {
                if let Some(existing) = fields.iter_mut().find(|f| f["offset"] == json!(covered[position].0)) {
                    existing["evidence"].as_array_mut().unwrap().push(json!(note));
                }
                return;
            }
            fields.retain(|f| f["offset"] != json!(covered[position].0));
            covered.remove(position);
        }
        covered.push((start, end, weight));
        fields.push(field);
    };
    for (start, stride, count, instruction) in &arrays {
        let group = groups.get(start);
        let element = group.map_or_else(
            || TypeGuess { ty: "uint8_t".into(), confidence: "low", note: None },
            |group| guess_type(*start, *stride, group, &evidence.maps),
        );
        let (element_type, _) = split_array(&element.ty);
        let ty = format!("{element_type}[{count}]");
        let weight: u64 = (0..*count).filter_map(|i| groups.get(&(start + i * stride))).map(|g| g.count).sum();
        let mut notes = vec![json!(format!("strided array: {instruction} accessed {count} elements at stride {stride:#x}"))];
        if let Some(note) = element.note {
            notes.push(json!(note));
        }
        push_field(
            json!({"offset":start,"size":stride * count,"name":format!("field_{start:#x}"),"type":ty,
                "confidence":"medium","evidence":notes}),
            *start,
            start + stride * count,
            weight + 1_000_000,
            &mut fields,
        );
    }
    for (offset, group) in &mut groups {
        let size = group
            .sizes
            .iter()
            .max_by_key(|(size, count)| (**count, **size))
            .map(|(size, _)| *size)
            .unwrap_or(1)
            .min(16);
        for image in &evidence.images {
            if let Some(value) = read_value(image, *offset, size.min(8)) {
                group.values.push(value);
            }
        }
        let guess = guess_type(*offset, size, group, &evidence.maps);
        let mut notes: Vec<Value> = group.evidence.iter().map(|text| json!(text)).collect();
        if let Some(note) = guess.note {
            notes.push(json!(note));
        }
        let distinct: BTreeSet<u64> = group.values.iter().copied().collect();
        if !distinct.is_empty() {
            notes.push(json!(format!(
                "observed values: {}",
                distinct.iter().take(6).map(|value| format!("{value:#x}")).collect::<Vec<_>>().join(", ")
            )));
        }
        push_field(
            json!({"offset":offset,"size":size,"name":format!("field_{offset:#x}"),"type":guess.ty,
                "confidence":guess.confidence,"evidence":notes,"access_count":group.count,
                "kinds":group.kinds.iter().collect::<Vec<_>>()}),
            *offset,
            offset + size,
            group.count,
            &mut fields,
        );
    }
    fields.sort_by_key(|field| field["offset"].as_u64().unwrap_or(0));
    let end = fields
        .iter()
        .map(|field| field["offset"].as_u64().unwrap_or(0) + field["size"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let image_len = evidence.images.iter().map(Vec::len).max().unwrap_or(0) as u64;
    let total = size.unwrap_or_else(|| end.max(span).max(if fields.is_empty() { image_len } else { 0 }).div_ceil(8) * 8).max(end);
    ensure!(total > 0 && total <= MAX_STRUCT_SIZE, "Inferred struct size out of range");
    // C declaration with explicit padding.
    let mut lines = vec![format!("struct {name} {{")];
    let mut cursor = 0u64;
    for field in &fields {
        let offset = field["offset"].as_u64().unwrap_or(0);
        let size = field["size"].as_u64().unwrap_or(0);
        if offset > cursor {
            lines.push(format!("    uint8_t _pad_{cursor:#x}[{:#x}];", offset - cursor));
        }
        let (base, suffix) = split_array(field["type"].as_str().unwrap_or("uint8_t"));
        lines.push(format!(
            "    {base} {}{}; /* {offset:#x} */",
            field["name"].as_str().unwrap_or("field"),
            suffix.unwrap_or("")
        ));
        cursor = offset + size;
    }
    if total > cursor {
        lines.push(format!("    uint8_t _pad_{cursor:#x}[{:#x}];", total - cursor));
    }
    lines.push("};".into());
    Ok(json!({"format":FORMAT,"name":name,"size":total,"fields":fields,
        "c_declaration":lines.join("\n"),
        "sources":{"access_logs":evidence.access_logs.len(),"images":evidence.images.len(),"maps":evidence.maps.len()},
        "note":"Types are heuristic: operand sizes and instruction classes are strong evidence; value-based guesses (pointer/float) depend on the samples supplied"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(instruction: &str, offset: u64, size: u64, kind: &str, disasm: &str, samples: Value) -> Value {
        json!({"instruction":instruction,"location":"game+0x1","disasm":disasm,"address":format!("{:#x}",0x5000+offset),
            "offset":offset,"size":size,"kind":kind,"count":2,"samples":samples})
    }

    #[test]
    fn infers_floats_pointers_bools_arrays_and_declaration() {
        let log = json!({"format":ACCESS_FORMAT,"base":"0x5000","accesses":[
            access("0x401000", 0x0, 8, "read", "mov rax, qword ptr [rbx]", json!([{"old":"0x400100","new":"0x400100"}])),
            access("0x401010", 0x10, 4, "write", "movss dword ptr [rbx+0x10], xmm0", json!([])),
            access("0x401020", 0x18, 8, "read", "mov rcx, qword ptr [rbx+0x18]", json!([{"new":"0x900000"}])),
            access("0x401030", 0x20, 1, "write", "mov byte ptr [rbx+0x20], al", json!([{"old":"0x0","new":"0x1"}])),
            access("0x401040", 0x30, 4, "read", "mov eax, dword ptr [rbx+rcx*4+0x30]", json!([])),
            access("0x401040", 0x34, 4, "read", "mov eax, dword ptr [rbx+rcx*4+0x30]", json!([])),
            access("0x401040", 0x38, 4, "read", "mov eax, dword ptr [rbx+rcx*4+0x30]", json!([])),
            access("0x401050", 0x40, 8, "read", "movsd xmm1, qword ptr [rbx+0x40]", json!([])),
        ]});
        let maps = vec![
            (0x400000, 0x401000, 1, "game".to_owned()),
            (0x401000, 0x402000, 5, "game".to_owned()),
            (0x900000, 0x901000, 3, String::new()),
        ];
        let result = infer("Player", None, &Evidence { access_logs: vec![log], images: vec![], maps }).unwrap();
        assert_eq!(result["format"], FORMAT);
        let field = |offset: u64| result["fields"].as_array().unwrap().iter().find(|f| f["offset"] == offset).cloned().unwrap();
        assert_eq!(field(0)["type"], "void**");
        assert_eq!(field(0x10)["type"], "float");
        assert_eq!(field(0x18)["type"], "void*");
        assert_eq!(field(0x20)["type"], "bool");
        assert_eq!(field(0x30)["type"], "uint32_t[3]");
        assert_eq!(field(0x30)["size"], 12);
        assert_eq!(field(0x40)["type"], "double");
        assert_eq!(field(0x10)["name"], "field_0x10");
        assert_eq!(result["size"], 0x48);
        let declaration = result["c_declaration"].as_str().unwrap();
        assert!(declaration.starts_with("struct Player {"), "{declaration}");
        assert!(declaration.contains("uint32_t field_0x30[3];"), "{declaration}");
        assert!(declaration.contains("uint8_t _pad_0x8[0x8];"), "{declaration}");
        assert!(infer("bad name", None, &Evidence::default()).is_err());
    }

    #[test]
    fn images_supply_values_for_plain_moves() {
        let log = json!({"format":ACCESS_FORMAT,"base":"0x0","accesses":[
            access("0x1", 0x4, 4, "read", "mov eax, dword ptr [rdi+0x4]", json!([]))]});
        let mut image = vec![0u8; 16];
        image[4..8].copy_from_slice(&1.5f32.to_bits().to_le_bytes());
        let result = infer("S", Some(16), &Evidence { access_logs: vec![log], images: vec![image], maps: vec![] }).unwrap();
        assert_eq!(result["fields"][0]["type"], "float");
        assert_eq!(result["fields"][0]["confidence"], "low");
        assert_eq!(result["size"], 16);
    }
}
