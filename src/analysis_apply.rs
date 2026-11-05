//! Validation and batching for `analysis_apply_*` broker tools.
//!
//! The broker reads a bounded JSON artifact, validates it here, rebases RVAs
//! (absolute `address` = `static_base` + RVA when `static_base` is supplied,
//! otherwise the item carries `rva` and the agent adds its own image base) and
//! sends compact batches to the connected analyzer agent. Agent operations:
//! `apply_prototypes`, `apply_struct`, `apply_coverage`, `apply_symbols`
//! (`analysis_apply_classes` is lowered to `apply_symbols`).
use crate::Result;
use crate::agents::parse_address;
use anyhow::{Context, bail};
use serde_json::{Map, Value, json};
use std::collections::HashSet;

pub const APPLY_TOOLS: &[&str] = &[
    "analysis_apply_prototypes",
    "analysis_apply_struct",
    "analysis_apply_coverage",
    "analysis_apply_classes",
    "analysis_apply_symbols",
];
/// Agent-side operations and the argument keys each accepts.
pub const AGENT_OPERATIONS: &[(&str, &[&str])] = &[
    ("apply_prototypes", &["prototypes", "overwrite"]),
    ("apply_struct", &["struct", "overwrite"]),
    ("apply_coverage", &["blocks", "clear", "color", "comment"]),
    ("apply_symbols", &["symbols", "overwrite"]),
];
/// Largest artifact the broker will parse for an apply operation.
pub const MAX_APPLY_ARTIFACT: usize = 16 * 1024 * 1024;
/// Largest batch (items per agent job).
pub const MAX_BATCH_ITEMS: usize = 2000;
const PROTOTYPE_BATCH: usize = 200;
const SYMBOL_BATCH: usize = 500;
const COVERAGE_BATCH: usize = 2000;
const MAX_STRUCT_FIELDS: usize = 4096;
const MAX_STRUCT_SIZE: u64 = 1 << 20;

pub struct Prepared {
    pub operation: &'static str,
    pub batches: Vec<Value>,
    pub items: usize,
    pub skipped: usize,
    pub format: String,
    pub module_sha256: Option<String>,
}

impl Prepared {
    pub fn summary(&self) -> Value {
        json!({"agent_operation": self.operation, "format": self.format, "items": self.items,
            "skipped_invalid": self.skipped, "batches": self.batches.len(), "module_sha256": self.module_sha256})
    }
}

fn rva_of(value: &Value) -> Option<u64> {
    match value {
        Value::String(text) => parse_address(text).ok(),
        Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

/// Item address fields: absolute `address` with a static base, else `rva` for agent-side rebasing.
fn place(rva: u64, static_base: Option<u64>) -> Option<(&'static str, Value)> {
    match static_base {
        Some(base) => base.checked_add(rva).map(|a| ("address", json!(format!("{a:#x}")))),
        None => Some(("rva", json!(format!("{rva:#x}")))),
    }
}

/// Analyzer-safe symbol name (same character set the broker's rename accepts).
pub fn symbol_name(text: &str) -> Option<String> {
    let clean: String = text
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '@' | '?' | ':' | '+' | '-') { c } else { '_' })
        .take(256)
        .collect();
    (!clean.is_empty() && !clean.chars().all(|c| c == '_')).then_some(clean)
}

fn c_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && !text.as_bytes()[0].is_ascii_digit()
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// C type text: identifiers, spaces, pointers, arrays, templates/namespaces; no statement separators.
fn c_type(text: &str) -> bool {
    !text.trim().is_empty()
        && text.len() <= 256
        && text.chars().all(|c| c.is_ascii_alphanumeric() || " _*&[]:<>,".contains(c))
}

/// Single function declaration without body or statement separators.
fn declaration(text: &str) -> bool {
    !text.trim().is_empty()
        && text.len() <= 1024
        && text.chars().all(|c| (c.is_ascii_graphic() || c == ' ') && !";{}#\"'`\\".contains(c))
}

fn comment(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    let clean: String = text.chars().filter(|c| *c != '\0').take(2048).collect();
    (!clean.is_empty()).then_some(clean)
}

fn chunk(items: Vec<Value>, size: usize, key: &str, extra: &Map<String, Value>) -> Vec<Value> {
    items
        .chunks(size.min(MAX_BATCH_ITEMS))
        .map(|part| {
            let mut batch = extra.clone();
            batch.insert(key.into(), Value::Array(part.to_vec()));
            Value::Object(batch)
        })
        .collect()
}

fn flag(args: &Map<String, Value>, key: &str) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn limit(args: &Map<String, Value>, default: usize) -> usize {
    args.get("max_items").and_then(Value::as_u64).map_or(default, |m| m as usize)
}

fn require_format(document: &Value, expected: &str) -> Result<()> {
    match document.get("format").and_then(Value::as_str) {
        Some(found) if found == expected => Ok(()),
        Some(found) => bail!("Artifact format is {found}; expected {expected}"),
        None => bail!("Artifact lacks format; expected {expected}"),
    }
}

fn module_hash(document: &Value) -> Option<String> {
    document
        .get("module_sha256")
        .and_then(Value::as_str)
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
}

/// Validate `document` for tool `name` and build agent batches.
pub fn prepare(name: &str, document: &Value, args: &Map<String, Value>, static_base: Option<u64>) -> Result<Prepared> {
    match name {
        "analysis_apply_prototypes" => prototypes(document, args),
        "analysis_apply_struct" => structure(document, args),
        "analysis_apply_coverage" => coverage(document, args, static_base),
        "analysis_apply_classes" => classes(document, args, static_base),
        "analysis_apply_symbols" => symbols(document, args, static_base),
        _ => bail!("Unknown apply operation: {name}"),
    }
}

fn prototypes(document: &Value, args: &Map<String, Value>) -> Result<Prepared> {
    require_format(document, "ps4wb-prototypes-v1")?;
    let entries = document.get("prototypes").and_then(Value::as_array).context("prototypes array required")?;
    let filter = args.get("filter").and_then(Value::as_str).map(str::to_ascii_lowercase);
    let maximum = limit(args, 20_000);
    let mut items = Vec::new();
    let mut skipped = 0;
    let mut seen = HashSet::new();
    for entry in entries {
        let Some(name) = entry.get("name").and_then(Value::as_str).filter(|n| c_identifier(n)) else {
            skipped += 1;
            continue;
        };
        if filter.as_ref().is_some_and(|f| !name.to_ascii_lowercase().contains(f.as_str())) || !seen.insert(name.to_owned()) {
            continue;
        }
        let text = match entry.get("declaration").and_then(Value::as_str) {
            Some(text) => text.trim().trim_end_matches(';').to_owned(),
            None => {
                let ret = entry.get("return").and_then(Value::as_str).unwrap_or("int");
                let mut params = Vec::new();
                let mut valid = c_type(ret);
                for (index, param) in entry.get("params").and_then(Value::as_array).into_iter().flatten().enumerate() {
                    let kind = param.get("type").and_then(Value::as_str).unwrap_or("");
                    let pname = param.get("name").and_then(Value::as_str).filter(|n| c_identifier(n))
                        .map_or_else(|| format!("a{}", index + 1), str::to_owned);
                    valid &= c_type(kind) && kind != "...";
                    params.push(format!("{kind} {pname}"));
                }
                if !valid {
                    skipped += 1;
                    continue;
                }
                format!("{ret} {name}({})", if params.is_empty() { "void".to_owned() } else { params.join(", ") })
            }
        };
        if !declaration(&text) {
            skipped += 1;
            continue;
        }
        let mut item = json!({"name": name, "declaration": text});
        for key in ["nid", "library"] {
            if let Some(value) = entry.get(key).and_then(Value::as_str).filter(|v| v.len() <= 128 && symbol_name(v).as_deref() == Some(*v)) {
                item[key] = json!(value);
            }
        }
        items.push(item);
        if items.len() >= maximum {
            break;
        }
    }
    let count = items.len();
    let mut extra = Map::new();
    extra.insert("overwrite".into(), json!(flag(args, "overwrite")));
    Ok(Prepared { operation: "apply_prototypes", batches: chunk(items, PROTOTYPE_BATCH, "prototypes", &extra), items: count,
        skipped, format: "ps4wb-prototypes-v1".into(), module_sha256: module_hash(document) })
}

fn structure(document: &Value, args: &Map<String, Value>) -> Result<Prepared> {
    require_format(document, "ps4wb-struct-v1")?;
    let name = document.get("name").and_then(Value::as_str).filter(|n| c_identifier(n)).context("struct name must be a C identifier")?;
    let size = document.get("size").and_then(Value::as_u64).filter(|s| (1..=MAX_STRUCT_SIZE).contains(s))
        .context("struct size must be 1..=1048576")?;
    let entries = document.get("fields").and_then(Value::as_array).context("fields array required")?;
    if entries.len() > MAX_STRUCT_FIELDS {
        bail!("Struct has more than {MAX_STRUCT_FIELDS} fields");
    }
    let mut fields = Vec::new();
    let mut skipped = 0;
    let mut names = HashSet::new();
    let mut end = 0u64;
    let mut sorted: Vec<&Value> = entries.iter().collect();
    sorted.sort_by_key(|f| f.get("offset").and_then(rva_of).unwrap_or(u64::MAX));
    for field in sorted {
        let offset = field.get("offset").and_then(rva_of);
        let width = field.get("size").and_then(Value::as_u64);
        let fname = field.get("name").and_then(Value::as_str).filter(|n| c_identifier(n));
        let (Some(offset), Some(width), Some(fname)) = (offset, width, fname) else {
            skipped += 1;
            continue;
        };
        if width == 0 || offset.checked_add(width).is_none_or(|e| e > size) || offset < end || !names.insert(fname.to_owned()) {
            skipped += 1;
            continue;
        }
        end = offset + width;
        let mut item = json!({"offset": offset, "size": width, "name": fname});
        if let Some(kind) = field.get("type").and_then(Value::as_str).filter(|t| c_type(t)) {
            item["type"] = json!(kind);
        }
        if let Some(evidence) = comment(field.get("evidence")) {
            item["comment"] = json!(evidence.chars().take(256).collect::<String>());
        }
        fields.push(item);
    }
    let mut definition = json!({"name": name, "size": size, "fields": fields});
    if let Some(text) = document.get("c_declaration").and_then(Value::as_str) {
        if text.len() > 65_536 || text.contains('\0') || text.contains('#') {
            bail!("c_declaration must be <= 64 KiB without NUL or preprocessor directives");
        }
        definition["c_declaration"] = json!(text);
    }
    let count = definition["fields"].as_array().map_or(0, Vec::len);
    Ok(Prepared { operation: "apply_struct", batches: vec![json!({"struct": definition, "overwrite": flag(args, "overwrite")})],
        items: count, skipped, format: "ps4wb-struct-v1".into(), module_sha256: module_hash(document) })
}

fn coverage(document: &Value, args: &Map<String, Value>, static_base: Option<u64>) -> Result<Prepared> {
    require_format(document, "ps4wb-coverage-v1")?;
    let entries = document.get("blocks").and_then(Value::as_array).context("blocks array required")?;
    let min_hits = args.get("min_hits").and_then(Value::as_u64).unwrap_or(1);
    let maximum = args.get("max_blocks").and_then(Value::as_u64).map_or(20_000, |m| m as usize);
    let mut items = Vec::new();
    let mut skipped = 0;
    for block in entries {
        let rva = block.get("rva").and_then(rva_of);
        let size = block.get("size").and_then(Value::as_u64).filter(|s| (1..=1 << 20).contains(s));
        let hits = block.get("hits").and_then(Value::as_u64).unwrap_or(1);
        let (Some(rva), Some(size)) = (rva, size) else {
            skipped += 1;
            continue;
        };
        if hits < min_hits {
            continue;
        }
        let Some((key, at)) = place(rva, static_base) else {
            skipped += 1;
            continue;
        };
        let mut item = json!({"size": size, "hits": hits});
        item[key] = at;
        items.push(item);
        if items.len() >= maximum {
            break;
        }
    }
    let color = args.get("color").and_then(Value::as_str).unwrap_or("0xC8F0C8");
    if !(color.len() == 8 && color.starts_with("0x") && color[2..].bytes().all(|b| b.is_ascii_hexdigit())) {
        bail!("color must be 0xRRGGBB");
    }
    let mut extra = Map::new();
    extra.insert("clear".into(), json!(flag(args, "clear")));
    extra.insert("color".into(), json!(color));
    extra.insert("comment".into(), json!(flag(args, "comment")));
    let count = items.len();
    Ok(Prepared { operation: "apply_coverage", batches: chunk(items, COVERAGE_BATCH, "blocks", &extra), items: count, skipped,
        format: "ps4wb-coverage-v1".into(), module_sha256: module_hash(document) })
}

fn symbol_item(rva: u64, name: Option<String>, note: Option<String>, only_if_unnamed: bool, static_base: Option<u64>) -> Option<Value> {
    if name.is_none() && note.is_none() {
        return None;
    }
    let (key, at) = place(rva, static_base)?;
    let mut item = json!({});
    item[key] = at;
    if let Some(name) = name {
        item["name"] = json!(name);
    }
    if let Some(note) = note {
        item["comment"] = json!(note);
    }
    if only_if_unnamed {
        item["only_if_unnamed"] = json!(true);
    }
    Some(item)
}

fn symbol_batches(items: Vec<Value>, skipped: usize, args: &Map<String, Value>, format: &str, document: &Value) -> Prepared {
    let count = items.len();
    let mut extra = Map::new();
    extra.insert("overwrite".into(), json!(flag(args, "overwrite")));
    Prepared { operation: "apply_symbols", batches: chunk(items, SYMBOL_BATCH, "symbols", &extra), items: count, skipped,
        format: format.into(), module_sha256: module_hash(document) }
}

fn classes(document: &Value, args: &Map<String, Value>, static_base: Option<u64>) -> Result<Prepared> {
    require_format(document, "ps4wb-classes-v1")?;
    let entries = document.get("classes").and_then(Value::as_array).context("classes array required")?;
    let overwrite = flag(args, "overwrite");
    let maximum = limit(args, 50_000);
    let mut items = Vec::new();
    let mut skipped = 0;
    let mut placed = HashSet::new();
    for class in entries {
        let Some(name) = class.get("name").and_then(Value::as_str).and_then(symbol_name) else {
            skipped += 1;
            continue;
        };
        let bases: Vec<&str> = class.get("bases").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).take(16).collect();
        let heading = if bases.is_empty() { format!("class {name}") } else { format!("class {name} : {}", bases.join(", ")) };
        for (key, prefix) in [("vtable", "vtable_for_"), ("typeinfo", "typeinfo_for_")] {
            if let Some(rva) = class.get(key).and_then(rva_of)
                && placed.insert(rva)
                && let Some(item) = symbol_item(rva, symbol_name(&format!("{prefix}{name}")), Some(format!("{key}: {heading}")), !overwrite, static_base)
            {
                items.push(item);
            }
        }
        for slot in class.get("virtuals").and_then(Value::as_array).into_iter().flatten() {
            let (Some(index), Some(target)) = (slot.get("index").and_then(Value::as_u64), slot.get("target").and_then(rva_of)) else {
                skipped += 1;
                continue;
            };
            if target == 0 || !placed.insert(target) {
                continue;
            }
            if let Some(item) = symbol_item(target, symbol_name(&format!("{name}::vf{index}")), None, true, static_base) {
                items.push(item);
            }
        }
        if items.len() >= maximum {
            items.truncate(maximum);
            break;
        }
    }
    Ok(symbol_batches(items, skipped, args, "ps4wb-classes-v1", document))
}

fn symbols(document: &Value, args: &Map<String, Value>, static_base: Option<u64>) -> Result<Prepared> {
    let maximum = limit(args, 50_000);
    let mut items = Vec::new();
    let mut skipped = 0;
    let format = document.get("format").and_then(Value::as_str).unwrap_or("rva-map").to_owned();
    let list = ["symbols", "annotations", "ported", "labels"]
        .iter()
        .find_map(|key| document.get(*key).and_then(Value::as_array));
    if let Some(list) = list {
        for entry in list {
            let rva = ["rva", "new_rva", "target_rva"].iter().find_map(|k| entry.get(*k).and_then(rva_of));
            let name = ["name", "label", "new_name"].iter().find_map(|k| entry.get(*k).and_then(Value::as_str)).and_then(symbol_name);
            let note = comment(entry.get("comment"));
            match rva.and_then(|rva| symbol_item(rva, name, note, false, static_base)) {
                Some(item) => items.push(item),
                None => skipped += 1,
            }
            if items.len() >= maximum {
                break;
            }
        }
    } else if let Some(map) = document.as_object().filter(|m| !m.contains_key("format")) {
        for (key, value) in map {
            let rva = parse_address(key).ok();
            let name = value.as_str().and_then(symbol_name);
            match rva.and_then(|rva| symbol_item(rva, name, None, false, static_base)) {
                Some(item) => items.push(item),
                None => skipped += 1,
            }
            if items.len() >= maximum {
                break;
            }
        }
    } else {
        bail!("Expected a {{rva: name}} map or an object with a symbols/annotations/ported/labels array");
    }
    Ok(symbol_batches(items, skipped, args, &format, document))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap()
    }

    #[test]
    fn prototypes_build_and_reject_injection() {
        let doc = json!({"format": "ps4wb-prototypes-v1", "prototypes": [
            {"name": "sceKernelUsleep", "nid": "1jfXLRVzisc", "library": "libkernel", "return": "int",
             "params": [{"name": "usec", "type": "unsigned int"}], "source": "orbis"},
            {"name": "sceKernelGetpid", "declaration": "int sceKernelGetpid(void);"},
            {"name": "evil", "declaration": "int evil(void); system(\"x\")"},
            {"name": "bad name", "declaration": "int x(void)"},
            {"name": "sceKernelUsleep", "declaration": "int sceKernelUsleep(int)"}]});
        let prepared = prepare("analysis_apply_prototypes", &doc, &Map::new(), None).unwrap();
        assert_eq!(prepared.items, 2);
        assert_eq!(prepared.skipped, 2);
        let batch = &prepared.batches[0];
        assert_eq!(batch["prototypes"][0]["declaration"], "int sceKernelUsleep(unsigned int usec)");
        assert_eq!(batch["prototypes"][0]["nid"], "1jfXLRVzisc");
        assert_eq!(batch["prototypes"][1]["declaration"], "int sceKernelGetpid(void)");
        assert_eq!(batch["overwrite"], false);
        let filtered = prepare("analysis_apply_prototypes", &doc, &args(json!({"filter": "getpid"})), None).unwrap();
        assert_eq!(filtered.items, 1);
        assert!(prepare("analysis_apply_prototypes", &json!({"format": "other"}), &Map::new(), None).is_err());
    }

    #[test]
    fn coverage_rebases_filters_and_batches() {
        let blocks: Vec<Value> = (0..2500).map(|i| json!({"rva": format!("{:#x}", 0x1000 + i * 16), "size": 16, "hits": i % 3})).collect();
        let doc = json!({"format": "ps4wb-coverage-v1", "module": "eboot.bin", "module_sha256": "A".repeat(64),
            "image_base": "0x400000", "blocks": blocks});
        let relative = prepare("analysis_apply_coverage", &doc, &Map::new(), None).unwrap();
        assert_eq!(relative.items, 1666);
        assert_eq!(relative.batches[0]["blocks"][0], json!({"rva": "0x1010", "size": 16, "hits": 1}));
        assert_eq!(relative.module_sha256.as_deref(), Some("a".repeat(64).as_str()));
        let absolute = prepare("analysis_apply_coverage", &doc,
            &args(json!({"min_hits": 2, "clear": true, "color": "0x00FF00"})), Some(0x10_0000)).unwrap();
        assert_eq!(absolute.items, 833);
        assert_eq!(absolute.batches.len(), 1);
        assert_eq!(absolute.batches[0]["blocks"][0]["address"], "0x101020");
        assert_eq!(absolute.batches[0]["clear"], true);
        assert!(prepare("analysis_apply_coverage", &doc, &args(json!({"color": "red"})), None).is_err());
        let overflow = json!({"format": "ps4wb-coverage-v1", "blocks": [{"rva": "0xffffffffffffffff", "size": 4}]});
        assert_eq!(prepare("analysis_apply_coverage", &overflow, &Map::new(), Some(1)).unwrap().skipped, 1);
    }

    #[test]
    fn struct_validation_drops_overlaps() {
        let doc = json!({"format": "ps4wb-struct-v1", "name": "Player", "size": 16, "fields": [
            {"offset": 8, "size": 4, "name": "health", "type": "float", "evidence": "write at 0x401234"},
            {"offset": 0, "size": 8, "name": "vtable", "type": "void *"},
            {"offset": 10, "size": 4, "name": "overlap", "type": "int"},
            {"offset": 14, "size": 4, "name": "past_end", "type": "int"},
            {"offset": 12, "size": 4, "name": "ammo", "type": "int; drop"}],
            "c_declaration": "struct Player { void *vtable; float health; int ammo; };"});
        let prepared = prepare("analysis_apply_struct", &doc, &Map::new(), None).unwrap();
        let fields = prepared.batches[0]["struct"]["fields"].as_array().unwrap();
        let names: Vec<&str> = fields.iter().map(|f| f["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["vtable", "health", "ammo"]);
        assert!(fields[2].get("type").is_none());
        assert_eq!(fields[1]["comment"], "write at 0x401234");
        assert_eq!(prepared.skipped, 2);
        assert!(prepare("analysis_apply_struct", &json!({"format": "ps4wb-struct-v1", "name": "1bad", "size": 4, "fields": []}), &Map::new(), None).is_err());
        assert!(prepare("analysis_apply_struct", &json!({"format": "ps4wb-struct-v1", "name": "S", "size": 4, "fields": [],
            "c_declaration": "#include <x>"}), &Map::new(), None).is_err());
    }

    #[test]
    fn classes_lower_to_symbols_and_symbols_accept_maps() {
        let doc = json!({"format": "ps4wb-classes-v1", "image_base": "0x0", "classes": [
            {"name": "game::Player", "mangled": "N4game6PlayerE", "typeinfo": "0x5000", "vtable": "0x6000", "bases": ["game::Actor"],
             "virtuals": [{"index": 0, "target": "0x1100"}, {"index": 1, "target": "0x1200"}]},
            {"name": "game::Actor", "vtable": "0x6100", "virtuals": [{"index": 0, "target": "0x1100"}]}]});
        let prepared = prepare("analysis_apply_classes", &doc, &Map::new(), Some(0x400000)).unwrap();
        assert_eq!(prepared.operation, "apply_symbols");
        let items = prepared.batches[0]["symbols"].as_array().unwrap();
        assert_eq!(items.len(), 5);
        assert_eq!(items[0], json!({"address": "0x406000", "name": "vtable_for_game::Player",
            "comment": "vtable: class game::Player : game::Actor", "only_if_unnamed": true}));
        assert_eq!(items[2]["name"], "game::Player::vf0");
        assert_eq!(items[2]["only_if_unnamed"], true);

        let map = json!({"0x1000": "player_tick", "4096x": "bad", "0x2000": "has space"});
        let prepared = prepare("analysis_apply_symbols", &map, &args(json!({"overwrite": true})), None).unwrap();
        assert_eq!(prepared.items, 2);
        assert_eq!(prepared.skipped, 1);
        assert_eq!(prepared.batches[0]["symbols"][1], json!({"rva": "0x2000", "name": "has_space"}));
        assert_eq!(prepared.batches[0]["overwrite"], true);
        let ported = json!({"format": "ps4wb-annotations-v1", "annotations": [{"new_rva": "0x10", "name": "a", "comment": "moved"}]});
        let prepared = prepare("analysis_apply_symbols", &ported, &Map::new(), Some(0x100)).unwrap();
        assert_eq!(prepared.batches[0]["symbols"][0], json!({"address": "0x110", "name": "a", "comment": "moved"}));
        assert!(prepare("analysis_apply_symbols", &json!({"format": "x"}), &Map::new(), None).is_err());
    }
}
