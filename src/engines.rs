//! Engine and runtime metadata recovery: Unity IL2CPP, Unreal names/objects, Itanium C++ RTTI/vtables, YARA-subset and crypto-constant scanning.
//!
//! All tools here are read-only. Byte access goes through
//! [`crate::bytesource::Source`] (offline artifacts or bounded live reads).
use crate::{Result, tools::ToolRegistry, workbench::Workbench};
use anyhow::{Context, ensure};
use serde_json::{Value, json};

/// Returns `None` when `name` is not a tool owned by this area.
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    let workbench = &mut registry.workbench;
    Some(match name {
        "il2cpp_dump" => crate::il2cpp::run(workbench, args),
        "unreal_dump" => crate::unreal::run(workbench, args),
        "rtti_recover" => crate::rtti::run(workbench, args),
        "yara_scan" => crate::yara::run(workbench, args),
        "crypto_scan" => crate::cryptoscan::run(workbench, args),
        "source_dump" => crate::source_engine::run(workbench, args),
        "engine_sdk_export" => engine_sdk_export(workbench, args),
        _ => return None,
    })
}

/// Save `value` as a pretty JSON artifact; returns the provenance record.
pub fn save_json(workbench: &Workbench, kind: &str, value: &Value, metadata: Value) -> Result<Value> {
    workbench.store.save(kind, &serde_json::to_vec_pretty(value)?, metadata, "json")
}

/// Save text as an artifact; returns the provenance record.
pub fn save_text(workbench: &Workbench, kind: &str, text: &str, extension: &str, metadata: Value) -> Result<Value> {
    workbench.store.save(kind, text.as_bytes(), metadata, extension)
}

/// Compact artifact reference for tool results.
pub fn artifact_ref(saved: &Value) -> Value {
    json!({"path": saved["path"], "sha256": saved["sha256"]})
}

/// Sanitize a dump name into a C++ identifier.
fn sdk_ident(text: &str) -> String { crate::sdkgen::safe_ident(text) }
fn unique_ident(text: &str, used: &mut std::collections::BTreeSet<String>) -> String {
    let base = sdk_ident(text);
    let mut name = base.clone(); let mut suffix = 2;
    while !used.insert(name.clone()) { name = format!("{base}_{suffix}"); suffix += 1; }
    name
}

fn unreal_sdk(workbench: &Workbench, path: &str, ns: &str, max_objects: u64) -> Result<Value> {
    let doc: Value = serde_json::from_slice(&workbench.read_artifact(path, 16 * 1024 * 1024)?)?;
    ensure!(doc["format"] == "ps4wb-unreal-v1", "unreal must be a ps4wb-unreal-v1 artifact");
    let base = crate::tools::address(&doc["image_base"])?;
    let gobjects = &doc["gobjects"];
    let gnames = &doc["gnames"];
    let rva = |value: &Value| -> Result<u64> {
        crate::tools::address(value)?.checked_sub(base).context("Engine global below image base")
    };
    let root = rva(&gobjects["address"])?;
    let objobjects = doc["offsets"]["objobjects"].as_u64().context("Missing offsets.objobjects")?;
    let slot = root.checked_add(objobjects).context("Object array RVA overflow")?;
    let layout = gobjects["layout"].as_str().context("Missing object array layout")?;
    ensure!(["FChunkedFixedUObjectArray", "FFixedUObjectArray"].contains(&layout), "Unsupported object array layout");
    let chunked = layout == "FChunkedFixedUObjectArray";
    let names_kind = gnames["kind"].as_str().context("Missing names kind")?;
    let names = rva(&gnames["address"])?;
    let (kind, indirect, string_offset) = match names_kind {
        "FNamePool" => ("Pool", false, 0),
        "TNameEntryArray" => ("Array", gnames["array"] != gnames["address"], gnames["name_string_offset"].as_u64().context("Missing name_string_offset")?),
        _ => anyhow::bail!("Unsupported names layout"),
    };
    let item_size = doc["offsets"]["item_size"].as_u64().context("Missing item_size")?;
    ensure!((8..=256).contains(&item_size), "Invalid item size");
    let object_name = doc["offsets"]["object_name"].as_u64().context("Missing object_name")?;
    let max_names = if names_kind == "FNamePool" { 1u64 << 29 } else { gnames["num_elements"].as_u64().context("Missing name count")? };
    let mut header = format!(
        "// Generated from {path}; layout {layout}, names {names_kind}.\n#pragma once\n#include <internals/ue4.hpp>\nnamespace {ns} {{\ninline constexpr ue4::Offsets make_ue4_offsets() {{\n    ue4::Offsets o;\n    o.gobjects = {root:#x};\n    o.objects_pointer = {slot:#x};\n    o.num_elements = {num:#x};\n    o.max_elements = {max:#x};\n    o.object_stride = {item_size};\n    o.object_name_index = {object_name:#x};\n    o.gnames = {names:#x};\n    o.blocks_pointer = 0; // GNames address is the inline Blocks array\n    o.names_kind = ue4::NamesKind::{kind};\n    o.name_array_indirect = {indirect};\n    o.name_entry_string = {string_offset};\n    o.max_objects = {max_objects};\n    o.max_names = {max_names};\n    o.chunked = {chunked};\n    return o;\n}}\ninline constexpr ue4::Offsets kUe4Offsets = make_ue4_offsets();\n}}\n",
        num = slot + if chunked { 0x14 } else { 0xc },
        max = slot + if chunked { 0x10 } else { 0x8 },
    );
    let (types, notes) = crate::sdkgen::unreal(&doc, ns)?;
    header.push_str(&types);
    let saved = save_text(workbench, "engine-sdk", &header, "hpp", json!({"tool": "engine_sdk_export", "source": path, "kind": "unreal", "source_sha256": crate::config::sha256_hex(&workbench.read_artifact(path, 16 << 20)?)}))?;
    Ok(json!({"kind":"unreal", "artifact": artifact_ref(&saved), "gobjects_rva":format!("{root:#x}"), "gnames_rva":format!("{names:#x}"), "chunked":chunked, "item_size":item_size, "object_name_index":object_name, "notes":notes}))
}

fn source_sdk(workbench: &Workbench, path: &str, ns: &str) -> Result<Value> {
    let doc: Value = serde_json::from_slice(&workbench.read_artifact(path, 32 * 1024 * 1024)?)?;
    ensure!(doc["format"] == crate::source_engine::FORMAT, "source must be a {} artifact", crate::source_engine::FORMAT);
    let mut out = String::from("// Generated by engine_sdk_export from source_dump evidence; do not edit by hand.\n#pragma once\n#include <cstddef>\n\n");
    out.push_str(&format!("namespace {ns} {{\n\n"));
    let mut tables = 0usize;
    let mut props_total = 0usize;
    let mut classes = std::collections::BTreeSet::new();
    for table in doc["recv_tables"].as_array().into_iter().flatten() {
        let class = unique_ident(table["name"].as_str().unwrap_or("recv_table").trim_start_matches("DT_"), &mut classes);
        out.push_str(&format!("namespace {class} {{\n"));
        let mut fields = std::collections::BTreeSet::new();
        for prop in table["props"].as_array().into_iter().flatten() {
            let name = unique_ident(prop["name"].as_str().unwrap_or("prop"), &mut fields);
            let Ok(offset) = crate::tools::address(&prop["offset"]) else { continue };
            let kind = prop["type"].as_str().unwrap_or("?").replace(['\r','\n','\\'], " ");
            out.push_str(&format!("inline constexpr std::ptrdiff_t {name} = {offset:#x}; // {kind}\n"));
            props_total += 1;
        }
        out.push_str("} // namespace\n\n");
        tables += 1;
    }
    let mut maps = 0usize;
    for map in doc["datamaps"].as_array().into_iter().flatten() {
        let class = unique_ident(&format!("{}_datamap",map["class"].as_str().unwrap_or("datamap")), &mut classes);
        out.push_str(&format!("namespace {class} {{\n"));
        let mut fields = std::collections::BTreeSet::new();
        for field in map["fields"].as_array().into_iter().flatten() {
            let name = unique_ident(field["name"].as_str().unwrap_or("field"), &mut fields);
            let Ok(offset) = crate::tools::address(&field["offset"]) else { continue };
            let kind = field["type"].as_str().unwrap_or("?").replace(['\r','\n','\\'], " ");
            out.push_str(&format!("inline constexpr std::ptrdiff_t {name} = {offset:#x}; // {kind}\n"));
            props_total += 1;
        }
        out.push_str("} // namespace\n\n");
        maps += 1;
    }
    out.push_str(&format!("}} // namespace {ns}\n"));
    let (types, notes) = crate::sdkgen::source(&doc, ns)?;
    out.push_str(&types);
    let saved = save_text(workbench, "engine-sdk", &out, "hpp", json!({"tool": "engine_sdk_export", "source": path, "kind": "source"}))?;
    Ok(json!({"kind": "source", "artifact": artifact_ref(&saved), "recv_tables": tables, "datamaps": maps, "props": props_total, "notes": notes}))
}

/// Export engine-specific SDK headers from engine dump artifacts:
/// `unreal` (ps4wb-unreal-v1) -> ue4::Offsets for the payload's ue4.hpp;
/// `source` (ps4wb-source-v1) -> per-class netvar/datamap offset constants.
pub fn engine_sdk_export(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    let ns = sdk_ident(args["namespace"].as_str().unwrap_or("game"));
    let max_objects = args["max_objects"].as_u64().unwrap_or(65536).clamp(1, 1 << 20);
    let mut result = match (args["unreal"].as_str(), args["source"].as_str()) {
        (Some(path), None) => unreal_sdk(workbench, path, &ns, max_objects),
        (None, Some(path)) => source_sdk(workbench, path, &ns),
        _ => anyhow::bail!("Supply exactly one of unreal or source dump artifacts"),
    }?;
    if let Some(sha) = args["module_sha256"].as_str() {
        crate::config::require_hash(sha, "module_sha256")?;
        let project = crate::project::require_active(&workbench.store)?;
        let records = crate::project::load_records(&workbench.store, &project)?;
        ensure!(records.iter().any(|r| r["type"] == "module" && r["sha256"] == sha), "Record this module build before binding an SDK");
        let path = result["artifact"]["path"].as_str().context("Missing generated SDK")?;
        let bytes = workbench.read_artifact(path, 16 << 20)?;
        let saved = workbench.store.save("engine-sdk", &bytes, json!({"tool":"engine_sdk_export","module_sha256":sha,"source":args["unreal"].as_str().or_else(||args["source"].as_str()),"source_header":path,"namespace":ns}), "hpp")?;
        result["artifact"] = artifact_ref(&saved);
        result["module_sha256"] = json!(sha);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debugger::fake;

    #[test]
    fn live_yara_and_crypto_scans_report_module_offsets() {
        let base = 0x40_0000u64;
        let mut image = vec![0x90u8; 0x3000];
        image[0x1234..0x123a].copy_from_slice(b"SECRET");
        image[0x2000..0x2100].copy_from_slice(&crate::cryptoscan::aes_sbox());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = fake::spawn_fixture(listener, fake::Fixture { pid: 93, base, image, ..Default::default() });
        let directory = tempfile::tempdir().unwrap();
        let profile = fake::qualified_profile(directory.path(), fake.port);
        let mut registry = ToolRegistry::new(Workbench::new(profile).unwrap()).unwrap();
        assert!(dispatch(&mut registry, "not_an_engine_tool", &json!({})).is_none());

        let rules = "rule secret { strings: $s = \"secret\" nocase condition: $s and @s[1] == 0x1234 }";
        let result = registry.call("yara_scan", json!({"rules": rules, "pid": 93, "module": "fixture.elf"})).unwrap();
        let hit = &result["matched_rules"][0]["strings"][0];
        assert_eq!(hit["module"], "fixture.elf", "{result:#}");
        assert_eq!(hit["module_offset"], "0x1234");
        assert_eq!(hit["address"], format!("{:#x}", base + 0x1234));

        let ranged = registry
            .call("yara_scan", json!({"rules": rules, "pid": 93, "address": format!("{:#x}", base + 0x1000), "length": 0x1000}))
            .unwrap();
        assert!(ranged["matched_rules"].as_array().unwrap().is_empty(), "offsets are relative to the range start");

        let crypto = registry
            .call("crypto_scan", json!({"pid": 93, "module": "fixture.elf", "min_confidence": "high"}))
            .unwrap();
        let finding = &crypto["findings"][0];
        assert_eq!(finding["algorithm"], "AES", "{crypto:#}");
        assert_eq!(finding["module_offset"], "0x2000");
        assert!(registry.call("crypto_scan", json!({"pid": 93})).is_err());
        assert!(registry.call("yara_scan", json!({"rules": "rule x { condition: for }", "pid": 93, "module": "fixture.elf"})).is_err());
    }

    #[test]
    fn engine_sdk_export_generates_unreal_and_source_headers() {
        let directory = tempfile::tempdir().unwrap();
        let workbench = Workbench::new(crate::artifacts::tests::test_profile(directory.path())).unwrap();
        let unreal = json!({
            "format": "ps4wb-unreal-v1", "image_base": "0x400000",
            "gnames": {"kind": "FNamePool", "address": "0x500000", "blocks": "0x500008", "current_block": 0, "current_byte_cursor": 0},
            "gobjects": {"address": "0x600000", "objects": "0x700000", "num_elements": 5, "max_elements": 5, "layout": "FChunkedFixedUObjectArray"},
            "offsets": {"objobjects": 16, "item_size": 24, "object_name": 8},
        });
        let source = json!({
            "format": "ps4wb-source-v1",
            "recv_tables": [{"name": "DT_Player", "props": [{"name": "m_iHealth", "offset": "0x32c", "type": "int"}]}],
            "datamaps": [{"class": "CPlayer", "fields": [{"name": "m_vecOrigin", "offset": "0x1fb0", "type": "vec3"}]}],
        });
        let ua = workbench.store.save("unreal", &serde_json::to_vec(&unreal).unwrap(), json!({}), "json").unwrap();
        let sa = workbench.store.save("source-dump", &serde_json::to_vec(&source).unwrap(), json!({}), "json").unwrap();
        let mut registry = ToolRegistry::new(workbench).unwrap();

        let out = registry.call("engine_sdk_export", json!({"unreal": ua["path"], "namespace": "fortnite"})).unwrap();
        assert_eq!(out["kind"], "unreal");
        assert_eq!(out["chunked"], true);
        let hpp = String::from_utf8(registry.workbench.read_artifact(out["artifact"]["path"].as_str().unwrap(), 1 << 20).unwrap()).unwrap();
        assert!(hpp.contains("o.gobjects = 0x200000;"), "{hpp}");
        assert!(hpp.contains("o.num_elements = 0x200024;"), "{hpp}");
        assert!(hpp.contains("o.gnames = 0x100000;"), "{hpp}");
        assert!(hpp.contains("o.object_stride = 24;"), "{hpp}");
        assert!(hpp.contains("o.object_name_index = 0x8;"), "{hpp}");
        assert!(hpp.contains("o.chunked = true;"), "{hpp}");
        assert!(hpp.contains("namespace fortnite"), "{hpp}");
        assert!(hpp.contains("inline constexpr ue4::Offsets make_ue4_offsets()"), "{hpp}");
        assert!(hpp.contains("inline constexpr ue4::Offsets kUe4Offsets = make_ue4_offsets();"), "{hpp}");

        let out = registry.call("engine_sdk_export", json!({"source": sa["path"], "namespace": "apex"})).unwrap();
        assert_eq!(out["kind"], "source");
        assert_eq!(out["props"], 2);
        let hpp = String::from_utf8(registry.workbench.read_artifact(out["artifact"]["path"].as_str().unwrap(), 1 << 20).unwrap()).unwrap();
        assert!(hpp.contains("inline constexpr std::ptrdiff_t m_iHealth = 0x32c; // int"), "{hpp}");
        assert!(hpp.contains("inline constexpr std::ptrdiff_t m_vecOrigin = 0x1fb0; // vec3"), "{hpp}");
        assert!(hpp.contains("namespace Player"), "{hpp}");
        assert!(hpp.contains("namespace CPlayer_datamap"), "{hpp}");
        assert!(registry.call("engine_sdk_export", json!({"unreal": ua["path"], "source": sa["path"]})).is_err());
    }
}
