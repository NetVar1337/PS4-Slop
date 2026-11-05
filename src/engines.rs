//! Engine and runtime metadata recovery: Unity IL2CPP, Unreal names/objects, Itanium C++ RTTI/vtables, YARA-subset and crypto-constant scanning.
//!
//! All tools here are read-only. Byte access goes through
//! [`crate::bytesource::Source`] (offline artifacts or bounded live reads).
use crate::{Result, tools::ToolRegistry, workbench::Workbench};
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
}
