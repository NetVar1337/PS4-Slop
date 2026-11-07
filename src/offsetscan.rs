//! Live offset verification and relocation, plus dump-vs-disk integrity.
//!
//! `offset_scan` checks offsets and wildcard signatures against the running
//! target: exact fingerprints from a `ps4wb-offsets-v1` manifest, and patterns
//! at their expected RVA. A signature that no longer matches at its RVA is
//! searched through the module's executable maps: exactly one hit means the
//! offset moved (relocated), zero means missing, several means ambiguous.
//!
//! `module_integrity` diffs an in-memory ELF dump against the on-disk ELF,
//! reporting changed executable-text ranges (hooks/patches applied at runtime).

use crate::{
    Result,
    analysis,
    binimage::Image,
    debugger::Debugger,
    tools::{ToolRegistry, address, number, string},
    workbench::Workbench,
};
use anyhow::{Context, ensure};
use serde_json::{Value, json};

const OFFSETS_FORMAT: &str = "ps4wb-offsets-v1";

struct ModuleLayout {
    base: u64,
    text: Vec<(u64, u64)>,
}

fn layout(debugger: &mut Debugger, pid: u32, module: &str, image_base: Option<u64>) -> Result<ModuleLayout> {
    let maps = debugger.maps(pid)?;
    let mut base = image_base;
    let mut text = Vec::new();
    for map in maps.as_array().into_iter().flatten() {
        let name = map["name"].as_str().unwrap_or("");
        let matches = name == "executable" || name == module || name.strip_suffix(module).is_some_and(|prefix| prefix.ends_with('/'));
        if !matches {
            continue;
        }
        let protection = map["protection"].as_u64().unwrap_or(0);
        if protection & 4 == 0 || protection & 1 == 0 {
            continue;
        }
        let start = map["start"].as_u64().context("Invalid map start")?;
        let end = map["end"].as_u64().context("Invalid map end")?;
        if start < end {
            text.push((start, end));
            base = Some(base.map_or(start, |b| b.min(start)));
        }
    }
    let base = base.context("No readable executable maps for this module; supply image_base")?;
    ensure!(!text.is_empty(), "No readable executable maps for module {module}");
    text.sort_unstable();
    Ok(ModuleLayout { base, text })
}

/// Whether `pattern` matches at exactly `address` in the target.
fn matches_at(debugger: &mut Debugger, pid: u32, address: u64, pattern: &str) -> Result<bool> {
    let length = analysis::pattern_len(pattern)?;
    let bytes = debugger.read_memory(pid, address, length, false)?;
    let found = analysis::scan_pattern_at(&bytes, pattern, address, 1)?;
    let want = format!("{address:#x}");
    Ok(found["matches"].as_array().is_some_and(|items| items.iter().any(|item| item.as_str() == Some(&want))))
}

/// Search the module's text maps for `pattern`, capped at `limit` matches.
fn find_in_module(debugger: &mut Debugger, pid: u32, layout: &ModuleLayout, pattern: &str, limit: usize) -> Result<Vec<u64>> {
    let chunk = debugger.profile.limit("memory_bytes").max(0x1000) as u64;
    let mut matches = Vec::new();
    for &(start, end) in &layout.text {
        let mut position = start;
        while position < end {
            let length = ((end - position).min(chunk)) as usize;
            let found = debugger.memory_search(pid, position, length, pattern, limit)?;
            for item in found["matches"].as_array().into_iter().flatten() {
                if let Some(text) = item.as_str() {
                    matches.push(u64::from_str_radix(text.trim_start_matches("0x"), 16)?);
                }
            }
            if matches.len() >= limit {
                return Ok(matches);
            }
            position += length as u64;
        }
    }
    Ok(matches)
}

fn offset_scan(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    let pid = number(args, "pid")? as u32;
    let module = args["module"].as_str().unwrap_or("eboot.bin");
    let image_base = args["image_base"].is_string().then(|| address(&args["image_base"])).transpose()?;
    let relocate = args["relocate"].as_bool().unwrap_or(true);
    let limit = args["max_matches"].as_u64().unwrap_or(4).clamp(1, 64) as usize;
    ensure!(args["offsets"].is_string() || args["signatures"].as_array().is_some(), "Supply offsets (ps4wb-offsets-v1 artifact) and/or signatures");

    let layout = layout(&mut workbench.debugger, pid, module, image_base)?;
    let base = layout.base;
    let mut results = Vec::new();
    let mut counts = std::collections::BTreeMap::new();

    let mut record = |symbol: &str, rva: u64, status: &str, address: u64, new_rva: Option<u64>| {
        *counts.entry(status.to_owned()).or_insert(0usize) += 1;
        results.push(json!({
            "symbol": symbol, "rva": format!("{rva:#x}"), "status": status,
            "address": format!("{address:#x}"),
            "new_rva": new_rva.map(|v| format!("{v:#x}")),
        }));
    };

    // Exact fingerprints from a ps4wb-offsets-v1 manifest.
    if let Some(path) = args["offsets"].as_str() {
        let doc: Value = serde_json::from_slice(&workbench.read_artifact(path, 4 * 1024 * 1024)?)?;
        ensure!(doc["format"] == OFFSETS_FORMAT, "offsets must be a {OFFSETS_FORMAT} artifact");
        for module in doc["modules"].as_array().into_iter().flatten() {
            for offset in module["offsets"].as_array().into_iter().flatten() {
                let symbol = offset["symbol"].as_str().unwrap_or("offset").to_owned();
                let rva = address(&offset["rva"])?;
                let address = base.checked_add(rva).context("Offset address overflow")?;
                match offset["verify"]["hex"].as_str() {
                    Some(hex_text) => {
                        let expected = hex::decode(hex_text)?;
                        let actual = workbench.debugger.read_memory(pid, address, expected.len(), false);
                        match actual {
                            Ok(actual) if actual == expected => record(&symbol, rva, "verified", address, None),
                            Ok(_) => record(&symbol, rva, "mismatch", address, None),
                            Err(_) => record(&symbol, rva, "read_error", address, None),
                        }
                    }
                    None => record(&symbol, rva, "no_fingerprint", address, None),
                }
            }
        }
    }

    // Wildcard signatures at their expected RVA, with optional relocation.
    for signature in args["signatures"].as_array().into_iter().flatten() {
        let symbol = signature["symbol"].as_str().unwrap_or("signature").to_owned();
        let rva = address(&signature["rva"])?;
        let pattern = string(signature, "pattern")?;
        let address = base.checked_add(rva).context("Signature address overflow")?;
        if matches_at(&mut workbench.debugger, pid, address, pattern)? {
            record(&symbol, rva, "verified", address, None);
            continue;
        }
        if !relocate {
            record(&symbol, rva, "mismatch", address, None);
            continue;
        }
        let found = find_in_module(&mut workbench.debugger, pid, &layout, pattern, limit)?;
        match found.len() {
            0 => record(&symbol, rva, "missing", address, None),
            1 => {
                let new_address = found[0];
                let new_rva = new_address.checked_sub(base);
                record(&symbol, rva, "relocated", new_address, new_rva);
            }
            _ => record(&symbol, rva, "ambiguous", address, None),
        }
    }

    Ok(json!({
        "pid": pid, "module": module, "image_base": format!("{base:#x}"),
        "results": results, "summary": counts,
        "note": "verified = bytes match at the expected RVA; relocated = exactly one pattern match elsewhere in the module",
    }))
}

fn module_integrity(workbench: &Workbench, args: &Value) -> Result<Value> {
    let dump_path = string(args, "dump")?;
    let disk_path = string(args, "disk")?;
    let max_ranges = args["max_ranges"].as_u64().unwrap_or(64).clamp(1, 1024) as usize;
    let dump = Image::from_elf(&workbench.read_artifact(dump_path, workbench.profile.limit("transfer_bytes"))?, Some("dump".into()))
        .context("dump must be an ELF (run elf_rebuild first for raw memory dumps)")?;
    let disk = Image::from_elf(&workbench.read_artifact(disk_path, workbench.profile.limit("transfer_bytes"))?, Some("disk".into()))?;

    let mut ranges = Vec::new();
    let mut changed_bytes = 0u64;
    let mut unmapped = 0u64;
    let mut segments_compared = 0usize;
    'segments: for segment in disk.exec_segments() {
        segments_compared += 1;
        let mut position = segment.vaddr;
        let end = segment.data_end();
        while position < end {
            let length = ((end - position) as usize).min(4096);
            let expected = segment.data[(position - segment.vaddr) as usize..(position - segment.vaddr) as usize + length].to_vec();
            let actual = dump.read(position, length);
            if actual.is_none() {
                unmapped += length as u64;
                position += length as u64;
                continue;
            }
            let actual = actual.unwrap();
            let mut offset = 0usize;
            while offset < length {
                if expected[offset] != actual[offset] {
                    let start = position + offset as u64;
                    let mut size = 1usize;
                    while offset + size < length && expected[offset + size] != actual[offset + size] {
                        size += 1;
                    }
                    changed_bytes += size as u64;
                    if ranges.len() < max_ranges {
                        let preview = |bytes: &[u8], skip: usize| -> String {
                            bytes.iter().skip(skip).take(16).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
                        };
                        ranges.push(json!({
                            "rva": format!("{start:#x}"), "length": size,
                            "expected_hex": preview(&expected, offset),
                            "actual_hex": preview(actual, offset),
                        }));
                    }
                    offset += size;
                } else {
                    offset += 1;
                }
            }
            position += length as u64;
        }
        if ranges.len() >= max_ranges {
            break 'segments;
        }
    }

    Ok(json!({
        "dump": dump_path, "disk": disk_path,
        "segments_compared": segments_compared,
        "changed_bytes": changed_bytes,
        "unmapped_bytes": unmapped,
        "ranges": ranges,
        "truncated": ranges.len() >= max_ranges,
        "note": "expected = on-disk file, actual = in-memory dump; differences are runtime hooks/patches",
    }))
}

pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    Some(match name {
        "offset_scan" => offset_scan(&mut registry.workbench, args),
        "module_integrity" => module_integrity(&registry.workbench, args),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::tests::test_profile;
    use crate::binimage::testelf::Builder;
    use crate::debugger::fake;
    use crate::tools::Toolset;

    #[test]
    fn integrity_reports_changed_exec_ranges() {
        let directory = tempfile::tempdir().unwrap();
        let workbench = Workbench::new(test_profile(directory.path())).unwrap();
        let mut first = Builder::new(0);
        first.text = (0u8..64).collect();
        let mut second = Builder::new(0);
        second.text = (0u8..64).collect();
        second.text[16] = 0xcc;
        let a = workbench.store.save("elfdump", &first.build(), json!({}), "elf").unwrap();
        let b = workbench.store.save("elfdisk", &second.build(), json!({}), "elf").unwrap();
        let mut registry = ToolRegistry::new(workbench).unwrap();
        let result = registry.call("module_integrity", json!({"dump": a["path"], "disk": b["path"]})).unwrap();
        assert_eq!(result["changed_bytes"], 1);
        assert_eq!(result["ranges"][0]["length"], 1);
        assert!(result["ranges"][0]["expected_hex"].as_str().unwrap().starts_with("cc"));
        assert!(result["ranges"][0]["actual_hex"].as_str().unwrap().starts_with("10"));
        assert_eq!(result["unmapped_bytes"], 0);
    }

    #[test]
    fn offset_scan_verifies_and_relocates_signatures() {
        let mut image = vec![0x90u8; 0x100];
        // verified signature at +0x20, relocated signature at +0x80
        image[0x20..0x24].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        image[0x40..0x42].copy_from_slice(&[0xde, 0xad]); // second copy for the ambiguous case
        image[0x80..0x84].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let fixture = fake::Fixture {
            pid: 71,
            thread_id: 72,
            base: 0x40_0000,
            image,
            rip: 0x40_0000,
            ..Default::default()
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = fake::spawn_fixture(listener, fixture);
        let directory = tempfile::tempdir().unwrap();
        let profile = fake::qualified_profile(directory.path(), fake.port);
        let workbench = Workbench::new(profile).unwrap();
        let mut registry = ToolRegistry::with_toolset(workbench, Toolset::Full).unwrap();

        let result = registry.call("offset_scan", json!({
            "pid": 71, "module": "fixture.elf", "image_base": "0x400000",
            "signatures": [
                {"symbol": "present", "rva": "0x20", "pattern": "de ad be ef"},
                {"symbol": "moved", "rva": "0x50", "pattern": "11 22 33 44"},
                {"symbol": "gone", "rva": "0x60", "pattern": "aa bb cc dd"},
                {"symbol": "twice", "rva": "0x90", "pattern": "de ad"},
            ],
        })).unwrap();
        let results = result["results"].as_array().unwrap();
        assert_eq!(results[0]["status"], "verified");
        assert_eq!(results[1]["status"], "relocated");
        assert_eq!(results[1]["address"], "0x400080");
        assert_eq!(results[1]["new_rva"], "0x80");
        assert_eq!(results[2]["status"], "missing");
        assert_eq!(results[3]["status"], "ambiguous");
        assert_eq!(result["image_base"], "0x400000");
    }

    #[test]
    fn offset_scan_verifies_manifest_fingerprints() {
        let mut image = vec![0x90u8; 0x100];
        image[0x20..0x24].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let fixture = fake::Fixture {
            pid: 71, thread_id: 72, base: 0x40_0000, image, rip: 0x40_0000,
            ..Default::default()
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = fake::spawn_fixture(listener, fixture);
        let directory = tempfile::tempdir().unwrap();
        let workbench = Workbench::new(fake::qualified_profile(directory.path(), fake.port)).unwrap();
        let sha = "a".repeat(64);
        let doc = json!({"format": OFFSETS_FORMAT, "modules": [{"module": "fixture.elf", "module_sha256": sha,
            "offsets": [{"symbol": "Good", "rva": "0x20", "verify": {"offset": "0x20", "hex": "deadbeef"}},
                        {"symbol": "Bad", "rva": "0x30", "verify": {"offset": "0x30", "hex": "deadbeef"}}]}]});
        let saved = workbench.store.save("offsets", &serde_json::to_vec(&doc).unwrap(), json!({}), "json").unwrap();
        let mut registry = ToolRegistry::with_toolset(workbench, Toolset::Full).unwrap();
        let result = registry.call("offset_scan", json!({
            "pid": 71, "module": "fixture.elf", "image_base": "0x400000", "offsets": saved["path"],
        })).unwrap();
        assert_eq!(result["results"][0]["status"], "verified");
        assert_eq!(result["results"][1]["status"], "mismatch");
        assert_eq!(result["summary"]["verified"], 1);
        assert_eq!(result["summary"]["mismatch"], 1);
    }
}
