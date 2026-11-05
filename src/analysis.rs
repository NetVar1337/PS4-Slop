//! Local, offline analysis over contained artifacts.
//!
//! Native port of the network-free parts of `ps4_workbench/analysis.py`.
//! Debugger round-trips (process info, maps, memory reads) stay with the
//! caller; `snapshot_record` and `correlate_maps` take their results.

use anyhow::{anyhow, bail};
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
}
