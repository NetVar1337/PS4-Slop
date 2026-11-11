//! MCP dispatch for access finding, struct inference, crash triage, pointer scanning and host breakpoint scripts.
use crate::{
    Result,
    debugger::access::{AccessRequest, CrashRequest, ScriptRequest},
    hostscript, pointerscan, structinfer,
    tools::{ToolRegistry, address, number, string},
};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::time::Duration;

/// Returns `None` when `name` is not a tool owned by this area.
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    Some(match name {
        "debug_find_accesses" | "debug_crash_triage" | "debug_run_script" => control(registry, name, args),
        "struct_infer" => struct_infer(registry, args),
        "memory_pointer_scan" => pointer_scan(registry, args),
        "memory_pointer_rescan" => pointer_rescan(registry, args),
        _ => return None,
    })
}

fn seconds(args: &Value, default: u64) -> Duration {
    Duration::from_secs(args["timeout_seconds"].as_u64().unwrap_or(default).clamp(1, 300))
}

/// Resuming tools: audit intent, run, audit the result (same as `debug_run`).
fn control(registry: &mut ToolRegistry, name: &str, args: &Value) -> Result<Value> {
    registry
        .workbench
        .store
        .audit("debug_control_intent", json!({"method":name,"arguments":args}))?;
    let result = match name {
        "debug_find_accesses" => find_accesses(registry, args),
        "debug_crash_triage" => crash_triage(registry, args),
        _ => run_script(registry, args),
    };
    registry.workbench.audit_result("debug_control", &result)?;
    result
}

fn find_accesses(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let request = AccessRequest {
        address: address(&args["address"])?,
        length: args["length"].as_u64().unwrap_or(4),
        access: args["access"].as_str().unwrap_or("write").to_owned(),
        span: args["struct_span"].as_u64(),
        timeout: seconds(args, 30),
        max_hits: args["max_hits"].as_u64().unwrap_or(256),
        samples: args["samples_per_instruction"].as_u64().unwrap_or(4) as usize,
    };
    let workbench = &mut registry.workbench;
    let mut result = workbench.debugger.find_accesses(&request)?;
    let document = result["document"].take();
    let artifact = workbench.store.save(
        "access-log",
        &serde_json::to_vec_pretty(&document)?,
        json!({"tool":"debug_find_accesses","format":structinfer::ACCESS_FORMAT,"base":document["base"],
            "length":document["length"],"pid":document["pid"],"access":request.access}),
        "json",
    )?;
    let summary: Vec<Value> = document["accesses"]
        .as_array()
        .into_iter()
        .flatten()
        .take(32)
        .map(|access| {
            json!({"instruction":access["instruction"],"location":access["location"],"disasm":access["disasm"],
                "offset":access["offset"],"size":access["size"],"kind":access["kind"],"count":access["count"],
                "confidence":access["confidence"],"last_sample":access["samples"].as_array().and_then(|s| s.last()).map(|s| json!({"old":s["old"],"new":s["new"]}))})
        })
        .collect();
    result.as_object_mut().context("result")?.remove("document");
    result["accesses"] = json!(summary);
    result["artifact"] = artifact;
    Ok(result)
}

fn crash_triage(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let request = CrashRequest {
        wait: args["wait"].as_bool().unwrap_or(false),
        timeout: seconds(args, 30),
        thread_id: args["thread_id"].as_u64().map(|thread| thread as u32),
        max_events: args["max_events"].as_u64().unwrap_or(64) as usize,
        capture_bytes: args["capture_bytes"].as_u64().unwrap_or(256) as usize,
    };
    let workbench = &mut registry.workbench;
    let report = workbench.debugger.crash_triage(&request)?;
    if report.get("registers").is_none() {
        return Ok(report); // timeout / max_events: nothing to analyze
    }
    let artifact = workbench.store.save(
        "crash-report",
        &serde_json::to_vec_pretty(&report)?,
        json!({"tool":"debug_crash_triage","classification":report["classification"],"rip":report["rip"]}),
        "json",
    )?;
    let frames: Vec<Value> = report["stack"]["frames"].as_array().into_iter().flatten().take(12).cloned().collect();
    Ok(json!({"fault":report["fault"],"thread_id":report["thread_id"],"signal":report["signal"],"status":report["status"],
        "classification":report["classification"],"classifications":report["classifications"],
        "rip":report["rip"],"rip_location":report["rip_location"],"rip_mapping":report["rip_mapping"],
        "instruction":report["instruction"],"memory_operands":report["memory_operands"],
        "page_fault_error":report["page_fault_error"],"rsp":report["rsp"],"frames":frames,
        "skipped_stops":report["skipped_stops"],"artifact":artifact,"note":report["note"]}))
}

fn run_script(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let workbench = &mut registry.workbench;
    let mut breakpoints = Vec::new();
    for entry in args["breakpoints"].as_array().context("Missing breakpoints")? {
        let text = string(entry, "address")?;
        let resolved = match address(&entry["address"]) {
            Ok(value) => value,
            Err(_) => {
                let value = workbench.debugger.evaluate(text, None, None)?;
                address(&value["value"])?
            }
        };
        let name = entry["name"].as_str().unwrap_or(text).to_owned();
        hostscript::validate_name(&name).or_else(|_| hostscript::validate_name(&format!("{resolved:#x}")))?;
        breakpoints.push((name, resolved));
    }
    let limits = hostscript::Limits {
        max_operations: args["max_operations"].as_u64().unwrap_or(1_000_000),
        per_hit: Duration::from_millis(args["per_hit_ms"].as_u64().unwrap_or(250)),
        ..hostscript::Limits::default()
    };
    let request = ScriptRequest {
        source: string(args, "script")?.to_owned(),
        breakpoints,
        timeout: seconds(args, 30),
        max_stops: args["max_stops"].as_u64().unwrap_or(100) as usize,
        limits,
    };
    let mut result = workbench.debugger.run_script(&request)?;
    let artifact = workbench.store.save(
        "script-log",
        &serde_json::to_vec_pretty(&result)?,
        json!({"tool":"debug_run_script","stop_reason":result["stop_reason"]}),
        "json",
    )?;
    let hits = result["hits"].as_array().cloned().unwrap_or_default();
    let logs = result["logs"].as_array().cloned().unwrap_or_default();
    result["hits"] = json!(hits.iter().rev().take(16).rev().collect::<Vec<_>>());
    result["logs"] = json!(logs.iter().rev().take(64).rev().collect::<Vec<_>>());
    result["truncated"] = json!(hits.len() > 16 || logs.len() > 64);
    result["artifact"] = artifact;
    Ok(result)
}

fn parse_number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| address(value).ok())
}

/// Maps from either `process_maps` objects or compact `[start, end, prot, name]` arrays.
fn parse_maps(value: &Value) -> Vec<structinfer::MapEntry> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            if let Some(array) = entry.as_array() {
                Some((
                    parse_number(array.first()?)?,
                    parse_number(array.get(1)?)?,
                    array.get(2)?.as_u64()?,
                    array.get(3).and_then(Value::as_str).unwrap_or("").to_owned(),
                ))
            } else {
                Some((
                    parse_number(&entry["start"])?,
                    parse_number(&entry["end"])?,
                    entry["protection"].as_u64()?,
                    entry["name"].as_str().unwrap_or("").to_owned(),
                ))
            }
        })
        .collect()
}

fn struct_infer(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let workbench = &mut registry.workbench;
    let limit = workbench.profile.limit("transfer_bytes");
    let mut evidence = structinfer::Evidence::default();
    let mut sources = Vec::new();
    for path in args["access_artifacts"].as_array().context("Missing access_artifacts")? {
        let path = path.as_str().context("artifact path must be a string")?;
        let log: Value = serde_json::from_slice(&workbench.read_artifact(path, limit)?)
            .with_context(|| format!("{path} is not JSON"))?;
        ensure!(log["format"] == structinfer::ACCESS_FORMAT, "{path} is not a {} artifact", structinfer::ACCESS_FORMAT);
        evidence.maps.extend(parse_maps(&log["maps"]));
        sources.push(json!({"artifact":path,"kind":"access_log","base":log["base"]}));
        evidence.access_logs.push(log);
    }
    let base = match args["address"].is_string() {
        true => address(&args["address"])?,
        false => evidence
            .access_logs
            .first()
            .and_then(|log| parse_number(&log["base"]))
            .context("No object base: pass address")?,
    };
    // Re-express every log relative to `base`.
    for log in &mut evidence.access_logs {
        let log_base = parse_number(&log["base"]).unwrap_or(base);
        let delta = log_base as i64 - base as i64;
        if delta != 0 {
            for access in log["accesses"].as_array_mut().into_iter().flatten() {
                if let Some(offset) = access["offset"].as_i64() {
                    access["offset"] = json!(offset + delta);
                }
            }
        }
    }
    let size = args["size"].as_u64();
    let image_length = size
        .or_else(|| evidence.access_logs.iter().filter_map(|log| parse_number(&log["length"])).max())
        .unwrap_or(0x100)
        .min(workbench.profile.limit("memory_bytes") as u64) as usize;
    let mut warnings = Vec::new();
    for path in args["snapshot_artifacts"].as_array().into_iter().flatten() {
        let path = path.as_str().context("artifact path must be a string")?;
        let bytes = workbench.read_artifact(path, limit)?;
        let sidecar: Value = workbench
            .read_artifact(&format!("{path}.json"), 1 << 20)
            .ok()
            .and_then(|content| serde_json::from_slice(&content).ok())
            .unwrap_or(Value::Null);
        evidence.maps.extend(parse_maps(&sidecar["metadata"]["maps"]));
        let start = parse_number(&sidecar["metadata"]["address"]).unwrap_or(base);
        match base.checked_sub(start).map(|offset| offset as usize).filter(|offset| *offset < bytes.len()) {
            Some(offset) => {
                evidence.images.push(bytes[offset..].iter().copied().take(image_length.max(1)).collect());
                sources.push(json!({"artifact":path,"kind":"snapshot","offset_in_snapshot":offset}));
            }
            None => warnings.push(format!("{path}: snapshot at {start:#x} does not cover base {base:#x}")),
        }
    }
    if let Some(pid) = args["pid"].as_u64() {
        let pid = pid as u32;
        if evidence.maps.is_empty() {
            evidence.maps.extend(parse_maps(&workbench.debugger.maps(pid)?));
        }
        match workbench.debugger.read_memory(pid, base, image_length.max(8), false) {
            Ok(bytes) => {
                sources.push(json!({"kind":"live","pid":pid,"address":format!("{base:#x}"),"length":bytes.len()}));
                evidence.images.push(bytes);
            }
            Err(error) => warnings.push(format!("live read failed: {error:#}")),
        }
    }
    let name = args["name"].as_str().unwrap_or("InferredStruct");
    let mut document = structinfer::infer(name, size, &evidence)?;
    document["base"] = json!(format!("{base:#x}"));
    document["sources"] = json!(sources);
    let artifact = workbench.store.save(
        "struct",
        &serde_json::to_vec_pretty(&document)?,
        json!({"tool":"struct_infer","format":structinfer::FORMAT,"name":name,"base":document["base"]}),
        "json",
    )?;
    document["artifact"] = artifact;
    document["warnings"] = json!(warnings);
    Ok(document)
}

fn pointer_scan(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let workbench = &mut registry.workbench;
    let pid = number(args, "pid")? as u32;
    let target = address(&args["target_address"])?;
    let options = pointerscan::ScanOptions {
        max_depth: args["max_depth"].as_u64().unwrap_or(4) as usize,
        max_offset: args["max_offset"].as_u64().unwrap_or(0x1000),
        max_results: args["max_results"].as_u64().unwrap_or(1000) as usize,
    };
    let budget = args["budget_bytes"]
        .as_u64()
        .map_or_else(|| workbench.profile.limit("transfer_bytes"), |value| value as usize);
    let (snapshot, stats) = workbench
        .debugger
        .pointer_snapshot(pid, budget, args["include_heap"].as_bool().unwrap_or(true))?;
    let outcome = pointerscan::scan(&snapshot, target, options);
    let modules: Vec<Value> = snapshot
        .modules
        .iter()
        .map(|module| json!({"name":module.name,"base":format!("{:#x}",module.base),"end":format!("{:#x}",module.end)}))
        .collect();
    let document = json!({"format":pointerscan::FORMAT,"pid":pid,"target":format!("{target:#x}"),
        "max_depth":options.max_depth,"max_offset":options.max_offset,"modules":modules,
        "paths":outcome.paths.iter().map(pointerscan::PointerPath::to_json).collect::<Vec<_>>(),
        "truncated":outcome.truncated,"index_entries":outcome.index_entries,"nodes_explored":outcome.nodes_explored,
        "snapshot":stats});
    let artifact = workbench.store.save(
        "pointer-paths",
        &serde_json::to_vec_pretty(&document)?,
        json!({"tool":"memory_pointer_scan","format":pointerscan::FORMAT,"target":document["target"],"count":outcome.paths.len()}),
        "json",
    )?;
    Ok(json!({"target":document["target"],"count":outcome.paths.len(),"truncated":outcome.truncated,
        "paths":outcome.paths.iter().take(32).map(pointerscan::PointerPath::text).collect::<Vec<_>>(),
        "index_entries":outcome.index_entries,"nodes_explored":outcome.nodes_explored,"snapshot":stats,
        "artifact":artifact,
        "note":"Static roots are locations inside named module images; validate with memory_pointer_rescan after a restart"}))
}

fn pointer_rescan(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let workbench = &mut registry.workbench;
    let path = string(args, "artifact")?;
    let pid = number(args, "pid")? as u32;
    let previous: Value = serde_json::from_slice(&workbench.read_artifact(path, workbench.profile.limit("transfer_bytes"))?)?;
    ensure!(previous["format"] == pointerscan::FORMAT, "{path} is not a {} artifact", pointerscan::FORMAT);
    let target = match args["target_address"].is_string() {
        true => address(&args["target_address"])?,
        false => address(&previous["target"])?,
    };
    let paths = previous["paths"]
        .as_array()
        .context("Artifact has no paths")?
        .iter()
        .take(pointerscan::MAX_RESULTS)
        .map(pointerscan::PointerPath::from_json)
        .collect::<Result<Vec<_>>>()?;
    let budget = args["budget_bytes"]
        .as_u64()
        .map_or_else(|| workbench.profile.limit("transfer_bytes"), |value| value as usize);
    let (resolved, stats) = workbench.debugger.pointer_resolve(pid, &paths, budget)?;
    let mut kept = Vec::new();
    let (mut moved, mut unresolved) = (0usize, 0usize);
    let mut rejected_sample = Vec::new();
    for (path, value) in paths.iter().zip(&resolved) {
        match value {
            Some(value) if *value == target => kept.push(path.clone()),
            Some(value) => {
                moved += 1;
                if rejected_sample.len() < 16 {
                    rejected_sample.push(json!({"path":path.text(),"resolves_to":format!("{value:#x}")}));
                }
            }
            None => unresolved += 1,
        }
    }
    let document = json!({"format":pointerscan::FORMAT,"pid":pid,"target":format!("{target:#x}"),
        "max_depth":previous["max_depth"],"max_offset":previous["max_offset"],"modules":stats["modules"],
        "paths":kept.iter().map(pointerscan::PointerPath::to_json).collect::<Vec<_>>(),
        "rescanned_from":path,"rescan":stats});
    let artifact = workbench.store.save(
        "pointer-paths",
        &serde_json::to_vec_pretty(&document)?,
        json!({"tool":"memory_pointer_rescan","format":pointerscan::FORMAT,"target":document["target"],"count":kept.len(),"previous":path}),
        "json",
    )?;
    Ok(json!({"target":format!("{target:#x}"),"checked":paths.len(),"kept":kept.len(),"wrong_target":moved,
        "unresolved":unresolved,"paths":kept.iter().take(32).map(pointerscan::PointerPath::text).collect::<Vec<_>>(),
        "rejected_sample":rejected_sample,"read_stats":stats,"artifact":artifact}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Profile, workbench::Workbench};

    #[test]
    fn catalog_entries_validate_and_offline_struct_infer_dispatches() {
        let directory = tempfile::tempdir().unwrap();
        let mut data: Value = serde_json::from_str(include_str!("../tests/fixtures/profile.json")).unwrap();
        data["artifact_directory"] = json!("artifacts");
        data["qualification_file"] = json!("qualification.json");
        let profile_path = directory.path().join("profile.json");
        std::fs::write(&profile_path, data.to_string()).unwrap();
        let profile = Profile::load(&profile_path).unwrap();
        let mut registry = ToolRegistry::new(Workbench::new(profile).unwrap()).unwrap();
        let names: Vec<String> = registry.available().iter().map(|tool| tool["name"].as_str().unwrap().to_owned()).collect();
        for offline in ["struct_infer", "memory_pointer_scan", "memory_pointer_rescan"] {
            assert!(names.contains(&offline.to_owned()), "{offline}");
        }
        assert!(!names.contains(&"debug_find_accesses".to_owned()), "control tool hidden without permission");
        let log = json!({"format":structinfer::ACCESS_FORMAT,"base":"0x1000","length":16,"accesses":[
            {"instruction":"0x400000","location":"eboot.bin+0x0","disasm":"movss dword ptr [rbx+0x4], xmm0","address":"0x1004",
             "offset":4,"size":4,"kind":"write","count":3,"samples":[]}]});
        let saved = registry
            .workbench
            .store
            .save("access-log", log.to_string().as_bytes(), json!({}), "json")
            .unwrap();
        let result = registry
            .call("struct_infer", json!({"access_artifacts":[saved["path"]],"name":"Thing","size":16}))
            .unwrap();
        assert_eq!(result["format"], structinfer::FORMAT);
        assert_eq!(result["fields"][0]["type"], "float");
        assert!(result["c_declaration"].as_str().unwrap().contains("float field_0x4;"));
        assert!(registry.call("struct_infer", json!({"access_artifacts":[], "bogus":1})).is_err());
    }
}
