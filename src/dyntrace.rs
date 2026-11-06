//! MCP dispatch for run-loop tracing tools (imports, syscalls, functions, coverage)
//! and the offline `coverage_diff`. The debugger-side engine lives in
//! `debugger::trace`; format helpers in `tracekit`.
use crate::{
    Result,
    debugger::trace::{DEFAULT_SCAN_LIMIT, MAX_INTERNAL_SLOTS, MAX_TRACE_EVENTS, MAX_TRACE_SECONDS, TraceOptions, TraceReport},
    tools::ToolRegistry,
    tracekit,
    workbench::Workbench,
};
use anyhow::{Context, bail};
use serde_json::{Value, json};
use std::time::Duration;

const PREVIEW_EVENTS: usize = 20;
const MAX_JSON_ARTIFACT: usize = 64 * 1024 * 1024;

/// Returns `None` when `name` is not a tool owned by this area.
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    match name {
        "debug_trace_imports" | "debug_trace_syscalls" | "debug_trace_function" | "debug_coverage" => {
            Some(controlled(&mut registry.workbench, name, args))
        }
        "coverage_diff" => Some(coverage_diff(&registry.workbench, args)),
        _ => None,
    }
}

/// Resuming tools: audit the intent, run, audit the result (as `tools.rs` does
/// for `debug_run` / `debug_step`).
fn controlled(workbench: &mut Workbench, name: &str, args: &Value) -> Result<Value> {
    workbench.store.audit("debug_control_intent", json!({"method": name, "arguments": args}))?;
    let result = match name {
        "debug_trace_imports" => trace_imports(workbench, args),
        "debug_trace_syscalls" => trace_syscalls(workbench, args),
        "debug_trace_function" => trace_function(workbench, args),
        _ => coverage(workbench, args),
    };
    workbench.audit_result("debug_control", &result)?;
    result
}

fn seconds(args: &Value) -> Duration {
    Duration::from_secs(args["timeout_seconds"].as_u64().unwrap_or(30).clamp(1, MAX_TRACE_SECONDS))
}

fn slots(args: &Value) -> u32 {
    args["max_breakpoints"].as_u64().unwrap_or(MAX_INTERNAL_SLOTS as u64).clamp(1, MAX_INTERNAL_SLOTS as u64) as u32
}

fn options(args: &Value, default_string_bytes: u64) -> TraceOptions {
    TraceOptions {
        timeout: seconds(args),
        max_events: args["max_events"].as_u64().unwrap_or(1000).clamp(1, MAX_TRACE_EVENTS as u64) as usize,
        max_breakpoints: slots(args),
        capture_returns: args["capture_returns"].as_bool().unwrap_or(false),
        arg_count: args["arg_count"].as_u64().unwrap_or(6).min(6) as usize,
        string_bytes: args["string_bytes"].as_u64().unwrap_or(default_string_bytes).min(256) as usize,
        thread_id: args["thread_id"].as_u64().map(|thread| thread as u32),
        backtrace_frames: args["backtrace_frames"].as_u64().unwrap_or(0).min(32) as usize,
        syscall_names: None,
    }
}

fn scan_limit(args: &Value) -> usize {
    args["scan_limit_bytes"].as_u64().map_or(DEFAULT_SCAN_LIMIT, |limit| limit as usize).clamp(4096, 256 * 1024 * 1024)
}

fn strings(args: &Value, key: &str) -> Vec<String> {
    args[key].as_array().map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_owned)).collect()).unwrap_or_default()
}

fn read_json(workbench: &Workbench, artifact: &str) -> Result<Value> {
    let raw = workbench.read_artifact(artifact, MAX_JSON_ARTIFACT)?;
    serde_json::from_slice(&raw).with_context(|| format!("{artifact} is not JSON"))
}

/// Save the JSONL trace, then report. Incomplete cleanup is an error (after the
/// artifact is safely written) so the audit log records an uncertain state.
fn finish(workbench: &Workbench, tool: &str, kind: &str, plan: Value, report: TraceReport) -> Result<Value> {
    let mut body = Vec::new();
    for event in &report.events {
        serde_json::to_writer(&mut body, event)?;
        body.push(b'\n');
    }
    let artifact = workbench.store.save(
        kind,
        &body,
        json!({"tool": tool, "format": "ps4wb-trace-jsonl-v1", "events": report.events.len(),
            "stop_reason": report.summary["stop_reason"], "runtime_identity": workbench.debugger.identity}),
        "jsonl",
    )?;
    if !report.cleanup_complete {
        bail!(
            "Trace saved to {} but cleanup was incomplete: {}. Console state uncertain: check debug_breakpoint_list, \
             debug_control halt, or debug_detach",
            artifact["path"].as_str().unwrap_or("?"),
            report.cleanup
        );
    }
    let mut summary = report.summary;
    let per_probe = summary.as_object_mut().and_then(|object| object.remove("per_probe"));
    Ok(json!({
        "artifact": {"path": artifact["path"], "sha256": artifact["sha256"], "size": artifact["size"]},
        "summary": summary,
        "per_probe": per_probe,
        "first_events": report.events.iter().take(PREVIEW_EVENTS).collect::<Vec<_>>(),
        "plan": plan,
    }))
}

fn trace_imports(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    workbench.debugger.require_qualified_debugger("debug_control")?;
    let elf = match args["elf_artifact"].as_str() {
        Some(path) => Some(workbench.read_artifact(path, workbench.profile.limit("transfer_bytes").max(1 << 20))?),
        None => None,
    };
    let filter = match args["filter"].as_str() {
        Some(pattern) => Some(
            regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .size_limit(1 << 20)
                .build()
                .context("Invalid filter regex")?,
        ),
        None => None,
    };
    let (probes, plan) = workbench.debugger.plan_imports(
        args["module"].as_str(),
        elf.as_deref(),
        filter.as_ref(),
        args["probe_at"].as_str().unwrap_or("plt"),
        scan_limit(args),
    )?;
    if args["dry_run"].as_bool().unwrap_or(false) {
        return Ok(json!({"dry_run": true, "plan": plan}));
    }
    let report = workbench.debugger.trace_probes(&probes, &options(args, 64))?;
    finish(workbench, "debug_trace_imports", "trace-imports", plan, report)
}

fn trace_syscalls(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    workbench.debugger.require_qualified_debugger("debug_control")?;
    let user = match args["dictionary_artifact"].as_str() {
        Some(path) => Some(tracekit::parse_syscall_dictionary(&workbench.read_artifact(path, 4 * 1024 * 1024)?)?),
        None => None,
    };
    let numbers: Vec<u64> = args["numbers"].as_array().map(|items| items.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
    let (probes, plan) = workbench.debugger.plan_syscalls(
        args["module"].as_str(),
        &numbers,
        &strings(args, "names"),
        user.as_ref(),
        args["include_unrecognized"].as_bool().unwrap_or(false),
        scan_limit(args),
    )?;
    if args["dry_run"].as_bool().unwrap_or(false) {
        return Ok(json!({"dry_run": true, "plan": plan}));
    }
    let mut options = options(args, 0);
    options.syscall_names = user;
    let report = workbench.debugger.trace_probes(&probes, &options)?;
    finish(workbench, "debug_trace_syscalls", "trace-syscalls", plan, report)
}

fn trace_function(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    workbench.debugger.require_qualified_debugger("debug_control")?;
    let (probes, plan) = workbench.debugger.plan_functions(&strings(args, "targets"))?;
    let report = workbench.debugger.trace_probes(&probes, &options(args, 0))?;
    finish(workbench, "debug_trace_function", "trace-function", plan, report)
}

fn coverage(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    workbench.debugger.require_qualified_debugger("debug_control")?;
    let blocks = match args["blocks_artifact"].as_str() {
        Some(path) => Some(tracekit::parse_blocks(&read_json(workbench, path)?)?),
        None => None,
    };
    let plan = workbench.debugger.plan_coverage(
        args["module"].as_str(),
        blocks,
        args["source"].as_str().unwrap_or("auto"),
        args["max_blocks"].as_u64().unwrap_or(50_000) as usize,
        scan_limit(args),
    )?;
    let plan_summary = json!({"module": plan.module, "runtime_base": format!("{:#x}", plan.base),
        "image_base": format!("{:#x}", plan.image_base), "granularity": plan.granularity, "source": plan.source,
        "blocks": plan.blocks.len(), "dropped": plan.dropped, "notes": plan.notes});
    if args["dry_run"].as_bool().unwrap_or(false) {
        return Ok(json!({"dry_run": true, "plan": plan_summary}));
    }
    let addresses: Vec<u64> = plan.blocks.iter().map(|(rva, _)| plan.base.wrapping_add(*rva)).collect();
    let max_hits = args["max_events"].as_u64().unwrap_or(addresses.len() as u64).max(1) as usize;
    let run = workbench.debugger.coverage_blocks(&addresses, seconds(args), slots(args), max_hits)?;
    let covered = run.hits.iter().filter(|hits| **hits > 0).count();
    let document = json!({
        "format": tracekit::COVERAGE_FORMAT,
        "module": plan.module,
        "module_sha256": plan.module_sha256,
        "image_base": format!("{:#x}", plan.image_base),
        "runtime_base": format!("{:#x}", plan.base),
        "granularity": plan.granularity,
        "blocks": plan.blocks.iter().zip(&run.hits).map(|((rva, size), hits)|
            json!({"rva": format!("{rva:#x}"), "size": size, "hits": hits})).collect::<Vec<_>>(),
        "run": {"stop_reason": run.stop_reason, "stops": run.stops, "never_armed": run.never_armed.len(),
            "foreign_stop": run.foreign_stop, "created_at": crate::artifacts::utc_now()},
    });
    let coverage_artifact = workbench.store.save(
        "coverage",
        &serde_json::to_vec_pretty(&document)?,
        json!({"tool": "debug_coverage", "format": tracekit::COVERAGE_FORMAT, "covered": covered,
            "total": plan.blocks.len(), "runtime_identity": workbench.debugger.identity}),
        "json",
    )?;
    // Function-entry granularity only proves the first instruction ran: emit 1-byte
    // BBs so Lighthouse/Cartographer do not paint whole functions.
    let drcov_blocks: Vec<(u64, u64)> = plan
        .blocks
        .iter()
        .zip(&run.hits)
        .filter(|(_, hits)| **hits > 0)
        .map(|((rva, size), _)| (*rva, if plan.granularity == "basic_block" { *size } else { 1 }))
        .collect();
    let drcov_artifact = workbench.store.save(
        "coverage-drcov",
        &tracekit::drcov(&plan.module, plan.base, plan.end, &drcov_blocks)?,
        json!({"tool": "debug_coverage", "format": "drcov-v2", "module": plan.module, "bbs": drcov_blocks.len()}),
        "drcov",
    )?;
    if !run.cleanup_complete {
        bail!(
            "Coverage saved to {} / {} but cleanup was incomplete: {}. Console state uncertain: check \
             debug_breakpoint_list, debug_control halt, or debug_detach",
            coverage_artifact["path"].as_str().unwrap_or("?"),
            drcov_artifact["path"].as_str().unwrap_or("?"),
            run.cleanup
        );
    }
    Ok(json!({
        "covered": covered, "total": plan.blocks.len(),
        "ratio": if plan.blocks.is_empty() { 0.0 } else { covered as f64 / plan.blocks.len() as f64 },
        "stop_reason": run.stop_reason, "stops": run.stops, "never_armed": run.never_armed.len(),
        "foreign_stop": run.foreign_stop,
        "coverage_artifact": {"path": coverage_artifact["path"], "sha256": coverage_artifact["sha256"]},
        "drcov_artifact": {"path": drcov_artifact["path"], "sha256": drcov_artifact["sha256"]},
        "plan": plan_summary, "cleanup": run.cleanup,
        "note": "One-shot breakpoints in rotating batches: each block costs one all-stop round trip the first time it runs; blocks never armed before the stop count as uncovered.",
    }))
}

fn coverage_diff(workbench: &Workbench, args: &Value) -> Result<Value> {
    let a = read_json(workbench, args["a"].as_str().context("Missing a")?)?;
    let b = read_json(workbench, args["b"].as_str().context("Missing b")?)?;
    tracekit::require_coverage(&a)?;
    tracekit::require_coverage(&b)?;
    tracekit::coverage_diff(&a, &b, args["max_list"].as_u64().unwrap_or(2000).clamp(1, 100_000) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debugger::fake;

    #[test]
    fn catalog_lists_trace_tools_with_control_permission() {
        let catalog: Vec<Value> = serde_json::from_str(include_str!("catalog/trace.json")).unwrap();
        for name in ["debug_trace_imports", "debug_trace_syscalls", "debug_trace_function", "debug_coverage"] {
            let tool = catalog.iter().find(|tool| tool["name"] == name).expect(name);
            assert_eq!(tool["permission"], "debug_control", "{name}");
        }
        let diff = catalog.iter().find(|tool| tool["name"] == "coverage_diff").unwrap();
        assert!(diff["permission"].is_null());
    }

    #[test]
    fn coverage_tool_runs_through_registry_and_diff_compares_artifacts() {
        let Some(_guard) = fake::callback_port_guard() else { return };
        let base = 0x40_0000u64;
        let step = |rip: u64| fake::FixtureStep { rip, ..Default::default() };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = fake::spawn_fixture(
            listener,
            fake::Fixture { pid: 71, thread_id: 72, base, image: vec![0x90; 0x100], rip: base,
                program: vec![step(base + 0x10), step(base + 0x30)], ..Default::default() },
        );
        let directory = tempfile::tempdir().unwrap();
        let profile = fake::qualified_profile(directory.path(), fake.port);
        let mut registry = ToolRegistry::with_toolset(
            Workbench::new(profile).unwrap(),
            crate::tools::Toolset::Full,
        )
        .unwrap();
        registry.call("debug_attach", json!({"pid": 71, "listen_address": "127.0.0.1"})).unwrap();
        registry.workbench.debugger.wait_stop(Duration::from_secs(2)).unwrap().expect("attach stop");
        let blocks = json!({"format": tracekit::BLOCKS_FORMAT, "module": "fixture.elf", "module_sha256": null,
            "image_base": "0x0", "blocks": [{"start":"0x10","size":4},{"start":"0x20","size":4},{"start":"0x30","size":4}],
            "functions": []});
        let saved = registry.workbench.store.save("blocks", blocks.to_string().as_bytes(), json!({}), "json").unwrap();
        let first = registry
            .call("debug_coverage", json!({"blocks_artifact": saved["path"], "timeout_seconds": 2, "max_breakpoints": 2}))
            .unwrap();
        assert_eq!(first["covered"], 2, "{first}");
        assert_eq!(first["total"], 3);
        let drcov = registry.workbench.read_artifact(first["drcov_artifact"]["path"].as_str().unwrap(), 1 << 20).unwrap();
        assert!(drcov.starts_with(b"DRCOV VERSION: 2\n"));
        assert!(String::from_utf8_lossy(&drcov).contains("BB Table: 2 bbs"));
        assert!(registry.workbench.debugger.breakpoints.is_empty());

        // A second document that only covered 0x20 (written offline) for the diff.
        let other = json!({"format": tracekit::COVERAGE_FORMAT, "module": "fixture.elf", "module_sha256": null,
            "image_base": "0x0", "blocks": [{"rva":"0x10","size":4,"hits":0},{"rva":"0x20","size":4,"hits":1},{"rva":"0x30","size":4,"hits":0}]});
        let other = registry.workbench.store.save("coverage", other.to_string().as_bytes(), json!({}), "json").unwrap();
        let diff = registry
            .call("coverage_diff", json!({"a": first["coverage_artifact"]["path"], "b": other["path"]}))
            .unwrap();
        assert_eq!(diff["only_a"], json!(["0x10", "0x30"]));
        assert_eq!(diff["only_b"], json!(["0x20"]));
        assert_eq!(diff["both"], json!([]));
        registry.call("debug_detach", json!({})).unwrap();
    }
}
