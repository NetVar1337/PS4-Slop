//! Static-analysis calls routed to agents: runtime module resolution and annotation sync/apply.

use super::*;

impl SessionHub {
    pub(super) fn resolve_runtime_module(
        &self,
        pid: Option<u32>,
        module: Option<&str>,
        runtime_addr: Option<u64>,
    ) -> Result<(Option<u64>, Option<u64>, Option<String>)> {
        let mut reg = lock(&self.registry);
        let Some(target_pid) = pid.or(reg.workbench.debugger.attached_pid) else {
            return Ok((None, None, module.map(str::to_owned)));
        };
        let listing = reg.workbench.debugger.module_list(target_pid)?;
        let Some(mods) = listing.as_array() else {
            return Ok((None, None, module.map(str::to_owned)));
        };
        let parse_bounds = |m: &Value| -> Option<(u64, u64)> {
            let b = m["base"]
                .as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())?;
            let sz = m["size"].as_u64().unwrap_or(0);
            Some((b, b.saturating_add(sz)))
        };
        let chosen = if let Some(want) = module {
            let needle = want.to_ascii_lowercase();
            mods.iter()
                .find(|m| m["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(want)))
                .or_else(|| {
                    mods.iter()
                        .find(|m| m["name"].as_str().is_some_and(|n| n.to_ascii_lowercase().contains(&needle)))
                })
        } else if let Some(rt) = runtime_addr {
            mods.iter()
                .find(|m| matches!(parse_bounds(m), Some((start, stop)) if start <= rt && rt < stop))
        } else {
            mods.iter()
                .find(|m| m["name"].as_str() == Some("eboot.bin"))
                .or_else(|| mods.first())
        };
        if let Some(m) = chosen
            && let Some((b, e)) = parse_bounds(m)
        {
            return Ok((Some(b), Some(e), m["name"].as_str().map(str::to_owned)));
        }
        Ok((None, None, module.map(str::to_owned)))
    }

    pub(super) fn sync_annotations(&self, arguments: &Map<String, Value>) -> Result<Value> {
        let target = arguments
            .get("target")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Missing target"))?;
        let direction = arguments
            .get("direction")
            .and_then(Value::as_str)
            .unwrap_or("bidirectional");
        let pid = arguments.get("pid").and_then(Value::as_u64).map(|p| p as u32);
        let module = arguments.get("module").and_then(Value::as_str);
        let static_base = match arguments.get("static_base").and_then(Value::as_str) {
            Some(s) => crate::agents::parse_address(s)?,
            None => 0,
        };
        let max_items = arguments
            .get("max_items")
            .and_then(Value::as_u64)
            .unwrap_or(100) as usize;

        let (rt_base, rt_end, resolved_mod) = self.resolve_runtime_module(pid, module, None)?;
        let effective_rt = rt_base.unwrap_or(static_base);
        let mut imported_labels = 0usize;
        let mut exported_renames = 0usize;
        let mut exported_comments = 0usize;

        let pre_export_snapshot = if matches!(direction, "export_to_static" | "bidirectional") {
            let reg = lock(&self.registry);
            Some((
                reg.workbench.debugger.label_list(),
                reg.workbench.debugger.breakpoint_list(),
            ))
        } else {
            None
        };

        if matches!(direction, "import_from_static" | "bidirectional") {
            let mut offset = 0usize;
            let mut to_set = Vec::new();
            while offset < max_items {
                let page_len = (max_items - offset).min(100);
                let page = self.analysis.submit(
                    target,
                    "functions",
                    json!({"offset": offset, "limit": page_len}),
                    JOB_TIMEOUT,
                )?;
                let Some(items) = page.as_array() else {
                    break;
                };
                if items.is_empty() {
                    break;
                }
                for item in items {
                    let Some(fn_name) = item.get("name").and_then(Value::as_str) else {
                        continue;
                    };
                    if fn_name.is_empty()
                        || fn_name.starts_with("sub_")
                        || fn_name.starts_with("FUN_")
                        || fn_name.starts_with("fcn.")
                        || fn_name.starts_with("loc_")
                    {
                        continue;
                    }
                    let Some(addr_str) = item.get("address").and_then(Value::as_str) else {
                        continue;
                    };
                    if let Ok(st_addr) = crate::agents::parse_address(addr_str)
                        && st_addr >= static_base
                    {
                        let rt_addr = effective_rt.saturating_add(st_addr - static_base);
                        to_set.push((fn_name.to_owned(), rt_addr));
                    }
                }
                if items.len() < page_len {
                    break;
                }
                offset += items.len();
            }
            if !to_set.is_empty() {
                let mut reg = lock(&self.registry);
                for (lbl, rt_addr) in to_set {
                    let clean: String = lbl
                        .chars()
                        .map(|c| {
                            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.') {
                                c
                            } else {
                                '_'
                            }
                        })
                        .take(128)
                        .collect();
                    if !clean.is_empty() && reg.workbench.debugger.label_set(&clean, rt_addr).is_ok() {
                        imported_labels += 1;
                    }
                }
            }
        }

        if let Some((labels, bps)) = pre_export_snapshot {
            if let Some(items) = labels.as_array() {
                for item in items.iter().take(max_items) {
                    let (Some(lbl), Some(addr_str)) = (
                        item.get("name").and_then(Value::as_str),
                        item.get("address").and_then(Value::as_str),
                    ) else {
                        continue;
                    };
                    let Ok(rt_addr) = crate::agents::parse_address(addr_str) else {
                        continue;
                    };
                    if rt_addr < effective_rt || rt_end.is_some_and(|end| rt_addr >= end) {
                        continue;
                    }
                    let st_addr = static_base.saturating_add(rt_addr - effective_rt);
                    if self
                        .analysis
                        .submit(
                            target,
                            "rename",
                            json!({"address": format!("{st_addr:#x}"), "name": lbl}),
                            JOB_TIMEOUT,
                        )
                        .is_ok()
                    {
                        exported_renames += 1;
                    }
                }
            }
            if let Some(bp_items) = bps.as_array() {
                for bp in bp_items.iter().take(max_items) {
                    let Some(addr_str) = bp.get("address").and_then(Value::as_str) else {
                        continue;
                    };
                    let Ok(rt_addr) = crate::agents::parse_address(addr_str) else {
                        continue;
                    };
                    if rt_addr < effective_rt || rt_end.is_some_and(|end| rt_addr >= end) {
                        continue;
                    }
                    let cond = bp.get("condition").and_then(Value::as_str).unwrap_or("");
                    let log = bp.get("log").and_then(Value::as_str).unwrap_or("");
                    if cond.is_empty() && log.is_empty() {
                        continue;
                    }
                    let st_addr = static_base.saturating_add(rt_addr - effective_rt);
                    let note = format!("PS4 BP cond={cond} log={log}");
                    if self
                        .analysis
                        .submit(
                            target,
                            "comment",
                            json!({"address": format!("{st_addr:#x}"), "text": note}),
                            JOB_TIMEOUT,
                        )
                        .is_ok()
                    {
                        exported_comments += 1;
                    }
                }
            }
        }

        Ok(json!({
            "target": target,
            "direction": direction,
            "module": resolved_mod,
            "runtime_base": format!("{effective_rt:#x}"),
            "static_base": format!("{static_base:#x}"),
            "imported_labels": imported_labels,
            "exported_renames": exported_renames,
            "exported_comments": exported_comments,
        }))
    }

    pub(super) fn analysis_call(&self, name: &str, arguments: Value) -> Result<Value> {
        let description = analysis_tools()
            .into_iter()
            .find(|tool| tool["name"] == name)
            .ok_or_else(|| anyhow!("Unknown static-analysis tool"))?;
        validate(&arguments, &description["inputSchema"], "arguments")?;
        if name == "analysis_status" {
            return Ok(self.analysis.status());
        }
        let mut fields = arguments.as_object().cloned().unwrap_or_default();
        if name == "analysis_sync_annotations" {
            return self.sync_annotations(&fields);
        }
        if crate::analysis_apply::APPLY_TOOLS.contains(&name) {
            return self.apply_annotations(name, &fields);
        }
        let target = fields
            .remove("target")
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_default();
        let rt_arg = fields.remove("runtime_address");
        let pid_arg = fields.remove("pid").and_then(|v| v.as_u64().map(|p| p as u32));
        let mod_arg = fields.remove("module").and_then(|v| v.as_str().map(str::to_owned));
        let sb_arg = fields.remove("static_base");

        if !fields.contains_key("address")
            && let Some(Value::String(rt_str)) = rt_arg
        {
            let rt_addr = crate::agents::parse_address(&rt_str)?;
            let st_base = match sb_arg.as_ref().and_then(Value::as_str) {
                Some(s) => crate::agents::parse_address(s)?,
                None => 0,
            };
            let (Some(rt_base), _, _) =
                self.resolve_runtime_module(pid_arg, mod_arg.as_deref(), Some(rt_addr))?
            else {
                bail!("Cannot rebase runtime_address without a matching live process module");
            };
            if rt_addr < rt_base {
                bail!("runtime_address {rt_addr:#x} precedes module base {rt_base:#x}");
            }
            fields.insert(
                "address".into(),
                json!(format!("{:#x}", st_base.saturating_add(rt_addr - rt_base))),
            );
        }

        let operation = name.trim_start_matches("analysis_");
        let mut result = self
            .analysis
            .submit(&target, operation, Value::Object(fields), JOB_TIMEOUT)?;

        // Enrich Orbis NID imports automatically when returned by static analyzers.
        if name == "analysis_imports"
            && let Some(items) = result.as_array_mut()
        {
            for item in items {
                let raw_name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_default();
                if let Some((nid, lib_tag, mod_tag)) = crate::nid::split_orbis_symbol(&raw_name)
                    && let Some(obj) = item.as_object_mut()
                {
                    obj.insert("nid".into(), json!(nid));
                    if let Some(lt) = lib_tag {
                        obj.insert("library_tag".into(), json!(lt));
                    }
                    if let Some(mt) = mod_tag {
                        obj.insert("module_tag".into(), json!(mt));
                    }
                    if let Some(demangled) = crate::nid::lookup_nid(&raw_name, None) {
                        obj.insert("resolved_symbol".into(), json!(demangled));
                    }
                }
            }
        }

        let encoded = python_json(&result, None, false);
        if encoded.len() > MAX_INLINE_RESULT {
            let store = lock(&self.registry).workbench.store.clone();
            let saved = store.save("static-analysis", encoded.as_bytes(), json!({"tool": name}), "json")?;
            return Ok(json!({"result_saved": saved}));
        }
        Ok(result)
    }

    /// `analysis_apply_*`: read and validate a bounded artifact, then send compact batches to the agent.
    pub(super) fn apply_annotations(&self, name: &str, fields: &Map<String, Value>) -> Result<Value> {
        let target = fields.get("target").and_then(Value::as_str).unwrap_or_default();
        let static_base = match fields.get("static_base").and_then(Value::as_str) {
            Some(text) => Some(crate::agents::parse_address(text)?),
            None => None,
        };
        let artifact = fields.get("artifact").and_then(Value::as_str);
        let document = match (artifact, fields.get("symbols")) {
            (Some(_), Some(_)) => bail!("Supply artifact or symbols, not both"),
            (Some(path), None) => {
                let store = lock(&self.registry).workbench.store.clone();
                let content = store.read_bounded(path, crate::analysis_apply::MAX_APPLY_ARTIFACT)?;
                serde_json::from_slice::<Value>(&content).map_err(|error| anyhow!("Artifact is not JSON: {error}"))?
            }
            (None, Some(inline)) if name == "analysis_apply_symbols" => inline.clone(),
            _ => bail!("Supply an artifact"),
        };
        let prepared = crate::analysis_apply::prepare(name, &document, fields, static_base)?;
        let program = self.analysis.status()[target]["program"].as_str().map(str::to_ascii_lowercase);
        let hash_matches = match (&prepared.module_sha256, &program) {
            (Some(expected), Some(actual)) if actual.len() == 64 => Some(expected == actual),
            _ => None,
        };
        let mut summary = prepared.summary();
        summary["target"] = json!(target);
        summary["artifact"] = json!(artifact);
        summary["rebased_to"] = match static_base {
            Some(base) => json!(format!("{base:#x}")),
            None => json!("analyzer image base"),
        };
        summary["module_hash_matches"] = json!(hash_matches);
        if hash_matches == Some(false) && fields.get("allow_hash_mismatch") != Some(&Value::Bool(true)) {
            bail!("Artifact module_sha256 differs from the {target} input hash; refusing to apply (allow_hash_mismatch overrides)");
        }
        if fields.get("dry_run") == Some(&Value::Bool(true)) {
            let mut preview = prepared.batches.first().cloned().unwrap_or(Value::Null);
            if let Some(items) = preview.as_object_mut().and_then(|batch| batch.values_mut().find_map(Value::as_array_mut)) {
                items.truncate(5);
            }
            summary["dry_run"] = json!(true);
            summary["preview"] = preview;
            return Ok(summary);
        }
        let (mut applied, mut skipped, mut failed) = (0u64, 0u64, 0u64);
        let mut errors: Vec<Value> = Vec::new();
        let mut unsupported: Vec<Value> = Vec::new();
        let mut sent = 0usize;
        for batch in &prepared.batches {
            match self.analysis.submit(target, prepared.operation, batch.clone(), JOB_TIMEOUT) {
                Ok(report) => {
                    sent += 1;
                    applied += report["applied"].as_u64().unwrap_or(0);
                    skipped += report["skipped"].as_u64().unwrap_or(0);
                    failed += report["failed"].as_u64().unwrap_or(0);
                    for error in report["errors"].as_array().into_iter().flatten() {
                        if errors.len() < 50 {
                            errors.push(error.clone());
                        }
                    }
                    for feature in report["unsupported"].as_array().into_iter().flatten() {
                        if !unsupported.contains(feature) && unsupported.len() < 16 {
                            unsupported.push(feature.clone());
                        }
                    }
                }
                Err(error) if sent == 0 => return Err(error),
                Err(error) => {
                    summary["error"] = json!(format!("Stopped after {sent} batches: {error}"));
                    break;
                }
            }
        }
        summary["batches_sent"] = json!(sent);
        summary["applied"] = json!(applied);
        summary["skipped"] = json!(skipped);
        summary["failed"] = json!(failed);
        summary["errors"] = Value::Array(errors);
        summary["unsupported"] = Value::Array(unsupported);
        summary["console_changed"] = json!(false);
        Ok(summary)
    }
}
