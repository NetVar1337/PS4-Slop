//! Native static analysis: function discovery, CFG/call graph, binary diffing, annotation porting, signatures, Orbis prototypes.
use crate::{
    Result,
    binimage::{FLAG_EXEC, FLAG_READ, FLAG_WRITE, Image, Segment},
    bindiff, cfg,
    cfg::{DiscoverOptions, Discovery, Node, hex},
    prototypes, sigmaker,
    tools::{ToolRegistry, address, string},
};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Returns `None` when `name` is not a tool owned by this area.
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    Some(match name {
        "artifact_functions" => artifact_functions(registry, args),
        "artifact_cfg" => artifact_cfg(registry, args),
        "artifact_callgraph" => artifact_callgraph(registry, args),
        "binary_diff" => binary_diff(registry, args),
        "annotation_port" => annotation_port(registry, args),
        "signature_make" => signature_make(registry, args),
        "orbis_prototypes" => orbis_prototypes(registry, args),
        _ => return None,
    })
}

const DEFAULT_PAGE: usize = 200;

fn optional_address(args: &Value, key: &str) -> Result<Option<u64>> {
    if args[key].is_string() {
        Ok(Some(address(&args[key])?))
    } else {
        Ok(None)
    }
}

fn read_json_artifact(registry: &ToolRegistry, artifact: &str) -> Result<Value> {
    let bytes = registry
        .workbench
        .read_artifact(artifact, registry.workbench.profile.limit("transfer_bytes"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("{artifact} is not JSON"))
}

/// Image from an ELF (or raw + `base_address`) artifact.
fn image_from_artifact(registry: &ToolRegistry, artifact: &str, base: Option<u64>) -> Result<Image> {
    let data = registry
        .workbench
        .read_artifact(artifact, registry.workbench.profile.limit("transfer_bytes"))?;
    if data.starts_with(b"\x7fELF") {
        return Image::from_elf(&data, Some(artifact.to_owned()));
    }
    let base = base.with_context(|| {
        format!("{artifact} is not an ELF image; pass base_address to analyse it as raw code (SELF/PKG containers must be decrypted/extracted first)")
    })?;
    Ok(Image::from_raw(base, data, Some(artifact.to_owned())))
}

/// Live module image: reads every mapped segment of `module` in `pid`
/// (read-only), bounded by `transfer_bytes`.
fn image_from_process(registry: &mut ToolRegistry, pid: u32, module: &str) -> Result<Image> {
    let modules = registry.workbench.debugger.module_list(pid)?;
    let list = modules.as_array().context("module_list returned no array")?;
    let lower = module.to_ascii_lowercase();
    let entry = list
        .iter()
        .find(|m| m["name"] == module)
        .or_else(|| list.iter().find(|m| m["name"].as_str().is_some_and(|n| n.to_ascii_lowercase() == lower)))
        .or_else(|| list.iter().find(|m| m["name"].as_str().is_some_and(|n| n.to_ascii_lowercase().ends_with(&lower))))
        .with_context(|| format!("Module {module} not found in pid {pid}"))?
        .clone();
    let chunk = registry.workbench.profile.limit("memory_bytes").max(4096);
    let mut budget = registry.workbench.profile.limit("transfer_bytes");
    let mut segments = Vec::new();
    let mut notes = Vec::new();
    for segment in entry["segments"].as_array().into_iter().flatten() {
        let parse = |key: &str| segment[key].as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        let (Some(start), Some(end)) = (parse("start"), parse("end")) else { continue };
        let protection = segment["protection"].as_str().unwrap_or("");
        let mut flags = 0;
        if protection.contains('r') {
            flags |= FLAG_READ;
        }
        if protection.contains('w') {
            flags |= FLAG_WRITE;
        }
        if protection.contains('x') {
            flags |= FLAG_EXEC;
        }
        let mut data = Vec::new();
        let mut at = start;
        while at < end {
            if budget == 0 {
                notes.push(format!("Stopped reading at {at:#x}: transfer_bytes budget exhausted"));
                break;
            }
            let length = ((end - at) as usize).min(chunk).min(budget);
            match registry.workbench.debugger.read_memory(pid, at, length, false) {
                Ok(bytes) => {
                    budget -= bytes.len();
                    at += bytes.len() as u64;
                    let short = bytes.len() < length;
                    data.extend(bytes);
                    if short {
                        break;
                    }
                }
                Err(error) => {
                    notes.push(format!("Read failed at {at:#x}: {error}"));
                    break;
                }
            }
        }
        segments.push(Segment { vaddr: start, memsz: end - start, data, flags });
    }
    ensure!(!segments.is_empty(), "Module {module} has no readable segments");
    let name = entry["name"].as_str().map(str::to_owned);
    let mut image = Image::from_segments(segments, name);
    image.notes = notes;
    image.notes.push("Live module: no ELF symbols/.eh_frame; functions come from call targets (and prologues if enabled)".into());
    Ok(image)
}

fn load_image(registry: &mut ToolRegistry, args: &Value) -> Result<Image> {
    if let Some(artifact) = args["artifact"].as_str() {
        ensure!(args["pid"].is_null(), "Pass either artifact or pid+module, not both");
        return image_from_artifact(registry, artifact, optional_address(args, "base_address")?);
    }
    let pid = args["pid"].as_u64().context("Pass artifact, or pid and module")? as u32;
    let module = args["module"].as_str().context("pid input requires module")?;
    image_from_process(registry, pid, module)
}

fn options(args: &Value, live: bool) -> DiscoverOptions {
    let flag = |key: &str, default: bool| args[key].as_bool().unwrap_or(default);
    DiscoverOptions {
        eh_frame: flag("eh_frame", true),
        symbols: flag("symbols", true),
        call_targets: flag("call_targets", true),
        linear_sweep: flag("linear_sweep", true),
        prologues: flag("prologues", live),
        max_functions: args["max_functions"].as_u64().map_or(cfg::DEFAULT_MAX_FUNCTIONS, |v| v as usize),
        max_function_insns: args["max_instructions"].as_u64().map_or(cfg::DEFAULT_MAX_FUNCTION_INSNS, |v| v as usize),
        max_total_insns: cfg::DEFAULT_MAX_TOTAL_INSNS,
    }
}

fn module_header(image: &Image) -> Value {
    json!({
        "module": image.name, "kind": image.kind, "module_sha256": image.sha256,
        "image_base": hex(image.base), "segments": image.segments.len(),
        "executable_bytes": image.exec_segments().map(|s| s.data.len()).sum::<usize>(),
        "symbols": image.symbols.len(), "imports": image.imports.len(), "notes": image.notes,
    })
}

fn save_blocks(registry: &ToolRegistry, image: &Image, discovery: &Discovery) -> Result<Value> {
    let document = discovery.blocks_document(image);
    let blocks = document["blocks"].as_array().map_or(0, Vec::len);
    let saved = registry.workbench.store.save(
        "blocks",
        &serde_json::to_vec(&document)?,
        json!({"format": "ps4wb-blocks-v1", "module": image.name, "module_sha256": image.sha256,
            "functions": discovery.functions.len(), "blocks": blocks, "truncated": discovery.truncated}),
        "json",
    )?;
    Ok(json!({"artifact": saved["path"], "blocks": blocks, "functions": discovery.functions.len()}))
}

fn page(args: &Value) -> (usize, usize) {
    (
        args["offset"].as_u64().unwrap_or(0) as usize,
        args["max_results"].as_u64().map_or(DEFAULT_PAGE, |v| v as usize),
    )
}

fn artifact_functions(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let image = load_image(registry, args)?;
    let discovery = cfg::discover(&image, &options(args, image.kind == "live"));
    let blocks = if args["save_blocks"].as_bool().unwrap_or(true) {
        save_blocks(registry, &image, &discovery)?
    } else {
        Value::Null
    };
    let mut by_source: BTreeMap<&str, usize> = BTreeMap::new();
    for function in &discovery.functions {
        for source in &function.sources {
            *by_source.entry(source).or_default() += 1;
        }
    }
    let (offset, limit) = page(args);
    let listed: Vec<Value> = discovery
        .functions
        .iter()
        .skip(offset)
        .take(limit)
        .map(|f| {
            json!({"start": hex(f.start), "rva": hex(f.start - image.base), "end": hex(f.end), "size": f.end - f.start,
                "name": f.name, "sources": f.sources, "blocks": f.cfg.blocks.len(), "calls": f.cfg.calls.len(),
                "cfg_truncated": f.cfg.truncated})
        })
        .collect();
    Ok(json!({
        "image": module_header(&image),
        "count": discovery.functions.len(), "by_source": by_source,
        "truncated": discovery.truncated, "notes": discovery.notes,
        "instructions_decoded": discovery.total_instructions,
        "offset": offset, "returned": listed.len(),
        "more": offset + listed.len() < discovery.functions.len(),
        "functions": listed, "blocks_artifact": blocks,
    }))
}

fn artifact_cfg(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let image = load_image(registry, args)?;
    let mode = args["mode"].as_str().unwrap_or("function");
    if mode == "module" {
        let discovery = cfg::discover(&image, &options(args, image.kind == "live"));
        let blocks = save_blocks(registry, &image, &discovery)?;
        let edges: usize = discovery.functions.iter().map(|f| f.cfg.edge_count()).sum();
        let tables: usize = discovery.functions.iter().map(|f| f.cfg.jump_tables.len()).sum();
        let unresolved: usize = discovery.functions.iter().map(|f| f.cfg.unresolved_indirect_jumps).sum();
        return Ok(json!({
            "image": module_header(&image), "mode": "module", "blocks_artifact": blocks,
            "edges": edges, "jump_tables": tables, "unresolved_indirect_jumps": unresolved,
            "truncated": discovery.truncated, "notes": discovery.notes,
        }));
    }
    let start = address(&args["address"]).context("function mode requires address")?;
    ensure!(image.is_exec(start), "Address {start:#x} is not in an executable segment");
    // Cheap context: FDE / symbol starts for tail-call detection and the bound.
    let ranges = cfg::eh_frame_ranges(&image);
    let mut known: std::collections::BTreeSet<u64> = ranges.iter().map(|r| r.0).collect();
    known.extend(image.function_symbols().map(|s| s.value));
    let bound = ranges
        .iter()
        .copied()
        .chain(image.function_symbols().filter(|s| s.size > 0).map(|s| (s.value, s.value + s.size)))
        .find(|(lo, _)| *lo == start);
    let containing = ranges.iter().find(|(lo, hi)| *lo < start && start < *hi).copied();
    let max = args["max_instructions"].as_u64().map_or(cfg::DEFAULT_MAX_FUNCTION_INSNS, |v| v as usize);
    let graph = cfg::function_cfg(&image, start, &known, bound, max);
    let name = image.function_symbols().find(|s| s.value == start).map(|s| s.name.clone());
    let format = args["format"].as_str().unwrap_or("json");
    let mut result = json!({"image": module_header(&image), "mode": "function", "name": name, "bounded_by": bound.map(|(lo, hi)| json!([hex(lo), hex(hi)]))});
    if let Some((lo, hi)) = containing {
        result["warning"] = json!(format!("address is inside the FDE range {lo:#x}-{hi:#x}, not at a function start"));
    }
    if format != "dot" {
        result["cfg"] = cfg::cfg_json(&image, &graph);
    } else {
        result["summary"] = json!({"blocks": graph.blocks.len(), "edges": graph.edge_count(), "truncated": graph.truncated});
    }
    if format != "json" {
        result["dot"] = json!(cfg::cfg_dot(&graph, name.as_deref()));
    }
    Ok(result)
}

fn artifact_callgraph(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let image = load_image(registry, args)?;
    let discovery = cfg::discover(&image, &options(args, image.kind == "live"));
    let start = address(&args["address"])?;
    let index = discovery
        .by_start(start)
        .or_else(|| discovery.containing(start))
        .with_context(|| format!("No discovered function at {start:#x}"))?;
    let function = &discovery.functions[index];
    let callees = cfg::callee_map(&discovery);
    let direction = args["direction"].as_str().unwrap_or("both");
    let limit = args["max_results"].as_u64().map_or(DEFAULT_PAGE, |v| v as usize);
    let mut result = json!({
        "image": module_header(&image),
        "function": cfg::node_json(&discovery, &image, &Node::Function(function.start)),
        "discovery_truncated": discovery.truncated,
    });
    if direction != "callers" {
        let list = callees.get(&function.start).cloned().unwrap_or_default();
        result["callees_total"] = json!(list.len());
        result["callees"] = json!(list.iter().take(limit).map(|(at, node)| {
            let mut entry = cfg::node_json(&discovery, &image, node);
            entry["call_site"] = json!(hex(*at));
            entry
        }).collect::<Vec<_>>());
    }
    if direction != "callees" {
        let me = function.name.clone().filter(|_| function.sources.contains("import_thunk"));
        let mut callers = Vec::new();
        for (caller, list) in &callees {
            for (at, node) in list {
                let hit = match node {
                    Node::Function(target) => *target == function.start,
                    Node::Import(name) => me.as_deref() == Some(name.as_str()),
                };
                if hit {
                    let mut entry = cfg::node_json(&discovery, &image, &Node::Function(*caller));
                    entry["call_site"] = json!(hex(*at));
                    callers.push(entry);
                }
            }
        }
        result["callers_total"] = json!(callers.len());
        callers.truncate(limit);
        result["callers"] = json!(callers);
    }
    let target = if let Some(to) = optional_address(args, "to_address")? {
        Some(Node::Function(
            discovery.containing(to).map_or(to, |i| discovery.functions[i].start),
        ))
    } else if let Some(name) = args["to_name"].as_str() {
        Some(
            discovery
                .functions
                .iter()
                .find(|f| f.name.as_deref() == Some(name) && !f.sources.contains("import_thunk"))
                .map_or_else(|| Node::Import(name.to_owned()), |f| Node::Function(f.start)),
        )
    } else {
        None
    };
    if let Some(target) = target {
        let depth = args["max_depth"].as_u64().unwrap_or(6) as usize;
        let max_paths = args["max_paths"].as_u64().unwrap_or(4) as usize;
        let (paths, truncated) = cfg::shortest_paths(&callees, function.start, &target, depth, max_paths);
        result["paths"] = json!(paths
            .iter()
            .map(|path| path.iter().map(|node| cfg::node_json(&discovery, &image, node)).collect::<Vec<_>>())
            .collect::<Vec<_>>());
        result["path_search"] = json!({"target": cfg::node_json(&discovery, &image, &target), "max_depth": depth,
            "found": !paths.is_empty(), "truncated": truncated,
            "note": "direct calls, tail calls and resolved imports only; indirect calls are not followed"});
    }
    Ok(result)
}

fn diff_images(registry: &mut ToolRegistry, args: &Value) -> Result<(Image, Image)> {
    let a = image_from_artifact(registry, string(args, "artifact_a")?, None)?;
    let b = image_from_artifact(registry, string(args, "artifact_b")?, None)?;
    Ok((a, b))
}

fn binary_diff(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let (a, b) = diff_images(registry, args)?;
    let opts = options(args, false);
    let disc_a = cfg::discover(&a, &opts);
    let disc_b = cfg::discover(&b, &opts);
    let mut document = bindiff::diff_document(&a, &disc_a, &b, &disc_b);
    document["options"] = json!({"prologues": opts.prologues, "linear_sweep": opts.linear_sweep});
    let saved = registry.workbench.store.save(
        "bindiff",
        &serde_json::to_vec(&document)?,
        json!({"format": bindiff::DIFF_FORMAT, "artifact_a": args["artifact_a"], "artifact_b": args["artifact_b"],
            "module_a_sha256": a.sha256, "module_b_sha256": b.sha256}),
        "json",
    )?;
    let limit = args["max_results"].as_u64().unwrap_or(50) as usize;
    let mut changed: Vec<&Value> = document["matches"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["identical"] == false)
        .collect();
    changed.sort_by(|x, y| x["similarity"].as_f64().partial_cmp(&y["similarity"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));
    let sample = |key: &str| -> Vec<Value> { document[key].as_array().into_iter().flatten().take(limit).cloned().collect() };
    Ok(json!({
        "artifact": saved["path"], "module_a": document["module_a"], "module_b": document["module_b"],
        "summary": document["summary"],
        "changed": changed.into_iter().take(limit).cloned().collect::<Vec<_>>(),
        "unmatched_a": sample("unmatched_a"), "unmatched_b": sample("unmatched_b"),
        "note": "Lists are capped at max_results; the full result (all matches with method/confidence) is in the artifact",
    }))
}

fn annotation_port(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let diff_path = string(args, "diff")?;
    let diff = read_json_artifact(registry, diff_path)?;
    ensure!(diff["format"] == bindiff::DIFF_FORMAT, "{diff_path} is not a {} document", bindiff::DIFF_FORMAT);
    let sha_a = diff["module_a"]["sha256"].as_str().map(str::to_owned);
    let sha_b = diff["module_b"]["sha256"].as_str().map(str::to_owned);
    let label_base = optional_address(args, "label_base")?;
    let allow = args["allow_hash_mismatch"].as_bool().unwrap_or(false);
    let mut items = Vec::new();
    for source in args["sources"].as_array().context("sources required")? {
        let path = source.as_str().context("sources[] must be strings")?;
        let document = read_json_artifact(registry, path)?;
        items.extend(bindiff::source_items(&document, path, sha_a.as_deref(), label_base, allow)?);
    }
    ensure!(items.len() <= 200_000, "Too many source items");
    let loaded = match (args["artifact_a"].as_str(), args["artifact_b"].as_str()) {
        (Some(_), Some(_)) => {
            let (a, b) = diff_images(registry, args)?;
            ensure!(a.sha256 == sha_a && b.sha256 == sha_b, "artifact_a/artifact_b do not match the modules recorded in the diff");
            let opts = DiscoverOptions {
                prologues: diff["options"]["prologues"].as_bool().unwrap_or(false),
                linear_sweep: diff["options"]["linear_sweep"].as_bool().unwrap_or(true),
                ..Default::default()
            };
            let (da, db) = (cfg::discover(&a, &opts), cfg::discover(&b, &opts));
            Some((a, da, b, db))
        }
        (None, None) => None,
        _ => bail!("Pass both artifact_a and artifact_b (or neither)"),
    };
    let min_confidence = args["min_confidence"].as_f64().unwrap_or(0.0);
    let (ported, unported) = bindiff::port(&diff, &items, loaded.as_ref().map(|(a, da, b, db)| (a, da, b, db)), min_confidence);
    let document = json!({
        "format": bindiff::PORT_FORMAT,
        "module_sha256": sha_b, "source_module_sha256": sha_a,
        "image_base": diff["module_b"]["image_base"], "diff_artifact": diff_path,
        "annotations": ported, "unported": unported,
    });
    let saved = registry.workbench.store.save(
        "annotations-ported",
        &serde_json::to_vec_pretty(&document)?,
        json!({"format": bindiff::PORT_FORMAT, "module_sha256": sha_b, "diff": diff_path, "ported": ported.len(), "unported": unported.len()}),
        "json",
    )?;
    let mut result = json!({
        "artifact": saved["path"], "module_sha256": sha_b, "ported": ported.len(), "unported": unported.len(),
        "sample": ported.iter().take(50).cloned().collect::<Vec<_>>(),
        "unported_sample": unported.iter().take(50).cloned().collect::<Vec<_>>(),
        "note": "Source artifacts are never modified",
    });
    if let Some(runtime) = optional_address(args, "runtime_base_b")? {
        let labels: Vec<Value> = ported
            .iter()
            .filter_map(|item| {
                let name = item["symbol"].as_str()?;
                let rva = u64::from_str_radix(item["rva"].as_str()?.trim_start_matches("0x"), 16).ok()?;
                Some(json!({"name": name, "address": hex(runtime.wrapping_add(rva))}))
            })
            .collect();
        let saved = registry.workbench.store.save(
            "labels",
            &serde_json::to_vec_pretty(&json!({"version": 1, "labels": labels}))?,
            json!({"count": labels.len(), "source": "annotation_port", "module_sha256": sha_b}),
            "json",
        )?;
        result["labels_artifact"] = json!({"artifact": saved["path"], "count": labels.len(), "load_with": "debug_label_load"});
    }
    Ok(result)
}

fn signature_make(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let image = load_image(registry, args)?;
    let target = address(&args["address"])?;
    let options = sigmaker::SigOptions {
        min_length: args["min_length"].as_u64().unwrap_or(5) as usize,
        max_length: args["max_length"].as_u64().unwrap_or(64) as usize,
        wildcard_operands: args["wildcard_operands"].as_bool().unwrap_or(false),
    };
    let mut result = sigmaker::make(&image, target, &options, args["via_reference"].as_str().unwrap_or("auto"))?;
    result["module"] = json!(image.name);
    result["module_sha256"] = json!(image.sha256);
    result["scope"] = json!("unique within the module's executable segments");
    Ok(result)
}

fn orbis_prototypes(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let action = args["action"].as_str().unwrap_or("build");
    let mut stats = json!({});
    let database: Vec<prototypes::Prototype> = if let Some(path) = args["database"].as_str() {
        let document = read_json_artifact(registry, path)?;
        ensure!(document["format"] == prototypes::FORMAT, "{path} is not a {} database", prototypes::FORMAT);
        stats["database"] = json!(path);
        prototypes::parse_user(&document)?
    } else {
        let mut lists = Vec::new();
        if let Some(path) = args["dictionary"].as_str() {
            let user = prototypes::parse_user(&read_json_artifact(registry, path)?)?;
            stats["user"] = json!(user.len());
            lists.push(user);
        }
        for header in args["headers"].as_array().into_iter().flatten() {
            let path = header.as_str().context("headers[] must be strings")?;
            let bytes = registry.workbench.read_artifact(path, 4 * 1024 * 1024)?;
            lists.push(prototypes::parse_header(&String::from_utf8_lossy(&bytes), path));
        }
        let include = match args["include_dir"].as_str() {
            Some(dir) => Some(std::path::PathBuf::from(dir)),
            None if args["use_sdk"].as_bool().unwrap_or(true) => std::env::var_os("OO_PS4_TOOLCHAIN")
                .map(|root| std::path::PathBuf::from(root).join("include"))
                .filter(|dir| dir.is_dir()),
            None => None,
        };
        match include {
            Some(dir) => {
                let (found, info) = prototypes::parse_directory(&dir)?;
                stats["include_dir"] = info;
                lists.push(found);
            }
            None => stats["include_dir"] = json!(null),
        }
        if args["include_builtin"].as_bool().unwrap_or(true) {
            lists.push(prototypes::builtin());
        }
        ensure!(
            !lists.is_empty(),
            "No prototype sources: pass include_dir, headers, dictionary or database (or set OO_PS4_TOOLCHAIN)"
        );
        let (merged, duplicates) = prototypes::merge(lists);
        stats["duplicates_skipped"] = json!(duplicates);
        merged
    };
    let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
    for prototype in &database {
        let key = if prototype.source == "builtin" || prototype.source == "user" { prototype.source.clone() } else { "header".into() };
        *by_source.entry(key).or_default() += 1;
    }
    let mut result = json!({"action": action, "count": database.len(), "by_source": by_source, "sources": stats});
    let save = args["save"].as_bool().unwrap_or(action == "build") && args["database"].is_null();
    if save {
        let document = prototypes::document(&database);
        let saved = registry.workbench.store.save(
            "prototypes",
            &serde_json::to_vec(&document)?,
            json!({"format": prototypes::FORMAT, "count": database.len()}),
            "json",
        )?;
        result["artifact"] = saved["path"].clone();
    }
    let by_nid: BTreeMap<&str, &prototypes::Prototype> = database.iter().map(|p| (p.nid.as_str(), p)).collect();
    let limit = args["max_results"].as_u64().map_or(DEFAULT_PAGE, |v| v as usize);
    match action {
        "build" => {
            result["sample"] = json!(database.iter().take(20).map(prototypes::Prototype::to_json).collect::<Vec<_>>());
        }
        "lookup" => {
            let mut found = Vec::new();
            for name in args["names"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                let nid = crate::nid::encode_nid(name);
                found.push(json!({"query": name, "nid": nid, "prototype": by_nid.get(nid.as_str()).map(|p| p.to_json())}));
            }
            for nid in args["nids"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                let bare = nid.split('#').next().unwrap_or(nid);
                found.push(json!({"query": nid, "nid": bare, "prototype": by_nid.get(bare).map(|p| p.to_json())}));
            }
            ensure!(!found.is_empty(), "lookup needs names or nids");
            result["results"] = json!(found);
        }
        "imports" => {
            let artifact = string(args, "artifact")?;
            let image = image_from_artifact(registry, artifact, None)?;
            let mut rows = Vec::new();
            let mut matched = 0usize;
            let mut seen = std::collections::BTreeSet::new();
            for symbol in image.symbols.iter().filter(|s| !s.defined) {
                let nid = symbol.nid.clone().unwrap_or_else(|| crate::nid::encode_nid(&symbol.raw));
                if !seen.insert(nid.clone()) {
                    continue;
                }
                let prototype = by_nid.get(nid.as_str());
                matched += usize::from(prototype.is_some());
                rows.push(json!({
                    "symbol": symbol.raw, "name": prototype.map_or(symbol.name.clone(), |p| p.name.clone()),
                    "nid": nid, "library": symbol.library, "prototype": prototype.map(|p| p.to_json()),
                }));
            }
            result["imports_total"] = json!(rows.len());
            result["imports_matched"] = json!(matched);
            rows.truncate(limit);
            result["imports"] = json!(rows);
        }
        other => bail!("Unknown action: {other}"),
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Profile, workbench::Workbench};

    fn registry(dir: &std::path::Path, profile: Option<Profile>) -> ToolRegistry {
        let profile = profile.unwrap_or_else(|| crate::artifacts::tests::test_profile(dir));
        ToolRegistry::with_toolset(Workbench::new(profile).unwrap(), crate::tools::Toolset::Full)
            .unwrap()
    }

    fn save(reg: &ToolRegistry, bytes: &[u8], ext: &str) -> String {
        reg.workbench.store.save("test", bytes, Value::Null, ext).unwrap()["path"].as_str().unwrap().to_owned()
    }

    #[test]
    fn offline_tools_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(dir.path(), None);
        let (builder_a, f0, f1, _) = crate::cfg::tests::sample(0x400000);
        let (mut builder_b, _, _, _) = crate::cfg::tests::sample_with(0x400000, 32);
        builder_b.symbols.clear();
        let elf_a = save(&reg, &builder_a.build(), "elf");
        let elf_b = save(&reg, &builder_b.build(), "elf");

        let functions = reg.call("artifact_functions", json!({"artifact": elf_a})).unwrap();
        assert_eq!(functions["count"], 2);
        assert_eq!(functions["functions"][0]["name"], "dispatch");
        let blocks_path = functions["blocks_artifact"]["artifact"].as_str().unwrap().to_owned();
        let blocks: Value = serde_json::from_slice(&reg.workbench.store.read(&blocks_path).unwrap()).unwrap();
        assert_eq!(blocks["format"], "ps4wb-blocks-v1");
        assert_eq!(blocks["module_sha256"], crate::config::sha256_hex(&builder_a.build()));

        let graph = reg.call("artifact_cfg", json!({"artifact": elf_a, "address": hex(f0), "format": "both"})).unwrap();
        assert_eq!(graph["cfg"]["jump_tables"][0]["entries"], 3);
        assert!(graph["dot"].as_str().unwrap().starts_with("digraph"));
        let module = reg.call("artifact_cfg", json!({"artifact": elf_a, "mode": "module"})).unwrap();
        assert_eq!(module["blocks_artifact"]["functions"], 2);

        let calls = reg
            .call("artifact_callgraph", json!({"artifact": elf_a, "address": hex(f0), "to_name": "sceKernelUsleep"}))
            .unwrap();
        assert_eq!(calls["callees_total"], 2);
        assert_eq!(calls["path_search"]["found"], true);
        let callers = reg.call("artifact_callgraph", json!({"artifact": elf_a, "address": hex(f1), "direction": "callers"})).unwrap();
        assert_eq!(callers["callers"][0]["address"], hex(f0));

        let signature = reg.call("signature_make", json!({"artifact": elf_a, "address": hex(f0)})).unwrap();
        let pattern = signature["direct"]["pattern"].as_str().unwrap().to_owned();
        let scan = reg.call("pattern_scan", json!({"artifact": elf_a, "pattern": pattern})).unwrap();
        assert_eq!(scan["matches"].as_array().unwrap().len(), 1);

        let diff = reg.call("binary_diff", json!({"artifact_a": elf_a, "artifact_b": elf_b})).unwrap();
        assert_eq!(diff["summary"]["matched"], 2);
        let diff_path = diff["artifact"].as_str().unwrap().to_owned();
        let sha_a = crate::config::sha256_hex(&builder_a.build());
        let note = reg
            .call("annotation_save", json!({"artifact": elf_a, "module_sha256": sha_a, "rva": "0x1004", "text": "after prologue", "symbol": "dispatch_body"}))
            .unwrap();
        let simple = save(&reg, br#"{"0x1000": "dispatch_renamed"}"#, "json");
        let ported = reg
            .call(
                "annotation_port",
                json!({"diff": diff_path, "sources": [note["path"], simple], "runtime_base_b": "0x880000000"}),
            )
            .unwrap();
        assert_eq!(ported["ported"], 2, "{ported}");
        let ported_doc: Value = serde_json::from_slice(&reg.workbench.store.read(ported["artifact"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(ported_doc["module_sha256"], crate::config::sha256_hex(&builder_b.build()));
        assert!(ported_doc["annotations"].as_array().unwrap().iter().any(|a| a["rva"] == "0x1024" && a["symbol"] == "dispatch_body"));
        let loaded = reg.call("debug_label_load", json!({"artifact": ported["labels_artifact"]["artifact"]})).unwrap();
        assert_eq!(loaded["loaded"], 2);

        let header = save(&reg, b"int sceKernelUsleep(unsigned int usec);\nint scePadOpen(int user, int type, int index, void *param);\n", "h");
        let built = reg.call("orbis_prototypes", json!({"action": "build", "headers": [header], "use_sdk": false})).unwrap();
        assert_eq!(built["by_source"]["header"], 2);
        let db = built["artifact"].as_str().unwrap().to_owned();
        let imports = reg.call("orbis_prototypes", json!({"action": "imports", "database": db, "artifact": elf_a})).unwrap();
        assert_eq!(imports["imports_matched"], 1);
        assert_eq!(imports["imports"][0]["prototype"]["name"], "sceKernelUsleep");
        let lookup = reg.call("orbis_prototypes", json!({"action": "lookup", "database": db, "names": ["scePadOpen"]})).unwrap();
        assert_eq!(lookup["results"][0]["prototype"]["params"][3]["name"], "param");
    }

    #[test]
    fn live_module_input_reads_process_memory() {
        let (builder, f0, f1, _) = crate::cfg::tests::sample(0);
        let elf = builder.build();
        let base = 0x8_8000_0000u64;
        // Serve the text segment as the module's process memory.
        let text = elf[0x1000..0x1000 + builder.text.len()].to_vec();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = crate::debugger::fake::spawn_fixture(
            listener,
            crate::debugger::fake::Fixture { pid: 71, thread_id: 72, base, image: text, rip: base, ..Default::default() },
        );
        let dir = tempfile::tempdir().unwrap();
        let profile = crate::debugger::fake::qualified_profile(dir.path(), fake.port);
        let mut reg = registry(dir.path(), Some(profile));
        let functions = reg.call("artifact_functions", json!({"pid": 71, "module": "fixture.elf"})).unwrap();
        let starts: Vec<&str> = functions["functions"].as_array().unwrap().iter().map(|f| f["start"].as_str().unwrap()).collect();
        assert!(starts.contains(&hex(base + f0 - 0x1000).as_str()), "{functions}");
        assert!(starts.contains(&hex(base + f1 - 0x1000).as_str()));
        let signature = reg.call("signature_make", json!({"pid": 71, "module": "fixture.elf", "address": hex(base + f0 - 0x1000)})).unwrap();
        assert!(signature["direct"]["pattern"].as_str().unwrap().starts_with("55 48 89 E5"));
    }
}
