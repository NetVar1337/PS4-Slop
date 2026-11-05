//! Process/module dumping: ELF rebuild, whole-process dumps, ELF core files, deduplicated snapshot timeline.
//!
//! Every tool here is read-only toward the console: it only issues memory
//! reads, map/module listings and (when a session is already attached)
//! register/thread queries. Outputs go to the local artifact store; partial
//! read failures are recorded per item instead of aborting the whole dump.
use crate::{
    Result,
    coredump::{self, CoreProcess, CoreRegion, CoreThread},
    debugger::Debugger,
    elfrebuild::{self, LiveContext, LiveModule, RebuildOptions},
    orbisdyn::{self, DynSources, ElfFile},
    snapstore,
    tools::{ToolRegistry, address, number, string},
    workbench::Workbench,
};
use anyhow::{Context, bail};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};

/// Returns `None` when `name` is not a tool owned by this area.
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    let wb = &mut registry.workbench;
    Some(match name {
        "elf_rebuild" => elf_rebuild(wb, args),
        "process_dump" => process_dump(wb, args),
        "process_core_dump" => process_core_dump(wb, args),
        "memory_snapshot_capture" => snapshot_capture(wb, args),
        "memory_snapshot_list" => snapstore::list(
            &wb.store,
            args["pid"].as_u64().map(|p| p as u32),
            args["label"].as_str(),
            args["limit"].as_u64().unwrap_or(256) as usize,
        ),
        "memory_snapshot_timeline" => snapshot_timeline(wb, args),
        _ => return None,
    })
}

fn optional_address(args: &Value, key: &str) -> Result<Option<u64>> {
    if args[key].is_string() { Ok(Some(address(&args[key])?)) } else { Ok(None) }
}

fn strings(args: &Value, key: &str) -> Vec<String> {
    args[key]
        .as_array()
        .map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

fn hex_field(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Read `length` bytes in `memory_bytes`-sized requests.
fn read_span(debugger: &mut Debugger, pid: u32, start: u64, length: usize, chunk: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(length);
    while out.len() < length {
        let ask = chunk.min(length - out.len());
        let bytes = debugger.read_memory(pid, start + out.len() as u64, ask, false)?;
        anyhow::ensure!(bytes.len() == ask, "Short read at {:#x}", start + out.len() as u64);
        out.extend(bytes);
    }
    Ok(out)
}

// ---- map selection ---------------------------------------------------------

#[derive(Clone, Debug)]
struct MapEntry {
    start: u64,
    end: u64,
    protection: u64,
    name: String,
}

fn protection_bits(spec: &str) -> u64 {
    spec.chars().fold(0, |bits, c| match c {
        'r' => bits | 1,
        'w' => bits | 2,
        'x' => bits | 4,
        _ => bits,
    })
}

fn map_entries(maps: &Value) -> Vec<MapEntry> {
    let mut entries: Vec<MapEntry> = maps
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| {
            Some(MapEntry {
                start: m["start"].as_u64()?,
                end: m["end"].as_u64()?,
                protection: m["protection"].as_u64().unwrap_or(0),
                name: m["name"].as_str().unwrap_or("").to_owned(),
            })
        })
        .filter(|m| m.end > m.start)
        .collect();
    entries.sort_by_key(|m| m.start);
    entries
}

/// Include/exclude are case-insensitive substrings; anonymous maps match `<anon>`.
fn name_selected(name: &str, include: &[String], exclude: &[String]) -> bool {
    let label = if name.is_empty() { "<anon>".to_owned() } else { name.to_ascii_lowercase() };
    let hit = |needle: &String| label.contains(&needle.to_ascii_lowercase());
    (include.is_empty() || include.iter().any(hit)) && !exclude.iter().any(hit)
}

fn select_maps(maps: &Value, args: &Value, default_protection: &str) -> Vec<MapEntry> {
    let include = strings(args, "include");
    let exclude = strings(args, "exclude");
    let required = protection_bits(args["protection"].as_str().unwrap_or(default_protection)) | 1;
    map_entries(maps)
        .into_iter()
        .filter(|m| m.protection & required == required && name_selected(&m.name, &include, &exclude))
        .collect()
}

fn budget(wb: &Workbench, args: &Value) -> u64 {
    args["max_total_bytes"].as_u64().unwrap_or(wb.profile.limit("transfer_bytes") as u64)
}

fn chunk_size(wb: &Workbench) -> usize {
    wb.profile.limit("memory_bytes").clamp(4096, 16 * 1024 * 1024)
}

// ---- live module context (GOT unresolution) -------------------------------

type ExportMap = BTreeMap<u64, (String, bool)>;

struct LiveModules {
    pid: u32,
    modules: Vec<LiveModule>,
    export_artifacts: HashMap<String, BTreeMap<u64, (String, bool)>>,
    loaded: HashMap<String, bool>,
    custom: Option<HashMap<String, String>>,
}

impl LiveModules {
    fn new(wb: &mut Workbench, pid: u32, custom: Option<HashMap<String, String>>) -> Result<Self> {
        let listing = wb.debugger.module_list(pid)?;
        let modules = listing
            .as_array()
            .context("Expected module array")?
            .iter()
            .filter_map(|m| {
                let base = hex_field(&m["base"])?;
                Some(LiveModule {
                    name: m["name"].as_str()?.to_owned(),
                    base,
                    end: base.saturating_add(m["size"].as_u64()?),
                    exports_source: "not_loaded".into(),
                    ..Default::default()
                })
            })
            .collect();
        Ok(Self { pid, modules, export_artifacts: HashMap::new(), loaded: HashMap::new(), custom })
    }

    fn find(&self, wanted: &str) -> Option<&LiveModule> {
        let needle = wanted.to_ascii_lowercase();
        self.modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(wanted))
            .or_else(|| self.modules.iter().find(|m| m.name.to_ascii_lowercase().contains(&needle)))
    }

    /// Exports from a local ELF artifact (an already-decrypted module file).
    fn add_export_artifact(&mut self, wb: &Workbench, module: &str, artifact: &str) -> Result<usize> {
        let bytes = wb.read_artifact(artifact, wb.profile.limit("transfer_bytes"))?;
        let elf = ElfFile::parse(&bytes)?;
        let info = orbisdyn::parse_image(&elf, self.custom.as_ref())
            .info
            .with_context(|| format!("No dynamic information in export artifact {artifact}"))?;
        let min = elf.min_vaddr();
        let exports: BTreeMap<u64, (String, bool)> =
            info.exports().into_iter().map(|e| (e.value.wrapping_sub(min), (e.name, e.known))).collect();
        let count = exports.len();
        self.export_artifacts.insert(module.to_ascii_lowercase(), exports);
        Ok(count)
    }

    /// Best-effort export table of a live module: export artifacts first, then
    /// the module's in-memory ELF header -> dynamic tables when they lie inside
    /// a loaded segment (Orbis `PT_SCE_DYNLIBDATA` normally is NOT loaded).
    fn ensure_exports(&mut self, debugger: &mut Debugger, index: usize, chunk: usize) {
        let name = self.modules[index].name.clone();
        if self.loaded.insert(name.clone(), true).is_some() {
            return;
        }
        let key = name.to_ascii_lowercase();
        let stem = key.rsplit_once('.').map_or(key.clone(), |(stem, _)| stem.to_owned());
        if let Some(exports) = self.export_artifacts.get(&key).or_else(|| self.export_artifacts.get(&stem)) {
            self.modules[index].exports = Some(exports.clone());
            self.modules[index].exports_source = "export_artifact".into();
            return;
        }
        let (pid, base, end) = (self.pid, self.modules[index].base, self.modules[index].end);
        let result = (|| -> Result<(ExportMap, u64)> {
            let header = debugger.read_memory(pid, base, 4096.min((end - base) as usize), false)?;
            let elf = ElfFile::parse(&header).context("no ELF header at module base")?;
            let min = elf.min_vaddr();
            let runtime = |va: u64| base.wrapping_add(va.wrapping_sub(min));
            let locate = |p: &orbisdyn::Phdr| -> Option<u64> {
                elf.loads()
                    .find(|l| l.offset <= p.offset && p.offset + p.filesz <= l.offset + l.filesz)
                    .map(|l| l.vaddr + (p.offset - l.offset))
                    .or_else(|| (p.vaddr != 0).then_some(p.vaddr))
            };
            let dynamic_phdr = elf.find(orbisdyn::PT_DYNAMIC).context("no PT_DYNAMIC")?;
            let dynamic_va = locate(dynamic_phdr).context("PT_DYNAMIC not in a loaded segment")?;
            anyhow::ensure!(dynamic_phdr.filesz <= 1 << 20, "PT_DYNAMIC too large");
            let dynamic = read_span(debugger, pid, runtime(dynamic_va), dynamic_phdr.filesz as usize, chunk)?;
            let dynlib = match elf.find(orbisdyn::PT_SCE_DYNLIBDATA) {
                Some(p) if p.filesz <= 16 << 20 => match locate(p).filter(|va| *va != 0 || p.vaddr != 0) {
                    Some(va) => Some(read_span(debugger, pid, runtime(va), p.filesz as usize, chunk)?),
                    None => anyhow::bail!("PT_SCE_DYNLIBDATA is not loaded in process memory"),
                },
                _ => None,
            };
            let mut reader = |va: u64, len: usize| -> Option<Vec<u8>> {
                (len <= 64 << 20).then(|| read_span(debugger, pid, runtime(va), len, chunk).ok()).flatten()
            };
            let mut sources = DynSources { dynamic: &dynamic, dynlib: dynlib.as_deref(), va_reader: &mut reader };
            let info = orbisdyn::parse_dynamic(&mut sources, self.custom.as_ref());
            Ok((info.exports().into_iter().map(|e| (e.value, (e.name, e.known))).collect(), min))
        })();
        let module = &mut self.modules[index];
        match result {
            Ok((exports, min)) => {
                module.static_base = min;
                module.exports_source = format!("live_memory ({} exports)", exports.len());
                module.exports = Some(exports);
            }
            Err(error) => module.exports_source = format!("unavailable: {error}"),
        }
    }

    /// Build the context for one image and fetch exports for every module its
    /// GOT values point into.
    fn context(
        &mut self,
        debugger: &mut Debugger,
        image: &[u8],
        runtime_base: u64,
        module_name: Option<String>,
        chunk: usize,
    ) -> Result<LiveContext> {
        let elf = ElfFile::parse(image)?;
        let min = elf.min_vaddr();
        let imports = orbisdyn::parse_image(&elf, self.custom.as_ref()).info.map(|i| i.imports()).unwrap_or_default();
        let mut got_values = HashMap::new();
        if let (Some(lo), Some(hi)) = (imports.iter().map(|i| i.slot).min(), imports.iter().map(|i| i.slot).max()) {
            let span = (hi - lo + 8) as usize;
            if span <= 16 << 20
                && let Ok(bytes) = read_span(debugger, self.pid, runtime_base.wrapping_add(lo - min), span, chunk)
            {
                for import in &imports {
                    let at = (import.slot - lo) as usize;
                    got_values.insert(import.slot, u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()));
                }
            }
        }
        let mut targets: Vec<usize> = got_values
            .values()
            .filter_map(|v| self.modules.iter().position(|m| m.base <= *v && *v < m.end))
            .collect();
        targets.sort_unstable();
        targets.dedup();
        for index in targets.into_iter().take(64) {
            self.ensure_exports(debugger, index, chunk);
        }
        Ok(LiveContext { pid: self.pid, runtime_base, module_name, modules: self.modules.clone(), got_values })
    }
}

fn nid_dictionary(wb: &Workbench, args: &Value) -> Result<Option<HashMap<String, String>>> {
    match args["nid_dictionary"].as_str() {
        Some(path) => Ok(Some(crate::nid::parse_dictionary(&wb.read_artifact(path, 16 * 1024 * 1024)?)?)),
        None => Ok(None),
    }
}

fn save_rebuilt(wb: &Workbench, source: &str, rebuilt: elfrebuild::Rebuilt) -> Result<Value> {
    let metadata = json!({"source_artifact": source, "summary": {
        "original_type": rebuilt.summary["original_type"], "output_type": rebuilt.summary["output_type"],
        "image_base": rebuilt.summary["image_base"], "sections_created": rebuilt.summary["sections_created"],
        "imports": rebuilt.summary["imports"]["total"]}, "format": "rebuilt_elf64"});
    let artifact = wb.store.save("elfrebuild", &rebuilt.bytes, metadata, "elf")?;
    let report = wb.store.save(
        "elfrebuild-report",
        &serde_json::to_vec_pretty(&json!({"source_artifact":source,"rebuilt":artifact["path"],
            "summary":rebuilt.summary,"imports":rebuilt.imports_detail}))?,
        json!({"source_artifact": source}),
        "json",
    )?;
    let mut summary = rebuilt.summary;
    summary["artifact"] = artifact;
    summary["report"] = json!({"path": report["path"], "sha256": report["sha256"]});
    Ok(summary)
}

fn elf_rebuild(wb: &mut Workbench, args: &Value) -> Result<Value> {
    let artifact = string(args, "artifact")?;
    let data = wb.read_artifact(artifact, wb.profile.limit("transfer_bytes"))?;
    let custom = nid_dictionary(wb, args)?;
    let options = RebuildOptions {
        image_base: optional_address(args, "image_base")?,
        restore_relocations: args["restore_relocations"].as_bool().unwrap_or(false),
        normalize_type: args["normalize_type"].as_bool().unwrap_or(true),
        custom_nids: custom.clone(),
    };
    let mut live = None;
    let mut notes = Vec::new();
    if let Some(pid) = args["pid"].as_u64().map(|p| p as u32) {
        let mut modules = LiveModules::new(wb, pid, custom)?;
        for pair in args["export_artifacts"].as_array().into_iter().flatten() {
            let (module, path) = (string(pair, "module")?, string(pair, "artifact")?);
            match modules.add_export_artifact(wb, module, path) {
                Ok(count) => notes.push(json!({"export_artifact":path,"module":module,"exports":count})),
                Err(error) => notes.push(json!({"export_artifact":path,"module":module,"error":error.to_string()})),
            }
        }
        // Runtime base: explicit > module list (by name) > artifact provenance sidecar.
        let sidecar: Value = wb
            .store
            .read_bounded(&format!("{artifact}.json"), 4 * 1024 * 1024)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        let module_name = args["module"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| sidecar["metadata"]["module"].as_str().map(str::to_owned));
        let runtime_base = match optional_address(args, "runtime_base")? {
            Some(base) => base,
            None => module_name
                .as_deref()
                .and_then(|name| modules.find(name).map(|m| m.base))
                .or_else(|| hex_field(&sidecar["metadata"]["runtime_base"]))
                .context("Cannot determine the module's runtime base: pass module or runtime_base")?,
        };
        let chunk = chunk_size(wb);
        live = Some(modules.context(&mut wb.debugger, &data, runtime_base, module_name, chunk)?);
    }
    let rebuilt = elfrebuild::rebuild(&data, &options, live.as_ref())?;
    let mut result = save_rebuilt(wb, artifact, rebuilt)?;
    if !notes.is_empty() {
        result["export_artifacts"] = json!(notes);
    }
    Ok(result)
}

// ---- process dump ---------------------------------------------------------------

/// Stream one address range into an artifact; unreadable chunks are zero-filled
/// and listed in the returned item.
fn dump_range(wb: &mut Workbench, pid: u32, entry: &MapEntry, kind: &str) -> Result<Value> {
    let store = wb.store.clone();
    let chunk = chunk_size(wb);
    let length = entry.end - entry.start;
    let mut failures: Vec<Value> = Vec::new();
    let debugger = &mut wb.debugger;
    let metadata = json!({"pid":pid,"start":format!("{:#x}",entry.start),"end":format!("{:#x}",entry.end),
        "name":entry.name,"protection":entry.protection,"format":"raw_memory","atomic_snapshot":false});
    let saved = store.save_stream("procregion", length as usize, metadata, "bin", |writer| {
        let mut done = 0u64;
        while done < length {
            let ask = ((length - done) as usize).min(chunk);
            let at = entry.start + done;
            let bytes = match debugger.read_memory(pid, at, ask, false) {
                Ok(bytes) if bytes.len() == ask => bytes,
                Ok(bytes) => {
                    failures.push(json!({"address":format!("{at:#x}"),"length":ask,"error":"short read"}));
                    let mut padded = bytes;
                    padded.resize(ask, 0);
                    padded
                }
                Err(error) => {
                    failures.push(json!({"address":format!("{at:#x}"),"length":ask,"error":error.to_string()}));
                    vec![0u8; ask]
                }
            };
            std::io::Write::write_all(writer, &bytes)?;
            done += ask as u64;
        }
        Ok(())
    })?;
    let status = if failures.is_empty() { "complete" } else { "partial" };
    failures.truncate(64);
    Ok(json!({"kind":kind,"name":entry.name,"start":format!("{:#x}",entry.start),"end":format!("{:#x}",entry.end),
        "protection":entry.protection,"path":saved["path"],"sha256":saved["sha256"],"size":saved["size"],
        "status":status,"failures":failures}))
}

fn process_dump(wb: &mut Workbench, args: &Value) -> Result<Value> {
    let pid = number(args, "pid")? as u32;
    let limit = budget(wb, args);
    let max_region = args["max_region_bytes"].as_u64().unwrap_or(limit);
    let include_modules = args["modules"].as_bool().unwrap_or(true);
    let include_regions = args["regions"].as_bool().unwrap_or(true);
    let rebuild = args["rebuild_modules"].as_bool().unwrap_or(true);
    let module_filter = strings(args, "module_names");
    let process = wb.debugger.process_info(pid).unwrap_or_else(|e| json!({"error":e.to_string()}));
    let maps = wb.debugger.maps(pid)?;
    wb.store.audit("process_dump_intent", json!({"pid":pid,"budget":limit}))?;
    let mut items: Vec<Value> = Vec::new();
    let mut used = 0u64;
    let mut covered: Vec<(u64, u64)> = Vec::new();
    let chunk = chunk_size(wb);

    if include_modules {
        let mut live = LiveModules::new(wb, pid, None)?;
        let modules = live.modules.clone();
        for module in modules {
            if !module_filter.is_empty() && !name_selected(&module.name, &module_filter, &[]) {
                continue;
            }
            let size = module.end - module.base;
            covered.push((module.base, module.end));
            let mut item = json!({"kind":"module","name":module.name,"start":format!("{:#x}",module.base),
                "end":format!("{:#x}",module.end),"runtime_base":format!("{:#x}",module.base)});
            if used + size > limit {
                item["status"] = json!("skipped_budget");
                items.push(item);
                continue;
            }
            match wb.memory_elf_dump(pid, Some(&module.name), Some(module.base)) {
                Ok(dumped) => {
                    used += dumped["size"].as_u64().unwrap_or(size);
                    let artifact = &dumped["artifact"];
                    item["path"] = artifact["path"].clone();
                    item["sha256"] = artifact["sha256"].clone();
                    item["size"] = artifact["size"].clone();
                    item["static_base"] = dumped["static_base"].clone();
                    let partial = dumped["partial_or_unmapped_chunks"].as_u64().unwrap_or(0);
                    item["status"] = json!(if partial == 0 { "complete" } else { "partial" });
                    item["partial_or_unmapped_chunks"] = json!(partial);
                    item["address_rebase"] = json!({"artifact":artifact["path"],"pid":pid,"module":module.name});
                    if rebuild {
                        let rebuilt = (|| -> Result<Value> {
                            let path = artifact["path"].as_str().context("artifact path")?;
                            let data = wb.read_artifact(path, wb.profile.limit("transfer_bytes"))?;
                            let context = live.context(&mut wb.debugger, &data, module.base, Some(module.name.clone()), chunk)?;
                            let rebuilt = elfrebuild::rebuild(&data, &RebuildOptions { normalize_type: true, ..Default::default() }, Some(&context))?;
                            let summary = save_rebuilt(wb, path, rebuilt)?;
                            Ok(json!({"path":summary["artifact"]["path"],"sha256":summary["artifact"]["sha256"],
                                "report":summary["report"]["path"],"imports":summary["imports"]["total"],
                                "live":summary["live"],"warnings":summary["warnings"]}))
                        })();
                        item["rebuilt"] = rebuilt.unwrap_or_else(|e| json!({"error":e.to_string()}));
                    }
                }
                Err(error) => {
                    // No ELF header in memory (common on real consoles): keep raw segments.
                    item["status"] = json!("elf_reconstruction_failed");
                    item["error"] = json!(error.to_string());
                    let segments: Vec<MapEntry> =
                        map_entries(&maps).into_iter().filter(|m| m.name == module.name && m.protection & 1 != 0).collect();
                    let mut raw = Vec::new();
                    for segment in segments {
                        let length = segment.end - segment.start;
                        if used + length > limit || length > max_region {
                            raw.push(json!({"start":format!("{:#x}",segment.start),"status":"skipped_budget"}));
                            continue;
                        }
                        used += length;
                        raw.push(dump_range(wb, pid, &segment, "module_segment").unwrap_or_else(|e| json!({"start":format!("{:#x}",segment.start),"status":"failed","error":e.to_string()})));
                    }
                    item["raw_segments"] = json!(raw);
                }
            }
            items.push(item);
        }
    }

    if include_regions {
        for entry in select_maps(&maps, args, "r") {
            if include_modules && covered.iter().any(|(s, e)| *s <= entry.start && entry.end <= *e) {
                continue;
            }
            let length = entry.end - entry.start;
            if length > max_region || used + length > limit {
                items.push(json!({"kind":"region","name":entry.name,"start":format!("{:#x}",entry.start),
                    "end":format!("{:#x}",entry.end),"protection":entry.protection,
                    "status": if length > max_region { "skipped_region_limit" } else { "skipped_budget" }}));
                continue;
            }
            used += length;
            items.push(dump_range(wb, pid, &entry, "region").unwrap_or_else(|e| {
                json!({"kind":"region","name":entry.name,"start":format!("{:#x}",entry.start),
                    "end":format!("{:#x}",entry.end),"status":"failed","error":e.to_string()})
            }));
        }
    }

    let threads = if args["threads"].as_bool().unwrap_or(true) && wb.debugger.attached_pid == Some(pid) {
        thread_states(&mut wb.debugger)
    } else {
        json!({"available":false,"reason":"no debugger session attached to this pid (read-only dump does not attach)"})
    };
    let count = |status: &str| items.iter().filter(|i| i["status"] == status).count();
    let summary = json!({
        "complete": count("complete"), "partial": count("partial"),
        "skipped": items.iter().filter(|i| i["status"].as_str().is_some_and(|s| s.starts_with("skipped"))).count(),
        "failed": count("failed") + count("elf_reconstruction_failed"),
    });
    let manifest = json!({
        "format": "ps4-process-dump-v1", "pid": pid, "process": process,
        "created_at": crate::artifacts::utc_now(), "atomic_snapshot": false,
        "budget": {"max_total_bytes": limit, "used_bytes": used, "max_region_bytes": max_region},
        "summary": summary, "items": items, "threads": threads, "maps": maps,
        "runtime_identity": wb.debugger.identity,
        "address_rebase_usage": "Each module item lists artifact/pid/module for address_rebase; region items keep their runtime start address",
    });
    let saved = wb.store.save("procdump", &serde_json::to_vec_pretty(&manifest)?, json!({"pid":pid}), "json")?;
    wb.store.audit("process_dump_result", json!({"pid":pid,"manifest":saved["path"],"used_bytes":used}))?;
    let compact: Vec<Value> = manifest["items"]
        .as_array()
        .unwrap()
        .iter()
        .take(48)
        .map(|i| json!({"kind":i["kind"],"name":i["name"],"start":i["start"],"status":i["status"],"path":i["path"],"rebuilt":i["rebuilt"]["path"]}))
        .collect();
    Ok(json!({"manifest": saved, "summary": summary, "used_bytes": used, "max_total_bytes": limit,
        "items": compact, "items_total": manifest["items"].as_array().map(Vec::len),
        "threads_captured": manifest["threads"]["threads"].as_array().map(Vec::len).unwrap_or(0)}))
}

/// Best-effort per-thread registers/FPU/TLS while a session is attached.
fn thread_states(debugger: &mut Debugger) -> Value {
    let ids = match debugger.threads() {
        Ok(ids) => ids,
        Err(error) => return json!({"available":false,"error":error.to_string()}),
    };
    let mut rows = Vec::new();
    for id in ids.as_array().into_iter().flatten().filter_map(Value::as_u64).take(256) {
        let id = id as u32;
        let capture = |result: Result<Value>| result.unwrap_or_else(|e| json!({"error":e.to_string()}));
        rows.push(json!({
            "thread_id": id,
            "info": capture(debugger.thread_info(id)),
            "registers": capture(debugger.get_registers(id)),
            "fpu": capture(debugger.fpu_registers(id)),
            "tls": capture(debugger.tls_bases(id)),
        }));
    }
    json!({"available": true, "threads": rows})
}

// ---- core dump -------------------------------------------------------------------

fn process_core_dump(wb: &mut Workbench, args: &Value) -> Result<Value> {
    let pid = number(args, "pid")? as u32;
    let limit = budget(wb, args);
    let maps = wb.debugger.maps(pid)?;
    let selected = select_maps(&maps, args, "r");
    if selected.is_empty() {
        bail!("No readable maps match the filter");
    }
    let info = wb.debugger.process_info(pid).unwrap_or(Value::Null);
    let process = CoreProcess {
        pid,
        name: info["name"].as_str().unwrap_or("").to_owned(),
        args: info["path"].as_str().unwrap_or("").to_owned(),
    };
    let mut used = 0u64;
    let mut regions = Vec::new();
    let mut skipped = Vec::new();
    for entry in &selected {
        let size = entry.end - entry.start;
        let include = used + size <= limit;
        if include {
            used += size;
        } else {
            skipped.push(json!({"start":format!("{:#x}",entry.start),"size":size,"name":entry.name}));
        }
        regions.push(CoreRegion { start: entry.start, size, protection: entry.protection, name: entry.name.clone(), include_data: include });
    }
    let mut threads = Vec::new();
    let mut thread_errors = Vec::new();
    let attached = wb.debugger.attached_pid == Some(pid);
    if attached && args["threads"].as_bool().unwrap_or(true) {
        match wb.debugger.threads() {
            Ok(ids) => {
                for id in ids.as_array().into_iter().flatten().filter_map(Value::as_u64).take(512) {
                    let id = id as u32;
                    match wb.debugger.get_registers_raw(id) {
                        Ok(gp) => {
                            let fpu = wb.debugger.fpu_registers_raw(id).ok();
                            let name = wb
                                .debugger
                                .thread_info(id)
                                .ok()
                                .and_then(|t| t["name"].as_str().map(str::to_owned))
                                .unwrap_or_default();
                            threads.push(CoreThread { lwpid: id, name, gp, fpu });
                        }
                        Err(error) => thread_errors.push(json!({"thread_id":id,"error":error.to_string()})),
                    }
                }
            }
            Err(error) => thread_errors.push(json!({"error":error.to_string()})),
        }
    }
    let layout = coredump::layout(&process, &threads, &regions, 0);
    let store = wb.store.clone();
    let chunk = chunk_size(wb);
    let mut failures = Vec::new();
    let debugger = &mut wb.debugger;
    let metadata = json!({"pid":pid,"format":"elf64_core_freebsd","threads":threads.len(),
        "memory_only":threads.is_empty(),"atomic_snapshot":false});
    let saved = store.save_stream("coredump", layout.total_size as usize, metadata, "core", |writer| {
        failures = coredump::write_core(writer, &layout, chunk, |address, length| {
            debugger.read_memory(pid, address, length, false)
        })?;
        Ok(())
    })?;
    let failure_count = failures.len();
    failures.truncate(128);
    let mode = if threads.is_empty() {
        if attached {
            "memory_only (attached, but no thread registers could be read)"
        } else {
            "memory_only (not attached to this pid; attach with debug_attach to include threads/registers)"
        }
    } else {
        "full (PRPSINFO + per-thread PRSTATUS/FPREGSET/THRMISC/X86_XSTATE)"
    };
    wb.store.audit("process_core_dump_result", json!({"pid":pid,"core":saved["path"],"threads":threads.len()}))?;
    Ok(json!({
        "core": saved, "mode": mode, "threads": threads.iter().map(|t| t.lwpid).collect::<Vec<_>>(),
        "thread_errors": thread_errors, "segments": regions.len(),
        "segments_with_data": regions.iter().filter(|r| r.include_data).count(),
        "skipped_budget": skipped, "data_bytes": used, "max_total_bytes": limit,
        "read_failures": failures, "read_failure_count": failure_count,
        "notes_layout": "FreeBSD amd64: prpsinfo_t v1 (120 B), prstatus_t v1 (224 B, pr_reg = 176-byte struct reg), fpreg (512 B FXSAVE), thrmisc (24 B), NT_X86_XSTATE (832 B, XCR0 at 464)",
        "usage": "gdb <rebuilt eboot ELF> <core>  (osabi FreeBSD); IDA: File > Open > core",
    }))
}

// ---- snapshots -------------------------------------------------------------------

fn snapshot_capture(wb: &mut Workbench, args: &Value) -> Result<Value> {
    let pid = number(args, "pid")? as u32;
    let ranges = match args["ranges"].as_array() {
        Some(items) if !items.is_empty() => snapstore::ranges_from_args(items)?,
        _ => {
            let maps = wb.debugger.maps(pid)?;
            select_maps(&maps, args, "rw")
                .into_iter()
                .map(|m| snapstore::Range { start: m.start, end: m.end, name: m.name })
                .collect()
        }
    };
    let limit = budget(wb, args);
    let chunk = chunk_size(wb);
    let label = args["label"].as_str().unwrap_or("");
    let store = wb.store.clone();
    snapstore::capture(&store, &mut wb.debugger, pid, &ranges, label, limit, chunk)
}

fn snapshot_timeline(wb: &mut Workbench, args: &Value) -> Result<Value> {
    let ids = strings(args, "snapshots");
    let filter = match (optional_address(args, "address")?, args["length"].as_u64()) {
        (Some(start), Some(length)) => Some((start, start.checked_add(length).context("range overflow")?)),
        (None, None) => None,
        _ => bail!("Range filter needs both address and length"),
    };
    let options = snapstore::TimelineOptions {
        filter,
        max_regions_per_step: args["max_regions_per_step"].as_u64().unwrap_or(64) as usize,
        max_values_per_step: args["max_values_per_step"].as_u64().unwrap_or(64) as usize,
        top_addresses: args["top_addresses"].as_u64().unwrap_or(32) as usize,
        series_addresses: args["series_addresses"].as_u64().unwrap_or(8) as usize,
    };
    snapstore::timeline(&wb.store, &ids, &options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debugger::fake;
    use crate::orbisdyn::testelf;

    const EBOOT_BASE: u64 = 0x40_0000;
    const KERNEL_BASE: u64 = 0x8_0000_0000;

    /// eboot importing two libkernel functions; libkernel image exporting them
    /// with its dynamic data inside a loaded segment.
    fn fixture() -> fake::Fixture {
        let kernel = testelf::build(&testelf::Spec {
            e_type: orbisdyn::ET_SCE_DYNAMIC,
            module_name: "libkernel",
            exports: vec![("sceKernelGetProcessTime", 0x100), ("myUnlistedExport", 0x200)],
            ..Default::default()
        });
        let eboot = testelf::build(&testelf::Spec {
            exports: vec![("sceKernelUsleep", 0x400)],
            imports: vec![("sceKernelGetProcessTime", 0x1008), ("myUnlistedExport", 0x1010)],
            relative: vec![(testelf::INIT_ARRAY, 0x400)],
            words: vec![(0x1008, KERNEL_BASE + 0x100), (0x1010, KERNEL_BASE + 0x200)],
            ..Default::default()
        });
        fake::Fixture {
            pid: 77,
            thread_id: 101,
            base: EBOOT_BASE,
            image: eboot,
            rip: EBOOT_BASE + 0x400,
            extra_maps: vec![
                (EBOOT_BASE + 0x1000, EBOOT_BASE + 0x4800, 3, "fixture.elf".into()),
                (KERNEL_BASE, KERNEL_BASE + 0x1000, 5, "libkernel.sprx".into()),
                (KERNEL_BASE + 0x1000, KERNEL_BASE + 0x4000, 3, "libkernel.sprx".into()),
                (0x9000_0000, 0x9000_2000, 3, "heap".into()),
            ],
            extra_memory: vec![(KERNEL_BASE, kernel), (0x9000_0000, vec![0x5a; 0x2000])],
            ..Default::default()
        }
    }

    fn registry(port: u16, directory: &std::path::Path) -> ToolRegistry {
        ToolRegistry::new(Workbench::new(fake::qualified_profile(directory, port)).unwrap()).unwrap()
    }

    #[test]
    fn catalog_schemas_reject_unknown_fields() {
        let tools: Vec<Value> = serde_json::from_str(include_str!("catalog/dumping.json")).unwrap();
        assert_eq!(tools.len(), 6);
        for tool in tools {
            assert!(tool["permission"].is_null());
            let validator = jsonschema::validator_for(&tool["inputSchema"]).unwrap();
            assert!(!validator.is_valid(&json!({"unexpected":true})));
        }
    }

    #[test]
    fn memory_dump_then_rebuild_resolves_got_against_live_exports() {
        let server = fake::spawn_fixture(std::net::TcpListener::bind("127.0.0.1:0").unwrap(), fixture());
        let directory = tempfile::tempdir().unwrap();
        let mut reg = registry(server.port, directory.path());
        let dumped = reg.call("memory_elf_dump", json!({"pid":77,"module":"fixture.elf"})).unwrap();
        let path = dumped["artifact"]["path"].as_str().unwrap().to_owned();
        let rebuilt = reg
            .call("elf_rebuild", json!({"artifact":path,"pid":77,"module":"fixture.elf","image_base":"0x400000"}))
            .unwrap();
        assert_eq!(rebuilt["imports"]["total"], 2, "{rebuilt}");
        assert_eq!(rebuilt["live"]["resolved_export"], 2, "{}", rebuilt["live"]);
        assert_eq!(rebuilt["live"]["renamed_from_exports"], 0, "export side is a NID too");
        assert_eq!(rebuilt["imports"]["rows"][0]["target_module"], "libkernel.sprx");
        assert_eq!(rebuilt["imports"]["rows"][0]["name_matches_export"], true);
        assert_eq!(rebuilt["image_base"], "0x400000");
        let out = reg.workbench.read_artifact(rebuilt["artifact"]["path"].as_str().unwrap(), 1 << 24).unwrap();
        let info = crate::analysis::elf_info(&out).unwrap();
        assert!(info["section_count"].as_u64().unwrap() > 10);
        // Without pid: offline rebuild works on the same artifact.
        let offline = reg.call("elf_rebuild", json!({"artifact":path,"restore_relocations":true})).unwrap();
        assert!(offline["live"].is_null());
        assert_eq!(offline["relocations_restored"]["relative"], 1);
    }

    #[test]
    fn process_dump_writes_manifest_with_modules_regions_and_budget() {
        let server = fake::spawn_fixture(std::net::TcpListener::bind("127.0.0.1:0").unwrap(), fixture());
        let directory = tempfile::tempdir().unwrap();
        let mut reg = registry(server.port, directory.path());
        let result = reg.call("process_dump", json!({"pid":77,"exclude":["<anon>"]})).unwrap();
        let manifest_path = result["manifest"]["path"].as_str().unwrap().to_owned();
        let manifest: Value = serde_json::from_slice(&reg.workbench.read_artifact(&manifest_path, 1 << 24).unwrap()).unwrap();
        let items = manifest["items"].as_array().unwrap();
        let eboot = items.iter().find(|i| i["name"] == "fixture.elf").unwrap();
        assert_eq!(eboot["status"], "complete", "{eboot}");
        assert!(eboot["rebuilt"]["path"].is_string(), "{eboot}");
        assert_eq!(eboot["rebuilt"]["live"]["resolved_export"], 2);
        let heap = items.iter().find(|i| i["name"] == "heap").unwrap();
        assert_eq!(heap["status"], "complete");
        assert_eq!(heap["size"], 0x2000);
        let bytes = reg.workbench.read_artifact(heap["path"].as_str().unwrap(), 1 << 20).unwrap();
        assert!(bytes.iter().all(|b| *b == 0x5a));
        assert!(!items.iter().any(|i| i["name"] == ""), "anonymous stack excluded");
        assert_eq!(manifest["threads"]["available"], false);
        // Tiny budget: everything past the budget is recorded as skipped, not fatal.
        let small = reg.call("process_dump", json!({"pid":77,"max_total_bytes":0x2000,"rebuild_modules":false})).unwrap();
        assert!(small["summary"]["skipped"].as_u64().unwrap() >= 1, "{small}");
        assert!(small["used_bytes"].as_u64().unwrap() <= 0x2000);
    }

    #[test]
    fn core_dump_memory_only_and_with_attached_threads() {
        let server = fake::spawn_fixture(std::net::TcpListener::bind("127.0.0.1:0").unwrap(), fixture());
        let directory = tempfile::tempdir().unwrap();
        let mut reg = registry(server.port, directory.path());
        let core = reg.call("process_core_dump", json!({"pid":77,"include":["heap","fixture"]})).unwrap();
        assert!(core["mode"].as_str().unwrap().starts_with("memory_only"));
        let bytes = reg.workbench.read_artifact(core["core"]["path"].as_str().unwrap(), 1 << 24).unwrap();
        let elf = ElfFile::parse(&bytes).unwrap();
        assert_eq!(elf.e_type, orbisdyn::ET_CORE);
        let heap = elf.phdrs.iter().find(|p| p.vaddr == 0x9000_0000).unwrap();
        assert!(bytes[heap.offset as usize..(heap.offset + heap.filesz) as usize].iter().all(|b| *b == 0x5a));
        let notes = coredump::parse_notes(&bytes[elf.phdrs[0].offset as usize..(elf.phdrs[0].offset + elf.phdrs[0].filesz) as usize]);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].n_type, coredump::NT_PRPSINFO);

        let Some(_guard) = fake::callback_port_guard() else { return };
        reg.call("debug_attach", json!({"pid":77,"listen_address":"127.0.0.1"})).unwrap();
        let core = reg.call("process_core_dump", json!({"pid":77,"include":["heap"]})).unwrap();
        assert_eq!(core["threads"], json!([101]), "{core}");
        let bytes = reg.workbench.read_artifact(core["core"]["path"].as_str().unwrap(), 1 << 24).unwrap();
        let elf = ElfFile::parse(&bytes).unwrap();
        let note = &elf.phdrs[0];
        let notes = coredump::parse_notes(&bytes[note.offset as usize..(note.offset + note.filesz) as usize]);
        let status = notes.iter().find(|n| n.n_type == coredump::NT_PRSTATUS).unwrap();
        assert_eq!(u32::from_le_bytes(status.desc[40..44].try_into().unwrap()), 101);
        let rip = u64::from_le_bytes(status.desc[48 + 136..48 + 144].try_into().unwrap());
        assert_eq!(rip, EBOOT_BASE + 0x400);
        assert!(notes.iter().any(|n| n.n_type == coredump::NT_FPREGSET));
        let dump = reg.call("process_dump", json!({"pid":77,"modules":false,"include":["heap"]})).unwrap();
        assert_eq!(dump["threads_captured"], 1);
        reg.call("debug_detach", json!({})).unwrap();
    }

    #[test]
    fn snapshot_tools_dispatch() {
        let server = fake::spawn_fixture(std::net::TcpListener::bind("127.0.0.1:0").unwrap(), fixture());
        let directory = tempfile::tempdir().unwrap();
        let mut reg = registry(server.port, directory.path());
        let a = reg.call("memory_snapshot_capture", json!({"pid":77,"include":["heap"],"label":"a"})).unwrap();
        assert_eq!(a["bytes"], 0x2000);
        let b = reg.call("memory_snapshot_capture", json!({"pid":77,"ranges":[{"address":"0x90000000","length":8192}],"label":"b"})).unwrap();
        assert_eq!(b["new_chunks"], 0);
        let listed = reg.call("memory_snapshot_list", json!({"label":"b"})).unwrap();
        assert_eq!(listed["total"], 1);
        let timeline = reg.call("memory_snapshot_timeline", json!({"snapshots":[a["id"],b["id"]]})).unwrap();
        assert_eq!(timeline["steps"][0]["changed_pages"], 0);
        assert!(reg.call("memory_snapshot_timeline", json!({"snapshots":[a["id"],b["id"]],"address":"0x90000000"})).is_err());
    }
}
