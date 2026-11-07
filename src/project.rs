//! Per-game project index, recipes (chained tool calls) and analyzer type/struct/coverage application.
//!
//! The project index is a local, append-only JSONL store under
//! `<artifact_directory>/project-index/<project-id>/` (no SQLite/C dependency):
//! `project.json` holds identity (title id, name, app version, tags) and
//! `records.jsonl` holds one JSON record per line (artifact, module, note,
//! finding, question, resolution). `project-index/active.json` names the
//! current project so `auto_record` only needs the artifact store.
use crate::artifacts::{ArtifactStore, utc_now};
use crate::{Result, tools::ToolRegistry};
use anyhow::{Context, anyhow, bail, ensure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};

const INDEX_DIR: &str = "project-index";
/// Upper bound on one project's record log; archive or start a new project beyond this.
pub const MAX_RECORDS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORD_LINE: usize = 64 * 1024;
const MAX_SIDECAR: usize = 1024 * 1024;
const MAX_AUTO_ARTIFACTS: usize = 32;
const MAX_PROJECTS_LISTED: usize = 200;
/// Read-only lookups whose results merely echo existing artifact paths.
const AUTO_RECORD_SKIP: &[&str] = &["artifact_list", "artifact_info", "artifact_read", "artifact_bundle"];

/// Returns `None` when `name` is not a tool owned by this area.
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    if name == "project_export_offsets" {
        return Some(export_offsets(&registry.workbench, args));
    }
    if name == "project_export_target" {
        return Some(export_target(&registry.workbench, args));
    }
    let store = &registry.workbench.store;
    Some(match name {
        "project_open" => open(store, args),
        "project_record" => record(store, args),
        "project_query" => query(store, args),
        "project_summary" => summary(store, args),
        "recipe_list" => crate::recipes::list(registry),
        "recipe_run" => crate::recipes::run(registry, args),
        _ => return None,
    })
}

fn slug(text: &str, maximum: usize) -> String {
    let mut out: String = text
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
        .take(maximum)
        .collect();
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn project_id(args: &Value) -> Result<String> {
    if let Some(id) = args["project"].as_str() {
        let clean = slug(id, 96);
        if clean != id || clean.is_empty() {
            bail!("Invalid project id");
        }
        return Ok(clean);
    }
    let title = args["title_id"].as_str().map(|t| slug(&t.to_ascii_uppercase(), 32));
    let name = args["name"].as_str().map(|n| slug(n, 48));
    let version = args["app_version"].as_str().map(|v| slug(v, 16));
    let base = match (title, name) {
        (Some(t), _) if !t.is_empty() => t,
        (_, Some(n)) if !n.is_empty() => n,
        _ => bail!("Supply project, title_id or name"),
    };
    Ok(match version {
        Some(v) if !v.is_empty() => format!("{base}-v{v}"),
        _ => base,
    })
}

fn index_path(store: &ArtifactStore, relative: &str) -> Result<std::path::PathBuf> {
    store.new_path(&format!("{INDEX_DIR}/{relative}"))
}

fn read_json(path: &std::path::Path) -> Result<Option<Value>> {
    if !path.is_file() {
        return Ok(None);
    }
    let content = crate::workbench::read_bounded(path, MAX_SIDECAR)?;
    Ok(Some(serde_json::from_slice(&content)?))
}

fn write_json(path: &std::path::Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

/// Identifier of the active project, if any.
pub fn active_project(store: &ArtifactStore) -> Result<Option<String>> {
    let path = index_path(store, "active.json")?;
    Ok(read_json(&path)?
        .and_then(|active| active["id"].as_str().map(str::to_owned))
        .filter(|id| index_path(store, &format!("{id}/project.json")).is_ok_and(|p| p.is_file())))
}

fn resolve_project(store: &ArtifactStore, args: &Value) -> Result<String> {
    match args["project"].as_str() {
        Some(_) => {
            let id = project_id(&json!({"project": args["project"]}))?;
            if !index_path(store, &format!("{id}/project.json"))?.is_file() {
                bail!("Unknown project: {id}");
            }
            Ok(id)
        }
        None => active_project(store)?.context("No active project; call project_open first"),
    }
}

fn load_records(store: &ArtifactStore, id: &str) -> Result<Vec<Value>> {
    let path = index_path(store, &format!("{id}/records.jsonl"))?;
    if !path.is_file() {
        return Ok(Vec::new());
    }
    if fs::metadata(&path)?.len() > MAX_RECORDS_BYTES {
        bail!("Project record log exceeds {MAX_RECORDS_BYTES} bytes; start a new project");
    }
    let mut records = Vec::new();
    for line in BufReader::new(fs::File::open(&path)?).lines() {
        let line = line?;
        if line.trim().is_empty() || line.len() > MAX_RECORD_LINE {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(&line) {
            records.push(value);
        }
    }
    Ok(records)
}

fn append_records(store: &ArtifactStore, id: &str, records: &[Value]) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let path = index_path(store, &format!("{id}/records.jsonl"))?;
    let existing = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
    let mut text = String::new();
    for record in records {
        let line = serde_json::to_string(record)?;
        if line.len() > MAX_RECORD_LINE {
            bail!("Project record exceeds {MAX_RECORD_LINE} bytes");
        }
        text.push_str(&line);
        text.push('\n');
    }
    if existing + text.len() as u64 > MAX_RECORDS_BYTES {
        bail!("Project record log would exceed {MAX_RECORDS_BYTES} bytes; start a new project");
    }
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    file.write_all(text.as_bytes())?;
    file.flush()?;
    Ok(())
}

fn new_record(kind: &str) -> Map<String, Value> {
    let mut record = Map::new();
    let uuid = uuid::Uuid::new_v4().simple().to_string();
    record.insert("id".into(), json!(format!("r-{}", &uuid[..12])));
    record.insert("time".into(), json!(utc_now()));
    record.insert("type".into(), json!(kind));
    record
}

fn list_projects(store: &ArtifactStore) -> Result<Vec<Value>> {
    let directory = index_path(store, ".")?;
    let mut projects = Vec::new();
    let Ok(entries) = fs::read_dir(&directory) else {
        return Ok(projects);
    };
    for entry in entries.flatten().take(10_000) {
        if let Ok(Some(meta)) = read_json(&entry.path().join("project.json")) {
            projects.push(meta);
        }
    }
    projects.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    projects.truncate(MAX_PROJECTS_LISTED);
    Ok(projects)
}

fn open(store: &ArtifactStore, args: &Value) -> Result<Value> {
    let selecting = ["project", "title_id", "name"].iter().any(|key| args.get(*key).is_some());
    if !selecting {
        return Ok(json!({"active": active_project(store)?, "projects": list_projects(store)?}));
    }
    let id = project_id(args)?;
    let path = index_path(store, &format!("{id}/project.json"))?;
    let existing = read_json(&path)?;
    let created = existing.is_none();
    if created && args.get("project").is_some() {
        bail!("Unknown project: {id}");
    }
    if created && args["create"] == false {
        bail!("Project {id} does not exist and create=false");
    }
    let mut meta = existing.unwrap_or_else(|| json!({"id": id, "created_at": utc_now(), "tags": []}));
    for key in ["title_id", "name", "app_version", "content_id", "description"] {
        if let Some(value) = args.get(key) {
            meta[key] = value.clone();
        }
    }
    if let Some(tags) = args["tags"].as_array() {
        let mut merged: BTreeSet<String> = meta["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str().map(str::to_owned))
            .collect();
        merged.extend(tags.iter().filter_map(|t| t.as_str().map(str::to_owned)));
        meta["tags"] = json!(merged);
    }
    meta["updated_at"] = json!(utc_now());
    fs::create_dir_all(index_path(store, &id)?)?;
    write_json(&path, &meta)?;
    write_json(&index_path(store, "active.json")?, &json!({"id": id, "selected_at": utc_now()}))?;
    let records = load_records(store, &id)?.len();
    store.audit("project_open", json!({"project": id, "created": created}))?;
    Ok(json!({"project": meta, "created": created, "active": true, "record_count": records,
        "storage": format!("{INDEX_DIR}/{id}/")}))
}

fn tags_of(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| t.is_string())
        .cloned()
        .collect()
}

/// Kind prefix of a `<kind>-<32 hex>` artifact identifier / file stem.
fn artifact_kind(path: &str) -> String {
    let stem = path.rsplit('/').next().unwrap_or(path);
    let stem = stem.split('.').next().unwrap_or(stem);
    match stem.rsplit_once('-') {
        Some((kind, uuid)) if uuid.len() == 32 && uuid.bytes().all(|b| b.is_ascii_hexdigit()) => kind.to_owned(),
        _ => "file".to_owned(),
    }
}

fn first_str(sources: &[&Value], keys: &[&str]) -> Option<Value> {
    for source in sources {
        for key in keys {
            match source.get(*key) {
                Some(Value::String(s)) if !s.is_empty() => return Some(json!(s)),
                Some(Value::Number(n)) => return Some(json!(n)),
                _ => {}
            }
        }
    }
    None
}

/// Artifact record from the provenance sidecar (when present) plus call context.
fn artifact_record(store: &ArtifactStore, path: &str, provenance: Option<&Value>, tool: Option<&str>,
    args: &Value, tags: &[Value]) -> Result<Value> {
    store.path(path)?;
    let sidecar = match provenance {
        Some(record) => record.clone(),
        None => store
            .new_path(&format!("{path}.json"))
            .ok()
            .filter(|p| p.is_file())
            .and_then(|p| crate::workbench::read_bounded(&p, MAX_SIDECAR).ok())
            .and_then(|content| serde_json::from_slice(&content).ok())
            .unwrap_or(Value::Null),
    };
    let metadata = sidecar.get("metadata").cloned().unwrap_or(Value::Null);
    let mut record = new_record("artifact");
    record.insert("path".into(), json!(path));
    record.insert("kind".into(), json!(artifact_kind(path)));
    for key in ["sha256", "size", "created_at"] {
        if let Some(value) = sidecar.get(key) {
            record.insert(key.into(), value.clone());
        }
    }
    let tool = tool.map(|t| json!(t)).or_else(|| first_str(&[&metadata], &["tool"]));
    if let Some(tool) = tool {
        record.insert("tool".into(), tool);
    }
    let fields: [(&str, &[&str]); 4] = [
        ("module", &["module", "module_name"]),
        ("module_sha256", &["module_sha256"]),
        ("pid", &["pid"]),
        ("address", &["address", "runtime_base", "base_address"]),
    ];
    for (field, keys) in fields {
        if let Some(value) = first_str(&[&metadata, args], keys) {
            record.insert(field.into(), value);
        }
    }
    if !tags.is_empty() {
        record.insert("tags".into(), json!(tags));
    }
    Ok(Value::Object(record))
}

fn record(store: &ArtifactStore, args: &Value) -> Result<Value> {
    let id = resolve_project(store, args)?;
    let tags = tags_of(&args["tags"]);
    let existing = load_records(store, &id)?;
    let known_paths: HashSet<&str> = existing
        .iter()
        .filter(|r| r["type"] == "artifact")
        .filter_map(|r| r["path"].as_str())
        .collect();
    let known_ids: HashSet<&str> = existing.iter().filter_map(|r| r["id"].as_str()).collect();
    let mut records = Vec::new();
    let mut duplicates = Vec::new();
    for path in args["artifacts"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if known_paths.contains(path) || records.iter().any(|r: &Value| r["path"] == path) {
            duplicates.push(path.to_owned());
            continue;
        }
        records.push(artifact_record(store, path, None, args["tool"].as_str(), &Value::Null, &tags)?);
    }
    for module in args["modules"].as_array().into_iter().flatten() {
        let mut record = new_record("module");
        for key in ["name", "sha256", "base", "size", "path", "version"] {
            if let Some(value) = module.get(key) {
                record.insert(key.into(), value.clone());
            }
        }
        if !tags.is_empty() {
            record.insert("tags".into(), json!(tags));
        }
        records.push(Value::Object(record));
    }
    for note in args["notes"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        let mut record = new_record("note");
        record.insert("text".into(), json!(note));
        if !tags.is_empty() {
            record.insert("tags".into(), json!(tags));
        }
        records.push(Value::Object(record));
    }
    for (kind, key) in [("finding", "findings"), ("question", "questions")] {
        for item in args[key].as_array().into_iter().flatten() {
            let mut record = new_record(kind);
            if let Some(fields) = item.as_object() {
                for (field, value) in fields {
                    record.insert(field.clone(), value.clone());
                }
            }
            if kind == "question" {
                record.insert("status".into(), json!("open"));
            }
            let mut merged = tags_of(&item["tags"]);
            merged.extend(tags.iter().cloned());
            if !merged.is_empty() {
                record.insert("tags".into(), json!(merged));
            }
            records.push(Value::Object(record));
        }
    }
    for target in args["resolve_questions"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if !known_ids.contains(target) {
            bail!("Unknown record id: {target}");
        }
        let mut record = new_record("resolution");
        record.insert("target".into(), json!(target));
        if let Some(answer) = args["resolution"].as_str() {
            record.insert("text".into(), json!(answer));
        }
        records.push(Value::Object(record));
    }
    if records.is_empty() && duplicates.is_empty() && tags.is_empty() {
        bail!("Nothing to record; supply artifacts, modules, notes, findings, questions or tags");
    }
    if records.is_empty() && !tags.is_empty() && duplicates.is_empty() {
        // Tags alone apply to the project itself.
        let path = index_path(store, &format!("{id}/project.json"))?;
        let mut meta = read_json(&path)?.unwrap_or_else(|| json!({"id": id}));
        let mut merged: BTreeSet<String> = tags_of(&meta["tags"]).iter().filter_map(|t| t.as_str().map(str::to_owned)).collect();
        merged.extend(tags.iter().filter_map(|t| t.as_str().map(str::to_owned)));
        meta["tags"] = json!(merged);
        write_json(&path, &meta)?;
        return Ok(json!({"project": id, "recorded": 0, "project_tags": meta["tags"]}));
    }
    append_records(store, &id, &records)?;
    let ids: Vec<&Value> = records.iter().map(|r| &r["id"]).collect();
    Ok(json!({"project": id, "recorded": records.len(), "record_ids": ids, "already_recorded": duplicates}))
}

fn haystack_matches(record: &Value, needle: &str) -> bool {
    let text = serde_json::to_string(record).unwrap_or_default().to_ascii_lowercase();
    text.contains(needle)
}

fn matches(record: &Value, args: &Value) -> bool {
    let eq = |field: &str, key: &str| {
        args[key].as_str().is_none_or(|want| record[field].as_str().is_some_and(|have| have.eq_ignore_ascii_case(want)))
    };
    if !eq("type", "type") || !eq("kind", "kind") || !eq("tool", "tool") {
        return false;
    }
    if let Some(sha) = args["module_sha256"].as_str() {
        let sha = sha.to_ascii_lowercase();
        let hit = record["module_sha256"].as_str() == Some(sha.as_str())
            || (record["type"] == "module" && record["sha256"].as_str() == Some(sha.as_str()));
        if !hit {
            return false;
        }
    }
    if let Some(module) = args["module"].as_str() {
        let field = if record["type"] == "module" { "name" } else { "module" };
        if !record[field].as_str().is_some_and(|m| m.to_ascii_lowercase().contains(&module.to_ascii_lowercase())) {
            return false;
        }
    }
    if let Some(tag) = args["tag"].as_str()
        && !record["tags"].as_array().is_some_and(|tags| tags.iter().any(|t| t.as_str() == Some(tag)))
    {
        return false;
    }
    let time = record["time"].as_str().unwrap_or("");
    if args["since"].as_str().is_some_and(|since| time < since) {
        return false;
    }
    if args["until"].as_str().is_some_and(|until| time > until) {
        return false;
    }
    if let Some(text) = args["text"].as_str()
        && !haystack_matches(record, &text.to_ascii_lowercase())
    {
        return false;
    }
    true
}

fn query(store: &ArtifactStore, args: &Value) -> Result<Value> {
    let id = resolve_project(store, args)?;
    let records = load_records(store, &id)?;
    let offset = args["offset"].as_u64().unwrap_or(0) as usize;
    let limit = args["limit"].as_u64().unwrap_or(50).min(100) as usize;
    let newest_first = args["order"].as_str() != Some("oldest");
    let mut hits: Vec<&Value> = records.iter().filter(|r| matches(r, args)).collect();
    if newest_first {
        hits.reverse();
    }
    let total = hits.len();
    let page: Vec<&Value> = hits.into_iter().skip(offset).take(limit).collect();
    let next = (offset + page.len() < total).then_some(offset + page.len());
    Ok(json!({"project": id, "total": total, "offset": offset, "count": page.len(), "next_offset": next, "items": page}))
}

fn bucket(kind: &str) -> Option<&'static str> {
    let kind = kind.to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| kind.contains(w));
    if has(&["coverage"]) {
        Some("coverage")
    } else if has(&["trace", "klog", "syscall", "access"]) {
        Some("traces")
    } else if has(&["dump", "elf", "core", "memory", "snapshot"]) {
        Some("dumps")
    } else if has(&["label", "annotation", "breakpoint", "symbol", "prototype", "rtti", "class", "struct", "port", "signature"]) {
        Some("annotations")
    } else {
        None
    }
}

fn compact(record: &Value) -> Value {
    let mut out = Map::new();
    for key in ["id", "time", "type", "kind", "path", "sha256", "tool", "module", "pid", "address", "title", "text", "tags", "status"] {
        if let Some(value) = record.get(key) {
            let value = match value {
                Value::String(s) if s.chars().count() > 256 => json!(format!("{}...", s.chars().take(256).collect::<String>())),
                other => other.clone(),
            };
            out.insert(key.into(), value);
        }
    }
    Value::Object(out)
}

fn summary(store: &ArtifactStore, args: &Value) -> Result<Value> {
    let id = resolve_project(store, args)?;
    let meta = read_json(&index_path(store, &format!("{id}/project.json"))?)?.unwrap_or(Value::Null);
    let records = load_records(store, &id)?;
    let per_bucket = args["limit"].as_u64().unwrap_or(20).min(100) as usize;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut modules: BTreeMap<String, Value> = BTreeMap::new();
    let mut buckets: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    let mut findings = Vec::new();
    let mut questions = Vec::new();
    let mut resolved: HashSet<&str> = HashSet::new();
    let mut tags: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_bytes = 0u64;
    for record in &records {
        let kind_of = record["type"].as_str().unwrap_or("unknown");
        *counts.entry(kind_of.to_owned()).or_default() += 1;
        for tag in record["tags"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            *tags.entry(tag.to_owned()).or_default() += 1;
        }
        match kind_of {
            "artifact" => {
                let kind = record["kind"].as_str().unwrap_or("file");
                *kinds.entry(kind.to_owned()).or_default() += 1;
                total_bytes += record["size"].as_u64().unwrap_or(0);
                if let Some(name) = bucket(kind).or_else(|| record["tool"].as_str().and_then(bucket)) {
                    buckets.entry(name).or_default().push(compact(record));
                }
                if let (Some(module), Some(sha)) = (record["module"].as_str(), record["module_sha256"].as_str()) {
                    modules.entry(format!("{module}:{sha}")).or_insert_with(|| json!({"name": module, "sha256": sha, "source": "artifact"}));
                }
            }
            "module" => {
                let key = format!("{}:{}", record["name"].as_str().unwrap_or("?"), record["sha256"].as_str().unwrap_or(""));
                modules.insert(key, compact(record));
            }
            "finding" => findings.push(compact(record)),
            "question" => questions.push(record),
            "resolution" => {
                if let Some(target) = record["target"].as_str() {
                    resolved.insert(target);
                }
            }
            _ => {}
        }
    }
    let open_questions: Vec<Value> = questions
        .iter()
        .filter(|q| q["id"].as_str().is_none_or(|qid| !resolved.contains(qid)))
        .map(|q| compact(q))
        .collect();
    let newest = |items: &Vec<Value>| -> Value {
        json!({"count": items.len(), "latest": items.iter().rev().take(per_bucket).collect::<Vec<_>>()})
    };
    let mut sections = Map::new();
    for name in ["dumps", "traces", "coverage", "annotations"] {
        sections.insert(name.into(), newest(buckets.get(name).unwrap_or(&Vec::new())));
    }
    Ok(json!({
        "project": meta,
        "record_count": records.len(),
        "counts": counts,
        "artifact_kinds": kinds,
        "artifact_bytes": total_bytes,
        "modules": modules.into_values().take(100).collect::<Vec<_>>(),
        "dumps": sections["dumps"],
        "traces": sections["traces"],
        "coverage": sections["coverage"],
        "annotations": sections["annotations"],
        "findings": newest(&findings),
        "open_questions": {"count": open_questions.len(), "items": open_questions.iter().take(per_bucket * 2).collect::<Vec<_>>()},
        "tags": tags,
        "latest": records.iter().rev().take(10).map(compact).collect::<Vec<_>>(),
    }))
}

fn collect_artifacts<'a>(value: &'a Value, depth: usize, found: &mut Vec<&'a Value>) {
    if depth > 6 || found.len() >= MAX_AUTO_ARTIFACTS {
        return;
    }
    match value {
        Value::Object(fields) => {
            let is_artifact = fields.get("path").and_then(Value::as_str).is_some()
                && fields
                    .get("sha256")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
            if is_artifact {
                found.push(value);
                return;
            }
            for child in fields.values() {
                collect_artifacts(child, depth + 1, found);
            }
        }
        Value::Array(items) => {
            for child in items.iter().take(256) {
                collect_artifacts(child, depth + 1, found);
            }
        }
        _ => {}
    }
}

/// Best-effort: record every artifact (object with `path` + `sha256`) found in
/// `result` into the active project. No-op (Ok(0)) when no project is active,
/// the tool is a project/recipe/lookup tool, or nothing new was produced.
pub fn auto_record(store: &ArtifactStore, tool: &str, args: &Value, result: &Value) -> Result<usize> {
    if tool.starts_with("project_") || tool.starts_with("recipe_") || AUTO_RECORD_SKIP.contains(&tool) {
        return Ok(0);
    }
    let mut found = Vec::new();
    collect_artifacts(result, 0, &mut found);
    if found.is_empty() {
        return Ok(0);
    }
    let Some(id) = active_project(store)? else {
        return Ok(0);
    };
    let existing = load_records(store, &id)?;
    let mut known: HashSet<String> = existing
        .iter()
        .filter(|r| r["type"] == "artifact")
        .filter_map(|r| r["path"].as_str().map(str::to_owned))
        .collect();
    let mut context = args.clone();
    if !context.is_object() {
        context = json!({});
    }
    for key in ["module", "module_sha256"] {
        if context.get(key).is_none()
            && let Some(value) = result.get(key).filter(|v| v.is_string())
        {
            context[key] = value.clone();
        }
    }
    let mut records = Vec::new();
    for provenance in found {
        let Some(path) = provenance["path"].as_str() else { continue };
        if !known.insert(path.to_owned()) {
            continue;
        }
        if let Ok(record) = artifact_record(store, path, Some(provenance), Some(tool), &context, &[]) {
            records.push(record);
        }
    }
    append_records(store, &id, &records)?;
    Ok(records.len())
}


/// Export format emitted by `project_export_offsets` (the `.json` companion of the `.hpp`).
pub const OFFSETS_FORMAT: &str = "ps4wb-offsets-v1";

/// Sanitize `text` into a usable C++ identifier; falls back when unusable.
fn cident(text: &str, fallback: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if out.is_empty() {
        return fallback.to_owned();
    }
    if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out = format!("_{out}");
    }
    out
}

struct OffsetEntry {
    symbol: String,
    rva: u64,
    comment: String,
    evidence: Value,
    evidence_sha256: Value,
    verify_hex: Option<String>,
}

struct OffsetsData {
    module_names: BTreeMap<String, String>,
    groups: BTreeMap<String, Vec<OffsetEntry>>,
    dump_bytes: BTreeMap<String, Vec<u8>>,
    skipped: Vec<Value>,
}

/// Shared collection for both exporters: module names, annotation-derived offset
/// entries grouped by module hash, and the newest dump-like artifact per module
/// used for verify fingerprints.
fn collect_offsets(workbench: &crate::workbench::Workbench, records: &[Value], want_sha: &Option<String>, verify_bytes: usize) -> OffsetsData {
    // module sha256 -> display name, from module records
    let mut module_names: BTreeMap<String, String> = BTreeMap::new();
    for record in records {
        if record["type"] == "module"
            && let (Some(sha), Some(name)) = (record["sha256"].as_str(), record["name"].as_str())
            && sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit())
        {
            module_names.insert(sha.to_ascii_lowercase(), name.to_owned());
        }
    }

    // Newest recorded dump-like artifact per module sha, for verify fingerprints.
    let transfer = workbench.profile.limit("transfer_bytes");
    let mut dump_bytes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for record in records.iter().rev() {
        if record["type"] != "artifact" {
            continue;
        }
        let Some(sha) = record["module_sha256"].as_str().map(str::to_ascii_lowercase) else { continue };
        if want_sha.as_ref().is_some_and(|w| *w != sha) || dump_bytes.contains_key(&sha) {
            continue;
        }
        let kind = record["kind"].as_str().unwrap_or("");
        if !["elf", "dump", "memory", "snapshot", "core"].iter().any(|k| kind.contains(k)) {
            continue;
        }
        if let Some(path) = record["path"].as_str()
            && let Ok(bytes) = workbench.read_artifact(path, transfer)
        {
            dump_bytes.insert(sha, bytes);
        }
    }

    // Annotation artifact bodies -> offset entries grouped by module sha.
    let mut groups: BTreeMap<String, Vec<OffsetEntry>> = BTreeMap::new();
    let mut seen: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    let mut skipped: Vec<Value> = Vec::new();
    for record in records.iter().rev() {
        if record["type"] != "artifact" || record["kind"] != "annotation" {
            continue;
        }
        let Some(path) = record["path"].as_str() else { continue };
        let body = workbench
            .read_artifact(path, MAX_SIDECAR)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        let Some(body) = body else { continue };
        let Some(sha) = body["module_sha256"].as_str().map(str::to_ascii_lowercase) else { continue };
        if want_sha.as_ref().is_some_and(|w| *w != sha) {
            continue;
        }
        let Ok(rva) = crate::tools::address(&body["rva"]) else {
            skipped.push(json!({"path": path, "reason": "annotation rva is not an address"}));
            continue;
        };
        let base_symbol = cident(body["symbol"].as_str().unwrap_or(""), &format!("off_{rva:x}"));
        let taken = seen.entry(sha.clone()).or_default();
        let mut symbol = base_symbol.clone();
        let mut suffix = 2;
        while !taken.insert(symbol.clone()) {
            symbol = format!("{base_symbol}_{suffix}");
            suffix += 1;
        }
        let verify_hex = dump_bytes.get(&sha).and_then(|dump| {
            let start = usize::try_from(rva).ok()?;
            let end = start.checked_add(verify_bytes)?;
            (end <= dump.len()).then(|| hex::encode(&dump[start..end]))
        });
        groups.entry(sha).or_default().push(OffsetEntry {
            symbol,
            rva,
            comment: body["comment"].as_str().unwrap_or("").replace('\n', " "),
            evidence: body["artifact"].clone(),
            evidence_sha256: body["artifact_sha256"].clone(),
            verify_hex,
        });
    }
    OffsetsData { module_names, groups, dump_bytes, skipped }
}

/// Export the active project's evidence annotations into a generated C++ header
/// (per-module namespaces, RVA constants, runtime verify fingerprints) plus a
/// `ps4wb-offsets-v1` JSON manifest. Verify bytes are sliced from a recorded dump
/// artifact of the same module when one exists; otherwise the check is omitted.
/// Fully local: reads only the artifact store and project index.
fn export_offsets(workbench: &crate::workbench::Workbench, args: &Value) -> Result<Value> {
    let store = &workbench.store;
    let id = resolve_project(store, args)?;
    let meta = read_json(&index_path(store, &format!("{id}/project.json"))?)?.unwrap_or_else(|| json!({"id": id}));
    let records = load_records(store, &id)?;
    let want_sha = args["module_sha256"].as_str().map(str::to_ascii_lowercase);
    let verify_bytes = args["verify_bytes"].as_u64().unwrap_or(16).clamp(1, 32) as usize;
    let namespace = args["namespace"].as_str()
        .map(|n| slug(&n.to_ascii_lowercase(), 48))
        .filter(|n| !n.is_empty())
        .or_else(|| meta["name"].as_str().map(|n| slug(&n.to_ascii_lowercase(), 48)).filter(|n| !n.is_empty()))
        .unwrap_or_else(|| slug(&id, 48));
    let data = collect_offsets(workbench, &records, &want_sha, verify_bytes);
    let OffsetsData { module_names, groups, skipped, .. } = data;
    let total: usize = groups.values().map(Vec::len).sum();

    // Generated C++ header.
    let mut hpp = String::new();
    hpp.push_str("// Generated by project_export_offsets; do not edit by hand.\n");
    hpp.push_str("// Regenerate from the workbench project index after annotation_save/annotation_port.\n");
    hpp.push_str(&format!("// project: {id}  title_id: {}  app_version: {}\n", meta["title_id"], meta["app_version"]));
    hpp.push_str("#pragma once\n#include <cstddef>\n#include <cstdint>\n\n");
    hpp.push_str(&format!("namespace {namespace} {{\n\n"));
    hpp.push_str("struct VerifyCheck {\n    std::uintptr_t offset;\n    std::size_t length;\n    std::uint8_t bytes[32];\n};\n\n");
    let mut modules_json = Vec::new();
    for (sha, entries) in &groups {
        let module = module_names.get(sha).cloned().unwrap_or_else(|| "module".to_owned());
        let modns = slug(&module.to_ascii_lowercase(), 48);
        hpp.push_str(&format!("namespace {modns} {{ // {module}  sha256={sha}\n"));
        hpp.push_str("inline constexpr VerifyCheck kVerifyChecks[] = {\n");
        let mut offsets_json = Vec::new();
        for entry in entries {
            if let Some(hex_text) = &entry.verify_hex {
                let bytes = hex::decode(hex_text).unwrap_or_default();
                let list: Vec<String> = bytes.iter().map(|b| format!("0x{b:02x}")).collect();
                hpp.push_str(&format!("    {{ {:#x}, {}, {{ {} }} }},\n", entry.rva, bytes.len(), list.join(", ")));
            }
            let comment = if entry.comment.is_empty() { String::new() } else { format!(" // {}", entry.comment) };
            hpp.push_str(&format!("inline constexpr std::uintptr_t {} = {:#x};{comment}\n", entry.symbol, entry.rva));
            offsets_json.push(json!({
                "symbol": entry.symbol, "rva": format!("{:#x}", entry.rva), "comment": entry.comment,
                "evidence": entry.evidence, "evidence_sha256": entry.evidence_sha256,
                "verify": entry.verify_hex.as_ref().map(|hex_text| json!({"offset": format!("{:#x}", entry.rva), "hex": hex_text})).unwrap_or(Value::Null),
            }));
        }
        hpp.push_str("};\n");
        hpp.push_str("inline constexpr std::size_t kVerifyCheckCount = sizeof(kVerifyChecks) / sizeof(kVerifyChecks[0]);\n\n");
        hpp.push_str(&format!("}} // namespace {modns}\n\n"));
        modules_json.push(json!({"module": module, "module_sha256": sha, "offsets": offsets_json}));
    }
    hpp.push_str(&format!("}} // namespace {namespace}\n"));

    let doc = json!({
        "format": OFFSETS_FORMAT,
        "project": id,
        "title_id": meta["title_id"],
        "app_version": meta["app_version"],
        "generated_at": utc_now(),
        "namespace": namespace,
        "verify_bytes": verify_bytes,
        "modules": modules_json,
    });
    let provenance = json!({"project": id, "format": OFFSETS_FORMAT, "tool": "project_export_offsets"});
    let header = store.save("offsets", hpp.as_bytes(), provenance.clone(), "hpp")?;
    let manifest = store.save("offsets", &serde_json::to_vec_pretty(&doc)?, provenance, "json")?;
    store.audit("project_export_offsets", json!({"project": id, "offsets": total, "modules": groups.len()}))?;
    Ok(json!({
        "project": id, "format": OFFSETS_FORMAT, "namespace": namespace,
        "header": header, "manifest": manifest,
        "offsets": total, "modules": groups.len(), "skipped": skipped,
    }))
}
/// Insert one absolute-address fingerprint, or record why it was skipped.
fn push_fingerprint(fingerprints: &mut BTreeMap<u64, String>, skipped: &mut Vec<Value>, base: u64, rva: u64, hex_text: &str, source: &str) {
    match base.checked_add(rva) {
        Some(absolute) => {
            fingerprints.entry(absolute).or_insert_with(|| hex_text.to_owned());
        }
        None => skipped.push(json!({"rva": format!("{rva:#x}"), "source": source, "reason": "absolute address overflow"})),
    }
}

/// Export format consumed by `payload_stage`/`payload_recover`/`process_call`.
pub const TARGET_FORMAT: &str = "ps4wb-internals-target-v1";

/// Emit a ready-to-stage `ps4wb-internals-target-v1` manifest from the active
/// project: identity from the project/module records, executable-text hash from
/// the module record, and absolute-address fingerprints from annotations plus
/// optional `signature_sites` (RVAs returned by `signature_make`). Bytes come
/// from the recorded dump of the same module; without a base and a dump the
/// corresponding fingerprint is skipped, never fabricated.
fn export_target(workbench: &crate::workbench::Workbench, args: &Value) -> Result<Value> {
    let store = &workbench.store;
    let id = resolve_project(store, args)?;
    let meta = read_json(&index_path(store, &format!("{id}/project.json"))?)?.unwrap_or_else(|| json!({"id": id}));
    let title_id = meta["title_id"].as_str().context("Project has no title_id; reopen it with project_open title_id")?;
    let records = load_records(store, &id)?;
    let want_sha = args["module_sha256"].as_str().map(str::to_ascii_lowercase);
    let verify_bytes = args["verify_bytes"].as_u64().unwrap_or(16).clamp(1, 32) as usize;
    let data = collect_offsets(workbench, &records, &want_sha, verify_bytes);
    let sha = match (&want_sha, data.groups.len()) {
        (Some(sha), _) => sha.clone(),
        (None, 1) => data.groups.keys().next().cloned().unwrap_or_default(),
        (None, 0) => bail!("No offsets recorded for this project; record annotations first"),
        (None, _) => bail!("Multiple modules have annotations; supply module_sha256"),
    };
    let entries = data.groups.get(&sha).map(Vec::as_slice).unwrap_or(&[]);
    let module = data.module_names.get(&sha).cloned().unwrap_or_else(|| "eboot.bin".to_owned());
    let module_record = records.iter().find(|r| {
        r["type"] == "module" && r["sha256"].as_str().map(str::to_ascii_lowercase) == Some(sha.clone())
    });
    let base = if args["image_base"].is_string() {
        crate::tools::address(&args["image_base"])?
    } else {
        module_record
            .and_then(|r| r["base"].as_str())
            .map(|text| crate::tools::address(&json!(text)))
            .transpose()?
            .context("Supply image_base or record the module base (project_record modules[].base)")?
    };
    let process_name = args["process_name"].as_str().unwrap_or(&module).to_owned();
    let process_path = args["process_path"].as_str()
        .map(str::to_owned)
        .or_else(|| module_record.and_then(|r| r["path"].as_str()).map(str::to_owned))
        .unwrap_or_else(|| format!("/app0/{process_name}"));
    let status_magic = if args["status_magic"].is_string() {
        crate::tools::address(&args["status_magic"])?
    } else {
        0x5053494E // "PSIN", internals/runtime.hpp kDefaultStatusMagic
    };
    ensure!(status_magic <= u32::MAX as u64, "status_magic must be uint32");

    let mut fingerprints: BTreeMap<u64, String> = BTreeMap::new();
    let mut skipped = data.skipped.clone();
    for entry in entries {
        match &entry.verify_hex {
            Some(hex_text) => push_fingerprint(&mut fingerprints, &mut skipped, base, entry.rva, hex_text, "annotation"),
            None => skipped.push(json!({"rva": format!("{:#x}", entry.rva), "source": "annotation", "reason": "no recorded dump covers this offset"})),
        }
    }
    // signature_sites: RVAs verified unique by signature_make; bytes from the dump.
    for site in args["signature_sites"].as_array().into_iter().flatten() {
        let rva = crate::tools::address(site)?;
        match data.dump_bytes.get(&sha).and_then(|dump| {
            let start = usize::try_from(rva).ok()?;
            let end = start.checked_add(verify_bytes)?;
            (end <= dump.len()).then(|| hex::encode(&dump[start..end]))
        }) {
            Some(hex_text) => push_fingerprint(&mut fingerprints, &mut skipped, base, rva, &hex_text, "signature"),
            None => skipped.push(json!({"rva": format!("{rva:#x}"), "source": "signature", "reason": "no recorded dump covers this site"})),
        }
    }
    ensure!(!fingerprints.is_empty(), "No fingerprints could be built; record a dump and annotations or signature_sites first");

    let mut pointers = Vec::new();
    for pointer in args["pointers"].as_array().into_iter().flatten().take(64) {
        let address = crate::tools::address(&pointer["address"])?;
        let expected = crate::tools::address(&pointer["expected"])?;
        pointers.push(json!({"address": format!("{address:#x}"), "expected": format!("{expected:#x}")}));
    }
    ensure!(args["pointers"].as_array().map_or(0, Vec::len) <= 64, "Too many pointer checks");
    ensure!(fingerprints.len() <= 64, "Too many fingerprints (max 64)");

    let manifest = json!({
        "format": TARGET_FORMAT,
        "name": meta["name"].as_str().unwrap_or(&id),
        "title_id": title_id,
        "process_name": process_name,
        "process_path": process_path,
        "application_version": meta["app_version"].as_str().unwrap_or("01.00"),
        "executable_text_sha256": sha,
        "status_magic": format!("{status_magic:#x}"),
        "fingerprints": fingerprints.iter().map(|(address, hex_text)| json!({"address": format!("{address:#x}"), "hex": hex_text})).collect::<Vec<_>>(),
        "pointers": pointers,
    });
    let saved = store.save("internals-target", &serde_json::to_vec_pretty(&manifest)?, json!({"project": id, "tool": "project_export_target", "module_sha256": sha}), "json")?;
    store.audit("project_export_target", json!({"project": id, "module": module, "fingerprints": fingerprints.len(), "pointers": pointers.len()}))?;
    Ok(json!({
        "project": id, "format": TARGET_FORMAT, "target": saved, "module": module,
        "image_base": format!("{base:#x}"), "fingerprints": fingerprints.len(),
        "pointers": pointers.len(), "skipped": skipped,
    }))
}

/// Error helper for callers wanting a uniform message.
pub fn require_active(store: &ArtifactStore) -> Result<String> {
    active_project(store)?.ok_or_else(|| anyhow!("No active project; call project_open first"))
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
    fn open_record_query_and_summary() {
        let (_dir, store) = store();
        assert!(require_active(&store).is_err());
        let listing = open(&store, &json!({})).unwrap();
        assert!(listing["active"].is_null());
        let opened = open(&store, &json!({"title_id": "cusa12345", "app_version": "01.02", "name": "Game"})).unwrap();
        assert_eq!(opened["project"]["id"], "CUSA12345-v01_02");
        assert_eq!(opened["created"], true);
        let again = open(&store, &json!({"title_id": "CUSA12345", "app_version": "01.02"})).unwrap();
        assert_eq!(again["created"], false);

        let dump = store.save("elfdump", b"\x7fELF", json!({"module": "eboot.bin", "pid": 71,
            "runtime_base": "0x400000", "module_sha256": "a".repeat(64)}), "elf").unwrap();
        let path = dump["path"].as_str().unwrap();
        let recorded = record(&store, &json!({"artifacts": [path], "tags": ["boot"],
            "modules": [{"name": "eboot.bin", "sha256": "a".repeat(64)}],
            "notes": ["Entry looks packed"],
            "findings": [{"title": "Anti-debug", "text": "checks ptrace", "address": "0x401000"}],
            "questions": [{"text": "What decrypts the save?"}]})).unwrap();
        assert_eq!(recorded["recorded"], 5);
        let dup = record(&store, &json!({"artifacts": [path]})).unwrap();
        assert_eq!(dup["already_recorded"][0], path);
        assert!(record(&store, &json!({"artifacts": ["missing.bin"]})).is_err());

        let page = query(&store, &json!({"type": "artifact"})).unwrap();
        assert_eq!(page["total"], 1);
        assert_eq!(page["items"][0]["kind"], "elfdump");
        assert_eq!(page["items"][0]["module"], "eboot.bin");
        assert_eq!(page["items"][0]["pid"], 71);
        assert_eq!(page["items"][0]["address"], "0x400000");
        assert_eq!(query(&store, &json!({"tag": "boot"})).unwrap()["total"], 5);
        assert_eq!(query(&store, &json!({"module_sha256": "A".repeat(64)})).unwrap()["total"], 2);
        assert_eq!(query(&store, &json!({"text": "PTRACE"})).unwrap()["total"], 1);
        assert_eq!(query(&store, &json!({"until": "2000-01-01"})).unwrap()["total"], 0);
        let paged = query(&store, &json!({"limit": 2})).unwrap();
        assert_eq!(paged["count"], 2);
        assert_eq!(paged["next_offset"], 2);

        let question = query(&store, &json!({"type": "question"})).unwrap()["items"][0]["id"].clone();
        let sum = summary(&store, &json!({})).unwrap();
        assert_eq!(sum["dumps"]["count"], 1);
        assert_eq!(sum["open_questions"]["count"], 1);
        assert_eq!(sum["modules"].as_array().unwrap().len(), 1);
        record(&store, &json!({"resolve_questions": [question], "resolution": "AES in sub_1234"})).unwrap();
        assert_eq!(summary(&store, &json!({})).unwrap()["open_questions"]["count"], 0);
        assert!(record(&store, &json!({"resolve_questions": ["r-nope"]})).is_err());
    }

    #[test]
    fn auto_record_is_noop_without_project_and_dedupes() {
        let (_dir, store) = store();
        let saved = store.save("coverage", b"{}", json!({"tool": "debug_coverage"}), "json").unwrap();
        let result = json!({"artifact": saved, "blocks": 3});
        assert_eq!(auto_record(&store, "debug_coverage", &json!({"pid": 9}), &result).unwrap(), 0);
        open(&store, &json!({"name": "Test Game"})).unwrap();
        assert_eq!(auto_record(&store, "debug_coverage", &json!({"pid": 9}), &result).unwrap(), 1);
        assert_eq!(auto_record(&store, "debug_coverage", &json!({"pid": 9}), &result).unwrap(), 0);
        assert_eq!(auto_record(&store, "artifact_info", &json!({}), &result).unwrap(), 0);
        assert_eq!(auto_record(&store, "console_status", &json!({}), &json!({"ok": true})).unwrap(), 0);
        let page = query(&store, &json!({"kind": "coverage"})).unwrap();
        assert_eq!(page["items"][0]["tool"], "debug_coverage");
        assert_eq!(page["items"][0]["pid"], 9);
        assert_eq!(summary(&store, &json!({})).unwrap()["coverage"]["count"], 1);
    }

    #[test]
    fn project_ids_are_contained() {
        assert!(project_id(&json!({"project": "../evil"})).is_err());
        assert_eq!(project_id(&json!({"name": "a/b\\c"})).unwrap(), "a_b_c");
        assert!(project_id(&json!({})).is_err());
        assert_eq!(artifact_kind("elfdump-0123456789abcdef0123456789abcdef.elf"), "elfdump");
        assert_eq!(artifact_kind("custom.bin"), "file");
    }

    #[test]
    fn export_offsets_generates_header_and_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let workbench = crate::workbench::Workbench::new(test_profile(directory.path())).unwrap();
        let store = &workbench.store;
        open(store, &json!({"title_id": "CUSA12345", "name": "Test Game"})).unwrap();
        let sha = "a".repeat(64);
        let mut dump = vec![0u8; 0x200];
        dump[0x100..0x107].copy_from_slice(&[0x48, 0x8b, 0x05, 0x11, 0x22, 0x33, 0x44]);
        let dump_art = store.save("elfdump", &dump, json!({"module": "eboot.bin", "module_sha256": sha}), "elf").unwrap();
        let ann = store.save("annotation", &serde_json::to_vec(&json!({
            "artifact": "evidence.bin", "artifact_sha256": "b".repeat(64), "module_sha256": sha,
            "rva": "0x100", "comment": "entity list", "symbol": "EntityList"
        })).unwrap(), json!({}), "json").unwrap();
        record(store, &json!({
            "artifacts": [dump_art["path"].as_str().unwrap(), ann["path"].as_str().unwrap()],
            "module_sha256": sha,
            "modules": [{"name": "eboot.bin", "sha256": sha}],
        })).unwrap();

        let out = export_offsets(&workbench, &json!({"verify_bytes": 7})).unwrap();
        assert_eq!(out["format"], OFFSETS_FORMAT);
        assert_eq!(out["offsets"], 1);
        assert_eq!(out["namespace"], "test_game");
        let hpp = String::from_utf8(workbench.read_artifact(out["header"]["path"].as_str().unwrap(), 1 << 20).unwrap()).unwrap();
        assert!(hpp.contains("namespace test_game"), "{hpp}");
        assert!(hpp.contains("namespace eboot_bin"), "{hpp}");
        assert!(hpp.contains("inline constexpr std::uintptr_t EntityList = 0x100; // entity list"), "{hpp}");
        assert!(hpp.contains("{ 0x100, 7, { 0x48, 0x8b, 0x05, 0x11, 0x22, 0x33, 0x44 } },"), "{hpp}");
        let doc: Value = serde_json::from_slice(&workbench.read_artifact(out["manifest"]["path"].as_str().unwrap(), 1 << 20).unwrap()).unwrap();
        assert_eq!(doc["format"], OFFSETS_FORMAT);
        assert_eq!(doc["modules"][0]["module"], "eboot.bin");
        assert_eq!(doc["modules"][0]["offsets"][0]["symbol"], "EntityList");
        assert_eq!(doc["modules"][0]["offsets"][0]["verify"]["hex"], "488b0511223344");

        let none = export_offsets(&workbench, &json!({"module_sha256": "c".repeat(64)})).unwrap();
        assert_eq!(none["offsets"], 0);
        assert_eq!(none["modules"], 0);
        let other_dir = tempfile::tempdir().unwrap();
        let other = crate::workbench::Workbench::new(test_profile(other_dir.path())).unwrap();
        assert!(export_offsets(&other, &json!({})).unwrap_err().to_string().contains("No active project"));
    }

    #[test]
    fn export_target_builds_stage_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let workbench = crate::workbench::Workbench::new(test_profile(directory.path())).unwrap();
        let store = &workbench.store;
        open(store, &json!({"title_id": "CUSA12345", "app_version": "01.02", "name": "Test Game"})).unwrap();
        let sha = "a".repeat(64);
        let mut dump = vec![0u8; 0x200];
        dump[0x100..0x104].copy_from_slice(&[0x48, 0x8b, 0x05, 0x11]);
        dump[0x140..0x144].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let dump_art = store.save("elfdump", &dump, json!({"module": "eboot.bin", "module_sha256": sha}), "elf").unwrap();
        let ann = store.save("annotation", &serde_json::to_vec(&json!({
            "artifact": "evidence.bin", "artifact_sha256": "b".repeat(64), "module_sha256": sha,
            "rva": "0x100", "comment": "entity list", "symbol": "EntityList"
        })).unwrap(), json!({}), "json").unwrap();
        record(store, &json!({
            "artifacts": [dump_art["path"].as_str().unwrap(), ann["path"].as_str().unwrap()],
            "module_sha256": sha,
            "modules": [{"name": "eboot.bin", "sha256": sha, "base": "0x400000", "path": "/app0/eboot.bin"}],
        })).unwrap();

        let out = export_target(&workbench, &json!({
            "verify_bytes": 4, "signature_sites": ["0x140"],
            "pointers": [{"address": "0x400010", "expected": "0x400000"}],
        })).unwrap();
        assert_eq!(out["format"], TARGET_FORMAT);
        assert_eq!(out["module"], "eboot.bin");
        assert_eq!(out["image_base"], "0x400000");
        assert_eq!(out["fingerprints"], 2);
        assert_eq!(out["pointers"], 1);
        let doc: Value = serde_json::from_slice(&workbench.read_artifact(out["target"]["path"].as_str().unwrap(), 1 << 20).unwrap()).unwrap();
        assert_eq!(doc["format"], TARGET_FORMAT);
        assert_eq!(doc["title_id"], "CUSA12345");
        assert_eq!(doc["process_name"], "eboot.bin");
        assert_eq!(doc["process_path"], "/app0/eboot.bin");
        assert_eq!(doc["application_version"], "01.02");
        assert_eq!(doc["executable_text_sha256"], sha);
        assert_eq!(doc["status_magic"], "0x5053494e");
        assert_eq!(doc["fingerprints"][0]["address"], "0x400100");
        assert_eq!(doc["fingerprints"][0]["hex"], "488b0511");
        assert_eq!(doc["fingerprints"][1]["address"], "0x400140");
        assert_eq!(doc["fingerprints"][1]["hex"], "deadbeef");
        assert_eq!(doc["pointers"][0]["expected"], "0x400000");
    }
}
