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
use anyhow::{Context, anyhow, bail};
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
}
