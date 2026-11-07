//! Recipes: bounded, declarative chains of tool calls.
//!
//! A recipe is `{"format":"ps4wb-recipe-v1","name","description","inputs":{name:{"type","required","default","description"}},
//! "steps":[{"tool","arguments","note"?}]}`. String values in step arguments
//! may reference `${input}`, `${inputs.input}` or `${steps.N.json.path}` (object
//! keys / array indices separated by `.`); `${steps.N.@artifact}` is the first
//! artifact path (object with `path` + `sha256`) found in step N's result. A
//! string that is exactly one `${...}` keeps the referenced JSON type; an
//! exactly-`${...}` value referencing an absent optional input removes the
//! argument. Every step runs through `ToolRegistry::call`, so schema,
//! permission and qualification checks apply; recipes cannot nest.
use crate::artifacts::utc_now;
use crate::{Result, tools::ToolRegistry};
use anyhow::{Context, anyhow, bail};
use serde_json::{Map, Value, json};

pub const MAX_STEPS: usize = 32;
const MAX_RECIPE_BYTES: usize = 256 * 1024;
const MAX_SUMMARY_TEXT: usize = 512;
pub const FORMAT: &str = "ps4wb-recipe-v1";

/// Tools referenced by built-in recipes that other feature areas are adding;
/// delete at merge once they are all in `full_catalog()`.
pub const PLANNED_TOOLS: &[&str] = &[];

pub const BUILTIN_RECIPES: &str = r#"[
 {"format": "ps4wb-recipe-v1", "name": "dump_and_rebuild",
  "description": "Dump a loaded module from memory, rebuild a loadable ELF and enumerate its functions.",
  "inputs": {"pid": {"type": "integer", "required": true, "description": "Target process id"},
             "module": {"type": "string", "description": "Module name; defaults to eboot.bin"}},
  "steps": [
   {"tool": "memory_elf_dump", "arguments": {"pid": "${pid}", "module": "${module}"}},
   {"tool": "elf_rebuild", "arguments": {"artifact": "${steps.0.artifact.path}"}},
   {"tool": "artifact_functions", "arguments": {"artifact": "${steps.1.artifact.path}"}}
  ]},
 {"format": "ps4wb-recipe-v1", "name": "static_triage",
  "description": "Offline triage of a module artifact: functions, RTTI classes, crypto constants and Orbis import prototypes.",
  "inputs": {"artifact": {"type": "string", "required": true, "description": "ELF/SELF-decrypted module artifact path"}},
  "steps": [
   {"tool": "artifact_functions", "arguments": {"artifact": "${artifact}"}},
   {"tool": "rtti_recover", "arguments": {"artifact": "${artifact}"}},
   {"tool": "crypto_scan", "arguments": {"artifact": "${artifact}"}},
   {"tool": "orbis_prototypes", "arguments": {"action": "imports", "artifact": "${artifact}", "use_sdk": true}}
  ]},
 {"format": "ps4wb-recipe-v1", "name": "update_port",
  "description": "Diff two builds of a module and port annotations from the old build to the new one.",
  "inputs": {"old_artifact": {"type": "string", "required": true, "description": "Previously annotated build"},
             "new_artifact": {"type": "string", "required": true, "description": "Updated build"},
             "annotations": {"type": "string", "required": true, "description": "Annotation artifact (annotation_save evidence, ported set or {rva: name} JSON) for the old build"}},
  "steps": [
   {"tool": "binary_diff", "arguments": {"artifact_a": "${old_artifact}", "artifact_b": "${new_artifact}"}},
   {"tool": "annotation_port", "arguments": {"diff": "${steps.0.artifact}", "sources": ["${annotations}"], "artifact_a": "${old_artifact}", "artifact_b": "${new_artifact}"}}
  ]},
 {"format": "ps4wb-recipe-v1", "name": "crash_capture",
  "description": "Run the attached process until it faults, triage the crash, then save a core dump.",
  "inputs": {"pid": {"type": "integer", "required": true, "description": "Attached target process id"}},
  "steps": [
   {"tool": "debug_crash_triage", "arguments": {"wait": true}},
   {"tool": "process_core_dump", "arguments": {"pid": "${pid}"}}
  ]},
 {"format": "ps4wb-recipe-v1", "name": "coverage_compare",
  "description": "Record block coverage for the attached process and diff it against a baseline coverage artifact.",
  "inputs": {"module": {"type": "string", "description": "Module to cover in the attached process; defaults to eboot.bin"},
             "baseline": {"type": "string", "required": true, "description": "Baseline coverage artifact"}},
  "steps": [
   {"tool": "debug_coverage", "arguments": {"module": "${module}"}},
   {"tool": "coverage_diff", "arguments": {"a": "${baseline}", "b": "${steps.0.coverage_artifact.path}"}}
  ]},
 {"format": "ps4wb-recipe-v1", "name": "offset_refresh",
  "description": "After a game update: dump the new build, rebuild its ELF, diff against the previous annotated build, port annotations, and regenerate the offsets header/manifest.",
  "inputs": {"pid": {"type": "integer", "required": true, "description": "Target process id"},
             "module": {"type": "string", "description": "Module name; defaults to eboot.bin"},
             "old_artifact": {"type": "string", "required": true, "description": "Previously annotated build artifact"},
             "annotations": {"type": "string", "required": true, "description": "Annotation artifact for the old build"},
             "module_sha256": {"type": "string", "description": "Restrict the offsets export to one module hash"},
             "namespace": {"type": "string", "description": "C++ namespace for the generated header"}},
  "steps": [
   {"tool": "memory_elf_dump", "arguments": {"pid": "${pid}", "module": "${module}"}},
   {"tool": "elf_rebuild", "arguments": {"artifact": "${steps.0.artifact.path}"}},
   {"tool": "binary_diff", "arguments": {"artifact_a": "${old_artifact}", "artifact_b": "${steps.1.artifact.path}"}},
   {"tool": "annotation_port", "arguments": {"diff": "${steps.2.artifact}", "sources": ["${annotations}"], "artifact_a": "${old_artifact}", "artifact_b": "${steps.1.artifact.path}"}},
   {"tool": "project_export_offsets", "arguments": {"module_sha256": "${module_sha256}", "namespace": "${namespace}"}}
  ]},
 {"format": "ps4wb-recipe-v1", "name": "stage_and_verify",
  "description": "Stage a hash-qualified resident payload, read its lifecycle status, then set the feature bitmask.",
  "inputs": {"pid": {"type": "integer", "required": true, "description": "Target process id"},
             "target": {"type": "string", "required": true, "description": "ps4wb-internals-target-v1 artifact (project_export_target)"},
             "payload": {"type": "string", "required": true, "description": "Resident payload ELF artifact"},
             "sha256": {"type": "string", "required": true, "description": "Expected payload SHA-256"},
             "features": {"type": "string", "default": "0x0", "description": "Feature bitmask for RPC command 1"}},
  "steps": [
   {"tool": "payload_stage", "arguments": {"pid": "${pid}", "target": "${target}", "payload": "${payload}", "sha256": "${sha256}"}},
   {"tool": "payload_status", "arguments": {"pid": "${pid}"}},
   {"tool": "payload_rpc", "arguments": {"pid": "${pid}", "command": 1, "argument": "${features}"}}
  ]},
 {"format": "ps4wb-recipe-v1", "name": "payload_crash_bundle",
  "description": "Triage a fault of the attached process, capture Klog, and archive both into one experiment bundle for payload_recover analysis.",
  "inputs": {"pid": {"type": "integer", "required": true, "description": "Attached target process id"},
             "seconds": {"type": "integer", "default": 5, "description": "Klog capture duration"},
             "notes": {"type": "string", "description": "Notes stored in the bundle"}},
  "steps": [
   {"tool": "debug_crash_triage", "arguments": {"wait": true}},
   {"tool": "klog_capture", "arguments": {"seconds": "${seconds}"}},
   {"tool": "experiment_bundle", "arguments": {"paths": ["${steps.0.@artifact}", "${steps.1.@artifact}"], "notes": "${notes}"}}
  ]},
 {"format": "ps4wb-recipe-v1", "name": "deep_dump",
  "description": "Full module RE dump: in-memory ELF dump, rebuilt ELF with sections/NID names, function discovery, RTTI classes and Orbis import prototypes in one pass.",
  "inputs": {"pid": {"type": "integer", "required": true, "description": "Target process id"},
             "module": {"type": "string", "description": "Module name; defaults to eboot.bin"}},
  "steps": [
   {"tool": "memory_elf_dump", "arguments": {"pid": "${pid}", "module": "${module}"}},
   {"tool": "elf_rebuild", "arguments": {"artifact": "${steps.0.artifact.path}"}},
   {"tool": "artifact_functions", "arguments": {"artifact": "${steps.1.artifact.path}"}},
   {"tool": "rtti_recover", "arguments": {"artifact": "${steps.1.artifact.path}"}},
   {"tool": "orbis_prototypes", "arguments": {"action": "imports", "artifact": "${steps.1.artifact.path}", "use_sdk": true}}
  ]},
 {"format": "ps4wb-recipe-v1", "name": "unreal_pipeline",
  "description": "UE4 game (e.g. Fortnite): dump the loaded module, rebuild the ELF, recover GNames/GObjects, export the ue4::Offsets SDK header, then regenerate offsets and a stage-ready target manifest.",
  "inputs": {"pid": {"type": "integer", "required": true, "description": "Target process id"},
             "module": {"type": "string", "description": "Module name; defaults to eboot.bin"},
             "module_sha256": {"type": "string", "description": "Restrict exports to one module hash"},
             "namespace": {"type": "string", "description": "C++ namespace for generated headers"},
             "image_base": {"type": "string", "description": "Runtime module base for the target manifest"},
             "signature_sites": {"type": "array", "description": "Optional RVAs verified unique by signature_make"}},
  "steps": [
   {"tool": "memory_elf_dump", "arguments": {"pid": "${pid}", "module": "${module}"}},
   {"tool": "elf_rebuild", "arguments": {"artifact": "${steps.0.artifact.path}"}},
   {"tool": "unreal_dump", "arguments": {"artifact": "${steps.1.artifact.path}", "sdk": true}},
   {"tool": "engine_sdk_export", "arguments": {"unreal": "${steps.2.json.path}", "namespace": "${namespace}"}},
   {"tool": "project_export_offsets", "arguments": {"module_sha256": "${module_sha256}", "namespace": "${namespace}"}},
   {"tool": "project_export_target", "arguments": {"module_sha256": "${module_sha256}", "image_base": "${image_base}", "signature_sites": "${signature_sites}"}}
  ]},
 {"format": "ps4wb-recipe-v1", "name": "source_pipeline",
  "description": "Source/Respawn game (e.g. Apex Legends): dump the loaded module, rebuild the ELF, recover netvars/datamaps, export the netvar SDK header, then regenerate offsets and a stage-ready target manifest.",
  "inputs": {"pid": {"type": "integer", "required": true, "description": "Target process id"},
             "module": {"type": "string", "description": "Module name; defaults to eboot.bin"},
             "module_sha256": {"type": "string", "description": "Restrict exports to one module hash"},
             "namespace": {"type": "string", "description": "C++ namespace for generated headers"},
             "image_base": {"type": "string", "description": "Runtime module base for the target manifest"},
             "signature_sites": {"type": "array", "description": "Optional RVAs verified unique by signature_make"}},
  "steps": [
   {"tool": "memory_elf_dump", "arguments": {"pid": "${pid}", "module": "${module}"}},
   {"tool": "elf_rebuild", "arguments": {"artifact": "${steps.0.artifact.path}"}},
   {"tool": "source_dump", "arguments": {"artifact": "${steps.1.artifact.path}"}},
   {"tool": "engine_sdk_export", "arguments": {"source": "${steps.2.artifact.path}", "namespace": "${namespace}"}},
   {"tool": "project_export_offsets", "arguments": {"module_sha256": "${module_sha256}", "namespace": "${namespace}"}},
   {"tool": "project_export_target", "arguments": {"module_sha256": "${module_sha256}", "image_base": "${image_base}", "signature_sites": "${signature_sites}"}}
  ]}
]"#;

pub fn builtins() -> Result<Vec<Value>> {
    Ok(serde_json::from_str(BUILTIN_RECIPES)?)
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Structural validation of a recipe definition.
pub fn validate(recipe: &Value) -> Result<()> {
    let fields = recipe.as_object().context("Recipe must be a JSON object")?;
    if fields.get("format").and_then(Value::as_str) != Some(FORMAT) {
        bail!("Recipe format must be {FORMAT}");
    }
    for key in fields.keys() {
        if !matches!(key.as_str(), "format" | "name" | "description" | "inputs" | "steps") {
            bail!("Unknown recipe field: {key}");
        }
    }
    let name = fields.get("name").and_then(Value::as_str).unwrap_or("");
    if !is_identifier(name) {
        bail!("Recipe name must be 1-64 alphanumeric/underscore characters");
    }
    if let Some(inputs) = fields.get("inputs") {
        let inputs = inputs.as_object().context("Recipe inputs must be an object")?;
        if inputs.len() > 32 {
            bail!("Recipe declares too many inputs");
        }
        for (input, spec) in inputs {
            if !is_identifier(input) || input == "steps" || input == "inputs" {
                bail!("Invalid recipe input name: {input}");
            }
            if !spec.is_object() {
                bail!("Recipe input {input} must be an object");
            }
        }
    }
    let steps = fields.get("steps").and_then(Value::as_array).context("Recipe needs steps")?;
    if steps.is_empty() || steps.len() > MAX_STEPS {
        bail!("Recipe needs 1 to {MAX_STEPS} steps");
    }
    for (index, step) in steps.iter().enumerate() {
        let step = step.as_object().with_context(|| format!("Step {index} must be an object"))?;
        for key in step.keys() {
            if !matches!(key.as_str(), "tool" | "arguments" | "note") {
                bail!("Unknown field in step {index}: {key}");
            }
        }
        let tool = step.get("tool").and_then(Value::as_str).unwrap_or("");
        if !is_identifier(tool) {
            bail!("Step {index} needs a tool name");
        }
        if tool.starts_with("recipe_") {
            bail!("Recipes cannot nest recipe tools");
        }
        if step.get("arguments").is_some_and(|a| !a.is_object()) {
            bail!("Step {index} arguments must be an object");
        }
    }
    Ok(())
}

/// Recipe selected by `recipe` (built-in name), `recipe_artifact` (JSON artifact) or inline `definition`.
pub fn resolve(registry: &ToolRegistry, args: &Value) -> Result<Value> {
    let sources = ["recipe", "recipe_artifact", "definition"].iter().filter(|k| args.get(**k).is_some()).count();
    if sources != 1 {
        bail!("Supply exactly one of recipe, recipe_artifact or definition");
    }
    let recipe = if let Some(name) = args["recipe"].as_str() {
        builtins()?
            .into_iter()
            .find(|r| r["name"] == name)
            .with_context(|| format!("Unknown built-in recipe: {name}; see recipe_list"))?
    } else if let Some(path) = args["recipe_artifact"].as_str() {
        let content = registry.workbench.store.read_bounded(path, MAX_RECIPE_BYTES)?;
        serde_json::from_slice(&content).map_err(|e| anyhow!("Recipe artifact is not JSON: {e}"))?
    } else {
        args["definition"].clone()
    };
    validate(&recipe)?;
    Ok(recipe)
}

/// Tool names a `recipe_run` call would invoke (for lease/policy checks before running).
pub fn referenced_tools(registry: &ToolRegistry, args: &Value) -> Result<Vec<String>> {
    let recipe = resolve(registry, args)?;
    Ok(recipe["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["tool"].as_str().map(str::to_owned))
        .collect())
}

pub fn list(registry: &ToolRegistry) -> Result<Value> {
    let available: Vec<String> = registry
        .available()
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect();
    let recipes: Vec<Value> = builtins()?
        .into_iter()
        .map(|recipe| {
            let steps: Vec<Value> = recipe["steps"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|s| {
                    let tool = s["tool"].as_str().unwrap_or("");
                    json!({"tool": tool, "available": available.iter().any(|a| a == tool)})
                })
                .collect();
            let runnable = steps.iter().all(|s| s["available"] == true);
            json!({"name": recipe["name"], "description": recipe["description"], "inputs": recipe["inputs"],
                "steps": steps, "runnable": runnable})
        })
        .collect();
    Ok(json!({"format": FORMAT, "recipes": recipes, "max_steps": MAX_STEPS,
        "note": "recipe_run also accepts recipe_artifact (JSON artifact path) or an inline definition; every step is policy-checked like a direct call"}))
}

fn first_artifact(value: &Value, depth: usize) -> Option<&str> {
    if depth > 6 {
        return None;
    }
    match value {
        Value::Object(fields) => {
            if let (Some(path), Some(sha)) = (fields.get("path").and_then(Value::as_str), fields.get("sha256").and_then(Value::as_str))
                && sha.len() == 64
            {
                return Some(path);
            }
            for key in ["artifact", "result_saved", "output"] {
                if let Some(found) = fields.get(key).and_then(|v| first_artifact(v, depth + 1)) {
                    return Some(found);
                }
            }
            fields.values().find_map(|v| first_artifact(v, depth + 1))
        }
        Value::Array(items) => items.iter().take(64).find_map(|v| first_artifact(v, depth + 1)),
        _ => None,
    }
}

enum Lookup {
    Found(Value),
    AbsentOptional,
}

fn lookup(reference: &str, inputs: &Map<String, Value>, results: &[Value]) -> Result<Lookup> {
    let mut parts = reference.split('.');
    let head = parts.next().unwrap_or("");
    if head == "steps" {
        let index: usize = parts
            .next()
            .and_then(|i| i.parse().ok())
            .with_context(|| format!("Bad step reference: ${{{reference}}}"))?;
        let mut current = results
            .get(index)
            .with_context(|| format!("${{{reference}}} refers to a step that has not run"))?;
        for part in parts {
            if part == "@artifact" {
                let path = first_artifact(current, 0).with_context(|| format!("No artifact in result for ${{{reference}}}"))?;
                return Ok(Lookup::Found(json!(path)));
            }
            current = match current {
                Value::Array(items) => part.parse::<usize>().ok().and_then(|i| items.get(i)),
                Value::Object(fields) => fields.get(part),
                _ => None,
            }
            .with_context(|| format!("${{{reference}}} not found in step result"))?;
        }
        return Ok(Lookup::Found(current.clone()));
    }
    let name = if head == "inputs" { parts.next().unwrap_or("") } else { head };
    if parts.next().is_some() {
        bail!("Input references cannot have a path: ${{{reference}}}");
    }
    match inputs.get(name) {
        Some(Value::Null) | None => Ok(Lookup::AbsentOptional),
        Some(value) => Ok(Lookup::Found(value.clone())),
    }
}

fn substitute(value: &Value, inputs: &Map<String, Value>, results: &[Value]) -> Result<Option<Value>> {
    Ok(Some(match value {
        Value::String(text) => {
            if let Some(inner) = text.strip_prefix("${").and_then(|t| t.strip_suffix('}'))
                && !inner.contains("${")
            {
                return match lookup(inner, inputs, results)? {
                    Lookup::Found(found) => Ok(Some(found)),
                    Lookup::AbsentOptional => Ok(None),
                };
            }
            let mut out = String::new();
            let mut rest = text.as_str();
            while let Some(start) = rest.find("${") {
                out.push_str(&rest[..start]);
                let end = rest[start..].find('}').with_context(|| format!("Unterminated reference in {text:?}"))?;
                let reference = &rest[start + 2..start + end];
                match lookup(reference, inputs, results)? {
                    Lookup::Found(Value::String(s)) => out.push_str(&s),
                    Lookup::Found(other) => out.push_str(&other.to_string()),
                    Lookup::AbsentOptional => bail!("Missing input for ${{{reference}}}"),
                }
                rest = &rest[start + end + 1..];
            }
            out.push_str(rest);
            Value::String(out)
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                if let Some(v) = substitute(item, inputs, results)? {
                    out.push(v);
                }
            }
            Value::Array(out)
        }
        Value::Object(fields) => {
            let mut out = Map::new();
            for (key, item) in fields {
                if let Some(v) = substitute(item, inputs, results)? {
                    out.insert(key.clone(), v);
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    }))
}

fn bind_inputs(recipe: &Value, supplied: &Value) -> Result<Map<String, Value>> {
    let supplied = match supplied {
        Value::Null => Map::new(),
        Value::Object(fields) => fields.clone(),
        _ => bail!("inputs must be an object"),
    };
    let declared = recipe["inputs"].as_object().cloned().unwrap_or_default();
    for key in supplied.keys() {
        if !declared.contains_key(key) {
            bail!("Unknown recipe input: {key}");
        }
    }
    let mut bound = Map::new();
    for (name, spec) in &declared {
        let value = supplied.get(name).cloned().or_else(|| spec.get("default").cloned());
        match value {
            Some(value) => {
                let ok = match spec["type"].as_str() {
                    Some("integer") => value.is_i64() || value.is_u64(),
                    Some("string") => value.is_string(),
                    Some("boolean") => value.is_boolean(),
                    Some("number") => value.is_number(),
                    Some("array") => value.is_array(),
                    Some("object") => value.is_object(),
                    _ => true,
                };
                if !ok {
                    bail!("Recipe input {name} must be {}", spec["type"]);
                }
                bound.insert(name.clone(), value);
            }
            None if spec["required"] == true => bail!("Missing required recipe input: {name}"),
            None => {}
        }
    }
    Ok(bound)
}

fn clip(text: &str) -> Value {
    if text.chars().count() > MAX_SUMMARY_TEXT {
        json!(format!("{}...", text.chars().take(MAX_SUMMARY_TEXT).collect::<String>()))
    } else {
        json!(text)
    }
}

/// Compact per-step summary: scalars, array lengths, key names and artifact paths.
pub fn summarize(result: &Value) -> Value {
    match result {
        Value::Object(fields) => {
            let mut out = Map::new();
            for (key, value) in fields.iter().take(32) {
                let compacted = match value {
                    Value::String(s) => clip(s),
                    Value::Array(items) => json!({"items": items.len()}),
                    Value::Object(inner) => match (inner.get("path"), inner.get("sha256")) {
                        (Some(path), Some(sha)) => json!({"path": path, "sha256": sha}),
                        _ => json!({"keys": inner.keys().take(16).collect::<Vec<_>>()}),
                    },
                    other => other.clone(),
                };
                out.insert(key.clone(), compacted);
            }
            Value::Object(out)
        }
        Value::Array(items) => json!({"items": items.len()}),
        Value::String(s) => clip(s),
        other => other.clone(),
    }
}

pub fn run(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let recipe = resolve(registry, args)?;
    let inputs = bind_inputs(&recipe, &args["inputs"])?;
    let steps = recipe["steps"].as_array().cloned().unwrap_or_default();
    let limit = args["max_steps"].as_u64().map_or(MAX_STEPS, |m| m as usize).min(MAX_STEPS);
    if steps.len() > limit {
        bail!("Recipe has {} steps; max_steps is {limit}", steps.len());
    }
    let dry_run = args["dry_run"] == true;
    let name = recipe["name"].as_str().unwrap_or("recipe").to_owned();
    let mut results: Vec<Value> = Vec::new();
    let mut reports = Vec::new();
    let mut artifacts = Vec::new();
    let mut failure = Value::Null;
    for (index, step) in steps.iter().enumerate() {
        let tool = step["tool"].as_str().unwrap_or_default().to_owned();
        let template = step.get("arguments").cloned().unwrap_or_else(|| json!({}));
        let arguments = match substitute(&template, &inputs, &results) {
            Ok(Some(arguments)) => arguments,
            Ok(None) => json!({}),
            Err(error) => {
                if dry_run {
                    reports.push(json!({"index": index, "tool": tool, "planned": true, "pending_references": error.to_string()}));
                    results.push(Value::Null);
                    continue;
                }
                failure = json!({"index": index, "tool": tool, "error": error.to_string()});
                reports.push(json!({"index": index, "tool": tool, "ok": false, "error": error.to_string()}));
                break;
            }
        };
        if dry_run {
            let known = registry.available().iter().any(|t| t["name"] == tool.as_str());
            reports.push(json!({"index": index, "tool": tool, "planned": true, "arguments": arguments, "available": known}));
            results.push(Value::Null);
            continue;
        }
        match registry.call(&tool, arguments.clone()) {
            Ok(result) => {
                if let Some(path) = first_artifact(&result, 0) {
                    artifacts.push(json!({"step": index, "tool": tool, "path": path}));
                }
                reports.push(json!({"index": index, "tool": tool, "ok": true, "arguments": arguments, "summary": summarize(&result)}));
                results.push(result);
            }
            Err(error) => {
                failure = json!({"index": index, "tool": tool, "error": error.to_string()});
                reports.push(json!({"index": index, "tool": tool, "ok": false, "arguments": arguments, "error": error.to_string()}));
                break;
            }
        }
    }
    let completed = failure.is_null();
    let mut outcome = json!({
        "recipe": name,
        "dry_run": dry_run,
        "completed": completed,
        "steps_total": steps.len(),
        "steps_run": if dry_run { 0 } else { results.len() },
        "steps": reports,
        "artifacts": artifacts,
        "failure": failure,
    });
    if !dry_run && !results.is_empty() {
        let log = json!({"recipe": recipe, "inputs": inputs, "time": utc_now(), "steps": outcome["steps"], "results": results});
        let encoded = serde_json::to_vec(&log)?;
        if encoded.len() <= registry.workbench.profile.limit("transfer_bytes") {
            let saved = registry.workbench.store.save("recipe-run", &encoded, json!({"tool": "recipe_run", "recipe": name, "completed": completed}), "json")?;
            outcome["run_log"] = json!(saved["path"]);
        }
        registry.workbench.store.audit("recipe_run", json!({"recipe": name, "completed": completed, "steps_run": results.len()}))?;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;
    use crate::workbench::Workbench;

    fn registry(directory: &std::path::Path) -> ToolRegistry {
        let mut data: Value = serde_json::from_str(include_str!("../profiles/ps4-1400.json")).unwrap();
        data["host"] = json!("127.0.0.1");
        data["artifact_directory"] = json!("artifacts");
        data["qualification_file"] = json!("qualification.json");
        let path = directory.join("profile.json");
        std::fs::write(&path, data.to_string()).unwrap();
        ToolRegistry::with_toolset(
            Workbench::new(Profile::load(path).unwrap()).unwrap(),
            crate::tools::Toolset::Full,
        )
        .unwrap()
    }

    #[test]
    fn builtin_recipes_name_known_or_planned_tools() {
        let catalog = crate::extensions::full_catalog().unwrap();
        let expected = [
            "memory_elf_dump", "elf_rebuild", "process_dump", "process_core_dump", "artifact_functions",
            "artifact_cfg", "orbis_prototypes", "rtti_recover", "il2cpp_dump", "crypto_scan", "yara_scan",
            "debug_coverage", "coverage_diff", "debug_crash_triage", "memory_pointer_scan", "binary_diff",
            "annotation_port", "signature_make",
        ];
        for planned in PLANNED_TOOLS {
            assert!(expected.contains(planned), "{planned} is not one of the agreed tool names");
        }
        for recipe in builtins().unwrap() {
            validate(&recipe).unwrap();
            for step in recipe["steps"].as_array().unwrap() {
                let tool = step["tool"].as_str().unwrap();
                let schema = catalog.iter().find(|t| t["name"] == tool);
                assert!(schema.is_some() || PLANNED_TOOLS.contains(&tool), "{tool} is neither cataloged nor planned");
                if let Some(schema) = schema {
                    let arguments = step["arguments"].as_object().unwrap();
                    for key in arguments.keys() {
                        assert!(schema["inputSchema"]["properties"].get(key).is_some(), "{tool} has no argument {key}");
                    }
                    for required in schema["inputSchema"]["required"].as_array().into_iter().flatten() {
                        let required = required.as_str().unwrap();
                        assert!(arguments.contains_key(required), "{tool} step lacks required argument {required}");
                    }
                }
            }
        }
    }

    #[test]
    fn substitution_types_paths_and_optional_inputs() {
        let inputs: Map<String, Value> = serde_json::from_value(json!({"pid": 71, "name": "eboot"})).unwrap();
        let results = vec![json!({"artifact": {"path": "elfdump-x.elf", "sha256": "a".repeat(64)}, "list": [{"v": 5}]})];
        let template = json!({"pid": "${pid}", "module": "${module}", "label": "m_${inputs.name}_${steps.0.list.0.v}",
            "artifact": "${steps.0.@artifact}", "direct": "${steps.0.artifact.path}"});
        let out = substitute(&template, &inputs, &results).unwrap().unwrap();
        assert_eq!(out, json!({"pid": 71, "label": "m_eboot_5", "artifact": "elfdump-x.elf", "direct": "elfdump-x.elf"}));
        assert!(substitute(&json!("${steps.3.x}"), &inputs, &results).is_err());
        assert!(substitute(&json!("x${missing}"), &inputs, &results).is_err());
        assert!(substitute(&json!("${steps.0.nope}"), &inputs, &results).is_err());
    }

    #[test]
    fn validation_rejects_nesting_and_unbounded_recipes() {
        let step = json!({"tool": "nid_resolve", "arguments": {}});
        let ok = json!({"format": FORMAT, "name": "x", "steps": [step]});
        validate(&ok).unwrap();
        let mut nested = ok.clone();
        nested["steps"] = json!([{"tool": "recipe_run"}]);
        assert!(validate(&nested).is_err());
        let mut long = ok.clone();
        long["steps"] = Value::Array(vec![step; MAX_STEPS + 1]);
        assert!(validate(&long).is_err());
        let mut odd = ok.clone();
        odd["extra"] = json!(1);
        assert!(validate(&odd).is_err());
        assert!(bind_inputs(&json!({"inputs": {"pid": {"type": "integer", "required": true}}}), &json!({})).is_err());
        assert!(bind_inputs(&json!({"inputs": {"pid": {"type": "integer"}}}), &json!({"pid": "x"})).is_err());
        assert!(bind_inputs(&json!({"inputs": {}}), &json!({"other": 1})).is_err());
    }

    #[test]
    fn run_chains_steps_through_policy_and_stops_on_error() {
        let directory = tempfile::tempdir().unwrap();
        let mut reg = registry(directory.path());
        let definition = json!({"format": FORMAT, "name": "labels", "inputs": {"name": {"type": "string", "default": "tick"}},
            "steps": [
                {"tool": "debug_label", "arguments": {"action": "set", "name": "${name}", "address": "0x401000"}},
                {"tool": "debug_label_save", "arguments": {}},
                {"tool": "debug_label_load", "arguments": {"artifact": "${steps.1.@artifact}", "merge": false}}
            ]});
        let outcome = run(&mut reg, &json!({"definition": definition})).unwrap();
        assert_eq!(outcome["completed"], true, "{outcome}");
        assert_eq!(outcome["steps_run"], 3);
        assert_eq!(outcome["steps"][2]["summary"]["loaded"], 1);
        assert!(outcome["run_log"].is_string());

        // A disabled (permissioned) tool fails the step exactly as a direct call would; later steps never run.
        let blocked = json!({"format": FORMAT, "name": "blocked", "steps": [
            {"tool": "memory_write", "arguments": {"pid": 1, "address": "0x1000", "hex_data": "90", "expected_hex": "cc"}},
            {"tool": "debug_label_save", "arguments": {}}]});
        let failed = run(&mut reg, &json!({"definition": blocked})).unwrap();
        assert_eq!(failed["completed"], false);
        assert_eq!(failed["steps"].as_array().unwrap().len(), 1);
        assert!(failed["failure"]["error"].as_str().unwrap().contains("disabled"), "{failed}");

        let dry = run(&mut reg, &json!({"recipe": "dump_and_rebuild", "inputs": {"pid": 71}, "dry_run": true})).unwrap();
        assert_eq!(dry["steps"][0]["arguments"], json!({"pid": 71}));
        assert!(dry["steps"][1]["pending_references"].is_string());
        assert!(run(&mut reg, &json!({"recipe": "dump_and_rebuild"})).is_err());
        assert!(run(&mut reg, &json!({"recipe": "nope"})).is_err());
        assert!(run(&mut reg, &json!({})).is_err());
        let listing = list(&reg).unwrap();
        assert!(listing["recipes"].as_array().unwrap().iter().any(|r| r["name"] == "crash_capture"));
        assert_eq!(referenced_tools(&reg, &json!({"recipe": "crash_capture"})).unwrap()[0], "debug_crash_triage");
    }
}
