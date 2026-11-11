//! Durable, cooperatively scheduled workflows. Each request advances a bounded
//! number of steps; clients can show progress or cancel between requests.
use crate::{Result, tools::ToolRegistry};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

type CancelCheck = Option<Box<dyn Fn() -> bool>>;
thread_local! { static CANCEL: RefCell<CancelCheck> = RefCell::new(None); }
pub fn cancelled() -> bool {
    CANCEL.with(|c| c.borrow().as_ref().is_some_and(|f| f()))
}
pub fn with_cancellation<T>(check: impl Fn() -> bool + 'static, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CANCEL.with(|c| *c.borrow_mut() = None);
        }
    }
    CANCEL.with(|c| *c.borrow_mut() = Some(Box::new(check)));
    let _reset = Reset;
    run()
}
#[derive(Serialize, Deserialize)]
struct Step {
    state: String,
    arguments: Value,
    result: Value,
    error: Option<String>,
    pins: BTreeMap<String, String>,
}
impl Default for Step {
    fn default() -> Self {
        Self {
            state: "pending".into(),
            arguments: Value::Null,
            result: Value::Null,
            error: None,
            pins: BTreeMap::new(),
        }
    }
}
#[derive(Serialize, Deserialize)]
struct Session {
    format: String,
    id: String,
    recipe: Value,
    recipe_sha256: String,
    profile_sha256: String,
    project: Option<String>,
    inputs: serde_json::Map<String, Value>,
    steps: Vec<Step>,
    state: String,
    updated: String,
}
fn session_path(registry: &ToolRegistry, id: &str) -> Result<std::path::PathBuf> {
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid session id"
    );
    registry
        .workbench
        .store
        .new_path(&format!("sessions/{id}.json"))
}
fn load(registry: &ToolRegistry, id: &str) -> Result<Session> {
    let path = session_path(registry, id)?;
    let session: Session =
        serde_json::from_slice(&crate::workbench::read_bounded(&path, 32 << 20)?)?;
    ensure!(
        session.format == "ps4wb-session-v1"
            && session.id == id
            && crate::config::canonical_hash(&session.recipe) == session.recipe_sha256,
        "Invalid session contract"
    );
    Ok(session)
}
fn save(registry: &ToolRegistry, session: &mut Session) -> Result<()> {
    session.updated = crate::artifacts::utc_now();
    let path = session_path(registry, &session.id)?;
    std::fs::create_dir_all(path.parent().context("Missing session directory")?)?;
    let data = serde_json::to_vec_pretty(session)?;
    ensure!(data.len() <= 32 << 20, "Session exceeds 32 MiB");
    let next = path.with_extension(format!("next-{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&next, data)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&next)?
        .sync_all()?;
    std::fs::rename(&next, path)?;
    Ok(())
}
fn summary(session: &Session) -> Value {
    let mut outputs = serde_json::Map::new();
    for (index, step) in session
        .steps
        .iter()
        .enumerate()
        .filter(|(_, s)| s.state == "completed")
    {
        if let Some(tool) = session.recipe["steps"][index]["tool"].as_str()
            && [
                "project_bind_module",
                "engine_sdk_export",
                "project_export_offsets",
                "project_export_target",
                "project_install",
                "sdk_build",
            ]
            .contains(&tool)
        {
            outputs.insert(tool.into(), step.result.clone());
        }
    }
    json!({"id":session.id,"state":session.state,"updated":session.updated,"recipe":session.recipe["name"],"completed":session.steps.iter().filter(|s| s.state == "completed").count(),"total":session.steps.len(),"outputs":outputs,"steps":session.steps.iter().enumerate().map(|(i,s)| json!({"index":i,"tool":session.recipe["steps"][i]["tool"],"state":s.state,"error":s.error,"summary":crate::recipes::summarize(&s.result)})).collect::<Vec<_>>(),"automatic_retry":false})
}
fn pin(registry: &ToolRegistry, value: &Value, pins: &mut BTreeMap<String, String>) -> Result<()> {
    match value {
        Value::String(path) => {
            if registry.workbench.store.path(path).is_ok() {
                let bytes = registry
                    .workbench
                    .store
                    .read_bounded(path, crate::bytesource::ARTIFACT_MAX)?;
                pins.insert(path.clone(), crate::config::sha256_hex(&bytes));
            }
        }
        Value::Array(items) => {
            for item in items {
                pin(registry, item, pins)?;
            }
        }
        Value::Object(fields) => {
            for item in fields.values() {
                pin(registry, item, pins)?;
            }
        }
        _ => {}
    }
    ensure!(pins.len() <= 512, "Too many session artifact dependencies");
    Ok(())
}
fn read_only(name: &str) -> bool {
    crate::extensions::full_catalog()
        .ok()
        .into_iter()
        .flatten()
        .any(|t| {
            t["name"] == name
                && (t["annotations"]["readOnlyHint"] == true
                    || t["permission"].is_null()
                    || t["permission"] == "build")
        })
}
fn invalidate(registry: &ToolRegistry, session: &mut Session) -> Result<()> {
    let mut dirty = BTreeSet::new();
    for (index, step) in session.steps.iter().enumerate() {
        if step.state != "completed" {
            continue;
        }
        if step.pins.iter().any(|(path, sha)| {
            registry
                .workbench
                .store
                .read_bounded(path, crate::bytesource::ARTIFACT_MAX)
                .map(|b| crate::config::sha256_hex(&b) != *sha)
                .unwrap_or(true)
        }) {
            dirty.insert(index);
        }
        let args = serde_json::to_string(&session.recipe["steps"][index]["arguments"])?;
        if dirty
            .iter()
            .any(|i| args.contains(&format!("${{steps.{i}.")))
        {
            dirty.insert(index);
        }
    }
    for index in dirty {
        let tool = session.recipe["steps"][index]["tool"]
            .as_str()
            .unwrap_or("");
        session.steps[index] = Step::default();
        if !read_only(tool) {
            session.steps[index].state = "blocked".into();
            session.steps[index].error = Some(
                "Dependencies changed after a mutating step; record recovery evidence before retry"
                    .into(),
            );
        }
    }
    Ok(())
}
pub fn referenced_tools(registry: &ToolRegistry, args: &Value) -> Result<Vec<String>> {
    let recipe = if args["action"] == "create" {
        crate::recipes::resolve(registry, args)?
    } else {
        load(
            registry,
            args["session"].as_str().context("Missing session")?,
        )?
        .recipe
    };
    Ok(recipe["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["tool"].as_str().map(str::to_owned))
        .collect())
}
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    if name != "recipe_session" {
        return None;
    }
    Some((|| {
        let action = args["action"].as_str().context("Missing action")?;
        if action == "create" {
            let recipe = crate::recipes::resolve(registry, args)?;
            let inputs = crate::recipes::bind_inputs(&recipe, &args["inputs"])?;
            let mut session = Session {
                format: "ps4wb-session-v1".into(),
                id: uuid::Uuid::new_v4().simple().to_string(),
                recipe_sha256: crate::config::canonical_hash(&recipe),
                profile_sha256: registry.workbench.profile.fingerprint(),
                project: crate::project::active_project(&registry.workbench.store)?,
                steps: recipe["steps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|_| Step::default())
                    .collect(),
                recipe,
                inputs,
                state: "pending".into(),
                updated: String::new(),
            };
            save(registry, &mut session)?;
            return Ok(summary(&session));
        }
        let mut session = load(
            registry,
            args["session"].as_str().context("Missing session")?,
        )?;
        if action == "status" {
            return Ok(summary(&session));
        }
        if action == "cancel" {
            session.state = "cancelled".into();
            save(registry, &mut session)?;
            return Ok(summary(&session));
        }
        ensure!(
            session.profile_sha256 == registry.workbench.profile.fingerprint(),
            "Profile changed; create a new session"
        );
        ensure!(
            session.project == crate::project::active_project(&registry.workbench.store)?,
            "Active project changed; reopen the session's project"
        );
        if action == "revise" {
            ensure!(
                session.state != "cancelled",
                "Cancelled sessions cannot be revised"
            );
            let patch = args["inputs"].as_object().context("Revise needs inputs")?;
            let mut merged = session.inputs.clone();
            for (key, value) in patch {
                merged.insert(key.clone(), value.clone());
            }
            let bound = crate::recipes::bind_inputs(&session.recipe, &Value::Object(merged))?;
            let changed: Vec<_> = bound
                .iter()
                .filter(|(key, value)| session.inputs.get(*key) != Some(*value))
                .map(|(key, _)| key.clone())
                .collect();
            let mut dirty = BTreeSet::new();
            for index in 0..session.steps.len() {
                let template = serde_json::to_string(&session.recipe["steps"][index]["arguments"])?;
                if changed.iter().any(|key| {
                    template.contains(&format!("${{{key}}}"))
                        || template.contains(&format!("${{inputs.{key}}}"))
                        || template.contains(&format!("${{{key}."))
                        || template.contains(&format!("${{inputs.{key}."))
                }) || dirty
                    .iter()
                    .any(|i| template.contains(&format!("${{steps.{i}.")))
                {
                    dirty.insert(index);
                }
            }
            for index in dirty {
                let was_uncertain = session.steps[index].state == "running"
                    || session.steps[index].state == "blocked";
                let tool = session.recipe["steps"][index]["tool"]
                    .as_str()
                    .unwrap_or("");
                let mutated = session.steps[index].state != "pending" && !read_only(tool);
                session.steps[index] = Step::default();
                if was_uncertain || mutated {
                    session.steps[index].state = "blocked".into();
                    session.steps[index].error=Some("Inputs changed after an uncertain/control step; record recovery evidence before retry".into());
                }
            }
            session.inputs = bound;
            session.state = "pending".into();
            save(registry, &mut session)?;
            return Ok(summary(&session));
        }
        if action == "retry" {
            let index = args["step"].as_u64().context("Retry needs step")? as usize;
            let step = session.steps.get_mut(index).context("Invalid step")?;
            ensure!(
                ["failed", "running", "blocked"].contains(&step.state.as_str()),
                "Step is not retryable"
            );
            let tool = session.recipe["steps"][index]["tool"]
                .as_str()
                .unwrap_or("");
            if !read_only(tool) {
                let evidence = args["recovery_evidence"].as_str().context("Mutating retry requires recovery_evidence artifact; never retry an uncertain console mutation automatically")?;
                registry.workbench.store.read_bounded(evidence, 1 << 20)?;
                registry.workbench.store.audit(
                    "session_explicit_retry",
                    json!({"session":session.id,"step":index,"evidence":evidence}),
                )?;
            }
            *step = Step::default();
            session.state = "pending".into();
            save(registry, &mut session)?;
            return Ok(summary(&session));
        }
        ensure!(action == "advance", "Unknown session action");
        ensure!(
            session.state != "cancelled",
            "Session cancelled; create a new session to restart"
        );
        invalidate(registry, &mut session)?;
        let max_steps = args["max_steps"].as_u64().unwrap_or(1).clamp(1, 32);
        for _ in 0..max_steps {
            if cancelled() {
                session.state = "cancelled".into();
                break;
            }
            let Some(index) = session.steps.iter().position(|s| s.state != "completed") else {
                session.state = "completed".into();
                break;
            };
            if session.steps[index].state != "pending" {
                session.state = "blocked".into();
                break;
            }
            let values: Vec<Value> = session.steps.iter().map(|s| s.result.clone()).collect();
            let arguments = crate::recipes::substitute(
                &session.recipe["steps"][index]["arguments"],
                &session.inputs,
                &values,
            )?
            .unwrap_or_else(|| json!({}));
            let tool = session.recipe["steps"][index]["tool"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            let mut pins = BTreeMap::new();
            pin(registry, &arguments, &mut pins)?;
            session.steps[index].state = "running".into();
            session.steps[index].arguments = arguments.clone();
            session.state = "running".into();
            save(registry, &mut session)?; // Crash after this point means uncertain, never auto retry.
            match registry.call(&tool, arguments) {
                Ok(mut result) => {
                    if let Some(path) = result["result_saved"]["path"].as_str() {
                        result = serde_json::from_slice(
                            &registry.workbench.store.read_bounded(path, 16 << 20)?,
                        )?;
                    }
                    pin(registry, &result, &mut pins)?;
                    session.steps[index] = Step {
                        state: "completed".into(),
                        arguments: session.steps[index].arguments.clone(),
                        result,
                        error: None,
                        pins,
                    };
                    session.state = if session.steps.iter().all(|s| s.state == "completed") {
                        "completed"
                    } else {
                        "pending"
                    }
                    .into();
                }
                Err(error) => {
                    session.steps[index].state = "failed".into();
                    session.steps[index].error = Some(format!("{error:#}"));
                    session.state = "failed".into();
                }
            }
            save(registry, &mut session)?;
            if session.state == "failed" {
                break;
            }
        }
        save(registry, &mut session)?;
        Ok(summary(&session))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sessions_resume_cancel_and_invalidate_artifact_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let profile = crate::artifacts::tests::test_profile(dir.path());
        let mut registry = ToolRegistry::with_toolset(
            crate::workbench::Workbench::new(profile.clone()).unwrap(),
            crate::tools::Toolset::Full,
        )
        .unwrap();
        let artifact = registry
            .workbench
            .store
            .save("input", b"original", json!({}), "bin")
            .unwrap();
        let definition = json!({"format":"ps4wb-recipe-v1","name":"replay","inputs":{"artifact":{"type":"string","required":true}},"steps":[{"tool":"artifact_read","arguments":{"artifact":"${artifact}"}},{"tool":"console_status","arguments":{}}]});
        let created=registry.call("recipe_session",json!({"action":"create","definition":definition,"inputs":{"artifact":artifact["path"]}})).unwrap();
        let id = created["id"].as_str().unwrap();
        let first = registry
            .call("recipe_session", json!({"action":"advance","session":id}))
            .unwrap();
        assert_eq!(first["completed"], 1);
        drop(registry);
        let mut registry = ToolRegistry::with_toolset(
            crate::workbench::Workbench::new(profile).unwrap(),
            crate::tools::Toolset::Full,
        )
        .unwrap();
        assert_eq!(
            registry
                .call("recipe_session", json!({"action":"advance","session":id}))
                .unwrap()["state"],
            "completed"
        );
        std::fs::write(
            registry
                .workbench
                .store
                .path(artifact["path"].as_str().unwrap())
                .unwrap(),
            "changed",
        )
        .unwrap();
        let updated = registry
            .call("recipe_session", json!({"action":"advance","session":id}))
            .unwrap();
        assert_eq!(updated["steps"][0]["state"], "completed");
        let state = load(&registry, id).unwrap();
        assert_eq!(state.steps[0].result["utf8"], "changed");
        registry
            .call("recipe_session", json!({"action":"cancel","session":id}))
            .unwrap();
        assert!(
            registry
                .call("recipe_session", json!({"action":"advance","session":id}))
                .is_err()
        );
    }
    #[test]
    fn cancellation_is_scoped_and_checked_before_a_step() {
        assert!(!cancelled());
        with_cancellation(|| true, || assert!(cancelled()));
        assert!(!cancelled());
    }
}
