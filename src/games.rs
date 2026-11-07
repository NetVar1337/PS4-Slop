//! Game-project authoring: repo-shaped scaffolds and one-call update/stage/verify.
//!
//! `game_new` emits a standalone game repository (workbench.json, a Makefile that
//! includes the shared `templates/payload/orbis.mk` toolchain fragment, the engine
//! feature pack, and a per-build `offsets/` store), so projects like Apex-PS4 or
//! Fortnite-PS4 need no hand-written injector or build glue. `game_update` drives
//! the engine pipeline as a durable recipe session and installs the generated
//! inputs into the registered repository. `game_stage` is the hash-qualified
//! upload plus RPC recovery in one call (the same path `ps4-workbench inject`
//! uses). `game_verify` runs the read-only evidence checks. None of these deploy
//! anything by themselves; staging still requires the `process_inject` permission
//! and a hardware-qualified payload hash.
use crate::{Result, tools::ToolRegistry};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::path::Path;

/// Tools owned by this area.
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    Some(match name {
        "game_new" => new_project(registry, args),
        "game_update" => update(registry, args),
        "game_stage" => stage(registry, args),
        "game_verify" => verify(registry, args),
        _ => return None,
    })
}

/// Extra files a game repo gets on top of the shared payload scaffold files.
const GAME_FILES: &[(&str, &str)] = &[
    ("src/payload.cpp", include_str!("../templates/game/payload.cpp")),
    ("src/features.hpp", include_str!("../templates/game/features.hpp")),
    ("Makefile", include_str!("../templates/game/Makefile")),
    ("offsets/README.md", include_str!("../templates/game/offsets/README.md")),
];

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphabetic()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

fn engine_define(engine: &str) -> &'static str {
    match engine {
        "source" => "-DPS4WB_ENGINE_SOURCE",
        "unreal" => "-DPS4WB_ENGINE_UNREAL",
        _ => "",
    }
}

fn default_magic(engine: &str) -> &'static str {
    match engine {
        "source" => "0x41584553", // 'APES'
        _ => "0x5053494e",        // 'PSIN'
    }
}

/// Pipeline recipe for an engine; `update` selects the annotation-porting variant.
pub(crate) fn default_recipe(engine: &str, update: bool) -> Result<&'static str> {
    Ok(match (engine, update) {
        ("unreal", false) => "unreal_pipeline",
        ("unreal", true) => "unreal_update",
        ("source", false) => "source_pipeline",
        ("source", true) => "source_update",
        _ => anyhow::bail!("No default pipeline for engine '{engine}'; pass an explicit recipe"),
    })
}

fn render(template: &str, name: &str, engine: &str, payload: &str) -> String {
    template
        .replace("__NAME__", name)
        .replace("__ENGINE__", engine)
        .replace("__PAYLOAD__", payload)
        .replace("__ENGINE_DEFINE__", engine_define(engine))
}

/// Emit a standalone, buildable game repository under `directory/name`.
fn new_project(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let name = args["name"].as_str().context("name required")?;
    ensure!(valid_name(name), "Invalid project name");
    let engine = args["engine"].as_str().unwrap_or("generic");
    ensure!(
        ["generic", "source", "unreal"].contains(&engine),
        "Unknown engine"
    );
    let directory = args["directory"].as_str().context("directory required")?;
    let root = crate::config::resolve_lenient(Path::new(directory))?;
    ensure!(root.is_dir(), "Parent directory must exist: {}", root.display());
    let folder = root.join(name);
    ensure!(!folder.exists(), "Project already exists: {}", folder.display());
    let payload = args["payload"].as_str().unwrap_or("payload.elf");
    ensure!(
        !payload.is_empty()
            && payload.len() <= 128
            && !payload.contains("..")
            && payload
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b)),
        "Invalid payload path"
    );
    let title_id = args["title_id"].as_str().unwrap_or("");
    ensure!(
        title_id.is_empty() || {
            let bytes = title_id.as_bytes();
            bytes.len() == 9
                && bytes[..4].iter().all(|b| b.is_ascii_uppercase())
                && bytes[4..].iter().all(|b| b.is_ascii_digit())
        },
        "title_id must look like CUSA12345"
    );
    std::fs::create_dir_all(&folder)?;
    let mut written = Vec::new();
    let mut emit = |folder: &Path, path: &str, content: &str| -> Result<()> {
        let path = folder.join(path);
        std::fs::create_dir_all(path.parent().context("Missing parent")?)
            .with_context(|| format!("Cannot create {}", path.display()))?;
        std::fs::write(&path, content)?;
        written.push(path.display().to_string());
        Ok(())
    };
    // Shared payload scaffold files, except the entry point (game template wins).
    for (path, content) in crate::scaffold::FILES {
        if *path == "src/payload.cpp" {
            continue;
        }
        emit(&folder, path, content)?;
    }
    for (path, content) in GAME_FILES {
        emit(&folder, path, &render(content, name, engine, payload))?;
    }
    let source_commit = std::process::Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    let python = if cfg!(windows) { "python" } else { "python3" };
    let recipe = json!({"sdk":"payload","source_commit":source_commit,
        "commands":[[python,"build.py","--engine",engine]],"output":payload,"environment":{},"timeout_seconds":300});
    emit(&folder, "recipe.json", &serde_json::to_string_pretty(&recipe)?)?;
    let mut descriptor = json!({"format":"ps4wb-scaffold-v1","engine":engine,"rpc_version":1,
        "staging":"immediate","payload":payload,"generated_directory":"src/generated",
        "hardware_verified":false});
    if !title_id.is_empty() {
        descriptor["title_id"] = json!(title_id);
    }
    emit(&folder, "workbench.json", &serde_json::to_string_pretty(&descriptor)?)?;
    emit(&folder, ".gitignore", "build/\n__pycache__/\n")?;
    let readme = format!(
        "# {name}\n\nResident diagnostic payload scaffolded by `game_new` (engine: {engine}).\n\n\
         - `make` builds `{payload}` with the shared toolchain fragment `templates/payload/orbis.mk`.\n\
         - `make host-test` (or `python build.py --host-test --engine {engine}`) runs the offline lifecycle smoke test.\n\
         - `make inject PID=<pid> TARGET_MANIFEST=<target artifact>` stages through `ps4-workbench inject`;\n\
         \x20 no per-project injector is needed. Staging requires a qualified local profile with `process_inject`.\n\
         - `game_update` (or `ps4_workbench.ctl update --project-dir .`) runs the engine pipeline and\n\
         \x20 `project_install` writes generated headers into `src/generated/`.\n\
         - `offsets/` keeps the per-build generated offset headers/manifests (`project_export_offsets archive`).\n\n\
         Target checks are initially empty and stay unavailable. No build deploys to a console.\n\
         RPC 7 negotiates protocol v1; RPC 6 telemetry index 0 is verification, index 1 object count.\n\
         See docs/GAME_PROJECT.md in PS4-MCP.\n"
    );
    emit(&folder, "README.md", &readme)?;
    registry.workbench.store.audit(
        "game_new",
        json!({"project":folder.display().to_string(),"engine":engine,"payload":payload}),
    )?;
    Ok(json!({
        "project": folder.display().to_string(),
        "engine": engine,
        "payload": payload,
        "workbench_json": folder.join("workbench.json").display().to_string(),
        "files": written,
        "host_test": [python, "build.py", "--host-test", "--engine", engine],
        "next": [
            "ps4-workbench call project_open with the observed title_id/app_version",
            "ps4-workbench call game_update --arguments '{\"pid\": <pid>}' (engine pipeline + project_install)",
            "make && make inject PID=<pid> TARGET_MANIFEST=<target artifact>",
        ],
        "hardware_verified": false,
    }))
}

/// Resolve a `result_saved` wrapper produced for oversized tool results.
fn expand(registry: &ToolRegistry, value: Value) -> Result<Value> {
    if let Some(reference) = value.get("result_saved") {
        let path = reference["path"].as_str().context("Missing result_saved path")?;
        let bytes = registry
            .workbench
            .store
            .read_bounded(path, 64 << 20)?;
        return Ok(serde_json::from_slice(&bytes)?);
    }
    Ok(value)
}

/// Accept either an artifact-store path or a local file; local files are ingested
/// into the store. Returns the artifact path to pass to payload tools.
fn intern_file(registry: &ToolRegistry, path: &str, kind: &str, extension: &str) -> Result<(String, Vec<u8>)> {
    if registry.workbench.read_artifact(path, 1 << 20).is_ok() {
        let bytes = registry
            .workbench
            .read_artifact(path, registry.workbench.profile.limit("transfer_bytes"))?;
        return Ok((path.to_owned(), bytes));
    }
    let local = crate::config::resolve_lenient(Path::new(path))?;
    ensure!(local.is_file(), "Not an artifact or local file: {path}");
    let bytes = crate::workbench::read_bounded(&local, registry.workbench.profile.limit("transfer_bytes"))?;
    let saved = registry.workbench.store.save(
        kind,
        &bytes,
        json!({"original_name": local.file_name(), "source": "local-file"}),
        extension,
    )?;
    Ok((
        saved["path"].as_str().context("Missing saved path")?.to_owned(),
        bytes,
    ))
}

/// One-call hash-qualified staging: ingest local files if needed, compute the
/// payload hash when not supplied, run `payload_stage`, then read RPC status.
fn stage(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let pid = crate::tools::number(args, "pid")? as u32;
    let (target, _) = intern_file(registry, crate::tools::string(args, "target")?, "internals-target", "json")?;
    let (payload, payload_bytes) = intern_file(registry, crate::tools::string(args, "payload")?, "payload", "elf")?;
    let sha256 = match args["sha256"].as_str() {
        Some(value) => crate::config::require_hash(value, "sha256")?.to_owned(),
        None => crate::config::sha256_hex(&payload_bytes),
    };
    let staged = registry.call(
        "payload_stage",
        json!({"pid":pid,"target":target,"payload":payload,"sha256":sha256}),
    )?;
    let status = registry.call("payload_status", json!({"pid":pid}))?;
    Ok(json!({"stage":staged,"status":status,"payload_sha256":sha256,"automatic_retry":false,
              "hardware_verified":false}))
}

/// Read-only evidence check for a game project: doctor report, project summary,
/// and optional payload inspection of a collected build manifest.
fn verify(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let mut call_args = json!({});
    if let Some(project) = args["project"].as_str() {
        call_args["project"] = json!(project);
    }
    let doctor = registry.call("project_doctor", call_args.clone())?;
    let summary = registry.call("project_summary", call_args.clone())?;
    let mut inspect = Value::Null;
    if let Some(payload) = args["payload"].as_str() {
        inspect = registry.call("payload_inspect", json!({"manifest": payload}))?;
    }
    Ok(json!({
        "doctor": doctor,
        "summary": summary,
        "payload_inspect": inspect,
        "hardware_verified": false,
        "note": "Host-side evidence consistency only; console acceptance still requires observed hardware results.",
    }))
}

/// Drive the engine pipeline as a durable session, register the build contract,
/// and install generated inputs into the registered repository.
fn update(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let store = registry.workbench.store.clone();
    let project = match crate::project::active_project(&store)? {
        Some(project) => project,
        None => {
            let title_id = args["title_id"].as_str().context(
                "No active project; pass title_id and app_version (observed values) to open one",
            )?;
            let app_version = args["app_version"].as_str().context("app_version required")?;
            let name = args["name"].as_str().unwrap_or(title_id);
            registry.call(
                "project_open",
                json!({"title_id":title_id,"app_version":app_version,"name":name}),
            )?;
            crate::project::require_active(&store)?
        }
    };
    let prior = crate::research::manifest_of(&store, &project)?;
    let engine = args["engine"].as_str()
        .or_else(|| prior.as_ref().map(|m| m.engine.as_str()))
        .context("engine required (no active manifest)")?;
    ensure!(
        ["generic", "unreal", "source"].contains(&engine),
        "Unknown engine"
    );
    let update_mode = args["old_artifact"].is_string();
    if update_mode {
        ensure!(
            args["annotations"].is_string(),
            "Pass old_artifact and annotations together"
        );
    }
    let recipe = match args["recipe"].as_str() {
        Some(name) => {
            ensure!(
                crate::recipes::builtins()?.iter().any(|r| r["name"] == name),
                "Unknown built-in recipe: {name}; see recipe_list"
            );
            name.to_owned()
        }
        None => default_recipe(engine, update_mode)?.to_owned(),
    };
    let pid = crate::tools::number(args, "pid")?;
    let mut inputs = json!({
        "pid": pid,
        "module": args["module"].as_str().unwrap_or("eboot.bin"),
        "namespace": args["namespace"].as_str().unwrap_or("game"),
        "status_magic": args["status_magic"].as_str().unwrap_or_else(|| default_magic(engine)),
    });
    for key in ["module_sha256", "image_base"] {
        if let Some(value) = args[key].as_str() {
            inputs[key] = json!(value);
        }
    }
    if let Some(sites) = args["signature_sites"].as_array() {
        inputs["signature_sites"] = json!(sites);
    }
    if update_mode {
        inputs["old_artifact"] = json!(args["old_artifact"].as_str().unwrap());
        inputs["annotations"] = json!(args["annotations"].as_str().unwrap());
    }
    let mut current = if let Some(id) = args["session"].as_str() {
        registry.call("recipe_session", json!({"action":"status","session":id}))?
    } else {
        registry.call("recipe_session", json!({"action":"create","recipe":recipe,"inputs":inputs}))?
    };
    let session_id = current["id"].as_str().context("Missing session id")?.to_owned();
    let mut guard = 0usize;
    while current["state"] == "pending" || current["state"] == "running" {
        guard += 1;
        ensure!(guard <= 4096, "Session did not converge; inspect it with recipe_session status");
        let advanced =
            registry.call("recipe_session", json!({"action":"advance","session":session_id}))?;
        current = expand(registry, advanced)?;
    }
    ensure!(
        current["state"] == "completed",
        "Research session {session_id} is {}; inspect it, then retry explicitly",
        current["state"]
    );
    let outputs = current["outputs"].clone();
    let target_ref = outputs["project_export_target"]["target"]
        .as_object()
        .context("Pipeline produced no target manifest")?;
    let offsets_ref = outputs["project_export_offsets"]["header"]
        .as_object()
        .context("Pipeline produced no offsets header")?;
    let sdk_ref = outputs["engine_sdk_export"]["artifact"]
        .as_object()
        .context("Pipeline produced no engine SDK")?;
    let target_bytes = registry.workbench.read_artifact(
        target_ref["path"].as_str().context("target path")?,
        1 << 20,
    )?;
    let target: Value = serde_json::from_slice(&target_bytes)?;
    let repository = match args["repository"].as_str() {
        Some(value) => value.to_owned(),
        None => prior
            .as_ref()
            .map(|m| m.repository.clone())
            .context("repository required when no manifest is registered")?,
    };
    let repo = crate::config::resolve_lenient(Path::new(&repository))?;
    ensure!(repo.is_dir(), "Payload repository must exist: {}", repo.display());
    let commit = std::process::Command::new("git")
        .args(["-C", repo.to_str().context("Repository path is not UTF-8")?, "rev-parse", "HEAD"])
        .output()
        .context("git rev-parse failed")?;
    ensure!(
        commit.status.success(),
        "Payload repository must have a pinned source commit"
    );
    let source_commit = String::from_utf8_lossy(&commit.stdout).trim().to_owned();
    let sdk = args["sdk"].as_str().unwrap_or(match engine {
        "unreal" => "openorbis",
        _ => "payload",
    });
    let mut manifest = json!({
        "format": "ps4wb-project-v1",
        "title_id": target["title_id"],
        "app_version": target["application_version"],
        "module_sha256": target["module_sha256"],
        "engine": engine,
        "sdk": sdk,
        "source_commit": source_commit,
        "repository": repo.display().to_string(),
        "staging": args["staging"].as_str().unwrap_or("immediate"),
        "rpc_version": 1,
    });
    if let Some(prior) = &prior {
        if !prior.features.is_empty() {
            manifest["features"] = serde_json::to_value(&prior.features)?;
        }
        if !prior.bindings.is_empty() {
            manifest["bindings"] = serde_json::to_value(&prior.bindings)?;
        }
    }
    registry.call("project_manifest", json!({"manifest": manifest}))?;
    let installed = if args["install"].as_bool().unwrap_or(true) {
        Some(registry.call(
            "project_install",
            json!({
                "target": target_ref["path"],
                "offsets": offsets_ref["path"],
                "engine": sdk_ref["path"],
            }),
        )?)
    } else {
        None
    };
    Ok(json!({
        "project": project,
        "session": session_id,
        "state": current["state"],
        "recipe": recipe,
        "engine": engine,
        "update": update_mode,
        "module_sha256": target["module_sha256"],
        "installed": installed,
        "next": {
            "build": "make (or python build.py --engine <engine>) in the payload repository",
            "stage": "ps4-workbench inject --pid <pid> --target <target artifact> --payload <elf>  (or game_stage)",
            "verify": "game_verify",
        },
        "deployed": false,
        "hardware_verified": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{tools::Toolset, workbench::Workbench};

    fn make_registry(dir: &tempfile::TempDir) -> ToolRegistry {
        ToolRegistry::with_toolset(
            Workbench::new(crate::artifacts::tests::test_profile(dir.path())).unwrap(),
            Toolset::Full,
        )
        .unwrap()
    }

    #[test]
    fn game_new_emits_repo_shaped_project_with_shared_toolchain() {
        let dir = tempfile::tempdir().unwrap();
        let parent = tempfile::tempdir().unwrap();
        let mut registry = make_registry(&dir);
        let out = registry
            .call(
                "game_new",
                json!({"name":"GamePS4","engine":"unreal","directory":parent.path().to_str().unwrap(),
                       "title_id":"CUSA12552","payload":"build/game_payload.elf"}),
            )
            .unwrap();
        let folder = parent.path().join("GamePS4");
        assert_eq!(out["project"], folder.display().to_string());
        let descriptor: Value =
            serde_json::from_slice(&std::fs::read(folder.join("workbench.json")).unwrap()).unwrap();
        assert_eq!(descriptor["engine"], "unreal");
        assert_eq!(descriptor["rpc_version"], 1);
        assert_eq!(descriptor["payload"], "build/game_payload.elf");
        assert_eq!(descriptor["generated_directory"], "src/generated");
        assert_eq!(descriptor["title_id"], "CUSA12552");
        let makefile = std::fs::read_to_string(folder.join("Makefile")).unwrap();
        assert!(makefile.contains("include $(WORKBENCH_DIR)/templates/payload/orbis.mk"));
        assert!(makefile.contains("-DPS4WB_ENGINE_UNREAL"));
        assert!(makefile.contains("build/game_payload.elf"));
        assert!(makefile.contains("ps4-workbench") && makefile.contains(" inject "));
        assert!(folder.join("src/features.hpp").is_file());
        assert!(folder.join("src/payload.cpp").is_file());
        assert!(folder.join("offsets/README.md").is_file());
        assert!(folder.join("include/internals/runtime.hpp").is_file());
        assert!(folder.join("runtime.cpp").is_file());
        assert!(folder.join("build.py").is_file());
        assert!(folder.join("tests/host_smoke.cpp").is_file());
        let payload_cpp = std::fs::read_to_string(folder.join("src/payload.cpp")).unwrap();
        assert!(payload_cpp.contains("features::allowed(bits)"));
        // Duplicate creation is refused.
        assert!(
            registry
                .call(
                    "game_new",
                    json!({"name":"GamePS4","engine":"unreal","directory":parent.path().to_str().unwrap()})
                )
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        // Bad names, engines, title ids and payload paths are rejected.
        for args in [
            json!({"name":"1bad","directory":parent.path()}),
            json!({"name":"Ok","engine":"unity","directory":parent.path()}),
            json!({"name":"Ok","directory":parent.path(),"title_id":"nope"}),
            json!({"name":"Ok","directory":parent.path(),"payload":"../evil.elf"}),
            json!({"name":"Ok"}),
        ] {
            assert!(registry.call("game_new", args).is_err());
        }
    }

    #[test]
    fn game_new_source_project_compiles_host_smoke() {
        let dir = tempfile::tempdir().unwrap();
        let parent = tempfile::tempdir().unwrap();
        let mut registry = make_registry(&dir);
        registry
            .call(
                "game_new",
                json!({"name":"ApexLike","engine":"source","directory":parent.path().to_str().unwrap()}),
            )
            .unwrap();
        let folder = parent.path().join("ApexLike");
        let makefile = std::fs::read_to_string(folder.join("Makefile")).unwrap();
        assert!(makefile.contains("-DPS4WB_ENGINE_SOURCE"));
        let output = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
            .args([
                folder.join("build.py").to_str().unwrap(),
                "--host-test",
                "--engine",
                "source",
            ])
            .current_dir(&folder)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn game_verify_reports_doctor_and_summary() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = make_registry(&dir);
        registry
            .call(
                "project_open",
                json!({"title_id":"CUSA99999","app_version":"01.00","name":"VerifyGame"}),
            )
            .unwrap();
        let out = registry.call("game_verify", json!({})).unwrap();
        assert_eq!(out["doctor"]["ready"], false);
        assert!(out["summary"]["project"].is_object());
        assert_eq!(out["hardware_verified"], false);
        // Without an active project the read-only checks fail cleanly.
        let dir2 = tempfile::tempdir().unwrap();
        let mut registry2 = make_registry(&dir2);
        assert!(registry2.call("game_verify", json!({})).is_err());
    }

    #[test]
    fn game_stage_requires_pid_and_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = make_registry(&dir);
        assert!(registry.call("game_stage", json!({})).is_err());
        // The fixture profile has no process_inject permission, so the
        // permission gate fires before any file access.
        let error = registry
            .call("game_stage", json!({"pid":1,"target":"missing.json","payload":"missing.elf"}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("game_stage"), "unexpected error: {error}");
    }

    #[test]
    fn default_recipes_cover_both_engines() {
        assert_eq!(default_recipe("unreal", false).unwrap(), "unreal_pipeline");
        assert_eq!(default_recipe("unreal", true).unwrap(), "unreal_update");
        assert_eq!(default_recipe("source", false).unwrap(), "source_pipeline");
        assert_eq!(default_recipe("source", true).unwrap(), "source_update");
        assert!(default_recipe("generic", false).is_err());
    }
}
