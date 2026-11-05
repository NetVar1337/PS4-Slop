//! SDK status, project scaffolds and hash-allowlisted local builds.
//!
//! Native port of `ps4_workbench/development.py`. Builds run only recipes
//! whose SHA-256 is on the hardware qualification allowlist, use argv arrays
//! (never a shell), refuse batch files, bound time and log output, and never
//! deploy their output.

use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use serde_json::{Map, Value, json};

use crate::Result;
use crate::artifacts::ArtifactStore;
use crate::config::{
    Profile, is_lower_hex, python_json_ordered, require_hash, require_integer, resolve_lenient,
    sha256_hex,
};

/// Recipes are small JSON documents.
pub const MAX_RECIPE_BYTES: usize = 65_536;
/// Maximum argv commands per recipe.
pub const MAX_COMMANDS: usize = 16;
const READER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Known SDK descriptors keyed by scaffold kind.
pub fn sdks() -> Value {
    json!({
        "homebrew": {"name": "OpenOrbis", "environment": "OO_PS4_TOOLCHAIN",
                     "repository": "https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain",
                     "artifact_format": "pkg", "runtime_14_00_verified": false},
        "plugin": {"name": "GoldHEN Plugins SDK", "environment": "GOLDHEN_SDK",
                   "repository": "https://github.com/GoldHEN/GoldHEN_Plugins_SDK",
                   "artifact_format": "prx", "runtime_14_00_verified": false},
        "payload": {"name": "PS4 Payload SDK", "environment": "PS4_PAYLOAD_SDK",
                    "repository": "https://github.com/ps4-payload-dev/sdk",
                    "artifact_format": "elf", "runtime_14_00_verified": false,
                    "warning": "Published SDK firmware list does not include 14.00; ELF must not use BinLoader"},
    })
}

fn valid_project_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn executable_candidates(command: &Path) -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let extensions: Vec<String> = std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|ext| !ext.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        let text = command.to_string_lossy().to_ascii_lowercase();
        if extensions.iter().any(|ext| text.ends_with(ext.as_str())) {
            return vec![command.to_path_buf()];
        }
        extensions
            .iter()
            .map(|ext| {
                let mut name = command.as_os_str().to_os_string();
                name.push(ext);
                PathBuf::from(name)
            })
            .collect()
    }
    #[cfg(not(windows))]
    {
        vec![command.to_path_buf()]
    }
}

/// Python `shutil.which` without the implicit current-directory search.
pub fn which(command: &str, search_path: Option<&OsString>) -> Option<PathBuf> {
    if command.is_empty() || command.contains('\0') {
        return None;
    }
    let candidate = Path::new(command);
    if candidate.components().count() > 1 || candidate.is_absolute() {
        return executable_candidates(candidate)
            .into_iter()
            .find(|path| is_executable_file(path));
    }
    let search = search_path.cloned().or_else(|| std::env::var_os("PATH"))?;
    std::env::split_paths(&search)
        .filter(|directory| !directory.as_os_str().is_empty())
        .flat_map(|directory| executable_candidates(&directory.join(command)))
        .find(|path| is_executable_file(path))
}

pub struct Development {
    pub profile: Profile,
    pub store: Arc<ArtifactStore>,
}

struct Recipe {
    sdk: String,
    source_commit: String,
    commands: Vec<Vec<String>>,
    environment: Map<String, Value>,
    timeout: Duration,
    output: String,
}

fn parse_recipe(content: &[u8]) -> Result<Recipe> {
    let settings: Value = serde_json::from_slice(content)
        .map_err(|error| anyhow!("Build recipe is not valid JSON: {error}"))?;
    let Some(settings) = settings.as_object() else {
        bail!("Build recipe must be a JSON object");
    };
    let sdk = settings.get("sdk").and_then(Value::as_str).unwrap_or("");
    if sdks().get(sdk).is_none() {
        bail!("Unknown SDK recipe");
    }
    let source_commit = settings
        .get("source_commit")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !is_lower_hex(source_commit, 40) {
        bail!("Pin the sample/source commit in the recipe");
    }
    let commands = match settings.get("commands") {
        Some(Value::Array(list)) if (1..=MAX_COMMANDS).contains(&list.len()) => list,
        _ => bail!("Recipe needs 1 to 16 explicit argv commands"),
    };
    let commands = commands
        .iter()
        .map(|command| match command {
            Value::Array(parts) if !parts.is_empty() => parts
                .iter()
                .map(|part| match part {
                    Value::String(text) if !text.contains('\0') => Ok(text.clone()),
                    _ => Err(anyhow!(
                        "Build commands must be nonempty string argv arrays"
                    )),
                })
                .collect::<Result<Vec<String>>>(),
            _ => Err(anyhow!(
                "Build commands must be nonempty string argv arrays"
            )),
        })
        .collect::<Result<Vec<_>>>()?;
    let environment = match settings.get("environment") {
        None => Map::new(),
        Some(Value::Object(map))
            if map.iter().all(|(key, value)| {
                value.as_str().is_some_and(|text| !text.contains('\0'))
                    && !key.is_empty()
                    && !key.contains(['=', '\0'])
            }) =>
        {
            map.clone()
        }
        Some(_) => bail!("Recipe environment must map strings to strings"),
    };
    let timeout = require_integer(
        settings.get("timeout_seconds").unwrap_or(&json!(120)),
        "build timeout",
        1,
        600,
    )?;
    let Some(output) = settings.get("output").and_then(Value::as_str) else {
        bail!("Recipe needs a relative output path");
    };
    Ok(Recipe {
        sdk: sdk.to_string(),
        source_commit: source_commit.to_string(),
        commands,
        environment,
        timeout: Duration::from_secs(timeout as u64),
        output: output.to_string(),
    })
}

struct Outcome {
    code: Option<i32>,
    timed_out: bool,
    exceeded: bool,
}

fn spawn_reader(
    mut stream: impl Read + Send + 'static,
    logs: Arc<Mutex<Vec<u8>>>,
    exceeded: Arc<AtomicBool>,
    limit: usize,
    done: mpsc::Sender<()>,
) {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    let mut logs = logs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    let available = limit.saturating_sub(logs.len());
                    logs.extend_from_slice(&chunk[..count.min(available)]);
                    if count > available {
                        exceeded.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    exceeded.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        let _ = done.send(());
    });
}

impl Development {
    pub fn new(profile: Profile, store: Arc<ArtifactStore>) -> Self {
        Self { profile, store }
    }

    pub fn status(&self) -> Result<Value> {
        let mut sdk_status = Map::new();
        if let Value::Object(map) = sdks() {
            for (name, mut settings) in map {
                let variable = settings["environment"].as_str().unwrap_or("").to_string();
                settings["configured_path"] = std::env::var_os(&variable)
                    .map(|path| Value::from(path.to_string_lossy().into_owned()))
                    .unwrap_or(Value::Null);
                sdk_status.insert(name, settings);
            }
        }
        let mut executables = Map::new();
        for name in ["clang", "clang++", "cmake", "make", "ninja", "git"] {
            let found =
                which(name, None).map(|path| Value::from(path.to_string_lossy().into_owned()));
            executables.insert(name.into(), found.unwrap_or(Value::Null));
        }
        Ok(json!({
            "sdks": sdk_status,
            "executables": executables,
            "note": "Presence is not build or firmware compatibility verification; SDKs are not installed automatically",
        }))
    }

    pub fn scaffold(&self, kind: &str, name: &str) -> Result<Value> {
        let catalog = sdks();
        let Some(sdk) = catalog.get(kind).filter(|_| valid_project_name(name)) else {
            bail!("Choose homebrew/plugin/payload and a simple project name");
        };
        let relative = format!("projects/{name}");
        fs::create_dir_all(&self.store.root)?;
        let projects = self.store.new_path("projects")?;
        fs::create_dir_all(&projects)?;
        let folder = self.store.new_path(&relative)?;
        fs::create_dir(&folder).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow!("Project already exists: {relative}")
            } else {
                anyhow!("Cannot create project {relative}: {error}")
            }
        })?;
        let folder = self.store.new_path(&relative)?;
        let recipe = python_json_ordered(
            &[
                ("sdk", Value::from(kind)),
                ("source_commit", Value::Null),
                ("commands", json!([])),
                ("output", Value::Null),
                ("environment", json!({})),
                ("timeout_seconds", json!(120)),
            ],
            2,
        );
        fs::write(folder.join("recipe.json"), recipe)?;
        let readme = format!(
            "# {name}\n\nSDK: {}\nUpstream: {}\n\n\
             Copy a matching upstream sample into this directory, pin its source commit, and supply\n\
             the actual compiler/linker commands and relative output in recipe.json.\n\
             This scaffold deliberately does not invent firmware offsets, SDK APIs, or linker scripts.\n\
             Commands are argv arrays, never shell strings. Use native executables (not .bat/.cmd).\n\
             Hash and locally approve the complete recipe before building through MCP.\n\
             A successful build does not qualify its output for your console.\n",
            sdk["name"].as_str().unwrap_or(""),
            sdk["repository"].as_str().unwrap_or(""),
        );
        fs::write(folder.join("README.md"), readme)?;
        Ok(json!({
            "project": self.store.relative_of(&folder)?,
            "recipe": format!("{relative}/recipe.json"),
            "sdk": sdk,
            "ready_to_build": false,
            "next": "Add and pin an upstream SDK sample and complete recipe",
        }))
    }

    fn run_command(
        &self,
        command: &[String],
        project: &Path,
        recipe: &Recipe,
        deadline: Instant,
        logs: &Arc<Mutex<Vec<u8>>>,
    ) -> Result<Outcome> {
        let search_path = recipe
            .environment
            .get("PATH")
            .and_then(Value::as_str)
            .map(OsString::from);
        let executable = which(&command[0], search_path.as_ref())
            .filter(|path| {
                let lower = path.to_string_lossy().to_ascii_lowercase();
                !lower.ends_with(".bat") && !lower.ends_with(".cmd")
            })
            .ok_or_else(|| {
                anyhow!(
                    "Build executable missing or batch file unsupported: {}",
                    command[0]
                )
            })?;
        let mut process = Command::new(&executable);
        process
            .args(&command[1..])
            .current_dir(project)
            .envs(
                recipe
                    .environment
                    .iter()
                    .map(|(key, value)| (key, value.as_str().unwrap_or(""))),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            process.creation_flags(0x0800_0000);
        }
        let mut child = process
            .spawn()
            .map_err(|error| anyhow!("Cannot start build command {}: {error}", command[0]))?;
        let exceeded = Arc::new(AtomicBool::new(false));
        let limit = self.profile.limit("log_bytes");
        let (done, finished) = mpsc::channel();
        let mut readers = 0;
        if let Some(stdout) = child.stdout.take() {
            spawn_reader(stdout, logs.clone(), exceeded.clone(), limit, done.clone());
            readers += 1;
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_reader(stderr, logs.clone(), exceeded.clone(), limit, done.clone());
            readers += 1;
        }
        drop(done);
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if exceeded.load(Ordering::SeqCst) || Instant::now() >= deadline {
                timed_out = !exceeded.load(Ordering::SeqCst);
                let _ = child.kill();
                break child.wait()?;
            }
            std::thread::sleep(POLL_INTERVAL);
        };
        let join_deadline = Instant::now() + READER_JOIN_TIMEOUT;
        for _ in 0..readers {
            let remaining = join_deadline.saturating_duration_since(Instant::now());
            if finished.recv_timeout(remaining).is_err() {
                exceeded.store(true, Ordering::SeqCst);
                break;
            }
        }
        Ok(Outcome {
            code: status.code(),
            timed_out,
            exceeded: exceeded.load(Ordering::SeqCst),
        })
    }

    /// Run a hash-allowlisted recipe; returns the build artifact and log.
    pub fn build(&self, recipe: &str, sha256: &str) -> Result<Value> {
        let qualification = self.profile.require("build")?;
        let content = self.store.read_bounded(recipe, MAX_RECIPE_BYTES)?;
        let digest = sha256_hex(&content);
        let allowed = qualification
            .get("build_recipe_sha256_allowlist")
            .and_then(Value::as_array)
            .is_some_and(|list| {
                list.iter()
                    .any(|item| item.as_str() == Some(digest.as_str()))
            });
        if require_hash(sha256, "sha256")? != digest || !allowed {
            bail!("Build recipe must match the locally approved SHA-256");
        }
        let settings = parse_recipe(&content)?;
        let project = self
            .store
            .path(recipe)?
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow!("Recipe has no project directory"))?;
        let inside_project = |path: &Path| path.starts_with(&project) && path != project;
        let output = if settings.output.contains('\0') {
            None
        } else {
            resolve_lenient(&project.join(&settings.output)).ok()
        };
        let Some(output) = output.filter(|path| inside_project(path)) else {
            bail!("Build output must stay inside project");
        };
        if fs::symlink_metadata(&output).is_ok() || output.exists() {
            bail!(
                "Build output already exists; archive/remove it locally to prevent stale-output success"
            );
        }
        self.store
            .audit("build_intent", json!({"recipe": recipe, "sha256": sha256}))?;
        let logs = Arc::new(Mutex::new(Vec::new()));
        let deadline = Instant::now() + settings.timeout;
        for command in &settings.commands {
            let outcome = self.run_command(command, &project, &settings, deadline, &logs)?;
            if outcome.code != Some(0) || outcome.timed_out || outcome.exceeded {
                let captured = logs
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                let log = self.store.save(
                    "build-log",
                    &captured,
                    json!({"returncode": outcome.code, "timeout": outcome.timed_out}),
                    "bin",
                )?;
                self.store.audit("build_failure", json!({"log": log}))?;
                bail!(
                    "Build failed or exceeded bounds; see {}",
                    log["path"].as_str().unwrap_or("build log")
                );
            }
        }
        let produced = resolve_lenient(&output)?;
        if !inside_project(&produced) {
            bail!("Build output must stay inside project");
        }
        if !produced.is_file() {
            bail!("Build succeeded but declared output does not exist");
        }
        let relative_output = self.store.relative_of(&produced)?;
        let built = self.store.read(&relative_output)?;
        let artifact = self.store.save(
            "build",
            &built,
            json!({"recipe_sha256": sha256, "sdk": settings.sdk,
                   "source_commit": settings.source_commit, "hardware_verified": false}),
            "bin",
        )?;
        let captured = logs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let log = self
            .store
            .save("build-log", &captured, Value::Null, "bin")?;
        self.store
            .audit("build_result", json!({"artifact": artifact, "log": log}))?;
        Ok(json!({"artifact": artifact, "log": log, "deployed": false, "hardware_verified": false}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ATTESTATION;

    struct Fixture {
        _directory: tempfile::TempDir,
        root: PathBuf,
    }

    fn base_settings() -> Value {
        let mut data: Value =
            serde_json::from_str(include_str!("../profiles/ps4-1400.json")).unwrap();
        data["host"] = json!("127.0.0.1");
        data["artifact_directory"] = json!("artifacts");
        data["qualification_file"] = json!("qualification.json");
        data
    }

    fn load(root: &Path, data: &Value) -> Profile {
        let path = root.join("profile.json");
        fs::write(&path, data.to_string()).unwrap();
        Profile::load(path).unwrap()
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().to_path_buf();
        Fixture {
            _directory: directory,
            root,
        }
    }

    fn qualified(root: &Path, log_bytes: u64, recipes: &[String]) -> Profile {
        let mut data = base_settings();
        data["permissions"]["build"] = json!(true);
        data["limits"]["log_bytes"] = json!(log_bytes);
        data["jailbreak"]["installed_commit"] = json!("a".repeat(40));
        data["jailbreak"]["hen_build"] = json!("test-hen");
        let profile = load(root, &data);
        let record = json!({"profile_sha256": profile.fingerprint(), "attestation": ATTESTATION,
                            "approved_permissions": ["build"], "build_recipe_sha256_allowlist": recipes});
        fs::write(profile.qualification_path(), record.to_string()).unwrap();
        profile
    }

    fn development(root: &Path, profile: Profile) -> Development {
        let store = Arc::new(ArtifactStore::new(&profile).unwrap());
        let _ = root;
        Development::new(profile, store)
    }

    #[cfg(windows)]
    fn copy_command() -> Vec<&'static str> {
        vec!["cmd", "/C", "copy", "/Y", "README.md", "output.bin"]
    }
    #[cfg(not(windows))]
    fn copy_command() -> Vec<&'static str> {
        vec!["cp", "README.md", "output.bin"]
    }
    #[cfg(windows)]
    fn fail_command() -> Vec<&'static str> {
        vec!["cmd", "/C", "exit", "2"]
    }
    #[cfg(not(windows))]
    fn fail_command() -> Vec<&'static str> {
        vec!["sh", "-c", "echo build failed; exit 2"]
    }
    #[cfg(windows)]
    fn print_command() -> Vec<&'static str> {
        vec!["cmd", "/C", "type", "README.md"]
    }
    #[cfg(not(windows))]
    fn print_command() -> Vec<&'static str> {
        vec!["cat", "README.md"]
    }
    #[cfg(windows)]
    fn sleep_command() -> Vec<&'static str> {
        vec!["ping", "-n", "30", "127.0.0.1"]
    }
    #[cfg(not(windows))]
    fn sleep_command() -> Vec<&'static str> {
        vec!["sleep", "30"]
    }

    /// Scaffold a project, write the recipe and qualify its digest.
    fn recipe(
        fixture: &Fixture,
        commands: Vec<Vec<&str>>,
        output: &str,
        timeout: u64,
        log_bytes: u64,
    ) -> (Development, String, String) {
        let unqualified = development(&fixture.root, load(&fixture.root, &base_settings()));
        let scaffold = unqualified.scaffold("homebrew", "sample").unwrap();
        let relative = scaffold["recipe"].as_str().unwrap().to_string();
        let content =
            json!({"sdk": "homebrew", "source_commit": "a".repeat(40), "commands": commands,
                             "environment": {}, "output": output, "timeout_seconds": timeout})
            .to_string();
        fs::write(unqualified.store.path(&relative).unwrap(), &content).unwrap();
        let digest = sha256_hex(content.as_bytes());
        let profile = qualified(&fixture.root, log_bytes, std::slice::from_ref(&digest));
        (development(&fixture.root, profile), relative, digest)
    }

    #[test]
    fn scaffold_is_not_a_ready_binary_and_never_overwrites() {
        let fixture = fixture();
        let development = development(&fixture.root, load(&fixture.root, &base_settings()));
        let result = development.scaffold("plugin", "my-plugin").unwrap();
        assert_eq!(result["ready_to_build"], json!(false));
        assert_eq!(result["project"], json!("projects/my-plugin"));
        let recipe: Value = serde_json::from_slice(
            &development
                .store
                .read(result["recipe"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(recipe["sdk"], json!("plugin"));
        assert!(
            development
                .scaffold("plugin", "my-plugin")
                .unwrap_err()
                .to_string()
                .contains("exists")
        );
        for name in ["../bad", "1bad", "", "a/b", &"a".repeat(65)] {
            assert!(development.scaffold("homebrew", name).is_err(), "{name}");
        }
        assert!(development.scaffold("kernel", "ok").is_err());
    }

    #[test]
    fn status_reports_sdks_without_claiming_compatibility() {
        let fixture = fixture();
        let development = development(&fixture.root, load(&fixture.root, &base_settings()));
        let status = development.status().unwrap();
        assert_eq!(
            status["sdks"]["payload"]["runtime_14_00_verified"],
            json!(false)
        );
        assert!(status["sdks"]["homebrew"].get("configured_path").is_some());
        assert!(status["executables"].get("git").is_some());
    }

    #[test]
    fn build_requires_permission_and_qualification() {
        let fixture = fixture();
        let development = development(&fixture.root, load(&fixture.root, &base_settings()));
        assert!(
            development
                .build("projects/x/recipe.json", &"a".repeat(64))
                .unwrap_err()
                .to_string()
                .contains("Disabled")
        );
    }

    #[test]
    fn build_runs_locally_and_never_deploys() {
        let fixture = fixture();
        let (development, recipe, digest) =
            recipe(&fixture, vec![copy_command()], "output.bin", 30, 1_048_576);
        let result = development.build(&recipe, &digest).unwrap();
        assert_eq!(result["deployed"], json!(false));
        assert_eq!(result["hardware_verified"], json!(false));
        let built = development
            .store
            .read(result["artifact"]["path"].as_str().unwrap())
            .unwrap();
        assert!(String::from_utf8_lossy(&built).starts_with("# sample"));
        let audit = fs::read_to_string(development.store.path("audit.jsonl").unwrap()).unwrap();
        assert!(audit.contains("build_intent") && audit.contains("build_result"));
        assert!(
            development
                .build(&recipe, &digest)
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
    }

    #[test]
    fn build_hash_change_blocks_execution() {
        let fixture = fixture();
        let (development, recipe, digest) =
            recipe(&fixture, vec![copy_command()], "output.bin", 30, 1_048_576);
        fs::write(development.store.path(&recipe).unwrap(), "{}").unwrap();
        assert!(
            development
                .build(&recipe, &digest)
                .unwrap_err()
                .to_string()
                .contains("SHA-256")
        );
        assert!(development.store.path("audit.jsonl").is_err());
    }

    #[test]
    fn build_failure_archives_log() {
        let fixture = fixture();
        let (development, recipe, digest) =
            recipe(&fixture, vec![fail_command()], "output.bin", 30, 1_048_576);
        assert!(
            development
                .build(&recipe, &digest)
                .unwrap_err()
                .to_string()
                .contains("Build failed")
        );
        let audit = fs::read_to_string(development.store.path("audit.jsonl").unwrap()).unwrap();
        assert!(audit.contains("build_failure"));
    }

    #[test]
    fn build_output_must_stay_in_project() {
        let fixture = fixture();
        for output in ["../escape.bin", ".", "/tmp/abs.bin"] {
            let fixture = self::fixture();
            let (development, recipe, digest) =
                recipe(&fixture, vec![copy_command()], output, 30, 1_048_576);
            assert!(
                development
                    .build(&recipe, &digest)
                    .unwrap_err()
                    .to_string()
                    .contains("inside project"),
                "{output}"
            );
        }
        drop(fixture);
    }

    #[test]
    fn build_output_cannot_be_stale() {
        let fixture = fixture();
        let (development, recipe, digest) =
            recipe(&fixture, vec![copy_command()], "output.bin", 30, 1_048_576);
        let output = development
            .store
            .path(&recipe)
            .unwrap()
            .parent()
            .unwrap()
            .join("output.bin");
        fs::write(output, b"stale").unwrap();
        assert!(
            development
                .build(&recipe, &digest)
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
    }

    #[test]
    fn build_log_limit_terminates_command() {
        let fixture = fixture();
        let (development, recipe, digest) =
            recipe(&fixture, vec![print_command()], "output.bin", 30, 16);
        assert!(
            development
                .build(&recipe, &digest)
                .unwrap_err()
                .to_string()
                .contains("Build failed")
        );
        let entries = development.store.inventory().unwrap();
        let logs: Vec<&Value> = entries
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["id"].as_str().unwrap().starts_with("build-log-"))
            .collect();
        assert_eq!(logs[0]["size"], json!(16));
    }

    #[test]
    fn build_deadline_terminates_command() {
        let fixture = fixture();
        let (development, recipe, digest) =
            recipe(&fixture, vec![sleep_command()], "output.bin", 1, 1_048_576);
        let started = Instant::now();
        assert!(
            development
                .build(&recipe, &digest)
                .unwrap_err()
                .to_string()
                .contains("Build failed")
        );
        assert!(started.elapsed() < Duration::from_secs(15));
    }

    #[test]
    fn recipe_validation() {
        let base = json!({"sdk": "homebrew", "source_commit": "a".repeat(40), "commands": [["x"]],
                          "environment": {}, "output": "o.bin", "timeout_seconds": 5});
        assert!(parse_recipe(base.to_string().as_bytes()).is_ok());
        let cases: Vec<(&str, Value, &str)> = vec![
            ("sdk", json!("other"), "Unknown SDK"),
            ("source_commit", Value::Null, "Pin"),
            ("commands", json!([]), "1 to 16"),
            ("commands", json!(vec![vec!["x"]; 17]), "1 to 16"),
            ("commands", json!(["x y"]), "argv"),
            ("commands", json!([[]]), "argv"),
            ("environment", json!({"A": 1}), "environment"),
            ("environment", Value::Null, "environment"),
            ("timeout_seconds", json!(601), "build timeout"),
            ("timeout_seconds", json!(1.5), "build timeout"),
            ("output", Value::Null, "output"),
        ];
        for (key, value, expected) in cases {
            let mut recipe = base.clone();
            recipe[key] = value;
            let error = parse_recipe(recipe.to_string().as_bytes())
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains(expected), "{key}: {error}");
        }
        assert!(parse_recipe(b"[]").is_err());
    }

    #[test]
    fn batch_files_are_refused() {
        let fixture = fixture();
        let script = fixture.root.join("evil.cmd");
        fs::write(&script, "@echo off").unwrap();
        let found = which(script.to_str().unwrap(), None);
        let refused = found.is_none_or(|path| {
            path.to_string_lossy()
                .to_ascii_lowercase()
                .ends_with(".cmd")
        });
        assert!(refused);
    }
}
