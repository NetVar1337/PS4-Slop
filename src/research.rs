//! Build-bound typed research, project contracts, diagnostics and SDK views.
use crate::{Result, artifacts::ArtifactStore, tools::ToolRegistry};
use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const FORMAT: &str = "ps4wb-research-v1";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Hypothesis,
    StaticSupported,
    LiveValidated,
    Rejected,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    ModuleRva,
    ObjectMember,
    VtableSlot,
    PointerChain,
    FunctionAbi,
    Enum,
    Constant,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub artifact: String,
    pub sha256: String,
    pub kind: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Abi {
    pub calling_convention: String,
    pub returns: String,
    pub arguments: Vec<String>,
    pub thread: String,
    pub lifetime: String,
    #[serde(default)]
    pub is_method: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub module_sha256: String,
    pub kind: Kind,
    pub state: State,
    pub value: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub data_type: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub indirection: Vec<String>,
    #[serde(default)]
    pub abi: Option<Abi>,
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub enum_values: BTreeMap<String, i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feature {
    pub bit: u32,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcField {
    pub name: String,
    pub index: u32,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub default: Value,
    #[serde(default)]
    pub minimum: Option<Value>,
    #[serde(default)]
    pub maximum: Option<Value>,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub description: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub title_id: String,
    pub app_version: String,
    pub module_sha256: String,
    pub engine: String,
    pub sdk: String,
    pub source_commit: String,
    pub repository: String,
    pub staging: String,
    pub rpc_version: u32,
    #[serde(default)]
    pub features: BTreeMap<String, Feature>,
    #[serde(default)]
    pub bindings: BTreeMap<String, String>,
    #[serde(default)]
    pub config: Vec<RpcField>,
    #[serde(default)]
    pub telemetry: Vec<RpcField>,
}
#[derive(Serialize, Deserialize)]
struct Research {
    format: String,
    revision: u64,
    manifest: Option<Manifest>,
    findings: BTreeMap<String, Finding>,
}
impl Default for Research {
    fn default() -> Self {
        Self {
            format: FORMAT.into(),
            revision: 0,
            manifest: None,
            findings: BTreeMap::new(),
        }
    }
}
pub fn cpp_type(name: &str) -> Option<&'static str> {
    Some(match name {
        "void" => "void",
        "bool" => "bool",
        "u8" => "std::uint8_t",
        "i8" => "std::int8_t",
        "u16" => "std::uint16_t",
        "i16" => "std::int16_t",
        "u32" => "std::uint32_t",
        "i32" => "std::int32_t",
        "u64" => "std::uint64_t",
        "i64" => "std::int64_t",
        "f32" => "float",
        "f64" => "double",
        "pointer" => "std::uintptr_t",
        _ => return None,
    })
}
fn type_size(name: &str) -> u64 {
    match name {
        "bool" | "u8" | "i8" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" | "pointer" => 8,
        _ => 0,
    }
}
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 96 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}
fn validate_finding(store: &ArtifactStore, finding: &Finding) -> Result<()> {
    ensure!(valid_id(&finding.id), "Invalid finding id");
    crate::config::require_hash(&finding.module_sha256, "module_sha256")?;
    crate::tools::address(&json!(finding.value))?;
    ensure!(
        finding.notes.len() <= 4096 && finding.owner.len() <= 128,
        "Finding text too long"
    );
    ensure!(
        (1..=64).contains(&finding.evidence.len()),
        "Findings need 1-64 evidence artifacts"
    );
    for evidence in &finding.evidence {
        ensure!(
            [
                "decompilation",
                "trace",
                "memory",
                "hardware",
                "layout",
                "diff"
            ]
            .contains(&evidence.kind.as_str()),
            "Unknown evidence kind"
        );
        let bytes = store.read_bounded(&evidence.artifact, crate::bytesource::ARTIFACT_MAX)?;
        ensure!(
            crate::config::sha256_hex(&bytes) == evidence.sha256,
            "Evidence changed: {}",
            evidence.artifact
        );
    }
    if finding.state == State::LiveValidated {
        ensure!(
            finding.evidence.iter().any(|e| e.kind == "hardware"),
            "Live validation requires a hardware evidence record (user attestation, not automatic certification)"
        );
    }
    ensure!(
        finding.indirection.len() <= 16,
        "Pointer chain exceeds 16 steps"
    );
    for offset in &finding.indirection {
        crate::tools::address(&json!(offset))?;
    }
    if finding.kind == Kind::PointerChain {
        ensure!(!finding.indirection.is_empty(), "Pointer chain needs steps");
    }
    if finding.kind == Kind::ObjectMember || finding.kind == Kind::Constant {
        ensure!(
            (finding.kind != Kind::ObjectMember || !finding.owner.is_empty())
                && type_size(&finding.data_type) == finding.size
                && finding.size > 0,
            "Member/constant needs an exact supported type/size; members also need an owner"
        );
    }
    if finding.kind == Kind::FunctionAbi {
        let abi = finding.abi.as_ref().context("Function needs ABI")?;
        ensure!(
            abi.calling_convention == "sysv_amd64" && cpp_type(&abi.returns).is_some(),
            "Unsupported calling convention/return type"
        );
        ensure!(
            abi.arguments.len() <= 16
                && abi
                    .arguments
                    .iter()
                    .all(|a| a != "void" && cpp_type(a).is_some()),
            "Unsupported ABI arguments"
        );
        ensure!(
            !abi.thread.trim().is_empty() && !abi.lifetime.trim().is_empty(),
            "ABI needs calling thread and lifetime evidence"
        );
        if abi.is_method {
            ensure!(
                abi.arguments.first().is_some_and(|a| a == "pointer"),
                "Method ABI must include explicit this pointer"
            );
        }
    }
    ensure!(
        finding.enum_values.len() <= 4096 && finding.enum_values.keys().all(|k| valid_id(k)),
        "Invalid enum values"
    );
    Ok(())
}
fn path(store: &ArtifactStore, project: &str) -> Result<std::path::PathBuf> {
    store.new_path(&format!("project-index/{project}/research.json"))
}
fn load(store: &ArtifactStore, project: &str) -> Result<Research> {
    let path = path(store, project)?;
    if !path.exists() {
        return Ok(Research::default());
    }
    let bytes = crate::workbench::read_bounded(&path, 16 << 20)?;
    let state: Research = serde_json::from_slice(&bytes)?;
    ensure!(state.format == FORMAT, "Unsupported research state");
    if let Some(manifest) = &state.manifest {
        validate_manifest(manifest)?;
    }
    Ok(state)
}
/// The registered project manifest, if any (used by game tooling to derive
/// engine/repository defaults without mutating state).
pub(crate) fn manifest_of(store: &ArtifactStore, project: &str) -> Result<Option<Manifest>> {
    Ok(load(store, project)?.manifest)
}
fn save(store: &ArtifactStore, project: &str, state: &mut Research) -> Result<()> {
    ensure!(state.findings.len() <= 10_000, "Too many findings");
    state.revision += 1;
    let bytes = serde_json::to_vec_pretty(state)?;
    ensure!(bytes.len() <= 16 << 20, "Research state exceeds 16 MiB");
    // Immutable snapshots provide revision history; replace only the current pointer file.
    store.save(
        "research",
        &bytes,
        json!({"project":project,"revision":state.revision}),
        "json",
    )?;
    let file = path(store, project)?;
    let temp = file.with_extension(format!("next-{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&temp, &bytes)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&temp)?
        .sync_all()?;
    std::fs::rename(&temp, &file)?;
    store.audit(
        "research_update",
        json!({"project":project,"revision":state.revision}),
    )?;
    Ok(())
}
fn validate_manifest(manifest: &Manifest) -> Result<()> {
    ensure!(
        manifest.format == "ps4wb-project-v1",
        "Unsupported manifest"
    );
    ensure!(
        !manifest.title_id.is_empty() && !manifest.app_version.is_empty(),
        "Manifest needs title/version"
    );
    crate::config::require_hash(&manifest.module_sha256, "module_sha256")?;
    ensure!(
        crate::config::is_lower_hex(&manifest.source_commit, 40),
        "Pin source_commit to 40 lowercase hex characters"
    );
    ensure!(
        ["unreal", "source", "generic"].contains(&manifest.engine.as_str()),
        "Unknown engine"
    );
    ensure!(
        ["openorbis", "payload"].contains(&manifest.sdk.as_str()),
        "Unknown SDK"
    );
    ensure!(
        ["immediate", "elf_rpc"].contains(&manifest.staging.as_str()) && manifest.rpc_version == 1,
        "Unsupported staging/RPC contract"
    );
    ensure!(
        std::path::Path::new(&manifest.repository).is_absolute(),
        "Repository path must be absolute"
    );
    let mut bits = BTreeSet::new();
    for (name, feature) in &manifest.features {
        ensure!(
            valid_id(name) && feature.bit.is_power_of_two() && bits.insert(feature.bit),
            "Feature bits must be unique powers of two"
        );
        ensure!(
            feature.requires.len() <= 128 && feature.dependencies.len() <= 32,
            "Too many feature dependencies"
        );
        for dependency in &feature.dependencies {
            ensure!(
                manifest.features.contains_key(dependency),
                "Unknown feature dependency {dependency}"
            );
        }
    }
    fn visit(
        name: &str,
        features: &BTreeMap<String, Feature>,
        stack: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
    ) -> Result<()> {
        if done.contains(name) {
            return Ok(());
        }
        ensure!(
            stack.insert(name.into()),
            "Feature dependency cycle at {name}"
        );
        ensure!(stack.len() <= 32, "Feature graph too deep");
        for next in &features[name].dependencies {
            visit(next, features, stack, done)?;
        }
        stack.remove(name);
        done.insert(name.into());
        Ok(())
    }
    let mut done = BTreeSet::new();
    for name in manifest.features.keys() {
        visit(name, &manifest.features, &mut BTreeSet::new(), &mut done)?;
    }
    ensure!(
        manifest.bindings.len() <= 32 && manifest.bindings.keys().all(|k| valid_id(k)),
        "Invalid engine bindings"
    );
    fn validate_rpc(fields: &[RpcField], maximum: u32, telemetry: bool) -> Result<()> {
        let mut indices = BTreeSet::new();
        for field in fields {
            ensure!(valid_id(&field.name) && field.index < maximum && indices.insert(field.index),
                "Invalid or duplicate RPC field");
            ensure!(["bool", "u64", "i64", "f32", "f64"].contains(&field.kind.as_str()),
                "Unsupported RPC field type");
            ensure!(field.role.is_empty() || (telemetry && field.role == "active_features"),
                "Unsupported RPC field role");
            for value in std::iter::once(&field.default).chain(field.minimum.iter().chain(field.maximum.iter())) {
                match field.kind.as_str() {
                    "bool" => ensure!(value.is_boolean(), "Boolean RPC values must be JSON booleans"),
                    "f32" | "f64" => ensure!(value.is_number(), "Float RPC values must be JSON numbers"),
                    _ => ensure!(value.is_number() || value.is_string(), "Integer RPC values must be numbers or strings"),
                }
            }
            if field.kind == "bool" {
                ensure!(field.minimum.is_none() && field.maximum.is_none(), "Boolean RPC fields cannot have ranges");
            }
        }
        Ok(())
    }
    validate_rpc(&manifest.config, 32, false)?;
    validate_rpc(&manifest.telemetry, 16, true)?;
    Ok(())
}

fn write_generated_set(output: &std::path::Path, files: &BTreeMap<String, Vec<u8>>, module_sha256: &str) -> Result<(Value, Vec<Value>)> {
    let marker_path = output.join("install.json");
    let mut previous = BTreeMap::new();
    for name in files.keys().chain([&"install.json".to_owned()]) {
        let path = output.join(name);
        previous.insert(name.clone(), path.is_file().then(|| std::fs::read(&path)).transpose()?);
    }
    let installed: Vec<Value> = files.iter().map(|(name, bytes)| {
        json!({"file":name,"sha256":crate::config::sha256_hex(bytes)})
    }).collect();
    let marker = serde_json::to_vec_pretty(&json!({
        "format":"ps4wb-installed-v1","module_sha256":module_sha256,"files":installed,
    }))?;
    let write_atomic = |path: &std::path::Path, bytes: &[u8]| -> Result<()> {
        let temp = path.with_extension(format!("ps4wb-{}.tmp", uuid::Uuid::new_v4().simple()));
        std::fs::write(&temp, bytes)?;
        if let Err(error) = std::fs::rename(&temp, path) {
            let _ = std::fs::remove_file(&temp);
            return Err(error.into());
        }
        Ok(())
    };
    let outcome = (|| -> Result<()> {
        for (name, bytes) in files {
            write_atomic(&output.join(name), bytes)?;
        }
        // The hash manifest is the commit record and is always published last.
        write_atomic(&marker_path, &marker)?;
        Ok(())
    })();
    if let Err(error) = outcome {
        for (name, old) in previous {
            let path = output.join(name);
            if let Some(bytes) = old {
                let _ = std::fs::write(path, bytes);
            } else {
                let _ = std::fs::remove_file(path);
            }
        }
        return Err(error).context("Generated install failed; previous files were restored where possible");
    }
    Ok((serde_json::from_slice(&marker)?, installed))
}

fn install(
    registry: &ToolRegistry,
    project: &str,
    state: &Research,
    args: &Value,
) -> Result<Value> {
    let manifest = state
        .manifest
        .as_ref()
        .context("Register a project manifest before installing generated code")?;
    let store = &registry.workbench.store;
    let root = crate::config::resolve_lenient(std::path::Path::new(&manifest.repository))?;
    ensure!(root.is_dir(), "Project repository missing");
    let descriptor_path = root.join("workbench.json");
    let descriptor: Value = if descriptor_path.is_file() {
        serde_json::from_slice(&crate::workbench::read_bounded(&descriptor_path, 64 << 10)?)?
    } else {
        Value::Null
    };
    let directory = descriptor["generated_directory"].as_str().unwrap_or(
        if root.join("payload/include/apex").is_dir() {
            "payload/include/apex/generated"
        } else {
            "src/generated"
        },
    );
    let output = crate::config::resolve_lenient(&root.join(directory))?;
    ensure!(
        output.starts_with(&root) && output != root,
        "Generated directory escapes registered repository"
    );
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    let mut engine_namespace = String::from("game");
    for (argument, file) in [("engine", "engine.hpp"), ("offsets", "offsets.hpp")] {
        if let Some(path) = args[argument].as_str() {
            let bytes = store.read_bounded(path, 16 << 20)?;
            ensure!(
                bytes.starts_with(b"// Generated"),
                "Only generated headers may be installed"
            );
            let sidecar: Value =
                serde_json::from_slice(&store.read_bounded(&format!("{path}.json"), 1 << 20)?)?;
            ensure!(
                sidecar["metadata"]["module_sha256"] == manifest.module_sha256
                    && sidecar["sha256"] == crate::config::sha256_hex(&bytes),
                "Generated header belongs to another build or changed: {path}"
            );
            if argument == "engine" {
                engine_namespace = sidecar["metadata"]["namespace"]
                    .as_str()
                    .unwrap_or("game")
                    .to_owned();
                ensure!(
                    crate::sdkgen::safe_ident(&engine_namespace) == engine_namespace,
                    "Invalid generated engine namespace"
                );
            }
            files.insert(file.into(), bytes);
        }
    }
    let target_path = args["target"]
        .as_str()
        .context("project_install needs a verified target manifest")?;
    let target_bytes = store.read_bounded(target_path, 1 << 20)?;
    let target: Value = serde_json::from_slice(&target_bytes)?;
    ensure!(
        target["format"] == "ps4wb-internals-target-v1"
            && target["module_sha256"] == manifest.module_sha256
            && target["title_id"] == manifest.title_id,
        "Target build/title does not match project contract"
    );
    let base = crate::tools::address(&target["image_base"])?;
    let checks = target["fingerprints"]
        .as_array()
        .context("Target needs fingerprints")?;
    ensure!(
        !checks.is_empty() && checks.len() <= 64,
        "Target needs 1-64 checks"
    );
    let mut header = format!(
        "// Generated by project_install; do not edit.\n#pragma once\n#include <internals/verify.hpp>\nnamespace target {{\ninline constexpr std::uintptr_t kModuleBase = {base:#x};\ninline constexpr internals::VerifyCheck kVerifyChecks[] = {{\n"
    );
    for check in checks {
        let address = crate::tools::address(&check["address"])?;
        let rva = address
            .checked_sub(base)
            .context("Fingerprint below image base")?;
        let bytes = hex::decode(check["hex"].as_str().context("Missing fingerprint bytes")?)?;
        ensure!(
            (1..=32).contains(&bytes.len()),
            "Resident fingerprints need 1-32 bytes"
        );
        header.push_str(&format!(
            "{{ {rva:#x}, {}, {{ {} }} }},\n",
            bytes.len(),
            bytes
                .iter()
                .map(|b| format!("0x{b:02x}"))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    header.push_str("};\ninline constexpr std::size_t kVerifyCheckCount = sizeof(kVerifyChecks) / sizeof(kVerifyChecks[0]);\n}\n");
    files.insert("target.hpp".into(), header.into_bytes());
    let research = export(store, project, state)?;
    files.insert(
        "research.hpp".into(),
        store.read_bounded(research["header"]["path"].as_str().unwrap(), 16 << 20)?,
    );
    let mut feature_gate = String::from("// Generated by project_install; do not edit.\n#pragma once\n#include <cstdint>\n#include \"research.hpp\"\nnamespace features {\ninline constexpr std::uint32_t kEvidenceMask = research::kAvailableFeatures;\ninline bool dependencies_satisfied(std::uint32_t requested) noexcept {\n");
    for feature in manifest.features.values() {
        let required = feature.dependencies.iter().filter_map(|name| manifest.features.get(name))
            .fold(0u32, |mask, dependency| mask | dependency.bit);
        if required != 0 {
            feature_gate.push_str(&format!("    if ((requested & {:#x}) != 0 && (requested & {required:#x}) != {required:#x}) return false;\n", feature.bit));
        }
    }
    feature_gate.push_str("    return true;\n}\n}\n");
    files.insert("feature_dependencies.hpp".into(), feature_gate.into_bytes());
    let mut config = String::from("// Generated by project_install; do not edit.\n#pragma once\n#include \"research.hpp\"\n");
    if manifest.engine == "unreal" && files.contains_key("engine.hpp") {
        config.push_str("#include \"engine.hpp\"\n");
        if engine_namespace != "game" {
            config.push_str(&format!(
                "namespace game {{ using ::{engine_namespace}::kUe4Offsets; }}\n"
            ));
        }
        config.push_str("#define PS4WB_ENGINE_UNREAL 1\n");
    }
    if manifest.engine == "source" {
        config.push_str("#include <internals/source.hpp>\nnamespace game { inline constexpr source::EntityLayout kEntityLayout = {\n");
        let mut values = Vec::new();
        for binding in [
            "entity_slots",
            "entity_count",
            "entity_stride",
            "entity_pointer",
            "entity_serial",
        ] {
            let finding = manifest
                .bindings
                .get(binding)
                .and_then(|id| state.findings.get(id))
                .filter(|f| {
                    f.state == State::LiveValidated && f.module_sha256 == manifest.module_sha256
                });
            values.push(finding.map(|f| f.value.as_str()).unwrap_or("0"));
        }
        config.push_str(&values.join(","));
        config.push_str("}; }\n#define PS4WB_ENGINE_SOURCE 1\n");
    }
    config.push_str("namespace game::bindings {\n");
    for (name, id) in &manifest.bindings {
        let binding = crate::sdkgen::ident(name);
        let finding = state.findings.get(id).filter(|finding| finding.module_sha256 == manifest.module_sha256);
        let available = finding.is_some_and(|finding| finding.state == State::LiveValidated);
        if finding.is_some() {
            config.push_str(&format!("inline constexpr bool {binding}_available = research::{}_available;\n", crate::sdkgen::ident(id)));
        } else {
            config.push_str(&format!("inline constexpr bool {binding}_available = false;\n"));
        }
        if available {
            config.push_str(&format!("inline constexpr std::uintptr_t {binding} = research::{};\n", crate::sdkgen::ident(id)));
        } else {
            config.push_str(&format!("inline constexpr std::uintptr_t {binding} = 0;\n"));
        }
    }
    config.push_str("}\n");
    files.insert("engine_config.hpp".into(), config.into_bytes());
    let rpc = json!({
        "format":"ps4wb-rpc-v1","rpc_version":manifest.rpc_version,
        "module_sha256":manifest.module_sha256,
        "features":manifest.features.iter().map(|(name, feature)| json!({"name":name,"bit":feature.bit})).collect::<Vec<_>>(),
        "config":manifest.config,"telemetry":manifest.telemetry,
    });
    files.insert("rpc.json".into(), serde_json::to_vec_pretty(&rpc)?);
    files.insert("manifest.json".into(), serde_json::to_vec_pretty(manifest)?);
    // Preflight every destination before writing any file. A manifest records
    // ownership; user-authored files are never silently overwritten.
    for (name, bytes) in &files {
        let path = crate::config::resolve_lenient(&output.join(name))?;
        ensure!(
            path.starts_with(&output),
            "Generated file escapes directory"
        );
        if path.exists() {
            let old = crate::workbench::read_bounded(&path, 16 << 20)?;
            ensure!(
                old == *bytes
                    || old.starts_with(b"// Generated")
                    || old.starts_with(b"#pragma once\n// Generated")
                    || name == "manifest.json"
                    || name == "rpc.json"
                    || (name == "target.hpp"
                        && old == include_bytes!("../templates/payload/target.hpp")),
                "Refusing to overwrite user-authored file {}",
                path.display()
            );
        }
    }
    std::fs::create_dir_all(&output)?;
    let (install_manifest, installed) = write_generated_set(&output, &files, &manifest.module_sha256)?;
    store.audit(
        "project_install",
        json!({"project":project,"directory":output,"files":installed}),
    )?;
    Ok(
        json!({"directory":output,"files":installed,"install_manifest":install_manifest,"module_sha256":manifest.module_sha256,"deployed":false}),
    )
}
fn report(store: &ArtifactStore, state: &Research) -> Value {
    let mut blockers = Vec::new();
    let Some(manifest) = &state.manifest else {
        return json!({"ready":false,"blockers":["No project manifest"],"revision":state.revision});
    };
    let mut valid = BTreeSet::new();
    for (id, finding) in &state.findings {
        match validate_finding(store, finding) {
            Ok(())
                if finding.module_sha256 == manifest.module_sha256
                    && finding.state == State::LiveValidated =>
            {
                valid.insert(id.clone());
            }
            Ok(()) => {}
            Err(error) => blockers.push(json!({"finding":id,"reason":error.to_string()})),
        }
    }
    let mut features = BTreeMap::new();
    fn available(
        name: &str,
        manifest: &Manifest,
        valid: &BTreeSet<String>,
        memo: &mut BTreeMap<String, bool>,
    ) -> bool {
        if let Some(value) = memo.get(name) {
            return *value;
        }
        let feature = &manifest.features[name];
        let ready = feature.requires.iter().all(|r| valid.contains(r))
            && feature
                .dependencies
                .iter()
                .all(|d| available(d, manifest, valid, memo));
        memo.insert(name.into(), ready);
        ready
    }
    let mut mask = 0u32;
    let mut memo = BTreeMap::new();
    for (name, feature) in &manifest.features {
        let ready = available(name, manifest, &valid, &mut memo);
        if ready {
            mask |= feature.bit;
        }
        let missing: Vec<_> = feature
            .requires
            .iter()
            .filter(|r| !valid.contains(*r))
            .collect();
        features.insert(name.clone(), json!({"available":ready,"bit":feature.bit,"missing_findings":missing,"dependencies":feature.dependencies}));
    }
    json!({"ready":blockers.is_empty(),"revision":state.revision,"module_sha256":manifest.module_sha256,"features":features,"available_features":format!("{mask:#x}"),"blockers":blockers,"hardware_verified":false,"validation_basis":"user-recorded evidence; artifact integrity checked, hardware claims not independently certified"})
}
fn export(store: &ArtifactStore, project: &str, state: &Research) -> Result<Value> {
    let manifest = state
        .manifest
        .as_ref()
        .context("Register a project manifest first")?;
    let report = report(store, state);
    ensure!(
        report["ready"] == true,
        "Evidence integrity check failed: {}",
        report["blockers"]
    );
    let mut out = String::from(
        "// Generated by project_research_export; do not edit.\n#pragma once\n#include <cstdint>\n#include <internals/memory.hpp>\nnamespace research {\n",
    );
    out.push_str(&format!("inline constexpr const char* kModuleSha256 = \"{}\";\ninline constexpr std::uint32_t kAvailableFeatures = {};\n", manifest.module_sha256, report["available_features"].as_str().unwrap_or("0x0")));
    let mut prototypes = Vec::new();
    for finding in state
        .findings
        .values()
        .filter(|f| f.module_sha256 == manifest.module_sha256)
    {
        let name = crate::sdkgen::ident(&finding.id);
        let value = crate::tools::address(&json!(finding.value))?;
        let enabled = finding.state == State::LiveValidated;
        out.push_str(&format!(
            "inline constexpr bool {name}_available = {enabled};\n"
        ));
        if !enabled {
            continue;
        }
        out.push_str(&format!(
            "inline constexpr std::uintptr_t {name} = {value:#x};\n"
        ));
        match finding.kind {
            Kind::ObjectMember => {
                let kind = cpp_type(&finding.data_type).context("Unsupported member type")?;
                out.push_str(&format!("inline bool read_{name}(internals::MemoryReader reader, std::uintptr_t object, {kind}& out) noexcept {{ return object && object <= UINTPTR_MAX - {name} && reader.Get(object + {name}, out); }}\n"));
            }
            Kind::FunctionAbi => {
                let abi = finding.abi.as_ref().context("Missing ABI")?;
                let params: Vec<_> = abi.arguments.iter().map(|a| cpp_type(a).unwrap()).collect();
                // Type aliases support analysis/application without silently calling on the wrong thread.
                out.push_str(&format!(
                    "using {name}_fn = {} (*)({});\n",
                    cpp_type(&abi.returns).unwrap(),
                    params.join(", ")
                ));
                let c_type = |kind: &str| cpp_type(kind).unwrap().replace("std::", "");
                let params: Vec<_> = abi
                    .arguments
                    .iter()
                    .enumerate()
                    .map(|(i, a)| format!("{} arg{i}", c_type(a)))
                    .collect();
                prototypes.push(json!({"name":name,"rva":finding.value,"declaration":format!("{} {name}({})",c_type(&abi.returns),if params.is_empty(){"void".into()}else{params.join(", ")}),"calling_convention":abi.calling_convention,"thread":abi.thread,"lifetime":abi.lifetime,"evidence":finding.evidence}));
            }
            Kind::PointerChain => {
                out.push_str(&format!("inline bool resolve_{name}(internals::MemoryReader reader, std::uintptr_t base, std::uintptr_t& out) noexcept {{ if (base > UINTPTR_MAX - {name}) return false; std::uintptr_t at = base + {name};\n"));
                for step in &finding.indirection {
                    let offset = crate::tools::address(&json!(step))?;
                    out.push_str(&format!("    if (!reader.Get(at, at) || !at || at > UINTPTR_MAX - {offset:#x}) return false; at += {offset:#x};\n"));
                }
                out.push_str("    out = at; return true; }\n");
            }
            Kind::Enum => {
                out.push_str(&format!("enum class {name}_enum : std::int64_t {{\n"));
                for (key, value) in &finding.enum_values {
                    out.push_str(&format!("{} = {value},\n", crate::sdkgen::ident(key)));
                }
                out.push_str("};\n");
            }
            _ => {}
        }
    }
    out.push_str("}\n");
    let header = store.save(
        "research-sdk",
        out.as_bytes(),
        json!({"project":project,"revision":state.revision,"module_sha256":manifest.module_sha256}),
        "hpp",
    )?;
    let manifest = store.save(
        "project-manifest",
        &serde_json::to_vec_pretty(manifest)?,
        json!({"project":project}),
        "json",
    )?;
    let prototypes = store.save("research-prototypes", &serde_json::to_vec_pretty(&json!({"format":"ps4wb-prototypes-v1","module_sha256":report["module_sha256"],"prototypes":prototypes}))?,json!({"project":project}),"json")?;
    Ok(json!({"header":header,"manifest":manifest,"prototypes":prototypes,"validation":report}))
}

fn collect_build(registry: &ToolRegistry, state: &Research) -> Result<Value> {
    let manifest = state
        .manifest
        .as_ref()
        .context("Register a project manifest first")?;
    let root = crate::config::resolve_lenient(std::path::Path::new(&manifest.repository))?;
    let lock_path = crate::config::resolve_lenient(&root.join("workbench.lock.json"))?;
    ensure!(
        lock_path.starts_with(&root),
        "Build evidence escapes repository"
    );
    let evidence = crate::workbench::read_bounded(&lock_path, 8 << 20)?;
    let lock: Value = serde_json::from_slice(&evidence)?;
    ensure!(
        lock["format"] == "ps4wb-build-lock-v1",
        "Unsupported build lock"
    );
    let inputs = lock["source"]["files"]
        .as_object()
        .context("Build lock lacks source pins")?;
    ensure!(inputs.len() <= 10000, "Too many source pins");
    let mut total = 0usize;
    for (relative, hash) in inputs {
        let path = crate::config::resolve_lenient(&root.join(relative))?;
        ensure!(
            path.starts_with(&root) && path != root,
            "Source pin escapes repository"
        );
        let bytes = crate::workbench::read_bounded(&path, 32 << 20)?;
        total = total
            .checked_add(bytes.len())
            .context("Source size overflow")?;
        ensure!(
            total <= 512 << 20 && crate::config::sha256_hex(&bytes) == *hash,
            "Build source changed: {relative}"
        );
    }
    let output = crate::config::resolve_lenient(std::path::Path::new(
        lock["payload"]["path"]
            .as_str()
            .context("Missing payload path")?,
    ))?;
    ensure!(
        output.starts_with(&root) && output != root,
        "Payload escapes repository"
    );
    let bytes = crate::workbench::read_bounded(
        &output,
        registry.workbench.profile.limit("transfer_bytes"),
    )?;
    let sha = lock["payload"]["sha256"]
        .as_str()
        .context("Missing payload hash")?;
    let image = crate::internals::PayloadImage::parse(&bytes, sha)?;
    let build = registry.workbench.store.save(
        "build-evidence",
        &evidence,
        json!({"module_sha256":manifest.module_sha256}),
        "json",
    )?;
    let payload = registry.workbench.store.save("payload", &bytes, json!({"module_sha256":manifest.module_sha256,"source_commit":manifest.source_commit,"build_evidence":build,"rpc_version":manifest.rpc_version}), "elf")?;
    Ok(
        json!({"payload":payload,"build_evidence":build,"image_entry":format!("{:#x}",image.image_entry),"rpc_symbol":format!("{:#x}",image.rpc_value),"deployed":false,"hardware_verified":false}),
    )
}
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    if name == "payload_scaffold" {
        return Some(crate::scaffold::create(
            &registry.workbench.store,
            args["name"].as_str().unwrap_or(""),
            args["engine"].as_str().unwrap_or("generic"),
        ));
    }
    if ![
        "project_manifest",
        "project_finding",
        "project_doctor",
        "project_research_export",
        "project_install",
        "project_collect_build",
    ]
    .contains(&name)
    {
        return None;
    }
    Some((|| {
        let store = &registry.workbench.store;
        let project = crate::project::resolve_project(store, args)?;
        let mut state = load(store, &project)?;
        match name {
            "project_manifest" => {
                if let Some(value) = args.get("manifest") {
                    let manifest: Manifest = serde_json::from_value(value.clone())?;
                    validate_manifest(&manifest)?;
                    state.manifest = Some(manifest);
                    save(store, &project, &mut state)?;
                }
                Ok(json!({"manifest":state.manifest,"revision":state.revision}))
            }
            "project_finding" => {
                if let Some(value) = args.get("finding") {
                    let finding: Finding = serde_json::from_value(value.clone())?;
                    validate_finding(store, &finding)?;
                    if let Some(manifest) = &state.manifest {
                        ensure!(
                            finding.module_sha256 == manifest.module_sha256,
                            "Finding belongs to a different build"
                        );
                    }
                    state.findings.insert(finding.id.clone(), finding);
                    save(store, &project, &mut state)?;
                }
                if let Some(id) = args["id"].as_str() {
                    return Ok(json!({"finding":state.findings.get(id),"revision":state.revision}));
                }
                Ok(json!({"findings":state.findings,"revision":state.revision}))
            }
            "project_doctor" => Ok(report(store, &state)),
            "project_research_export" => export(store, &project, &state),
            "project_install" => install(registry, &project, &state, args),
            "project_collect_build" => collect_build(registry, &state),
            _ => bail!("Unknown research tool"),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{tools::Toolset, workbench::Workbench};
    #[test]
    fn evidence_feature_gates_exports_and_installation() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = ToolRegistry::with_toolset(
            Workbench::new(crate::artifacts::tests::test_profile(dir.path())).unwrap(),
            Toolset::Full,
        )
        .unwrap();
        registry
            .call(
                "project_open",
                json!({"title_id":"CUSA12345","app_version":"01.00","name":"Game"}),
            )
            .unwrap();
        let repo = dir.path().join("payload");
        std::fs::create_dir(&repo).unwrap();
        let manifest = json!({"format":"ps4wb-project-v1","title_id":"CUSA12345","app_version":"01.00","module_sha256":"a".repeat(64),"engine":"generic","sdk":"openorbis","source_commit":"b".repeat(40),"repository":repo,"staging":"immediate","rpc_version":1,"features":{"diagnostics":{"bit":1,"requires":["health"]},"menu":{"bit":2,"requires":["missing"],"dependencies":["diagnostics"]}},"bindings":{"entity_health":"health"},"config":[{"name":"sensitivity","index":0,"type":"f32","default":1.0,"minimum":0.0,"maximum":10.0}],"telemetry":[{"name":"active_features","index":2,"type":"u64","role":"active_features"}]});
        registry
            .call("project_manifest", json!({"manifest":manifest}))
            .unwrap();
        let evidence = registry
            .workbench
            .store
            .save(
                "hardware-evidence",
                b"User-attested exact-build capture",
                json!({}),
                "txt",
            )
            .unwrap();
        let mut finding = json!({"id":"health","module_sha256":"a".repeat(64),"kind":"object_member","state":"hypothesis","value":"0x30","owner":"Player","data_type":"i32","size":4,"evidence":[{"artifact":evidence["path"],"sha256":evidence["sha256"],"kind":"memory"}]});
        registry
            .call("project_finding", json!({"finding":finding}))
            .unwrap();
        assert_eq!(
            registry.call("project_doctor", json!({})).unwrap()["features"]["diagnostics"]["available"],
            false
        );
        finding["state"] = json!("live_validated");
        assert!(
            registry
                .call("project_finding", json!({"finding":finding}))
                .unwrap_err()
                .to_string()
                .contains("hardware")
        );
        finding["evidence"][0]["kind"] = json!("hardware");
        registry
            .call("project_finding", json!({"finding":finding}))
            .unwrap();
        assert_eq!(
            registry.call("project_doctor", json!({})).unwrap()["available_features"],
            "0x1"
        );
        let sdk = registry.call("project_research_export", json!({})).unwrap();
        let bytes = registry
            .workbench
            .store
            .read(sdk["header"]["path"].as_str().unwrap())
            .unwrap();
        std::fs::write(dir.path().join("research.hpp"), bytes).unwrap();
        crate::test_support::compile_run(
            dir.path(),
            "#include \"research.hpp\"\n#include <cassert>\nint main(){ static_assert(research::wb_health_available); std::int32_t value=0; assert(!research::read_wb_health({},0,value)); static_assert(research::kAvailableFeatures==1); }",
            false,
        );
        let target=registry.workbench.store.save("internals-target",&serde_json::to_vec(&json!({"format":"ps4wb-internals-target-v1","title_id":"CUSA12345","module_sha256":"a".repeat(64),"image_base":"0x400000","fingerprints":[{"address":"0x400100","hex":"9090"}]})).unwrap(),json!({}),"json").unwrap();
        registry
            .call("project_install", json!({"target":target["path"]}))
            .unwrap();
        assert!(repo.join("src/generated/research.hpp").is_file());
        let rpc = std::fs::read_to_string(repo.join("src/generated/rpc.json")).unwrap();
        assert!(rpc.contains("ps4wb-rpc-v1") && rpc.contains("active_features"), "{rpc}");
        let config = std::fs::read_to_string(repo.join("src/generated/engine_config.hpp")).unwrap();
        assert!(config.contains("wb_entity_health_available = research::wb_health_available"), "{config}");
        assert!(config.contains("wb_entity_health = research::wb_health"), "{config}");
        let gate = std::fs::read_to_string(repo.join("src/generated/feature_dependencies.hpp")).unwrap();
        assert!(gate.contains("kEvidenceMask = research::kAvailableFeatures"), "{gate}");
        assert!(gate.contains("(requested & 0x2)"), "{gate}");
        crate::test_support::compile_run(
            &repo,
            "#include \"src/generated/feature_dependencies.hpp\"\n#include \"src/generated/engine_config.hpp\"\nstatic_assert(features::kEvidenceMask==1);\nstatic_assert(game::bindings::wb_entity_health_available);\nint main(){ return features::dependencies_satisfied(2) || !features::dependencies_satisfied(3); }",
            false,
        );
        std::fs::write(repo.join("src/generated/target.hpp"), "// user file").unwrap();
        assert!(
            registry
                .call("project_install", json!({"target":target["path"]}))
                .unwrap_err()
                .to_string()
                .contains("user-authored")
        );
        std::fs::write(
            registry
                .workbench
                .store
                .path(evidence["path"].as_str().unwrap())
                .unwrap(),
            "changed",
        )
        .unwrap();
        assert_eq!(
            registry.call("project_doctor", json!({})).unwrap()["features"]["diagnostics"]["available"],
            false
        );
        assert!(registry.call("project_research_export", json!({})).is_err());
    }
    #[test]
    fn manifest_cycles_and_unsupported_abis_are_rejected() {
        let mut manifest: Manifest=serde_json::from_value(json!({"format":"ps4wb-project-v1","title_id":"CUSA12345","app_version":"1","module_sha256":"a".repeat(64),"engine":"generic","sdk":"payload","source_commit":"b".repeat(40),"repository":std::env::temp_dir(),"staging":"immediate","rpc_version":1,"features":{"a":{"bit":1,"dependencies":["a"]}}})).unwrap();
        assert!(validate_manifest(&manifest).is_err());
        manifest.features.clear();
        assert!(validate_manifest(&manifest).is_ok());
    }
}
