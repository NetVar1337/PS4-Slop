use crate::Result;
use crate::agents::{AnalysisAgents, JOB_TIMEOUT};
use crate::artifacts::utc_now;
use crate::config::{Profile, python_json, require_integer};
use crate::tools::ToolRegistry;
use anyhow::{anyhow, bail};
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rand::RngCore;
use serde_json::{Map, Value, json};
use std::collections::VecDeque;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

pub const MAX_BODY: usize = 1_048_576;
pub const JOURNAL_CAPACITY: usize = 1024;
pub const MAX_CONNECTIONS: usize = 32;
pub const MAX_INLINE_RESULT: usize = 24_576;
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
pub const PUMP_INTERVAL: Duration = Duration::from_millis(50);
pub const CONTROL_TOOLS: &[&str] = &[
    "debug_attach",
    "debug_control",
    "debug_breakpoint",
    "debug_watchpoint",
    "memory_write",
    "kernel_write",
    "debug_detach",
    "debug_step",
    "debug_run",
    "debug_registers_set",
    "debug_registers_fpu_set",
    "debug_tls_set",
    "debug_breakpoint_load",
    "memory_patch",
    "patch_restore",
    "memory_alloc",
    "memory_free",
    "memory_protect",
    // Run-loop tools: each resumes the target and owns execution until it stops.
    "debug_trace_imports",
    "debug_trace_syscalls",
    "debug_trace_function",
    "debug_coverage",
    "debug_find_accesses",
    "debug_crash_triage",
    "debug_run_script",
];

/// Control tools that resume the target (the broker reports `running` while they execute).
pub const RESUMING_TOOLS: &[&str] = &[
    "debug_run",
    "debug_trace_imports",
    "debug_trace_syscalls",
    "debug_trace_function",
    "debug_coverage",
    "debug_find_accesses",
    "debug_crash_triage",
    "debug_run_script",
];
const MAX_TOKEN_FILE: u64 = 1024;
const SAFE_INTEGER: i128 = 9_007_199_254_740_991;

pub fn token_file(profile: &Profile) -> PathBuf {
    profile.path.parent().unwrap_or_else(|| Path::new(".")).join("broker-token.local")
}

fn is_token(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn load_token(path: &Path, create: bool) -> Result<String> {
    let path = std::path::absolute(path)?;
    if create && !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut stream = options.open(&path)?;
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        stream.write_all(format!("{}\n", hex::encode(secret)).as_bytes())?;
        stream.sync_all()?;
    }
    let mut content = Vec::new();
    std::fs::File::open(&path)?.take(MAX_TOKEN_FILE + 1).read_to_end(&mut content)?;
    let text = std::str::from_utf8(&content).ok().filter(|_| content.len() as u64 <= MAX_TOKEN_FILE).map(str::trim);
    match text {
        Some(token) if is_token(token) => Ok(token.to_string()),
        _ => bail!("Broker token file must contain exactly 64 lowercase hex characters"),
    }
}

pub fn valid_client_identity(client: &str) -> bool {
    (1..=96).contains(&client.len())
        && client.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn text_schema(description: &str, maximum: usize) -> Value {
    json!({"type": "string", "description": description, "maxLength": maximum})
}

fn bounded_text_schema(description: &str, minimum: usize, maximum: usize) -> Value {
    json!({"type": "string", "description": description, "minLength": minimum, "maxLength": maximum})
}

fn integer_schema(minimum: i64, maximum: i64) -> Value {
    json!({"type": "integer", "minimum": minimum, "maximum": maximum})
}

fn address_schema() -> Value {
    json!({"type": "string", "description": "Unsigned address or RVA, e.g. 0x400000; string avoids JSON precision loss",
        "maxLength": 20, "pattern": "^(0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$"})
}

pub fn analysis_tools() -> Vec<Value> {
    let mut target = text_schema("Live static-analysis application", 4096);
    target["enum"] = json!(["ida", "ghidra", "binja", "iaito"]);
    let mut direction = text_schema("Reference direction", 32);
    direction["enum"] = json!(["to", "from", "both"]);
    let mut sync_dir = text_schema("Annotation sync direction", 64);
    sync_dir["enum"] = json!(["import_from_static", "export_to_static", "bidirectional"]);
    let pid_schema = integer_schema(1, 2_147_483_647);
    let mod_schema = bounded_text_schema("Module name for runtime_address rebasing", 1, 256);
    let filter_schema = bounded_text_schema("Case-insensitive substring filter", 1, 256);

    let operations = [
        (
            "analysis_status",
            "Connected IDA/Ghidra/Binary Ninja/iaito (radare2) analysis agents; no application is launched automatically.",
            json!({}),
            json!([]),
            true,
        ),
        (
            "analysis_decompile",
            "Decompile a function in a connected IDA/Ghidra/Binary Ninja/iaito database. Supply static address or runtime_address.",
            json!({
                "target": target,
                "address": address_schema(),
                "runtime_address": address_schema(),
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_functions",
            "List a bounded page of functions from a connected static-analysis database.",
            json!({
                "target": target,
                "offset": integer_schema(0, 1_000_000),
                "limit": integer_schema(1, 100),
                "filter": filter_schema,
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_xrefs",
            "List bounded references to/from a static database address.",
            json!({
                "target": target,
                "address": address_schema(),
                "runtime_address": address_schema(),
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
                "limit": integer_schema(1, 100),
                "direction": direction,
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_disasm",
            "Disassemble instructions at a static database address in IDA/Ghidra/Binary Ninja/iaito.",
            json!({
                "target": target,
                "address": address_schema(),
                "runtime_address": address_schema(),
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
                "count": integer_schema(1, 256),
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_strings",
            "List strings in a connected static-analysis database.",
            json!({
                "target": target,
                "offset": integer_schema(0, 1_000_000),
                "limit": integer_schema(1, 100),
                "filter": filter_schema,
                "min_length": integer_schema(1, 256),
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_imports",
            "List imported symbols in a connected static-analysis database, automatically enriched with Orbis NID demangling.",
            json!({
                "target": target,
                "offset": integer_schema(0, 1_000_000),
                "limit": integer_schema(1, 100),
                "filter": filter_schema,
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_rename",
            "Rename a function or label in a connected static-analysis database (local database only; never touches console).",
            json!({
                "target": target,
                "address": address_schema(),
                "runtime_address": address_schema(),
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
                "name": bounded_text_schema("New symbol identifier", 1, 256),
            }),
            json!(["target", "name"]),
            false,
        ),
        (
            "analysis_comment",
            "Set or clear a comment at an address in a connected static-analysis database (local database only; never touches console).",
            json!({
                "target": target,
                "address": address_schema(),
                "runtime_address": address_schema(),
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
                "text": text_schema("Comment text", 2048),
            }),
            json!(["target", "text"]),
            false,
        ),
        (
            "analysis_sync_annotations",
            "Synchronize host debugger labels/breakpoints and static-analysis function names/comments with automatic ASLR rebasing.",
            json!({
                "target": target,
                "direction": sync_dir,
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
                "max_items": integer_schema(1, 500),
            }),
            json!(["target"]),
            false,
        ),
        (
            "analysis_apply_prototypes",
            "Apply a ps4wb-prototypes-v1 artifact (e.g. from orbis_prototypes) as function types on matching import/function names in a connected analyzer (local database only; never touches console).",
            apply_properties(&target, json!({
                "filter": filter_schema,
                "overwrite": {"type": "boolean", "description": "Replace existing user-defined types"},
                "max_items": integer_schema(1, 20_000),
            })),
            json!(["target", "artifact"]),
            false,
        ),
        (
            "analysis_apply_struct",
            "Create or update a struct type from a ps4wb-struct-v1 artifact in a connected analyzer (local database only).",
            apply_properties(&target, json!({
                "overwrite": {"type": "boolean", "description": "Replace an existing type with the same name"},
            })),
            json!(["target", "artifact"]),
            false,
        ),
        (
            "analysis_apply_coverage",
            "Colour (and optionally comment) covered basic blocks from a ps4wb-coverage-v1 artifact; clear=true removes that colouring. RVAs are rebased to static_base or the analyzer's image base.",
            apply_properties(&target, json!({
                "clear": {"type": "boolean", "description": "Remove colour/coverage comments for the listed blocks instead of applying"},
                "color": {"type": "string", "description": "Highlight colour 0xRRGGBB", "maxLength": 8, "pattern": "^0x[0-9a-fA-F]{6}$"},
                "comment": {"type": "boolean", "description": "Also add a hit-count comment at each block start"},
                "min_hits": integer_schema(0, 2_147_483_647),
                "max_blocks": integer_schema(1, 100_000),
            })),
            json!(["target", "artifact"]),
            false,
        ),
        (
            "analysis_apply_classes",
            "Label vtables/typeinfo from a ps4wb-classes-v1 artifact (e.g. rtti_recover) and name unnamed virtual functions Class::vfN in a connected analyzer.",
            apply_properties(&target, json!({
                "overwrite": {"type": "boolean", "description": "Rename vtable/typeinfo labels even when already named"},
                "max_items": integer_schema(1, 50_000),
            })),
            json!(["target", "artifact"]),
            false,
        ),
        (
            "analysis_apply_symbols",
            "Rename/comment addresses from a {rva: name} map, a ps4wb symbols list or a ported annotation set (artifact or inline symbols) in a connected analyzer.",
            apply_properties(&target, json!({
                "symbols": {"type": "object", "description": "Inline {\"0x<rva>\": \"name\"} map (instead of artifact)"},
                "overwrite": {"type": "boolean", "description": "Rename even when the address already has a user-defined name"},
                "max_items": integer_schema(1, 50_000),
            })),
            json!(["target"]),
            false,
        ),
    ];
    operations
        .into_iter()
        .map(|(name, description, properties, required, read_only)| {
            json!({
                "name": name,
                "description": description,
                "inputSchema": {"type": "object", "properties": properties, "required": required, "additionalProperties": false},
                "annotations": {"readOnlyHint": read_only, "destructiveHint": false, "openWorldHint": true}
            })
        })
        .collect()
}

/// Shared `analysis_apply_*` arguments plus tool-specific `extra` properties.
fn apply_properties(target: &Value, extra: Value) -> Value {
    let mut properties = json!({
        "target": target,
        "artifact": bounded_text_schema("Relative path of the JSON artifact inside the artifact directory", 1, 1024),
        "static_base": address_schema(),
        "dry_run": {"type": "boolean", "description": "Validate and show the batches without contacting the analyzer"},
        "allow_hash_mismatch": {"type": "boolean", "description": "Apply even when the artifact module_sha256 differs from the analyzer's input hash"},
    });
    if let (Some(fields), Some(more)) = (properties.as_object_mut(), extra.as_object()) {
        fields.extend(more.clone());
    }
    properties
}

fn python_list(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|item| format!("'{item}'")).collect::<Vec<_>>().join(", "))
}

pub fn validate(value: &Value, schema: &Value, location: &str) -> Result<()> {
    let expected = schema.get("type").and_then(Value::as_str).unwrap_or("object");
    let matches = match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_f64() || value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        _ => false,
    };
    if !matches {
        bail!("{location} must be {expected}");
    }
    if let Some(choices) = schema.get("enum").and_then(Value::as_array)
        && !choices.contains(value)
    {
        bail!("{location} must be one of {}", Value::Array(choices.clone()));
    }
    match value {
        Value::Object(fields) => {
            let has_properties = schema.get("properties").and_then(Value::as_object).is_some();
            let closed = schema.get("additionalProperties") == Some(&Value::Bool(false)) || has_properties;
            let properties = schema.get("properties").and_then(Value::as_object).cloned().unwrap_or_default();
            if closed {
                let mut unknown: Vec<String> = fields.keys().filter(|key| !properties.contains_key(*key)).cloned().collect();
                if !unknown.is_empty() {
                    unknown.sort();
                    bail!("Unknown {location} fields: {}", python_list(&unknown));
                }
            }
            for field in schema.get("required").and_then(Value::as_array).into_iter().flatten() {
                let field = field.as_str().unwrap_or_default();
                if !fields.contains_key(field) {
                    bail!("Missing {location}.{field}");
                }
            }
            for (field, supplied) in fields {
                if let Some(prop_schema) = properties.get(field) {
                    validate(supplied, prop_schema, &format!("{location}.{field}"))?;
                }
            }
        }
        Value::String(text) => {
            let length = text.chars().count() as u64;
            let minimum = schema.get("minLength").and_then(Value::as_u64).unwrap_or(0);
            let maximum = schema.get("maxLength").and_then(Value::as_u64).unwrap_or(4096);
            if length < minimum || length > maximum {
                bail!("{location} length out of bounds");
            }
            if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
                let expression = regex::Regex::new(&format!("^(?:{pattern})$"))?;
                if !expression.is_match(text) {
                    bail!("{location} has invalid syntax");
                }
            }
        }
        Value::Number(num) => {
            if expected == "number" {
                let val = num.as_f64().ok_or_else(|| anyhow!("{location} must be finite"))?;
                let minimum = schema.get("minimum").and_then(Value::as_f64).unwrap_or(f64::NEG_INFINITY);
                let maximum = schema.get("maximum").and_then(Value::as_f64).unwrap_or(f64::INFINITY);
                if !val.is_finite() || val < minimum || val > maximum {
                    bail!("{location} out of bounds");
                }
            } else {
                let minimum = schema.get("minimum").and_then(Value::as_i64).map_or(0, i128::from);
                let maximum = schema.get("maximum").and_then(Value::as_i64).map_or(2_147_483_647, i128::from);
                require_integer(value, location, minimum, maximum).map_err(|_| anyhow!("{location} out of bounds"))?;
            }
        }
        Value::Array(items) => {
            let length = items.len() as u64;
            let minimum = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
            let maximum = schema.get("maxItems").and_then(Value::as_u64).unwrap_or(100);
            if length < minimum || length > maximum {
                bail!("{location} item count out of bounds");
            }
            let item_schema = schema.get("items").cloned().unwrap_or_else(|| json!({}));
            for item in items {
                validate(item, &item_schema, &format!("{location}[]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn fallback_permission(name: &str) -> Option<&'static str> {
    match name {
        "payload_execute" => Some("payload_execute"),
        "payload_stage" | "payload_recover" | "payload_status" | "payload_rpc" | "payload_shutdown" => {
            Some("process_inject")
        }
        "memory_write" | "memory_patch" | "patch_restore" | "memory_alloc" | "memory_free" | "memory_protect" => {
            Some("process_write")
        }
        "kernel_read" | "kernel_base" => Some("kernel_read"),
        "kernel_write" => Some("kernel_write"),
        "debug_attach"
        | "debug_control"
        | "debug_breakpoint"
        | "debug_watchpoint"
        | "debug_step"
        | "debug_run"
        | "debug_registers_set"
        | "debug_registers_fpu_set"
        | "debug_tls_set"
        | "debug_breakpoint_load" => Some("debug_control"),
        "ftp_upload" => Some("ftp_upload"),
        "sdk_build" => Some("build"),
        _ => None,
    }
}

fn tool_permission(description: &Value, name: &str) -> Option<String> {
    match description.get("permission") {
        Some(Value::String(permission)) => Some(permission.clone()),
        Some(_) => None,
        None => fallback_permission(name).map(str::to_string),
    }
}

fn is_shared(name: &str) -> bool {
    ["debug_", "process_", "memory_", "kernel_", "patch_", "payload_"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || matches!(
            name,
            "debugger_info"
                | "address_rebase"
                | "disassemble"
                | "module_list"
                | "code_xrefs"
                | "payload_execute"
        )
}

struct SessionState {
    controller: Option<String>,
    journal: VecDeque<Value>,
    sequence: u64,
    event_failure: bool,
    session_id: Option<String>,
    execution_state: &'static str,
    last_stop: Value,
    cached_attached_pid: Option<u32>,
    cached_profile_sha256: String,
    cached_host: String,
}

impl SessionState {
    fn publish(&mut self, event: Value) {
        self.sequence += 1;
        let mut entry = Map::new();
        entry.insert("sequence".into(), json!(self.sequence));
        entry.insert("received_at".into(), json!(utc_now()));
        if let Value::Object(fields) = event {
            entry.extend(fields);
        }
        if self.journal.len() >= JOURNAL_CAPACITY {
            self.journal.pop_front();
        }
        self.journal.push_back(Value::Object(entry));
    }

    fn publish_stop_event(&mut self, pid: u32, event: Value) -> Result<()> {
        let thread_id = event
            .get("thread_id")
            .cloned()
            .ok_or_else(|| anyhow!("Stop event lacks thread_id"))?;
        let status = event
            .get("status")
            .cloned()
            .ok_or_else(|| anyhow!("Stop event lacks status"))?;
        self.execution_state = "stopped";
        let mut record = json!({"type": "stop", "pid": pid, "session_id": self.session_id});
        if let (Some(fields), Value::Object(extra)) = (record.as_object_mut(), event) {
            fields.extend(extra);
        }
        self.publish(record);
        self.last_stop = json!({
            "thread_id": thread_id,
            "status": status,
            "session_id": self.session_id,
            "sequence": self.sequence,
        });
        Ok(())
    }
}

pub struct SessionHub {
    registry: Arc<Mutex<ToolRegistry>>,
    debug: Mutex<SessionState>,
    analysis: AnalysisAgents,
    stopping: AtomicBool,
    worker: Mutex<Option<JoinHandle<()>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl SessionHub {
    pub fn new(registry: Arc<Mutex<ToolRegistry>>) -> Self {
        let (cached_attached_pid, cached_profile_sha256, cached_host) = {
            let reg = lock(&registry);
            (
                reg.workbench.debugger.attached_pid,
                reg.workbench.profile.fingerprint(),
                reg.workbench.profile.host().to_owned(),
            )
        };
        Self {
            registry,
            debug: Mutex::new(SessionState {
                controller: None,
                journal: VecDeque::new(),
                sequence: 0,
                event_failure: false,
                session_id: None,
                execution_state: "detached",
                last_stop: Value::Null,
                cached_attached_pid,
                cached_profile_sha256,
                cached_host,
            }),
            analysis: AnalysisAgents::new(),
            stopping: AtomicBool::new(false),
            worker: Mutex::new(None),
        }
    }

    pub fn from_registry(registry: ToolRegistry) -> Self {
        Self::new(Arc::new(Mutex::new(registry)))
    }

    pub fn registry(&self) -> Arc<Mutex<ToolRegistry>> {
        self.registry.clone()
    }

    pub fn publish(&self, event: Value) {
        lock(&self.debug).publish(event);
    }

    pub fn profile_fingerprint(&self) -> String {
        if let Ok(registry) = self.registry.try_lock() {
            return registry.workbench.profile.fingerprint();
        }
        lock(&self.debug).cached_profile_sha256.clone()
    }

    pub fn events_since(&self, cursor: &Value, limit: &Value) -> Result<Value> {
        let cursor = require_integer(cursor, "cursor", 0, SAFE_INTEGER)? as u64;
        let limit = require_integer(limit, "event limit", 1, JOURNAL_CAPACITY as i128)? as usize;
        let state = lock(&self.debug);
        if cursor > state.sequence {
            bail!("Event cursor is ahead of this broker; reconnect explicitly after a restart");
        }
        let oldest = state.journal.front().and_then(|entry| entry["sequence"].as_u64()).unwrap_or(state.sequence + 1);
        let selected: Vec<Value> = state.journal.iter()
            .filter(|entry| entry["sequence"].as_u64().is_some_and(|sequence| sequence > cursor))
            .take(limit).cloned().collect();
        let next = selected.last().and_then(|entry| entry["sequence"].as_u64()).unwrap_or(state.sequence);
        Ok(json!({"events": selected, "cursor": next, "latest_cursor": state.sequence,
            "lost_events": oldest.saturating_sub(cursor + 1)}))
    }

    pub fn pump(&self) {
        if lock(&self.debug).event_failure {
            return;
        }
        let Ok(mut registry) = self.registry.try_lock() else {
            // A tool call is actively using the debugger; skip this tick without
            // blocking state/events readers or stealing wait_stop packets.
            return;
        };
        let Some(pid) = registry.workbench.debugger.attached_pid else {
            drop(registry);
            lock(&self.debug).cached_attached_pid = None;
            return;
        };
        let outcome = registry.workbench.debugger.poll_events().and_then(|events| match events {
            Value::Array(items) => Ok(items),
            _ => bail!("Debugger event poll did not return an array"),
        });
        drop(registry);

        let mut state = lock(&self.debug);
        state.cached_attached_pid = Some(pid);
        if state.event_failure {
            return;
        }
        let failure = match outcome {
            Ok(events) => events
                .into_iter()
                .try_for_each(|event| state.publish_stop_event(pid, event))
                .err(),
            Err(error) => Some(error),
        };
        if let Some(error) = failure {
            state.event_failure = true;
            state.execution_state = "uncertain";
            state.publish(json!({"type": "session_error", "error": error.to_string(), "console_state": "uncertain"}));
        }
    }

    pub fn start(self: &Arc<Self>) -> Result<()> {
        let hub = self.clone();
        let handle = std::thread::Builder::new().name("ps4-event-pump".into()).spawn(move || {
            while !hub.stopping.load(Ordering::SeqCst) {
                std::thread::sleep(PUMP_INTERVAL);
                if hub.stopping.load(Ordering::SeqCst) {
                    break;
                }
                hub.pump();
            }
        })?;
        *lock(&self.worker) = Some(handle);
        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(handle) = lock(&self.worker).take() {
            let _ = handle.join();
        }
        let closed = lock(&self.registry).workbench.close();
        let mut state = lock(&self.debug);
        state.cached_attached_pid = None;
        state.execution_state = "detached";
        closed
    }

    pub fn state(&self) -> Value {
        let live_snapshot = self.registry.try_lock().ok().map(|reg| {
            (
                reg.workbench.debugger.attached_pid,
                reg.workbench.profile.fingerprint(),
                reg.workbench.profile.host().to_owned(),
            )
        });
        let mut state = lock(&self.debug);
        if let Some((pid, fp, host)) = live_snapshot {
            state.cached_attached_pid = pid;
            state.cached_profile_sha256 = fp;
            state.cached_host = host;
        }
        json!({
            "controller": state.controller,
            "attached_pid": state.cached_attached_pid,
            "profile_sha256": state.cached_profile_sha256,
            "host": state.cached_host,
            "event_cursor": state.sequence,
            "event_channel_failed": state.event_failure,
            "session_id": state.session_id,
            "execution_state": state.execution_state,
            "last_stop": state.last_stop,
            "hardware_compatibility_guaranteed": false,
        })
    }

    pub fn call(&self, client: &str, name: &str, arguments: Value) -> Result<Value> {
        if !valid_client_identity(client) {
            bail!("Use a simple unique broker client identifier");
        }
        if name == "debug_events" {
            bail!("Shared events use events_since(cursor); draining the callback is broker-owned");
        }
        if name.starts_with("analysis_") {
            return self.analysis_call(name, arguments);
        }
        if name == "recipe_run" || (name == "recipe_session" && arguments["action"] == "advance") {
            // Recipe steps reach the registry directly, so enforce the shared debug lease up front.
            let steps = if name == "recipe_session" { crate::sessions::referenced_tools(&lock(&self.registry), &arguments)? } else { crate::recipes::referenced_tools(&lock(&self.registry), &arguments)? };
            if steps.iter().any(|step| CONTROL_TOOLS.contains(&step.as_str()))
                && lock(&self.debug).controller.as_deref() != Some(client)
            {
                bail!("Recipe contains debugger control steps; acquire the debug lease (debug_attach) first");
            }
        }
        if !is_shared(name) {
            return lock(&self.registry).call(name, arguments);
        }

        // Acquire `registry` first, then `debug` ONLY for fast in-memory lease/state
        // updates so `state()` and `events_since()` remain non-blocking during console I/O.
        let mut registry = lock(&self.registry);
        if name == "payload_execute" && registry.workbench.debugger.attached_pid.is_some() {
            bail!("Detach the active debug session before sending a payload");
        }
        let description = registry
            .available()
            .into_iter()
            .find(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| anyhow!("Unknown or locally disabled tool: {name}"))?;
        validate(
            &arguments,
            description.get("inputSchema").unwrap_or(&json!({"type": "object"})),
            "arguments",
        )?;
        if let Some(permission) = tool_permission(&description, name) {
            registry.workbench.profile.require(&permission)?;
        }
        let control = CONTROL_TOOLS.contains(&name);
        let claimed = {
            let mut state = lock(&self.debug);
            state.cached_attached_pid = registry.workbench.debugger.attached_pid;
            state.cached_profile_sha256 = registry.workbench.profile.fingerprint();
            state.cached_host = registry.workbench.profile.host().to_owned();
            if control && state.controller.as_deref().is_some_and(|owner| owner != client) {
                bail!("Another client owns debug control; observers may still read memory and events");
            }
            let claiming = name == "debug_attach" && state.controller.is_none();
            if claiming {
                state.controller = Some(client.to_string());
                state.session_id = Some(uuid::Uuid::new_v4().simple().to_string());
                state.execution_state = "attaching";
                state.last_stop = Value::Null;
            } else if RESUMING_TOOLS.contains(&name)
                || (matches!(name, "debug_control" | "debug_step")
                    && matches!(
                        arguments.get("action").and_then(Value::as_str),
                        Some("resume" | "step" | "step_thread" | "into" | "over" | "out")
                    ))
            {
                state.execution_state = "running";
            }
            claiming
        };

        let action = arguments.get("action").and_then(Value::as_str).map(str::to_string);
        let outcome = registry.call(name, arguments);
        let now_attached = registry.workbench.debugger.attached_pid;
        let now_fp = registry.workbench.profile.fingerprint();
        let now_host = registry.workbench.profile.host().to_owned();
        drop(registry);

        let mut state = lock(&self.debug);
        state.cached_attached_pid = now_attached;
        state.cached_profile_sha256 = now_fp;
        state.cached_host = now_host;

        let result = match outcome {
            Ok(result) => result,
            Err(error) => {
                if control || (now_attached.is_none() && state.controller.is_some()) {
                    state.execution_state = "uncertain";
                }
                if claimed {
                    state.publish(json!({
                        "type": "session_error",
                        "error": "Attach failed; inspect console before retrying",
                        "console_state": "uncertain",
                    }));
                }
                return Err(error);
            }
        };

        if matches!(name, "debug_attach" | "debug_detach") {
            state.event_failure = false;
        }
        if name == "debug_detach" {
            state.controller = None;
            state.publish(json!({"type": "detached"}));
            state.session_id = None;
            state.execution_state = "detached";
            state.last_stop = Value::Null;
        } else if name == "debug_step" {
            if let (Some(pid), Some(ev)) = (now_attached, result.get("event").cloned())
                && ev.is_object()
            {
                let _ = state.publish_stop_event(pid, ev);
            }
        } else if name == "debug_run" {
            if let (Some(pid), Some(stops)) = (now_attached, result.get("stops").and_then(Value::as_array)) {
                for stop in stops {
                    if let Some(ev) = stop.get("event").cloned()
                        && ev.is_object()
                    {
                        let _ = state.publish_stop_event(pid, ev);
                    }
                }
            }
        } else if name == "debug_control" {
            match action.as_deref() {
                Some("halt") => state.execution_state = "halting",
                Some("resume" | "step" | "step_thread") => state.execution_state = "running",
                _ => {}
            }
        }
        Ok(result)
    }

    fn resolve_runtime_module(
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

    fn sync_annotations(&self, arguments: &Map<String, Value>) -> Result<Value> {
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

    fn analysis_call(&self, name: &str, arguments: Value) -> Result<Value> {
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
    fn apply_annotations(&self, name: &str, fields: &Map<String, Value>) -> Result<Value> {
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

    pub fn dispatch(&self, client: &str, operation: &Value, arguments: &Map<String, Value>) -> Result<Value> {
        let field = |key: &str| arguments.get(key).ok_or_else(|| anyhow!("Missing argument: {key}"));
        match operation.as_str().unwrap_or_default() {
            "tools" => {
                let registry = lock(&self.registry);
                let mut tools: Vec<Value> = registry.available().into_iter()
                    .filter(|tool| tool.get("name").and_then(Value::as_str) != Some("debug_events"))
                    .map(|mut tool| {
                        if let Some(fields) = tool.as_object_mut() {
                            fields.remove("permission");
                        }
                        tool
                    })
                    .collect();
                tools.extend(analysis_tools());
                Ok(Value::Array(tools))
            }
            "call" => {
                let name = arguments.get("name").and_then(Value::as_str);
                let supplied = arguments.get("arguments").cloned().unwrap_or_else(|| json!({}));
                match name {
                    Some(name) if supplied.is_object() => self.call(client, name, supplied),
                    _ => bail!("call requires name and object arguments"),
                }
            }
            "events" => {
                let limit = arguments.get("limit").cloned().unwrap_or(json!(64));
                require_integer(&limit, "event page limit", 1, 64)?;
                self.events_since(&arguments.get("cursor").cloned().unwrap_or(json!(0)), &limit)
            }
            "state" => Ok(self.state()),
            "agent_register" => self.analysis.register(client, field("target")?, field("program")?),
            "agent_poll" => self.analysis.poll(client, field("target")?),
            "agent_unregister" => self.analysis.unregister(client, field("target")?),
            "agent_result" => self.analysis.complete(client, field("identifier")?,
                arguments.get("result").cloned().unwrap_or(Value::Null),
                arguments.get("error").cloned().unwrap_or(Value::Null)),
            "release" => {
                let attached = lock(&self.registry).workbench.debugger.attached_pid;
                {
                    let mut state = lock(&self.debug);
                    state.cached_attached_pid = attached;
                    if state.controller.as_deref() != Some(client) {
                        bail!("Only the controlling client can release its lease");
                    }
                    if attached.is_some() {
                        bail!("Detach before releasing debug control");
                    }
                    state.controller = None;
                }
                Ok(self.state())
            }
            _ => bail!("Unknown broker operation"),
        }
    }

    pub fn handle_request(&self, client: &str, content: &[u8]) -> Result<Value> {
        let request: Value = serde_json::from_slice(content)?;
        let Some(envelope) = request.as_object() else {
            bail!("Request must be an operation/arguments object");
        };
        let empty = Map::new();
        let arguments = match envelope.get("arguments") {
            None => &empty,
            Some(Value::Object(fields)) => fields,
            Some(_) => bail!("Request must be an operation/arguments object"),
        };
        let operation = envelope.get("operation").cloned().unwrap_or(Value::Null);
        let expected = envelope.get("profile_sha256").cloned().unwrap_or(Value::Null);
        if expected.as_str() != Some(self.profile_fingerprint().as_str())
            && (!expected.is_null() || operation.as_str() != Some("state"))
        {
            bail!("Broker profile mismatch; reconnect explicitly to the intended console profile");
        }
        if !valid_client_identity(client) {
            bail!("Missing or invalid client identity");
        }
        self.dispatch(client, &operation, arguments)
    }
}

struct Shared {
    hub: Arc<SessionHub>,
    token: String,
    expected_host: String,
    slots: Arc<Semaphore>,
}

fn respond(status: StatusCode, value: Value) -> Response {
    let content = serde_json::to_vec(&value).unwrap_or_else(|_| b"{\"error\":\"Unencodable broker result\"}".to_vec());
    let mut response = (status, content).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    headers.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    headers.insert(header::CONNECTION, header::HeaderValue::from_static("close"));
    response
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let supplied = headers.get(header::AUTHORIZATION).map(|value| value.as_bytes()).unwrap_or_default();
    let expected = format!("Bearer {token}");
    supplied.is_ascii() && bool::from(supplied.ct_eq(expected.as_bytes()))
}

async fn handle(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let Ok(_permit) = shared.slots.clone().try_acquire_owned() else {
        return respond(StatusCode::SERVICE_UNAVAILABLE, json!({"error": "Broker is busy; no automatic retry"}));
    };
    let headers = request.headers();
    let host = headers.get(header::HOST).and_then(|value| value.to_str().ok());
    if host != Some(shared.expected_host.as_str()) || headers.contains_key(header::ORIGIN) {
        return respond(StatusCode::FORBIDDEN, json!({"error": "Loopback native clients only; browser origins are forbidden"}));
    }
    if !authorized(headers, &shared.token) {
        return respond(StatusCode::UNAUTHORIZED, json!({"error": "Broker authentication required"}));
    }
    if request.method() != Method::POST {
        return respond(StatusCode::METHOD_NOT_ALLOWED, json!({"error": "Use POST /rpc with Content-Length"}));
    }
    let length = headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok())
        .and_then(|text| text.trim().parse::<usize>().ok());
    let framed = request.uri().path() == "/rpc" && request.uri().query().is_none()
        && !headers.contains_key(header::TRANSFER_ENCODING);
    let length = match length {
        Some(length) if framed && (1..=MAX_BODY).contains(&length) => length,
        Some(_) if framed => return respond(StatusCode::BAD_REQUEST,
            json!({"error": format!("body length must be an integer in [1, {MAX_BODY}]")})),
        _ => return respond(StatusCode::BAD_REQUEST, json!({"error": "Use POST /rpc with Content-Length"})),
    };
    let client = headers.get("X-PS4-Client").and_then(|value| value.to_str().ok()).unwrap_or_default().to_string();
    let body: Body = request.into_body();
    let content = match tokio::time::timeout(REQUEST_DEADLINE, to_bytes(body, length)).await {
        Ok(Ok(content)) if content.len() == length => content,
        _ => return respond(StatusCode::BAD_REQUEST, json!({"error": "Truncated request body"})),
    };
    let hub = shared.hub.clone();
    match tokio::task::spawn_blocking(move || hub.handle_request(&client, &content)).await {
        Ok(Ok(result)) => respond(StatusCode::OK, json!({"result": result})),
        Ok(Err(error)) => respond(StatusCode::BAD_REQUEST, json!({"error": error.to_string()})),
        Err(_) => respond(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": "Internal broker failure; no automatic retry"})),
    }
}

pub struct BrokerServer {
    hub: Arc<SessionHub>,
    listener: tokio::net::TcpListener,
    token: String,
}

impl BrokerServer {
    pub async fn bind(hub: Arc<SessionHub>, address: SocketAddr, token: String) -> Result<Self> {
        if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            bail!("The broker binds only to 127.0.0.1");
        }
        if !is_token(&token) {
            bail!("Broker token must be 64 lowercase hex characters");
        }
        let listener = tokio::net::TcpListener::bind(address).await?;
        Ok(Self { hub, listener, token })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn hub(&self) -> Arc<SessionHub> {
        self.hub.clone()
    }

    pub async fn run(self, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<()> {
        let port = self.local_addr()?.port();
        let shared = Arc::new(Shared { hub: self.hub, token: self.token, expected_host: format!("127.0.0.1:{port}"),
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)) });
        let application = axum::Router::new().fallback(handle).with_state(shared);
        axum::serve(self.listener, application).with_graceful_shutdown(shutdown).await?;
        Ok(())
    }
}

pub async fn serve(registry: ToolRegistry, address: SocketAddr, token_path: PathBuf) -> Result<()> {
    let artifact_root = registry.workbench.profile.artifact_root();
    let absolute = std::path::absolute(&token_path)?;
    if absolute.starts_with(&artifact_root) {
        bail!("Broker token must stay outside MCP-readable artifact storage");
    }
    let token = load_token(&absolute, true)?;
    let hub = Arc::new(SessionHub::from_registry(registry));
    let server = BrokerServer::bind(hub.clone(), address, token).await?;
    hub.start()?;
    let outcome = server.run(async {
        let _ = tokio::signal::ctrl_c().await;
    }).await;
    let closing = hub.clone();
    let closed = tokio::task::spawn_blocking(move || closing.close()).await
        .map_err(|_| anyhow!("Broker shutdown cleanup panicked; console state uncertain"))?;
    outcome.and(closed)
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::workbench::Workbench;

    pub struct Fixture {
        pub directory: tempfile::TempDir,
        pub profile_path: PathBuf,
        pub token_path: PathBuf,
        pub token: String,
        pub hub: Arc<SessionHub>,
    }

    pub fn profile_document() -> Value {
        let mut settings: Value = serde_json::from_str(include_str!("../tests/fixtures/profile.json")).unwrap();
        settings["host"] = json!("127.0.0.1");
        settings["artifact_directory"] = json!("artifacts");
        settings["qualification_file"] = json!("qualification.json");
        settings
    }

    pub fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let profile_path = directory.path().join("profile.json");
        std::fs::write(&profile_path, serde_json::to_vec(&profile_document()).unwrap()).unwrap();
        let profile = Profile::load(&profile_path).unwrap();
        let registry = ToolRegistry::with_toolset(
            Workbench::new(profile).unwrap(),
            crate::tools::Toolset::Full,
        )
        .unwrap();
        let token_path = directory.path().join("broker-token.local");
        let token = load_token(&token_path, true).unwrap();
        Fixture { directory, profile_path, token_path, token, hub: Arc::new(SessionHub::from_registry(registry)) }
    }

    pub struct Running {
        pub url: String,
        pub port: u16,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    pub fn run(hub: Arc<SessionHub>, token: String) -> Running {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (ready, bound) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
            runtime.block_on(async move {
                let server = BrokerServer::bind(hub, "127.0.0.1:0".parse().unwrap(), token).await.unwrap();
                ready.send(server.local_addr().unwrap().port()).unwrap();
                server.run(async {
                    let _ = stopped.await;
                }).await.unwrap();
            });
        });
        let port = bound.recv().unwrap();
        Running { url: format!("http://127.0.0.1:{port}"), port, stop: Some(stop), thread: Some(thread) }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::client::BrokerClient;

    fn raw(port: u16, request: &str) -> String {
        use std::net::TcpStream;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    }

    fn post(port: u16, host: &str, extra: &str, body: &str) -> String {
        raw(port, &format!("POST /rpc HTTP/1.1\r\nHost: {host}\r\nX-PS4-Client: test\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()))
    }

    #[test]
    fn token_is_created_once_and_validated() {
        let fixture = fixture();
        assert_eq!(load_token(&fixture.token_path, true).unwrap(), fixture.token);
        assert!(is_token(&fixture.token));
        let invalid = fixture.directory.path().join("bad.local");
        std::fs::write(&invalid, "ABC").unwrap();
        assert!(load_token(&invalid, false).is_err());
        assert!(load_token(&fixture.directory.path().join("absent.local"), false).is_err());
        // Profile::load canonicalizes the profile path (Windows 8.3 short names
        // like RUNNER~1 expand), so canonicalize the expected side too.
        let expected_token = crate::config::resolve_lenient(&fixture.directory.path().join("broker-token.local")).unwrap();
        assert_eq!(token_file(&Profile::load(&fixture.profile_path).unwrap()), expected_token);
    }

    #[test]
    fn authentication_host_and_origin_are_enforced() {
        let fixture = fixture();
        let running = run(fixture.hub.clone(), fixture.token.clone());
        let host = format!("127.0.0.1:{}", running.port);
        let body = r#"{"operation":"state"}"#;
        assert!(post(running.port, &host, "", body).starts_with("HTTP/1.1 401"));
        let bearer = format!("Authorization: Bearer {}\r\n", fixture.token);
        let wrong = format!("Authorization: Bearer {}\r\n", "0".repeat(64));
        assert!(post(running.port, &host, &wrong, body).starts_with("HTTP/1.1 401"));
        let origin = format!("{bearer}Origin: http://evil.invalid\r\n");
        assert!(post(running.port, &host, &origin, body).starts_with("HTTP/1.1 403"));
        assert!(post(running.port, &format!("localhost:{}", running.port), &bearer, body).starts_with("HTTP/1.1 403"));
        let accepted = post(running.port, &host, &bearer, body);
        assert!(accepted.starts_with("HTTP/1.1 200"), "{accepted}");
        assert!(accepted.contains("\"profile_sha256\""));
        let mismatch = post(running.port, &host, &bearer, r#"{"operation":"tools"}"#);
        assert!(mismatch.starts_with("HTTP/1.1 400") && mismatch.contains("profile mismatch"));
        let path = raw(running.port, &format!("POST /other HTTP/1.1\r\nHost: {host}\r\n{bearer}X-PS4-Client: t\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"));
        assert!(path.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn client_binds_profile_and_reads_state_without_console() {
        let fixture = fixture();
        let running = run(fixture.hub.clone(), fixture.token.clone());
        let client = BrokerClient::new(&running.url, &fixture.token_path, "ida", None).unwrap();
        let state = client.state().unwrap();
        assert!(state["attached_pid"].is_null());
        assert_eq!(state["execution_state"], "detached");
        assert_eq!(client.call("console_status", json!({})).unwrap()["host"], "127.0.0.1");
        assert!(client.call("not_a_tool", json!({})).is_err());
        let names: Vec<String> = client.descriptions().unwrap().iter()
            .map(|tool| tool["name"].as_str().unwrap().to_string()).collect();
        assert!(names.contains(&"analysis_decompile".to_string()));
        assert!(!names.contains(&"debug_events".to_string()));
        let mismatch = BrokerClient::new(&running.url, &fixture.token_path, "x", Some("0".repeat(64)));
        assert!(mismatch.err().unwrap().to_string().contains("profile mismatch"));
        assert!(client.call("debug_events", json!({})).unwrap_err().to_string().contains("broker-owned"));
        let denied = client.call("payload_execute", json!({"manifest": "anything", "sha256": "a".repeat(64)}));
        assert!(denied.unwrap_err().to_string().contains("disabled"));
        let refused = client.call("debug_attach", json!({"pid": 71, "listen_address": "127.0.0.1"}));
        assert!(refused.unwrap_err().to_string().contains("disabled"));
        assert!(client.state().unwrap()["controller"].is_null());
        assert!(client.release().unwrap_err().to_string().contains("controlling client"));
    }

    #[test]
    fn event_journal_pagination_gap_and_future_cursor() {
        let fixture = fixture();
        for index in 0..10 {
            fixture.hub.publish(json!({"type": "test", "index": index}));
        }
        let first = fixture.hub.events_since(&json!(0), &json!(6)).unwrap();
        let second = fixture.hub.events_since(&first["cursor"], &json!(6)).unwrap();
        let indices: Vec<i64> = first["events"].as_array().unwrap().iter().chain(second["events"].as_array().unwrap())
            .map(|event| event["index"].as_i64().unwrap()).collect();
        assert_eq!(indices, (0..10).collect::<Vec<_>>());
        assert_eq!(first["latest_cursor"], 10);
        assert!(fixture.hub.events_since(&json!(11), &json!(5)).unwrap_err().to_string().contains("ahead"));
        for index in 0..1020 {
            fixture.hub.publish(json!({"type": "test", "index": index}));
        }
        let gap = fixture.hub.events_since(&json!(0), &json!(1024)).unwrap();
        assert_eq!(gap["lost_events"], 6);
        assert_eq!(gap["events"].as_array().unwrap().len(), 1024);
        assert!(fixture.hub.events_since(&json!(-1), &json!(5)).is_err());
        assert!(fixture.hub.events_since(&json!(0), &json!(0)).is_err());
    }

    #[test]
    fn pump_is_idle_when_detached() {
        let fixture = fixture();
        fixture.hub.pump();
        assert_eq!(fixture.hub.state()["event_cursor"], 0);
    }

    #[test]
    fn static_analysis_round_trip_through_http() {
        let fixture = fixture();
        let running = run(fixture.hub.clone(), fixture.token.clone());
        let agent = BrokerClient::new(&running.url, &fixture.token_path, "ghidra-agent-1", None).unwrap();
        agent.request("agent_register", json!({"target": "ghidra", "program": "a".repeat(64)})).unwrap();
        let caller = BrokerClient::new(&running.url, &fixture.token_path, "mcp", None).unwrap();
        assert_eq!(caller.call("analysis_status", json!({})).unwrap()["ghidra"]["connected"], true);
        assert!(caller.call("analysis_decompile", json!({"target": "ghidra", "address": "nope"})).is_err());
        let pending = std::thread::spawn(move || caller.call("analysis_functions", json!({"target": "ghidra", "limit": 2})));
        let job = loop {
            let job = agent.request("agent_poll", json!({"target": "ghidra"})).unwrap();
            if !job.is_null() {
                break job;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(job["operation"], "functions");
        assert_eq!(job["arguments"], json!({"limit": 2}));
        let completion = agent.request("agent_result",
            json!({"identifier": job["id"], "result": [{"address": "0x1000", "name": "entry"}]})).unwrap();
        assert_eq!(completion["accepted"], true);
        assert_eq!(pending.join().unwrap().unwrap()[0]["name"], "entry");
        assert_eq!(agent.request("agent_unregister", json!({"target": "ghidra"})).unwrap()["unregistered"], true);
    }

    #[test]
    fn schema_validation_matches_python_rules() {
        let schema = json!({"type": "object", "properties": {"pid": {"type": "integer", "minimum": 1, "maximum": 10},
            "address": address_schema()}, "required": ["pid"], "additionalProperties": false});
        assert!(validate(&json!({"pid": 3, "address": "0x10"}), &schema, "arguments").is_ok());
        assert!(validate(&json!({"pid": 0}), &schema, "arguments").is_err());
        assert!(validate(&json!({"pid": 3.0}), &schema, "arguments").is_err());
        assert!(validate(&json!({"address": "0x10"}), &schema, "arguments").is_err());
        assert!(validate(&json!({"pid": 1, "address": "0xZZ"}), &schema, "arguments").is_err());
        assert!(validate(&json!({"pid": 1, "other": 1}), &schema, "arguments").unwrap_err().to_string().contains("Unknown"));
        assert!(validate(&json!([]), &schema, "arguments").is_err());

        let num_schema = json!({"type": "object", "properties": {
            "tolerance": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "registers": {"type": "object"}
        }, "additionalProperties": false});
        assert!(validate(&json!({"tolerance": 0.25, "registers": {"xmm0": "00"}}), &num_schema, "arguments").is_ok());
        assert!(validate(&json!({"tolerance": 1, "registers": {}}), &num_schema, "arguments").is_ok());
        assert!(validate(&json!({"tolerance": 1.5}), &num_schema, "arguments").is_err());
        assert!(validate(&json!({"tolerance": true}), &num_schema, "arguments").is_err());
        assert!(validate(&json!({"registers": [1, 2]}), &num_schema, "arguments").is_err());
    }

    #[test]
    fn imports_nid_demangling_and_bidirectional_annotation_sync() {
        let fixture = fixture();
        let running = run(fixture.hub.clone(), fixture.token.clone());
        let agent = BrokerClient::new(&running.url, &fixture.token_path, "ida-agent-1", None).unwrap();
        agent.request("agent_register", json!({"target": "ida", "program": "b".repeat(64)})).unwrap();
        let caller = BrokerClient::new(&running.url, &fixture.token_path, "mcp-sync", None).unwrap();

        // Seed a runtime label in the debugger so bidirectional sync exports it to IDA.
        caller.call("debug_label", json!({"action": "set", "name": "player_tick", "address": "0x402000"})).unwrap();

        // 1. Test analysis_imports Orbis NID demangling (`sceKernelUsleep` -> `Q3xaNI1RVdc`).
        let caller_imp = caller.clone();
        let imp_handle = std::thread::spawn(move || {
            caller_imp.call("analysis_imports", json!({"target": "ida", "limit": 10}))
        });
        let job = loop {
            let j = agent.request("agent_poll", json!({"target": "ida"})).unwrap();
            if !j.is_null() {
                break j;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(job["operation"], "imports");
        let nid = crate::nid::encode_nid("sceKernelUsleep");
        agent.request("agent_result", json!({
            "identifier": job["id"],
            "result": [{"address": "0x1080", "name": format!("{nid}#A#B"), "library": "libkernel"}]
        })).unwrap();
        let enriched = imp_handle.join().unwrap().unwrap();
        assert_eq!(enriched[0]["nid"], nid);
        assert_eq!(enriched[0]["resolved_symbol"], "sceKernelUsleep");

        // 2. Test analysis_sync_annotations bidirectional sync with static_base rebasing.
        let caller_sync = caller.clone();
        let sync_handle = std::thread::spawn(move || {
            caller_sync.call("analysis_sync_annotations", json!({
                "target": "ida",
                "direction": "bidirectional",
                "static_base": "0x400000",
                "max_items": 10
            }))
        });

        // Agent serves `functions` first, then `rename` for `player_tick`.
        let mut saw_rename = false;
        for _ in 0..2 {
            let j = loop {
                let polled = agent.request("agent_poll", json!({"target": "ida"})).unwrap();
                if !polled.is_null() {
                    break polled;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            match j["operation"].as_str().unwrap() {
                "functions" => {
                    agent.request("agent_result", json!({
                        "identifier": j["id"],
                        "result": [
                            {"address": "0x401000", "name": "sub_401000"},
                            {"address": "0x401500", "name": "orbis_main"}
                        ]
                    })).unwrap();
                }
                "rename" => {
                    assert_eq!(j["arguments"]["name"], "player_tick");
                    assert_eq!(j["arguments"]["address"], "0x402000");
                    saw_rename = true;
                    agent.request("agent_result", json!({
                        "identifier": j["id"],
                        "result": {"address": "0x402000", "name": "player_tick"}
                    })).unwrap();
                }
                other => panic!("Unexpected sync operation: {other}"),
            }
        }
        let summary = sync_handle.join().unwrap().unwrap();
        assert!(saw_rename);
        assert_eq!(summary["imported_labels"], 1);
        assert_eq!(summary["exported_renames"], 1);
        let labels = caller.call("debug_label", json!({"action": "list"})).unwrap();
        assert!(labels.as_array().unwrap().iter().any(|l| l["name"] == "orbis_main" && l["address"] == "0x401500"));
    }

    fn next_job(agent: &BrokerClient, target: &str) -> Value {
        loop {
            let polled = agent.request("agent_poll", json!({"target": target})).unwrap();
            if !polled.is_null() {
                return polled;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn apply_tools_validate_rebase_and_check_module_hash() {
        let fixture = fixture();
        let running = run(fixture.hub.clone(), fixture.token.clone());
        let program = "c".repeat(64);
        let agent = BrokerClient::new(&running.url, &fixture.token_path, "ida-agent-apply", None).unwrap();
        agent.request("agent_register", json!({"target": "ida", "program": program})).unwrap();
        let caller = BrokerClient::new(&running.url, &fixture.token_path, "mcp-apply", None).unwrap();
        let store = lock(&fixture.hub.registry()).workbench.store.clone();
        let save = |kind: &str, document: Value| -> String {
            store.save(kind, document.to_string().as_bytes(), json!({}), "json").unwrap()["path"].as_str().unwrap().to_owned()
        };
        let coverage = save("coverage", json!({"format": "ps4wb-coverage-v1", "module": "eboot.bin", "module_sha256": program,
            "image_base": "0x7fff00000000", "blocks": [{"rva": "0x1000", "size": 12, "hits": 3}, {"rva": "0x1010", "size": 4, "hits": 0}]}));

        // Dry run: validated and rebased without contacting the agent.
        let dry = caller.call("analysis_apply_coverage", json!({"target": "ida", "artifact": coverage,
            "static_base": "0x400000", "dry_run": true})).unwrap();
        assert_eq!(dry["items"], 1);
        assert_eq!(dry["module_hash_matches"], true);
        assert_eq!(dry["preview"]["blocks"][0], json!({"address": "0x401000", "size": 12, "hits": 3}));

        let pending = {
            let caller = caller.clone();
            let coverage = coverage.clone();
            std::thread::spawn(move || caller.call("analysis_apply_coverage", json!({"target": "ida", "artifact": coverage, "comment": true})))
        };
        let job = next_job(&agent, "ida");
        assert_eq!(job["operation"], "apply_coverage");
        assert_eq!(job["arguments"]["blocks"], json!([{"rva": "0x1000", "size": 12, "hits": 3}]));
        assert_eq!(job["arguments"]["comment"], true);
        agent.request("agent_result", json!({"identifier": job["id"], "result": {"applied": 1, "skipped": 0, "failed": 0}})).unwrap();
        let report = pending.join().unwrap().unwrap();
        assert_eq!(report["applied"], 1);
        assert_eq!(report["batches_sent"], 1);
        assert_eq!(report["rebased_to"], "analyzer image base");

        let foreign = save("coverage", json!({"format": "ps4wb-coverage-v1", "module_sha256": "d".repeat(64),
            "blocks": [{"rva": "0x10", "size": 4, "hits": 1}]}));
        let refused = caller.call("analysis_apply_coverage", json!({"target": "ida", "artifact": foreign}));
        assert!(refused.unwrap_err().to_string().contains("module_sha256"));
        let forced = caller.call("analysis_apply_coverage", json!({"target": "ida", "artifact": foreign,
            "allow_hash_mismatch": true, "dry_run": true})).unwrap();
        assert_eq!(forced["module_hash_matches"], false);

        // Agent-side errors propagate; malformed artifacts and arguments are rejected by the broker.
        let pending = {
            let caller = caller.clone();
            std::thread::spawn(move || caller.call("analysis_apply_symbols", json!({"target": "ida", "symbols": {"0x20": "tick"},
                "static_base": "0x1000"})))
        };
        let job = next_job(&agent, "ida");
        assert_eq!(job["operation"], "apply_symbols");
        assert_eq!(job["arguments"]["symbols"], json!([{"address": "0x1020", "name": "tick"}]));
        agent.request("agent_result", json!({"identifier": job["id"], "error": "apply_symbols unsupported by backend"})).unwrap();
        assert!(pending.join().unwrap().unwrap_err().to_string().contains("unsupported"));
        let wrong = save("struct", json!({"format": "ps4wb-coverage-v1", "blocks": []}));
        assert!(caller.call("analysis_apply_struct", json!({"target": "ida", "artifact": wrong})).unwrap_err().to_string().contains("expected ps4wb-struct-v1"));
        assert!(caller.call("analysis_apply_struct", json!({"target": "ida", "artifact": "../escape.json"})).is_err());
        assert!(caller.call("analysis_apply_coverage", json!({"target": "ida", "artifact": coverage, "color": "green"})).is_err());
        assert!(caller.call("analysis_apply_symbols", json!({"target": "ida"})).is_err());
        assert!(fixture.hub.analysis.submit("ida", "apply_symbols", json!({"symbols": [], "evil": 1}), JOB_TIMEOUT).is_err());
    }

    #[test]
    fn recipes_with_control_steps_need_the_debug_lease() {
        let fixture = fixture();
        let refused = fixture.hub.call("mcp", "recipe_run", json!({"recipe": "crash_capture", "inputs": {"pid": 7}}));
        assert!(refused.unwrap_err().to_string().contains("debug lease"));
        let planned = fixture.hub.call("mcp", "recipe_run", json!({"recipe": "static_triage", "inputs": {"artifact": "x.elf"},
            "dry_run": true})).unwrap();
        assert_eq!(planned["steps"].as_array().unwrap().len(), 4);
    }
}
