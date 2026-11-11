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

mod analysis;
mod schema;
pub use schema::{analysis_tools, validate};
#[cfg(test)]
use schema::address_schema;

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
