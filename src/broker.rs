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
pub const CONTROL_TOOLS: [&str; 7] = ["debug_attach", "debug_control", "debug_breakpoint", "debug_watchpoint",
    "memory_write", "kernel_write", "debug_detach"];
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

fn integer_schema(minimum: i64, maximum: i64) -> Value {
    json!({"type": "integer", "minimum": minimum, "maximum": maximum})
}

fn address_schema() -> Value {
    json!({"type": "string", "description": "Unsigned address or RVA, e.g. 0x400000; string avoids JSON precision loss",
        "maxLength": 20, "pattern": "^(0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$"})
}

pub fn analysis_tools() -> Vec<Value> {
    let mut target = text_schema("Live static-analysis application", 4096);
    target["enum"] = json!(["ida", "ghidra"]);
    let operations = [
        ("analysis_status", "Connected IDA/Ghidra analysis agents; no application is launched automatically.",
         json!({}), json!([])),
        ("analysis_decompile", "Decompile a function in a connected IDA/Ghidra database. Address is STATIC, not a runtime VA.",
         json!({"target": target, "address": address_schema()}), json!(["target", "address"])),
        ("analysis_functions", "List a bounded page of functions from a connected static-analysis database.",
         json!({"target": target, "offset": integer_schema(0, 1_000_000), "limit": integer_schema(1, 100)}), json!(["target"])),
        ("analysis_xrefs", "List bounded references to a static database address.",
         json!({"target": target, "address": address_schema(), "limit": integer_schema(1, 100)}), json!(["target", "address"])),
    ];
    operations.into_iter().map(|(name, description, properties, required)| json!({
        "name": name, "description": description,
        "inputSchema": {"type": "object", "properties": properties, "required": required, "additionalProperties": false},
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": true}
    })).collect()
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
        "boolean" => value.is_boolean(),
        _ => false,
    };
    if !matches {
        bail!("{location} must be {expected}");
    }
    if let Some(choices) = schema.get("enum").and_then(Value::as_array)
        && !choices.contains(value) {
            bail!("{location} must be one of {}", Value::Array(choices.clone()));
        }
    match value {
        Value::Object(fields) => {
            let properties = schema.get("properties").and_then(Value::as_object).cloned().unwrap_or_default();
            let mut unknown: Vec<String> = fields.keys().filter(|key| !properties.contains_key(*key)).cloned().collect();
            if !unknown.is_empty() {
                unknown.sort();
                bail!("Unknown {location} fields: {}", python_list(&unknown));
            }
            for field in schema.get("required").and_then(Value::as_array).into_iter().flatten() {
                let field = field.as_str().unwrap_or_default();
                if !fields.contains_key(field) {
                    bail!("Missing {location}.{field}");
                }
            }
            for (field, supplied) in fields {
                validate(supplied, &properties[field], &format!("{location}.{field}"))?;
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
        Value::Number(_) => {
            let minimum = schema.get("minimum").and_then(Value::as_i64).map_or(0, i128::from);
            let maximum = schema.get("maximum").and_then(Value::as_i64).map_or(2_147_483_647, i128::from);
            require_integer(value, location, minimum, maximum).map_err(|_| anyhow!("{location} out of bounds"))?;
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
        "memory_write" => Some("process_write"),
        "kernel_read" | "kernel_base" => Some("kernel_read"),
        "kernel_write" => Some("kernel_write"),
        "debug_attach" | "debug_control" | "debug_breakpoint" | "debug_watchpoint" => Some("debug_control"),
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
    ["debug_", "process_", "memory_", "kernel_"].iter().any(|prefix| name.starts_with(prefix))
        || matches!(name, "debugger_info" | "address_correlate" | "payload_execute")
}

struct SessionState {
    controller: Option<String>,
    journal: VecDeque<Value>,
    sequence: u64,
    event_failure: bool,
    session_id: Option<String>,
    execution_state: &'static str,
    last_stop: Value,
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
        Self {
            registry,
            debug: Mutex::new(SessionState { controller: None, journal: VecDeque::new(), sequence: 0,
                event_failure: false, session_id: None, execution_state: "detached", last_stop: Value::Null }),
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
        lock(&self.registry).workbench.profile.fingerprint()
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
        let mut state = lock(&self.debug);
        let mut registry = lock(&self.registry);
        let Some(pid) = registry.workbench.debugger.attached_pid else {
            return;
        };
        if state.event_failure {
            return;
        }
        let outcome = registry.workbench.debugger.poll_events().and_then(|events| match events {
            Value::Array(items) => Ok(items),
            _ => bail!("Debugger event poll did not return an array"),
        });
        let failure = match outcome {
            Ok(events) => events.into_iter().try_for_each(|event| -> Result<()> {
                let thread_id = event.get("thread_id").cloned().ok_or_else(|| anyhow!("Stop event lacks thread_id"))?;
                let status = event.get("status").cloned().ok_or_else(|| anyhow!("Stop event lacks status"))?;
                state.execution_state = "stopped";
                let mut record = json!({"type": "stop", "pid": pid, "session_id": state.session_id});
                if let (Some(fields), Value::Object(extra)) = (record.as_object_mut(), event) {
                    fields.extend(extra);
                }
                state.publish(record);
                state.last_stop = json!({"thread_id": thread_id, "status": status,
                    "session_id": state.session_id, "sequence": state.sequence});
                Ok(())
            }).err(),
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
        let _state = lock(&self.debug);
        lock(&self.registry).workbench.close()
    }

    pub fn state(&self) -> Value {
        let state = lock(&self.debug);
        let registry = lock(&self.registry);
        json!({"controller": state.controller, "attached_pid": registry.workbench.debugger.attached_pid,
            "profile_sha256": registry.workbench.profile.fingerprint(), "host": registry.workbench.profile.host(),
            "event_cursor": state.sequence, "event_channel_failed": state.event_failure,
            "session_id": state.session_id, "execution_state": state.execution_state,
            "last_stop": state.last_stop, "hardware_compatibility_guaranteed": false})
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
        if !is_shared(name) {
            return lock(&self.registry).call(name, arguments);
        }
        let mut state = lock(&self.debug);
        let mut registry = lock(&self.registry);
        if name == "payload_execute" && registry.workbench.debugger.attached_pid.is_some() {
            bail!("Detach the active debug session before sending a payload");
        }
        let description = registry.available().into_iter()
            .find(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| anyhow!("Unknown or locally disabled tool: {name}"))?;
        validate(&arguments, description.get("inputSchema").unwrap_or(&json!({"type": "object"})), "arguments")?;
        if let Some(permission) = tool_permission(&description, name) {
            registry.workbench.profile.require(&permission)?;
        }
        let control = CONTROL_TOOLS.contains(&name);
        if control && state.controller.as_deref().is_some_and(|owner| owner != client) {
            bail!("Another client owns debug control; observers may still read memory and events");
        }
        let claimed = name == "debug_attach" && state.controller.is_none();
        if claimed {
            state.controller = Some(client.to_string());
            state.session_id = Some(uuid::Uuid::new_v4().simple().to_string());
            state.execution_state = "attaching";
            state.last_stop = Value::Null;
        }
        let action = arguments.get("action").and_then(Value::as_str).map(str::to_string);
        let result = match registry.call(name, arguments) {
            Ok(result) => result,
            Err(error) => {
                if control || (registry.workbench.debugger.attached_pid.is_none() && state.controller.is_some()) {
                    state.execution_state = "uncertain";
                }
                if claimed {
                    state.publish(json!({"type": "session_error", "error": "Attach failed; inspect console before retrying",
                        "console_state": "uncertain"}));
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
        } else if name == "debug_control" {
            match action.as_deref() {
                Some("halt") => state.execution_state = "halting",
                Some("resume" | "step" | "step_thread") => state.execution_state = "running",
                _ => {}
            }
        }
        Ok(result)
    }

    fn analysis_call(&self, name: &str, arguments: Value) -> Result<Value> {
        let description = analysis_tools().into_iter()
            .find(|tool| tool["name"] == name)
            .ok_or_else(|| anyhow!("Unknown static-analysis tool"))?;
        validate(&arguments, &description["inputSchema"], "arguments")?;
        if name == "analysis_status" {
            return Ok(self.analysis.status());
        }
        let mut fields = arguments.as_object().cloned().unwrap_or_default();
        let target = fields.remove("target").and_then(|value| value.as_str().map(str::to_string)).unwrap_or_default();
        let operation = name.trim_start_matches("analysis_");
        let result = self.analysis.submit(&target, operation, Value::Object(fields), JOB_TIMEOUT)?;
        let encoded = python_json(&result, None, false);
        if encoded.len() > MAX_INLINE_RESULT {
            let store = lock(&self.registry).workbench.store.clone();
            let saved = store.save("static-analysis", encoded.as_bytes(), json!({"tool": name}), "json")?;
            return Ok(json!({"result_saved": saved}));
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
                {
                    let mut state = lock(&self.debug);
                    if state.controller.as_deref() != Some(client) {
                        bail!("Only the controlling client can release its lease");
                    }
                    if lock(&self.registry).workbench.debugger.attached_pid.is_some() {
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
        let mut settings: Value = serde_json::from_str(include_str!("../profiles/ps4-1400.json")).unwrap();
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
        let registry = ToolRegistry::new(Workbench::new(profile).unwrap()).unwrap();
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
        assert_eq!(token_file(&Profile::load(&fixture.profile_path).unwrap()), fixture.directory.path().join("broker-token.local"));
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
    }
}
