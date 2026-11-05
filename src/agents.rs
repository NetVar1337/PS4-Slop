use crate::Result;
use crate::client::BrokerClient;
use crate::config::require_integer;
use anyhow::{anyhow, bail};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const AGENT_TARGETS: [&str; 2] = ["ida", "ghidra"];
pub const AGENT_LIVENESS: Duration = Duration::from_secs(30);
pub const MAX_JOBS: usize = 32;
pub const JOB_TIMEOUT: Duration = Duration::from_secs(20);

struct Agent {
    client: String,
    last_seen: Instant,
    program: String,
    queue: VecDeque<String>,
}

struct Job {
    agent: String,
    operation: String,
    arguments: Value,
    done: bool,
    result: Value,
    error: Value,
}

#[derive(Default)]
struct Registry {
    agents: HashMap<String, Agent>,
    jobs: HashMap<String, Job>,
}

pub struct AnalysisAgents {
    state: Mutex<Registry>,
    completed: Condvar,
}

impl Default for AnalysisAgents {
    fn default() -> Self {
        Self::new()
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|parsed| parsed != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

fn error_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

pub fn parse_address(value: &str) -> Result<u64> {
    let parsed = match value.strip_prefix("0x") {
        Some(digits) if !digits.is_empty() && digits.chars().all(|character| character.is_ascii_hexdigit()) => {
            u128::from_str_radix(digits, 16).map_err(|_| anyhow!("Address exceeds uint64"))?
        }
        None if !value.is_empty() && value.chars().all(|character| character.is_ascii_digit()) => {
            value.parse::<u128>().map_err(|_| anyhow!("Address exceeds uint64"))?
        }
        _ => bail!("Invalid address syntax: {value}"),
    };
    u64::try_from(parsed).map_err(|_| anyhow!("Address exceeds uint64"))
}

impl AnalysisAgents {
    pub fn new() -> Self {
        Self { state: Mutex::new(Registry::default()), completed: Condvar::new() }
    }

    fn lock(&self) -> MutexGuard<'_, Registry> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn status(&self) -> Value {
        let state = self.lock();
        let mut result = Map::new();
        for (target, agent) in &state.agents {
            result.insert(target.clone(), json!({"client": agent.client,
                "connected": agent.last_seen.elapsed() < AGENT_LIVENESS, "program": agent.program}));
        }
        Value::Object(result)
    }

    pub fn register(&self, client: &str, target: &Value, program: &Value) -> Result<Value> {
        let target = target.as_str().filter(|name| AGENT_TARGETS.contains(name));
        let program = program.as_str().filter(|text| text.chars().count() <= 2048);
        let (Some(target), Some(program)) = (target, program) else {
            bail!("Register ida/ghidra with a bounded program identity");
        };
        let mut state = self.lock();
        if let Some(previous) = state.agents.get(target)
            && previous.client != client && previous.last_seen.elapsed() < AGENT_LIVENESS {
                bail!("An analysis agent is already registered for this target");
            }
        state.agents.insert(target.to_string(), Agent { client: client.to_string(), last_seen: Instant::now(),
            program: program.to_string(), queue: VecDeque::new() });
        Ok(json!({"registered": target}))
    }

    pub fn poll(&self, client: &str, target: &Value) -> Result<Value> {
        let mut guard = self.lock();
        let state = &mut *guard;
        let agent = target.as_str().and_then(|name| state.agents.get_mut(name)).filter(|agent| agent.client == client);
        let Some(agent) = agent else {
            bail!("Register this analysis agent first");
        };
        agent.last_seen = Instant::now();
        while let Some(identifier) = agent.queue.pop_front() {
            if let Some(job) = state.jobs.get(&identifier) {
                return Ok(json!({"id": identifier, "operation": job.operation, "arguments": job.arguments}));
            }
        }
        Ok(Value::Null)
    }

    pub fn unregister(&self, client: &str, target: &Value) -> Result<Value> {
        let mut state = self.lock();
        let Some(name) = target.as_str().filter(|name| state.agents.contains_key(*name)).map(str::to_string) else {
            return Ok(json!({"unregistered": false}));
        };
        if state.agents[&name].client != client {
            bail!("Cannot unregister another analysis agent");
        }
        state.agents.remove(&name);
        for job in state.jobs.values_mut() {
            if job.agent == client {
                job.error = json!("Analysis agent stopped");
                job.done = true;
            }
        }
        drop(state);
        self.completed.notify_all();
        Ok(json!({"unregistered": true}))
    }

    pub fn complete(&self, client: &str, identifier: &Value, result: Value, error: Value) -> Result<Value> {
        let mut state = self.lock();
        let Some(job) = identifier.as_str().and_then(|key| state.jobs.get_mut(key)) else {
            return Ok(json!({"accepted": false, "reason": "expired_or_unknown_job"}));
        };
        if job.agent != client {
            bail!("Foreign analysis job");
        }
        if job.done {
            bail!("Analysis job already completed");
        }
        job.result = result;
        job.error = error;
        job.done = true;
        drop(state);
        self.completed.notify_all();
        Ok(json!({"accepted": true}))
    }

    pub fn submit(&self, target: &str, operation: &str, arguments: Value, timeout: Duration) -> Result<Value> {
        if !AGENT_TARGETS.contains(&target) || !["decompile", "functions", "xrefs"].contains(&operation) {
            bail!("Unsupported static-analysis target or operation");
        }
        let Some(fields) = arguments.as_object() else {
            bail!("Analysis arguments must be an object");
        };
        let allowed: &[&str] = match operation {
            "functions" => &["offset", "limit"],
            "decompile" => &["address"],
            _ => &["address", "limit"],
        };
        if fields.keys().any(|key| !allowed.contains(&key.as_str())) {
            bail!("Unknown static-analysis arguments");
        }
        if operation != "functions" {
            let address = fields.get("address").and_then(Value::as_str).filter(|text| text.chars().count() <= 20);
            let Some(address) = address else {
                bail!("Supply a static database address string");
            };
            parse_address(address)?;
        }
        if let Some(limit) = fields.get("limit") {
            require_integer(limit, "limit", 1, 100)?;
        }
        if let Some(offset) = fields.get("offset") {
            require_integer(offset, "offset", 0, 1_000_000)?;
        }
        let identifier = uuid::Uuid::new_v4().simple().to_string();
        let mut state = self.lock();
        let agent_client = match state.agents.get(target) {
            Some(agent) if agent.last_seen.elapsed() < AGENT_LIVENESS => agent.client.clone(),
            _ => bail!("No live {target} analysis agent; start it inside the application"),
        };
        if state.jobs.len() >= MAX_JOBS {
            bail!("Analysis job queue is full");
        }
        state.jobs.insert(identifier.clone(), Job { agent: agent_client, operation: operation.to_string(),
            arguments, done: false, result: Value::Null, error: Value::Null });
        if let Some(agent) = state.agents.get_mut(target) {
            agent.queue.push_back(identifier.clone());
        }
        let deadline = Instant::now() + timeout;
        loop {
            if state.jobs.get(&identifier).is_none_or(|job| job.done) {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                state.jobs.remove(&identifier);
                bail!("Static-analysis job timed out; no automatic retry");
            }
            state = self.completed.wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner()).0;
        }
        let Some(job) = state.jobs.remove(&identifier) else {
            bail!("Static-analysis job vanished; no automatic retry");
        };
        if truthy(&job.error) {
            bail!("{}", error_text(&job.error));
        }
        Ok(job.result)
    }
}

pub type AnalysisHandler = Box<dyn Fn(&str, &Value) -> Result<Value> + Send + 'static>;

pub struct AnalysisWorker {
    client: BrokerClient,
    target: String,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    last_error: Arc<Mutex<Option<String>>>,
}

impl AnalysisWorker {
    pub fn start(client: BrokerClient, target: &str, program: &str, handler: AnalysisHandler) -> Result<Self> {
        client.request("agent_register", json!({"target": target, "program": program}))?;
        let stopping = Arc::new(AtomicBool::new(false));
        let last_error = Arc::new(Mutex::new(None));
        let worker_client = client.clone();
        let worker_target = target.to_string();
        let worker_stopping = stopping.clone();
        let worker_error = last_error.clone();
        let thread = std::thread::Builder::new().name(format!("{target}-analysis-agent")).spawn(move || {
            let record = |message: String| {
                *worker_error.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(message);
            };
            while !worker_stopping.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(200));
                if worker_stopping.load(Ordering::SeqCst) {
                    break;
                }
                let outcome = (|| -> Result<()> {
                    let job = worker_client.request("agent_poll", json!({"target": worker_target}))?;
                    if job.is_null() {
                        return Ok(());
                    }
                    let operation = job.get("operation").and_then(Value::as_str).unwrap_or_default();
                    let arguments = job.get("arguments").cloned().unwrap_or_else(|| json!({}));
                    let (result, error) = match handler(operation, &arguments) {
                        Ok(value) => (value, Value::Null),
                        Err(failure) => (Value::Null, json!(failure.to_string())),
                    };
                    let completion = worker_client.request("agent_result",
                        json!({"identifier": job.get("id").cloned().unwrap_or(Value::Null), "result": result, "error": error}))?;
                    if completion.get("accepted") != Some(&Value::Bool(true)) {
                        record("Analysis result arrived after job expiration".to_string());
                    }
                    Ok(())
                })();
                if let Err(failure) = outcome {
                    record(failure.to_string());
                    worker_stopping.store(true, Ordering::SeqCst);
                }
            }
        })?;
        Ok(Self { client, target: target.to_string(), stopping, thread: Some(thread), last_error })
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    pub fn running(&self) -> bool {
        !self.stopping.load(Ordering::SeqCst)
    }

    pub fn stop(&mut self) -> Result<()> {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take()
            && thread.thread().id() != std::thread::current().id() {
                let _ = thread.join();
            }
        let outcome = self.client.request("agent_unregister", json!({"target": self.target}));
        if let Err(failure) = &outcome {
            *self.last_error.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(failure.to_string());
        }
        outcome.map(|_| ())
    }
}

impl Drop for AnalysisWorker {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_round_trip_through_registered_agent() {
        let agents = Arc::new(AnalysisAgents::new());
        agents.register("ida-agent", &json!("ida"), &json!("abc")).unwrap();
        let submitter = agents.clone();
        let pending = std::thread::spawn(move || {
            submitter.submit("ida", "decompile", json!({"address": "0x4000"}), Duration::from_secs(5))
        });
        let job = loop {
            let job = agents.poll("ida-agent", &json!("ida")).unwrap();
            if !job.is_null() {
                break job;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(job["operation"], "decompile");
        assert_eq!(job["arguments"]["address"], "0x4000");
        let accepted = agents.complete("ida-agent", &job["id"], json!({"text": "int f();"}), Value::Null).unwrap();
        assert_eq!(accepted["accepted"], true);
        assert_eq!(pending.join().unwrap().unwrap()["text"], "int f();");
        let late = agents.complete("ida-agent", &job["id"], Value::Null, Value::Null).unwrap();
        assert_eq!(late["accepted"], false);
    }

    #[test]
    fn foreign_agent_cannot_steal_or_complete() {
        let agents = AnalysisAgents::new();
        agents.register("first", &json!("ghidra"), &json!("p")).unwrap();
        assert!(agents.register("second", &json!("ghidra"), &json!("p")).is_err());
        assert!(agents.poll("second", &json!("ghidra")).is_err());
        assert!(agents.unregister("second", &json!("ghidra")).is_err());
        assert!(agents.register("x", &json!("radare"), &json!("p")).is_err());
        assert_eq!(agents.unregister("first", &json!("ghidra")).unwrap()["unregistered"], true);
        assert_eq!(agents.unregister("first", &json!("ghidra")).unwrap()["unregistered"], false);
    }

    #[test]
    fn submit_validation_and_timeouts() {
        let agents = AnalysisAgents::new();
        assert!(agents.submit("ida", "functions", json!({}), Duration::from_millis(10)).unwrap_err()
            .to_string().contains("No live ida"));
        agents.register("a", &json!("ida"), &json!("p")).unwrap();
        assert!(agents.submit("ida", "decompile", json!({"limit": 2}), Duration::from_millis(10)).is_err());
        assert!(agents.submit("ida", "xrefs", json!({"address": "zz"}), Duration::from_millis(10)).is_err());
        assert!(agents.submit("ida", "functions", json!({"limit": 101}), Duration::from_millis(10)).is_err());
        assert!(agents.submit("ida", "write", json!({}), Duration::from_millis(10)).is_err());
        let failure = agents.submit("ida", "functions", json!({"limit": 5}), Duration::from_millis(20)).unwrap_err();
        assert!(failure.to_string().contains("timed out"));
        assert!(agents.poll("a", &json!("ida")).unwrap().is_null());
    }

    #[test]
    fn agent_error_and_unregister_fail_pending_jobs() {
        let agents = Arc::new(AnalysisAgents::new());
        agents.register("a", &json!("ida"), &json!("p")).unwrap();
        let submitter = agents.clone();
        let pending = std::thread::spawn(move || submitter.submit("ida", "functions", json!({}), Duration::from_secs(5)));
        while agents.lock().jobs.is_empty() {
            std::thread::sleep(Duration::from_millis(5));
        }
        agents.unregister("a", &json!("ida")).unwrap();
        assert!(pending.join().unwrap().unwrap_err().to_string().contains("stopped"));
    }

    #[test]
    fn addresses_parse_like_python() {
        assert_eq!(parse_address("0x10").unwrap(), 16);
        assert_eq!(parse_address("10").unwrap(), 10);
        assert!(parse_address("0x10000000000000000").is_err());
        assert!(parse_address("-1").is_err());
    }
}
