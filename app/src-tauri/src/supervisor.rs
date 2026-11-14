// app/src-tauri/src/supervisor.rs
//
// owns the engine sidecar for the whole app lifetime: spawns it, reads the
// stdout handshake, notices when it dies after the handshake, respawns it with
// backoff and republishes the endpoint, and stops it gracefully on exit
// the ui hears about all of it through two tauri events:
//   engine-crashed   {reason, exit_code, restarts, retry_in_ms, log_path}
//                    retry_in_ms is null once the supervisor gives up
//   engine-restarted {port, generation}
// after engine-restarted (or an sse drop) the ui re-invokes engine_endpoint

use crate::engine_log::EngineLog;
use serde::Serialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};

/// how long a launch may take to report its port, long because a human might
/// be clicking through an elevation prompt; the ui uses the same number
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(180);
/// a run this long resets the crash counter, so one crash an hour never
/// accumulates into giving up
const STABLE_RUN: Duration = Duration::from_secs(60);
/// consecutive short-lived runs before the supervisor stops respawning
const MAX_FAST_FAILURES: u32 = 5;
/// how long a graceful stop may take before the process is killed
const STOP_GRACE: Duration = Duration::from_secs(4);

pub const EVENT_CRASHED: &str = "engine-crashed";
pub const EVENT_RESTARTED: &str = "engine-restarted";

/// lock that survives a panic elsewhere, the guarded data is plain state that
/// stays consistent between statements, so a poisoned lock is still usable
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Endpoint {
    pub port: u16,
    pub token: String,
    /// bumps on every successful handshake, a changed value means a new engine
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Starting,
    Running,
    Restarting,
    Failed,
    Stopped,
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub phase: Phase,
    pub generation: u64,
    pub restarts: u32,
    pub port: Option<u16>,
    pub last_error: Option<String>,
    pub log_path: String,
}

#[derive(Clone, Debug, Serialize)]
struct CrashedEvent {
    reason: String,
    exit_code: Option<i32>,
    restarts: u32,
    retry_in_ms: Option<u64>,
    log_path: String,
}

#[derive(Clone, Debug, Serialize)]
struct RestartedEvent {
    port: u16,
    generation: u64,
}

struct Inner {
    endpoint: Option<Endpoint>,
    /// set only when the supervisor gave up, wakes engine_endpoint waiters
    failure: Option<String>,
    phase: Phase,
    generation: u64,
    restarts: u32,
    last_error: Option<String>,
    /// the current endpoint belongs to an engine some other process started
    adopted: bool,
    restart_requested: bool,
    shutting_down: bool,
}

pub struct Engine {
    inner: Mutex<Inner>,
    changed: Condvar,
    child: Mutex<Option<Child>>,
    /// per-launch bearer token handed to the engine through SLOP_MCP_TOKEN so
    /// it never travels through stdout; empty when no secure rng was available,
    /// then the engine prints its persisted token instead
    token: String,
    log: Arc<EngineLog>,
}

impl Engine {
    pub fn new(log: Arc<EngineLog>) -> Self {
        let token = match random_token() {
            Ok(t) => t,
            Err(e) => {
                log.line("supervisor", &format!("no secure rng for a launch token ({e}); using the engine's persisted token"));
                String::new()
            }
        };
        Self {
            inner: Mutex::new(Inner {
                endpoint: None,
                failure: None,
                phase: Phase::Starting,
                generation: 0,
                restarts: 0,
                last_error: None,
                adopted: false,
                restart_requested: false,
                shutting_down: false,
            }),
            changed: Condvar::new(),
            child: Mutex::new(None),
            token,
            log,
        }
    }

    pub fn status(&self) -> Status {
        let inner = lock(&self.inner);
        Status {
            phase: inner.phase,
            generation: inner.generation,
            restarts: inner.restarts,
            port: inner.endpoint.as_ref().map(|e| e.port),
            last_error: inner.last_error.clone(),
            log_path: self.log.path().display().to_string(),
        }
    }

    /// returns the generation and whether an earlier engine was live before
    fn publish(&self, port: u16, token: String) -> (u64, bool) {
        let mut inner = lock(&self.inner);
        inner.generation += 1;
        let generation = inner.generation;
        inner.endpoint = Some(Endpoint { port, token, generation });
        inner.failure = None;
        // a handover line (SLOP_ENGINE_EXISTING) follows and flips this back
        inner.adopted = false;
        inner.phase = Phase::Running;
        drop(inner);
        self.changed.notify_all();
        (generation, generation > 1)
    }

    fn note_error(&self, reason: &str) {
        lock(&self.inner).last_error = Some(reason.to_string());
    }

    fn begin_restart(&self, reason: &str) -> u32 {
        let mut inner = lock(&self.inner);
        inner.endpoint = None;
        inner.adopted = false;
        inner.phase = Phase::Restarting;
        inner.last_error = Some(reason.to_string());
        inner.restarts += 1;
        inner.restarts
    }

    pub fn give_up(&self, reason: &str) {
        let mut inner = lock(&self.inner);
        inner.endpoint = None;
        inner.adopted = false;
        inner.phase = Phase::Failed;
        inner.failure = Some(reason.to_string());
        inner.last_error = Some(reason.to_string());
        drop(inner);
        self.changed.notify_all();
    }

    fn shutting_down(&self) -> bool {
        lock(&self.inner).shutting_down
    }

    fn interrupted(&self) -> bool {
        let inner = lock(&self.inner);
        inner.shutting_down || inner.restart_requested
    }

    fn take_restart_request(&self) -> bool {
        std::mem::take(&mut lock(&self.inner).restart_requested)
    }

    /// waits for the handshake of the current or next engine; blocks through a
    /// restart in progress and only errors once the supervisor gave up
    pub fn wait(&self, timeout: Duration) -> Result<Endpoint, String> {
        let deadline = Instant::now() + timeout;
        let mut inner = lock(&self.inner);
        loop {
            if let Some(ep) = inner.endpoint.clone() {
                return Ok(ep);
            }
            if let Some(err) = inner.failure.clone() {
                return Err(err);
            }
            if inner.shutting_down {
                return Err("engine is shutting down".into());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("engine did not report a listening port in time".into());
            }
            inner = self
                .changed
                .wait_timeout(inner, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// sleeps through a backoff delay; false when shutdown interrupted it
    /// a restart request cuts the delay short
    fn backoff_sleep(&self, delay: Duration) -> bool {
        let deadline = Instant::now() + delay;
        let mut inner = lock(&self.inner);
        loop {
            if inner.shutting_down {
                return false;
            }
            if inner.restart_requested {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return true;
            }
            inner = self
                .changed
                .wait_timeout(inner, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// parks a supervisor that gave up until restart_engine or shutdown
    fn park_until_restart(&self) -> bool {
        let mut inner = lock(&self.inner);
        loop {
            if inner.shutting_down {
                return false;
            }
            if inner.restart_requested {
                return true;
            }
            inner = self.changed.wait(inner).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// marks shutdown; false when another caller already started it
    fn begin_shutdown(&self) -> bool {
        let mut inner = lock(&self.inner);
        if inner.shutting_down {
            return false;
        }
        inner.shutting_down = true;
        drop(inner);
        self.changed.notify_all();
        true
    }

    fn owned_endpoint(&self) -> Option<Endpoint> {
        let inner = lock(&self.inner);
        if inner.adopted {
            None
        } else {
            inner.endpoint.clone()
        }
    }

    fn child_running(&self) -> bool {
        lock(&self.child)
            .as_mut()
            .is_some_and(|c| matches!(c.try_wait(), Ok(None)))
    }

    /// polls the current child until it exits, then forgets it
    fn reap(&self) -> Option<ExitStatus> {
        loop {
            {
                let mut slot = lock(&self.child);
                let status = slot.as_mut()?.try_wait();
                match status {
                    Ok(Some(st)) => {
                        *slot = None;
                        return Some(st);
                    }
                    Ok(None) => {}
                    Err(_) => {
                        *slot = None;
                        return None;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// asks our own engine to quit through its api, kills it after the grace
    /// period; the child stays in the slot so the supervisor still reaps it
    fn stop_child(&self, reason: &str) {
        if !self.child_running() {
            return;
        }
        if let Some(ep) = self.owned_endpoint() {
            if let Err(e) = request_quit(ep.port, &ep.token, reason) {
                self.log.line("supervisor", &format!("graceful stop request failed: {e}"));
            }
        }
        let deadline = Instant::now() + STOP_GRACE;
        while Instant::now() < deadline {
            if !self.child_running() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut slot = lock(&self.child);
        if let Some(c) = slot.as_mut() {
            if matches!(c.try_wait(), Ok(None)) {
                self.log.line("supervisor", "engine did not stop in time, killing it");
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

/// shutdown for app exit, safe to call more than once and from any thread
pub fn shutdown(app: &AppHandle) {
    let engine = app.state::<Engine>();
    if !engine.begin_shutdown() {
        return;
    }
    engine.log.line("supervisor", "app exiting, stopping engine");
    engine.stop_child("front end exited");
    lock(&engine.inner).phase = Phase::Stopped;
}

/// restart on request: re-arms a supervisor that gave up, or cycles a live
/// engine without counting it as a crash
pub fn request_restart(app: &AppHandle) -> Result<(), String> {
    let engine = app.state::<Engine>();
    {
        let mut inner = lock(&engine.inner);
        if inner.shutting_down {
            return Err("engine is shutting down".into());
        }
        if inner.restart_requested {
            return Ok(());
        }
        inner.restart_requested = true;
        inner.failure = None;
        inner.endpoint = None;
        inner.phase = Phase::Restarting;
    }
    engine.changed.notify_all();
    engine.log.line("supervisor", "restart requested by the ui");
    let app = app.clone();
    std::thread::spawn(move || app.state::<Engine>().stop_child("restart requested"));
    Ok(())
}

/// supervisor thread entry, never panics out: a panic is logged and turned
/// into the failed state so the ui sees it rather than a silent dead engine
pub fn run(app: AppHandle, path: Result<PathBuf, String>) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| supervise(&app, path)));
    if result.is_err() {
        let engine = app.state::<Engine>();
        let reason = format!("engine supervisor crashed; see {}", engine.log.path().display());
        engine.give_up(&reason);
        emit_crashed(&app, &engine, &reason, None, None);
    }
}

fn supervise(app: &AppHandle, path: Result<PathBuf, String>) {
    let engine = app.state::<Engine>();
    let path = match path {
        Ok(p) => p,
        Err(e) => {
            // nothing to retry, the binary is missing
            engine.log.line("supervisor", &e);
            engine.give_up(&e);
            emit_crashed(app, &engine, &e, None, None);
            return;
        }
    };

    let mut fast_failures = 0u32;
    loop {
        if engine.shutting_down() {
            break;
        }
        engine.take_restart_request();
        let started = Instant::now();
        let outcome = run_once(app, &engine, &path);
        if engine.shutting_down() {
            break;
        }
        if engine.take_restart_request() {
            fast_failures = 0;
            let restarts = engine.begin_restart("restart requested");
            engine.log.line("supervisor", &format!("restarting engine on request (restart #{restarts})"));
            continue;
        }

        let reason = outcome.describe();
        engine.log.line("supervisor", &reason);
        if outcome.published && started.elapsed() >= STABLE_RUN {
            fast_failures = 0;
        }
        fast_failures += 1;
        let exit_code = outcome.exit.and_then(|s| s.code());

        if fast_failures > MAX_FAST_FAILURES {
            let msg = format!(
                "{reason}; gave up after {MAX_FAST_FAILURES} restarts in quick succession (log: {})",
                engine.log.path().display()
            );
            engine.log.line("supervisor", &msg);
            engine.give_up(&msg);
            emit_crashed(app, &engine, &msg, exit_code, None);
            if !engine.park_until_restart() {
                break;
            }
            fast_failures = 0;
            continue;
        }

        let delay = backoff(fast_failures);
        let restarts = engine.begin_restart(&reason);
        engine.log.line(
            "supervisor",
            &format!("restarting engine in {} ms (restart #{restarts})", delay.as_millis()),
        );
        emit_crashed(app, &engine, &reason, exit_code, Some(delay));
        if !engine.backoff_sleep(delay) {
            break;
        }
    }
    lock(&engine.inner).phase = Phase::Stopped;
}

/// 0.5s, 1s, 2s, 4s, 8s ... capped at 30s, failures counts from 1
pub fn backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    Duration::from_millis((500u64 << shift).min(30_000))
}

fn emit_crashed(
    app: &AppHandle,
    engine: &Engine,
    reason: &str,
    exit_code: Option<i32>,
    retry: Option<Duration>,
) {
    let payload = CrashedEvent {
        reason: reason.to_string(),
        exit_code,
        restarts: lock(&engine.inner).restarts,
        retry_in_ms: retry.map(|d| d.as_millis() as u64),
        log_path: engine.log.path().display().to_string(),
    };
    if let Err(e) = app.emit(EVENT_CRASHED, payload) {
        engine.log.line("supervisor", &format!("could not emit {EVENT_CRASHED}: {e}"));
    }
}

struct Outcome {
    published: bool,
    exit: Option<ExitStatus>,
    /// spawn error or the engine's own SLOP_ENGINE_FAILED message
    error: Option<String>,
    /// the child handed over to an engine that was already running
    adopted: bool,
    adopted_pid: Option<u32>,
}

impl Outcome {
    fn describe(&self) -> String {
        if self.adopted && self.published {
            let pid = self.adopted_pid.map_or_else(|| "?".to_string(), |p| p.to_string());
            return format!("adopted engine (pid {pid}) is gone");
        }
        let code = self.exit.map(describe_exit).unwrap_or_else(|| "unknown exit status".into());
        match (&self.error, self.published) {
            (Some(e), _) => format!("{e} ({code})"),
            (None, true) => format!("engine exited unexpectedly ({code})"),
            (None, false) => format!("engine exited before reporting a port ({code})"),
        }
    }
}

fn describe_exit(status: ExitStatus) -> String {
    match status.code() {
        // ntstatus crash codes read better in hex, 0xC0000005 and friends
        Some(c) if c < 0 => format!("exit code 0x{:08X}", c as u32),
        Some(c) => format!("exit code {c}"),
        None => "terminated by signal".into(),
    }
}

/// one stdout line from the engine
#[derive(Debug, PartialEq, Eq)]
pub enum Line<'a> {
    Ready { port: u16, token: Option<&'a str> },
    Malformed,
    Existing(Option<u32>),
    Failed(&'a str),
    Log,
}

pub fn parse_line(line: &str) -> Line<'_> {
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some("SLOP_ENGINE_READY") => match parts.next().and_then(|p| p.parse::<u16>().ok()) {
            Some(port) if port != 0 => Line::Ready { port, token: parts.next() },
            _ => Line::Malformed,
        },
        Some("SLOP_ENGINE_EXISTING") => Line::Existing(parts.next().and_then(|p| p.parse().ok())),
        Some("SLOP_ENGINE_FAILED") => {
            Line::Failed(line.trim_start().trim_start_matches("SLOP_ENGINE_FAILED").trim())
        }
        _ => Line::Log,
    }
}

fn run_once(app: &AppHandle, engine: &Engine, path: &Path) -> Outcome {
    let mut out = Outcome { published: false, exit: None, error: None, adopted: false, adopted_pid: None };

    let mut cmd = Command::new(path);
    cmd.arg("--headless")
        .arg("--parent-pid")
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !engine.token.is_empty() {
        cmd.env("SLOP_MCP_TOKEN", &engine.token);
    }
    // the engine is a console subsystem binary; without this a black console
    // flashes up beside the window on every launch
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    engine.log.line("supervisor", &format!("starting {}", path.display()));
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            out.error = Some(format!("failed to start {}: {e}", path.display()));
            return out;
        }
    };

    #[cfg(windows)]
    if let Err(e) = crate::job::adopt(&child) {
        engine.log.line("supervisor", &format!("engine job object unavailable ({e}); relying on parent watch"));
    }

    let stdout = child.stdout.take();
    if let Some(stderr) = child.stderr.take() {
        let app = app.clone();
        std::thread::spawn(move || {
            let engine = app.state::<Engine>();
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                engine.log.line("engine", &line);
            }
        });
    }
    *lock(&engine.child) = Some(child);

    if let Some(stdout) = stdout {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            match parse_line(&line) {
                Line::Ready { port, token } => {
                    let token = token.map(str::to_string).unwrap_or_else(|| engine.token.clone());
                    let (generation, restarted) = engine.publish(port, token);
                    out.published = true;
                    engine.log.line("supervisor", &format!("engine listening on 127.0.0.1:{port} (generation {generation})"));
                    if restarted {
                        if let Err(e) = app.emit(EVENT_RESTARTED, RestartedEvent { port, generation }) {
                            engine.log.line("supervisor", &format!("could not emit {EVENT_RESTARTED}: {e}"));
                        }
                    }
                }
                Line::Existing(pid) => {
                    out.adopted = true;
                    out.adopted_pid = pid;
                    lock(&engine.inner).adopted = true;
                    engine.log.line("supervisor", &format!("handed over to an engine that was already running (pid {})", pid.map_or("?".into(), |p| p.to_string())));
                }
                Line::Failed(msg) => {
                    let msg = format!("engine reported failure: {msg}");
                    engine.note_error(&msg);
                    engine.log.line("supervisor", &msg);
                    out.error = Some(msg);
                }
                Line::Malformed => {
                    let msg = format!("malformed handshake: {line}");
                    engine.note_error(&msg);
                    engine.log.line("supervisor", &msg);
                    out.error = Some(msg);
                }
                Line::Log => engine.log.line("stdout", &line),
            }
        }
    }

    // stdout closed: the process is exiting or gone
    out.exit = engine.reap();

    // a handed-over engine outlives our short-lived child, supervise that one
    if out.published && out.adopted && lock(&engine.inner).adopted {
        let port = lock(&engine.inner).endpoint.as_ref().map(|e| e.port).unwrap_or(0);
        watch_external(engine, out.adopted_pid, port);
    }
    out
}

/// blocks until the adopted engine is gone, or shutdown or a restart request
fn watch_external(engine: &Engine, pid: Option<u32>, port: u16) {
    #[cfg(windows)]
    if let Some(pid) = pid {
        if let Some(handle) = win::open_sync(pid) {
            while !engine.interrupted() {
                if handle.wait(Duration::from_millis(250)) {
                    return;
                }
            }
            return;
        }
    }
    let _ = pid;
    // no handle to wait on: three refused connections in a row means it's gone
    let mut misses = 0;
    while !engine.interrupted() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            misses = 0;
        } else {
            misses += 1;
            if misses >= 3 {
                return;
            }
        }
        for _ in 0..10 {
            if engine.interrupted() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// POST /api/v1 {tool: app, action: shutdown}, the same request File > Exit sends
fn request_quit(port: u16, token: &str, reason: &str) -> Result<(), String> {
    let body = serde_json::json!({
        "tool": "app",
        "action": "shutdown",
        "params": { "reason": reason },
    })
    .to_string();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(1000))
        .map_err(|e| format!("connect: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));
    let auth = if token.is_empty() { String::new() } else { format!("Authorization: Bearer {token}\r\n") };
    let request = format!(
        "POST /api/v1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).map_err(|e| format!("send: {e}"))?;
    let mut head = [0u8; 64];
    let n = stream.read(&mut head).map_err(|e| format!("receive: {e}"))?;
    let status_line = String::from_utf8_lossy(&head[..n]);
    match status_line.split_whitespace().nth(1) {
        Some("200") => Ok(()),
        Some(code) => Err(format!("engine answered HTTP {code}")),
        None => Err("engine closed the connection without answering".into()),
    }
}

/// 32 random bytes as hex from the os csprng
fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(windows)]
fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    // SAFETY: buf is a valid writable slice of the length passed
    let status = unsafe {
        BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    if status == 0 {
        Ok(())
    } else {
        Err(format!("BCryptGenRandom failed with 0x{:08X}", status as u32))
    }
}

#[cfg(not(windows))]
fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|e| e.to_string())
}

#[cfg(windows)]
mod win {
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};

    pub struct ProcessHandle(HANDLE);

    pub fn open_sync(pid: u32) -> Option<ProcessHandle> {
        // SAFETY: plain win32 call, a null result is handled
        let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        (!h.is_null()).then_some(ProcessHandle(h))
    }

    impl ProcessHandle {
        /// true once the process has exited
        pub fn wait(&self, timeout: Duration) -> bool {
            // SAFETY: the handle is open for SYNCHRONIZE until drop
            unsafe { WaitForSingleObject(self.0, timeout.as_millis() as u32) == WAIT_OBJECT_0 }
        }
    }

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            // SAFETY: we own the handle
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_handshake_lines() {
        assert_eq!(
            parse_line("SLOP_ENGINE_READY 8765 abc"),
            Line::Ready { port: 8765, token: Some("abc") }
        );
        // tokenless form used when the supervisor passes SLOP_MCP_TOKEN
        assert_eq!(parse_line("SLOP_ENGINE_READY 8765"), Line::Ready { port: 8765, token: None });
        assert_eq!(parse_line("SLOP_ENGINE_READY 0 abc"), Line::Malformed);
        assert_eq!(parse_line("SLOP_ENGINE_READY nope"), Line::Malformed);
        assert_eq!(parse_line("SLOP_ENGINE_READY"), Line::Malformed);
        assert_eq!(parse_line("SLOP_ENGINE_EXISTING 4242"), Line::Existing(Some(4242)));
        assert_eq!(parse_line("SLOP_ENGINE_EXISTING"), Line::Existing(None));
        assert_eq!(
            parse_line("SLOP_ENGINE_FAILED mcp server did not bind"),
            Line::Failed("mcp server did not bind")
        );
        assert_eq!(parse_line("boot: stage 3/6"), Line::Log);
        assert_eq!(parse_line(""), Line::Log);
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let ms: Vec<u128> = (1..=8).map(|n| backoff(n).as_millis()).collect();
        assert_eq!(ms, [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000]);
        assert_eq!(backoff(0).as_millis(), 500);
        assert_eq!(backoff(u32::MAX).as_millis(), 30000);
    }

    #[test]
    fn outcome_descriptions_distinguish_cases() {
        let none = Outcome { published: false, exit: None, error: None, adopted: false, adopted_pid: None };
        assert!(none.describe().starts_with("engine exited before reporting a port"));
        let crashed = Outcome { published: true, ..none };
        assert!(crashed.describe().starts_with("engine exited unexpectedly"));
        let failed = Outcome {
            published: false,
            exit: None,
            error: Some("engine reported failure: x".into()),
            adopted: false,
            adopted_pid: None,
        };
        assert!(failed.describe().starts_with("engine reported failure: x"));
        let adopted = Outcome { published: true, exit: None, error: None, adopted: true, adopted_pid: Some(7) };
        assert_eq!(adopted.describe(), "adopted engine (pid 7) is gone");
        let unknown = Outcome { adopted_pid: None, ..adopted };
        assert_eq!(unknown.describe(), "adopted engine (pid ?) is gone");
    }

    #[test]
    fn random_tokens_are_64_hex_and_distinct() {
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    fn engine() -> Engine {
        let dir = std::env::temp_dir().join(format!("slop-supervisor-test-{}", std::process::id()));
        Engine::new(Arc::new(EngineLog::at(dir.join("engine.log"), 1 << 20)))
    }

    #[test]
    fn wait_blocks_through_restart_and_returns_new_endpoint() {
        let e = Arc::new(engine());
        let (g1, restarted) = e.publish(1000, "t".into());
        assert_eq!((g1, restarted), (1, false));
        e.begin_restart("crash");
        assert_eq!(e.status().phase, Phase::Restarting);
        let e2 = Arc::clone(&e);
        let waiter = std::thread::spawn(move || e2.wait(Duration::from_secs(10)));
        std::thread::sleep(Duration::from_millis(100));
        let (g2, restarted) = e.publish(2000, "t".into());
        assert_eq!((g2, restarted), (2, true));
        let ep = waiter.join().unwrap().unwrap();
        assert_eq!((ep.port, ep.generation), (2000, 2));
        assert_eq!(e.status().restarts, 1);
    }

    #[test]
    fn wait_errors_once_supervisor_gives_up_and_times_out_otherwise() {
        let e = engine();
        assert!(e.wait(Duration::from_millis(30)).unwrap_err().contains("in time"));
        e.give_up("boom");
        assert_eq!(e.wait(Duration::from_secs(10)).unwrap_err(), "boom");
        assert_eq!(e.status().phase, Phase::Failed);
    }

    #[test]
    fn shutdown_interrupts_backoff_and_parking() {
        let e = Arc::new(engine());
        let e2 = Arc::clone(&e);
        let sleeper = std::thread::spawn(move || e2.backoff_sleep(Duration::from_secs(30)));
        let e3 = Arc::clone(&e);
        let parked = std::thread::spawn(move || e3.park_until_restart());
        std::thread::sleep(Duration::from_millis(100));
        assert!(e.begin_shutdown());
        assert!(!e.begin_shutdown(), "second shutdown is a no-op");
        assert!(!sleeper.join().unwrap());
        assert!(!parked.join().unwrap());
        assert!(e.wait(Duration::from_secs(1)).is_err());
    }

    #[test]
    fn poisoned_state_lock_is_recovered() {
        let e = Arc::new(engine());
        let e2 = Arc::clone(&e);
        let _ = std::thread::spawn(move || {
            let _guard = e2.inner.lock().unwrap();
            panic!("poison it");
        })
        .join();
        assert!(e.inner.is_poisoned());
        e.publish(3000, "t".into());
        assert_eq!(e.wait(Duration::from_secs(1)).unwrap().port, 3000);
    }

    #[test]
    fn quit_request_reaches_api_with_bearer_token() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let mut got = Vec::new();
            loop {
                let n = s.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got);
                if let Some(at) = text.find("\r\n\r\n") {
                    let len: usize = text
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    if got.len() >= at + 4 + len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
            String::from_utf8(got).unwrap()
        });
        request_quit(port, "secret", "bye").unwrap();
        let req = server.join().unwrap();
        assert!(req.starts_with("POST /api/v1 HTTP/1.1\r\n"));
        assert!(req.contains("Authorization: Bearer secret\r\n"));
        let body: serde_json::Value = serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["tool"], "app");
        assert_eq!(body["action"], "shutdown");
        assert_eq!(body["params"]["reason"], "bye");
    }
}
