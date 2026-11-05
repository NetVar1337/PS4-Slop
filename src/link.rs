//! Passive connection health and bounded retry policy for console services.
//!
//! Health is recorded when a service is actually used; nothing here probes the
//! console in the background (the debugger port accepts one client, and a loader
//! connection can have side effects). Retries apply only to idempotent
//! operations (reads, listings, connection establishment). Mutations and
//! payload sends are never retried.

use crate::Result;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::ErrorKind,
    sync::{Mutex, MutexGuard, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Default, Clone)]
struct ServiceHealth {
    successes: u64,
    failures: u64,
    consecutive_failures: u32,
    retries: u64,
    last_ok: Option<u64>,
    last_error: Option<String>,
    last_error_at: Option<u64>,
}

fn table() -> MutexGuard<'static, BTreeMap<&'static str, ServiceHealth>> {
    static TABLE: OnceLock<Mutex<BTreeMap<&'static str, ServiceHealth>>> = OnceLock::new();
    TABLE
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub fn record_ok(service: &'static str) {
    let mut table = table();
    let entry = table.entry(service).or_default();
    entry.successes += 1;
    entry.consecutive_failures = 0;
    entry.last_ok = Some(now());
}

pub fn record_err(service: &'static str, error: &anyhow::Error) {
    let mut table = table();
    let entry = table.entry(service).or_default();
    entry.failures += 1;
    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    entry.last_error = Some(format!("{error:#}").chars().take(300).collect());
    entry.last_error_at = Some(now());
}

pub fn record_retry(service: &'static str) {
    table().entry(service).or_default().retries += 1;
}

fn state(entry: &ServiceHealth) -> &'static str {
    match (entry.successes + entry.failures, entry.consecutive_failures) {
        (0, _) => "unknown",
        (_, 0) => "up",
        (_, 1 | 2) => "degraded",
        _ => "down",
    }
}

/// Per-service health since this process started. "up" means the last operation
/// succeeded, not that the protocol or firmware is compatible.
pub fn snapshot() -> Value {
    let table = table();
    let mut result = json!({});
    for service in ["ftp", "klog", "debug", "payload"] {
        let entry = table.get(service).cloned().unwrap_or_default();
        result[service] = json!({
            "state": state(&entry),
            "successes": entry.successes,
            "failures": entry.failures,
            "consecutive_failures": entry.consecutive_failures,
            "retries": entry.retries,
            "last_ok_unix": entry.last_ok,
            "last_error": entry.last_error,
            "last_error_unix": entry.last_error_at,
        });
    }
    result
}

/// True for connection-level failures that are safe to retry for idempotent
/// operations: refused/reset/aborted/timed-out sockets, early EOF, and FTP
/// 421/425/426 "service or data connection unavailable" replies.
pub fn is_transient(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::BrokenPipe
                    | ErrorKind::TimedOut
                    | ErrorKind::WouldBlock
                    | ErrorKind::UnexpectedEof
            );
        }
        let text = cause.to_string();
        text.contains("disconnected")
            || ["421", "425", "426"]
                .iter()
                .any(|code| text.contains(&format!("rejected: {code}")))
    })
}

const BACKOFF_MILLIS: [u64; 3] = [150, 450, 1000];

/// Run an **idempotent** operation up to `attempts` times, backing off between
/// transient failures. Non-transient errors return immediately. Every attempt is
/// recorded in the health table.
pub fn retry<T>(
    service: &'static str,
    attempts: u32,
    mut operation: impl FnMut() -> Result<T>,
) -> Result<T> {
    let attempts = attempts.clamp(1, 4);
    let mut attempt = 0;
    loop {
        attempt += 1;
        match operation() {
            Ok(value) => {
                record_ok(service);
                return Ok(value);
            }
            Err(error) => {
                record_err(service, &error);
                if attempt >= attempts || !is_transient(&error) {
                    return Err(error);
                }
                record_retry(service);
                let delay = BACKOFF_MILLIS[(attempt as usize - 1).min(BACKOFF_MILLIS.len() - 1)];
                std::thread::sleep(Duration::from_millis(delay));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    // Tests share the global table; use distinct service names via the public
    // API and assert only on deltas for the service each test owns.
    fn counters(service: &str) -> (u64, u64, u64) {
        let snapshot = snapshot();
        (
            snapshot[service]["successes"].as_u64().unwrap(),
            snapshot[service]["failures"].as_u64().unwrap(),
            snapshot[service]["retries"].as_u64().unwrap(),
        )
    }

    #[test]
    fn transient_errors_are_retried_then_recorded() {
        let before = counters("klog");
        let mut calls = 0;
        let value = retry("klog", 3, || {
            calls += 1;
            if calls < 3 {
                Err(std::io::Error::from(ErrorKind::ConnectionReset).into())
            } else {
                Ok(7)
            }
        })
        .unwrap();
        assert_eq!((value, calls), (7, 3));
        let after = counters("klog");
        assert_eq!(after.0 - before.0, 1);
        assert_eq!(after.1 - before.1, 2);
        assert_eq!(after.2 - before.2, 2);
    }

    #[test]
    fn permanent_errors_are_not_retried() {
        let mut calls = 0;
        let result: Result<()> = retry("debug", 3, || {
            calls += 1;
            Err(anyhow!("Debugger firmware mismatch: 9.00"))
        });
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }

    #[test]
    fn classification_covers_ftp_and_socket_failures() {
        assert!(is_transient(&anyhow!("FTP command rejected: 421 busy")));
        assert!(is_transient(&anyhow!("FTP command rejected: 425 no data")));
        assert!(!is_transient(&anyhow!("FTP command rejected: 550 missing")));
        assert!(is_transient(&anyhow!("Debugger disconnected mid-response")));
        assert!(!is_transient(&anyhow!("Unsupported debugger protocol")));
    }

    #[test]
    fn health_state_transitions() {
        let mut entry = ServiceHealth::default();
        assert_eq!(state(&entry), "unknown");
        entry.failures = 1;
        entry.consecutive_failures = 1;
        assert_eq!(state(&entry), "degraded");
        entry.consecutive_failures = 3;
        assert_eq!(state(&entry), "down");
        entry.consecutive_failures = 0;
        entry.successes = 1;
        assert_eq!(state(&entry), "up");
    }
}
