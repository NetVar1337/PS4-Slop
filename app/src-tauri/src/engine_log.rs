// app/src-tauri/src/engine_log.rs
//
// persistent log for the engine sidecar, release builds run under the windows
// subsystem so stdout and stderr go nowhere, everything the engine and the
// supervisor say lands in %LOCALAPPDATA%\reverse-slop\logs\engine.log instead
// the file rotates by size so a chatty engine can never fill the disk

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

/// rotate once the live file passes this size
pub const MAX_BYTES: u64 = 4 << 20;
/// engine.1.log .. engine.N.log are kept, older ones are dropped
pub const KEEP: u32 = 3;

struct Sink {
    file: Option<File>,
    size: u64,
}

pub struct EngineLog {
    path: PathBuf,
    max_bytes: u64,
    sink: Mutex<Sink>,
}

impl EngineLog {
    /// the standard location, falls back to the temp dir when LOCALAPPDATA is
    /// missing (service accounts, stripped environments)
    pub fn default_location() -> Self {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self::at(base.join("reverse-slop").join("logs").join("engine.log"), MAX_BYTES)
    }

    pub fn at(path: PathBuf, max_bytes: u64) -> Self {
        Self {
            path,
            max_bytes,
            sink: Mutex::new(Sink { file: None, size: 0 }),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// one line, timestamped and tagged with where it came from
    /// failures to write are swallowed on purpose, logging must never take the
    /// supervisor down with it
    pub fn line(&self, source: &str, text: &str) {
        let entry = format!("{} [{source}] {}\n", timestamp(SystemTime::now()), text.trim_end());
        if cfg!(debug_assertions) {
            eprint!("{entry}");
        }
        let mut sink = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
        self.append(&mut sink, &entry);
    }

    /// same as line but gives up instead of blocking when the log is busy,
    /// for the panic hook, which may fire while this thread holds the lock
    pub fn try_line(&self, source: &str, text: &str) {
        let entry = format!("{} [{source}] {}\n", timestamp(SystemTime::now()), text.trim_end());
        if cfg!(debug_assertions) {
            eprint!("{entry}");
        }
        let mut sink = match self.sink.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        self.append(&mut sink, &entry);
    }

    fn append(&self, sink: &mut Sink, entry: &str) {
        if sink.file.is_none() {
            self.open(sink);
        }
        if sink.file.is_some() && sink.size > 0 && sink.size + entry.len() as u64 > self.max_bytes {
            sink.file = None;
            rotate(&self.path, KEEP);
            self.open(sink);
        }
        if let Some(file) = sink.file.as_mut() {
            if file.write_all(entry.as_bytes()).is_ok() {
                sink.size += entry.len() as u64;
            } else {
                // drop the handle so the next line retries a fresh open
                sink.file = None;
            }
        }
    }

    fn open(&self, sink: &mut Sink) {
        if let Some(dir) = self.path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        // an oversized file left by a previous run rotates before we append
        if fs::metadata(&self.path).is_ok_and(|m| m.len() >= self.max_bytes) {
            rotate(&self.path, KEEP);
        }
        match OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(file) => {
                sink.size = file.metadata().map(|m| m.len()).unwrap_or(0);
                sink.file = Some(file);
            }
            Err(_) => sink.file = None,
        }
    }
}

/// engine.log -> engine.1.log -> engine.2.log ..., the oldest falls off
fn rotate(path: &Path, keep: u32) {
    let numbered = |n: u32| -> PathBuf {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("engine");
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("log");
        path.with_file_name(format!("{stem}.{n}.{ext}"))
    };
    if keep == 0 {
        let _ = fs::remove_file(path);
        return;
    }
    let _ = fs::remove_file(numbered(keep));
    for n in (1..keep).rev() {
        let from = numbered(n);
        if from.exists() {
            let _ = fs::rename(&from, numbered(n + 1));
        }
    }
    let _ = fs::rename(path, numbered(1));
}

/// utc, iso 8601 with milliseconds, no date crate needed for one format
pub fn timestamp(now: SystemTime) -> String {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let millis = since.subsec_millis();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// howard hinnant's days -> civil date
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "slop-engine-log-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn timestamp_formats_known_instants() {
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(1_709_164_800_123); // 2024-02-29
        assert_eq!(timestamp(t), "2024-02-29T00:00:00.123Z");
        let t = UNIX_EPOCH + Duration::from_secs(4_102_444_799); // 2099-12-31T23:59:59
        assert_eq!(timestamp(t), "2099-12-31T23:59:59.000Z");
    }

    #[test]
    fn writes_tagged_lines_and_creates_directories() {
        let dir = scratch("write");
        let log = EngineLog::at(dir.join("logs").join("engine.log"), MAX_BYTES);
        log.line("stdout", "hello");
        log.line("stderr", "world\r\n");
        let text = fs::read_to_string(log.path()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with(" [stdout] hello"));
        assert!(lines[1].ends_with(" [stderr] world"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotates_by_size_and_keeps_bounded_history() {
        let dir = scratch("rotate");
        let path = dir.join("engine.log");
        let log = EngineLog::at(path.clone(), 200);
        for i in 0..200 {
            log.line("stderr", &format!("line {i:04} padding padding padding"));
        }
        assert!(fs::metadata(&path).unwrap().len() <= 200);
        for n in 1..=KEEP {
            assert!(dir.join(format!("engine.{n}.log")).is_file(), "missing engine.{n}.log");
        }
        assert!(!dir.join(format!("engine.{}.log", KEEP + 1)).exists());
        // the newest line is in the live file, the history is in order
        let live = fs::read_to_string(&path).unwrap();
        assert!(live.contains("line 0199"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_file_from_previous_run_rotates_on_open() {
        let dir = scratch("reopen");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("engine.log");
        fs::write(&path, vec![b'x'; 512]).unwrap();
        let log = EngineLog::at(path.clone(), 256);
        log.line("supervisor", "fresh");
        assert_eq!(fs::metadata(dir.join("engine.1.log")).unwrap().len(), 512);
        assert!(fs::read_to_string(&path).unwrap().contains("fresh"));
        let _ = fs::remove_dir_all(&dir);
    }
}
