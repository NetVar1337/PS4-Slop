//! Contained, hash-recorded local artifact storage.
//!
//! Native port of `ps4_workbench/artifacts.py`. Every path is resolved through
//! symlinks/junctions (reparse points) and must stay strictly inside the
//! resolved artifact root; reads are bounded by profile limits.

use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, bail};
use serde_json::{Map, Value, json};

use crate::Result;
use crate::config::{
    Profile, canonical_json, python_json, read_bounded_file, resolve_lenient, sha256_hex,
};

/// Upper bound on directory entries examined by `inventory`.
const MAX_SCANNED_ENTRIES: usize = 1_000_000;
/// Python `bundle` accepts 1..=100 selections.
pub const MAX_BUNDLE_SELECTIONS: usize = 100;

/// Python `datetime.now(timezone.utc).isoformat()`.
pub fn utc_now() -> String {
    let now = time::OffsetDateTime::now_utc();
    let micros = now.microsecond();
    let mut text = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    if micros != 0 {
        text.push_str(&format!(".{micros:06}"));
    }
    text.push_str("+00:00");
    text
}

fn is_windows_device_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.len() == 4
        && matches!(stem.as_bytes()[3], b'0'..=b'9' | 0xB9 | 0xB2 | 0xB3))
}

/// Lexical validation shared by `ArtifactStore::path` and `new_path`.
fn validate_relative(relative: &str) -> Result<()> {
    let invalid = || anyhow!("Use a relative path inside the artifact directory");
    if relative.is_empty()
        || relative.contains(':')
        || relative.contains('\0')
        || relative.starts_with('/')
        || relative.starts_with('\\')
        || Path::new(relative).is_absolute()
        || Path::new(relative).has_root()
    {
        return Err(invalid());
    }
    for component in relative.replace('\\', "/").split('/') {
        if component == ".." {
            return Err(invalid());
        }
        if component.is_empty() || component == "." {
            continue;
        }
        if component.ends_with('.')
            || component.ends_with(' ')
            || component
                .chars()
                .any(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
            || is_windows_device_name(component)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub struct ArtifactStore {
    pub profile: Profile,
    pub root: PathBuf,
    audit_lock: Mutex<()>,
}

impl std::fmt::Debug for ArtifactStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArtifactStore")
            .field("root", &self.root)
            .finish()
    }
}

impl ArtifactStore {
    pub fn new(profile: &Profile) -> Result<Self> {
        Ok(Self {
            profile: profile.clone(),
            root: profile.artifact_root(),
            audit_lock: Mutex::new(()),
        })
    }

    fn resolved_root(&self) -> Result<PathBuf> {
        resolve_lenient(&self.root)
    }

    fn ensure_root(&self) -> Result<()> {
        fs::create_dir_all(&self.root).map_err(|error| {
            anyhow!(
                "Cannot create artifact directory {}: {error}",
                self.root.display()
            )
        })
    }

    /// Resolve a contained path that may not exist yet (Python
    /// `path(relative, must_exist=False)`).
    pub fn new_path(&self, relative: &str) -> Result<PathBuf> {
        validate_relative(relative)?;
        let root = self.resolved_root()?;
        let candidate = resolve_lenient(&root.join(relative))
            .map_err(|_| anyhow!("Artifact path escapes the artifact directory"))?;
        if !candidate.starts_with(&root) || candidate == root {
            bail!("Artifact path escapes the artifact directory");
        }
        Ok(candidate)
    }

    /// Resolve an existing contained regular file (Python `path(relative)`).
    pub fn path(&self, relative: &str) -> Result<PathBuf> {
        let candidate = self.new_path(relative)?;
        if !candidate.is_file() {
            bail!("Artifact does not exist: {relative}");
        }
        Ok(candidate)
    }

    /// Path of `absolute` relative to the artifact root, POSIX separators.
    pub fn relative_of(&self, absolute: &Path) -> Result<String> {
        let root = self.resolved_root()?;
        let resolved = resolve_lenient(absolute)?;
        let relative = resolved
            .strip_prefix(&root)
            .map_err(|_| anyhow!("Artifact path escapes the artifact directory"))?;
        let parts: Vec<String> = relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();
        if parts.is_empty() {
            bail!("Artifact path escapes the artifact directory");
        }
        Ok(parts.join("/"))
    }

    /// Read an artifact bounded by `transfer_bytes`.
    pub fn read(&self, relative: &str) -> Result<Vec<u8>> {
        self.read_bounded(relative, self.profile.limit("transfer_bytes"))
    }

    /// Read an artifact of at most `maximum` bytes (0 means `transfer_bytes`,
    /// mirroring Python's `maximum or limit`).
    pub fn read_bounded(&self, relative: &str, maximum: usize) -> Result<Vec<u8>> {
        let maximum = if maximum == 0 {
            self.profile.limit("transfer_bytes")
        } else {
            maximum
        };
        let path = self.path(relative)?;
        read_bounded_file(&path, maximum as u64).map_err(|error| {
            if error.kind() == std::io::ErrorKind::Other {
                anyhow!("Artifact exceeds the configured size limit")
            } else {
                anyhow!("Cannot read artifact {relative}: {error}")
            }
        })
    }

    fn create_new(&self, relative: &str, content: &[u8]) -> Result<()> {
        let target = self.new_path(relative)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|error| anyhow!("Cannot create artifact {relative}: {error}"))?;
        file.write_all(content)?;
        file.flush()?;
        Ok(())
    }

    /// Store `content` as `<kind>-<uuid>.<extension>` plus a JSON provenance
    /// sidecar; returns the provenance record.
    pub fn save(
        &self,
        kind: &str,
        content: &[u8],
        metadata: Value,
        extension: &str,
    ) -> Result<Value> {
        let simple = |text: &str, extra: &[char]| {
            !text.is_empty()
                && text.len() <= 64
                && text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
        };
        if !simple(kind, &['-', '_']) || !simple(extension, &[]) {
            bail!("Invalid artifact kind or extension");
        }
        let identifier = format!("{kind}-{}", uuid::Uuid::new_v4().simple());
        let relative = format!("{identifier}.{extension}");
        self.ensure_root()?;
        self.create_new(&relative, content)?;
        let metadata = if metadata.is_null() {
            Value::Object(Map::new())
        } else {
            metadata
        };
        let data = &self.profile.data;
        let record = json!({
            "id": identifier,
            "path": relative,
            "size": content.len(),
            "sha256": sha256_hex(content),
            "created_at": utc_now(),
            "profile_sha256": self.profile.fingerprint(),
            "firmware": data.get("firmware").cloned().unwrap_or(Value::Null),
            "jailbreak": data.get("jailbreak").cloned().unwrap_or(Value::Null),
            "debugger": data.get("debugger").cloned().unwrap_or(Value::Null),
            "metadata": metadata,
        });
        self.create_new(
            &format!("{relative}.json"),
            python_json(&record, Some(2), false).as_bytes(),
        )?;
        Ok(record)
    }

    /// Append a durable JSON line to `audit.jsonl`. `details` (an object or
    /// null) is merged over `time`, `action` and `profile_sha256`.
    pub fn audit(&self, action: &str, details: Value) -> Result<()> {
        let mut entry = Map::new();
        entry.insert("time".into(), Value::from(utc_now()));
        entry.insert("action".into(), Value::from(action));
        entry.insert(
            "profile_sha256".into(),
            Value::from(self.profile.fingerprint()),
        );
        match details {
            Value::Null => {}
            Value::Object(fields) => entry.extend(fields),
            _ => bail!("Audit details must be a JSON object"),
        }
        let mut line = canonical_json(&Value::Object(entry));
        line.push('\n');
        let _guard = self
            .audit_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_root()?;
        let path = self.new_path("audit.jsonl")?;
        if fs::symlink_metadata(&path).is_ok_and(|meta| !meta.is_file()) {
            bail!("Audit log is not a regular file");
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| anyhow!("Cannot open audit log: {error}"))?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    }

    /// Bounded list of artifact provenance records (sorted sidecars).
    pub fn inventory(&self) -> Result<Value> {
        if fs::symlink_metadata(&self.root).is_err() {
            return Ok(Value::Array(Vec::new()));
        }
        let root = self.resolved_root()?;
        let mut names = Vec::new();
        for (scanned, entry) in fs::read_dir(&root)?.enumerate() {
            if scanned >= MAX_SCANNED_ENTRIES {
                bail!("Artifact directory has too many entries; archive older captures locally");
            }
            let name = entry?.file_name().to_string_lossy().into_owned();
            if matches_sidecar_glob(&name) {
                names.push(name);
            }
        }
        names.sort();
        names.truncate(self.profile.limit("list_entries"));
        let limit = self.profile.limit("transfer_bytes");
        let mut total = 0usize;
        let mut result = Vec::with_capacity(names.len());
        for name in names {
            let content = self.read(&name)?;
            total += content.len();
            if total > limit {
                bail!("Artifact metadata inventory exceeds limit; archive older captures locally");
            }
            let record: Value = serde_json::from_slice(&content)
                .map_err(|error| anyhow!("Invalid artifact metadata {name}: {error}"))?;
            result.push(record);
        }
        Ok(Value::Array(result))
    }

    /// Zip selected artifacts, their sidecars and the profile into a new
    /// `experiment` artifact.
    pub fn bundle(&self, paths: &[String], notes: &str) -> Result<Value> {
        if !(1..=MAX_BUNDLE_SELECTIONS).contains(&paths.len()) {
            bail!("Select 1 to 100 artifacts");
        }
        let limit = self.profile.limit("transfer_bytes");
        let mut selected: Vec<(String, Vec<u8>)> = Vec::new();
        let mut total = 0usize;
        for relative in paths {
            let sidecar = format!("{relative}.json");
            for name in [relative.as_str(), sidecar.as_str()] {
                if name != relative && !self.new_path(name)?.is_file() {
                    continue;
                }
                let archived = self.relative_of(&self.path(name)?)?;
                if selected.iter().any(|(existing, _)| *existing == archived) {
                    continue;
                }
                let content = self.read(name)?;
                total += content.len();
                if total > limit {
                    bail!("Experiment bundle exceeds transfer limit");
                }
                selected.push((archived, content));
            }
        }
        let manifest = json!({
            "notes": notes,
            "time": utc_now(),
            "profile": self.profile.data,
            "profile_sha256": self.profile.fingerprint(),
        });
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        archive.start_file("experiment.json", options)?;
        archive.write_all(python_json(&manifest, Some(2), false).as_bytes())?;
        for (name, content) in &selected {
            archive.start_file(format!("artifacts/{name}"), options)?;
            archive.write_all(content)?;
        }
        let output = archive.finish()?.into_inner();
        self.save("experiment", &output, json!({"paths": paths}), "zip")
    }
}

/// Python `Path.glob("*-*.*.json")` on a single (non-hidden) file name.
fn matches_sidecar_glob(name: &str) -> bool {
    if name.starts_with('.') {
        return false;
    }
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    stem.find('-')
        .is_some_and(|dash| stem[dash + 1..].contains('.'))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Read;

    pub(crate) fn test_profile(directory: &Path) -> Profile {
        let mut data: Value =
            serde_json::from_str(include_str!("../profiles/ps4-1400.json")).unwrap();
        data["host"] = json!("127.0.0.1");
        data["artifact_directory"] = json!("artifacts");
        data["qualification_file"] = json!("qualification.json");
        let path = directory.join("profile.json");
        fs::write(&path, data.to_string()).unwrap();
        Profile::load(path).unwrap()
    }

    fn store() -> (tempfile::TempDir, ArtifactStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(&test_profile(directory.path())).unwrap();
        (directory, store)
    }

    #[test]
    fn paths_reject_escapes_and_windows_streams() {
        let (_directory, store) = store();
        for path in [
            "../secret",
            "a/../../secret",
            "C:\\secret",
            "/etc/passwd",
            "file:stream",
            "a/../file",
            "",
            "\\\\server\\share",
            "x\0y",
            "NUL",
            "con.txt",
            "a/LPT1",
            "trail.",
            "trail ",
            "*.json",
            ".",
        ] {
            assert!(store.new_path(path).is_err(), "{path:?}");
        }
        assert!(store.new_path("projects/sample/recipe.json").is_ok());
        assert!(
            store
                .path("missing.bin")
                .unwrap_err()
                .to_string()
                .contains("does not exist")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected() {
        let (directory, store) = store();
        fs::create_dir_all(&store.root).unwrap();
        let outside = directory.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret"), b"x").unwrap();
        std::os::unix::fs::symlink(&outside, store.root.join("link")).unwrap();
        assert!(store.path("link/secret").is_err());
        assert!(store.new_path("link/new").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn junction_or_symlink_escape_is_rejected() {
        let (directory, store) = store();
        fs::create_dir_all(&store.root).unwrap();
        let outside = directory.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret"), b"x").unwrap();
        let link = store.root.join("link");
        let created = std::os::windows::fs::symlink_dir(&outside, &link).is_ok()
            || std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(&outside)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
        assert!(created, "could not create a directory symlink or junction");
        assert!(store.path("link/secret").is_err());
        assert!(store.new_path("link/new").is_err());
    }

    #[test]
    fn save_records_hash_and_provenance() {
        let (_directory, store) = store();
        let record = store
            .save("memory", b"hello", json!({"pid": 71}), "bin")
            .unwrap();
        assert_eq!(record["sha256"], json!(sha256_hex(b"hello")));
        assert_eq!(record["profile_sha256"], json!(store.profile.fingerprint()));
        assert_eq!(record["metadata"]["pid"], json!(71));
        assert_eq!(record["size"], json!(5));
        let path = record["path"].as_str().unwrap();
        assert_eq!(store.read(path).unwrap(), b"hello");
        let sidecar: Value =
            serde_json::from_slice(&store.read(&format!("{path}.json")).unwrap()).unwrap();
        assert_eq!(sidecar, record);
        assert!(
            store
                .read_bounded(path, 4)
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );
        assert!(store.save("../x", b"", Value::Null, "bin").is_err());
        assert!(store.save("x", b"", Value::Null, "b/in").is_err());
        let empty = store.save("x", b"", Value::Null, "bin").unwrap();
        assert_eq!(empty["metadata"], json!({}));
    }

    #[test]
    fn audit_appends_json_lines() {
        let (_directory, store) = store();
        store.audit("first", json!({"recipe": "a"})).unwrap();
        store.audit("second", Value::Null).unwrap();
        assert!(store.audit("bad", json!([1])).is_err());
        let text = fs::read_to_string(store.path("audit.jsonl").unwrap()).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["action"], json!("first"));
        assert_eq!(lines[0]["recipe"], json!("a"));
        assert_eq!(
            lines[1]["profile_sha256"],
            json!(store.profile.fingerprint())
        );
    }

    #[test]
    fn inventory_and_bundle() {
        let (_directory, store) = store();
        assert_eq!(store.inventory().unwrap(), json!([]));
        let memory = store.save("memory", b"hello", Value::Null, "bin").unwrap();
        let path = memory["path"].as_str().unwrap().to_string();
        store
            .save("annotation", b"{}", Value::Null, "json")
            .unwrap();
        store.audit("noise", Value::Null).unwrap();
        let bundle = store
            .bundle(std::slice::from_ref(&path), "test notes")
            .unwrap();
        assert_eq!(store.inventory().unwrap().as_array().unwrap().len(), 3);
        let content = store.read(bundle["path"].as_str().unwrap()).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(content)).unwrap();
        let names: Vec<String> = archive.file_names().map(str::to_string).collect();
        assert!(names.contains(&format!("artifacts/{path}")));
        assert!(names.contains(&format!("artifacts/{path}.json")));
        let mut manifest = String::new();
        archive
            .by_name("experiment.json")
            .unwrap()
            .read_to_string(&mut manifest)
            .unwrap();
        let manifest: Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(manifest["notes"], json!("test notes"));
        assert_eq!(bundle["metadata"]["paths"], json!([path]));
        assert!(store.bundle(&[], "x").is_err());
        assert!(store.bundle(&vec![path.clone(); 101], "x").is_err());
        assert!(store.bundle(&["missing.bin".to_string()], "x").is_err());
    }

    #[test]
    fn inventory_respects_entry_and_byte_limits() {
        let directory = tempfile::tempdir().unwrap();
        let mut profile = test_profile(directory.path());
        profile.data["limits"]["list_entries"] = json!(2);
        let store = ArtifactStore::new(&profile).unwrap();
        for _ in 0..4 {
            store.save("memory", b"x", Value::Null, "bin").unwrap();
        }
        assert_eq!(store.inventory().unwrap().as_array().unwrap().len(), 2);
        let mut tight = profile.clone();
        tight.data["limits"]["transfer_bytes"] = json!(64);
        let store = ArtifactStore::new(&tight).unwrap();
        assert!(
            store
                .inventory()
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
    }

    #[test]
    fn sidecar_glob() {
        assert!(matches_sidecar_glob("memory-abc.bin.json"));
        assert!(matches_sidecar_glob("annotation-abc.json.json"));
        assert!(!matches_sidecar_glob("annotation-abc.json"));
        assert!(!matches_sidecar_glob("audit.jsonl"));
        assert!(!matches_sidecar_glob(".memory-abc.bin.json"));
        assert!(!matches_sidecar_glob("plain.bin.json"));
    }

    #[test]
    fn timestamps_look_like_python_isoformat() {
        let stamp = utc_now();
        assert!(stamp.ends_with("+00:00"));
        assert_eq!(&stamp[10..11], "T");
    }
}
