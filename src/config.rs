//! Local profile policy, hardware qualification and canonical hashing.
//!
//! Native port of `ps4_workbench/config.py`. The profile fingerprint is the
//! SHA-256 of Python's `json.dumps(value, sort_keys=True, separators=(",", ":"))`
//! (with the default `ensure_ascii=True`), so qualification records written by
//! either implementation stay interchangeable.

use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::Result;

/// Profiles and qualification records are small; refuse to read huge files.
const MAX_POLICY_FILE_BYTES: u64 = 1024 * 1024;

const SERVICES: [&str; 4] = ["payload", "ftp", "klog", "debug"];
const PERMISSIONS: [&str; 7] = [
    "ftp_upload",
    "payload_execute",
    "process_write",
    "debug_control",
    "kernel_read",
    "kernel_write",
    "build",
];
const LIMIT_CAPS: [(&str, i64); 5] = [
    ("memory_bytes", 1_048_576),
    ("transfer_bytes", 67_108_864),
    ("log_bytes", 16_777_216),
    ("log_seconds", 120),
    ("list_entries", 16_384),
];
pub const ATTESTATION: &str = "I_TESTED_THIS_EXACT_CONFIGURATION";
pub const AFTERGLOW_REPOSITORY: &str = "https://github.com/well0nez/afterglow-web";

/// SHA-256 hex digest of the Python-compatible canonical JSON encoding.
pub fn canonical_hash(value: &Value) -> String {
    sha256_hex(canonical_json(value).as_bytes())
}

/// Python `json.dumps(value, sort_keys=True, separators=(",", ":"))`.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_json(&mut out, value, None, true, 0);
    out
}

/// Largest integer a JSON consumer using IEEE-754 doubles represents exactly.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Python `json_safe`: integers whose magnitude exceeds 2^53 - 1 become
/// `hex()` strings (`"0x.."` / `"-0x.."`) so JavaScript-based clients never
/// silently round 64-bit addresses. Applied recursively; other values pass through.
pub fn json_safe(value: Value) -> Value {
    match value {
        Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                if unsigned > MAX_SAFE_INTEGER {
                    return Value::String(format!("{unsigned:#x}"));
                }
            } else if let Some(signed) = number.as_i64()
                && signed.unsigned_abs() > MAX_SAFE_INTEGER
            {
                return Value::String(format!("-{:#x}", signed.unsigned_abs()));
            }
            Value::Number(number)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(json_safe).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(key, item)| (key, json_safe(item)))
                .collect(),
        ),
        other => other,
    }
}

/// Python `json.dumps(value, indent=indent, sort_keys=sort_keys)` with
/// `ensure_ascii=True`. With `indent=None` this uses Python's default
/// `", "`/`": "` separators.
pub fn python_json(value: &Value, indent: Option<usize>, sort_keys: bool) -> String {
    let mut out = String::new();
    match indent {
        Some(_) => write_json(&mut out, value, indent, sort_keys, 0),
        None => write_json_default_separators(&mut out, value, sort_keys),
    }
    out
}

/// Python `json.dumps(dict(pairs), indent=2)`: an object whose keys keep the
/// given insertion order (serde_json maps may not preserve it).
pub fn python_json_ordered(pairs: &[(&str, Value)], indent: usize) -> String {
    let mut out = String::new();
    if pairs.is_empty() {
        return "{}".to_string();
    }
    out.push('{');
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        newline(&mut out, Some(indent), 1);
        write_string(&mut out, key);
        out.push_str(": ");
        write_json(&mut out, value, Some(indent), false, 1);
    }
    newline(&mut out, Some(indent), 0);
    out.push('}');
    out
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn newline(out: &mut String, indent: Option<usize>, depth: usize) {
    if let Some(width) = indent {
        out.push('\n');
        for _ in 0..width * depth {
            out.push(' ');
        }
    }
}

fn sorted_entries(map: &Map<String, Value>, sort_keys: bool) -> Vec<(&String, &Value)> {
    let mut entries: Vec<_> = map.iter().collect();
    if sort_keys {
        entries.sort_by(|a, b| a.0.cmp(b.0));
    }
    entries
}

fn write_json(
    out: &mut String,
    value: &Value,
    indent: Option<usize>,
    sort_keys: bool,
    depth: usize,
) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(out, number),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(out, indent, depth + 1);
                write_json(out, item, indent, sort_keys, depth + 1);
            }
            newline(out, indent, depth);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (index, (key, item)) in sorted_entries(map, sort_keys).into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(out, indent, depth + 1);
                write_string(out, key);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write_json(out, item, indent, sort_keys, depth + 1);
            }
            newline(out, indent, depth);
            out.push('}');
        }
    }
}

fn write_json_default_separators(out: &mut String, value: &Value, sort_keys: bool) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_json_default_separators(out, item, sort_keys);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in sorted_entries(map, sort_keys).into_iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_string(out, key);
                out.push_str(": ");
                write_json_default_separators(out, item, sort_keys);
            }
            out.push('}');
        }
        other => write_json(out, other, None, sort_keys, 0),
    }
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            _ => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

fn write_number(out: &mut String, number: &serde_json::Number) {
    if let Some(value) = number.as_u64() {
        let _ = write!(out, "{value}");
    } else if let Some(value) = number.as_i64() {
        let _ = write!(out, "{value}");
    } else if let Some(value) = number.as_f64() {
        out.push_str(&python_float_repr(value));
    } else {
        out.push_str(&number.to_string());
    }
}

/// Python `float.__repr__` as used by `json.dumps`.
pub fn python_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    let negative = value.is_sign_negative();
    if value == 0.0 {
        return if negative { "-0.0" } else { "0.0" }.into();
    }
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let decpt = exponent + 1;
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if decpt <= -4 || decpt > 16 {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let shown = decpt - 1;
        let sign = if shown < 0 { '-' } else { '+' };
        let _ = write!(out, "e{sign}{:02}", shown.abs());
    } else if decpt <= 0 {
        out.push_str("0.");
        for _ in 0..(-decpt) {
            out.push('0');
        }
        out.push_str(digits);
    } else {
        let decpt = decpt as usize;
        if decpt >= digits.len() {
            out.push_str(digits);
            for _ in 0..decpt - digits.len() {
                out.push('0');
            }
            out.push_str(".0");
        } else {
            out.push_str(&digits[..decpt]);
            out.push('.');
            out.push_str(&digits[decpt..]);
        }
    }
    out
}

/// Python `require_integer`: a JSON integer (not bool, not float) in range.
pub fn require_integer(value: &Value, name: &str, minimum: i128, maximum: i128) -> Result<i128> {
    let parsed = match value {
        Value::Number(number) if !number.is_f64() => number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from)),
        _ => None,
    };
    match parsed {
        Some(number) if (minimum..=maximum).contains(&number) => Ok(number),
        _ => bail!("{name} must be an integer in [{minimum}, {maximum}]"),
    }
}

/// Python `require_hash`: lowercase 64-hex SHA-256 digest.
pub fn require_hash<'a>(value: &'a str, name: &str) -> Result<&'a str> {
    if is_lower_hex(value, 64) {
        Ok(value)
    } else {
        bail!("{name} must be a lowercase SHA-256 digest")
    }
}

pub(crate) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Python truthiness for JSON values.
pub(crate) fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    }
}

/// Read at most `maximum` bytes; larger files are an error.
pub(crate) fn read_bounded_file(path: &Path, maximum: u64) -> std::io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut data = Vec::new();
    file.take(maximum + 1).read_to_end(&mut data)?;
    if data.len() as u64 > maximum {
        return Err(std::io::Error::other("file exceeds size limit"));
    }
    Ok(data)
}

/// Strip the Windows verbatim prefix produced by `canonicalize` so paths stay
/// comparable with lexically built ones.
pub(crate) fn simplify(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let text = path.to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            let bytes = rest.as_bytes();
            if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
                return PathBuf::from(rest);
            }
        }
    }
    path
}

/// Lexically normalize, then canonicalize the longest existing ancestor
/// (following symlinks and junctions) and append the remainder.
pub fn resolve_lenient(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    let mut existing = normalized.clone();
    let mut remainder: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if fs::symlink_metadata(&existing).is_ok() {
            match fs::canonicalize(&existing) {
                Ok(real) => {
                    let mut result = simplify(real);
                    for part in remainder.iter().rev() {
                        result.push(part);
                    }
                    return Ok(result);
                }
                Err(error) => {
                    return Err(anyhow!(
                        "Cannot resolve path {}: {error}",
                        existing.display()
                    ));
                }
            }
        }
        match (
            existing.file_name().map(|n| n.to_os_string()),
            existing.parent(),
        ) {
            (Some(name), Some(parent)) => {
                remainder.push(name);
                existing = parent.to_path_buf();
            }
            _ => return Ok(normalized),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Profile {
    pub path: PathBuf,
    pub data: Value,
}

fn section<'a>(data: &'a Value, name: &str) -> &'a Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    data.get(name)
        .and_then(Value::as_object)
        .unwrap_or_else(|| EMPTY.get_or_init(Map::new))
}

/// Python 3.13+ `IPv4Address.is_private`.
fn ipv4_is_private(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    if address == Ipv4Addr::new(192, 0, 0, 9) || address == Ipv4Addr::new(192, 0, 0, 10) {
        return false;
    }
    const NETWORKS: [([u8; 4], u32); 14] = [
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 0, 170], 31),
        ([192, 0, 2, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([240, 0, 0, 0], 4),
        ([255, 255, 255, 255], 32),
    ];
    NETWORKS.iter().any(|(network, prefix)| {
        let mask = if *prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        value & mask == u32::from(Ipv4Addr::from(*network)) & mask
    })
}

impl Profile {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = resolve_lenient(path.as_ref())?;
        let raw = read_bounded_file(&path, MAX_POLICY_FILE_BYTES)
            .map_err(|error| anyhow!("Cannot read profile {}: {error}", path.display()))?;
        let text = std::str::from_utf8(&raw).map_err(|_| anyhow!("Profile must be UTF-8"))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let data: Value = serde_json::from_str(text)
            .map_err(|error| anyhow!("Profile is not valid JSON: {error}"))?;
        let data = Self::validate(data)?;
        Ok(Self { path, data })
    }

    /// Validate a profile document exactly like Python `Profile.load`,
    /// returning it with the `timeout_seconds` default applied.
    pub fn validate(mut data: Value) -> Result<Value> {
        let Some(object) = data.as_object_mut() else {
            bail!("Profile must be a JSON object");
        };
        for name in ["jailbreak", "debugger", "ports", "limits", "permissions"] {
            if !object.get(name).is_some_and(Value::is_object) {
                bail!("Profile needs an object section: {name}");
            }
        }
        for name in ["artifact_directory", "qualification_file"] {
            match object.get(name).and_then(Value::as_str) {
                Some(text) if !text.trim().is_empty() => {}
                _ => bail!("Profile needs a nonempty {name}"),
            }
        }
        if object.get("firmware").and_then(Value::as_str) != Some("14.00") {
            bail!("This release supports only the 14.00 profile; no offset fallback");
        }
        let Some(host) = object.get("host").and_then(Value::as_str) else {
            bail!("Console host must be a private IPv4 string");
        };
        let address: Ipv4Addr = host
            .parse()
            .map_err(|_| anyhow!("Console host must be a private or loopback IPv4 literal"))?;
        if !(ipv4_is_private(address) || address.is_loopback())
            || address.is_unspecified()
            || address.is_multicast()
        {
            bail!("Console host must be a private or loopback IPv4 literal");
        }
        let jailbreak = object["jailbreak"].as_object().cloned().unwrap_or_default();
        if jailbreak.get("repository").and_then(Value::as_str) != Some(AFTERGLOW_REPOSITORY) {
            bail!("Only the configured Afterglow host is supported");
        }
        let debugger = object["debugger"].as_object().cloned().unwrap_or_default();
        if debugger.get("backend").and_then(Value::as_str) != Some("ps4debug-ng")
            || debugger.get("protocol").and_then(Value::as_str) != Some("1.3")
        {
            bail!("Unsupported debugger backend or protocol");
        }
        let ports = object["ports"].as_object().cloned().unwrap_or_default();
        if ports.len() != SERVICES.len() || !SERVICES.iter().all(|s| ports.contains_key(*s)) {
            bail!("Only payload, ftp, klog and debug service ports are allowed");
        }
        let mut seen = Vec::new();
        for service in SERVICES {
            let port = require_integer(&ports[service], &format!("ports.{service}"), 1, 65535)?;
            if !seen.contains(&port) {
                seen.push(port);
            }
        }
        if seen.len() != SERVICES.len() {
            bail!("Service ports must be distinct; never use a payload port for read-only probes");
        }
        let timeout = object
            .get("timeout_seconds")
            .cloned()
            .unwrap_or_else(|| Value::from(3));
        let seconds = match &timeout {
            Value::Number(number) => number.as_f64(),
            _ => None,
        };
        if !seconds.is_some_and(|s| s.is_finite() && (0.1..=30.0).contains(&s)) {
            bail!("timeout_seconds must be between 0.1 and 30");
        }
        object.insert("timeout_seconds".into(), timeout);
        let limits = object["limits"].as_object().cloned().unwrap_or_default();
        for (name, maximum) in LIMIT_CAPS {
            require_integer(
                limits.get(name).unwrap_or(&Value::Null),
                name,
                1,
                maximum.into(),
            )?;
        }
        let permissions = object["permissions"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for name in PERMISSIONS {
            if !permissions.get(name).is_some_and(Value::is_boolean) {
                bail!("permissions.{name} must be boolean");
            }
        }
        for name in ["reference_commit", "installed_commit"] {
            match jailbreak.get(name) {
                None | Some(Value::Null) => {}
                Some(Value::String(commit)) if is_lower_hex(commit, 40) => {}
                Some(_) => bail!("Invalid jailbreak {name}"),
            }
        }
        match debugger.get("payload_sha256") {
            None | Some(Value::Null) => {}
            Some(Value::String(digest)) => {
                require_hash(digest, "sha256")?;
            }
            Some(_) => bail!("sha256 must be a lowercase SHA-256 digest"),
        }
        match debugger.get("expected_brand") {
            None | Some(Value::Null) => {}
            Some(Value::String(brand))
                if brand.starts_with("ps4debug-NG by Pharaoh2k v")
                    && brand.chars().count() <= 256 => {}
            Some(_) => bail!("Invalid expected debugger branding"),
        }
        match object.get("ftp_upload_roots") {
            Some(Value::Array(roots)) if roots.iter().all(Value::is_string) => {}
            _ => bail!("ftp_upload_roots must be a list of POSIX paths"),
        }
        Ok(data)
    }

    pub fn host(&self) -> &str {
        self.data.get("host").and_then(Value::as_str).unwrap_or("")
    }

    pub fn timeout(&self) -> Duration {
        let seconds = self
            .data
            .get("timeout_seconds")
            .and_then(Value::as_f64)
            .filter(|s| s.is_finite() && *s >= 0.1)
            .unwrap_or(3.0)
            .min(30.0);
        Duration::from_secs_f64(seconds)
    }

    /// Configured limit; unknown names return 0 so callers fail closed.
    pub fn limit(&self, name: &str) -> usize {
        section(&self.data, "limits")
            .get(name)
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0)
    }

    /// Configured service port; unknown names return 0 (never connectable).
    pub fn port(&self, name: &str) -> u16 {
        section(&self.data, "ports")
            .get(name)
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(0)
    }

    pub fn permission_enabled(&self, permission: &str) -> bool {
        section(&self.data, "permissions").get(permission) == Some(&Value::Bool(true))
    }

    pub fn fingerprint(&self) -> String {
        canonical_hash(&self.data)
    }

    pub fn firmware(&self) -> &str {
        self.data
            .get("firmware")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    fn relative_setting(&self, name: &str) -> PathBuf {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let setting = self.data.get(name).and_then(Value::as_str).unwrap_or("");
        let joined = parent.join(setting);
        resolve_lenient(&joined).unwrap_or(joined)
    }

    pub fn artifact_root(&self) -> PathBuf {
        self.relative_setting("artifact_directory")
    }

    pub fn qualification_path(&self) -> PathBuf {
        self.relative_setting("qualification_file")
    }

    /// Require a locally enabled and hardware-qualified permission; returns
    /// the qualification record.
    pub fn require(&self, permission: &str) -> Result<Value> {
        if !self.permission_enabled(permission) {
            bail!("Disabled by local profile: {permission}");
        }
        let qualification = self.qualification()?;
        let approved = qualification
            .get("approved_permissions")
            .and_then(Value::as_array)
            .is_some_and(|list| list.iter().any(|item| item.as_str() == Some(permission)));
        if !approved {
            bail!("Hardware qualification does not approve {permission}");
        }
        Ok(qualification)
    }

    pub fn qualification(&self) -> Result<Value> {
        let unreadable = || {
            anyhow!(
                "No readable local hardware qualification; see CLI qualify and docs/COMPATIBILITY.md"
            )
        };
        let raw = read_bounded_file(&self.qualification_path(), MAX_POLICY_FILE_BYTES)
            .map_err(|_| unreadable())?;
        let text = std::str::from_utf8(&raw).map_err(|_| unreadable())?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let record: Value = serde_json::from_str(text).map_err(|_| unreadable())?;
        if !record.is_object() {
            bail!("Qualification must be a JSON object");
        }
        if record.get("profile_sha256").and_then(Value::as_str) != Some(self.fingerprint().as_str())
            || record.get("attestation").and_then(Value::as_str) != Some(ATTESTATION)
        {
            bail!("Qualification is stale or invalid; profile must match exactly");
        }
        let jailbreak = section(&self.data, "jailbreak");
        if !truthy(jailbreak.get("installed_commit")) || !truthy(jailbreak.get("hen_build")) {
            bail!("Record the actual installed Afterglow commit and HEN build first");
        }
        if !record
            .get("approved_permissions")
            .is_some_and(Value::is_array)
        {
            bail!("Invalid qualification permissions");
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const REFERENCE_PROFILE: &str = include_str!("../profiles/ps4-1400.json");

    pub(crate) fn settings() -> Value {
        let mut data: Value = serde_json::from_str(REFERENCE_PROFILE).unwrap();
        data["host"] = json!("127.0.0.1");
        data["artifact_directory"] = json!("artifacts");
        data["qualification_file"] = json!("qualification.json");
        data
    }

    fn write_profile(directory: &Path, data: &Value) -> Result<Profile> {
        let path = directory.join("profile.json");
        fs::write(&path, serde_json::to_vec(data).unwrap()).unwrap();
        Profile::load(path)
    }

    /// Cross-language fixture: expected canonical text and digest were produced by
    /// CPython 3.15 `hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":")).encode()).hexdigest()`.
    const FIXTURE: &str = r#"{"z":[1,2.5,-0.0,1e16,1e15,0.0001,1e-05,0.1,123456789012345678.0,5e-324,3.0,1.7976931348623157e308],
        "a":{"\u00e9t\u00e9":"caf\u00e9 \ud83d\ude80","ctl":"\u0000\u001f\u007f\b\f\n\r\t\"\\/"},
        "M":true,"n":null,"big":18446744073709551615,"neg":-9223372036854775808,"e":[],"o":{}}"#;
    const FIXTURE_CANONICAL: &str = r#"{"M":true,"a":{"ctl":"\u0000\u001f\u007f\b\f\n\r\t\"\\/","\u00e9t\u00e9":"caf\u00e9 \ud83d\ude80"},"big":18446744073709551615,"e":[],"n":null,"neg":-9223372036854775808,"o":{},"z":[1,2.5,-0.0,1e+16,1000000000000000.0,0.0001,1e-05,0.1,1.2345678901234568e+17,5e-324,3.0,1.7976931348623157e+308]}"#;
    const FIXTURE_SHA256: &str = "206dcf038a8db3f504ee8aed312ece5c013521271d5be9335b8e5b441b298f79";

    #[test]
    fn canonical_json_matches_python_fixture() {
        let value: Value = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(canonical_json(&value), FIXTURE_CANONICAL);
        assert_eq!(canonical_hash(&value), FIXTURE_SHA256);
    }

    #[test]
    fn python_float_repr_rules() {
        for (value, expected) in [
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (1e-5, "1e-05"),
            (-0.0, "-0.0"),
            (0.1, "0.1"),
            (1.5e300, "1.5e+300"),
            (3.0, "3.0"),
            (0.30000000000000004, "0.30000000000000004"),
            (-2.5e-7, "-2.5e-07"),
            (123.456, "123.456"),
        ] {
            assert_eq!(python_float_repr(value), expected);
        }
    }

    #[test]
    fn reference_profile_fingerprint_matches_python() {
        let directory = tempfile::tempdir().unwrap();
        let profile = write_profile(directory.path(), &settings()).unwrap();
        assert_eq!(
            profile.fingerprint(),
            "5441c8eb4d6a73e2f1ff3bf1659ac4e7935acc2288cd5ebe87397667dfb1a524"
        );
        let mut data = settings();
        data["timeout_seconds"] = json!(2.5);
        let profile = write_profile(directory.path(), &data).unwrap();
        assert_eq!(
            profile.fingerprint(),
            "1053673d70d798783a57aeb027205213a3227caeb0d0e5fa24410e07e603fa8e"
        );
    }

    #[test]
    fn indented_output_matches_python_layout() {
        let value = json!({"b": [1, {"x": "é"}], "a": {}, "c": []});
        assert_eq!(
            python_json(&value, Some(2), true),
            "{\n  \"a\": {},\n  \"b\": [\n    1,\n    {\n      \"x\": \"\\u00e9\"\n    }\n  ],\n  \"c\": []\n}"
        );
        assert_eq!(
            python_json(&value, None, true),
            "{\"a\": {}, \"b\": [1, {\"x\": \"\\u00e9\"}], \"c\": []}"
        );
        assert_eq!(
            python_json_ordered(&[("z", json!(1)), ("a", json!("q"))], 2),
            "{\n  \"z\": 1,\n  \"a\": \"q\"\n}"
        );
    }

    /// Python `test_large_wire_integers_are_exact_strings`.
    #[test]
    fn large_wire_integers_become_exact_hex_strings() {
        let value = json!({"address": 0xFFFF_FFFF_8000_1000u64, "small": 4096,
            "edge": 9_007_199_254_740_991u64, "over": 9_007_199_254_740_992u64,
            "negative": -9_007_199_254_740_992i64, "float": 1.5,
            "nested": [{"end": u64::MAX}, "text", null]});
        assert_eq!(
            json_safe(value),
            json!({"address": "0xffffffff80001000", "small": 4096,
                "edge": 9_007_199_254_740_991u64, "over": "0x20000000000000",
                "negative": "-0x20000000000000", "float": 1.5,
                "nested": [{"end": "0xffffffffffffffff"}, "text", null]})
        );
    }

    #[test]
    fn wrong_firmware_fails() {
        let directory = tempfile::tempdir().unwrap();
        let mut data = settings();
        data["firmware"] = json!("12.02");
        let error = write_profile(directory.path(), &data).unwrap_err();
        assert!(error.to_string().contains("14.00"));
    }

    #[test]
    fn public_or_unspecified_host_fails() {
        let directory = tempfile::tempdir().unwrap();
        for host in [
            "8.8.8.8",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "localhost",
            "192.168.086.1",
            "100.64.0.1",
            "192.0.0.9",
        ] {
            let mut data = settings();
            data["host"] = json!(host);
            assert!(write_profile(directory.path(), &data).is_err(), "{host}");
        }
        for host in [
            "10.1.2.3",
            "172.31.0.1",
            "192.168.86.25",
            "127.0.0.2",
            "169.254.1.1",
        ] {
            let mut data = settings();
            data["host"] = json!(host);
            assert!(write_profile(directory.path(), &data).is_ok(), "{host}");
        }
        let mut data = settings();
        data["host"] = json!(2130706433u32);
        let error = write_profile(directory.path(), &data).unwrap_err();
        assert!(error.to_string().contains("string"));
    }

    type Mutation = Box<dyn Fn(&mut Value)>;

    #[test]
    fn profile_shape_validation() {
        let directory = tempfile::tempdir().unwrap();
        let cases: Vec<(Mutation, &str)> = vec![
            (
                Box::new(|d| d["permissions"]["payload_execute"] = json!("false")),
                "boolean",
            ),
            (Box::new(|d| d["ports"]["debug"] = json!(9090)), "distinct"),
            (
                Box::new(|d| d["ports"]["other"] = json!(9090)),
                "service ports",
            ),
            (Box::new(|d| d["ports"]["ftp"] = json!(true)), "integer"),
            (Box::new(|d| d["ports"]["ftp"] = json!(2121.0)), "integer"),
            (
                Box::new(|d| d["timeout_seconds"] = json!(0.05)),
                "timeout_seconds",
            ),
            (
                Box::new(|d| d["timeout_seconds"] = json!(true)),
                "timeout_seconds",
            ),
            (
                Box::new(|d| d["limits"]["memory_bytes"] = json!(1_048_577)),
                "memory_bytes",
            ),
            (
                Box::new(|d| d["jailbreak"]["installed_commit"] = json!("A".repeat(40))),
                "installed_commit",
            ),
            (
                Box::new(|d| d["debugger"]["payload_sha256"] = json!("x")),
                "SHA-256",
            ),
            (
                Box::new(|d| d["debugger"]["expected_brand"] = json!("other")),
                "branding",
            ),
            (
                Box::new(|d| d["ftp_upload_roots"] = json!("/data")),
                "ftp_upload_roots",
            ),
            (
                Box::new(|d| d["artifact_directory"] = json!("  ")),
                "artifact_directory",
            ),
            (
                Box::new(|d| d["debugger"]["protocol"] = json!("1.2")),
                "protocol",
            ),
        ];
        for (mutate, expected) in cases {
            let mut data = settings();
            mutate(&mut data);
            let error = write_profile(directory.path(), &data)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error} !~ {expected}");
        }
    }

    #[test]
    fn missing_timeout_has_working_default() {
        let directory = tempfile::tempdir().unwrap();
        let mut data = settings();
        data.as_object_mut().unwrap().remove("timeout_seconds");
        let profile = write_profile(directory.path(), &data).unwrap();
        assert_eq!(profile.timeout(), Duration::from_secs(3));
        assert_eq!(profile.data["timeout_seconds"], json!(3));
        assert_eq!(profile.port("debug"), 744);
        assert_eq!(profile.port("nope"), 0);
        assert_eq!(profile.limit("memory_bytes"), 1_048_576);
        assert_eq!(profile.limit("nope"), 0);
        assert_eq!(profile.host(), "127.0.0.1");
        assert_eq!(
            profile.artifact_root(),
            resolve_lenient(&directory.path().join("artifacts")).unwrap()
        );
    }

    pub(crate) fn qualify(directory: &Path, permissions: &[&str], recipes: &[String]) -> Profile {
        let mut data = settings();
        for permission in permissions {
            data["permissions"][*permission] = json!(true);
        }
        data["jailbreak"]["installed_commit"] = json!("a".repeat(40));
        data["jailbreak"]["hen_build"] = json!("test-hen");
        data["debugger"]["expected_brand"] = json!("ps4debug-NG by Pharaoh2k v1.3.4");
        data["debugger"]["payload_sha256"] = json!("b".repeat(64));
        let profile = write_profile(directory, &data).unwrap();
        let record = json!({
            "profile_sha256": profile.fingerprint(), "attestation": ATTESTATION,
            "approved_permissions": permissions, "debugger_payload_sha256": "b".repeat(64),
            "payload_sha256_allowlist": [], "build_recipe_sha256_allowlist": recipes,
        });
        fs::write(profile.qualification_path(), record.to_string()).unwrap();
        profile
    }

    #[test]
    fn qualification_policy() {
        let directory = tempfile::tempdir().unwrap();
        let profile = write_profile(directory.path(), &settings()).unwrap();
        fs::write(profile.qualification_path(), "not JSON").unwrap();
        assert!(
            profile
                .qualification()
                .unwrap_err()
                .to_string()
                .contains("No readable")
        );
        fs::write(profile.qualification_path(), "[]").unwrap();
        assert!(
            profile
                .qualification()
                .unwrap_err()
                .to_string()
                .contains("JSON object")
        );

        let mut enabled = settings();
        enabled["permissions"]["process_write"] = json!(true);
        let profile = write_profile(directory.path(), &enabled).unwrap();
        fs::remove_file(profile.qualification_path()).unwrap();
        assert!(
            profile
                .require("process_write")
                .unwrap_err()
                .to_string()
                .contains("qualification")
        );

        let profile = qualify(directory.path(), &["process_write"], &[]);
        let record = profile.require("process_write").unwrap();
        assert_eq!(record["approved_permissions"], json!(["process_write"]));
        assert!(
            profile
                .require("build")
                .unwrap_err()
                .to_string()
                .contains("Disabled")
        );

        let mut stale = profile.clone();
        stale.data["jailbreak"]["hen_build"] = json!("changed-hen");
        assert!(
            stale
                .require("process_write")
                .unwrap_err()
                .to_string()
                .contains("stale")
        );

        let mut unapproved = qualify(directory.path(), &["ftp_upload"], &[]);
        unapproved.data["permissions"]["process_write"] = json!(true);
        let mut record = unapproved.qualification_path();
        record.set_extension("json");
        let mut stored: Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
        stored["profile_sha256"] = json!(unapproved.fingerprint());
        fs::write(&record, stored.to_string()).unwrap();
        assert!(
            unapproved
                .require("process_write")
                .unwrap_err()
                .to_string()
                .contains("does not approve")
        );
    }
}
