//! Local-only verification for the Afterglow 14.00 jailbreak and the
//! ps4debug-NG payload that sits on top of it.
//!
//! Nothing here contacts the console. The checks are deliberately local so a
//! preflight can run before any payload is loaded.

use crate::{
    Result,
    config::{Profile, is_lower_hex},
    tools::ToolRegistry,
};
use anyhow::{Context, bail, ensure};
use md5::Md5;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Component, Path, PathBuf},
    time::Duration,
};

pub const AFTERGLOW_REPOSITORY: &str = "https://github.com/well0nez/afterglow-web";
pub const AFTERGLOW_REFERENCE_COMMIT: &str = "688fd1565f36c54aa9aaaa2e9d0ad121968db775";
/// Afterglow's patched ps4-hen build for 14.00.
pub const HEN_MD5_PATCHED: &str = "6417a84a72f9c7988f0e33b3ae190542";
/// Upstream ps4-hen build; every app launch freezes 14.00 until reboot.
pub const HEN_MD5_UPSTREAM_BAD: &str = "9aff7544eddef2f8202f72fc633d2be3";
pub const HEN_SHA256_PATCHED: &str =
    "364e5f6fd59e8a7afc207c70e27b840699f8173f3ae0241b63bc6dec6b394bfe";
pub const GOLDHEN_SHA256: &str = "39452f5e1c305ac9efcb4745eef7958b4db8c6d85299529f08700970b009ea4d";
pub const PATCHSET_1400_SHA256: &str =
    "615f275b96831cc04173757db39e93f0d27b52888976af2a6444604aa8ac5dbf";
pub const DEBUGGER_PAYLOAD_SHA256: &str =
    "8bfe0507972718e6078778c5f9c44d84293197c0547239ab4227bdb351299b3e";

const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const QUALIFIED_PERMISSIONS: &[&str] = &[
    "ftp_upload",
    "payload_execute",
    "process_inject",
    "process_write",
    "debug_control",
    "kernel_read",
    "kernel_write",
    "build",
];

fn profile_string<'a>(profile: &'a Profile, section: &str, name: &str) -> Option<&'a str> {
    profile.data.get(section)?.get(name)?.as_str()
}

fn expected_or(profile: &Profile, section: &str, name: &str, fallback: &str) -> String {
    profile_string(profile, section, name)
        .map(str::to_owned)
        .unwrap_or_else(|| fallback.to_owned())
}

fn resolve_directory(profile: &Profile, argument: Option<&Path>) -> Option<PathBuf> {
    let path = argument
        .map(Path::to_path_buf)
        .or_else(|| profile_string(profile, "jailbreak", "local_directory").map(PathBuf::from))
        .or_else(|| std::env::var_os("PS4_AFTERGLOW_DIR").map(PathBuf::from))?;
    Some(std::path::absolute(&path).unwrap_or(path))
}

fn resolve_debugger_payload(profile: &Profile, argument: Option<&Path>) -> Option<PathBuf> {
    let path = argument
        .map(Path::to_path_buf)
        .or_else(|| profile_string(profile, "debugger", "payload_path").map(PathBuf::from))
        .or_else(|| std::env::var_os("PS4DEBUG_NG_PAYLOAD").map(PathBuf::from))?;
    Some(std::path::absolute(&path).unwrap_or(path))
}

fn hash_file(path: &Path) -> Result<(String, String)> {
    let metadata = fs::metadata(path).with_context(|| format!("Cannot read {}", path.display()))?;
    ensure!(metadata.is_file(), "Not a file: {}", path.display());
    ensure!(
        metadata.len() <= MAX_FILE_BYTES,
        "{} exceeds the {} byte verification limit",
        path.display(),
        MAX_FILE_BYTES
    );
    let mut file = fs::File::open(path)?;
    let mut md5 = Md5::new();
    let mut sha256 = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        md5.update(&buffer[..count]);
        sha256.update(&buffer[..count]);
    }
    Ok((hex::encode(md5.finalize()), hex::encode(sha256.finalize())))
}

fn git_commit(directory: &Path) -> Result<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(["rev-parse", "HEAD"])
        .output()
        .context("git is not available; install git or verify the files without commit identity")?;
    ensure!(
        output.status.success(),
        "git rev-parse HEAD failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let commit = String::from_utf8(output.stdout)?
        .trim()
        .to_ascii_lowercase();
    ensure!(
        is_lower_hex(&commit, 40),
        "git returned an invalid commit identity"
    );
    Ok(commit)
}

fn git_dirty_files(directory: &Path) -> Result<Vec<String>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .context("git status is unavailable")?;
    ensure!(output.status.success(), "git status failed");
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .map(str::to_owned)
        .collect())
}

fn file_report(path: &Path, expected_sha256: &str, expected_md5: Option<&str>) -> Result<Value> {
    if !path.is_file() {
        return Ok(json!({
            "present": false,
            "path": path.display().to_string(),
            "ok": false,
            "error": "missing",
        }));
    }
    let (md5, sha256) = hash_file(path)?;
    let md5_ok = expected_md5.map(|expected| expected == md5.as_str());
    let sha256_ok = sha256 == expected_sha256;
    Ok(json!({
        "present": true,
        "path": path.display().to_string(),
        "md5": md5,
        "sha256": sha256,
        "expected_md5": expected_md5,
        "expected_sha256": expected_sha256,
        "md5_ok": md5_ok,
        "sha256_ok": sha256_ok,
        "ok": md5_ok.unwrap_or(true) && sha256_ok,
    }))
}

fn hen_verdict(md5: &str) -> &'static str {
    if md5 == HEN_MD5_PATCHED {
        "patched"
    } else if md5 == HEN_MD5_UPSTREAM_BAD {
        "unpatched"
    } else {
        "unknown"
    }
}

fn hen_report(path: &Path, profile: &Profile) -> Result<Value> {
    if !path.is_file() {
        return Ok(json!({
            "present": false,
            "path": path.display().to_string(),
            "ok": false,
            "error": "missing",
            "verdict": "missing",
        }));
    }
    let (md5, sha256) = hash_file(path)?;
    let expected_md5 = expected_or(profile, "jailbreak", "expected_hen_md5", HEN_MD5_PATCHED);
    let expected_sha256 = expected_or(
        profile,
        "jailbreak",
        "expected_hen_sha256",
        HEN_SHA256_PATCHED,
    );
    let verdict = hen_verdict(&md5);
    let matches_expected = md5 == expected_md5 && sha256 == expected_sha256;
    Ok(json!({
        "present": true,
        "path": path.display().to_string(),
        "md5": md5,
        "sha256": sha256,
        "expected_md5": expected_md5,
        "expected_sha256": expected_sha256,
        "upstream_bad_md5": HEN_MD5_UPSTREAM_BAD,
        "verdict": verdict,
        "matches_expected": matches_expected,
        "ok": verdict == "patched" && matches_expected,
    }))
}

fn safe_relative(path: &str) -> bool {
    let path = Path::new(path);
    !path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

fn cache_report(directory: &Path) -> Result<Value> {
    let path = directory.join("cache.appcache");
    if !path.is_file() {
        return Ok(json!({
            "present": false,
            "path": path.display().to_string(),
            "entries": 0,
            "mismatches": [],
            "ok": false,
            "warning": "cache.appcache is absent; the served page may be stale",
        }));
    }
    let text = fs::read_to_string(&path)?;
    let mut checked = Vec::new();
    let mut mismatches = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || matches!(line, "CACHE MANIFEST" | "CACHE:" | "FALLBACK:" | "NETWORK:")
        {
            continue;
        }
        let Some((name, declared)) = line.split_once('#') else {
            continue;
        };
        let name = name.trim();
        let declared = declared.trim().to_ascii_lowercase();
        if !is_lower_hex(&declared, 32) || !safe_relative(name) {
            mismatches.push(json!({
                "file": name,
                "declared": declared,
                "error": "invalid manifest entry",
            }));
            continue;
        }
        let target = directory.join(name);
        let Ok((_, sha256)) = hash_file(&target) else {
            mismatches.push(json!({
                "file": name,
                "declared": declared,
                "error": "missing or unreadable",
            }));
            continue;
        };
        let actual = sha256.get(..32).unwrap_or(&sha256).to_owned();
        let ok = actual == declared;
        checked.push(json!({
            "file": name,
            "declared": declared,
            "actual": actual,
            "ok": ok,
        }));
        if !ok {
            mismatches.push(json!({
                "file": name,
                "declared": declared,
                "actual": actual,
            }));
        }
    }
    Ok(json!({
        "present": true,
        "path": path.display().to_string(),
        "entries": checked.len(),
        "details": checked,
        "mismatches": mismatches,
        "ok": mismatches.is_empty(),
    }))
}

fn afterglow_report(profile: &Profile, directory: &Path) -> Result<Value> {
    ensure!(
        directory.is_dir(),
        "Afterglow directory does not exist: {}",
        directory.display()
    );
    let hen = hen_report(&directory.join("hen.bin"), profile)?;
    let goldhen = file_report(
        &directory.join("goldhen.bin"),
        &expected_or(
            profile,
            "jailbreak",
            "expected_goldhen_sha256",
            GOLDHEN_SHA256,
        ),
        None,
    )?;
    let patchset = file_report(
        &directory.join("patchset-1400.bin"),
        &expected_or(
            profile,
            "jailbreak",
            "expected_patchset_1400_sha256",
            PATCHSET_1400_SHA256,
        ),
        None,
    )?;
    let cache = cache_report(directory)?;
    let cache_entries: Vec<&str> = cache["details"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry["file"].as_str())
        .collect();
    let missing_cache_files: Vec<&str> = ["hen.bin", "goldhen.bin", "patchset-1400.bin"]
        .into_iter()
        .filter(|name| !cache_entries.contains(name))
        .collect();
    let cache_complete = cache["ok"] == true && missing_cache_files.is_empty();
    let git = match git_commit(directory) {
        Ok(commit) => json!({"commit": commit, "ok": true}),
        Err(error) => json!({"commit": null, "ok": false, "error": error.to_string()}),
    };
    let dirty = match git_dirty_files(directory) {
        Ok(files) => json!({"clean": files.is_empty(), "tracked_changes": files}),
        Err(error) => json!({"clean": false, "tracked_changes": [], "error": error.to_string()}),
    };
    let reference = profile_string(profile, "jailbreak", "reference_commit");
    let installed = profile_string(profile, "jailbreak", "installed_commit");
    let commit = git["commit"].as_str();
    let reference_matches = reference.map(|expected| commit == Some(expected));
    let installed_matches = installed.map(|expected| commit == Some(expected));
    let ok = git["ok"] == true
        && dirty["clean"] == true
        && hen["ok"] == true
        && goldhen["ok"] == true
        && patchset["ok"] == true
        && cache_complete
        && installed_matches != Some(false)
        && reference_matches != Some(false);
    Ok(json!({
        "format": "ps4wb-afterglow-v1",
        "directory": directory.display().to_string(),
        "repository": AFTERGLOW_REPOSITORY,
        "git": git,
        "worktree": dirty,
        "reference_commit": reference,
        "installed_commit": installed,
        "reference_matches": reference_matches,
        "installed_matches": installed_matches,
        "hen": hen,
        "goldhen": goldhen,
        "patchset_1400": patchset,
        "cache": cache,
        "cache_required_files_missing": missing_cache_files,
        "cache_complete": cache_complete,
        "ok": ok,
    }))
}

pub fn afterglow_verify(profile: &Profile, directory: Option<&Path>) -> Result<Value> {
    let Some(directory) = resolve_directory(profile, directory) else {
        bail!("Afterglow directory is not configured; pass directory or set PS4_AFTERGLOW_DIR");
    };
    afterglow_report(profile, &directory)
}

fn debugger_payload_report(profile: &Profile, path: &Path) -> Result<Value> {
    ensure!(
        path.is_file(),
        "ps4debug-NG payload does not exist: {}",
        path.display()
    );
    let (md5, sha256) = hash_file(path)?;
    let expected_sha256 = expected_or(
        profile,
        "debugger",
        "payload_sha256",
        DEBUGGER_PAYLOAD_SHA256,
    );
    let brand = profile_string(profile, "debugger", "expected_brand");
    Ok(json!({
        "format": "ps4wb-debugger-payload-v1",
        "present": true,
        "path": path.display().to_string(),
        "md5": md5,
        "sha256": sha256,
        "expected_sha256": expected_sha256,
        "expected_brand": brand,
        "ok": sha256 == expected_sha256,
    }))
}

pub fn debugger_payload_verify(profile: &Profile, path: Option<&Path>) -> Result<Value> {
    let Some(path) = resolve_debugger_payload(profile, path) else {
        bail!("ps4debug-NG payload is not configured; pass path or set PS4DEBUG_NG_PAYLOAD");
    };
    debugger_payload_report(profile, &path)
}

fn probe_services(profile: &Profile) -> Result<Value> {
    let host: IpAddr = profile
        .host()
        .parse()
        .context("Profile host is not a valid IP address")?;
    let timeout = profile.timeout().min(Duration::from_secs(2));
    let mut services = serde_json::Map::new();
    for service in ["ftp", "klog"] {
        let port = profile.port(service);
        let report = if port == 0 {
            json!({"probed": false, "error": "port is not configured"})
        } else {
            match TcpStream::connect_timeout(&SocketAddr::new(host, port), timeout) {
                Ok(stream) => {
                    drop(stream);
                    json!({"probed": true, "open": true, "port": port})
                }
                Err(error) => json!({
                    "probed": true,
                    "open": false,
                    "port": port,
                    "error": error.to_string(),
                }),
            }
        };
        services.insert(service.to_owned(), report);
    }
    services.insert(
        "payload".to_owned(),
        json!({
            "probed": false,
            "port": profile.port("payload"),
            "reason": "the payload port is never probed",
        }),
    );
    Ok(Value::Object(services))
}

pub fn preflight(
    profile: &Profile,
    afterglow_directory: Option<&Path>,
    debugger_payload: Option<&Path>,
    probe: bool,
) -> Result<Value> {
    let mut checks = Vec::new();
    let mut warnings = Vec::new();

    checks.push(json!({
        "name": "profile",
        "ok": true,
        "detail": format!("{} at {}", profile.firmware(), profile.host()),
    }));

    let qualification_result = profile.qualification();
    let (qualification, qualification_error) = match qualification_result {
        Ok(value) => (value, None),
        Err(error) => (Value::Null, Some(error.to_string())),
    };
    let mutating = QUALIFIED_PERMISSIONS
        .iter()
        .any(|permission| profile.permission_enabled(permission));
    match &qualification_error {
        None => checks.push(json!({
            "name": "qualification",
            "ok": true,
            "detail": "local qualification matches the profile",
        })),
        Some(error) if mutating => checks.push(json!({
            "name": "qualification",
            "ok": false,
            "detail": error,
        })),
        Some(error) => {
            warnings.push(format!("No qualification: {error}"));
            checks.push(json!({
                "name": "qualification",
                "ok": true,
                "skipped": true,
                "detail": "not required while every mutating permission is disabled",
            }));
        }
    }

    let afterglow = match resolve_directory(profile, afterglow_directory) {
        Some(directory) => Some(afterglow_report(profile, &directory)?),
        None => None,
    };
    match &afterglow {
        Some(report) => {
            let ok = report["ok"].as_bool() == Some(true);
            checks.push(json!({
                "name": "afterglow",
                "ok": ok,
                "detail": if ok { "patched hen.bin and manifest verified".to_owned() } else { "Afterglow verification failed".to_owned() },
            }));
        }
        None if mutating => checks.push(json!({
            "name": "afterglow",
            "ok": false,
            "skipped": true,
            "detail": "pass --afterglow-directory or set PS4_AFTERGLOW_DIR before enabling mutations",
        })),
        None if profile.permission_enabled("debug_control") => checks.push(json!({
            "name": "debugger_payload",
            "ok": false,
            "skipped": true,
            "detail": "debug_control is enabled; verify the exact ps4debug-NG BIN before use",
        })),
        None => {
            warnings.push("Afterglow directory not provided; hen.bin was not verified".to_owned());
            checks.push(json!({
                "name": "afterglow",
                "ok": true,
                "skipped": true,
                "detail": "not provided",
            }));
        }
    }

    let debugger_payload = match resolve_debugger_payload(profile, debugger_payload) {
        Some(path) => Some(debugger_payload_report(profile, &path)?),
        None => None,
    };
    match &debugger_payload {
        Some(report) => {
            let ok = report["ok"].as_bool() == Some(true);
            checks.push(json!({
                "name": "debugger_payload",
                "ok": ok,
                "detail": if ok { "ps4debug-NG SHA-256 matches".to_owned() } else { "ps4debug-NG SHA-256 mismatch".to_owned() },
            }));
        }
        None => {
            warnings.push("ps4debug-NG payload not provided; its hash was not verified".to_owned());
            checks.push(json!({
                "name": "debugger_payload",
                "ok": true,
                "skipped": true,
                "detail": "not provided",
            }));
        }
    }

    let services = if probe {
        let services = probe_services(profile)?;
        for service in ["ftp", "klog"] {
            let open = services[service]["open"].as_bool() == Some(true);
            if !open {
                warnings.push(format!(
                    "Optional {service} service on port {} is not reachable",
                    profile.port(service)
                ));
            }
            checks.push(json!({
                "name": format!("service_{service}"),
                "ok": true,
                "available": open,
                "optional": true,
                "detail": if open { "TCP port is open".to_owned() } else { format!("TCP port {} is closed", profile.port(service)) },
            }));
        }
        let mut debugger = crate::debugger::Debugger::new(profile.clone());
        let handshake = debugger.probe();
        let _ = debugger.close();
        match handshake {
            Ok(identity) => {
                checks.push(json!({
                    "name": "ps4debug_handshake",
                    "ok": true,
                    "detail": "identity handshake accepted",
                    "identity": identity,
                }));
            }
            Err(error) => checks.push(json!({
                "name": "ps4debug_handshake",
                "ok": false,
                "detail": error.to_string(),
            })),
        }
        Some(services)
    } else {
        checks.push(json!({
            "name": "services",
            "ok": true,
            "skipped": true,
            "detail": "probe=false; no console connection attempted",
        }));
        None
    };

    let ok = checks.iter().all(|check| check["ok"] == true);
    Ok(json!({
        "format": "ps4wb-preflight-v1",
        "profile": {
            "name": profile.data.get("name"),
            "host": profile.host(),
            "firmware": profile.firmware(),
            "permissions": profile.data.get("permissions"),
            "profile_sha256": profile.fingerprint(),
        },
        "qualification": qualification,
        "afterglow": afterglow,
        "debugger_payload": debugger_payload,
        "services": services,
        "checks": checks,
        "warnings": warnings,
        "ok": ok,
    }))
}

pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    let profile = &registry.workbench.profile;
    Some(match name {
        "afterglow_verify" => afterglow_verify(profile, args["directory"].as_str().map(Path::new)),
        "debugger_payload_verify" => {
            debugger_payload_verify(profile, args["path"].as_str().map(Path::new))
        }
        "preflight" => preflight(
            profile,
            args["afterglow_directory"].as_str().map(Path::new),
            args["debugger_payload"].as_str().map(Path::new),
            args["probe"].as_bool().unwrap_or(false),
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_profile(mut data: Value, directory: &Path) -> Profile {
        data["host"] = json!("127.0.0.1");
        data["artifact_directory"] = json!("artifacts");
        data["qualification_file"] = json!("qualification.json");
        let data = Profile::validate(data).unwrap();
        Profile {
            path: directory.join("profile.json"),
            data,
        }
    }

    #[test]
    fn known_content_hashes_match_published_values() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("abc.bin");
        fs::write(&path, b"abc").unwrap();
        let (md5, sha256) = hash_file(&path).unwrap();
        assert_eq!(md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hen_verdict_rejects_upstream_build() {
        assert_eq!(hen_verdict(HEN_MD5_PATCHED), "patched");
        assert_eq!(hen_verdict(HEN_MD5_UPSTREAM_BAD), "unpatched");
        assert_eq!(hen_verdict("00000000000000000000000000000000"), "unknown");
    }

    #[test]
    fn hen_report_fails_closed_for_unrecognized_bytes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("hen.bin");
        fs::write(&path, b"not the patched HEN").unwrap();
        let data: Value = serde_json::from_str(include_str!("../tests/fixtures/profile.json")).unwrap();
        let profile = test_profile(data, directory.path());
        let report = hen_report(&path, &profile).unwrap();
        assert_eq!(report["ok"], json!(false));
        assert_eq!(report["verdict"], json!("unknown"));
    }

    #[test]
    fn cache_manifest_detects_stale_files() {
        let directory = tempdir().unwrap();
        let file = directory.path().join("hen.bin");
        fs::write(&file, b"safe").unwrap();
        let (_, sha256) = hash_file(&file).unwrap();
        fs::write(
            directory.path().join("cache.appcache"),
            format!("CACHE MANIFEST\nhen.bin #{}\n", &sha256[..32]),
        )
        .unwrap();
        let report = cache_report(directory.path()).unwrap();
        assert_eq!(report["ok"], json!(true));
        assert_eq!(report["entries"], json!(1));

        fs::write(&file, b"changed").unwrap();
        let report = cache_report(directory.path()).unwrap();
        assert_eq!(report["ok"], json!(false));
        assert_eq!(report["mismatches"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn debugger_payload_hash_is_checked_against_the_profile() {
        let directory = tempdir().unwrap();
        let payload = directory.path().join("ps4debug.bin");
        fs::write(&payload, b"payload").unwrap();
        let (_, sha256) = hash_file(&payload).unwrap();
        let data: Value = serde_json::from_str(include_str!("../tests/fixtures/profile.json")).unwrap();
        let mut data = data;
        data["debugger"]["payload_sha256"] = json!(sha256);
        let profile = test_profile(data, directory.path());
        let report = debugger_payload_report(&profile, &payload).unwrap();
        assert_eq!(report["ok"], json!(true));
    }

    #[test]
    fn missing_afterglow_directory_is_an_error() {
        let directory = tempdir().unwrap();
        let data: Value = serde_json::from_str(include_str!("../tests/fixtures/profile.json")).unwrap();
        let profile = test_profile(data, directory.path());
        assert!(afterglow_verify(&profile, Some(&directory.path().join("missing"))).is_err());
    }

    #[test]
    fn tracked_profile_hashes_are_the_known_good_afterglow_build() {
        let data: Value = serde_json::from_str(include_str!("../tests/fixtures/profile.json")).unwrap();
        assert_eq!(
            data["jailbreak"]["expected_hen_md5"],
            json!(HEN_MD5_PATCHED)
        );
        assert_eq!(
            data["jailbreak"]["expected_hen_sha256"],
            json!(HEN_SHA256_PATCHED)
        );
        assert_eq!(
            data["jailbreak"]["expected_goldhen_sha256"],
            json!(GOLDHEN_SHA256)
        );
        assert_eq!(
            data["jailbreak"]["expected_patchset_1400_sha256"],
            json!(PATCHSET_1400_SHA256)
        );
    }
}
