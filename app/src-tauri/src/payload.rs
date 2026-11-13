// app/src-tauri/src/payload.rs
// ps4debug-NG payload: the build stages the latest release under
// payloads/ps4debug-ng; the app can check GitHub and download a newer one.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

const REPO: &str = "Pharaoh2k/ps4debug-NG";
const API: &str = "https://api.github.com/repos/Pharaoh2k/ps4debug-NG/releases/latest";

#[derive(Debug, Clone, Serialize)]
pub struct PayloadInfo {
    pub tag: String,
    pub name: String,
    pub asset: String,
    pub url: String,
    pub sha256: String,
    pub path: String,
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct PayloadStatus {
    pub bundled: Option<PayloadInfo>,
    pub local: Option<PayloadInfo>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    tag: String,
    name: String,
    asset: String,
    url: String,
    sha256: String,
    source: String,
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    name: String,
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

fn read_manifest(dir: &Path) -> Option<PayloadInfo> {
    let text = std::fs::read_to_string(dir.join("manifest.json")).ok()?;
    let m: Manifest = serde_json::from_str(&text).ok()?;
    let bin = dir.join("ps4debug-ng.bin");
    if !bin.is_file() {
        return None;
    }
    Some(PayloadInfo {
        tag: m.tag,
        name: m.name,
        asset: m.asset,
        url: m.url,
        sha256: m.sha256,
        path: bin.to_string_lossy().into_owned(),
        source: m.source,
    })
}

fn bundled_dir(app: &AppHandle) -> Option<PathBuf> {
    Some(app.path().resource_dir().ok()?.join("payloads").join("ps4debug-ng"))
}

fn local_dir(app: &AppHandle) -> Option<PathBuf> {
    Some(app.path().app_local_data_dir().ok()?.join("payloads").join("ps4debug-ng"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

#[tauri::command]
pub fn ps4debug_payload(app: AppHandle) -> PayloadStatus {
    PayloadStatus {
        bundled: bundled_dir(&app).and_then(|d| read_manifest(&d)),
        local: local_dir(&app).and_then(|d| read_manifest(&d)),
    }
}

#[tauri::command]
pub async fn ps4debug_payload_latest() -> Result<PayloadInfo, String> {
    let client = reqwest::Client::new();
    let release: Release = client
        .get(API)
        .header("User-Agent", "SlopStation")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("ps4debug-NG release check failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("ps4debug-NG release check failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("ps4debug-NG release parse failed: {e}"))?;
    let asset = release
        .assets
        .into_iter()
        .find(|a| a.name.ends_with(".bin"))
        .ok_or_else(|| "the latest ps4debug-NG release has no .bin asset".to_string())?;
    Ok(PayloadInfo {
        tag: release.tag_name,
        name: release.name,
        asset: asset.name,
        url: asset.browser_download_url,
        sha256: String::new(),
        path: String::new(),
        source: format!("https://github.com/{REPO}"),
    })
}

#[tauri::command]
pub async fn ps4debug_payload_download(app: AppHandle) -> Result<PayloadInfo, String> {
    let latest = ps4debug_payload_latest().await?;
    let dir = local_dir(&app).ok_or("no app data directory for the payload")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("create payload dir: {e}"))?;
    let bytes = reqwest::Client::new()
        .get(&latest.url)
        .header("User-Agent", "SlopStation")
        .send()
        .await
        .map_err(|e| format!("payload download failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("payload download failed: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("payload download failed: {e}"))?;
    let bin = dir.join("ps4debug-ng.bin");
    std::fs::write(&bin, &bytes).map_err(|e| format!("write payload: {e}"))?;
    let sha = sha256_hex(&bytes);
    let manifest = serde_json::json!({
        "repo": REPO,
        "tag": &latest.tag,
        "name": &latest.name,
        "published_at": "",
        "asset": &latest.asset,
        "url": &latest.url,
        "sha256": &sha,
        "fetched_at": "",
        "license": "GPL-3.0",
        "source": &latest.source,
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write payload manifest: {e}"))?;
    Ok(PayloadInfo {
        sha256: sha,
        path: bin.to_string_lossy().into_owned(),
        ..latest
    })
}

#[tauri::command]
pub fn ps4debug_payload_save(source: String, dest: String) -> Result<(), String> {
    std::fs::copy(&source, &dest)
        .map(|_| ())
        .map_err(|e| format!("save payload: {e}"))
}
