# Install

## Installer (recommended)

Download `SlopStation_<version>_x64-setup.exe` from
[Releases](https://github.com/NetVar1337/SlopStation/releases/latest) and run it. The
installer is per-user (`installMode: "currentUser"` in `app/src-tauri/tauri.conf.json`) —
no administrator prompt — and installs the app, the engine, the bundled ps4debug-NG
payload and the optional Magicmida sidecars.

**Auto-update is on by default.** On launch the app checks the latest GitHub release,
downloads the signed installer in the background and offers **Install & restart** in the
banner. **Settings → Updates** shows the running version and a manual check. Updates are
verified against the embedded Tauri public key; the installer is Authenticode-signed when
the signing secrets are configured.

## Portable single file

`SlopStation.exe` from the release zip (`SlopStation-portable-<tag>.zip`) is
self-contained: the engine is embedded in the executable and extracted to
`%LOCALAPPDATA%\dev.slopstation.ui\engine` on first run. No installer, no sidecar folder.
The payload card can download the latest ps4debug-NG release on demand.

## Package managers

| Manager | Command | Notes |
| --- | --- | --- |
| winget | `winget install NetVar1337.SlopStation` | user scope, NSIS installer |
| Scoop | `scoop install slopstation` | portable zip |
| Chocolatey | `choco install slopstation` | NSIS installer, silent |

The manifests live in [`packaging/`](https://github.com/NetVar1337/SlopStation/tree/main/packaging)
and are generated from a release's `SHA256SUMS` by `tools/gen_packages.ps1`; the
`packages` workflow publishes them as artifacts on every release.

## Requirements

| Needed for | Requirement |
| --- | --- |
| Running the app | Windows 10/11 x64, WebView2 runtime (bundled with Windows 11) |
| Console work | A PS4 on the same network running the ps4debug-NG payload |
| Building | Visual Studio 2022+ with _Desktop development with C++_, CMake ≥ 3.25, Ninja, Node.js + npm, Rust/Cargo |
| Optional | Administrator rights for host packet capture; Magicmida for Themida unpacking |

## Verify the download

Every release ships `SHA256SUMS` next to the assets:

```powershell
gh release download v0.2.3 -R NetVar1337/SlopStation -p SHA256SUMS
Get-FileHash -Algorithm SHA256 .\SlopStation_0.2.3_x64-setup.exe
```

The hash must match the line for that file. The `.sig` file next to the installer is the
Tauri updater signature, not an Authenticode signature — the app checks it, `Get-AuthenticodeSignature`
reports the code-signing certificate when the release was signed.
