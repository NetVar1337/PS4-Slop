# Changelog

All notable changes to SlopStation are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The release job publishes the
section matching the pushed tag as the GitHub release notes.

## [0.2.2] - 2026-11-14

### Fixed

- The workspace now fills the window when neither the engine nor the update
  banner is visible; the main grid row was landing in the banner's auto row,
  leaving the lower half black.

## [0.2.1] - 2026-11-14

### Fixed

- The portable zip now unpacks into `SlopStation/` (the dist folder was still
  named `reverse-slop`).

## [0.2.0] - 2026-11-13

### Added

- Auto-update: release builds check GitHub on launch, download the signed
  installer with progress, and offer **Install & restart**; Settings → Updates
  shows the running version and a manual check.
- Single-file portable: the packaging job appends the engine to the app exe
  (`SLOPENG1` overlay) and extracts it on first run, so the portable download
  is one exe. The installer still ships the engine resource.
- `memory.scan_save` / `memory.scan_load`: persist an address-list scan to
  `%LOCALAPPDATA%\reverse-slop\scans\<name>.json` and resume it after an engine
  restart (rows are capped at 500k; a pid mismatch needs `force:true`).
- `memory.watch_freeze_once` and `memory.watch_undo`: a hold that releases after
  the first write-back, and a restore of the value captured when the freeze was
  armed.
- `ps4_status` now reports a `capabilities` object (native scan, turbo scan,
  write_multi, proc_modules, proc_snapshot, assemble, elf_rpc, gdb bridge) and a
  `payload_note`, so an upstream ps4debug-NG payload is visible before a command
  fails.
- Automatic console reconnect with exponential backoff after a dropped
  connection (`ps4_auto_reconnect` setting, default on). An intentional
  `ps4_disconnect` is never undone.

### Fixed

- .NET metadata: attacker-controlled table row counts are clamped to the
  stream before any vector is sized (the owner-table fill was a heap OOB write
  on a crafted assembly); signature/TypeRef recursion is depth- and cycle-capped;
  the EH-section walk can no longer spin on a zero-size section.
- MCP: the hidden `app` tool (settings, token rotation, shutdown) is rejected on
  `/mcp` and remains reachable only through the UI `/api` channel; `proxy replay`
  and `fs` writes are classified as mutating for the confirm gate.
- Audit log and `proxy.entry` redact bearer tokens, `Authorization`, `Cookie`
  and token-ish query values by default (`reveal:true` opts out per call).
- `fs` refuses paths inside the engine data dir (settings, token, audit log,
  session store), including hits from search/grep walks.
- GDB Remote: `P`/`G` reads and writes map r8-r15 to their real registers
  (the old code added the register index to the value).
- Debug-event listener on TCP 755 accepts only the attached console, and each
  connection is drained on its own thread so a silent peer cannot block the
  payload's connect-back.
- `watch_add {freeze:true}` latches the live value instead of writing zero.
- Unknown-initial rescans compare values that straddle a stash chunk boundary.
- Lua sandbox: `slop.image.load` requires `script_unsafe` (host file access).
- Empty bearer token fails closed: a token is generated and persisted, or the
  MCP server refuses to start.
- `types.add_member` no longer self-deadlocks on the catalog mutex.
- ZIP: valid zero-length deflated entries extract (zlib needs a non-zero output
  window).
- PE parser: `e_lfanew + 24` no longer truncates to 16 bits, section offset
  arithmetic widens before adding, a zero-raw-size section no longer hides
  later sections, and an unmapped import-name RVA no longer reads offset 0.
- Loaders: SELF rebuilds and ELF files are capped at 2 GiB; Mach-O `LC_MAIN`
  entry underflow is guarded.
- Decompiler expression emission is depth-capped; `parallel_for` swallows a
  throwing body and cannot hang on a concurrent pool stop.
- ASan lane runs the `mcp` area (minus the Unicorn-backed emulate cases) so the
  HTTP/JSON/SSE/fs surface is sanitized.
- Tauri CSP adds `script-src`, `object-src 'none'`, `base-uri 'none'` and
  `frame-ancestors 'none'`; the proxy token field is masked.

### Changed

- The NSIS installer installs per-user (`currentUser`), so installs and
  updates need no UAC prompt.
- CI: PRs run only the lanes their paths touch; ASan, `/analyze`, clang-tidy
  and packaging run on main/tags (a PR can opt into packaging with the
  `ci:package` label). The test lane retries only failed CTest entries.
- Release builds sign the installer for the Tauri updater and publish
  `latest.json` next to the setup exe.

- `app/e2e`: end-to-end driver that spawns the real engine and the
  `SlopTarget` fixture — `npm run smoke` (API battery, also runs in the new
  nightly CI lane `.github/workflows/e2e.yml`) and `npm run screenshots`,
  which regenerates the README screenshots from the live UI; wrapped by
  `tools/screenshots.ps1`.
- `ROADMAP.md`: prioritized plan distilled from the full audit (`docs/AUDIT.md`).
- `CODEOWNERS`; full project audit with 115 findings (`docs/AUDIT.md`);
  README screenshots regenerated from the real app against the fixture.
- MIT `LICENSE` and `THIRD_PARTY_NOTICES.md` (generated by
  `tools/gen_third_party_notices.py`), shipped in the installer and the
  portable build.
- Single product version in `VERSION` (CMake, VERSIONINFO, manifests) synced
  into the frontend/Tauri manifests by `tools/sync_version.ps1`; CI checks it
  and the release tag.
- VERSIONINFO resources in `reverse-slop-engine.exe` and `reverse-slop.exe`.
- CMake presets for Debug, AddressSanitizer and `/analyze`, plus `testPresets`;
  `SLOP_BUILD_UI`, `SLOP_SANITIZE`, `SLOP_ANALYZE` options; `.clang-tidy` and
  `tools/clang_tidy.ps1`.
- CI lanes for ASan tests, `/analyze`, clang-tidy, the legacy ImGui shell and
  a version check; weekly benchmark workflow; Dependabot.
- `SHA256SUMS` for every release asset; Authenticode signing through Azure
  Trusted Signing when the signing secrets are configured.
- CTest entry per test area plus one full-suite entry; per-test watchdog
  timeouts in the test harness.
- `tools/mcp_live_test.py` spawns and health-checks the engine itself, takes
  paths from argv/env and exits non-zero on failure.
- `examples/` Lua scripts (PS4 and generic) with a README.
- `CONTRIBUTING.md`, `SECURITY.md`, issue and pull-request templates.

### Changed

- `tools/sync_version.ps1` also checks the README version badge against `VERSION`.
- Every C/C++ dependency archive is pinned by SHA-256 and every git dependency
  by commit SHA; workflow actions are pinned by commit SHA.
- Tag releases are published only after all build, test and analysis lanes
  pass.
- `tools/build.ps1` regenerates build trees configured from another checkout
  location, `-FullClean` also clears `_ext\*-build` / `_ext\*-subbuild`, and
  log directories are pruned.

### Removed

- Unused frida-core devkit download and the `slop_frida.dll` CI artifact that
  no target produced.
- zlib's example programs and their CTest entries.

## [0.1.1]

- First tagged reverse-slop release: PS4 (ps4debug-NG) console connection,
  live memory, debugger, static analysis and decompiler, Tauri front end and
  MCP server.

[Unreleased]: https://github.com/NetVar1337/PS4-Slop/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/NetVar1337/PS4-Slop/releases/tag/v0.1.1
