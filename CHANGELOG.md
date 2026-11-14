# Changelog

All notable changes to SlopStation are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The release job publishes the
section matching the pushed tag as the GitHub release notes.

## [Unreleased]

### Added

- **PS5 backend** over ps5debug-NG v1.3.2: `target.ps5_connect/ps5_disconnect/ps5_reconnect/ps5_auto/ps5_notify`
  and `debugger.ps5_*` (attach, 30 breakpoint slots, 4 DR watchpoints, continue/step/suspend/resume,
  registers, threads, port-755 stop events, console info/notify/print/foreground app). The memory,
  scanner and disassembly tools work on a PS5 through the same backend abstraction; `docs/ps5.md`
  documents the protocol source, ports and limits.
- **Multi-console manager**: `target.consoles_list/consoles_save/consoles_remove/consoles_switch` keep
  saved endpoints (host, port, notes, default pid, title filter, auto-connect) with a per-console
  profile (named watchlist set + scan width/kind). Switching detaches cleanly (session, breakpoint and
  watchpoint slots, scan state), restores the target console's profile and falls back to the previous
  console when the new one does not answer. Targets panel gained the saved-consoles card, the status
  bar an active-console quick switch.
- **Tern onboarding**: `slopstation` is registered in `%APPDATA%\tern\settings.json` (`agents.mcp`,
  http, `${SLOP_MCP_TOKEN}` bearer) and is the only client written when Tern is installed. New
  `mcp_onboard_clients` (empty = auto) and `mcp_token_in_configs` (default off) settings, plus a
  Settings banner listing client configs that still hold a plaintext token.
- **MCP**: `resources` (`slop://state/target`, `slop://state/image`, `slop://guide/<topic>`) and
  `prompts` (the guide playbooks); `notifications/progress` for a `tools/call` carrying
  `_meta.progressToken`; per-tool rate limits (`mcp_rate_limits`); `GET /api/v1/openapi.json`.
- **Scanner**: host-side unknown-initial-value scans for the usermode backend, relative-change kinds
  (`changed_by_more_than`, `changed_by_less_than`, `increased_by`, `decreased_by`), multi-level pointer
  scans with per-level offset ranges/wildcards/alignment and module-relative roots, `memory.scan_export`
  (CSV), `memory.diff export:{csv|json}`, IDA/x64dbg/CE/C signature renderings, Cheat Engine `.CT`
  watchlist import/export, and per-entry freeze rates (`interval_ms`).
- **Debugger**: hit-count breakpoints (`hits`, `hit_mode`), logging breakpoints (`log`, `continue`),
  `ps4_trace_start/stop/status` continuous JSONL traces with a ring buffer, breakpoint slot ownership
  (`owner`, `force`), `debugger.stop/state/log` SSE events, PE `.pdata` callstacks on the local backend
  and thread-aware stepping.
- **Static analysis**: Hyperion function starts merge into the shared function index (`source` marked,
  `disasm.index_updated` event); the decompile cache is keyed by type/name generation so edits re-render;
  inter-procedural call-argument types and RTTI `this` promotion; `disasm.load_self` with a decrypted-dump
  path (`docs/encrypted-self.md`); `disasm.strings {decode:true}` XOR/ROT/base64/UTF-16 previews;
  `re.libsig {sig_path}` IDA FLIRT import; CFG `graph` (nodes/edges) on `disasm.blocks` and `xray.cfg`.
- **Emulation**: persistent sessions (`emulate.session_create/session_step/session_run/session_destroy`)
  with bounded snapshot/restore, dynamic backward slicing (`emulate.slice`), Orbis syscall emulation
  (`orbis_syscalls`), and ARM64 emulation for Mach-O/iOS images (`arch:"arm64"`).
- **Lua**: `slop.log(level, msg)` with levels, `slop.api()` plus `script.api`, named snippets
  (`script.save/list/load/delete` + a Snippets sidebar with examples), and `slop.*` completion in the
  Scripts editor.
- **Network**: `network.import_pcap` (classic pcap and pcapng, Ethernet/SLL/raw-IP), pcapng export with
  per-packet comments (`network.annotate`), QUIC long-header awareness in `deep_inspect`/`stats`, and
  `proxy.status` MITM state.
- **Persistence**: `sessions.db` schema migrations (`PRAGMA user_version`), `fs_root` jail for every `fs`
  action, `notes.export`/`notes.import` for Git-shareable `symbols/<hash>.json`, and a patch journal that
  survives a restart.
- **UI**: a Pseudocode tab (highlighted, clickable tokens, `types.changed` re-render) with a
  dependency-free CFG graph; Structs (ReClass-style catalog editor with live `read_field` values) and
  Unpacker (packer verdict, patch passes, journal, revert) tabs; X-ray, Patches, Network and Emulator
  panels; a PS5 card in Targets; a disassembly minimap; snapshot-diff highlighting and a caret
  inspector in the hex editor; help search over the generated docs index; layout export/import; a
  typed i18n catalog (English/German) with a language selector; and a theme editor with named custom
  themes and JSON round-trip.
- **Notes**: `notes.push` / `notes.pull` share `symbols/<hash>.json` through any HTTP symbol store.
- **Tooling**: `app.diag_bundle` (support zip) with Settings "Copy diagnostics" and a crash-banner "Open
  log folder"; libFuzzer targets for the ELF/PE/Mach-O/.ipa/ZIP/ps4debug-NG/.NET parsers; coverage and
  `/analyze` ratchets; gitleaks; release-artifact mitigation checks; winget/Scoop/Chocolatey manifests;
  an mdBook site over `docs/` with tutorials; `tools/gen_help_index.mjs`.

### Changed

- The frontend, the e2e driver and the supervisor use `/api/v1` and `/api/v1/events`; `/api` and
  `/events` remain as deprecated aliases with a `Deprecation` header.
- `--port <n>` is honoured (it beats `SLOP_MCP_PORT` and the settings port), and the engine probes the
  endpoint before announcing `SLOP_ENGINE_READY` or reusing `engine.json`.
- Client configs reference `${SLOP_MCP_TOKEN}` instead of the literal token; token rotation follows the
  same policy.
- `script.run {unsafe:true}` needs per-run `confirm:true` unless `script_unsafe` is on;
  `script.api/list/load` are read-only actions.
- Proxy captures are redacted at storage time (`proxy_redact_secrets`, default on), and `proxy.replay`
  strips credentials unless `with_secrets:true`.
- Unicorn is built with the aarch64 backend alongside x86.
- The ps4 test suite uses a per-test ephemeral debug-event port instead of the machine-global 755.
- The event stream is also served over WebSocket (`/api/v1/events/ws`, RFC 6455); the UI prefers it
  and falls back to SSE. The weekly bench lane gained a 1,000,000-row virtualized-list case with a
  scroll-frame budget.

### Fixed

- Loopback no longer implies trust: the bearer token is required unless the engine runs with
  `--insecure-dev`.
- `pe_parse` read out of bounds on a crafted `e_lfanew` that wrapped in 32-bit arithmetic (found by
  fuzzing).
- `libsig` pattern masks compared only the low bit of each byte, so signature hits were false positives.
- A Lua script stuck in native code (a tight `slop.mem.read_bytes` loop, one huge `string.rep`) now ends
  at `timeout_ms`.
- An emulated run that stops on an invalid instruction or an unhandled guest exception reports its
  registers and memory instead of failing the tool call.
- `ps4_composites_on_local_debugger` and `ps4_chaos_peer_close_drops_socket_and_reconnect_restores` no
  longer flake on a busy machine, and the suite runs against a per-run scratch profile instead of the
  developer's `%LOCALAPPDATA%`.

### Security

- Breakpoint slots record their owning client; foreign slots require `force:true`.
- Captured HTTP credentials no longer persist anywhere the engine exposes.
- `/guard:cf` and `/CETCOMPAT` are deliberately not used: the Unicorn JIT executes generated code that
  neither mitigation can validate, so either one faults the first emulation run (`SECURITY.md`).
- Token generation is confirmed CSPRNG (`BCryptGenRandom`, 32 bytes), including the `--stdio` bridge.

## [0.2.3] - 2026-11-14

### Added

- `target.ps4_send_payload {host, port=9090, path?}`: stream the bundled (or a
  given) `.bin`/`.elf` payload to the console's BinLoader over one fresh TCP
  connection. The Targets payload card has **Send to console** with a loader
  port, and the connect form has **Discover** (UDP broadcast, PS4 consoles).
- The payload card can send the latest downloaded payload, not just the
  bundled one.

### Changed

- CI is lighter: the tests job builds and uploads the engine, so the separate
  engine job is gone; packaging runs only in the tag release workflow, which
  reuses the successful main build's artifacts instead of rebuilding.

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
