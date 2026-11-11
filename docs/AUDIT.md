# reverse-slop — Full Audit

Date: 2026-11-11 · Scope: whole repo (`src/`, `app/`, `tools/`, CI, docs) · Baseline: v0.1.1, ~36.4k lines of first-party C++ (280 files), ~7.5k lines of TypeScript/React, 455 C++ test cases, 50 frontend tests.

## Verdict up front

This is an unusually healthy codebase: pinned dependencies, ASAN + `/analyze` + clang-tidy CI lanes, a deterministic live-fixture test target, chaos-mode protocol tests, benchmark baselines with CI regression gating, signed releases with SHA256SUMS, a sandboxed Lua surface, loopback-only HTTP with bearer tokens and DNS-rebinding guards. There are **no confirmed critical defects** in the audited state. The findings below are dominated by _feature gaps and hardening opportunities_, plus a small number of concrete issues.

**Top 5 things to act on first:**

1. **Unfinished merge in the working tree** — `git status` shows an in-progress merge with conflicts in `src/core/mcp/mcp_tools.cpp`, `src/core/runtime/backend_ps4.cpp`, `src/tests/test_ps4.cpp` (and staged edits in `backend_ps4.hpp`, `ps4_protocol.hpp`). The tree does not build in this state and the conflicted hunks contain typos (`INTALL`, `intall`, `ths`, `clen`). Resolve, commit or abort before anything else.
2. **No fuzzing** of the ELF/PE/Mach-O/IPA/packet parsers that consume untrusted dumps and captures.
3. **No code-coverage reporting** in CI — 455 tests exist, but nobody measures what they reach.
4. **No e2e/UI tests** for the Tauri app — only component/store unit tests; nothing drives a real engine.
5. **README/docs drift risk** — version badge is hardcoded, deep reference tables duplicate the code, and the README is 36 KB (reworked separately in this pass).

Severity legend: **P0** fix now · **P1** next milestone · **P2** roadmap · **P3** nice-to-have.

---

## 1. Repository / process

| #   | Sev    | Finding                                                                                                                                                                                   |
| --- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **P0** | Unresolved merge conflicts (`UU` files) left in the working tree; build is broken until resolved.                                                                                         |
| 2   | P2     | `.cache/` (clangd index) is not in `.gitignore`; it sits untracked in the working tree.                                                                                                   |
| 3   | P2     | Two stale build trees (`build/`, `build-ninja-msvc-asan/`) live in the checkout; documented, but a `tools/clean.ps1` convenience would help.                                              |
| 4   | P3     | No `CODEOWNERS`; review routing is implicit.                                                                                                                                              |
| 5   | P3     | No `FUNDING.yml` / sponsorship metadata.                                                                                                                                                  |
| 6   | P2     | No `ROADMAP.md`; intended direction (PS5? Switch? Linux host?) is discoverable only from issues.                                                                                          |
| 7   | P3     | `THIRD_PARTY_NOTICES.md` is 609 KB generated noise in the repo root; generate at packaging time instead and keep a checksum.                                                              |
| 8   | P3     | Git history mixes `feat:`/`refactor:` conventional commits with free-form ones; add commitlint only if you care — currently cosmetic.                                                     |
| 9   | P2     | Release notes are auto-cut from CHANGELOG by tag; CHANGELOG `Unreleased` section is healthy but make `tools/sync_version.ps1` also verify the badge version in README (currently manual). |

## 2. Build / CI

| #   | Sev | Finding                                                                                                                                                                                                                                                                     |
| --- | --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 10  | P1  | No code-coverage lane (OpenCPPCoverage/`/cs`-style or llvm-cov) — add one and gate PRs on core modules.                                                                                                                                                                     |
| 11  | P1  | No fuzz targets. libFuzzer harnesses for `elf_loader`, `pe_parser`, `macho_loader`, `ipa`, `zip_reader`, and the ps4debug-NG packet parser would pay for themselves (these eat untrusted dumps).                                                                            |
| 12  | P2  | Windows-only toolchain. A Linux engine build (headless MCP server on a analysis VM) requires abstracting `backend_usermode` (Win32), raw sockets (SIO_RCVALL), WinHTTP and the Tauri supervisor — big, but the core is mostly portable STL.                                 |
| 13  | P2  | `_ext` downloads are pinned by SHA-256 (good) but there is no Dependabot-style automation for the _pinned archives_; a monthly "bump deps" script with build+test gating would close the loop.                                                                              |
| 14  | P2  | No precompiled-header or unity-build option; full rebuilds of `src/core` + `src/hyperion` are slow on laptops.                                                                                                                                                              |
| 15  | P3  | `tools/build.ps1` flags proliferate (`-NoFrontend -FullClean -PlanOnly -Preset -Full -Targets -CmakeExtra -Test -TestLabel`); consider a `build.ps1 -Interactive` or documented common recipes.                                                                             |
| 16  | P3  | No ccache/sccache guidance for local dev (CI uses sccache; locals get cold caches).                                                                                                                                                                                         |
| 17  | P2  | No CI lane builds the docs/README assets (screenshots are regenerated by hand; see §10).                                                                                                                                                                                    |
| 18  | P3  | `analyze` job lists `/analyze` findings in the summary but never fails; consider a ratchet (fail on new IDs).                                                                                                                                                               |
| 19  | P2  | Two timing-sensitive debugger tests are documented as flaky under full-suite runs (`ps4_composites_on_local_debugger`, `ps4_chaos_peer_close_drops_socket_and_reconnect_restores`) — randomize/retry or give the suite a per-test port pool instead of documenting forever. |
| 20  | P3  | No nightly/scheduled full-suite run with the ASAN preset + live fixture (weekly bench exists; nightly tests don't).                                                                                                                                                         |

## 3. Engine core (`src/core`)

### Runtime / PS4 backend

| #   | Sev | Finding                                                                                                                                                                                                                                               |
| --- | --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 21  | P1  | `target.ps4_reconnect` restores breakpoints/watchpoints but scan state restore is partial (documented in README as "restores ... and scan state" — verify; the native scanner on-console state is payload-side and may be gone after a payload drop). |
| 22  | P1  | One console at a time, hard. A console _manager_ (saved endpoints, quick-switch, per-console session profiles) would help multi-console devkits.                                                                                                      |
| 23  | P2  | No automatic reconnect with backoff when the console drops mid-session (manual `ps4_reconnect` only).                                                                                                                                                 |
| 24  | P2  | No connection over the payload's secondary interfaces (USB? uart?) — TCP/IP only; fine, but document limits.                                                                                                                                          |
| 25  | P2  | `ps4_call` RPC stub: one stub per process, 6 args — no floating-point args, no struct-by-value, no error semantics when the target function faults (documented? verify).                                                                              |
| 26  | P2  | Breakpoint slots are client-allocated 0–29 but there is no UI/MCP guard against two MCP clients fighting over slot ownership.                                                                                                                         |
| 27  | P2  | Hardware watchpoints: DR0–DR3 only, no masked-data watchpoints (RWX DR7 masks exist in silicon; payload may not expose).                                                                                                                              |
| 28  | P3  | `ps4_wait` is poll-over-TCP-755; a persistent SSE-style event push to the UI exists (`/events`), but debugger stop events are not pushed — the UI polls too.                                                                                          |
| 29  | P2  | No gdbserver/RSP compatibility shim — would unlock IDA/x64dbg/LLDB as frontends for the console.                                                                                                                                                      |
| 30  | P3  | usermode backend is Windows-only and undocumented as a feature (it's how tests run); exposing it in the UI as "attach to this PC's process" is already there via Targets — good; document it as a first-class feature.                                |

### Memory

| #   | Sev | Finding                                                                                                                                                        |
| --- | --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 31  | P1  | Scanner: no "unknown initial value" scan host-side (console-side `ps4_scan_all` covers PS4 only). Add a host-side unknown-value pass for the usermode backend. |
| 32  | P1  | No grouped/nexted scan ("value between X and Y" exists; "changed by more than N" doesn't).                                                                     |
| 33  | P2  | Pointer scan: single-level offsets only? multi-level chains with wildcards per level + negative offsets would match CE parity.                                 |
| 34  | P2  | Watchlist freeze is ~10 Hz fixed; no per-entry rate, no "freeze once", no undo of freeze writes.                                                               |
| 35  | P2  | Snapshots: compare/list/free exist; no snapshot diff _export_ (CSV/JSON) for external analysis.                                                                |
| 36  | P3  | `siggen` output format is bespoke; add IDA/Cheat-Engine-compatible signature export.                                                                           |
| 37  | P3  | No scan-result persistence (save/resume a scan across engine restarts).                                                                                        |

### Debugger

| #   | Sev | Finding                                                                                                               |
| --- | --- | --------------------------------------------------------------------------------------------------------------------- |
| 38  | P1  | No conditional breakpoints (expression on registers/memory evaluated engine-side).                                    |
| 39  | P1  | No breakpoint hit counting / logging breakpoints ("break when hit N times, then log").                                |
| 40  | P2  | Trace actions are one-shot; no continuous trace-to-file with ring buffer.                                             |
| 41  | P2  | Callstack is rbp-chain only; no unwind info (PE `.pdata` exists for x64 — use it).                                    |
| 42  | P2  | `ps4_stack` server-side walk exists; locals rendering is raw hex windows — no type-aware locals without user structs. |
| 43  | P3  | No thread-aware stepping (step only this lwp exists in UI; verify engine parity).                                     |

### Disassembly / static

| #   | Sev | Finding                                                                                                                                                                          |
| --- | --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 44  | P1  | Encrypted SELF segments are not decrypted (documented). Partner with fpKG/decrypt tooling (e.g. via the payload's decrypt facilities) rather than leaving it at "analyze dumps". |
| 45  | P2  | Function index is Zydis-based linear/recursive descent; no function-start heuristics feed from Hyperion analysis back into the index (both compute their own). Unify.            |
| 46  | P2  | No graph view (CFG rendering) in the UI — xray computes CFGs but there's no interactive graph canvas.                                                                            |
| 47  | P2  | Strings view: no string _decoding_ (UTF-16 exists; no AES/XOR brute previews inline).                                                                                            |
| 48  | P3  | No FLIRT/.sig signature library format — `libsig` is custom; add Lumina-style server or import FLIRT.                                                                            |

### Decompiler (Hyperion)

| #   | Sev | Finding                                                                                                                                                                                                                            |
| --- | --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 49  | P1  | ARM64 lifter exists (`lifter_arm64.cpp`) but PS4 is x86-64; the IPA/Mach-O path loads arm64 images with no emulation backend (Unicorn is x86-64 only) — decomp quality for iOS images is lift-only. Add Unicorn arm64 or document. |
| 50  | P2  | Type inference is intra-procedural; no inter-procedural propagation or user-type promotion from RTTI.                                                                                                                              |
| 51  | P2  | No editing round-trip: types/structs edits don't re-render already-decompiled functions until reload.                                                                                                                              |
| 52  | P3  | Pseudocode emitter has no syntax highlighting / clickable tokens in the Tauri UI (check — if the React view is plain text, upgrade).                                                                                               |
| 53  | P3  | `.hdb` export/import is custom; add Binary Ninja/IDA database interop if adoption matters.                                                                                                                                         |

### Emulation / taint

| #   | Sev | Finding                                                                                                     |
| --- | --- | ----------------------------------------------------------------------------------------------------------- |
| 54  | P2  | Unicorn demand paging pages from the image/live memory — good; no snapshot/restore of an emulation session. |
| 55  | P2  | Taint is byte-granular forward taint only; no backward slicing.                                             |
| 56  | P3  | No emulation of PS4 syscalls — Orbis syscall table exists for naming, not emulation.                        |

### Analysis / patching

| #   | Sev | Finding                                                                                                                  |
| --- | --- | ------------------------------------------------------------------------------------------------------------------------ |
| 57  | P2  | Patch journal is per-session (verify): persisted journals across restarts would make the patch workflow survive reboots. |
| 58  | P2  | `full_pass` chains heuristics; no user-defined pass ordering or per-pass toggles persisted.                              |
| 59  | P3  | Xray scoring (obfuscation/CFF) is heuristic-only; no ML model option (fine, but document thresholds).                    |

### Network / proxy

| #   | Sev | Finding                                                                                                                                                                                                                    |
| --- | --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 60  | P1  | Plaintext HTTP proxy logging is opt-out-able but the _replay_ of captured requests can carry secrets; add a "redact Authorization/Cookie" toggle (default on).                                                             |
| 61  | P1  | MITM installs a CA into CurrentUser ROOT (with consent dialog). Document the uninstall path more prominently (`mitm_uninstall` exists); warn that captured TLS keys at rest are sensitive.                                 |
| 62  | P2  | Capture is host-NIC only (documented); add ERSPAN/remote-capture ingestion (pcap import exists? verify `export_pcap` only) — _importing_ pcaps from a switched tap would cover the console without routing through the PC. |
| 63  | P2  | No TLS 1.3 decryption beyond MITM CA; no QUIC/HTTP-3 awareness in parsers.                                                                                                                                                 |
| 64  | P3  | PCAP export format only — add pcapng with comments for annotated flows.                                                                                                                                                    |

### Persistence / RE utilities

| #   | Sev | Finding                                                                                                                           |
| --- | --- | --------------------------------------------------------------------------------------------------------------------------------- |
| 65  | P2  | `sessions.db` is SQLite without schema versioning/migrations story (verify `persist` code); add `PRAGMA user_version` migrations. |
| 66  | P3  | No cloud/team sharing of symbols/comments (deliberate? fine — document the stance).                                               |

### Lua scripting

| #   | Sev | Finding                                                                                                                                                                                                 |
| --- | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 67  | P2  | Sandbox caps memory/instructions but there is no per-script _wall-clock_ cap separate from `timeout_ms` (verify); a script in a native C loop (e.g. huge `string.rep`) can still hog the engine thread. |
| 68  | P2  | No script persistence/snippets library in the app (Scripts panel has per-run history only).                                                                                                             |
| 69  | P2  | No autocomplete/IntelliSense for `slop.*` in the editor textarea.                                                                                                                                       |
| 70  | P3  | `script_unsafe` is a global toggle; make it per-run consent (MCP param) rather than a setting.                                                                                                          |
| 71  | P3  | No structured logging from Lua (`slop.log` goes to engine log; no levels).                                                                                                                              |

### MCP / HTTP server

| #   | Sev | Finding                                                                                                                                                                                                                                 |
| --- | --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 72  | P1  | Token rotation rewrites client config files in place with the plaintext token (`.claude.json` etc.) — documented, but add a "client config contains secrets" warning banner and an option to _not_ embed the token (prompt-on-connect). |
| 73  | P2  | No per-tool rate limiting (global caps exist); a buggy agent in a `memory.scan` loop can starve the engine. Add token-bucket per tool.                                                                                                  |
| 74  | P2  | MCP protocol level: 2025-06-18 — no `resources`, `prompts`, `elicitation`, or `progress` support; tools carry prose `ai_hint`s instead. Upgrading to full MCP features would help agent UX.                                             |
| 75  | P2  | No API versioning on `/api`; breaking changes will hit Tauri + MCP clients simultaneously. Add `v1` prefix now while it's cheap.                                                                                                        |
| 76  | P3  | `/events` SSE has a 16-stream cap; browser tabs + agents can exhaust it — raise or make configurable.                                                                                                                                   |
| 77  | P3  | No WebSocket endpoint; SSE is one-way. Fine, but agents poll `watch.values`.                                                                                                                                                            |
| 78  | P2  | `tools/list` returns 20 tools with big descriptions; add `annotations` (read-only, destructive, idempotent) so agents know `patch.*` and `memory.write` are destructive — today only prose hints say it.                                |
| 79  | P3  | No OpenAPI descriptor for `/api` (only MCP schemas); an OpenAPI JSON would unlock generic clients.                                                                                                                                      |

## 4. Frontend (`app/`)

| #   | Sev | Finding                                                                                                                                                                                                |
| --- | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 80  | P1  | No e2e tests. Add a Playwright lane that starts the engine + `SlopTarget.exe` and drives the real UI (the screenshot pipeline built for this README is 80% of that harness — promote it to `app/e2e`). |
| 81  | P1  | No crash/error telemetry opt-in; when the engine dies the user pastes logs manually. At minimum: a "copy diagnostics" bundle button (diag exists via `app.diag` — surface it).                         |
| 82  | P2  | Targets panel defaults to "Connect a console"; local-process listing is one click away — add a "remember my backend choice" or a split view.                                                           |
| 83  | P2  | Memory hex editor: no diff highlighting vs a snapshot, no string/struct inspector pane at the caret.                                                                                                   |
| 84  | P2  | No data-export from scanner results (CSV), watchlist (Cheat Engine .CT?), or findings generally.                                                                                                       |
| 85  | P2  | Command palette covers navigation/actions; no in-app _help search_ (docs are README-only).                                                                                                             |
| 86  | P3  | No localization framework (all strings hardcoded English).                                                                                                                                             |
| 87  | P3  | Themes are 5 built-ins; no user theme editor (tokens.css is hand-editable but not exposed).                                                                                                            |
| 88  | P3  | No minimap/overview in the disassembly listing for long functions.                                                                                                                                     |
| 89  | P3  | Virtualized lists are tested at 4096 rows (bench) — add a stress fixture (1M rows) to the bench suite.                                                                                                 |
| 90  | P2  | Zustand stores persist layout to localStorage; no export/import of app layout+settings for support scenarios.                                                                                          |

## 5. Native shells

| #   | Sev | Finding                                                                                                                                                                         |
| --- | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 91  | P2  | The ImGui shell is "kept for parity work" and CI keeps it compiling — decide: ship it as a lightweight fallback (document it properly) or delete it; half-supported shells rot. |
| 92  | P3  | ImGui shell has an Unpacker view the Tauri app lacks (per README) — feature parity matrix needed either way.                                                                    |
| 93  | P3  | Tauri supervisor: engine restart backoff exists; add a "open engine log folder" action in the crash dialog (log path is shown but not clickable/openable).                      |

## 6. Documentation / community

| #   | Sev | Finding                                                                                                                                                                                                                                     |
| --- | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 94  | P1  | README was 36 KB / 670 lines — too long for a landing page (reworked in this pass; keep deep reference in `docs/` going forward).                                                                                                           |
| 95  | P2  | No tutorial/walkthrough docs ("first console connect", "first dump → rename → decompile" as a guided doc with screenshots).                                                                                                                 |
| 96  | P2  | No hosted docs site (mkdocs/mdBook from `docs/`); everything is GitHub-rendered markdown.                                                                                                                                                   |
| 97  | P2  | `docs/screenshots` had stale hand-made images; this pass regenerated them from the real app against the bundled fixture. Automate: a `tools/screenshots.ps1` that reruns the Playwright driver (keep it out of CI — flaky — but script it). |
| 98  | P3  | Examples cover PS4 workflows; add a local-only example (attach to SlopTarget / any PC process) so users without a console can try everything except console actions.                                                                        |
| 99  | P3  | `CONTRIBUTING.md` is solid; add a "good first issue" label policy and a dev-setup FAQ from the Troubleshooting table.                                                                                                                       |
| 100 | P3  | No video/GIF demos; a 60-second capture of connect→scan→freeze would outperform any text.                                                                                                                                                   |
| 101 | P2  | CHANGELOG `Unreleased` is maintained (good); enforce via CI check that PRs touch CHANGELOG (or use release-please).                                                                                                                         |

## 7. Security hardening

| #   | Sev | Finding                                                                                                                                                                                                                             |
| --- | --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 102 | P1  | Add a SECURITY-focused CI lane: gitleaks (secret scanning) + a Windows-binary check (no unexpected imports/sections in release artifacts).                                                                                          |
| 103 | P2  | The engine accepts _no token_ from loopback browsers in dev mode (`isInsecureDev`) — documented, but consider requiring the token even on loopback unless `--insecure-dev` is passed; the current default trusts any local process. |
| 104 | P2  | `fs` tool has no path jail; any bearer-token holder can read/write the whole user profile. Add an optional `fs_root` jail setting (default off = today, but give paranoid users the knob).                                          |
| 105 | P2  | `web` tool SSRF guards exist (loopback/private denied by default) — add DNS-rebinding resistance: pin the resolved IP for the whole request (verify `web_fetch` re-resolves per redirect).                                          |
| 106 | P2  | Lua sandbox: verify the instruction cap counts _C callbacks_ loops (e.g. `slop.mem.read_bytes` in a tight loop) — engine-side timeouts on the whole run are the real backstop; document that.                                       |
| 107 | P3  | Token entropy: verify generation uses a CSPRNG (BCryptGenRandom or equivalent) — grep says "generated automatically"; confirm source and note it in SECURITY.md.                                                                    |
| 108 | P3  | No binary hardening flags documented (/DYNAMICBASE, /NXCOMPAT, /CET, control-flow guard) — add to CMake for engine/app and list in SECURITY.md.                                                                                     |

## 8. Features / roadmap (new capability)

| #   | Sev | Finding                                                                                                                                                         |
| --- | --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 109 | P2  | **PS5 backend**: the architecture (backend registry + protocol) is shaped for a second console backend; ps5debug protocol support is the natural v0.2 headline. |
| 110 | P2  | **Nintendo Switch / other targets**: same backend abstraction; low priority.                                                                                    |
| 111 | P2  | **Team workflows**: shared symbol/comment server (self-hosted), or at least Git-based sync of `symbols/<hash>.json`.                                            |
| 112 | P3  | **Unpacker view in Tauri** (parity with ImGui shell).                                                                                                           |
| 113 | P3  | **winget/choco/scoop packages** alongside the NSIS installer; plus in-app update checks (Tauri updater).                                                        |
| 114 | P3  | **Struct editor UI** in Tauri (types tool is MCP/Lua-only? verify — if so, a visual ReClass-style editor is the gap).                                           |
| 115 | P3  | **Time-travel debugging** snapshot ring on the console — heavy; research-grade.                                                                                 |

---

## Summary counts

- **P0:** 1 (merge conflicts in working tree)
- **P1:** 14 (fuzzing, coverage, e2e, conditional breakpoints, unknown-value scans, encrypted-SELF strategy, SELF-decrypt, secret redaction in proxy, MITM key handling, MCP annotations/versioning, UI telemetry/export parity, README)
- **P2:** ~55 items across runtime, memory, debugger, decompiler, network, MCP, frontend, docs, security hardening, platform ports
- **P3:** ~45 polish/parity/community items

**Theme of the audit:** the _engineering floor_ (build, CI, tests, pinning, signing) is already better than most commercial tooling; the leverage is now in (a) closing the test-visibility gap (coverage, fuzz, e2e), (b) debugger/scanner parity with Cheat Engine-class expectations (conditions, counts, unknown-value, pointer chains), (c) agent-facing upgrades to the MCP surface (annotations, versioning, rate limits, elicitation), and (d) deciding the fate of the ImGui shell and the multi-console roadmap.

---

## Addendum — implementation pass (same day)

Landed from this audit:

- Items 2, 4, 6, 9: `.gitignore` covers `.cache/`; `CODEOWNERS`; `ROADMAP.md`;
  `tools/sync_version.ps1` also validates the README version badge.
- Items 80 + 97: `app/e2e` driver (smoke + screenshots modes), `tools/screenshots.ps1`,
  nightly `.github/workflows/e2e.yml`. Both modes verified green against the real
  engine + fixture, with no leaked processes.
- README: new screenshots regenerated through the committed driver; Tests section
  documents the e2e lane; screenshot disclaimer updated.
- CHANGELOG updated under Unreleased.

New findings surfaced while building the e2e harness:

- **P2 — `--port` ignored by the current build.** The engine announces/binds the
  settings port even with `--port <n>` on the command line; the `SLOP_MCP_PORT`
  environment variable works. Either the checked-in binary predates the flag or the
  flag plumbing regressed; rebuild and re-test (the e2e driver passes both and trusts
  the engine's own `SLOP_ENGINE_READY` announce instead of the requested port).
- **P2 — spawner can report a dead endpoint.** Under process churn, `engine.json` can
  name a pid that is alive-but-not-serving (or reused); a spawner then prints
  `SLOP_ENGINE_READY <port>` for an endpoint that 401s/times out. The e2e driver works
  around it (probes health + detects `SLOP_ENGINE_EXISTING`); the engine should verify
  the registration round-trip before announcing (or liveness-probe the endpoint).
- **P3 — `/health` is unauthenticated** (liveness, by design) — automation must treat
  the first `/api` call as the real readiness gate.
