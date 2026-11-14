# Roadmap

Prioritized from the full audit ([`docs/AUDIT.md`](docs/AUDIT.md), 115 items). Severities:
**P0** blocks everything · **P1** next milestone · **P2** following · **P3** polish.

## Landed (2026-11-14, "agent-grade" pass)

Everything below shipped in one pass; see the `Unreleased` section of
[`CHANGELOG.md`](CHANGELOG.md) for the details.

- [x] Resolve the in-progress merge and get `main` building green (done before this pass).
- [x] Code-coverage lane with a ratchet, libFuzzer targets for every untrusted-input parser
      (two real bugs found and fixed), `/analyze` finding ratchet, gitleaks, release-artifact
      mitigation checks, CHANGELOG gate.
- [x] e2e lane over the real engine + `SlopTarget` (nightly, `app/e2e`).
- [x] MCP: `resources` + `prompts`, `notifications/progress`, per-tool rate limits, `/api/v1`
      prefix with a deprecated alias, OpenAPI descriptor, `--port` fix, endpoint probe before
      `SLOP_ENGINE_READY`.
- [x] Proxy: credentials redacted at storage time, replay strips them, MITM state reporting.
- [x] Scanner: host-side unknown-initial scan, relative-change kinds, multi-level pointer chains
      with per-level wildcards and module-relative roots, CSV/`.CT` exports, per-entry freeze rates.
- [x] Debugger: hit-count and logging breakpoints, continuous trace to file, `debugger.stop/state/log`
      push events, breakpoint slot ownership, `.pdata` unwinding, thread-aware stepping.
- [x] Encrypted-SELF strategy documented (`docs/encrypted-self.md`) with `disasm.load_self`.
- [x] Token policy: client configs reference `${SLOP_MCP_TOKEN}`; Tern is the primary target;
      loopback requires the token unless `--insecure-dev`.
- [x] Multi-console manager (saved endpoints, quick switch, per-console profiles).
- [x] CFG graph data on `disasm.blocks`/`xray.cfg`; unified Hyperion/Zydis function detection.
- [x] ARM64 emulation path for Mach-O/iOS images; emulation sessions with snapshot/restore;
      backward slicing; Orbis syscall emulation.
- [x] PCAP import and pcapng export with comments; QUIC awareness.
- [x] `sessions.db` schema migrations; `fs_root` jail; web DNS pinning verified with a test.
- [x] Persisted patch journal; Git-shareable `notes.export`/`notes.import`.
- [x] PS5 backend over ps5debug-NG (connect, memory, modules, debugger, console feedback).
- [x] ImGui shell decision: kept as a documented lightweight fallback (`docs/imgui-shell.md`
      carries the parity matrix); the Unpacker view stays ImGui-only for now.
- [x] Tutorials, an mdBook site over `docs/`, a help index generator, winget/Scoop/Chocolatey
      manifests, and a demo-capture script.

## Next (P1)

- [ ] **UI panels for the tools that are still MCP/Lua-only**: decompiler view with syntax
      highlighting and clickable tokens, an interactive CFG graph canvas, a ReClass-style struct
      editor, the unpacker view, and Xray / patch-journal / network-capture / emulator panels.
- [ ] **Linux engine port**: the portable subset (Hyperion + `dissect`) already configures off
      Windows; next are `backend_usermode`, raw-socket capture, WinHTTP and the Tauri supervisor.
- [ ] **PS5 depth**: on-console scan engine, module dump, remote call and ELF upload once the
      payload exposes them; real-hardware verification of the current surface.
- [ ] **Localization** framework (all strings are hardcoded English) and a user theme editor.
- [ ] **Time-travel debugging**: a snapshot ring on the console (research-grade).

## Later (P3, opportunistic)

- [ ] Nintendo Switch / other targets behind the same backend abstraction.
- [ ] Shared symbol/comment server (self-hosted) on top of `notes.export`/`import`.
- [ ] FLIRT crc16 tails and referenced-function constraints (import models anchors only today).
- [ ] `emulate.slice` for ARM64 (x86-64 only today).
- [ ] `.eh_frame` unwinding for PS4 ELF callstacks (rbp chain today).
- [ ] Disassembly minimap, 1M-row virtualized-list stress fixture, WebSocket `/events` alternative.

Items are checked off as they land; the audit doc carries the full detail and
file-level pointers for each item.
