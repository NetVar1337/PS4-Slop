# Roadmap

Prioritized from the full audit ([`docs/AUDIT.md`](docs/AUDIT.md), 115 items). Severities:
**P0** blocks everything · **P1** next milestone · **P2** following · **P3** polish.

## Now (P0)

- [ ] Resolve the in-progress merge (`mcp_tools.cpp`, `backend_ps4.cpp`, `test_ps4.cpp`)
      and get `main` building green again.

## Landed (ecosystem merge, see [`docs/MERGE.md`](docs/MERGE.md))

- [x] MCP audit log (JSONL, every tool call) + `mcp_require_confirm` gate on mutating
      actions — ps4debug-mcp safety model, now server-side.
- [x] `target.ps4_discover` UDP broadcast discovery + `host:"auto"` for
      `ps4_connect`/`ps4_auto`.
- [x] `host` MCP tool: HTTP payload host with sha256 `/manifest.json`, token-gated
      LAN binds — afterglow-web function built in.
- [x] Homebrew injection recipe book: [`docs/injection/README.md`](docs/injection/README.md).
- [x] Session broker + GDB Remote (RSP) bridge ported from PS4-MCP into
      `src/core/runtime` (`broker.*`, `gdb_rsp.*`): the UI, the MCP server and a
      GDB/LLDB client now share one console connection; exposed as the `gdb` MCP
      tool (`start`/`stop`/`status`, loopback-only, writes opt-in).
- [x] PS4-MCP IDA/Ghidra/Binary Ninja/iaito adapters merged under
      `integrations/ps4-mcp-adapters/` with an MCP shim client for the built-in
      server (see its README for the op mapping).

## Landed (audit-fixes branch, 2026-11-13)

- P0/P1 correctness and security: .NET metadata row clamp (heap OOB write),
  MCP `app` boundary, audit/proxy secret redaction, `fs` engine-data guard,
  GDB r8-r15 mapping, port-755 peer pinning + per-connection drain,
  watch freeze latch, stash overlap, Lua `image.load` gate, fail-closed token,
  type-catalog deadlock, zip empty deflate, PE offset fixes, loader caps,
  Mach-O entry underflow, decompiler depth guard, `parallel_for` safety.
- Console readiness: auto-reconnect with backoff, conditional breakpoints,
  scan save/load, freeze-once/undo, `ps4_status` capability report.
- CI: the `mcp` area runs under ASan without the Unicorn cases; Tauri CSP
  hardening.

Still open from this audit: UI panels for the non-memory tools, hit-count
breakpoints, coverage/fuzz lanes, gitleaks, pcap import, ARM64 emulation,
PS5 backend, Linux engine port.

## Next milestone — v0.2 "agent-grade" (P1)

Test visibility and agent-facing surface, because that is where the leverage is:

- [ ] Code-coverage CI lane (engine core) with a ratchet on new code.
- [ ] libFuzzer targets for the untrusted-input parsers: `elf_loader`, `pe_parser`,
      `macho_loader`, `ipa`, `zip_reader`, ps4debug-NG packet parser.
- [ ] E2E lane driving the real UI against the engine + `SlopTarget` fixture
      (harness lands as `app/e2e`; promote from nightly to PR-blocking once stable).
- [ ] MCP: `annotations` on every tool (read-only vs destructive), per-tool rate
      limits, and an `/api/v1` prefix before the API surface freezes.
- [ ] Proxy: redact `Authorization`/`Cookie` in captured traffic by default.
- [ ] Scanner: host-side unknown-initial-value scan and "changed by more than N".
- [ ] Debugger: conditional breakpoints and hit-count/logging breakpoints.
- [ ] Encrypted-SELF strategy: document the partner-tooling flow or integrate
      payload-side decryption.
- [ ] Token policy: stop embedding the plaintext bearer token in MCP client configs
      by default; prompt-on-connect alternative.

## Following — v0.3 (P2)

- [ ] Multi-console manager (saved endpoints, quick-switch, per-console profiles)
      and automatic reconnect with backoff.
- [ ] Pointer-scan multi-level chains with per-level wildcards and negative offsets.
- [ ] CFG graph view in the UI; unify Hyperion/Zydis function detection.
- [ ] `.pdata`-based stack unwinding; thread-aware stepping parity.
- [ ] ARM64 emulation path for Mach-O/iOS images (Unicorn is x86-64 only today).
- [ ] PCAP _import_: analyze console traffic from a tap without routing
      it through the PC.
- [ ] `sessions.db` schema versioning/migrations.
- [ ] Decide the fate of the ImGui shell: ship it as a documented lightweight
      fallback or remove it; publish the parity matrix either way.
- [ ] Tutorial docs ("first console connect", "dump → rename → decompile") and a
      hosted docs site generated from `docs/`.
- [ ] Linux engine port (headless MCP server on an analysis VM): abstract
      `backend_usermode`, raw-socket capture, WinHTTP and the Tauri supervisor.
- [ ] Security CI: gitleaks + release-artifact import/section checks; document
      binary hardening flags.

## Later (P3, opportunistic)

- [ ] PS5 backend (the backend registry is shaped for a second console backend).
- [ ] Team workflows: self-hosted symbol/comment sharing or Git-based sync of
      `symbols/<hash>.json`.
- [ ] winget/choco/scoop packages + Tauri in-app updater.
- [ ] Unpacker view and a ReClass-style struct editor in the Tauri UI.
- [ ] Localization, user theme editor, script snippets library, Lua autocomplete.

Items are checked off as they land; the audit doc carries the full detail and
file-level pointers for each item.
