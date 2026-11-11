# Ecosystem merge plan

How the sibling projects fold into reverse-slop (PS4-Slop), what landed, and
what was deliberately left out.

Scope rule: everything merged here is for **hardware you own** — homebrew
payloads, your own debug builds, your own dumps. Anything whose purpose is
cheating in live online games, evading bans, or circumventing licensing is
not merged and will not be extended.

## Landed in this repo

| From | What landed | Where |
| --- | --- | --- |
| ps4debug-mcp | UDP broadcast discovery (`target.ps4_discover`, `host:"auto"`) | `src/core/mcp/tools_target.cpp`, `kBroadcastMagic/kBroadcastPort` in `src/core/runtime/ps4_protocol.hpp` |
| ps4debug-mcp | JSONL audit log on every MCP tool call (`mcp_audit_enabled`, `mcp_audit_path` settings) | `call_tool` wrapper in `src/core/mcp/mcp_tools.cpp` |
| ps4debug-mcp | `confirm:true` gate for mutating actions (`mcp_require_confirm` setting) | same wrapper; mutating set in `action_mutating()` |
| afterglow-web | `host` MCP tool: HTTP payload host with index page, `/files/<name>`, auto `/manifest.json` (sha256 per file), token required on non-loopback binds, `put` action | `src/core/mcp/tools_host.cpp` |
| ps4-injection-lab | Homebrew injection recipe book (userland methods only) | `docs/injection/README.md` |
| ps4debug-NG | Already the wire transport; fork extensions exposed as `ps4_*` actions | `src/core/runtime/backend_ps4.cpp` |
| PS4-MCP | Session broker (`broker_gate`, client registry) + GDB Remote Serial bridge (full RSP: threads, regs, memory, breakpoints/watchpoints, async stop replies) so the UI, MCP agents and a GDB client share one console connection | `src/core/runtime/broker.*`, `src/core/runtime/gdb_rsp.*`, `gdb` tool in `src/core/mcp/tools_gdb.cpp` |

## Still external (by design)

- **ps4debug-mcp** (Python client/CLI) stays a standalone companion client;
  its safety model is now also enforced server-side in this repo, so agents
  get the same guarantees through the built-in MCP server.
- **PS4-MCP** (Rust rmcp server) keeps the IDA/Ghidra/Binary Ninja adapters.
  Its session broker + GDB-RSP bridge (`src/rsp.rs`) is now ported into
  `src/core/runtime` (see above); next step is the adapters under
  `integrations/`.

## Explicitly not merged

- Apex/Fortnite PS4 cheat payloads and per-game cheat offsets (live online
  games; harms other players).
- HWID spoofing, kernel/DMA/Bluetooth-spoof injection methods, GoldHEN
  cheat XML — anti-cheat evasion and ban evasion.
- License-key generation / auth bypass and customer loaders.

If you want any of those, that's a hard no — not a configuration toggle.

## Settings added

| Key | Default | Meaning |
| --- | --- | --- |
| `mcp_audit_enabled` | `true` | append every MCP tool call to the audit log |
| `mcp_audit_path` | `%LOCALAPPDATA%\reverse-slop\mcp_audit.jsonl` | audit log location; empty disables |
| `mcp_require_confirm` | `false` | mutating console/target actions need `"confirm": true` |
| `host_token` | empty | bearer token required for non-loopback `host.start` binds |
