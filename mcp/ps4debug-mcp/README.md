# ps4debug-mcp

[MCP](https://modelcontextprotocol.io) server + Python client for the
[ps4debug-NG](https://github.com/Pharaoh2k/ps4debug-NG) payload on jailbroken
PS4 consoles. Lets an AI agent (Claude, Cursor, pi, ...) do dynamic reverse
engineering of PS4 games over the payload's TCP protocol: disassembly, AoB
scans, xrefs, breakpoints/watchpoints, register inspection, memory R/W,
kernel R/W — everything the payload can do.

## Install

```sh
pip install .          # or: pip install -e .[test]
```

Requires Python 3.10+. The console must be running the ps4debug-NG payload
(see the payload repo for installation; any 5.05–14.02 firmware).

## Use as an MCP server (AI agents)

Stdio transport — add to your MCP client config:

```json
{
  "mcpServers": {
    "ps4debug": {
      "command": "ps4debug-mcp"
    }
  }
}
```

(Claude Desktop: Settings → Developer → Edit Config; Cursor: `.cursor/mcp.json`.)

Then in the agent: "connect to the PS4" → it calls `ps4_connect` (auto-discovers
the console via UDP broadcast), "list processes", "attach to the game",
"find what writes the health address" (watchpoint), "scan for the ammo value",
"disassemble that function and find its xrefs", ...

### Safety model

- Read-only tools work directly.
- **Every mutating tool requires `confirm=True`** — the tool refuses otherwise,
  so the agent must ask you before writing memory, setting breakpoints,
  continuing execution, or touching the kernel.
- Every console-reaching call is appended to a JSONL audit log
  (`PS4DEBUG_AUDIT_LOG` env var; default `./ps4debug_audit.jsonl`) so you can
  replay exactly what the agent did.

## Use as a Python library

```python
from ps4debug_ng import Ps4DebugClient

with Ps4DebugClient.discover() as host, Ps4DebugClient(host) as dbg:
    print(dbg.server_info())
    pid = next(p["pid"] for p in dbg.list_processes() if "Game" in p["name"])
    regions = dbg.list_regions(pid)
    hits = dbg.scan_aob(pid, 0, 0x7FFF00000000,
                        bytes.fromhex("488B05CCCCCCCC"), regions=regions)
    print([hex(h) for h in hits])
```

## Tool surface (58 tools)

| Group | Tools |
|---|---|
| Connection | `ps4_discover`, `ps4_connect`, `ps4_disconnect`, `ps4_server_info` |
| Processes | `ps4_list_processes`, `ps4_process_info`, `ps4_list_regions` |
| Memory | `ps4_read_memory`, `ps4_write_memory` (confirm) |
| RE | `ps4_disassemble`, `ps4_assemble`, `ps4_code_targets`, `ps4_find_xrefs`, `ps4_read_stack`, `ps4_scan_aob` |
| Debug | `ps4_attach`, `ps4_detach` (confirm), `ps4_wait_event`, `ps4_set_breakpoint` (confirm), `ps4_set_watchpoint` (confirm), `ps4_list_threads`, `ps4_thread_info`, `ps4_suspend_thread`/`ps4_resume_thread` (confirm), `ps4_get_registers`, `ps4_set_registers` (confirm), `ps4_get_debug_registers`, `ps4_get_fsgsbase`, `ps4_continue` (confirm), `ps4_step`/`ps4_step_thread` (confirm), `ps4_stop_process` (confirm) |
| Kernel | `ps4_kernel_base`, `ps4_kernel_read`, `ps4_kernel_write` (confirm) |
| Console | `ps4_notify` (confirm) |
| Modules | `ps4_list_modules`, `ps4_module_imports`, `ps4_module_exports` (ELF parsed live from memory) |
| Pointer scan | `ps4_find_pointer_chains` (CE-style reverse scan), `ps4_pointer_rescan` (revalidate after restart) |
| Snapshots/integrity | `ps4_snapshot_save`, `ps4_snapshot_diff`, `ps4_memory_hash`, `ps4_integrity_check` |
| Tracing | `ps4_trace_calls` (breakpoint + auto-continue register capture), `ps4_find_what_writes` (watchpoint writer capture) |
| Execution | `ps4_install_stub`, `ps4_call_function` (RPC into the target), `ps4_protect`, `ps4_load_elf` |
| Freeze | `ps4_freeze_start`/`ps4_freeze_stop`/`ps4_freeze_list` (CE-style poke loop) |
| Cheat/replay | `ps4_cheat_export`/`ps4_cheat_import`/`ps4_cheat_apply` (ps4cheat v1 JSON), `ps4_replay_audit` (re-apply audit-log actions) |

Notes:
- Scans run client-side over `proc_read`, so they need no scan auth
  (PROTOCOL.md §1.8). For big regions the payload's server-side turbo scan is
  faster, but requires the undocumented auth handshake.
- Debug events (breakpoint hits etc.) arrive on TCP port 755; the client
  listens automatically while attached.
- Tested against the protocol documented in the payload's PROTOCOL.md; wire
  layouts unchanged by ps4debug-NG PR #2 (hardening limits only reject
  malformed input).

## Web UI

```sh
python -m ps4debug_ng.ui          # http://127.0.0.1:8337
```

x64dbg-style single-page app: live hex memory view, disasm + registers +
call stack, breakpoints/watchpoints (pause triggers) with a pause log
(disasm+stack trace per pause), pointer scanner with restart revalidation,
and a memory-integrity monitor. Every mutating action asks for confirmation
in the browser before it reaches the console.

## CLI / REPL

```sh
python -m ps4debug_ng.cli [host]  # then: help
```

Interactive shell over the same client library: `procs`, `use`, `regions`,
`modules`, `imports`/`exports`, `read`/`write`, `scan aob|value`, `chains`/
`rescan`, `attach`, `break`/`watch`, `cont`/`step`, `regs`/`stack`,
`whatwrites`, `install`/`call` (RPC), `protect`, `loadelf`, `freeze`,
`snapshot save|diff`, `cheat apply`, `notify`. Mutations ask for
confirmation (or `--yes`).

## Development

```sh
pip install -e .[test]
pytest
```

## License

GPL-3.0-only, matching the ps4debug-NG payload.
