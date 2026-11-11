# PS4-MCP analyzer adapters (ported into PS4-Slop)

The IDA / Ghidra / Binary Ninja / iaito adapters from PS4-MCP, rewired to
PS4-Slop's **built-in MCP server** instead of the Rust broker's custom `/rpc`
protocol.

```
integrations/ps4-mcp-adapters/
├── ps4_mcp/                  adapter package (from PS4-MCP, unchanged logic)
│   ├── client.py             NEW: BrokerClient shim speaking MCP JSON-RPC to
│   │                         http://127.0.0.1:8765/mcp (PS4-Slop's server)
│   ├── config.py             validation helpers (verbatim)
│   ├── agents.py             analyzer-side analysis worker (verbatim)
│   └── adapters/             base/ida/ghidra/binja/iaito (verbatim)
└── scripts/
    ├── ida/ps4_connect.py        run inside IDA's Python
    ├── ghidra/ps4_connect.py     Ghidra script (Python); PS4Mcp.java +
    │                             ApplyWorkbenchAnnotation.java are the upstream
    │                             Java plugin — they still target the PS4-MCP
    │                             /rpc broker and are kept for reference
    ├── binja/ps4_connect.py      run inside Binary Ninja's Python
    ├── iaito/ps4_connect.py      run with r2/iaito (r2pipe)
    └── live/start-live.ps1       start the engine + GDB-RSP bridge
```

## Wiring

PS4-Slop's engine already serves MCP on `127.0.0.1:8765` (`POST /mcp`,
JSON-RPC 2.0). The shim in `ps4_mcp/client.py` keeps the `BrokerClient`
interface the adapters were written against and maps the broker operations
onto PS4-Slop tools:

| PS4-MCP broker op   | PS4-Slop MCP tool.action | Notes |
| ------------------- | ------------------------ | ----- |
| `state`             | `target.status`          | synthesized broker-state view |
| `events`            | `debugger.ps4_events`    | console stop-event drain |
| `release`           | local no-op              |       |
| `memory_peek`       | `memory.read`            | live console read, hex out |
| `process_maps`      | `target.regions` (+`modules` for names) | `start/end/name/protection` shape |
| `ftp_download`      | `target.ps4_dump_module` | dumps a module over ps4debug-NG to a local file, sha256 reported |
| `payload_execute`   | `debugger.ps4_elf_load`  | homebrew ELF payload; client-side sha256 verified first |
| `agent_register/poll/result/unregister` | local no-ops | PS4-Slop runs analysis agents through its own MCP loop; `agent_poll` returns `None` |

Environment for the connect scripts: `PS4_SLOP_URL` (default
`http://127.0.0.1:8765`), `PS4_SLOP_ROOT` (adapter root, default is this
checkout). No broker token is needed — PS4-Slop's MCP server is loopback-only
by default; the shim sends `Authorization` only if a token file is passed.

## Console + live debugging

1. Start the engine: `tools/build.ps1 -NoFrontend` then run
   `build/src/engine/reverse-slop-engine.exe` (or just the app).
2. Attach the console from the UI, or via MCP: `target.ps4_connect {host,
   port=744, pid}` / `target.ps4_auto {host}` then `debugger.ps4_attach {pid}`.
3. Open the GDB Remote bridge so an external GDB/LLDB can share the session:
   `gdb` tool `start` (loopback only, `allow_writes` opt-in), then
   `gdb -ex 'target remote 127.0.0.1:2331'`. The UI, MCP agents and the GDB
   client serialize on one console connection through the session broker
   (`src/core/runtime/broker.*`).

## Scope

Only dev-tooling surface was ported. PS4-MCP's game-project authoring
(`games.rs` and friends) and anything cheat-oriented stays out, per
`docs/MERGE.md`.
