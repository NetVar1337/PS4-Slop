# PS5 console backend (ps5debug-NG)

SlopStation can drive a jailbroken PS5 running the **ps5debug-NG** payload the
same way it drives a local process: process list, attach, memory read/write,
VM maps, module list, live debugging (breakpoints, watchpoints, registers,
continue/step) and console notifications.

## Protocol source

Implemented against **ps5debug-NG v1.3.2**:

- repository: <https://github.com/Pharaoh2k/ps5debug-NG>
- commit: `a1a6cb2dae7544f892454f62046b7f70500ffa8e` (2026-10-22)
- references: `common/include/protocol.h` and `PROTOCOL.md`

ps5debug-NG descends from golden's ps4debug, so the framing is identical to
ps4debug-NG's: a 12-byte `{magic, cmd, datalen}` header (`magic =
0xFFAABBCC`) followed by `datalen` raw body bytes, every field little-endian
and every struct packed. The vm_map entry (58 bytes) and the port-755 stop
packet (0x4A0 bytes) are byte-identical to ps4debug's, which is why the
backend reuses the PS4 segment/module grouping and stop-event decoder.

Differences from the PS4 backend that matter:

| Topic | ps5debug-NG |
|-------|-------------|
| Status words | bit-swapped on the wire; the client compares `CMD_SUCCESS = 0x80000000`, `CMD_ERROR = 0xF0000001`, `CMD_DATA_NULL = 0xF0000003`, `CMD_ALREADY_DEBUG = 0xF0000004`, `CMD_INVALID_INDEX = 0xF0000005` |
| Read/write streaming | 64 KiB chunks (`NET_MAX_LENGTH` is 8192 payload-side) |
| `CMD_DEBUG_ATTACH` body | 4 bytes (`pid` only; the payload takes the client IP from the connection slot) |
| Module list | none server-side: modules are grouped from `CMD_PROC_MAPS` by backing file |
| Unknown opcode | `CMD_ERROR` **and the payload closes the client**, so the backend never probes for commands it does not need |
| Auth | `CMD_PROC_AUTH` only gates the on-console scan trio; this backend does not use those commands (the generic scanner reads memory instead), so no auth handshake is performed |
| Watchpoint length | the payload wants the DR7 length field (0=1, 1=2, 2=8, 3=4 bytes), not a byte count; the backend converts |

## Ports

| Port | Proto | Direction | Purpose |
|------|-------|-----------|---------|
| 744 | TCP | PC → console | command server (`target.ps5_connect`) |
| 755 | TCP | console → PC | stop events; the backend listens and pins the peer to the console it attached to |
| 1010 | UDP | broadcast | discovery (`host: "auto"`), magic `0xFFFFAAAA` |

## Commands used

| Command | ID | Backend use |
|---------|----|-------------|
| `CMD_VERSION` | `0xBD000001` | handshake: protocol version string |
| `CMD_FW_VERSION` | `0xBD000500` | handshake: firmware as `major*100+minor` (900 = 9.00) |
| `CMD_BRANDING` | `0xBD000501` | handshake: brand + `NUL` + capability level |
| `CMD_PLATFORM_ID` | `0xBD000502` | handshake: must answer 5 (PS5), else the connect is refused |
| `CMD_PROC_NOP` | `0xBDAACC06` | `ping()` and the handshake liveness probe |
| `CMD_PROC_LIST` | `0xBDAA0001` | `target.list` |
| `CMD_PROC_INFO` | `0xBDAA000A` | attach validation, name/path |
| `CMD_PROC_READ` / `CMD_PROC_WRITE` | `0xBDAA0002/3` | `memory.read`/`memory.write` and the generic scanner |
| `CMD_PROC_MAPS` | `0xBDAA0004` | `target.regions`, `target.modules`, read-coverage checks |
| `CMD_PROC_PROTECT` | `0xBDAA0008` | `memory.protect` |
| `CMD_PROC_ALLOC` / `CMD_PROC_ALLOC_HINTED` / `CMD_PROC_FREE` | `0xBDAA000B/0E/0C` | `memory.alloc`/`memory.free` |
| `CMD_DEBUG_ATTACH` / `CMD_DEBUG_DETACH` | `0xBDBB0001/2` | `debugger.ps5_attach`/`ps5_detach` |
| `CMD_DEBUG_SET_BREAKPOINT` / `CMD_DEBUG_SET_WATCHPOINT` | `0xBDBB0003/4` | `ps5_bp_set`/`ps5_watch_set` (30 software / 4 hardware slots) |
| `CMD_DEBUG_GET_THREAD_LIST` / `CMD_DEBUG_THREAD_INFO` | `0xBDBB0005/11` | `target.threads`, `debugger.ps5_threads` |
| `CMD_DEBUG_GETREGS` / `CMD_DEBUG_SETREGS` | `0xBDBB0008/9` | `ps5_regs`, `ps5_set_reg` |
| `CMD_DEBUG_CONTINUE` / `CMD_DEBUG_STEP` / `CMD_DEBUG_STEP_THREAD` | `0xBDBB0010/12/13` | `ps5_continue`, `ps5_step` |
| `CMD_DEBUG_SUSPEND` / `CMD_DEBUG_RESUME` | `0xBDBB0006/7` | `ps5_suspend`/`ps5_resume` |
| `CMD_CONSOLE_NOTIFY` / `CMD_CONSOLE_PRINT` | `0xBDDD0004/3` | `target.ps5_notify`, `debugger.ps5_print` |
| `CMD_CONSOLE_INFO` / `CMD_CONSOLE_FOREGROUND_APP` | `0xBDDD0005/6` | `ps5_console_info`, `ps5_app` |

## MCP surface

`target`:

- `ps5_connect {host, port=744, pid?}` — handshake + optional attach; `host:
  "auto"` uses the UDP discovery probe.
- `ps5_disconnect`, `ps5_reconnect` (re-handshake, re-attach the debuggee,
  re-arm every breakpoint/watchpoint), `ps5_auto {host}` (connect, pick the
  process whose maps live under `/app0/`, attach, debug-attach),
  `ps5_notify {msg}`.
- `status` adds a `ps5` block (endpoint, branding, server version, caps, fw,
  platform, connected/lost, drops, debug state).
- `list`, `attach`, `modules`, `regions`, `threads`, `memory.*`, `disasm.*`,
  `memory.scan`/`aob` work through the backend abstraction unchanged once a
  PS5 is the active backend.

`debugger`:

- `ps5_status`, `ps5_attach`, `ps5_detach`, `ps5_console_info`,
  `ps5_bp_set`/`ps5_bp_clear`/`ps5_bp_list`,
  `ps5_watch_set`/`ps5_watch_clear`/`ps5_watch_list`,
  `ps5_continue`, `ps5_step`, `ps5_suspend`, `ps5_resume`, `ps5_regs`,
  `ps5_set_reg`, `ps5_threads`, `ps5_wait`, `ps5_events`, `ps5_notify`,
  `ps5_print`, `ps5_app`.

## Limits

- **No on-console scan engine.** ps5debug-NG's `CMD_PROC_SCAN*` family needs
  the `CMD_PROC_AUTH` challenge-response and only accepts four-byte-relative
  result offsets; this backend does not implement it. `memory.scan`, `aob`
  and pointer scans stream memory over the wire instead (correct, slower).
  `engine=console` is therefore rejected for PS5.
- **No remote function call / ELF upload / on-device disasm / snapshot.**
  Those ps4debug-NG commands are not part of the ps5debug-NG v1.3.2 surface
  this backend targets (it deliberately does not probe unknown opcodes, since
  the payload closes the client on one).
- **No `target.ps5_dump_module`.** `target.dump_module` is PE-only; dump PS5
  modules with `memory.read` over the `target.modules` ranges (or wait for a
  follow-up slice).
- **Threads need a debug session.** The payload only lists lwpids while
  attached, so `target.threads` on a PS5 fails with "no ps5 debug session"
  until `debugger.ps5_attach`.
- **One console at a time.** Connecting a PS5 drops a selected PS4 and vice
  versa; the registry swaps the active backend and detaches the session first.
- **A failed command usually drops the connection** (the payload closes the
  client on handler failure). The backend then reports `connected=false`,
  `lost=true` and a reason; `target.ps5_reconnect` re-runs the handshake,
  re-attaches the debuggee and re-arms the slots. There is no transparent
  reconnect: unlike the PS4 backend, the next call fails fast instead of
  re-opening behind the caller's back.
- Firmware coverage is whatever ps5debug-NG v1.3.2 supports (the payload does
  its own firmware-specific kernel work); the backend only reports the
  firmware number it announces.

## Tests

`src/tests/test_ps5.cpp` runs against `src/tests/ps5_fixture.hpp`, a fake
ps5debug-NG payload on loopback TCP that implements the command subset above,
the port-755 connect-back and fault injection (fragmented replies, a byte
budget that cuts the connection mid-reply, a silent command, a non-status
word). Areas: `SLOP_TEST_AREA=ps5`.
