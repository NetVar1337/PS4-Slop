# Tutorial: a local process, no console

Everything in SlopStation except the `ps4_*` actions works against a **local Windows
process** through the user-mode backend (`OpenProcess` / `ReadProcessMemory` /
`WriteProcessMemory`). That is how the test fixture and the screenshots are driven, and it
is the fastest way to learn the scanner and the debugger without a console on the desk.

The bundled fixture is `SlopTarget.exe` (`src/target`), built by
`powershell -File tools/build.ps1 -NoFrontend` into `build/src/app/SlopTarget.exe`.

## 1. Start a target

```powershell
.\build\src\app\SlopTarget.exe
```

It prints its PID and the addresses of its known values (`values.health`, `values.score`,
`values.speed`, `values.gold`, …) and then waits on stdin:

```
commands: tick, auto <hz>, stop, set <name> <val>, inc <name>, dec <name>,
          mutate, realloc, report, regions, quit
>
```

`auto 2` makes it tick twice a second: health decreases, score increases by 10, speed
drifts by 0.01. That gives the scanner something to narrow against.

Any other process works too — a game, a debug build of your own code. The backend needs
`PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION`
on it, so same-user processes are fine and protected/elevated ones need an elevated
SlopStation.

## 2. Attach

In **Targets**, click **“List this PC's processes instead”**. The panel title becomes
**Host processes (this PC)** and lists PID / Name / Arch / Action with a filter box
(**Filter processes…**). Find `SlopTarget.exe` and attach it.

![Targets panel listing host processes](../screenshots/workspace.png)

The same from an agent:

```json
{ "tool": "target", "action": "list", "params": {} }
{ "tool": "target", "action": "attach", "params": { "pid": 12345 } }
```

`list` returns up to 4096 processes with `pid`, `name`, `arch`, `path` and `elevation`;
filter client-side. `attach` also loads the process's main module into the image session
when nothing is loaded, so the Disassembly tab has something to show
(`image_auto_loaded` in the reply).

## 3. Scan for a value

The **Scanner** panel is the Cheat-Engine flow:

1. Pick a width (`u32`, `f32`, `u64`, …) and a scan kind (`exact`, `between`, `changed`,
   `increased`, `decreased`, …).
2. Type the current value and press **First**.
3. Change the value in the target (`set health 87` in the SlopTarget console, or just let
   `auto` tick), type the new value, press **Next** until a handful of hits remain.
4. Add a hit to the watchlist with the **Add to watchlist** button on its row.

From an agent:

```json
{ "tool": "memory", "action": "scan",
  "params": { "kind": "exact", "width": "u32", "value": 100 } }
{ "tool": "memory", "action": "rescan",
  "params": { "kind": "decreased", "width": "u32" } }
{ "tool": "memory", "action": "watch_add",
  "params": { "addr": "0x7FF6A1B2C3D4", "width": "u32", "label": "player.health" } }
```

`scan` returns hits with addresses and values; `rescan` narrows the same scan state.
`scan_state` reports whether a scan is live, `scan_reset` clears it.

## 4. Freeze it

The **Watchlist** table has a **Freeze** column. Toggling it makes the watch service write
the captured value back about 10 times a second. `*` next to a value means the entry is
frozen.

```json
{ "tool": "memory", "action": "watch_set",
  "params": { "id": 1, "freeze": true } }
{ "tool": "memory", "action": "watch_freeze_once", "params": { "id": 1 } }
{ "tool": "memory", "action": "watch_undo", "params": { "id": 1 } }
```

`watch_freeze_once` releases after the first write-back; `watch_undo` restores the value
captured when the entry was added. The SlopTarget fixture prints
`[!] frozen_probe is N (external freeze detected)` when a freeze is visible from the
target's side — a cheap way to prove the write actually landed.

## 5. Find what writes the address

This is where the local debugger comes in. The four one-shot composite flows
(`ps4_until`, `ps4_find_write`, `ps4_trace_calls`, `ps4_trace_steps`) run on the **local
Win32 debugger** whenever the attached session is a local process — the `ps4_` prefix is
just the historical name, the reply carries `"debugger": "user"`.

```json
{ "tool": "debugger", "action": "ps4_find_write",
  "params": { "addr": "0x7FF6A1B2C3D4", "len": 4, "timeout_ms": 10000 } }
```

The flow: arm a hardware write watchpoint on the address, resume the process, wait for the
trap, then walk the stack of the thread that wrote. The reply contains `halted`, the stop
`event` (registers), `callstack`, `writer_rip` and `writer_rip_hex`. If nothing writes in
time, `halted` is false and the process is left running.

Related one-shots:

| Action | What it does locally |
| --- | --- |
| `ps4_until {addr, timeout_ms}` | run until an address is hit, one-shot breakpoint |
| `ps4_trace_calls {addr, count, timeout_ms}` | log the 6 argument registers at each call to `addr` |
| `ps4_trace_steps {lwpid, count, timeout_ms}` | single-step trace with disassembly per step |
| `ps4_detach` | detach the local debugger (the process keeps running) |

`debugger.status` reports the local debugger as
`local_debugger: { attached, pid, stopped }` alongside the PS4 fields.

The local debugger attaches with `DebugActiveProcess`, so it needs the same access rights
as the backend, and a process that already has a debugger cannot be attached again. It
never kills the target on exit (`DebugSetProcessKillOnExit(FALSE)`).

## What does not work without a console

`ps4_attach`, `ps4_bp_set`, `ps4_watch_set`, `ps4_continue`, `ps4_regs`, `ps4_call`,
`ps4_scan*`, `ps4_turbo_*`, `ps4_dump_module` and the rest of the console surface need a
connected PS4 — they talk to the payload, not to Windows. Static analysis, the decompiler,
the emulator, Lua, the network tools and the scanner/watchlist all work locally.

## 6. Keep going

- [Live memory](../features/live-memory.md) — scan kinds, AOB, pointer chains, snapshots.
- [Live debugging](../features/live-debugging.md) — the console debugger for comparison.
- [Tests](../project/tests.md) — how the fixture and the fake ps4debug server are used in CI.
