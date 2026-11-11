# Lua examples

Scripts for reverse-slop's Lua 5.4 engine (API reference: the header comment of
`src/core/script/lua_engine.hpp` and the README's "Lua scripting" section).
They run against the same session as the UI: the attached process (PS4 console
or local), the loaded image, renames and comments.

| Script | Needs | What it does |
|---|---|---|
| `ps4_find_value.lua` | PS4 with ps4debug-NG | Connects, attaches to a game process, scans for a 32-bit value and narrows the hits while you change the value in-game. |
| `ps4_breakpoint_trace.lua` | PS4 with ps4debug-NG | Sets a software breakpoint, waits for the hit, prints registers and the call stack, then removes the breakpoint and resumes. |
| `ps4_eboot_overview.lua` | a dumped `eboot.bin` / module (ELF) | Loads the image, waits for analysis, lists the largest functions and the code referencing interesting strings. |
| `ue5_dumper.lua` | a process running an Unreal Engine 5.x x64 build (PS4 or PC) | Walks `GObjects`/`GNames` and dumps classes, properties and functions (Dumpspace-style `ClassesInfo.json` + `FNames.txt`). |

## Running

- **Scripts panel**: open the script, edit the `ARGS` table at the top, `Ctrl+Enter`.
- **MCP**: `script` tool, `action=run`, `code=<file contents>`, `timeout_ms` as needed.
  The engine caps a single run (see the `script` tool description); on big games
  lower the dumper's `max_objects` if a run hits the cap.
- **`/api`**: same `script.run` action.

### Parameters

Every example starts with

```lua
ARGS = ARGS or { ... defaults ... }
```

so a caller can prepend its own table instead of editing the file, e.g. over MCP:

```text
code = 'ARGS = { host = "192.168.1.50", process = "eboot.bin", value = 100 }\n' .. <file contents>
```

Unset fields fall back to the defaults shown in each script.

### Sandbox

Scripts run sandboxed by default: no `io`, no `os` (except `os.clock`/`os.time`/
`os.difftime`), no `require`/`package`/`debug`. Results come back through `print()`
and the script's return value. Only `ue5_dumper.lua` writes files, and only when
`ARGS.output_dir` is set **and** the `script_unsafe` setting is enabled
(`app.settings_set {key:"script_unsafe", value:true}` or the Settings dialog);
otherwise it prints the dump instead.

### Addresses

Values like `0x...` are console (or process) virtual addresses. PS4 is x86-64;
game data usually lives above `0x200000000`. Find candidates with the scanner,
`ps4_find_value.lua` or the module list (`target` tool, `action=modules`).
