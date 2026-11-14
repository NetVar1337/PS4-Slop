# SlopStation

**PS4 reverse-engineering workbench** — live memory, scanning and debugging over
ps4debug-NG · static analysis of dumped modules · a decompiler and x86-64 emulator ·
Lua scripting · a built-in MCP server for AI agents.

![SlopStation workspace: host process list, value scanner and watchlist, disassembly of a loaded PE, inspector](screenshots/workspace.png)

SlopStation is a Windows workbench for PS4 reverse engineering and game research. It
speaks the [ps4debug-NG](https://github.com/Pharaoh2k/ps4debug-NG) wire protocol directly,
runs the same analysis stack against local Windows processes, and exposes everything —
live memory, the debugger, the scanner, the decompiler, the emulator, the network tools —
through one UI, one Lua surface and one MCP server.

> **Scope.** Use SlopStation only on consoles, games, and systems you own or are
> authorized to test. Live debugging and memory writes can crash the console or the game.
> Host-side packet capture needs administrator rights on the analysis PC. See
> [Security and qualification](project/security.md).

## Where to go next

| If you want to | Read |
| --- | --- |
| install the app and connect a console | [Install](getting-started/install.md), [Quick start](getting-started/quick-start.md) |
| follow a walkthrough | [Tutorials](tutorials/first-console-connect.md) |
| know what each area does | [Feature map](features/overview.md) |
| drive it from an AI agent or a script | [MCP and HTTP endpoints](api/README.md), [Lua scripting](features/lua.md) |
| build it from source | [Building](project/building.md) |
| load your own code on the console | [Injection recipes](injection/README.md) |

Screenshots on these pages were captured from the real UI against the bundled
[`SlopTarget`](https://github.com/NetVar1337/SlopStation/tree/main/src/target) fixture over
the local user-mode backend — every address and value is genuine runtime data. Console-only
views are shown in their waiting state.
