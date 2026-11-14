# The ImGui shell

**Decision: keep it, as a documented lightweight fallback — not as a second product.**

The Tauri v2 + React app is the shell that ships: it is what the installer installs, what
the updater updates, what the screenshots show and what the e2e driver drives. The legacy
ImGui/DX11 shell (`src/app` + `src/ui`) stays in the tree because it is cheap to keep
compiling (it is part of the same CMake build and the same CI lane) and it is useful when:

- you want the workbench **without WebView2, Node or Rust** — a plain Win32 binary that
  links the same `slop_core`;
- you are debugging the core itself and want a shell with no IPC boundary;
- you need the **Magicmida unpacker UI**, which only exists there today.

It is not a supported end-user surface: no auto-update, no MCP client onboarding, no
settings UI, no Lua panel. Do not add features to it that the Tauri app lacks unless the
feature is the reason it exists (the unpacker).

## Building it

The shell is a normal CMake target and is on by default:

```powershell
powershell -File tools/build.ps1 -NoFrontend          # builds build\src\app\reverse-slop.exe
```

To build **only** the shell (no engine host, no tests):

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release `
      -DSLOP_BUILD_UI=ON -DSLOP_BUILD_ENGINE=OFF -DSLOP_BUILD_TESTS=OFF
cmake --build build --target reverse-slop
```

`SLOP_BUILD_UI=ON` is the default; `-DSLOP_BUILD_UI=OFF` drops `src/ui` and `src/app` from
the build entirely (CI builds the engine and the Tauri app, so the shell only has to keep
compiling).

Output: `build\src\app\reverse-slop.exe`.

## Views

Registered in `src/ui/panels.cpp` (`RegisterBuiltins`), with these shortcuts:

| View | Shortcut | Notes |
| --- | --- | --- |
| Targets | `Ctrl+1` | process list, attach, PS4 connect |
| Inspector | `Ctrl+2` | placeholder in this shell (the Tauri app has the real one) |
| Disassembly | `Ctrl+3` | function list + instruction view |
| Pseudocode | `Ctrl+0` | decompiler output with jump-back navigation |
| Memory | `Ctrl+4` | regions + hex editor |
| Output | `Ctrl+5` | engine log |
| Scanner | `Ctrl+6` | value scanner |
| Strings | `Ctrl+7` | string index |
| Image Browser | `Ctrl+8` | sections/imports/exports |
| Debugger | `Ctrl+9` | PS4 breakpoints, watchpoints, registers, events, remote calls |
| Unpacker | — | Magicmida job UI (hidden by default) |
| Frame Metrics | `F12` | ImGui draw stats (debug) |

Plus a command palette (`src/ui/command_palette.cpp`), docking and three themes
(Obsidian, Nord-slop, Blood-orange).

## Feature parity

Derived from `src/ui/panels.cpp` + `src/ui/view_*.cpp` versus
`app/src/components/**` (ActivityRail, WorkspacePanel tabs, panels/). "MCP" means the
feature is reachable from the Tauri app through an agent or `/api`, not through its own
widget.

| Feature | ImGui shell | Tauri app | Gap |
| --- | --- | --- | --- |
| Targets / attach | yes | yes | — |
| PS4 connect + payload card | connect popup only | full card (send/save/check/download) | ImGui has no payload card |
| Modules list | yes (table inside Targets, with dump + analyze) | **Modules** panel | — |
| Inspector | placeholder text | full inspector | ImGui inspector is a stub |
| Scanner | yes | yes | — |
| Watchlist + freeze | yes | yes | — |
| Memory / hex editor | yes | yes | — |
| Disassembly | yes | yes | — |
| Strings | yes | yes | — |
| Image Browser (PE) | yes | yes | — |
| Decompiler (pseudocode) | **yes** (Pseudocode view) | no widget (MCP `decomp.function` / Lua) | Tauri has no pseudocode pane |
| Debugger (PS4) | yes | yes | — |
| Local debugger composites | no widget | no widget | both are MCP-only |
| Xray / patch / devirt / emulate | no widget | no widget | MCP-only on both |
| Magicmida unpacker | **yes** (Unpacker view) | no widget (MCP `devirt.themida_*`) | Tauri has no unpacker UI |
| Lua scripts | no | **yes** (Scripts panel) | ImGui has no script surface |
| Command palette | yes | yes (`Ctrl+K`) | — |
| Output panel | yes | yes | — |
| Settings UI | no (edit `settings.json`) | **yes** (Settings modal) | ImGui has no settings UI |
| MCP token rotation | no | yes | ImGui has no settings UI |
| Auto-update | no | **yes** (Tauri updater) | ImGui has no updater |
| MCP client onboarding | no | yes (engine-side, shared) | the engine does it for both |
| Themes | 3 | 5 (+Daylight, High contrast) | ImGui has no light theme |
| Frame metrics | yes (`F12`) | no | debug-only |
| E2E / screenshots | no | yes (`app/e2e`) | screenshots come from the Tauri UI |

The two "Tauri lacks it" rows are the honest ones: the pseudocode pane and the unpacker UI
exist only in the ImGui shell. Both are reachable in the Tauri app through MCP, so no
capability is lost — only a widget.
