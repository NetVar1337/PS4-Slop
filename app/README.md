# reverse-slop UI (`app/`)

The desktop front end of reverse-slop: a React 18 + TypeScript single-page app
rendered by a Tauri v2 shell (`src-tauri/`). It has no business logic of its
own; every button drives the same engine tool actions an AI agent uses over
MCP, so whatever the UI does an agent can do, and vice versa.

```
┌──────────── Tauri shell (src-tauri) ─────────────┐
│ spawns reverse-slop-engine, supervises/restarts  │
│ it, hands the UI {port, token} via IPC           │
└───────────────┬──────────────────────────────────┘
                │ engine_endpoint / engine-crashed / engine-restarted
┌───────────────▼──────────────┐   POST /api  (bearer token)   ┌─────────────────────┐
│ React UI (this directory)    │ ─────────────────────────────▶│ reverse-slop-engine │
│ zustand stores ◀── events ───│ ◀──── GET /events?ticket=… ───│ 127.0.0.1:<port>    │
└──────────────────────────────┘        (server-sent events)   └─────────────────────┘
```

## Architecture

- **Transport** (`src/lib/rpc.ts`): `call(tool, action, params)` posts
  `{tool, action, params}` to `/api` and returns `data` or throws `ToolError`.
  Every request has a deadline (30 s default, longer for scans/dumps) so a
  wedged engine surfaces as a `TimeoutError` instead of a stuck spinner.
  `batch()` sends several actions in one round trip (the debugger view
  refreshes with one).
- **Events** (`src/lib/events.ts`): one `EventSource` on `/events`. With a
  token-protected engine the UI first asks `app.events_ticket` for a
  single-use, 60 s ticket and connects with `?ticket=`; the bearer token never
  appears in a URL. Drops reconnect with backoff (and, in the shell,
  re-resolve the endpoint first, a restarted engine may have a new port).
- **Stores** (`src/store/*`): zustand stores mirror engine state. Nothing polls
  except the Log tab: `target.changed`, `backend.changed`, `image.changed`,
  `hype.progress`, `watch.*` and `output` events keep them current, and every
  stream (re)open re-seeds them from `app.status`. A binary loaded or a process
  attached by an agent therefore shows up in the UI immediately.
- **Endpoint** (`src/lib/endpoint.ts`): in the shell the endpoint comes from
  the supervisor (`engine_endpoint`, blocking during a restart); startup waits
  for `/health` up to the supervisor's `startup_deadline_ms` (180 s, it covers
  the UAC prompt). Crash/restart events drive the Retry banner.
- **Layout** (`src/store/ui.ts`): rail, tabs, inspector visibility and
  splitter sizes persist in `localStorage` (`reverse-slop.layout`).

### Views

| View            | File                            | Purpose                                                                               |
| --------------- | ------------------------------- | ------------------------------------------------------------------------------------- |
| Title bar       | `components/TitleBar.tsx`       | Menus (File/View/Window/Theme/Help), window buttons, insecure-dev badge               |
| Command palette | `components/CommandPalette.tsx` | Ctrl+K: jump to a function (server-side search) or address, switch views, run actions |
| Splash          | `components/Splash.tsx`         | Boot stages as the engine reports them, Retry on failure                              |
| Activity rail   | `components/ActivityRail.tsx`   | Targets / Modules / Scripts + Settings                                                |
| Targets         | `panels/TargetsPanel.tsx`       | Connect a PS4 (ps4debug-NG); console process list, attach/detach                      |
| Modules         | `panels/ModulesPanel.tsx`       | Modules of the attached process, dump + analyze                                       |
| Scripts         | `panels/ScriptsPanel.tsx`       | Lua scratchpad over `script.run`                                                      |
| Scanner         | `panels/ScannerPanel.tsx`       | Value scanner and watchlist (labels, freeze, poke)                                    |
| Disassembly     | `panels/DisassemblyView.tsx`    | Paged, server-filtered function list + listing                                        |
| Strings         | `panels/StringsView.tsx`        | String hits with xref-follow                                                          |
| Memory          | `panels/MemoryView.tsx`         | Region list + continuously scrolling hex editor                                       |
| Debugger        | `panels/DebuggerView.tsx`       | PS4 live debug: run control, regs, callstack, bp/wp, on-console scan                  |
| Image browser   | `panels/PeView.tsx`             | ELF/SELF/PE/Mach-O sections, imports, exports                                         |
| Output / Log    | `panels/OutputPanel.tsx`        | Engine output ring (streamed) and diag log (polled)                                   |
| Inspector       | `panels/InspectorPanel.tsx`     | Facts about the target and image                                                      |
| Settings        | `components/SettingsModal.tsx`  | Theme, motion, engine endpoints, MCP token, engine policy settings                    |

### Keyboard

| Keys                                   | Action                                                    |
| -------------------------------------- | --------------------------------------------------------- |
| Ctrl+K, Ctrl+Shift+P, Ctrl+G           | Command palette                                           |
| Ctrl+O                                 | Open binary                                               |
| Ctrl+,                                 | Settings                                                  |
| Ctrl+1 … Ctrl+5                        | Disassembly / Strings / Memory / Debugger / Image browser |
| Ctrl+Alt+I                             | Toggle inspector                                          |
| Arrow keys on a focused splitter       | Resize (Shift = larger steps, Home/End = min/max)         |
| Arrow keys / Home / End in a tab strip | Switch tab                                                |

Themes: Obsidian, Nord-slop, Blood-orange (dark), Daylight (light) and High
contrast. On first run the OS `prefers-contrast` / `prefers-color-scheme`
picks between them. Motion defaults to "Auto" (follows the OS reduced-motion
setting).

## Running

Prerequisites: Node 20+, and for the shell a Rust toolchain plus a built
engine (`reverse-slop-engine.exe`, see the repository README).

```sh
npm install
npm run tauri dev     # the desktop app: Vite dev server + Tauri shell + engine
```

### Browser dev mode

`npm run dev` serves the UI on http://localhost:1420 without the shell. It
then connects to whatever engine listens on `127.0.0.1:8765` with no token and
no handshake, and the title bar shows an **insecure dev mode** badge: nothing
proves that listener is the engine. Start one yourself
(`reverse-slop-engine.exe` with the MCP server on its default port); its CORS
allow-list already includes `http://localhost:1420` and `http://127.0.0.1:1420`.
For an engine on another port or with an MCP token, put them in
`app/.env.local` (ignored by `app/.gitignore`; never commit a token):

```sh
VITE_SLOP_PORT=8765
VITE_SLOP_TOKEN=<the engine's mcp_token>
```

## Scripts

| Script                             | What it does                                                                                                                                                          |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run dev`                      | Vite dev server (port 1420, fixed: the CSP and the engine's CORS allow-list name it)                                                                                  |
| `npm run build`                    | Typecheck, then a production bundle in `dist/` (no sourcemaps; `SOURCEMAP=1` or a Tauri debug build enables them)                                                     |
| `npm run typecheck`                | `tsc --noEmit` (strict)                                                                                                                                               |
| `npm run lint`                     | ESLint (TypeScript + React hooks rules), zero warnings allowed                                                                                                        |
| `npm run format` / `format:check`  | Prettier write / check                                                                                                                                                |
| `npm test`                         | The store-level smoke test (`scripts/test-app.mjs`) and the vitest suite                                                                                              |
| `npm run test:unit` / `test:watch` | vitest only (jsdom + Testing Library), once / watch                                                                                                                   |
| `npm run check:api`                | Cross-checks every `call(tool, action, {params})` in `src/` against a running engine's `tools/list` schema (`node scripts/check-api.mjs [port]`); needs a live engine |
| `npm run bench`                    | SSR render benchmark of the 4096-row output pane                                                                                                                      |
| `npm run icons`                    | Regenerates the app icons from `src/assets/reverse-slop-icon.png`                                                                                                     |
| `npm run tauri …`                  | The Tauri CLI                                                                                                                                                         |

## Tests

- `scripts/test-app.mjs` loads the real stores through Vite's SSR loader with
  a fake `EventSource`/`fetch`: output ring bounds and dedupe, watch teardown,
  function-list refresh on analysis completion, the native endpoint
  handshake, the ticketed event stream and startup/reconnect recovery.
- `src/**/*.test.ts(x)` (vitest, jsdom): component and store tests with a fake
  `/api` (`src/test/api.ts`). Each fixed UI bug has a regression test there.

## Conventions

- Talk to the engine only through `call`/`batch`; add a new `app` action to
  `kAppActions` in `scripts/check-api.mjs`.
- Icon-only buttons use `IconButton` (its tooltip is also its accessible
  name); tab strips use `Tabs`; dialogs use `Modal`.
- Colours come from CSS variables in `src/styles/tokens.css`; never hard-code
  a colour that must work in the light and high-contrast themes.
- Dependencies are pinned to exact versions; `@tauri-apps/*` track the
  `tauri` crate's minor version in `src-tauri/Cargo.lock`.
