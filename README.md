<!-- logo pinned to a commit so github's image cache can't serve a stale one,
     bump the sha whenever the icon changes -->
<p align="center">
  <img src="https://raw.githubusercontent.com/kaizer1308/reverse-slap/a61180fb51fc19141104a13a2caf6c33b9661bcc/app/src-tauri/icons/256x256.png" width="144" alt="reverse-slop" />
</p>

# reverse-slop

PS4 reverse-engineering toolkit with desktop interfaces, live remote analysis
and debugging of a console running the ps4debug-NG payload, static analysis
and decompilation of dumped game binaries, host-side network capture, and a
built-in Model Context Protocol (MCP) server so AI agents can drive whole
game-RE workflows end to end.

> [!WARNING]
> Use reverse-slop only on consoles, games, and systems you own or are
> authorized to test. Live debugging and memory writes on a PS4 can crash the
> console or trip anti-cheat; host-side packet capture needs administrator
> privileges on the analysis PC.

## Inspiration and attribution

reverse-slop is heavily inspired by [AiDA Private](https://github.com/sigwl/AiDAPrivate),
created by [sigwl](https://github.com/sigwl) (ruarridh). Most, if not almost all,
of reverse-slop's feature set and feature concepts are based on that project.

## Screenshots

The main workspace, process list and disassembly side by side under the kernel badge:

![main workspace](docs/reverse-slop-main.png)

The strings view with search, UTF-16 flagging and xref counts:

![strings view](docs/reverse-slop-strings.png)

## Highlights

- **Two desktop interfaces, one core:** native ImGui/DX11 shell and Tauri v2 +
  React shell both drive the same C++ engine.
- **Headless operation:** run the engine without a window for MCP or HTTP clients.
- **Remote PS4 targets:** connect directly to a console running the
  [ps4debug-NG](https://github.com/Pharaoh2k/ps4debug-NG) payload (TCP 744) and
  use the same process list, attach, memory read/write/scan, regions, modules,
  and threads against the console — plus live remote debugging: breakpoints,
  hardware watchpoints, continue/step, stop events, register get/set,
  callstacks, and remote function calls via the `debugger` tool's `ps4_*`
  actions and the one-call `target.ps4_auto`.
- **Live analysis over the wire:** memory read/write/protect/alloc, Cheat
  Engine-style scans, AOB search, pointer chains, snapshots and diffs,
  watchlists, and module/region enumeration all run against the console
  process through ps4debug-NG.
- **Static analysis:** PE, PS4/Orbis ELF64 (SELF) and Mach-O/`.ipa` loading,
  x86/x64 and ARM64 disassembly, function and cross-reference indexes, strings,
  globals, vtables, RTTI, signatures, binary diffing, packer detection, and
  security-focused reconnaissance — built for analyzing dumped `eboot.bin`
  and game modules offline.
- **Decompiler:** Hyperion p-code lifting, SSA, dead-code elimination, type
  inference, control-flow structuring, and C-like output with source addresses.
- **Emulation:** isolated x86-64 Unicorn execution with demand paging from the
  loaded image or live console memory, IAT stubs, register/memory setup,
  tracing, and byte-level taint propagation.
- **Network tooling:** host-side raw-socket capture (packets, DNS, streams,
  per-packet HTTP/TLS/DNS classification, PCAP export) plus an independent
  localhost HTTP inspection proxy.
- **Unpacking and devirtualization:** Magicmida Themida sidecars, VM handler and
  opcode-map recovery, trace/lift/pseudocode flows, CFG recovery, predicate
  proofs, invariants, and IAT auditing.
- **Agent-native control:** 25 MCP-visible domain tools with consolidated
  `action` parameters, task playbooks via `guide`, plus an `/api`-only
  application-control tool and SSE events.

## Platform and requirements

### Required for the C++ build

- Windows 10 or 11, x64
- Visual Studio 2022 with **Desktop development with C++** and the
  `Microsoft.VisualStudio.Component.VC.Tools.x86.x64` component
- CMake 3.25 or newer
- Ninja
- PowerShell
- Git and internet access during first configure

`tools/build.ps1` locates Visual Studio with `vswhere`, then uses Visual
Studio's bundled CMake and Ninja. CMake downloads pinned dependencies into
`_ext/`, including ImGui, FreeType, Zydis, Capstone, Unicorn, nlohmann/json,
cpp-httplib, SQLite, Lua, fmt, spdlog, and zlib.

### Additional requirements by component

| Component | Additional requirements |
|---|---|
| Tauri desktop shell | Node.js/npm, Rust toolchain with Cargo, WebView2 runtime |
| Themida unpacking | Separately installed Magicmida x86/x64 sidecars |
| Host packet capture (`network` tool) | Administrator privileges for SIO_RCVALL |

## Build

Run commands from a PowerShell prompt at repository root.

### Standard build

```powershell
powershell -File tools/build.ps1
```

This configures and builds the `ninja-msvc-release` preset into `build/`, then
builds the Tauri app (portable folder plus installer). Incremental builds reuse
both directories. Add `-NoFrontend` for the C++ targets alone.

Useful build-script switches:

```powershell
# Delete build/ before configuring
powershell -File tools/build.ps1 -FullClean

# Configure only; do not compile
powershell -File tools/build.ps1 -PlanOnly

# Select another preset if one has been added to CMakePresets.json
powershell -File tools/build.ps1 -Preset ninja-msvc-release

# Full installer: bundle Magicmida and the WebView2
# runtime so the target machine needs nothing but Windows (no internet,
# no WebView2, no dev tools). Fails instead of skipping a missing component
powershell -File tools/build.ps1 -Full
```

Default CMake options are all enabled:

| Option | Default | Output |
|---|---:|---|
| `SLOP_BUILD_ENGINE` | `ON` | Headless engine host |
| `SLOP_BUILD_TEST_TARGET` | `ON` | `SlopTarget.exe` fixture |
| `SLOP_BUILD_TESTS` | `ON` | Core test harness |

For manual configuration, first enter an x64 Visual Studio developer shell:

```powershell
cmake --preset ninja-msvc-release -S .
cmake --build --preset ninja-msvc-release
```

### Tauri + React desktop build

The Tauri UI is the app that ships; `reverse-slop.exe` (ImGui) is the legacy
shell kept for parity work. The frontend build needs the C++ engine first
because Tauri bundles `reverse-slop-engine.exe` as a resource.

```powershell
powershell -File tools/build.ps1
```

That performs the C++ build, runs `npm install` if `app/node_modules` is
missing, builds the React app, and produces two standalone outputs:

```text
dist\reverse-slop\reverse-slop.exe                          portable folder
app\src-tauri\target\release\bundle\nsis\...-setup.exe       per-machine installer
```

The portable folder carries its own `engine\` directory, so it runs from a copy
with no installer and no build tree. It needs the Microsoft Edge WebView2
runtime, which ships with Windows 11 and current Windows 10; the NSIS installer
downloads it when missing.

Run the same command with `-Full` for a self-contained release installer: the
setup exe embeds the WebView2 runtime (offline install, no download on the
target machine) and hard-requires every optional component, so the Magicmida
sidecars are always inside. The build fails loudly instead
of silently shipping a degraded bundle when the network or Magicmida is missing.

Use `-NoFrontend` for a fast C++-only loop (skips Rust, npm, and the bundle).

Release Tauri builds request administrator elevation so the engine sidecar can
run host-side packet capture (SIO_RCVALL). Debug Tauri builds run as the
invoking user and packet capture reports unavailable.

Frontend development:

```powershell
# Terminal 1: build or refresh the C++ engine
powershell -File tools/build.ps1 -NoFrontend

# Terminal 2
cd app
npm install
npm run tauri -- dev
```

Vite uses fixed port `1420`; the engine's CORS allow-list depends on it.
Additional frontend checks:

```powershell
cd app
npm run typecheck
npm run build

# Requires a running engine; validates frontend calls against tools/list
npm run check:api -- 8765
```

### Magicmida Themida sidecars

Magicmida and its ScyllaHide dependency are separate GPLv3 programs, not linked
into reverse-slop. Install the pinned, SHA-256-verified `2026-05-14` release:

```powershell
powershell -File tools/install_magicmida.ps1
```

Default destination:

```text
%LOCALAPPDATA%\reverse-slop\tools\magicmida\2026-05-14\x86
%LOCALAPPDATA%\reverse-slop\tools\magicmida\2026-05-14\x64
```

Overrides:

- `SLOP_MAGICMIDA_ROOT` — root containing `x86` and `x64` directories
- `SLOP_MAGICMIDA_X86` — direct path to x86 executable
- `SLOP_MAGICMIDA_X64` — direct path to x64 executable

## Run

### Tauri app (primary)

```powershell
.\dist\reverse-slop\reverse-slop.exe
```

Requests administrator elevation once, spawns `engine\reverse-slop-engine.exe`
as a sidecar in a kill-on-close job object, and drives it over `/api` +
`/events`. Installed builds behave the same from `%ProgramFiles%`.

### Native ImGui shell (legacy)

```powershell
.\build\src\app\reverse-slop.exe
```

The executable requests administrator elevation. It owns a Win32 window with a
DX11 composition swapchain, docking, FreeType fonts, keyboard navigation, and
DWM styling. Built-in views and shortcuts:

| View | Shortcut |
|---|---|
| Targets | `Ctrl+1` |
| Inspector | `Ctrl+2` |
| Disassembly | `Ctrl+3` |
| Memory | `Ctrl+4` |
| Output | `Ctrl+5` |
| Scanner/watchlist | `Ctrl+6` |
| Strings | `Ctrl+7` |
| PE Browser | `Ctrl+8` |
| Debugger | `Ctrl+9` |
| Pseudocode | `Ctrl+0` |
| Unpacker | No default shortcut |
| Frame Metrics | `F12` |

### Headless engine

Safest development path, with no client-config changes:

```powershell
.\build\src\engine\reverse-slop-engine.exe --no-onboard
```

Full engine:

```powershell
.\build\src\engine\reverse-slop-engine.exe
```

Options:

| Option | Effect |
|---|---|
| `--no-onboard` | Do not register MCP endpoint in supported AI clients |
| `--quiet` | Suppress mirrored engine output on stderr |
| `--port <n>` | Override MCP/API port for this process |
| `--parent-pid <pid>` | Exit through clean teardown when parent exits |
| `--headless` | Accepted for supervisor compatibility; engine is always headless |

Successful startup writes this machine-readable line to stdout:

```text
SLOP_ENGINE_READY <port> <token>
```

If another live reverse-slop endpoint is advertised, a new engine reports that
endpoint with `SLOP_ENGINE_EXISTING <pid>` and exits rather than competing for
the port.

### Tauri shell

Launch installed `reverse-slop`, or during development:

```powershell
cd app
npm run tauri -- dev
```

The Rust supervisor starts the C++ engine, waits up to 180 seconds for its
handshake, places it in a kill-on-close job object, and lets it perform clean
shutdown when the UI exits. The React shell exposes targets (including the PS4 connect/auto flow),
modules, scripts, scanner/watchlist, disassembly, strings, memory, the PS4
debugger, PE browser, output, inspector, and theme/motion settings.

## Feature reference

### Process and live-memory workspace

On a connected PS4 these run against the console process over the ps4debug-NG
wire; a hidden local user-mode backend remains for the automated test fixture.

- Enumerate processes with icons and architecture/elevation metadata.
- Attach/detach a shared target session.
- Enumerate modules, threads, virtual-memory regions, heaps, heap blocks, and
  handles (`target.heaps` / `target.heap_blocks` over MCP, local targets only).
- Reconstruct a conventional PE from a mapped module (local Windows targets
  only; PS4 modules are ELF/SELF); strict mode rejects unreadable spans, while
  best-effort mode zero-fills them.
- Read/write memory in hex, UTF-8, integer, and floating-point formats.
- Allocate, free, and change page protection.
- Cheat Engine-style initial and refined numeric scans with exact/range/change,
  signed/unsigned/floating widths, rounding, region/protection, address,
  alignment, worker, chunk, and result-cap filters.
- AOB wildcard search, pointer-chain scans, signature generation, and live
  cryptographic-constant search.
- Snapshot memory, compare snapshots, list/free snapshot state.
- Shared watchlist sampled around 10 Hz, including freeze writes; UI and MCP
  changes appear in both surfaces.

### Remote PS4 targets (ps4debug-NG)

With a PS4 on the same network running the
[ps4debug-NG](https://github.com/Pharaoh2k/ps4debug-NG) payload, reverse-slop
speaks its wire protocol directly (TCP 744, plus the port-755 debug-event
callback) through a dedicated `PS4` backend:

- Connect from the ImGui targets view ("PS4..." button), the Tauri targets
  panel (gamepad button), or MCP with `target.ps4_connect {host, port=744,
  pid?}`; `target.ps4_disconnect` drops the console. `target.status` reports
  the endpoint and the server branding string. `target.ps4_auto {host,
  port?}` does the whole setup in one call: connect, pick the game process
  (the one with `/app0/` modules, eboot-named preferred), attach a session
  and the ps4debug debug session, and return modules/threads/regions.
- Once connected, `target.list` enumerates console processes and the existing
  attach button / `target.attach {pid}` opens a session over the wire; the
  backend badge reads `PS4`.
- Memory read/write, protect/alloc/free, AOB and numeric scans, snapshots,
  watchlists, regions, and module enumeration all work against the remote
  process. Reads are validated against the console's VM map so unmapped
  ranges report failure instead of zero fill; Windows `PAGE_*` constants are
  translated to FreeBSD `VM_PROT_*` on the way out.
- `target.threads` and thread register get/set use ps4debug-NG's debug
  commands (`CMD_DEBUG_ATTACH` + `GET_THREAD_LIST`/`GETREGS`/`SETREGS`); the
  engine listens on port 755 for the server's event callback while a debug
  session is attached.
- PS4 modules are ELF/SELF, not PE, so `dump_module`/PE loading stay local-only;
  pull a module's raw memory image off the console with
  `target.ps4_dump_module {name|base, path, load?}` (load=true opens ELF dumps in
  `disasm`), or analyze live addresses with `disasm.disassemble` and
  `memory.read` instead.

### Live debugging on the PS4 (ps4debug-NG)

With a console connected (`target.ps4_connect`), the `debugger` tool's `ps4_*`
actions drive the payload's debug session live, no local target needed:

- `ps4_attach {pid}` / `ps4_detach` / `ps4_status` manage the debug session
  (the engine accepts the payload's port-755 event connection automatically).
- `ps4_bp_set {addr, index?}` / `ps4_bp_clear {addr|index}` arm software INT3
  breakpoints (slots 0-29 auto-allocated client-side, since the payload has no
  query command); `ps4_watch_set {addr, len=1|2|4|8, type=0|1|3, index?}` /
  `ps4_watch_clear` arm hardware DR0-DR3 watchpoints (type 0=exec, 1=write,
  3=read/write).
- `ps4_continue {stop}` resumes the debuggee (stop 0=resume, 1=SIGSTOP,
  2=SIGKILL); `ps4_step {lwpid?}` single-steps (0/absent = all threads);
  `ps4_suspend`/`ps4_resume {lwpid}` freeze one thread; `ps4_process_stop
  {state}` signals the whole process.
- Every stop (breakpoint hit, watchpoint hit, step, signal) arrives as a
  0x4A0-byte event packet on port 755 and is queued: `ps4_wait {timeout_ms}`
  blocks for the next one (returns the full register set, signal, thread
  name, and DR registers), `ps4_events {max, clear}` drains the queue.
- `ps4_regs {lwpid}` / `ps4_set_reg {lwpid, name, value}` read or write one
  register (`rax`..`r15`, `rip`, `rsp`, `rbp`, `flags`); `ps4_dbregs {lwpid}`
  dumps DR0-DR7+; `ps4_callstack {lwpid, depth}` walks the rbp frame chain via
  live memory reads.
- `ps4_call {addr, args[6]}` installs the payload's RPC stub once per process
  (`CMD_PROC_INTALL`) and calls any address in the console process with up to
  six arguments (rdi, rsi, rdx, rcx, r8, r9), returning `rax` — remote function
  calls for dynamic analysis, e.g. resolving a function live and calling it
  with crafted arguments.
- One-call "power actions" wrap the common dynamic-analysis moves:
  `ps4_until {addr, timeout_ms}` (arm a one-shot bp, continue, wait, auto-clear),
  `ps4_find_write {addr, len, timeout_ms, depth}` (write watchpoint + continue +
  wait, returns the event and the writer callstack), `ps4_trace_calls {addr,
  count, timeout_ms}` (bp arg logger: every hit with rdi/rsi/rdx/rcx/r8/r9),
  `ps4_trace_steps {lwpid, count, timeout_ms}` (step+wait loop with rip and the
  disassembled instruction per step), and `ps4_bp_list` / `ps4_watch_list` to
  see the armed slots.
- Register completeness: `ps4_fpregs {lwpid}` / `ps4_set_fpregs {lwpid, hex}`
  read/write the 832-byte savefpu (XMM/YMM) block, `ps4_set_dbregs {lwpid,
  hex}` writes the 128-byte DR set, `ps4_fsgs {lwpid}` /
  `ps4_set_fsgs {lwpid, fs_base, gs_base}` read/write FS/GS base.
- Console-side tooling (everything below runs inside the ps4debug-NG payload on
  the console, not on the PC):
  - Native memory scan, unlocked by `ps4_auth` (run automatically on connect;
    the payload's challenge keystream is four LFSRs seeded 200/300/400/500):
    `ps4_scan {addr, len, value_type, compare, value|hex}` seeds a scan over a
    range, `ps4_rescan {compare, value?}` narrows the stored hit set
    (exact/fuzzy/bigger/smaller/between/increased/decreased/changed/unchanged/
    unknown), `ps4_scan_state` / `ps4_scan_reset` manage it, `ps4_scan_all`
    scans every readable map, and `ps4_scan_aob {addr, len, pattern}` scans for
    a byte pattern with `??` wildcards.
  - On-device code analysis: `ps4_disasm {addr, len, max}` (payload-side Zydis:
    kind flags, mem operands, rip-relative targets), `ps4_xrefs {addr, len}`
    (all branch/call targets in a range), `ps4_xrefs_to {addr, len, target}`,
    `ps4_stack {rbp?, rsp?, depth}` (server-side rbp-chain walk with frame
    locals and a code window per frame).
  - `ps4_assemble {asm, base?, syntax?}` assembles x86-64 on the console
    (payload-side Keystone) — write the bytes with `memory.write`.
  - `ps4_elf_rpc {path}` / `ps4_elf_load {path}` upload a raw ELF64 payload into
    the game process and get its entry address / jump into it.
  - `ps4_notify {msg, type?}` shows a system notification on the PS4 UI,
    `ps4_print {msg}` writes to the console kernel log, `ps4_app` returns the
    foreground game's pid/titleid/contentid/version.
- The same controls exist in the ImGui debugger view: while a PS4 backend is
  active it shows a live panel with debug attach/detach, continue/step,
  breakpoint and watchpoint arming, the port-755 event feed, registers of the
  last stopped thread, and remote calls through the rpc stub.
- The `guide` tool is the AI playbook index: `guide list` shows the topics and
  `guide get {topic}` returns a ready-to-run tool-call sequence (e.g.
  `ps4_setup`, `ps4_breakpoint`, `ps4_api_trace`, `ps4_find_write`,
  `ps4_step_trace`, `ps4_remote_call`, `find_health`, `find_damage_source`,
  `pointer_chain`, `runtime_decrypt`, `ps4_api_monitor`, `snapshot_diff`,
  `emulate_function`, `devirt_cflow`, `ps4_unpack_runtime`,
  `ps4_hw_watchpoints`, `ps4_native_scan`, `ps4_dump_and_analyze`).

### Static analysis and decompilation

- PE headers, sections, data directories, imports, exports, and runtime-base
  rebasing.
- Fast synchronous Zydis function, xref, string, and PE indexes.
- Background Hyperion recursive analysis with CFGs, globals, vtables, RTTI,
  names, PDB/FLIRT support, and progress/cancellation state.
- .NET/CLI assemblies: `disasm.loaded` reports `hype.managed`, and
  `disasm.managed` lists TypeDefs (`type_filter`), renders one type as
  dnSpy-style C# (`type`), or dumps one method's ILDASM-style listing
  (`method_token`).
- x86/x64 disassembly and assembly.
- PS4/Orbis ELF64 (SELF) static analysis: ELF loading, segment-backed section
  mapping, and SCE `PT_SCE_DYNLIBDATA` import extraction, so a dumped
  `eboot.bin` or game module can be analyzed offline with the full disasm /
  xray / decomp surface while the console is driven live over ps4debug-NG.
- iOS apps and Mach-O: `disasm.load`, `slop.image.load` and both Disassembly
  open dialogs accept an `.ipa`, a thin Mach-O or a FAT Mach-O, detected by
  content. For an `.ipa` the main executable is the `Payload/<Name>.app/`
  entry named by `Info.plist` `CFBundleExecutable` (XML or binary plist,
  falling back to the bundle stem); a FAT binary is reduced to its arm64 slice
  (else x86_64, arm, x86). The image gets a section map (`__TEXT.__text`,
  `__TEXT.__cstring`, ...), imports from the GOT/lazy pointers grouped by
  dylib, `__stubs` and local symbols as names, and function bounds from
  `LC_FUNCTION_STARTS`. ARM64 code decodes with Capstone and decompiles
  through the Hyperion ARM64 lifter; xrefs come from the Hyperion DB.
  `disasm.loaded` reports `format`, `arch`, `bundle` (id, version, build,
  minimum iOS) and `encrypted`. App Store copies are FairPlay-encrypted
  (`cryptid != 0`): load a decrypted dump, or the code is noise. Tools that
  decode x86 (`xray` except `entropy`/`apihash`, `emulate`, `devirt`,
  code-rewriting `patch` actions, `disasm.assemble`) or parse PE structures
  (`analyze.packer`, `re.rtti_scan`) refuse Mach-O/ARM64 images with an error.
- Structured decompilation pipeline: instruction lifting to p-code, SSA,
  propagation, dead-code elimination, type inference, control-flow structuring,
  and C-like emission.
- Per-line virtual-address mappings, optional address annotations, reconstructed
  stack variables, signatures, and persisted user names.
- Binary-to-binary function diff with added/removed/modified functions and
  similarity scores.
- Packer/protector indicators: signatures, entropy, import anomalies, W+X
  sections, TLS, overlay, and crypto constants.
- RTTI class/vtable recovery, dangerous-import callsites, library byte
  signatures, user structs/enums, typed formatting, comments, and bookmarks.
- Per-binary metadata persists by file hash and remaps across different runtime
  bases.

### Xray and patching

Read-only Xray passes include:

- CFG and cyclomatic complexity
- Control-flow flattening and general obfuscation scoring
- String reconstruction and indirect-call recovery
- Anti-analysis patterns
- Hook checks and direct-syscall discovery
- Imported API hash resolution
- Entropy windows and executable-page classification
- Crypto constants and ROP gadget search

File-image patching includes:

- Junk-NOP cleanup and opaque-predicate resolution
- Anti-debug patching
- XOR unpacking and string decoding
- Explicit byte writes
- Patch journal and full revert
- Combined full pass
- Function re-decode/index invalidation after edits

Patches affect the loaded analysis image, not live process memory. Use the memory
suite for live writes.

### Debugger (PS4 live debugging)

The `debugger` tool is PS4-only in this build; see
"Live debugging on the PS4 (ps4debug-NG)" above for the full `ps4_*` action
list: software breakpoints, DR0-DR3 hardware watchpoints, continue/step,
suspend/resume, stop events on the payload's port-755 stream, register
read/write, callstacks, remote calls (`ps4_call`), and the one-call power
actions (`ps4_until`, `ps4_find_write`, `ps4_trace_calls`, `ps4_trace_steps`).
Both the ImGui debugger view and the Tauri debugger tab drive the same
ps4debug-NG session. Local Win32 debugging, the kernel VEH mode, and the
driver-backed hardware breakpoints were removed with the Windows toolkit.

### Emulation and devirtualization

- Isolated x86-64 Unicorn execution from explicit bytes, loaded-file addresses,
  or attached-target addresses.
- Demand paging from the loaded image (relocated when rebased) or the attached
  process, so runs follow calls, jumps and global loads past the code slice.
- IAT stubs that log every import call with its arguments and return a chosen
  value per import, plus a TEB/PEB behind `gs`.
- Final-memory dumps and a write log with stored values.
- Custom register, stack, and memory-map initialization.
- Instruction-count, target-address, and timeout stopping conditions.
- Bounded instruction traces and byte-granular taint tracking.
- VM identification, handler discovery, opcode maps, execution traces, lifting,
  and pseudocode.
- CFG recovery, multi-run predicate proofs and invariant discovery, plus IAT
  audits.
- Supervised Magicmida jobs with architecture validation, cancellation,
  timeouts, output selection, and optional loading into analysis session.

### Network and proxy

Host-side network features on the analysis PC (raw socket with SIO_RCVALL,
needs administrator; `pid`/`port`/`protocol` act as capture filters):

- Capture start/stop, packet paging with text filters, DNS query log,
  statistics, and PCAP export
- Stream listing, payload reads, and TCP reassembly from the capture store
- Connection 4-tuple listing and per-packet deep inspection (HTTP
  method/host/path, TLS version/SNI/content-type, DNS)

Independent HTTP/1.1 proxy features include start/stop, captured entries,
exchange detail, and request replay. CONNECT tunnels record metadata/SNI but do
not decrypt tunnel bodies; replay applies to captured plain HTTP.

### Automation, persistence, filesystem, and web access

- Lua 5.4 scripts with bounded execution, covering the whole static-analysis
  surface the way IDAPython covers IDA (see "Lua scripting" below), plus APIs
  for logging, targets, memory, live disassembly, and packer analysis.
- SQLite session snapshots and key/value storage.
- Hyperion `.hdb` project export/import for names and comments.
- Host filesystem read/write/list/create/delete/name-search/content-search.
- Outbound WinHTTP GET/POST requests without browser-cookie inheritance.

### Lua scripting

Scripts run through the `script` MCP tool (`action=run`, `code`, `timeout_ms`)
or the engine API and execute against the same shared binary session as the
UI and every other MCP tool — loads, renames, and comments made from one
surface appear in all of them. Returned values are serialized into the
captured output as `return: <value>`.

```lua
-- Load a binary, wait for the Hyperion analysis, and walk the functions.
assert(slop.image.load([[C:\bin\target.exe]]))
assert(slop.image.wait_ready(30000))

for _, f in ipairs(slop.disasm.functions()) do
    slop.log(string.format("%X  %s (%d bytes)", f.va, f.name, f.size))
end

-- Cross-references, decompilation, and annotation all interoperate:
local refs = slop.disasm.xrefs_to(0x140001000)     -- { {from=..., kind=...}, ... }
local d    = slop.decomp.decompile(0x140001000)   -- pseudo-C lines + signature
slop.disasm.set_name(d.va, "entry_handler")        -- persisted rename
slop.disasm.set_comment(d.va, "called on startup") -- persisted comment
```

The static-analysis surface:

| Group | Functions |
|---|---|
| Session | `slop.image.load(path[, base])`, `load_from_target`, `unload`, `status`, `wait_ready([ms])` |
| Instructions | `slop.disasm.decode(addr[, count])`, `slop.disasm.bytes(addr[, len])` |
| Functions | `slop.disasm.functions([limit])`, `slop.disasm.function_at(va)` |
| Cross-refs | `slop.disasm.xrefs_to(va)` |
| Data | `slop.disasm.strings([min[, limit]])`, `slop.disasm.pe()` |
| Annotation | `slop.disasm.name/set_name/comment/set_comment`, `bookmark_toggle`, `bookmarks` |
| Decompiler | `slop.decomp.decompile(va)` (pseudo-C + signature), `blocks(va)` (CFG) |
| Rich DB | `slop.decomp.vtables()`, `globals()`, `rtti()` |

`decomp.*` requires the Hyperion analysis to be ready — call
`slop.image.wait_ready()` after loading. On a connected PS4 the same
`slop.target.*` / `slop.mem.*` surface reads and writes the console process
over the wire, alongside `slop.disasm.disassemble` and `slop.analyze.packer`.

## MCP and HTTP API

### Endpoints

Default listener: `127.0.0.1:8765`. It never binds to a non-loopback address.

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness and version |
| `POST /mcp` | MCP JSON-RPC 2.0 (`initialize`, `ping`, `tools/list`, `tools/call`) |
| `GET /mcp` | MCP SSE endpoint/keepalive |
| `POST /api` | Direct frontend RPC; accepts one request or an array |
| `GET /events` | Frontend SSE event stream |

Protocol version: `2025-06-18`.

`initialize` returns two agent-facing fields beyond the standard handshake:
`instructions` (a short server-level usage preamble clients surface to the
model) and `state` — the live session context: active backend badge, attached
target (`pid`/`name`/`arch`), debugger state, and the loaded-image summary
including Hyperion analysis readiness (`image.hype.ready`). The same context
is available mid-session through `target.status` and `disasm.loaded`.

Configure `%LOCALAPPDATA%\reverse-slop\settings.json`:

```json
{
  "mcp_enabled": true,
  "mcp_port": 8765,
  "mcp_token": "",
  "mcp_onboarded": false
}
```

`SLOP_MCP_PORT` or engine `--port` overrides configured port for that process.
When configured port is busy, reverse-slop uses an ephemeral port and skips
onboarding so existing clients remain pointed at owner of well-known port.
Set `mcp_token` to require `Authorization: Bearer <token>` on MCP/API routes.
The `/events` route also accepts a token query parameter because browser
`EventSource` cannot set custom headers.

Request bodies are capped at 32 MiB. Tool calls share core state and are
serialized where required; cancellation notifications propagate to supported
long-running operations.

### MCP examples

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
```

List tools:

```powershell
$body = @{
  jsonrpc = '2.0'
  id = 1
  method = 'tools/list'
} | ConvertTo-Json -Depth 8

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8765/mcp `
  -ContentType 'application/json' `
  -Body $body
```

List processes through MCP:

```powershell
$body = @{
  jsonrpc = '2.0'
  id = 2
  method = 'tools/call'
  params = @{
    name = 'target'
    arguments = @{ action = 'list' }
  }
} | ConvertTo-Json -Depth 8

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8765/mcp `
  -ContentType 'application/json' `
  -Body $body
```

Direct `/api` request:

```powershell
$body = @{
  tool = 'disasm'
  action = 'loaded'
  params = @{}
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8765/api `
  -ContentType 'application/json' `
  -Body $body
```

### MCP tool/action index

All MCP tools accept an `action` string. Exact parameter schemas and detailed
operational guidance are returned by `tools/list`.

| Tool | Actions |
|---|---|
| `target` | `list`, `attach`, `detach`, `status`, `modules`, `dump_module`, `threads`, `regions`, `handles`, `heaps`, `heap_blocks`, `icon`, `ps4_connect`, `ps4_disconnect`, `ps4_auto`, `ps4_dump_module` |
| `memory` | `read`, `write`, `scan`, `rescan`, `scan_state`, `scan_reset`, `aob`, `pointerscan`, `snapshot`, `snapshots`, `diff`, `snapshot_free`, `protect`, `alloc`, `free`, `siggen`, `live_crypto`, `watch_list`, `watch_add`, `watch_remove`, `watch_clear`, `watch_set` |
| `disasm` | `assemble`, `disassemble`, `loaded`, `pe`, `functions`, `xrefs`, `strings`, `symbols`, `symbol_set`, `blocks`, `globals`, `vtables`, `load`, `unload`, `analyze_stop`, `managed` |
| `debugger` | `status`, `ps4_attach`, `ps4_detach`, `ps4_status`, `ps4_bp_set`, `ps4_bp_clear`, `ps4_watch_set`, `ps4_watch_clear`, `ps4_continue`, `ps4_step`, `ps4_suspend`, `ps4_resume`, `ps4_process_stop`, `ps4_regs`, `ps4_set_reg`, `ps4_dbregs`, `ps4_wait`, `ps4_events`, `ps4_callstack`, `ps4_call`, `ps4_bp_list`, `ps4_watch_list`, `ps4_until`, `ps4_find_write`, `ps4_trace_calls`, `ps4_trace_steps` |
| `xray` | `cfg`, `complexity`, `cff`, `obfuscation`, `strings_recon`, `indirect_calls`, `anti_analysis`, `hooks`, `syscalls`, `apihash`, `entropy`, `pages`, `crypto_range`, `gadgets` |
| `patch` | `nop_junk`, `resolve_opaque`, `patch_antidebug`, `unpack_xor`, `decode_strings`, `write_bytes`, `revert_all`, `journal`, `full_pass`, `rebuild` |
| `devirt` | `themida_status`, `themida_start`, `themida_job`, `themida_cancel`, `identify`, `handlers`, `opcode_map`, `trace`, `lift`, `pseudocode`, `recover_cfg`, `prove_predicates`, `invariants`, `iat_audit` |
| `types` | `declare`, `create_struct`, `get_struct`, `list_structs`, `add_member`, `remove_struct`, `create_enum`, `get_enum`, `list_enums`, `remove_enum`, `read_field`, `format_at` |
| `notes` | `set_comment`, `get_comment`, `comments`, `bookmark_toggle`, `bookmarks` |
| `emulate` | `run` |
| `analyze` | `packer`, `signatures`, `diff` |
| `network` | `status`, `capture_start`, `capture_stop`, `packets`, `dns`, `stats`, `export_pcap`, `streams`, `stream_data`, `reassemble_stream`, `connections`, `deep_inspect` |
| `proxy` | `start`, `stop`, `status`, `entries`, `entry`, `replay` |
| `persist` | `save`, `list`, `load`, `delete`, `kv_set`, `kv_get`, `hype_save`, `hype_load` |
| `re` | `rtti_scan`, `vftable`, `danger`, `libsig` |
| `decomp` | `function` |
| `fs` | `read_file`, `write_file`, `list_directory`, `create_directory`, `delete_path`, `search_files`, `grep_in_files` |
| `web` | `fetch`, `post` |
| `script` | `run` |
| `guide` | `list`, `get` |

`app` is intentionally omitted from MCP `tools/list`; it is frontend plumbing
available only through `/api`: `status`, `ping`, `output`, `output_clear`, `log`,
`diag`, and `shutdown`.

### Events

`GET /events` sends `hello` with an output revision cursor, then events such as:

- `output`
- `boot.stage`
- `target.changed`
- `backend.changed`
- `hype.progress`
- `watch.list`
- `watch.values`
- `app.quitting`

On reconnect, frontend can replay missed output with `app.output` and the last
revision.

### Automatic MCP client registration

On first successful startup at configured port, reverse-slop adds a
`reverse-slop` HTTP MCP entry without replacing existing entries in:

- Claude Code: `%USERPROFILE%\.claude.json` (user scope; the entry needs
  `"type": "http"`, server definitions do not live in `settings.json`)
- Cursor: `%USERPROFILE%\.cursor\mcp.json`
- Windsurf: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`
- VS Code: `%APPDATA%\Code\User\settings.json` (under `mcp.servers`)
- OpenCode: `%USERPROFILE%\.config\opencode\config.json`

Claude Desktop is not auto-registered: `claude_desktop_config.json` supports
stdio servers only, so a remote HTTP entry cannot work there — add it through
Claude Desktop's Connectors UI instead. Unparseable client config files are
left untouched rather than overwritten.

Use `--no-onboard` for a headless run that must not edit client configuration.
Set `mcp_onboarded` to `false` to request another onboarding pass after removing
or changing entries.

## Architecture

```text
                       +----------------------+
                       | ImGui / DX11 shell   |
                       | src/app + src/ui     |
                       +----------+-----------+
                                  |
                                  | in-process calls
                                  |
+---------------------+   HTTP    v    +--------------------------+
| Tauri / React shell |<-------------->| shared C++ core          |
| app/                |  /api,/events  | src/core                 |
+----------+----------+                +------------+-------------+
           |                                        |
           | supervises                             +-- process/memory
           v                                        +-- runtime (ps4 backend)
+--------------------------+                        +-- disasm/analysis/decomp
| headless engine          |                        +-- network/proxy
| src/engine               |                        +-- MCP/API/event bus
+--------------------------+
```

Both native and headless hosts drive the shared lifecycle in
`src/core/infra/lifecycle.cpp`:

1. Initialize application paths and worker/job queues.
2. Start process and target services.
3. Load settings and persistence state.
4. Bind MCP/API server and optionally onboard clients.
5. Publish capabilities and enter periodic target/watch/event servicing.
6. On shutdown, stop server/jobs/watches/targets and save settings.

Key directories:

```text
src/
├── app/          Win32 entry point and DX11 loop
├── engine/       Headless lifecycle host and parent-process contract
├── ui/           ImGui chrome, docking, theme, fonts, and views
├── hyperion/     Vendored analysis/decompiler engine (`hype` namespace)
├── core/
│   ├── infra/    Lifecycle, jobs, settings, paths, events, onboarding
│   ├── process/  Targets, processes, modules, threads, heaps, handles, dumps
│   ├── memory/   Scanner, AOB, pointers, snapshots, watch service
│   ├── disasm/   PE/Zydis indexes and Hyperion session bridge
│   ├── debugger/ Call-stack unwinding (used by ps4_* frame walks)
│   ├── runtime/  PS4 (ps4debug-NG) backend + hidden user-mode test fixture
│   ├── analysis/ Packer, signatures, xray, patches, devirt, Magicmida
│   ├── emu/      Unicorn execution and taint propagation
│   ├── network/  Raw-socket capture, traffic store, proxy, WinHTTP
│   ├── mcp/      MCP schemas, tool dispatcher, `/api`, `/events`
│   └── ...       Types, RTTI, persistence, scripting, filesystem
├── target/       Deterministic live-analysis fixture
├── tests/        Core test harness
└── live/         Live probes and integration utilities
app/              Tauri v2 supervisor and React/TypeScript frontend
tools/            Build, Magicmida, and live-test scripts
```

Tauri supervises a separate C++ engine instead of linking it into Rust, avoiding
static/dynamic CRT mixing and providing crash isolation. The PS4 backend lives
in `slop_core` and speaks the ps4debug-NG wire protocol directly, so no payload
or driver is loaded on the analysis PC.

## Runtime data

Application state lives under `%LOCALAPPDATA%\reverse-slop`:

| Path | Purpose |
|---|---|
| `settings.json` | MCP and runtime settings |
| `engine.json` | Live engine PID/port/token advertisement; removed on clean exit |
| `dock.ini` | ImGui layout |
| `sessions.db` | SQLite snapshots and key/value state |
| `symbols\<hash>.json` | Per-binary names, comments, and bookmarks |
| `sessions\` | Session artifacts |
| `crashes\` | Crash artifacts |
| `tools\magicmida\...` | Optional Magicmida installation |

Do not publish `engine.json` if bearer token is configured.

## Tests

Build includes deterministic `SlopTarget.exe` and `slop_tests.exe` by default.
Run full suite:

```powershell
.\build\tests\slop_tests.exe
```

Or through CTest:

```powershell
ctest --test-dir build --output-on-failure
```

Filter tests by case-name substring:

```powershell
$env:SLOP_TEST_FILTER = 'decomp'
.\build\tests\slop_tests.exe
Remove-Item Env:SLOP_TEST_FILTER
```

Test coverage includes infrastructure, memory, disassembly, the PS4 backend
(fake ps4debug-NG server) and its `ps4_*` MCP flows, MCP wire/schema, analysis,
emulation, network capture store, persistence, RTTI/types, Lua, module dumping,
Hyperion/decompilation, Mach-O/`.ipa` loading, Xray/patching, Magicmida
supervision, and filesystem/web/PKI helpers.

`tools/mcp_live_test.py` is a destructive-capable integration battery intended
for a controlled local fixture with a running engine and loaded `SlopTarget`.
Review paths and actions before running it; it exercises writes, patches,
filesystem operations, and network calls.

## Troubleshooting

### Configure cannot download dependencies

First configure requires HTTPS access to pinned upstream archives/repositories.
Retry with network/proxy access available. Once populated,
CMake uses `_ext/` with disconnected updates.

### `Visual Studio 2022 with C++ tools not found`

Install Desktop development with C++, verify `vswhere.exe` exists under Visual
Studio Installer, and ensure x64 C++ tools are selected.

### Port 8765 is busy

Engine falls back to an ephemeral port and records it in `engine.json`. Use
`--port <n>`, change `mcp_port`, or stop the process owning 8765. Automatic
onboarding is skipped on fallback ports.

### Tauri cannot find engine

Build C++ target first:

```powershell
powershell -File tools/build.ps1
```

Expected development path:

```text
build\src\engine\reverse-slop-engine.exe
```

### Hyperion-dependent calls fail

Call `disasm.loaded` and wait until `image.hype.ready` is true. Use
`image.hype.progress` and `image.hype.error` for state. Reload image to restart
analysis after `disasm.analyze_stop`.

### Magicmida unavailable

Run installer or set path overrides, then call `devirt.themida_status` before
starting a job.

## Security notes

- HTTP services bind only to `127.0.0.1`.
- Empty MCP token means no authentication; any local process can then invoke
  mutation-capable tools. Configure a bearer token on shared or untrusted
  workstations.
- `/api` browser origins are restricted to Tauri and fixed Vite development
  origins. Non-browser local clients are still governed by loopback and bearer
  authentication.
- Filesystem, web, script, debugger (`ps4_*`), patch, network capture, proxy,
  and memory tools can change analysis-host or console state. Expose MCP only
  to trusted clients.
- Keep analysis isolated from production and personal systems; use disposable
  virtual machines and snapshots for untrusted samples.

## Project status

reverse-slop is version `0.1.1` and Windows-only. APIs and analysis output may
change. No root project license file is currently present; do not assume a
license for reverse-slop itself. Third-party components retain their own
licenses, and separately downloaded Magicmida/ScyllaHide components are GPLv3.
