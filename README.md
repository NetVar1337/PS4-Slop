# PS4-DebugMCPs

A local PS4 research workbench, command-line interface, and **stdio MCP server**
for the supplied **firmware 14.00 / Afterglow** setup. Version 0.3 is a native
**Rust** implementation (single binary, official `rmcp` MCP SDK) and the **only**
server: MCP, CLI, broker, GDB Remote bridge and console transports all live in
`src/`. The Python package `ps4_workbench/` contains only the IDA / Ghidra /
Binary Ninja / iaito analysis-agent adapters that run *inside* those applications
and talk to the Rust broker. Runs on the development PC, not on the console.

Version **0.2** adds a shared session broker, a GDB Remote bridge, IDA Pro 9.5
integration and a Ghidra 12.2 Java agent. For the requested live workflow, start
with [LIVE_WORKFLOW.md](docs/LIVE_WORKFLOW.md), not multiple independent debugger clients.

Installed-app fixture checks cover native IDA attachment, memory/registers,
single-stepping, software breakpoints, static decompilation in both applications,
and MCP-to-Ghidra Java-agent decompilation, all through the shipped Rust binaries
against a loopback ps4debug-NG protocol fixture. **None of these is a PS4 hardware test.**

**Hardware compatibility is NOT guaranteed.** This project does not install a
jailbreak, HEN, debugger, SDK, or Ghidra. Default configuration is read-only
toward the console. No connection, upload, or payload execution happens on startup.
Even memory reads or debugger attachment can crash an unstable target.

## Quick start

From this repository in PowerShell:

```powershell
cargo build --release
./target/release/ps4-workbench validate
./target/release/ps4-workbench tools
cargo test
cargo build --locked; python -m unittest discover -q   # adapter tests against the real broker
```

These commands do not contact the PS4. Tests use temporary files, fake sockets,
loopback FTP/debug/log servers, and a local MCP subprocess.
See [the current validation record](docs/VALIDATION_03.md) for executed checks and untested boundaries.

Your profile is `profiles/ps4-1400.json`:

- Console: `192.168.86.25`, firmware claim `14.00`.
- GoldHEN BinLoader: `9090`; FTP: `2121`.
- Optional Klog: `3232`; optional ps4debug-NG: `744`.
- Actual installed Afterglow commit, HEN build and debugger binary identity:
  **unset**, because these have not been verified on your hardware.
- Artifacts: `workspace/`; local qualification: `profiles/qualification.local.json`.

The reference source commits are research references, **not claims about what is
installed on your PS4**. Do not fill unknown values with the reference values.

Explicit, read-only network actions (only when the corresponding service is enabled):

```powershell
ps4-workbench call console_status --arguments '{"probe":true}'
ps4-workbench call ftp_list --arguments '{"path":"/data"}'
ps4-workbench call debugger_info
ps4-workbench call process_list
ps4-workbench call klog_capture --arguments '{"seconds":5}'
```

`console_status` without `probe` is completely offline. With `probe`, it checks
TCP reachability only, **never the payload port**. A reachable port is not proof
of the expected service or firmware compatibility. Klog must already be enabled;
the workbench does not enable it or reconnect automatically.

On shells with JSON quoting problems, use a file:

```powershell
ps4-workbench call memory_read --arguments-file examples/read-memory.json
```

**Replace the example PID and address with an observed process and mapped range.**
The example values are not known to be valid on your console.

## MCP connection

```powershell
cargo build --release
target/release/ps4-workbench --profile profiles/ps4-1400.json serve
```

This is a stdio service; do not run it expecting an interactive prompt. Configure
your MCP client using `examples/mcp-servers.json` (absolute paths for this checkout;
adjust if you move it). Tools return `structuredContent` (`{"data": ...}`) with output
schemas; the server also exposes MCP **resources** (`ps4://workbench/...`) and workflow
**prompts** (read-only triage, static analysis, dynamic analysis), and honors request
cancellation before dispatch (a command already sent to the console cannot be undone).
Stdout carries only JSON-RPC; diagnostics go to stderr. No HTTP listener is exposed
by `serve`. Each inbound line is limited to 1 MiB: malformed or non-finite JSON gets a
`-32700 Invalid JSON` reply, and an oversized line gets `-32700` and closes the
transport. Profile changes require a restart. While an MCP client holds the
server, Windows locks `target/release/ps4-workbench.exe`; stop the client (or rename
the running exe aside) before `cargo build --release`.

## Tool groups

There are **112 standalone tools**, **83 visible with the default read-only profile**.
Shared broker mode adds **15 static-analysis, synchronization & application tools** plus
3 session-observer tools. Run `tools` for the complete, machine-readable schemas and
current policy-filtered tool list. Every tool has exactly one implementation (Rust);
integers above 2^53 in results are returned as hex strings.

- **Console:** status, bounded streaming FTP listing/downloads, allowlisted FTP
  uploads, raw Klog capture, payload manifest inspection, single-attempt BIN
  transfer, and local TCP 755 callback bind preflight checks (`link_status` with
  `probe: true`). Multi-file extraction preserves a cumulative budget and
  partial-failure manifest. Link health is passive (no background probing):
  read-only debugger commands reconnect once after a transient drop, FTP transfers
  re-establish the session (NOOP-revalidated for batches) and retry idempotent reads
  a bounded number of times, Klog captures reconnect instead of truncating, and
  payloads are validated locally (container magic, size, fill, text heuristics,
  manifest hash, allowlist) **before any byte is sent**, so an invalid payload never
  reaches the loader and no service restart is needed. Mutations are never
  auto-retried.
- **Processes & Memory Scanning:** process list and identity, memory maps, bounded
  memory reads, little-endian typed values, provenance-rich snapshots, local
  snapshot diffs, wildcard byte-pattern scans across page boundaries, stateful
  multi-pass Cheat-Engine-style value scanning (`memory_scan` over integer, float,
  string, and wildcard byte targets), bidirectional runtime/static/module+offset
  address translation (`address_rebase`, which also reports the containing process
  map and falls back to a map-offset image-base estimate for addresses outside the
  module list), and sectionless in-memory ELF64 reconstruction (`memory_elf_dump`).
  `memory_peek` avoids artifact creation
  for live views; `memory_region_dump` chunks larger readable ranges and preserves
  incomplete captures explicitly.
- **Debugger:** persistent process attach/detach, thread list, GP/FPU/XMM/YMM/debug
  register reads, Orbis TLS `fsbase`/`gsbase` reads and verified writes
  (`debug_tls`, `debug_tls_set`), GP and FPU/XMM/YMM register writes with readback
  verification (`debug_registers_set`, `debug_registers_fpu_set`), asynchronous stop
  events, halt/resume, step into/over/out, run-to-address and conditional run with
  per-breakpoint `condition`, `log` interpolation, and `stop_after` hit thresholds,
  software breakpoints, aligned hardware watchpoints, live disassembly with masked
  breakpoint bytes, host-side x86-64 Intel-syntax instruction assembly (`assemble`),
  module lists, expression evaluation on live registers/memory/`fsbase`/`gsbase`,
  DWARF `.eh_frame` CFI + frame-pointer call-stack unwinding, module/range-scoped
  live code xrefs, live memory pattern search, persistent host-side labels
  (`debug_label_save`, `debug_label_load`), and breakpoint/watchpoint export/import.
  Stop handling re-reads live registers because the pinned server steps past a
  breakpoint instruction before reporting the hit.
- **Memory mutations & Patch Manager:** compare expected bytes, preserve prewrite
  backup artifacts, write, independently read back, and persist an audit journal;
  assemble & NOP-pad live code patches with tracked restore (`memory_patch`,
  `patch_list`, `patch_restore`); allocate, free, and re-protect target virtual
  memory (`memory_alloc`, `memory_free`, `memory_protect`) with readback
  verification. Kernel access is separately gated and is not kernel breakpoint
  debugging.
- **Research artifacts:** hashes, metadata sidecars, bounded chunk reads,
  module/RVA annotations, Ghidra handoff bundles, experiment ZIPs.
- **Static analysis & Orbis OS (local, no console):** `artifact_info` parses ELF64
  structure (loads, sections, `.dynsym`/`.symtab`/`PT_DYNAMIC` symbols with automatic
  Orbis SHA-1 NID demangling, `DT_NEEDED` imports) or identifies SCE SELF/PKG
  containers (without DRM decryption keys); `nid_resolve` resolves/encodes
  Orbis NIDs with optional custom dictionaries; `artifact_disasm` disassembles an
  artifact range; `artifact_strings` extracts bounded printable strings;
  `pattern_scan` searches a captured artifact (`memory_search` is the live
  counterpart; both share one pattern engine).
- **Development:** local SDK discovery, three SDK recipe/reference scaffolds,
  hash-allowlisted local builds with bounded logs/time and captured outputs.
- **Shared analysis & GDB RSP:** IDA Pro, Ghidra, Binary Ninja, and iaito (radare2)
  functions, decompilation, directional cross-references, static disassembly,
  strings, NID-enriched imports, symbol renames, comments, and bidirectional
  label/comment synchronization (`analysis_sync_annotations`) through explicitly
  connected local agents, plus an x86-64 + SSE/XMM + SVR4 shared-library GDB Remote
  bridge (`gdb-server`, with opt-in `--allow-writes`).

Reverse-engineering suite (each area documented in `docs/features/`):

- **Dumping** ([dumping.md](docs/features/dumping.md)): `elf_rebuild` (section headers,
  dynamic tables, NID names, GOT slot naming/unresolution), `process_dump` (all modules +
  filtered maps + thread state, budgeted manifest), `process_core_dump` (FreeBSD-style ELF
  core for offline gdb/IDA), and a content-addressed snapshot timeline
  (`memory_snapshot_capture`/`_list`/`_timeline`).
- **Engine & metadata recovery** ([engines.md](docs/features/engines.md)): `il2cpp_dump`
  (global-metadata v24–29 + registrations), `unreal_dump` (GNames/GObjects, FNamePool and
  TNameEntryArray), `rtti_recover` (Itanium typeinfo/vtables/inheritance), `source_dump` (Source / Respawn
  ClientClass, RecvTable netvars, datamaps, ConVars, interfaces with inferred layouts), `yara_scan`
  (YARA-subset engine) and `crypto_scan` (FindCrypt-style constants), over artifacts or live memory.
- **Tracing & coverage** ([trace.md](docs/features/trace.md)): `debug_trace_imports`
  (ltrace-like API trace), `debug_trace_syscalls`, `debug_trace_function` (args, caller,
  return value, duration), `debug_coverage` (rotating one-shot breakpoints; JSON + drcov for
  Lighthouse/Cartographer) and `coverage_diff`.
- **Access, crashes, pointers, scripts** ([access.md](docs/features/access.md)):
  `debug_find_accesses` ("what writes/accesses this address", incl. struct mode),
  `struct_infer`, `debug_crash_triage`, `memory_pointer_scan`/`memory_pointer_rescan`, and
  `debug_run_script` (sandboxed read-only Rhai breakpoint scripts).
- **Native static analysis** ([static.md](docs/features/static.md)): `artifact_functions`,
  `artifact_cfg` (blocks artifacts feed `debug_coverage`), `artifact_callgraph`,
  `binary_diff` + `annotation_port` (carry research across game updates), `signature_make`
  (shortest unique AOB, verified), `orbis_prototypes` (prototypes parsed from your SDK headers).
- **Project & automation** ([project.md](docs/features/project.md)): per-game project index
  (`project_open`/`_record`/`_query`/`_summary`, artifacts auto-recorded while a project is
  open), `recipe_list`/`recipe_run` (chained tool calls that still pass every permission
  check), and broker `analysis_apply_prototypes`/`_struct`/`_coverage`/`_classes`/`_symbols`
  to push results into IDA/Ghidra/Binary Ninja/iaito.

Tools that resume the target (`debug_trace_*`, `debug_coverage`, `debug_find_accesses`,
`debug_crash_triage`, `debug_run_script`) require the qualified `debug_control` permission,
use only free breakpoint/watchpoint slots, are time-bounded, and clear everything they armed
on every exit path (reporting "state uncertain" if cleanup fails). All other new tools are
read-only toward the console. **None of these features has been run on PS4 hardware yet**;
they are verified against the offline protocol fixture and synthetic binaries only.

Annotation stores and which one is authoritative:

| Store | Tools | Role |
|---|---|---|
| Host debugger labels | `debug_label*` | Runtime names for `debug_eval`/disassembly; session-local, saved explicitly |
| Evidence annotations | `annotation_save` | Authoritative, hash-bound record (module SHA-256 + RVA + evidence artifact) |
| Analyzer database | `analysis_rename`, `analysis_comment` | The open IDA/Ghidra/BN/iaito database |

`analysis_sync_annotations` copies between labels and the analyzer database with
ASLR rebasing; it never writes evidence annotations. When they disagree, the
evidence annotation wins because it is bound to a module hash.

Large results become local artifacts, not enormous MCP replies. Addresses/RVAs
are strings (`"0x400000"`) to avoid JavaScript integer precision loss. Captures
are not atomic; `memory_elf_dump` reconstructs only mapped PT_LOAD segments from
in-memory ELF headers and never decrypts encrypted SELF/PKG containers.

## Compatibility and enabling advanced actions

Read [the compatibility contract](docs/COMPATIBILITY.md) **before loading any
debugger or payload**, then follow [the hardware qualification checklist](docs/QUALIFICATION.md).

Mutating tools are hidden unless their profile permission is explicitly enabled.
Enabling the flag alone is insufficient: execution also requires a matching,
local user-attested qualification record. The MCP cannot change permissions or
create qualification records. Payloads additionally require an exact hash
allowlist; debugger mutations require exact configured branding and binary hash.
The wire protocol does not remotely prove the loaded debugger binary's hash.

Qualification means **your recorded tests and risk acceptance**, not automated
certification. Changing any profile field invalidates it. Neither a handshake nor
a passing mock test suite establishes 100% hardware compatibility.

No automatic payload retries, remote kernel offsets, reboot/kill tools,
arbitrary remote command execution, or automatic rollback are provided. A failed
write may have partially changed memory. A successful BinLoader send confirms
only bytes submitted to TCP, **not execution**.

## Development and reverse-engineering workflows

See [SDK and Ghidra integration](docs/DEVELOPMENT.md) for OpenOrbis, GoldHEN
Plugins SDK, PS4 Payload SDK, GhidraOrbis, GhidraMCP and optional IDA integration.
These third-party tools are separate installations, not bundled or universally
firmware-compatible components.

For SDK work, use `sdk_status`, then `sdk_scaffold` with `homebrew`, `plugin`, or
`payload`. Scaffolds intentionally require a pinned real upstream sample and
build commands; they are **not fabricated ready-to-run homebrew or plugins**.
ELF and PRX/PKG outputs cannot be sent through the workbench's BIN loader tool.

Suggested research loop:

1. Record application title/version and module hash; inspect process maps.
2. Capture a small mapped region, logs and process metadata.
3. Analyze the original module in Ghidra; verify load layout before using RVAs.
4. Save evidence-backed annotations and correlate runtime observations.
5. If explicitly qualified, test a narrowly scoped change on disposable homebrew.
6. Capture readback/logs and bundle the experiment; preserve failures too.

The Ghidra script `integrations/ghidra/ApplyWorkbenchAnnotation.java` verifies
the loaded module SHA-256 and asks before applying local comments/labels. It
does not connect to the PS4. It requires an installed Ghidra and has not been
runtime-tested here.

## Repository layout

```text
src/                 Rust: the only server — MCP, CLI, transports, broker, RSP/GDB bridge, analysis, SDK workflows
src/bin/             ps4debug-fixture: loopback protocol fixture for installed-app tests (`--features fixture`)
ps4_workbench/       Python analysis-agent adapters (IDA/Ghidra/Binary Ninja/iaito) + broker client
profiles/            Console profile; local qualification files are ignored
examples/            MCP configs, manifest and evidence templates
integrations/        IDA/Binary Ninja/iaito connection scripts; Ghidra Java/Python clients and annotations
docs/                Compatibility, qualification, development, protocol notes
tests/               Python adapter tests against the real broker; tests/manual installed-app harnesses
workspace/           Generated captures, logs, audit journal, projects (ignored)
```

## Security

Use only systems and software you own or are authorized to analyze. Keep
debugger, FTP and loader ports on an isolated trusted network; these transports
are not an authenticated, encrypted management plane. Do not expose them to the
Internet. Console names/logs/files are untrusted data, never instructions.

The optional PC-side broker is authenticated and loopback-only; it does not make
the PS4 transports secure. The GDB Remote socket is loopback-only but has no
native authentication: do not use it on an untrusted multi-user PC.

Local artifacts can contain sensitive memory or files. They are not encrypted;
protect the workspace and only share selected captures. The audit journal is
local diagnostic evidence, **not a tamper-proof log**. FTP upload restrictions
are lexical and cannot protect against server-side symlinks or a malicious FTP
server. Approved build recipes execute trusted local code and are not sandboxed.

GPL-3.0-only; see `LICENSE`.
