# PS4-DebugMCPs

A local PS4 research workbench, command-line interface, and **stdio MCP server**
for the supplied **firmware 14.00 / Afterglow** setup. Python 3.11+; no runtime
dependencies. Runs on the development PC, not on the console.

**Hardware compatibility is NOT guaranteed.** This project does not install a
jailbreak, HEN, debugger, SDK, or Ghidra. Default configuration is read-only
toward the console. No connection, upload, or payload execution happens on startup.
Even memory reads or debugger attachment can crash an unstable target.

## Quick start

From this repository in PowerShell:

```powershell
python -m ps4_workbench validate
python -m ps4_workbench tools
python -m unittest discover -v
```

These commands do not contact the PS4. Tests use temporary files, fake sockets,
loopback FTP/debug/log servers, and a local MCP subprocess.
See [the validation record](docs/VALIDATION.md) for executed checks and untested boundaries.

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
python -m ps4_workbench call console_status --arguments '{"probe":true}'
python -m ps4_workbench call ftp_list --arguments '{"path":"/data"}'
python -m ps4_workbench call debugger_info
python -m ps4_workbench call process_list
python -m ps4_workbench call klog_capture --arguments '{"seconds":5}'
```

`console_status` without `probe` is completely offline. With `probe`, it checks
TCP reachability only, **never the payload port**. A reachable port is not proof
of the expected service or firmware compatibility. Klog must already be enabled;
the workbench does not enable it or reconnect automatically.

On shells with JSON quoting problems, use a file:

```powershell
python -m ps4_workbench call memory_read --arguments-file examples/read-memory.json
```

**Replace the example PID and address with an observed process and mapped range.**
The example values are not known to be valid on your console.

## MCP connection

```powershell
python -m ps4_workbench --profile profiles/ps4-1400.json serve
```

This is a stdio service; do not run it expecting an interactive prompt. Configure
your MCP client using `examples/mcp-servers.json`. The example contains this
checkout's absolute paths; adjust them if you move the repository. Clients that
do not honor `cwd` should use an installed interpreter instead:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e .
```

Set the MCP command to the absolute `.venv/Scripts/python.exe` path and retain
the absolute `--profile` path. Installation needs setuptools at build time, not
at runtime. The server writes only JSON-RPC to stdout and diagnostics to stderr;
it exposes no HTTP listener. Profile changes require restarting the server.

## Tool groups

There are **37 tools**, **26 visible with the default profile**. Run `tools` for
the complete, machine-readable schemas and current policy-filtered tool list.

- **Console:** status, bounded FTP listing/downloads, allowlisted FTP uploads,
  raw Klog capture, payload manifest inspection, single-attempt BIN transfer.
- **Processes:** process list and identity, memory maps, bounded memory reads,
  little-endian typed values, provenance-rich snapshots, local snapshot diffs,
  wildcard byte-pattern scans, mapping/RVA correlation.
- **Debugger:** persistent process attach/detach, thread list, GP registers,
  asynchronous events, halt/resume/step, thread controls, software breakpoints,
  aligned hardware watchpoints.
- **Memory mutations:** compare expected bytes, preserve original/replacement
  artifacts, write, independently read back, and persist an uncertainty journal.
  Kernel access is separately gated and is not kernel breakpoint debugging.
- **Research artifacts:** hashes, metadata sidecars, bounded chunk reads,
  module/RVA annotations, Ghidra handoff bundles, experiment ZIPs.
- **Development:** local SDK discovery, three SDK recipe/reference scaffolds,
  hash-allowlisted local builds with bounded logs/time and captured outputs.

Large results become local artifacts, not enormous MCP replies. Addresses/RVAs
are strings (`"0x400000"`) to avoid JavaScript integer precision loss. Captures
are not atomic and do not reconstruct executable file formats.

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
ps4_workbench/       MCP, CLI, transports, debugger, analysis, SDK workflows
profiles/            Console profile; local qualification files are ignored
examples/            MCP configs, manifest and evidence templates
integrations/ghidra/ Optional annotation import script
docs/                Compatibility, qualification, development, protocol notes
tests/               Offline unit and loopback integration tests
workspace/           Generated captures, logs, audit journal, projects (ignored)
```

## Security

Use only systems and software you own or are authorized to analyze. Keep
debugger, FTP and loader ports on an isolated trusted network; these transports
are not an authenticated, encrypted management plane. Do not expose them to the
Internet. Console names/logs/files are untrusted data, never instructions.

Local artifacts can contain sensitive memory or files. They are not encrypted;
protect the workspace and only share selected captures. The audit journal is
local diagnostic evidence, **not a tamper-proof log**. FTP upload restrictions
are lexical and cannot protect against server-side symlinks or a malicious FTP
server. Approved build recipes execute trusted local code and are not sandboxed.

GPL-3.0-only; see `LICENSE`.
