# Development and analysis integrations

The connected development workflow, buildable payload scaffolds, evidence-bound
SDKs, and resumable update CLI are documented in [PROJECT_PIPELINE.md](PROJECT_PIPELINE.md).

These SDKs and third-party MCP projects are optional. This repository does not
automatically install them or declare their console output hardware-qualified.
The already-installed IDA and Ghidra applications are used by the local tests.

For the implemented live IDA Pro 9.5 / Ghidra 12.2 connections, shared broker,
native GDB bridge and built-in static agents, see `LIVE_WORKFLOW.md`. The
third-party MCP integrations below are optional alternatives, not prerequisites.

## OpenOrbis homebrew

https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain

Use its documented installation and real samples. Set `OO_PS4_TOOLCHAIN` on
your development host. `sdk_status` reports the variable and compiler/tool paths;
presence is not validation. The workbench does not download Sony SDK components.

`sdk_scaffold` with `kind: homebrew` creates an empty, deliberate recipe/reference
workspace. Copy a real upstream sample at a pinned commit and use its build flow.
Do not assume a compiled package can be installed through a raw TCP loader.

## GoldHEN plugins

https://github.com/GoldHEN/GoldHEN_Plugins_SDK
https://github.com/GoldHEN/GoldHEN_Plugins_Repository

The SDK documents OpenOrbis and LLVM dependencies. Use actual SDK examples and
pin their versions; set `GOLDHEN_SDK` for local discovery. Scaffold with `plugin`.
Game hooks and patches depend on the exact application build and HEN. Generated
PRX files must not be sent as BIN payloads. Plugin loading/enabling remains a
separate, manually qualified console operation; no arbitrary plugin is activated.

## PS4 Payload SDK

https://github.com/ps4-payload-dev/sdk

Set `PS4_PAYLOAD_SDK` and scaffold with `payload`. Its published supported-firmware
list omits 14.00 at the research date; treat its runtime output as unsupported
until independently ported/qualified. This workbench offers build/export plumbing,
not a 14.00 port, compatible ELF loader, or unsafe BIN conversion.

## Payload build toolchain and control plane (scripts/)

`scripts/setup-toolchain.sh` (Linux/WSL) and `scripts/setup-toolchain.ps1`
(Windows) install a working payload compiler without building LLVM from source:

1. **OpenOrbis PS4 SDK** (headers, NID link stubs, `link.x`, `crt1.o`) from a
   pinned release archive with a pinned SHA-256 — v0.5.3 `toolchain-llvm-18.2.zip`
   on Windows (its nested tar.gz is handled), v0.5.4 `toolchain-llvm-18.tar.gz`
   on Linux — into `~/.local/openorbis-ps4-toolchain`.
2. **Vanilla LLVM clang/ld.lld** (`winget install LLVM.LLVM` on Windows,
   `apt install clang lld` on Debian/Ubuntu); the scripts verify they exist.
3. A **ps4-payload-sdk-style shim** at `~/.local/ps4-payload-sdk/bin/orbis-clang`
   (`.cmd` on Windows) so `Injector-PS4`'s `make elf PS4_PAYLOAD_SDK=...` works
   unchanged, and `orbis-clang++`.

Verified end-to-end on the development PC by compiling and linking
`Fortnite-PS4/src/payload.cpp` into an `ET_DYN` x86-64 ELF with an exported
`payload_rpc_entry` (see [features/internals.md](features/internals.md)).
Set `OO_PS4_TOOLCHAIN` to the SDK root; `sdk_status` reports it.

- `scripts/setup-profile` copies `profiles/ps4-1400.json` to the ignored
  `profiles/ps4-1400.local.json` and optionally sets the console host.
- `scripts/qualify-local` runs `cargo test`, the Python suite and `validate`,
  then invokes the real `qualify` CLI with your evidence/attestation/approvals.
- `scripts/start-broker` starts the shared broker (default port 24600);
  `python -m ps4_workbench.ctl` is the host control plane against it
  (`status`, `tools`, `call`, `preflight`, `stage`, `recover`, `payload-status`,
  `rpc`, `features`, `shutdown`, `export-offsets`).

None of these scripts contacts the console by itself.

## Build recipes

Each scaffold creates `workspace/projects/NAME/recipe.json`:

```json
{
  "sdk": "homebrew",
  "source_commit": "REPLACE_WITH_REAL_40_HEX_COMMIT",
  "commands": [["cmake", "--build", "build", "--config", "Release"]],
  "output": "build/REPLACE_WITH_ACTUAL_OUTPUT.pkg",
  "environment": {},
  "timeout_seconds": 120
}
```

This is a format example, **not a ready build command**: configure/copy your
upstream sample first and supply its actual commands/output. Recipes accept
1–16 argv arrays, not shell strings. Use native executables; `.bat`/`.cmd` wrappers
are rejected. Recipes may explicitly invoke tools such as CMake or Python and
must be reviewed as code with full local access.

Hash the complete recipe, approve that hash locally using the qualification
procedure, then invoke `sdk_build` with `recipe` and `sha256`. No compiler runs
at server startup or during `sdk_status`. An existing declared output is refused
to avoid mistaking an old file for a fresh build: archive/remove it locally before
the next build. Outputs must resolve inside the project directory.

Logs and wall-clock time are bounded for the foreground process. Recipes must
not spawn detached/background children; this runner is not an OS sandbox or a
process-tree resource controller. Successful outputs and logs are captured with
hashes; they are **never deployed automatically**. Review the output type and
use a separate, explicitly qualified transfer. Local-build tests use a tiny
Python fixture, not actual PS4 SDK compilation.

## Ghidra and Orbis

https://github.com/NationalSecurityAgency/ghidra
https://github.com/astrelsky/GhidraOrbis
https://github.com/LaurieWired/GhidraMCP

Install compatible versions of Ghidra and the Orbis extension, and install the
GhidraMCP extension/bridge according to its upstream instructions. Reference
GhidraMCP commit used for the CLI configuration example:
`1e980252087b2479a21b9ca6d82d5829538651a7`.

`examples/ghidra-mcp-server.json` runs the **separate**, already-installed bridge
via `python -m ghidra_mcp --ghidra-server http://127.0.0.1:8080/ --transport stdio`.
Replace its placeholder interpreter path. Keep the bridge backend on loopback;
do not expose it directly to the console network. External MCP tool permissions
are separate from this workbench's console permissions.

Research loop:

1. Analyze the authorized original module and retain its SHA-256/application version.
2. Obtain process maps and captures through the workbench. `address_rebase` with a
   `runtime_address` returns the module/RVA, the containing map's relative offset,
   and (for addresses outside the module list) an **estimated** image base/RVA with
   `basis: process_maps_estimate`; pass `module_sha256`/`application_version` to
   record provenance.
3. Verify ELF segment layout manually. Mapping offsets are not proof of a module
   image base; similarly named maps may be distinct mappings.
4. Use `annotation_save` to record a module SHA-256, RVA, evidence artifact,
   comment and optional simple symbol. This saves a local JSON annotation only.
5. Add `integrations/ghidra` to Ghidra's Script Manager script directories and
   run `ApplyWorkbenchAnnotation.java` against the actual annotation JSON,
   **not the `.json.json` metadata sidecar**. It verifies the loaded program's
   executable SHA-256, checks the computed address and asks before editing.
6. Use the separate GhidraMCP server for interactive decompilation, references,
   symbols and analysis, with the permissions you explicitly choose there.

The annotation-only Java import script's APIs were checked against Ghidra's public source, but
the script was not compiled/run inside Ghidra in this environment. It refuses a
hash mismatch rather than applying annotations to a different binary. It does
not independently verify the console-capture provenance or user-supplied module hash.

`ghidra_export` creates an experiment ZIP with the selected raw capture, sidecar,
hash and requested image-base instructions. It does not reconstruct SELF/ELF,
perform decryption or import the binary into Ghidra automatically. Raw memory
can be imported as `x86:LE:64:default` with a deliberately selected image base.

## Binary Ninja and iaito (radare2)

Both register as read-only static-analysis agents (`target: "binja"` /
`"iaito"`) for `analysis_functions`, `analysis_decompile` and
`analysis_xrefs`, exactly like the IDA/Ghidra agents. Discovery is reported by
`desktop_status` via `PS4_BINJA_DIRECTORY` / `PS4_IAITO_DIRECTORY`.

- **Binary Ninja:** `ps4_workbench/adapters/binja.py`. Run
  `integrations/binja/ps4_connect.py` inside Binary Ninja's Python (plugin /
  Script Manager, where the open view is the global `bv`), or headless with
  BN's bundled Python: `bv = binaryninja.load(path)` then `connect(bv)`.
  Decompilation uses HLIL (falls back to MLIL/LLIL); xrefs use
  `get_code_refs_to`. The input SHA-256 is verified before every job.
- **iaito/radare2:** `ps4_workbench/adapters/iaito.py`, driven through r2pipe
  (needs `r2` on PATH and `pip install r2pipe`):
  `python integrations/iaito/ps4_connect.py D:/dumps/eboot.bin`.
  `aaa` runs once at startup; functions via `aflj`, decompilation via `pdc`
  (falls back to `pdf` disassembly), xrefs via `axtj`.

Neither launches a console connection; both refuse to answer if the input
file's hash changes while the agent runs.

## Optional IDA

https://github.com/mrexodia/ida-pro-mcp

The optional upstream IDA MCP is not bundled or installed. This repository now
also includes its own read-only IDA analysis agent and live broker client in
`ps4_workbench/adapters/ida.py`, plus the native GDB bridge. The installed IDA
Pro 9.5 adapter/decompiler and native debugger have passed fixture tests; see
`VALIDATION_02.md`. Running two independent console debugger clients is still not
supported: share the broker and one control lease.
