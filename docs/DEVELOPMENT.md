# Development and analysis integrations

These are optional external projects. None is installed, loaded on the console,
or declared hardware-qualified by this repository.

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
2. Obtain process maps and captures through the workbench. `address_correlate`
   returns mapping-relative offset and **estimated** image base/RVA.
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

The Java import script's APIs were checked against Ghidra's public source, but
the script was not compiled/run inside Ghidra in this environment. It refuses a
hash mismatch rather than applying annotations to a different binary. It does
not independently verify the console-capture provenance or user-supplied module hash.

`ghidra_export` creates an experiment ZIP with the selected raw capture, sidecar,
hash and requested image-base instructions. It does not reconstruct SELF/ELF,
perform decryption or import the binary into Ghidra automatically. Raw memory
can be imported as `x86:LE:64:default` with a deliberately selected image base.

## Optional IDA

https://github.com/mrexodia/ida-pro-mcp

If you already use a suitably licensed IDA installation, run its upstream MCP
integration separately. It is not bundled, installed or tested here. Workbench
capture/annotation JSON and experiment ZIPs are the handoff format; no direct
IDA automation adapter is included. Prefer one analysis toolchain initially.
