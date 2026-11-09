# Resident payload internals

Resident ELF payloads staged into a game process with ps4debug-NG
`CMD_PROC_ELF_RPC`, plus the small RPC control plane that drives them.
Game-specific offsets and features live in versioned target manifests, never in
the server.

## Tools (catalog `internals`)

All require the `process_inject` profile permission, a matching qualification
record, and a payload hash in the qualification's `payload_sha256_allowlist`.
The `debug` toolset does not expose them; use `full`.

| Tool | Role |
|---|---|
| `payload_stage` | Verify target identity + executable-text SHA-256 + fingerprints + pointers, refuse duplicate residency, upload the ELF via `CMD_PROC_ELF_RPC`, verify the relocated RPC signature, poll RPC status until ready (10 s deadline) |
| `payload_recover` | Revalidate the target and find the resident RPC signature in anonymous RWX maps without uploading again |
| `payload_status` | RPC command 0: lifecycle, initialization stage, heartbeat |
| `payload_rpc` | Bounded numeric command on the resident RPC entry (never an arbitrary address) |
| `payload_shutdown` | RPC command 2 |
| `payload_run` | One-shot ELF execution through `CMD_PROC_ELF` (0xBDAA0007): ELF/hash validation, then the server spawns the raw entry. No target manifest or RPC symbol needed. Not for resident RPC payloads |
| `process_call` | Call a fingerprint-pinned function through the RPC stub (`CMD_PROC_CALL`, six SysV args). The manifest must pin the call address; expected bytes are re-verified before every call |

`memory_scan_server` (base catalog) adds server-side exact-value scans through
`CMD_PROC_SCAN` (0xBDAA0009): every readable map, value-width stepping,
sentinel-terminated address stream. `process_find` resolves PIDs by name
substring. Both are read-only.

The target manifest is a `ps4wb-internals-target-v1` JSON artifact: `name`,
`title_id`, `process_name`, `process_path`, `application_version`,
`executable_text_sha256`, `status_magic`, up to 64 `fingerprints`
(`address` + expected `hex`) and 64 `pointers` (`address` + `expected`).
The payload must be a little-endian x86-64 `ET_DYN` ELF with one exported,
executable `payload_rpc_entry` symbol. The raw image entry is never called by
the host; only the relocated RPC entry is invoked through one cached RPC stub
per PID. No automatic retries: an uncertain upload requires manual recovery.

## Payload headers (`internals/include/internals/`)

- `runtime.hpp`: the shared RPC ABI (`RpcCallbacks`, `Runtime`, `Lifecycle`),
  config/telemetry words, and the callback gate for quiescent hook removal.
  RPC command numbers (verified against the Apex-PS4 dispatch): 0 = status,
  1 = features, 2 = shutdown, 3 = initialization stage, 4 = write config word,
  5 = read config word, 6 = read telemetry word.
- `verify.hpp`: `internals::verify_module(base, kVerifyChecks, kVerifyCheckCount)`
  compares module-relative fingerprints exported by `project_export_offsets`
  and fails closed on any mismatch. Call it once from the payload's own thread
  at startup, never from an RPC handler.

## End-to-end loop (offsets → payload → control)

1. `project_open` for the game, then dump/annotate: `process_dump` /
   `memory_elf_dump` + `elf_rebuild`, `source_dump`/`unreal_dump`,
   `signature_make`, `annotation_save`. Across updates: `binary_diff` +
   `annotation_port`.
2. `project_export_offsets` → `offsets.hpp` + `ps4wb-offsets-v1` manifest.
   `project_export_target` additionally emits a ready-to-stage
   `ps4wb-internals-target-v1` manifest: identity from the project/module
   records, absolute-address fingerprints from annotations and optional
   `signature_sites` (RVAs verified unique by `signature_make`), with bytes
   taken from the recorded dump. Unproven sites are skipped, never fabricated.
3. Build the payload against `internals/` with the OpenOrbis + LLVM toolchain
   (`scripts/setup-toolchain`); e.g. `Fortnite-PS4/Makefile`.
   `internals/src/runtime.cpp` is the reference implementation of the runtime
   ABI (status/features/config/telemetry, `CallbackGate`); new game payloads
   link it instead of re-implementing the dispatcher.
4. Qualify: enable `process_inject` in the local profile and add the ELF hash to
   the allowlist via `qualify --payload-sha256 ...`.
5. `scripts/start-broker` (or `serve`), then
   `python -m ps4_mcp.ctl ... stage --pid N --target T --payload P --sha256 H`,
   `rpc --command 1 --argument <bits>` to arm features, `payload-status` to
   observe, `config get|set` / `telemetry` for the config and telemetry words,
   `watch` for heartbeat monitoring, `shutdown` to retire.

### Game-update porting loop

When the game updates, the payload hash changes by design:

1. `recipe_run` `offset_refresh` (dump new build → `elf_rebuild` →
   `binary_diff` → `annotation_port` → `project_export_offsets`) with the old
   annotated build and its annotations as inputs.
2. `project_export_target` with the new module hash and any re-verified
   `signature_sites` to produce a fresh target manifest.
3. Rebuild the payload (`make`), re-run `qualify --replace` with the new ELF
   SHA-256 in the allowlist, then `stage_and_verify` to stage and arm features.
4. On a fault, `payload_crash_bundle` captures triage + Klog into one experiment
   bundle; `payload_recover` re-finds the resident RPC entry without re-uploading.

### Full pipelines per game

- `recipe_run` `unreal_pipeline` (Fortnite): dump → `elf_rebuild` →
  `unreal_dump` → `engine_sdk_export` (ue4::Offsets header) →
  `project_export_offsets` → `project_export_target`.
- `recipe_run` `source_pipeline` (Apex Legends): dump → `elf_rebuild` →
  `source_dump` → `engine_sdk_export` (netvar/datamap header) →
  `project_export_offsets` → `project_export_target`.
- `recipe_run` `deep_dump`: dump → `elf_rebuild` → functions → RTTI →
  Orbis import prototypes, one full RE pass.
- `offset_scan` ([offsetscan.md](offsetscan.md)) verifies offsets live and
  relocates moved signatures; `module_integrity` diffs dump vs disk.

`python -m ps4_mcp.ctl update --game fortnite|apex --pid N` runs the whole
loop: the pipeline recipe (or `offset_refresh` with `--old-artifact` +
`--annotations`), builds the payload locally, hashes it, and prints the exact
`ingest` / `qualify --replace` / `stage_and_verify` commands. Qualification
stays a human checkpoint; `--dry-run` prints the plan without any console calls.

The new code paths are covered by offline fixture and synthetic-binary tests
only; hardware qualification is your own recorded testing, not a compatibility
guarantee.
