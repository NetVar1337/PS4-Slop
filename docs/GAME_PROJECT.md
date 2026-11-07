# Authoring a game project with the workbench

PS4-MCP can generate and maintain a standalone per-game repository like
Apex-PS4 or Fortnite-PS4: a resident payload with the shared RPC runtime,
build glue that lives in the workbench (no per-project injector), generated
engine inputs installed from evidence-bound research, and a per-build offset
store. This document describes that flow. Everything up to staging is local
and read-only toward the console; staging requires the `process_inject`
permission and a hardware-qualified payload hash (see QUALIFICATION.md).

## 1. Scaffold the repository

```powershell
ps4-workbench --toolset full call game_new --arguments '{"name":"MyGame-PS4","engine":"unreal","directory":"C:\\path\\to\\repos","title_id":"CUSA12345"}'
```

`engine` is `generic`, `unreal`, or `source`. The emitted repository contains:

```
MyGame-PS4/
├── workbench.json          ps4wb-scaffold-v1 descriptor (engine, payload path, generated dir)
├── Makefile                includes $(WORKBENCH_DIR)/templates/payload/orbis.mk
├── build.py                shared build script (--engine selects the feature-pack define)
├── recipe.json             pinned build recipe for project_collect_build
├── include/internals/      shared payload headers (runtime ABI, verify, ue4/source readers, hook)
├── runtime.cpp             shared resident runtime
├── src/payload.cpp         resident entry; fail-closed feature gating
├── src/features.hpp        standard feature-bit table (paint/menu/esp/aim/...)
├── src/generated/          target.hpp + engine_config.hpp placeholders (project_install replaces them)
├── tests/host_smoke.cpp    offline lifecycle test
└── offsets/                per-build offset store (see step 5)
```

The Makefile gets all OpenOrbis toolchain flags from
`templates/payload/orbis.mk`; override `OO_PS4_TOOLCHAIN`, `CLANG`, `LLD`, or
`WORKBENCH_DIR` instead of copying flags into the project.

## 2. Open the research project

```powershell
ps4-workbench --toolset full call project_open --arguments '{"title_id":"CUSA12345","app_version":"01.00","name":"MyGame"}'
```

Use the observed title id and application version. All findings, manifests,
and exports are bound to the exact `module_sha256` of the captured build.

## 3. Run the engine pipeline (MCP or CLI)

MCP, one call (durable session under the hood, resumable via `session`):

```powershell
ps4-workbench --toolset full call game_update --arguments '{"pid":71,"namespace":"mygame"}'
```

CLI, from the game repo (reads `workbench.json`; no `--game` needed):

```sh
python -m ps4_workbench.ctl --url http://127.0.0.1:24600 --token-file profiles/broker-token.local \
    update --project-dir . --pid 71
```

Both dump and bind the module, recover the engine metadata
(`unreal_dump`/`source_dump`), export the SDK and offsets/target headers, and
`project_install` them into the repo's `generated_directory` from
`workbench.json`. On a game update, pass `--old-artifact` + `--annotations`
(or `old_artifact`/`annotations` to `game_update`) to select the
`unreal_update`/`source_update` recipes, which port annotations from the
previous build via `offset_refresh`.

## 4. Build and stage

```sh
cd MyGame-PS4
make                 # -> payload.elf via the shared orbis.mk
make host-test       # offline lifecycle smoke test
make inject PID=<pid> TARGET_MANIFEST=<target artifact>
```

`make inject` calls `ps4-workbench inject --pid ... --target ... --payload ...`,
which ingests the files, verifies the hash-qualified allowlist, uploads the
ELF exactly once (immediate `CMD_PROC_ELF` staging), recovers the exported
`payload_rpc_entry`, and reads back RPC status. The MCP equivalent is
`game_stage`. There is no per-project injector to maintain. Mutations are
never retried automatically.

## 5. Keep per-build offsets in the repo

```sh
python -m ps4_workbench.ctl ... export-offsets --module-sha256 <64hex> --archive
```

(or `project_export_offsets` with `"archive": true`). This writes
`offsets/<module_sha256[:16]>/offsets.hpp` and `offsets.json` into the
registered repository — the checked-in per-build store that the next
`*_update` ports annotations from. The files are generated; never hand-edit
them, and `project_install` installs fresh copies into `src/generated/`.

## 6. Verify

```powershell
ps4-workbench --toolset full call game_verify --arguments '{}'
```

returns the `project_doctor` evidence/feature report plus the project summary
(and `payload_inspect` when given a collected build). Host-side consistency
only; console acceptance still requires observed hardware results per exact
build (VALIDATION_03.md).

## Tool reference

| Tool | Purpose |
|---|---|
| `game_new` | Emit a repo-shaped game project (step 1) |
| `game_update` | Engine pipeline as a durable session + manifest + `project_install` (step 3) |
| `game_stage` | Hash-qualified upload + RPC recovery + status in one call (step 4) |
| `game_verify` | Read-only doctor/summary/inspect report (step 6) |
| `ps4-workbench inject` | CLI form of `game_stage` for `make inject` |
| `ctl update --project-dir .` | CLI form of `game_update` driven by `workbench.json` |

## Safety model

The scaffolded payload starts resident-only: the RPC features callback rejects
every bit outside the implemented mask (`features.hpp`), engine enumeration
activates only after `project_install` has installed a build-bound generated
header, and unverified target contracts stay unavailable. Extend
`kImplementedMask` only for features whose manifest findings are
`live_validated` for the exact build; `project_doctor` reports availability
per feature. Unsafe capabilities (world mutation, movement, scripts) remain
opt-in at compile time, mirroring the Apex-PS4 feature-bit model.
