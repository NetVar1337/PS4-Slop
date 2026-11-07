# Authoring a game project with the workbench

PS4-MCP generates and maintains standalone per-game repositories like
Apex-PS4 or Fortnite-PS4. The workbench owns research, generated inputs,
shared runtime components, build glue and qualified staging; the game repository
owns its engine providers, semantics, renderer backend and feature logic.
Everything before staging is read-only toward the console. Staging requires the
`process_inject` permission and a hardware-qualified payload hash.

## 1. Scaffold and pin the repository

```powershell
ps4-workbench --toolset full call game_new --arguments '{"name":"MyGame-PS4","engine":"unreal","directory":"C:\\path\\to\\repos","title_id":"CUSA12345"}'
cd C:\path\to\repos\MyGame-PS4
git init
git add .
git commit -m "Scaffold MyGame payload"
```

A source commit is required **before** `game_update`; missing repository,
engine or Git information fails before console research. `engine` is `generic`,
`unreal`, or `source`.

```
MyGame-PS4/
├── workbench.json          engine, payload/generated paths and RPC field schema
├── Makefile                shared orbis.mk; no duplicated toolchain flags
├── build.py                host/cross builds and generated-input integrity checks
├── recipe.json             declared output and pinned build command
├── include/internals/      runtime, memory, engine, hook, draw/input/snapshot APIs
├── runtime.cpp             lifecycle/RPC runtime
├── draw.cpp,input.cpp      optional game runtime kit implementations
├── src/payload.cpp         evidence-aware resident diagnostics
├── src/features.hpp        implemented feature bits
├── src/generated/          placeholders replaced by project_install
├── tests/host_smoke.cpp    offline lifecycle/feature-gate test
└── offsets/                per-build generated offset store
```

The shared runtime kit provides bounded draw geometry and UTF-8 text, controller
state/navigation/reconnect logic, fixed-size snapshot publication and capability
masks. It does not provide a renderer backend, game offsets, entity semantics,
weapon logic or gameplay providers. Those remain in the game repository.

Override `OO_PS4_TOOLCHAIN`, `CLANG`, `LLD`, `WORKBENCH_DIR`, or `LDLIBS_EXTRA`
instead of copying toolchain flags into the project.

## 2. Run the engine pipeline

MCP (a durable session under the hood, resumable with `session`):

```powershell
ps4-workbench --toolset full call game_update --arguments '{"pid":71,"repository":"C:\\path\\to\\repos\\MyGame-PS4","app_version":"01.00"}'
```

CLI from the game repository:

```sh
python -m ps4_workbench.ctl --url http://127.0.0.1:24600 --token-file profiles/broker-token.local \
    update --project-dir . --pid 71 --app-version 01.00
```

Both entry points use the same Rust `game_update` implementation. They read
`workbench.json`, derive the engine/repository/namespace/payload, dump and bind
the module, recover `unreal_dump`/`source_dump`, generate the SDK and target,
register the project contract and install generated inputs. The CLI additionally
builds and collects fresh evidence unless `--no-build` is passed. The title ID
comes from the descriptor or observed process; application version is always an
observed value.

For a game update, pass `old_artifact` + `annotations` (or the corresponding CLI
options). The `unreal_update`/`source_update` path ports annotations as research
candidates, not as live validation for the new build.

## 3. Generated integrity and feature gates

`project_install` writes `target.hpp`, `engine.hpp`, `offsets.hpp`,
`research.hpp`, `feature_dependencies.hpp`, `engine_config.hpp`, `manifest.json`,
`rpc.json`, and a hash-committed `install.json`. Files are replaced through
temporary files, the hash manifest is published last, and ordinary write errors
restore the previous set. Both `build.py` and `make` refuse missing, changed or
mixed generated inputs; rerun `project_install` after an interrupted install.

Feature activation requires all of:

1. a bit in `kImplementedMask`;
2. matching `live_validated` findings in `research::kAvailableFeatures`;
3. the manifest's generated dependency closure; and
4. successful runtime/provider activation.

`game::bindings` exposes each manifest binding's availability and build-bound
value. Source's five entity-layout bindings drive `kEntityLayout`; additional
semantic bindings (local player, camera, health, origin and so on) use the same
mechanism without hard-coded offsets in the shared runtime.

## 4. Build, verify and stage

```sh
make                 # descriptor payload, with generated-integrity preflight
make host-test       # offline lifecycle, feature-gate and runtime-kit checks
# Or directly:
python build.py --host-test --engine unreal
python build.py --engine unreal --output payload.elf
```

`game_verify` is read-only by default and reports implementation, evidence and
next actions per feature:

```powershell
ps4-workbench --toolset full call game_verify --arguments '{"repository":"C:\\path\\to\\repos\\MyGame-PS4"}'
```

Opt into local build checks or a resident telemetry check:

```json
{"repository":"C:\\path\\to\\repos\\MyGame-PS4","host_tests":true,"cross_build":true,"pid":71}
```

The PID path reads the `active_features` telemetry role from `rpc.json` and uses
normal payload RPC policy. Host/cross-build results never constitute hardware
acceptance.

Stage only the exact reviewed and qualified output:

```sh
make inject PID=<pid> TARGET_MANIFEST=<target artifact>
```

This calls `ps4-workbench inject`; `game_stage` is the MCP equivalent. Upload is
single-attempt, mutations are never automatically retried, and no per-project
injector is needed.

## 5. Named RPC and profiles

`rpc.json` describes feature names/bits and typed config/telemetry fields.
Extend `config` and `telemetry` in `workbench.json`/the project manifest; RPC
commands and wire words remain unchanged.

```sh
python -m ps4_workbench.ctl ... features --pid 71 --project-dir . --names diagnostics
python -m ps4_workbench.ctl ... config set --pid 71 --project-dir . --name sensitivity --value 1.5
python -m ps4_workbench.ctl ... telemetry --pid 71 --project-dir . --name active_features
python -m ps4_workbench.ctl ... profile save --pid 71 --project-dir . --path safe-profile.json
python -m ps4_workbench.ctl ... profile load --pid 71 --project-dir . --path safe-profile.json
```

Profiles are SHA-256-checked and bound to the module hash. Loading confirms each
configuration word through RPC5 before sending the next, then requests and (when
described) reads back features. A timeout stops later writes; there is no implicit
rollback or retry. `watch --safe-features safe` requests a safe mask once per
heartbeat-stall episode.

## 6. Keep per-build offsets

```sh
python -m ps4_workbench.ctl ... export-offsets --module-sha256 <64hex> --archive
```

This writes `offsets/<module_sha256[:16]>/offsets.hpp` and `offsets.json` into the
registered repository. These files and everything under `src/generated/` are
generated; do not hand-edit them. Revalidate ported findings before enabling
features for the new build.

## Tool reference

| Tool | Purpose |
|---|---|
| `game_new` | Emit the repo, runtime kit and descriptor |
| `game_update` | Descriptor-driven research, contract and generated install |
| `game_stage` | Qualified single-attempt upload and RPC status |
| `game_verify` | Actionable implementation/evidence/runtime report |
| `ps4-workbench inject` | CLI staging used by `make inject` |
| `ctl update --project-dir .` | The same update plus local build/collection |

The `ps4-game-project` MCP prompt follows this workflow. Start with resident
diagnostics and a read-only snapshot, then validate one capability at a time.
Unsafe capabilities remain explicit game-repository decisions and are never
enabled by annotation porting, a host test, or a successful ELF link.
