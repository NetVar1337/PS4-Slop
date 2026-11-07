# Evidence to resident payload

The workbench now has a connected development path: identify an exact build,
record typed research, export SDKs, install generated inputs, build a fresh ELF,
collect its evidence, and stage it through an explicitly qualified transport.
Local project-writing tools require the `full` toolset; they do not require
console mutation permissions. No scaffold, install, build, or collection deploys.

## Build a diagnostic project

```powershell
ps4-workbench --toolset full call payload_scaffold --arguments '{"name":"FortniteDiagnostics","engine":"unreal"}'
python workspace/projects/FortniteDiagnostics/build.py --host-test
python workspace/projects/FortniteDiagnostics/build.py
```

Use the actual artifact directory from your profile in place of `workspace`.
The cross build uses `OO_PS4_TOOLCHAIN` (or `--sdk`) and LLVM. The generated
project includes its own shared headers/runtime, build script, and host smoke
test. `sdk_scaffold kind=payload` creates the same buildable generic project.
Homebrew/plugin scaffolds still require their upstream SDK samples.

Unconfigured game functionality remains unavailable. Resident-only startup,
heartbeat, protocol negotiation, telemetry, and shutdown work independently.
The Orbis reader queries mapping protection before copying bytes. Captures and
live reads are not atomic: a mapping or object can change after a check.

## Register the build and its research

1. Open a project with `project_open`, supplying the observed title ID and
   application version. Capture the module with `memory_elf_dump`, rebuild it
   with `elf_rebuild`, then call `project_bind_module` with its artifact, PID,
   and module name. This records the process/title, base, verification site,
   research-artifact hash, and a separate hash of the live executable mappings.
2. Register a `ps4wb-project-v1` contract with `project_manifest`. It contains
   `title_id`, `app_version`, `module_sha256`, `engine` (`generic`, `unreal`,
   `source`), `sdk` (`openorbis`, `payload`), `source_commit`, absolute
   `repository`, `staging` (`immediate`, `elf_rpc`), and `rpc_version: 1`.
3. Record findings with `project_finding`. Each has a stable `id`, exact
   `module_sha256`, `kind`, `state`, address/offset `value` string, and evidence
   references containing `artifact`, `sha256`, and `kind`.

Finding kinds are `module_rva`, `object_member`, `vtable_slot`, `pointer_chain`,
`function_abi`, `enum`, and `constant`. States are `hypothesis`,
`static_supported`, `live_validated`, and `rejected`. Members include owner,
type and size. Pointer chains have bounded `indirection` offsets. Function ABIs
include `sysv_amd64`, return/argument types, explicit `this` for methods, calling
thread, and lifetime. An ABI type alias does not authorize calling the function
from an arbitrary thread.

`live_validated` requires a `hardware` evidence artifact. That artifact is a
user attestation: the tool verifies its integrity, not the truth of a hardware
claim. A changed evidence file invalidates availability. Revisions are retained
as immutable research artifacts; the current index is atomically replaced.

Manifest `features` map names to a unique power-of-two `bit`, required finding
IDs, and other feature `dependencies`. Cycles are rejected. `project_doctor`
checks evidence and reports each feature's availability and missing findings.
The top-level `ready` means evidence is consistent enough to export; individual
features may still be unavailable.

`project_research_export` generates typed readers, pointer resolvers, enum
definitions, ABI aliases, availability constants, and an analyzer-compatible
prototype artifact. Only matching, live-validated findings expose usable
values. Candidate findings export an unavailable flag. Use the existing
`analysis_apply_prototypes` tool to apply the prototype artifact locally.

## Engine SDK and generated inputs

`unreal_pipeline` and `source_pipeline` capture/bind the module, recover metadata
from live memory (including referenced heap objects), export a build-bound SDK,
and generate offsets and a target manifest. Engine APIs remain bounded by the
profile's read/transfer limits. Engine recovery can still fail on unsupported
or obfuscated layouts; it does not fabricate a replacement.

UE4 export supports fixed/chunked object arrays, FNamePool, and older
TNameEntryArray. Dumping and the resident reader agree on the FUObjectArray
root, object slot, count fields, and inline name-block array. Reflected types
have storage/field bounds assertions; known scalar fields get mapping-aware
readers. Packed/unknown property types remain offset-only. Source export
includes nested netvar paths and datamaps; fork-specific raw type numbers do not
silently become C++ types. Typed Source members come from typed findings.

Call `project_install` with the target artifact and optional engine/offsets
headers. It checks build/title/provenance hashes, then installs `target.hpp`,
`engine.hpp`, `offsets.hpp`, `research.hpp`, `engine_config.hpp`, and a manifest
under the registered repository's generated directory. Existing user-authored
headers are refused. The repository's `workbench.json` can select that directory.

For a Source diagnostic scaffold, manifest `bindings` map `entity_slots`,
`entity_count`, `entity_stride`, `entity_pointer`, and `entity_serial` to finding
IDs. Missing/unvalidated bindings produce an unavailable layout. Enumeration
is incremental and rechecks pointer/serial identity. This is separate from
Apex's existing renderer and exact-build engine implementation.

`offset_refresh`, `unreal_update`, and `source_update` carry annotations across
binary updates. Ported annotations now feed offset export directly. They remain
research candidates; typed live validation does not transfer to a new build.
ELF/core fingerprints use virtual segment mappings, never raw RVA file indexing.

## Durable sessions and the update CLI

```json
{"action":"create","recipe":"unreal_pipeline","inputs":{"pid":71,"module":"eboot.bin"}}
{"action":"advance","session":"<returned 32-character id>"}
{"action":"status","session":"<id>"}
{"action":"cancel","session":"<id>"}
```

These are `recipe_session` calls. `advance` defaults to one step. A UI/client
can show progress, stop scheduling, or cancel between steps without keeping a
long-running request open. Profile/project identity and artifact dependencies
are pinned. Changed artifacts invalidate affected steps and their dependants.
Completed independent steps remain reusable. Sessions survive broker restarts.
A crash during a step leaves `running`/uncertain state and requires explicit
retry. Retrying a console mutation requires a `recovery_evidence` artifact;
neither restart nor cancellation automatically repeats or undoes it.
Debugger-control steps retain the broker's debug lease requirement. MCP
cancellation is also checked between recipe steps.

`python -m ps4_workbench.ctl ... session` exposes those actions. The `update`
command uses durable sessions, registers the new build contract, installs fresh
generated inputs, then builds. Supply `--session-id` to resume, or `--dry-run`
to inspect a plan. A new project requires the actual `--app-version`.
`--old-artifact` and `--annotations` select the engine-specific update path.

Prefer `--build-argv '["python","build.py"]'` for an exact local command.
Commands run without a shell. Time/log limits, contained output paths, archived
previous outputs, and before/after source hashes prevent stale-output success.
`--no-build` exports/installs only and never offers an old ELF for staging.
Build recipes must not launch detached children; the runner is not an OS sandbox.

`project_collect_build` checks `workbench.lock.json`, source pins, ELF architecture,
entry point, RPC export and payload hash before ingesting immutable ELF/build
artifacts. Build evidence does not grant console permissions or qualify a new
payload hash. Qualification/staging remains a separate exact-configuration step.

## Runtime and hook contract

RPC commands 0..6 retain lifecycle/features/shutdown/stage/config/telemetry
semantics. Command 7 is a read-only descriptor, `0x50535742000100ff`: PSWB,
protocol version 1, commands 0..7. New target manifests require negotiation
before control commands. Telemetry is captured on the payload thread and read
through atomics by RPC. Older manifests without `rpc_version` retain their
legacy behavior; no unknown payload is upgraded by guessing its protocol.

Immediate staging sends `CMD_PROC_ELF` once, recovers the exported RPC entry
from refreshed mappings, negotiates, and checks readiness. `elf_rpc` is an
explicit alternative. Neither path calls a raw entry manually or retries an
uncertain upload. RPC symbols may precede or follow the ELF entry point.

`hook_plan` decodes a whole-instruction prefix, relocates branches/RIP-relative
instructions, emits a detour and return trampoline, and retains expected bytes.
It rejects terminal/invalid prefixes and data references into overwritten bytes.
`internals/hook.hpp` consumes the plan through platform callbacks for verified
reads/writes, exact protection restoration, cache flush and quiescence. Install
publishes the trampoline first. Restore neutralizes/drains callbacks and only
restores bytes still owned by that instance. Uncertain writes/restores retain an
uncertain state; callers must keep the image/trampoline resident.

## Replay and validation

`memory_image_capture` accepts a PID/module and optional explicit readable
ranges. Its `ps4wb-memory-image-v1` manifest references hashed module/heap chunks,
with missing pages and budget/deadline/cancellation reported separately.
Pass that manifest as `artifact` to mapped engine readers to reproduce analysis
offline. Missing bytes are holes, not synthesized zeros. Real captures stay in
the local artifact directory; CI fixtures are synthetic.

Run `cargo test --locked`, `cargo clippy --all-targets --features fixture --locked
-- -D warnings`, and `python -m unittest discover -q` after building the binary.
Tests compile generated SDKs against the real shared headers and exercise replay,
evidence tampering, dependencies, sessions, hook ownership and lifecycle failures.
The offline test profile is `tests/fixtures/profile.json`; developer-local console
settings do not change fixture permissions.

Hardware acceptance still requires observed startup/status, mapping lifetime,
engine-reader correctness, thread/ABI checks, restoration, and soak results for
each exact build. No host fixture or successful ELF link establishes those facts.
