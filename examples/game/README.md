# game (example)

Example repository emitted by `game_new` (engine: unreal, placeholder title id
CUSA00000). It lives inside the PS4-MCP checkout, so its Makefile points
`WORKBENCH_DIR` at `../..`; a standalone checkout uses `../PS4-MCP`.
See docs/GAME_PROJECT.md for the full flow.

Resident diagnostic payload scaffolded by `game_new` (engine: unreal).

- `make` builds `payload.elf` with the shared toolchain fragment `templates/payload/orbis.mk`.
- `make host-test` (or `python build.py --host-test --engine unreal`) runs the offline lifecycle smoke test.
- `make inject PID=<pid> TARGET_MANIFEST=<target artifact>` stages through `ps4-workbench inject`;
  no per-project injector is needed. Staging requires a qualified local profile with `process_inject`.
- `game_update` (or `ps4_workbench.ctl update --project-dir .`) runs the engine pipeline and
  `project_install` writes generated headers into `src/generated/`.
- `offsets/` keeps the per-build generated offset headers/manifests (`project_export_offsets archive`).

Target checks are initially empty and stay unavailable. No build deploys to a console.
RPC 7 negotiates protocol v1; RPC 6 telemetry index 0 is verification, index 1 object count.
See docs/GAME_PROJECT.md in PS4-MCP.
