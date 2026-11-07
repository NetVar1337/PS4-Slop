# game (example)

Checked-in example of `game_new` (Unreal, placeholder title `CUSA00000`). Its
Makefile uses `WORKBENCH_DIR=../..` because it lives inside PS4-MCP; standalone
projects normally use `../PS4-MCP`.

- `make host-test` runs lifecycle, fail-closed feature and runtime-kit checks.
- `make` builds `payload.elf` with the shared OpenOrbis fragment and verifies
  generated-input integrity first.
- `python build.py --engine unreal --output payload.elf` is the equivalent
  direct build.
- `game_update --repository <this repo>` reads `workbench.json`; commit the
  scaffold first. `project_install` writes the generated SDK, feature gates,
  semantic bindings, RPC descriptor and hash-committed install manifest.
- `game_verify` reports implementation/evidence/next actions and can optionally
  run host/cross-build checks.
- `make inject PID=<pid> TARGET_MANIFEST=<target>` uses the shared qualified
  staging path; no project injector or automatic retry exists.

The default target is unconfigured and all game features stay unavailable.
RPC 7 negotiates PSWB v1; telemetry indices 0/1/2 are verification, object count
and active features. See `docs/GAME_PROJECT.md` for research, runtime kit,
named RPC profiles, update porting and hardware acceptance boundaries.
