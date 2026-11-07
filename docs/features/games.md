# Game-project authoring

Tools that turn the research pipeline into a standalone per-game repository
(like Apex-PS4 / Fortnite-PS4) without per-project injectors or build glue.\r
See [GAME_PROJECT.md](../GAME_PROJECT.md) for the end-to-end flow.\r
\r
- `game_new` (local file writes, no console): emits `workbench.json`\r
  (`ps4wb-scaffold-v1`), a Makefile that includes\r
  `templates/payload/orbis.mk`, the engine feature pack (`src/features.hpp`\r
  with the standard fail-closed bit table), the shared internals headers and\r
  runtime, a host smoke test, and the per-build `offsets/` store.\r
- `game_update` (console reads via a durable recipe session): runs\r
  `unreal_pipeline`/`source_pipeline` (or the `*_update` variants with\r
  `old_artifact` + `annotations`), registers the `ps4wb-project-v1` contract,\r
  and `project_install`s the generated headers into the registered\r
  repository's `generated_directory`. Resumable via `session`.\r
- `game_stage` (permission `process_inject`): ingests local target/payload\r
  files when needed, computes the payload hash when omitted, then runs\r
  `payload_stage` + `payload_status` in one call. The CLI equivalent is\r
  `ps4-workbench inject --pid ... --target ... --payload ...`, which is what\r
  scaffolded `make inject` targets call.\r
- `game_verify` (read-only): `project_doctor` + `project_summary` (+ optional\r
  `payload_inspect`). Host-side consistency only.\r
\r
`ctl update --project-dir <repo>` reads the repo's `workbench.json` and derives\r
engine, recipe, payload path, and namespace, so updates no longer need `--game`.\r
`ctl export-offsets --archive` (or `project_export_offsets` with\r
`"archive": true`) additionally writes `offsets/<module_sha256[:16]>/`\r
into the registered repository.\r
