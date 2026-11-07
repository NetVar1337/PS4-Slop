# Game-project authoring

Tools for standalone game repositories without per-project injectors or build
glue. See [GAME_PROJECT.md](../GAME_PROJECT.md) for the complete workflow.

- `game_new` emits `workbench.json`, shared runtime/engine headers, the bounded
  draw/input/snapshot/capability kit, evidence-aware feature bits, host tests,
  and a per-build offset store. The game repository owns semantic providers and
  renderer backends.
- `game_update` reads the repository descriptor, validates its source commit
  before console access, runs the durable engine pipeline, registers the build
  contract, and installs generated inputs. The CLI calls this same Rust tool and
  then performs local build/evidence collection.
- `project_install` publishes `install.json` last with per-file hashes. Both
  build paths reject partial or modified generated sets. Generated feature
  dependencies and `research::kAvailableFeatures` gate activation together with
  `kImplementedMask` and runtime providers. Semantic bindings are exposed via
  `game::bindings`.
- `rpc.json` provides named features and typed config/telemetry metadata. The
  CLI supports named access, build-bound profile save/load with RPC5 mirror
  confirmation, and one-shot safe features on heartbeat stalls.
- `game_stage` retains hash-qualified, single-attempt staging and never retries
  uncertain mutations.
- `game_verify` reports implementation, evidence, optional runtime-active state,
  and next actions per feature. `host_tests`, `cross_build`, and `pid` checks are
  opt-in. None establishes hardware acceptance.

The `ps4-game-project` MCP prompt guides the same resident-diagnostics-first
workflow.
