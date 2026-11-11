# Benchmarks

Recorded performance baselines for the app-side hot paths, and the tooling that
checks them.

| File | Produced by | What it measures |
|---|---|---|
| `app-before.json` / `app-after.json` | `build\tests\slop_app_bench.exe <out.json>` (`src/tests/bench_app.cpp`) | Memory scanner, traffic-store slicing, event bus and MCP `output`/`diag` paths: median of 7 runs per workload plus allocation volume and a deterministic `result` per workload. |
| `ui-before.json` / `ui-after.json` | `npm run bench -- <out.json>` in `app/` (`app/scripts/bench-ui.mjs`) | Server-side render of the Output panel with 4096 rows (component work only, not browser frame time). |

`*-before.json` / `*-after.json` are the pair recorded around the optimization
that introduced them; **`*-after.json` is the current baseline**.

## Checking for regressions

```powershell
powershell -NoProfile -File tools\run_benchmarks.ps1            # build, run, compare
powershell -NoProfile -File tools\run_benchmarks.ps1 -SkipBuild  # reuse build\tests\slop_app_bench.exe
```

The script fails when a workload's `result` changes (a correctness change) or its
median exceeds `-MaxSlowdown` (default 3x) times the baseline. The factor is
generous on purpose: the baselines come from a developer machine and CI runners
are slower and noisier, so only real regressions trip it.

CI runs the same script weekly and on demand (`.github/workflows/bench.yml`),
writes a comparison table to the run summary, and uploads the raw JSON.

## Comparing two runs

```powershell
powershell -NoProfile -File tools\compare_app_bench.ps1 -Baseline docs\benchmarks\app-before.json -Candidate build\bench\app.json
```

prints per-workload speedup and allocation deltas (and fails if a workload's
result differs).

## Updating the baseline

After an intended performance change, on a quiet machine:

```powershell
powershell -NoProfile -File tools\run_benchmarks.ps1 -UpdateBaseline
```

copies the run over `app-after.json` / `ui-after.json`; commit them together
with the change.
