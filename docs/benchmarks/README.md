# Benchmarks

Recorded performance baselines for the app-side hot paths, and the tooling that
checks them.

| File | Produced by | What it measures |
|---|---|---|
| `app-before.json` / `app-after.json` | `build\tests\slop_app_bench.exe <out.json>` (`src/tests/bench_app.cpp`) | Memory scanner, traffic-store slicing, event bus and MCP `output`/`diag` paths: median of 7 runs per workload plus allocation volume and a deterministic `result` per workload. |
| `ui-before.json` / `ui-after.json` | `npm run bench -- <out.json>` in `app/` (`app/scripts/bench-ui.mjs`) | Server-side render of the Output panel with 4096 rows, plus a 1,000,000-row virtualized list mounted in jsdom (mount, scroll frame, filter). Component work only, not browser frame time. |

`*-before.json` / `*-after.json` are the pair recorded around the optimization
that introduced them; **`*-after.json` is the current baseline**. `ui-before.json`
predates the `virtual_list_1m_rows` workload, so only `ui-after.json` carries it.

## 1M-row virtualized list

`virtual_list_1m_rows` mounts `app/src/bench/VirtualListBench.tsx` — 1,000,000
synthetic rows, no engine — in jsdom, warms the render path with 10 scrolls,
then records:

| Metric | Baseline | Budget |
|---|---|---|
| `mount_ms` | 77.9 | generic 3x |
| `scroll_frame_ms` | 4.43 | **1.25x** |
| `filter_ms` | 383.7 | generic 3x |

`scroll_frame_ms` is the tenth percentile of 60 scroll-and-render frames (the
median is kept as `scroll_median_ms`): the fastest frames still carry the real
render cost, while a busy machine only inflates the rest. It is the hot path of
the listing, so the weekly bench lane fails when it regresses more than 25%
against `ui-after.json`; the other two keep the generic slowdown factor.

## Checking for regressions

```powershell
powershell -NoProfile -File tools\run_benchmarks.ps1            # build, run, compare
powershell -NoProfile -File tools\run_benchmarks.ps1 -SkipBuild  # reuse build\tests\slop_app_bench.exe
```

The script fails when a workload's `result` changes (a correctness change) or its
median exceeds `-MaxSlowdown` (default 3x) times the baseline. The factor is
generous on purpose: the baselines come from a developer machine and CI runners
are slower and noisier, so only real regressions trip it. The one exception is
the 1M-row list's `scroll_frame_ms`, which fails past 1.25x (see above).

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
