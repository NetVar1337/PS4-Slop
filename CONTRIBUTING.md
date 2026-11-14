# Contributing to reverse-slop

Thanks for helping. This file covers how to build, test and ship changes; the
README covers what the tool does.

## Toolchain

- Windows 10/11 x64
- Visual Studio 2022 or newer with **Desktop development with C++** (MSVC, the
  bundled CMake/Ninja) and, for clang-tidy, **C++ Clang tools for Windows**
- Node.js 22 and the Rust toolchain (`rustup`) for the Tauri front end
- PowerShell 7 (`pwsh`) for `tools/sync_version.ps1` and `tools/clang_tidy.ps1`

`tools/build.ps1` finds Visual Studio through `vswhere`; pass `-VsRoot <dir>` or
set `SLOP_VS_ROOT` for a non-standard install.

## Building

```powershell
powershell -File tools\build.ps1 -NoFrontend                 # C++ only (engine, ImGui shell, tests)
powershell -File tools\build.ps1                             # + Tauri front end, installer, portable dist
powershell -File tools\build.ps1 -NoFrontend -Test           # build, then every CTest test area
powershell -File tools\build.ps1 -NoFrontend -FullClean      # drop build\ and _ext\*-build|*-subbuild first
```

A build tree configured from a different checkout location (moved/copied repo)
is detected and regenerated automatically; downloaded sources in `_ext\*-src`
are kept.

`pwsh tools/clean.ps1` drops the generated trees (every `build*\` directory and
`_ext\*-build|*-subbuild`) and prints the space it frees; `-All` also removes
the downloaded dependency sources, `app\node_modules` and the cargo target
(the next build re-fetches them), `-DryRun` only lists them.

### Compiler cache (sccache)

CI wraps every compiler invocation in [sccache](https://github.com/mozilla/sccache);
a local build can do the same and skip most of the cold-build time:

```powershell
scoop install sccache            # or: cargo install sccache
$env:CMAKE_C_COMPILER_LAUNCHER   = 'sccache'
$env:CMAKE_CXX_COMPILER_LAUNCHER = 'sccache'
$env:RUSTC_WRAPPER               = 'sccache'   # frontend builds
powershell -File tools\build.ps1 -NoFrontend
sccache --show-stats
```

The launcher is read at configure time, so set it before the first configure of
a build tree (or re-run with `-FullClean`). sccache keeps working across
branches and checkouts; `sccache --zero-stats` resets the hit counters.

### CMake presets

| Configure preset | Binary dir | Purpose |
|---|---|---|
| `ninja-msvc-release` | `build/` | Shipped configuration (deps in `_ext/`) |
| `ninja-msvc-debug` | `build-ninja-msvc-debug/` | Debug CRT, `/RTC1` |
| `ninja-msvc-asan` | `build-ninja-msvc-asan/` | RelWithDebInfo + `/fsanitize=address` on every target |
| `ninja-msvc-analyze` | `build-ninja-msvc-analyze/` | MSVC `/analyze` on first-party code |
| `ninja-msvc-fuzz` | `build-ninja-msvc-fuzz/` | RelWithDebInfo + `/fsanitize=address,fuzzer` for `src/fuzz` (no engine, UI or tests) |

`tools\build.ps1 -Preset <name>` builds any of them; each non-release preset
keeps its own dependency checkout under `<binary dir>/_deps`. Matching
`testPresets` exist (`ctest --preset ninja-msvc-release`).

CMake options: `SLOP_BUILD_UI` (legacy ImGui shell, default ON),
`SLOP_BUILD_ENGINE`, `SLOP_BUILD_TESTS`, `SLOP_BUILD_TEST_TARGET`,
`SLOP_SANITIZE=address`, `SLOP_ANALYZE`, `SLOP_BUILD_FUZZ` (default OFF, needs
`SLOP_SANITIZE=address`).

Every first-party target links with `/DYNAMICBASE`, `/NXCOMPAT`,
`/HIGHENTROPYVA`, `/GUARD:CF` and `/CETCOMPAT` (see `SECURITY.md`);
`tools/check_binaries.ps1` verifies the shipped engine carries all five.

## Tests

`slop_tests` is one executable; CTest registers one entry per test area (each
`src/tests/test_<area>.cpp`, label `area`) plus `slop_tests_all` (label `all`).

```powershell
ctest --test-dir build -L area --output-on-failure      # every area, one process each
$env:SLOP_TEST_AREA = 'network,memory'; build\tests\slop_tests.exe
$env:SLOP_TEST_FILTER = 'pe_parse'; build\tests\slop_tests.exe   # substring of the test name
```

Every test case runs under a watchdog (default 300 s, `SLOP_TEST_TIMEOUT_SEC`
overrides it, `TEST_CASE_TIMEOUT(name, seconds)` sets it per test). A hung test
prints `[TIMEOUT] <name>` and the run exits with 124. New behavior needs a
regression test; tests must be deterministic and must not touch the real user
profile or certificate store.

`tools/mcp_live_test.py` drives a real engine over MCP:
`python tools/mcp_live_test.py --engine build\src\engine\reverse-slop-engine.exe`
(see `--help`).

## Fuzzing

`src/fuzz` holds one libFuzzer target per parser that eats untrusted input:
`elf_loader`, `pe_parser`, `macho_loader`, `ipa`, `zip_reader`, the ps4debug-NG
wire format and .NET metadata. They are MSVC-only and build with the
`ninja-msvc-fuzz` preset (ASan is part of the same instrumentation, so the whole
tree is instrumented).

```powershell
powershell -File tools\build.ps1 -Preset ninja-msvc-fuzz -NoFrontend -Targets "fuzz_elf,fuzz_zip"
pwsh tools/run_fuzzers.ps1 -Seconds 60                  # every target, 60 s each
pwsh tools/run_fuzzers.ps1 -Targets ps4 -Seconds 300    # one target, longer
```

The runner copies the committed seeds from `src/fuzz/corpus/<target>/` into a
scratch corpus (so the checkout stays clean) and fails on a crash, leaving the
reproducer in `fuzz-artifacts/<target>/`. Reproduce one with
`build-ninja-msvc-fuzz\fuzz\fuzz_<target>.exe <crash file>`.

Seeds are generated from the test fixtures:
`build-ninja-msvc-fuzz\fuzz\slop_fuzz_corpus.exe src/fuzz/corpus` (re-run after
a fixture or format change, then commit the files). A crash found by fuzzing
gets a regression test in the matching `src/tests/test_<area>.cpp`.

## Static analysis

- `pwsh tools/clang_tidy.ps1` runs clang-tidy (`.clang-tidy`) over first-party
  code using `build/compile_commands.json`. Error-level checks must stay clean.
- The `ninja-msvc-asan` and `ninja-msvc-analyze` presets back the `asan` and
  `analyze` CI lanes.

### Coverage and /analyze ratchets

- `docs/coverage-baseline.txt` holds the src/core line coverage the nightly
  lane must not drop more than 0.5 points below (`tools/coverage_ratchet.ps1`).
  The lane also runs on PRs that touch C++.
- `docs/analyze-baseline.txt` lists the accepted MSVC `/analyze` findings
  (`tools/analyze_ratchet.ps1`); a finding that is not listed fails the nightly
  analyze lane. After fixing or accepting one, re-baseline with `-Update`.

## Versioning and releases

- The product version lives only in `VERSION`. After changing it run
  `pwsh tools/sync_version.ps1` (updates `app/package.json`, `package-lock.json`,
  `tauri.conf.json`, `Cargo.toml`, `Cargo.lock`); CI fails on a mismatch and on a
  tag that differs from `VERSION`. CMake embeds it in the exe VERSIONINFO and
  manifests.
- Add a `## [x.y.z]` section to `CHANGELOG.md`; the release job publishes it as
  the release notes.
- Push tag `vX.Y.Z`. The release is published only after every CI lane passes,
  with `SHA256SUMS` for all assets. Binaries and the installer are
  Authenticode-signed through Azure Trusted Signing when the repository has the
  `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
  `AZURE_SIGNING_ENDPOINT`, `AZURE_SIGNING_ACCOUNT` and `AZURE_SIGNING_PROFILE`
  secrets.
- The Magicmida release and its package hashes live in
  `tools/magicmida-version.txt` (CMake, `install_magicmida.ps1`, `build.ps1` and
  the CI cache key read it).

## Dependencies

- C/C++ dependencies are declared in `cmake/deps.cmake`, each archive pinned by
  `URL_HASH SHA256` and each git dependency by a full commit SHA. When bumping
  one, update URL and hash together (`tools/dep_hash.ps1 <url>` prints the hash).
- After adding or bumping any dependency (C/C++, npm or cargo) regenerate the
  notices: `python tools/gen_third_party_notices.py` (needs a configured build,
  `npm ci` in `app/`, and the cargo registry). `--check` reports a stale file.

## Benchmarks

See `docs/benchmarks/README.md` (`tools/run_benchmarks.ps1`, weekly CI run).

## Pull requests

- Keep changes focused; describe behavior changes and how you tested them.
- A PR that touches `src/**` or `app/src/**` must add a `CHANGELOG.md` entry
  (CI enforces it; label the PR `no-changelog` for a change that does not
  belong there).
- MSVC `/W4` must stay warning-free in first-party code.
- Frontend: `npm run typecheck`, `npm test` and `npm run build` in `app/`.
- By contributing you agree that your contribution is licensed under the MIT
  license in `LICENSE`.
