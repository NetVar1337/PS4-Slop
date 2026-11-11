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

### CMake presets

| Configure preset | Binary dir | Purpose |
|---|---|---|
| `ninja-msvc-release` | `build/` | Shipped configuration (deps in `_ext/`) |
| `ninja-msvc-debug` | `build-ninja-msvc-debug/` | Debug CRT, `/RTC1` |
| `ninja-msvc-asan` | `build-ninja-msvc-asan/` | RelWithDebInfo + `/fsanitize=address` on every target |
| `ninja-msvc-analyze` | `build-ninja-msvc-analyze/` | MSVC `/analyze` on first-party code |

`tools\build.ps1 -Preset <name>` builds any of them; each non-release preset
keeps its own dependency checkout under `<binary dir>/_deps`. Matching
`testPresets` exist (`ctest --preset ninja-msvc-release`).

CMake options: `SLOP_BUILD_UI` (legacy ImGui shell, default ON),
`SLOP_BUILD_ENGINE`, `SLOP_BUILD_TESTS`, `SLOP_BUILD_TEST_TARGET`,
`SLOP_SANITIZE=address`, `SLOP_ANALYZE`.

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

## Static analysis

- `pwsh tools/clang_tidy.ps1` runs clang-tidy (`.clang-tidy`) over first-party
  code using `build/compile_commands.json`. Error-level checks must stay clean.
- The `ninja-msvc-asan` and `ninja-msvc-analyze` presets back the `asan` and
  `analyze` CI lanes.

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
- MSVC `/W4` must stay warning-free in first-party code.
- Frontend: `npm run typecheck`, `npm test` and `npm run build` in `app/`.
- By contributing you agree that your contribution is licensed under the MIT
  license in `LICENSE`.
