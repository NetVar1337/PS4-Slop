# Building

`tools/build.ps1` finds Visual Studio with `vswhere`, uses its bundled CMake and Ninja,
configures the `ninja-msvc-release` preset into `build/`, then builds the Tauri app.
First configure downloads pinned dependencies into `_ext/` (ImGui, FreeType, Zydis,
Capstone, Unicorn, nlohmann/json, cpp-httplib, SQLite, Lua, fmt, spdlog, zlib).

```powershell
git clone https://github.com/NetVar1337/SlopStation.git
cd SlopStation
powershell -File tools/build.ps1          # engine + Tauri app (portable + installer)
powershell -File tools/build.ps1 -NoFrontend   # C++ only, fastest loop
```

| Switch | Effect |
| --- | --- |
| _(none)_ | C++ engine + Tauri app: single-file portable (`dist\SlopStation\`) + per-user NSIS installer |
| `-NoFrontend` | C++ targets only |
| `-FullClean` | Delete `build/` before configuring |
| `-PlanOnly` | Configure without compiling |
| `-Preset <name>` | `ninja-msvc-debug`, `ninja-msvc-asan`, `ninja-msvc-analyze` |
| `-Test` | Build and run the CTest areas (`-TestLabel`, `-TestExclude`, `-TestJobs`) |
| `-Full` | Self-contained installer: embeds WebView2 and Magicmida |
| `-FrontendOnly` / `-BundleOnly` / `-FastBundle` | frontend binary, then bundling only |
| `-OnlineWebview` | use the online WebView2 bootstrapper |
| `-CmakeExtra`, `-Targets`, `-VsRoot` | extra CMake args, target subset, explicit VS root |

`SLOP_BUILD_DIR` moves the binary directory (useful off a virtual or overlay drive).

## CMake options

First-party targets compile with `/W4 /WX`.

| CMake option | Default | Builds |
| --- | ---: | --- |
| `SLOP_BUILD_ENGINE` | `ON` | headless engine |
| `SLOP_BUILD_UI` | `ON` | legacy ImGui shell |
| `SLOP_BUILD_TEST_TARGET` | `ON` | `SlopTarget.exe` fixture |
| `SLOP_BUILD_TESTS` | `ON` | `slop_tests.exe` |

`SLOP_ANALYZE=ON` runs MSVC `/analyze`; `SLOP_SANITIZE=address` builds with ASan.

## Payload

The bundled payload is fetched from the latest ps4debug-NG release before packaging:

```powershell
powershell -File tools/fetch_ps4debug.ps1          # latest release -> build/ps4debug-ng
powershell -File tools/fetch_ps4debug.ps1 -Force   # re-download
```

## Outputs

```text
build\src\engine\reverse-slop-engine.exe                     headless engine
build\src\app\reverse-slop.exe                               legacy ImGui shell
dist\SlopStation\SlopStation.exe                            portable single file (engine embedded by CI)
app\src-tauri\target\release\bundle\nsis\...-setup.exe       per-user installer
app\src-tauri\target\release\bundle\nsis\...-setup.exe.sig   updater signature (when the signing key is set)
```

## Versioning

`VERSION` is the single product version; `tools/sync_version.ps1` copies it into the
frontend/Tauri manifests and the README badge, and CI verifies the tag matches
(`tools/sync_version.ps1 -Check -Tag <tag>`).

## CI

- **PRs** run only the lanes their paths touch: C++ build/tests for `src/**`, frontend
  build/tests for `app/**`, and the docs build for `docs/**`.
- **main** runs the build + test + frontend gate. ASan, `/analyze` and clang-tidy run
  nightly (and on manual dispatch), off the push critical path.
- **Tags** use a separate release workflow: it downloads the successful main build's engine
  and frontend artifacts for the same commit, then packages, signs and publishes the
  installer, the single-file portable zip, `SHA256SUMS` and `latest.json` — no rebuild on
  the release path.

## Docs site

The site is mdBook over `docs/`:

```powershell
cargo install mdbook --locked
mdbook serve --open      # http://localhost:3000
mdbook build             # -> docs/book/
```

`.github/workflows/docs.yml` builds it on every PR that touches `docs/**` and deploys to
GitHub Pages from `main`.
