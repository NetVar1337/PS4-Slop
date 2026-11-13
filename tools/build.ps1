[CmdletBinding()]
param(
    [switch]$FullClean,
    [switch]$PlanOnly,
    [switch]$NoFrontend,
    [switch]$Test,
    [switch]$Full,
    [switch]$FrontendOnly,
    [switch]$BundleOnly,
    [switch]$FastBundle,
    [switch]$OnlineWebview,
    [string]$CmakeExtra = '',
    [string]$Preset = 'ninja-msvc-release',
    [string]$Targets = '',
    # CTest label selecting the test entries -Test runs ('area' = every area)
    [string]$TestLabel = 'area',
    # Regex of CTest entries to exclude (ctest -E); used to skip areas that
    # cannot run under a given preset (e.g. the Unicorn emulator under ASan)
    [string]$TestExclude = '',
    # Visual Studio install root; defaults to $env:SLOP_VS_ROOT, then vswhere
    [string]$VsRoot = $env:SLOP_VS_ROOT
)

$ErrorActionPreference = 'Stop'
if ($BundleOnly -and -not $FrontendOnly) { throw '-BundleOnly requires -FrontendOnly' }
if ($BundleOnly -and $NoFrontend) { throw '-BundleOnly cannot be combined with -NoFrontend' }
$repoRoot = Split-Path -Parent $PSScriptRoot

# One parent dir for every run's logs; keep the newest few, drop the rest
# (older layouts left a %TEMP%\slop-build-<stamp> dir behind per run)
$logRoot = Join-Path $env:TEMP 'slop-build'
New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter 'slop-build-*' -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath $logRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -Skip 4 |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
$logDir = Join-Path $logRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
New-Item -ItemType Directory -Path $logDir | Out-Null

# binaryDir of a configure preset (follows `inherits`, expands the macros the
# presets use) so build/test steps work for every preset, not only build/
function Resolve-PresetBinaryDir([string]$name) {
    $presets = (Get-Content -LiteralPath (Join-Path $repoRoot 'CMakePresets.json') -Raw | ConvertFrom-Json).configurePresets
    $cur = $presets | Where-Object name -EQ $name
    if (-not $cur) { throw "unknown configure preset '$name'" }
    $dir = $null
    while ($cur -and -not $dir) {
        if ($cur.binaryDir) { $dir = $cur.binaryDir; break }
        $parent = @($cur.inherits)[0]
        $cur = if ($parent) { $presets | Where-Object name -EQ $parent } else { $null }
    }
    if (-not $dir) { throw "preset '$name' has no binaryDir" }
    $dir = $dir.Replace('${sourceDir}', $repoRoot).Replace('${presetName}', $name)
    return [IO.Path]::GetFullPath($dir)
}

# A build tree configured from another checkout location (the repo was moved
# or copied) makes cmake refuse to configure, and FetchContent's sub-builds
# carry the old absolute paths too. Wipe exactly those; downloaded sources
# (_ext\*-src) stay. Only the primary build\ tree keeps its deps in _ext\, the
# other presets keep them inside their own binary dir.
function Clear-GeneratedTrees([string]$binaryDir, [string]$reason) {
    $primary = [IO.Path]::GetFullPath((Join-Path $repoRoot 'build')).TrimEnd('\') -eq $binaryDir.TrimEnd('\')
    Write-Host "==> $reason, removing $binaryDir$(if ($primary) { ' and _ext\*-build, _ext\*-subbuild' })"
    if (Test-Path -LiteralPath $binaryDir) { Remove-Item -LiteralPath $binaryDir -Recurse -Force }
    if ($primary) {
        Get-ChildItem -LiteralPath (Join-Path $repoRoot '_ext') -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*-build' -or $_.Name -like '*-subbuild' } |
            Remove-Item -Recurse -Force
    }
}

$vsCMake = 'cmake'
$vsCTest = 'ctest'
if (-not $FrontendOnly) {
if (-not $VsRoot) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $VsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    }
}
if (-not $VsRoot -or -not (Test-Path -LiteralPath (Join-Path $VsRoot 'VC\Auxiliary\Build\vcvars64.bat'))) {
    throw 'Visual Studio with C++ tools not found (install VS 2022+ with "Desktop development with C++", or pass -VsRoot / set SLOP_VS_ROOT)'
}

$vsCMake = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$vsCTest = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe'
$vsNinja = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
$vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'

Write-Host "==> repo:     $repoRoot"
Write-Host "==> vs root:  $vsRoot"
Write-Host "==> logs:     $logDir"
} else {
    Write-Host "==> repo:     $repoRoot (frontend-only, skipping VS detection)"
    Write-Host "==> logs:     $logDir"
}
if ($Full) {
    Write-Host '==> full installer mode: magicmida and the webview2 runtime are all required' -ForegroundColor Cyan
}

if (-not $FrontendOnly) {
cmd /c "call `"$vcvars`" > NUL 2>&1 && set" | ForEach-Object {
    if ($_ -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        Set-Item -Path ("Env:" + $Matches[1]) -Value $Matches[2]
    }
}

if (Test-Path -LiteralPath $vsNinja) {
    $env:path = "$(Split-Path -Parent $vsNinja);$env:path"
}
}

$binaryDir = $null
if (-not $FrontendOnly) {
    $binaryDir = Resolve-PresetBinaryDir $Preset
    if ($FullClean) {
        Clear-GeneratedTrees $binaryDir '-FullClean'
    } else {
        $cache = Join-Path $binaryDir 'CMakeCache.txt'
        if (Test-Path -LiteralPath $cache) {
            $cachedHome = (Select-String -LiteralPath $cache -Pattern '^CMAKE_HOME_DIRECTORY:INTERNAL=(.*)$' |
                Select-Object -First 1).Matches.Groups[1].Value
            if ($cachedHome -and ([IO.Path]::GetFullPath($cachedHome).TrimEnd('\') -ne [IO.Path]::GetFullPath($repoRoot).TrimEnd('\'))) {
                Clear-GeneratedTrees $binaryDir "build tree was configured for $cachedHome (repo moved)"
            }
        }
    }
}

if (-not $FrontendOnly) {
Write-Host "==> configuring preset '$Preset'"
# sccache (CI): mozilla sccache-action sets CMAKE_CXX_COMPILER_LAUNCHER=sccache
# in env. Forward it + any $CmakeExtra (e.g. -DSLOP_BUILD_TESTS=OFF) to the
# configure line so CI gets cache hits without touching local defaults.
$configureExtra = @()
if ($env:CMAKE_C_COMPILER_LAUNCHER) { $configureExtra += "-DCMAKE_C_COMPILER_LAUNCHER=$($env:CMAKE_C_COMPILER_LAUNCHER)" }
if ($env:CMAKE_CXX_COMPILER_LAUNCHER) { $configureExtra += "-DCMAKE_CXX_COMPILER_LAUNCHER=$($env:CMAKE_CXX_COMPILER_LAUNCHER)" }
if ($CmakeExtra -and $CmakeExtra.Trim()) { $configureExtra += $CmakeExtra.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries) }
if ($configureExtra.Count -gt 0) { Write-Host "==> configure extra: $($configureExtra -join ' ')" }
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $vsCMake --preset $Preset -S $repoRoot @configureExtra 2>&1 | ForEach-Object { "$_" } | Set-Content -LiteralPath (Join-Path $logDir 'configure.log')
Get-Content -LiteralPath (Join-Path $logDir 'configure.log') | Write-Host
$ErrorActionPreference = $prevEap
if ($LASTEXITCODE -ne 0) { throw "configure failed (exit $LASTEXITCODE), log: $(Join-Path $logDir 'configure.log')" }

if ($PlanOnly) {
    Write-Host '==> plan only, stopping before build'
    exit 0
}

Write-Host "==> building preset '$Preset'"
$ErrorActionPreference = 'Continue'
# `--build --preset` resolves CMakePresets.json from the *current* directory,
# which breaks when the script runs from anywhere but the repo root, build by
# binary dir instead (same dir the preset expands to, works from anywhere)
$buildArgs = @('--build', $binaryDir)
if ($Targets.Trim()) {
    $buildArgs += '--target'
    $buildArgs += $Targets.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries).Trim()
}
& $vsCMake @buildArgs 2>&1 | ForEach-Object { "$_" } | Set-Content -LiteralPath (Join-Path $logDir 'build.log')
Get-Content -LiteralPath (Join-Path $logDir 'build.log') | Write-Host
$ErrorActionPreference = $prevEap
if ($LASTEXITCODE -ne 0) { throw "build failed (exit $LASTEXITCODE), log: $(Join-Path $logDir 'build.log')" }

if ($Test) {
    # ctest from the same VS toolset (the vcvars PATH also carries the ASan
    # runtime DLLs an asan preset build needs)
    Write-Host "==> running tests (label '$TestLabel'$(if ($TestExclude) { ", excluding /$TestExclude/" }))"
    $ctestArgs = @('--test-dir', $binaryDir, '--output-on-failure', '--no-tests=error', '-L', $TestLabel)
    if ($TestExclude) { $ctestArgs += @('-E', $TestExclude) }
    & $vsCTest @ctestArgs
    # slop_tests_ps4 has a known intermittent watchdog hang that lands on a
    # different test each run (the debug-event listener and the fake payload's
    # port-755 channel). Retry only the entries that failed, up to twice, with
    # a short pause so the listener port settles; a real regression still fails
    # every attempt while the flake does not redden the lane.
    $retry = 0
    while ($LASTEXITCODE -ne 0 -and $retry -lt 2) {
        ++$retry
        Write-Host "==> tests failed, retrying the failed entries (retry $retry/2)"
        Start-Sleep -Seconds 2
        & $vsCTest --test-dir $binaryDir --output-on-failure --rerun-failed
    }
    if ($LASTEXITCODE -ne 0) { throw "tests failed (exit $LASTEXITCODE)" }
}

$cacheType = (Select-String -LiteralPath (Join-Path $binaryDir 'CMakeCache.txt') -Pattern '^CMAKE_BUILD_TYPE:STRING=(.*)$' |
    Select-Object -First 1).Matches.Groups[1].Value
$summary = [ordered]@{
    preset   = $Preset
    config   = $cacheType
    result   = 'success'
    logDir   = $logDir
    binary   = Join-Path $binaryDir 'src\app\reverse-slop.exe'
    engine   = Join-Path $binaryDir 'src\engine\reverse-slop-engine.exe'
}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $logDir 'summary.json')

Write-Host '==> build succeeded'
Write-Host "==> binary: $($summary.binary)"
Write-Host "==> engine: $($summary.engine)"
} else {
    Write-Host '==> frontend-only: skipping C++ configure/build (artifacts come from cxx job)'
}

# Tauri front end (the app)
# The Tauri UI is the shipped app; reverse-slop.exe (ImGui) is the legacy shell
# -NoFrontend skips this for a fast C++-only loop (the web build needs the Rust
# toolchain and node_modules, neither of which the engine or the ImGui shell
# depend on). The engine must already be built, tauri.conf.json bundles it as a
# resource from build\src\engine
if (-not $NoFrontend) {
    # Magicmida (Themida/WinLicense unpacker). The engine resolves it next to
    # itself (engine\tools\magicmida\<version>) before falling back to
    # %LOCALAPPDATA%. Keep the LOCALAPPDATA install as the source of truth
    # (tests and dev runs use it), then mirror it into build\ so the tauri
    # resource map can reference a repo-relative path
    $magicmidaVersion = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'magicmida-version.txt') -TotalCount 1).Trim()
    & powershell -NoProfile -File (Join-Path $PSScriptRoot 'install_magicmida.ps1')
    if ($LASTEXITCODE -ne 0) {
        if ($Full) { throw 'magicmida install failed, the full installer bundles the unpacker (network access needed)' }
        Write-Host '==> magicmida install failed (offline?), bundling without the unpacker' -ForegroundColor Yellow
    }
    $magicmidaLocal = Join-Path $env:LOCALAPPDATA "reverse-slop\tools\magicmida\$magicmidaVersion"
    $magicmidaStaged = Join-Path $repoRoot 'build\tools\magicmida'
    if (Test-Path -LiteralPath $magicmidaLocal) {
        if (Test-Path -LiteralPath $magicmidaStaged) { Remove-Item -LiteralPath $magicmidaStaged -Recurse -Force }
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $magicmidaStaged) | Out-Null
        Copy-Item -LiteralPath $magicmidaLocal -Destination $magicmidaStaged -Recurse
        Write-Host "==> magicmida staged: $magicmidaStaged"
    } else {
        if ($Full) { throw "magicmida not installed at $magicmidaLocal, run tools/install_magicmida.ps1 first" }
        Write-Host '==> magicmida not installed, bundling without the unpacker' -ForegroundColor Yellow
    }

    $appDir = Join-Path $repoRoot 'app'
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'cargo not found, install the Rust toolchain (https://rustup.rs) to build the Tauri front end'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $appDir 'node_modules'))) {
        Write-Host '==> installing frontend dependencies'
        # npm chats on stderr; under ErrorActionPreference=Stop PowerShell 5.1
        # turns the first stderr line into a terminating error, flatten the
        # streams like the cmake calls below.
        # `npm ci` is ~20-30% faster than `npm install` when package-lock.json
        # exists (clean, parallel, offline-cache friendly) — critical on CI
        # where node_modules cache may have missed.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        Push-Location $appDir
        try {
            if (Test-Path -LiteralPath (Join-Path $appDir 'package-lock.json')) {
                & npm ci --prefer-offline --no-audit --no-fund 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (Join-Path $logDir 'npm-install.log')
            } else {
                & npm install --no-audit --no-fund 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (Join-Path $logDir 'npm-install.log')
            }
            $npmExit = $LASTEXITCODE
        } finally { Pop-Location }
        $ErrorActionPreference = $prevEap
        if ($npmExit -ne 0) { throw "npm install failed (exit $npmExit), log: $(Join-Path $logDir 'npm-install.log')" }
    }
    Write-Host '==> building tauri bundle'
    Push-Location $appDir
    # node + tauri.js directly: `npm run tauri -- build` loses the `--` to
    # PowerShell, and npx needs a node_modules/.bin shim npm does not always write
    $tauriCli = Join-Path $appDir 'node_modules\@tauri-apps\cli\tauri.js'
    try {
        # tauri hard-fails on missing resource files, so filter the bundle map
        # to what exists. The override
        # carries the complete filtered resources map; the committed
        # tauri.conf.json stays authoritative
        $confPath = Join-Path $appDir 'src-tauri\tauri.conf.json'
        $conf = Get-Content -LiteralPath $confPath -Raw | ConvertFrom-Json
        $resources = [ordered]@{}
        foreach ($prop in $conf.bundle.resources.PSObject.Properties) {
            $src = Join-Path $repoRoot ($prop.Name -replace '^(\.\./)+', '')
            if (Test-Path -LiteralPath $src) { $resources[$prop.Name] = $prop.Value }
            elseif ($Full) { throw "resource missing: $($prop.Name), the full installer bundles everything" }
            else { Write-Host "==> resource missing, skipping: $($prop.Name)" }
        }
        if (Test-Path -LiteralPath $magicmidaStaged) {
            $resources['../../build/tools/magicmida'] = 'engine/tools/magicmida'
        } elseif ($Full) {
            throw 'magicmida absent, the full installer bundles the themida unpacker'
        } else {
            Write-Host '==> magicmida absent, bundling without the Themida unpacker'
        }
        $bundleOverride = @{ resources = $resources }
        # Updater artifacts (installer .sig, consumed by latest.json) need the
        # signing key; CI sets it for release builds. Local builds without the
        # key still produce the plain installer.
        if ($env:TAURI_SIGNING_PRIVATE_KEY -or $env:TAURI_SIGNING_PRIVATE_KEY_PATH) {
            $bundleOverride['createUpdaterArtifacts'] = $true
        }
        if ($Full -and -not $OnlineWebview) {
            # embed the whole webview2 runtime so a machine with neither
            # webview2 nor internet still installs, adds ~130 MB to the setup exe.
            # CI passes -OnlineWebview to skip the 150MB runtime download +
            # NSIS recompression (~1-2 min saved); local full builds keep offline.
            $bundleOverride['windows'] = @{ webviewInstallMode = @{ type = 'offlineInstaller' } }
        }
        if ($FastBundle) {
            if (-not $bundleOverride.ContainsKey('windows')) { $bundleOverride['windows'] = @{} }
            $bundleOverride['windows']['nsis'] = @{ compression = 'zlib' }
        }
        $override = @{ bundle = $bundleOverride }
        $overridePath = Join-Path $appDir 'src-tauri\tauri.build.conf.json'
        $override | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $overridePath
        # The tauri CLI logs its progress to stderr, which under
        # ErrorActionPreference=Stop kills PowerShell 5.1 as a NativeCommandError  
        # same flattening as the cmake/npm calls
        $prevEap = $ErrorActionPreference
        $tauriCommand = 'build'
        if ($BundleOnly) {
            $tauriCommand = 'bundle'
            $releaseDir = Join-Path $appDir 'src-tauri\target\release'
            if (-not (Test-Path -LiteralPath (Join-Path $releaseDir 'reverse-slop-ui.exe'))) {
                throw 'compiled frontend missing: download frontend-binary before -BundleOnly'
            }
            # Compilation deliberately has no sidecar resources. Stage the real
            # same-run artifacts for the portable layout as well as the installer.
            foreach ($entry in $resources.GetEnumerator()) {
                $src = Join-Path $repoRoot ($entry.Key -replace '^(\.\./)+', '')
                $dst = Join-Path $releaseDir $entry.Value
                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
                if (Test-Path -LiteralPath $src -PathType Container) {
                    New-Item -ItemType Directory -Force -Path $dst | Out-Null
                    Get-ChildItem -LiteralPath $src | Copy-Item -Destination $dst -Recurse -Force
                } else {
                    Copy-Item -LiteralPath $src -Destination $dst -Force
                }
            }
        }
        $ErrorActionPreference = 'Continue'
        & node $tauriCli $tauriCommand --config $overridePath 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (Join-Path $logDir 'tauri.log')
        $tauriExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        if ($tauriExit -ne 0) { throw "tauri build failed (exit $tauriExit), log: $(Join-Path $logDir 'tauri.log')" }
    } finally { Pop-Location }
    $nsisDir = Join-Path $appDir 'src-tauri\target\release\bundle\nsis'
    Write-Host "==> installer: $nsisDir"
    if ($Full) {
        # one place to see everything the setup exe carries, the whole point of
        # the full build is that the target machine needs nothing else
        $setup = Get-ChildItem -LiteralPath $nsisDir -Filter '*-setup.exe' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime | Select-Object -Last 1
        if ($setup) {
            Write-Host "==> full setup exe: $($setup.Name) ($('{0:N1}' -f ($setup.Length / 1MB)) MB)" -ForegroundColor Cyan
        }
        Write-Host '==> full installer contents:'
        if ($OnlineWebview) {
            Write-Host '    app + webview bootstrapper (downloads runtime if missing)'
        } else {
            Write-Host '    app + webview (offline runtime embedded, no download at install)'
        }
        Write-Host '    engine/reverse-slop-engine.exe'
        Write-Host '    engine/tools/magicmida (themida unpacker)'
        Write-Host '    target machine needs: windows (internet if webview bootstrapper needs the runtime)'
    }

    # Portable layout: the app exe plus the engine\ dir it looks for next to
    # itself. The packaging job appends the engine to the exe (SLOPENG1
    # overlay), so that build is one file; a local build without the overlay
    # still ships the engine\ dir.
    $release = Join-Path $appDir 'src-tauri\target\release'
    $portable = Join-Path $repoRoot 'dist\SlopStation'
    if (Test-Path -LiteralPath $portable) { Remove-Item -LiteralPath $portable -Recurse -Force }
    New-Item -ItemType Directory -Path $portable | Out-Null
    $portableExe = Join-Path $portable 'SlopStation.exe'
    Copy-Item -LiteralPath (Join-Path $release 'reverse-slop-ui.exe') -Destination $portableExe
    $embedded = $false
    $fs = [IO.File]::OpenRead($portableExe)
    try {
        if ($fs.Length -ge 24) {
            $fs.Seek(-24, [IO.SeekOrigin]::End) | Out-Null
            $footer = [byte[]]::new(24)
            $fs.Read($footer, 0, 24) | Out-Null
            $embedded = [Text.Encoding]::ASCII.GetString($footer, 0, 8) -eq 'SLOPENG1'
        }
    } finally { $fs.Close() }
    if (-not $embedded) {
        Copy-Item -LiteralPath (Join-Path $release 'engine') -Destination $portable -Recurse
    } else {
        Write-Host '==> portable: engine embedded in the exe (single file)'
    }
    # license + third-party notices travel with every distribution (the
    # installer gets them through the tauri resource map)
    Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination (Join-Path $portable 'LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'THIRD_PARTY_NOTICES.md') -Destination (Join-Path $portable 'THIRD_PARTY_NOTICES.md')
    Write-Host "==> portable: $(Join-Path $portable 'SlopStation.exe')"
    Write-Host '==> portable manifest:'
    Get-ChildItem -LiteralPath $portable -Recurse -File |
        ForEach-Object { "    $($_.FullName.Substring($portable.Length + 1)) ($('{0:N1}' -f ($_.Length / 1KB)) KB)" } |
        Write-Host
}
