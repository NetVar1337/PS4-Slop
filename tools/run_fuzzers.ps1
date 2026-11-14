# tools/run_fuzzers.ps1
# Runs the libFuzzer targets from the ninja-msvc-fuzz preset for a fixed time
# each and fails on a crash (libFuzzer writes the reproducer into
# <ArtifactDir>/<target>/).
#
#   powershell -NoProfile -File tools/run_fuzzers.ps1 -Seconds 60
#   powershell -NoProfile -File tools/run_fuzzers.ps1 -Targets ps4,zip -Seconds 300
#
# The seeds in src/fuzz/corpus/<target>/ are copied to a scratch corpus first:
# libFuzzer appends new units to the corpus directory and the checkout must
# stay clean.

[CmdletBinding()]
param(
    [string]$Preset = 'ninja-msvc-fuzz',
    # seconds per target
    [int]$Seconds = 60,
    # comma list of target suffixes (elf, pe, macho, ipa, zip, ps4, dotnet)
    [string]$Targets = '',
    [string]$ArtifactDir = 'fuzz-artifacts',
    [int]$MaxLen = 65536,
    [string]$VsRoot = $env:SLOP_VS_ROOT
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

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
    return [IO.Path]::GetFullPath($dir.Replace('${sourceDir}', $repoRoot).Replace('${presetName}', $name))
}

# The fuzzers are ASan-instrumented: clang_rt.asan_dynamic-x86_64.dll lives in
# the MSVC toolset bin dir, so run them with the vcvars environment.
if (-not $VsRoot) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $VsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    }
}
if (-not $VsRoot -or -not (Test-Path -LiteralPath (Join-Path $VsRoot 'VC\Auxiliary\Build\vcvars64.bat'))) {
    throw 'Visual Studio with C++ tools not found (pass -VsRoot or set SLOP_VS_ROOT)'
}
$vcvars = Join-Path $VsRoot 'VC\Auxiliary\Build\vcvars64.bat'
cmd /c "call `"$vcvars`" > NUL 2>&1 && set" | ForEach-Object {
    if ($_ -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        Set-Item -Path ("Env:" + $Matches[1]) -Value $Matches[2]
    }
}

$binaryDir = if ($env:SLOP_BUILD_DIR) { [IO.Path]::GetFullPath($env:SLOP_BUILD_DIR) } else { Resolve-PresetBinaryDir $Preset }
$fuzzDir = Join-Path $binaryDir 'fuzz'
$all = @('elf', 'pe', 'macho', 'ipa', 'zip', 'ps4', 'dotnet')
$names = if ($Targets.Trim()) { $Targets.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries).Trim() } else { $all }

$artifactRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot $ArtifactDir))
if (Test-Path -LiteralPath $artifactRoot) { Remove-Item -LiteralPath $artifactRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null

$failed = @()
foreach ($name in $names) {
    $exe = Join-Path $fuzzDir "fuzz_$name.exe"
    if (-not (Test-Path -LiteralPath $exe)) { throw "fuzz_$name.exe not built in $fuzzDir (build the $Preset preset)" }

    # scratch corpus: seeds copied, mutations stay out of the checkout
    $corpus = Join-Path $env:TEMP "slop-fuzz-corpus-$name"
    if (Test-Path -LiteralPath $corpus) { Remove-Item -LiteralPath $corpus -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $corpus | Out-Null
    $seeds = Join-Path $repoRoot "src/fuzz/corpus/$name"
    if (Test-Path -LiteralPath $seeds) { Copy-Item -Path (Join-Path $seeds '*') -Destination $corpus -Recurse -Force }
    $artifacts = Join-Path $artifactRoot $name
    New-Item -ItemType Directory -Force -Path $artifacts | Out-Null

    Write-Host "==> fuzz_$name for $Seconds s"
    $fuzzArgs = @("$corpus", "-max_total_time=$Seconds", "-max_len=$MaxLen",
                  "-artifact_prefix=$artifacts\", "-print_final_stats=1")
    & $exe @fuzzArgs
    $code = $LASTEXITCODE
    $crashes = @(Get-ChildItem -LiteralPath $artifacts -File -ErrorAction SilentlyContinue)
    if ($code -ne 0 -or $crashes.Count -gt 0) {
        $failed += "$name (exit $code, $($crashes.Count) artifact(s))"
        $crashes | ForEach-Object { Write-Host "  crash: $($_.FullName)" }
    }
}

if ($failed.Count -gt 0) {
    throw "fuzz targets failed: $($failed -join '; ') (reproducers in $artifactRoot)"
}
Write-Host "==> every fuzz target ran $Seconds s without a crash"
