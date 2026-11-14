# tools/clean.ps1
# Drops the generated trees that pile up in a checkout: the CMake build dirs
# (one per preset) and the dependency sub-builds. Downloaded dependency
# sources in _ext\*-src are kept unless -All is passed, so the next build does
# not re-download them.
#
#   powershell -NoProfile -File tools/clean.ps1            # build trees only
#   powershell -NoProfile -File tools/clean.ps1 -All       # + deps sources, node_modules, cargo target
#   powershell -NoProfile -File tools/clean.ps1 -DryRun    # print what would go

[CmdletBinding()]
param(
    # also drop _ext\*-src, app\node_modules, app\src-tauri\target and the
    # release/coverage scratch files (a full re-fetch on the next build)
    [switch]$All,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

$targets = @()

# CMake build dirs: build\ plus one build-<preset>\ per non-release preset
$targets += @(Get-ChildItem -LiteralPath $repoRoot -Directory -Filter 'build*' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq 'build' -or $_.Name -like 'build-*' })

$ext = Join-Path $repoRoot '_ext'
if (Test-Path -LiteralPath $ext) {
    $targets += @(Get-ChildItem -LiteralPath $ext -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*-build' -or $_.Name -like '*-subbuild' })
    if ($All) {
        $targets += @(Get-ChildItem -LiteralPath $ext -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*-src' })
    }
}

if ($All) {
    foreach ($rel in @('app\node_modules', 'app\src-tauri\target', 'dist', '_release', 'fuzz-artifacts')) {
        $p = Join-Path $repoRoot $rel
        if (Test-Path -LiteralPath $p) { $targets += Get-Item -LiteralPath $p }
    }
    foreach ($rel in @('coverage.xml', 'analyze.log', 'mcp_live_results.json')) {
        $p = Join-Path $repoRoot $rel
        if (Test-Path -LiteralPath $p) { $targets += Get-Item -LiteralPath $p }
    }
}

if ($targets.Count -eq 0) {
    Write-Host 'nothing to clean'
    return
}

$freed = 0L
foreach ($t in ($targets | Sort-Object FullName -Unique)) {
    $size = if ($t.PSIsContainer) {
        (Get-ChildItem -LiteralPath $t.FullName -Recurse -File -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
    } else { $t.Length }
    if (-not $size) { $size = 0 }
    $freed += $size
    $rel = $t.FullName.Substring($repoRoot.Length).TrimStart('\')
    if ($DryRun) {
        Write-Host ("would remove {0} ({1:N1} MB)" -f $rel, ($size / 1MB))
    } else {
        Write-Host ("removing {0} ({1:N1} MB)" -f $rel, ($size / 1MB))
        Remove-Item -LiteralPath $t.FullName -Recurse -Force
    }
}
$verb = if ($DryRun) { 'would free' } else { 'freed' }
Write-Host ("{0} {1:N1} GB" -f $verb, ($freed / 1GB))
