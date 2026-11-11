[CmdletBinding()]
param(
    # Skip building slop_app_bench (use the existing build\tests binary)
    [switch]$SkipBuild,
    # Skip the frontend SSR benchmark (needs app\node_modules)
    [switch]$SkipUi,
    # Fail when a workload's median exceeds baseline * this factor. CI runners
    # are noisier than the machine that recorded the baseline, so the default
    # only catches real regressions (algorithmic blow-ups, lost caches).
    [double]$MaxSlowdown = 3.0,
    # Overwrite docs\benchmarks\*-after.json with this run (after an intended
    # performance change; commit the result)
    [switch]$UpdateBaseline,
    # Where this run's JSON goes
    [string]$OutDir = ''
)
# Runs the app benchmarks and compares them with the committed baselines in
# docs\benchmarks (see docs\benchmarks\README.md). Exit 1 on a regression or a
# changed workload result.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$docs = Join-Path $root 'docs\benchmarks'
if (-not $OutDir) { $OutDir = Join-Path $root 'build\bench' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not $SkipBuild) {
    & powershell -NoProfile -File (Join-Path $PSScriptRoot 'build.ps1') -NoFrontend -Targets 'slop_app_bench' `
        -CmakeExtra '-DSLOP_BUILD_TESTS=ON -DSLOP_BUILD_TEST_TARGET=ON'
    if ($LASTEXITCODE -ne 0) { throw 'building slop_app_bench failed' }
}

$failures = [Collections.Generic.List[string]]::new()
$rows = [Collections.Generic.List[object]]::new()
function Add-Row($suite, $name, $base, $now) {
    $ratio = if ($base -gt 0) { [Math]::Round($now / $base, 2) } else { $null }
    $rows.Add([pscustomobject]@{ Suite = $suite; Workload = $name; BaselineMs = $base; Ms = $now; Ratio = $ratio })
    if ($ratio -and $ratio -gt $MaxSlowdown) {
        $failures.Add("$suite/$name median $now ms is ${ratio}x the baseline $base ms (limit ${MaxSlowdown}x)")
    }
}

# native: slop_app_bench (scanner, traffic store, event bus, MCP output paths)
$appOut = Join-Path $OutDir 'app.json'
& (Join-Path $root 'build\tests\slop_app_bench.exe') $appOut | Out-Null
if ($LASTEXITCODE -ne 0) { throw "slop_app_bench failed (exit $LASTEXITCODE)" }
$app = Get-Content -LiteralPath $appOut -Raw | ConvertFrom-Json
$appBase = Get-Content -LiteralPath (Join-Path $docs 'app-after.json') -Raw | ConvertFrom-Json
foreach ($b in $appBase.workloads) {
    $n = @($app.workloads | Where-Object name -EQ $b.name)
    if ($n.Count -ne 1) { $failures.Add("app/$($b.name): workload missing from this run"); continue }
    if ("$($n[0].result)" -ne "$($b.result)") {
        $failures.Add("app/$($b.name): result changed $($b.result) -> $($n[0].result)")
    }
    Add-Row 'app' $b.name $b.median_ms $n[0].median_ms
}

# frontend: OutputPanel SSR render of 4096 rows (app\scripts\bench-ui.mjs)
if (-not $SkipUi) {
    $uiOut = Join-Path $OutDir 'ui.json'
    Push-Location (Join-Path $root 'app')
    try {
        & node scripts/bench-ui.mjs $uiOut | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "bench-ui.mjs failed (exit $LASTEXITCODE)" }
    } finally { Pop-Location }
    $ui = Get-Content -LiteralPath $uiOut -Raw | ConvertFrom-Json
    $uiBase = Get-Content -LiteralPath (Join-Path $docs 'ui-after.json') -Raw | ConvertFrom-Json
    if ($ui.workload -ne $uiBase.workload) { $failures.Add("ui: workload $($ui.workload) != baseline $($uiBase.workload)") }
    Add-Row 'ui' $ui.workload ([Math]::Round($uiBase.median_ms, 3)) ([Math]::Round($ui.median_ms, 3))
}

$table = $rows | Format-Table -AutoSize | Out-String
Write-Host $table
if ($env:GITHUB_STEP_SUMMARY) {
    $md = @('| Suite | Workload | Baseline ms | This run ms | Ratio |', '|---|---|---|---|---|')
    $md += $rows | ForEach-Object { "| $($_.Suite) | $($_.Workload) | $($_.BaselineMs) | $($_.Ms) | $($_.Ratio) |" }
    $md += ''
    $md += if ($failures.Count) { $failures | ForEach-Object { "- :x: $_" } } else { "- no regression beyond ${MaxSlowdown}x" }
    $md -join "`n" | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
}

if ($UpdateBaseline) {
    Copy-Item -LiteralPath $appOut -Destination (Join-Path $docs 'app-after.json') -Force
    if (-not $SkipUi) { Copy-Item -LiteralPath (Join-Path $OutDir 'ui.json') -Destination (Join-Path $docs 'ui-after.json') -Force }
    Write-Host '==> baselines updated in docs\benchmarks (commit them)'
    exit 0
}
if ($failures.Count) {
    $failures | ForEach-Object { Write-Host "REGRESSION: $_" }
    exit 1
}
Write-Host "==> benchmarks within ${MaxSlowdown}x of baseline"
