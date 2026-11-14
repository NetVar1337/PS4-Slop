# tools/coverage_ratchet.ps1
# Line-coverage ratchet for src/core, fed by the Cobertura report the nightly
# coverage lane produces (OpenCppCoverage over a Debug build).
#
#   powershell -NoProfile -File tools/coverage_ratchet.ps1 -Cobertura coverage.xml
#   powershell -NoProfile -File tools/coverage_ratchet.ps1 -Cobertura coverage.xml -Update
#
# The baseline lives in docs/coverage-baseline.txt. A run fails when src/core
# line coverage drops more than -Tolerance points below it; -Update rewrites
# the baseline after an intentional improvement.

[CmdletBinding()]
param(
    [string]$Cobertura = 'coverage.xml',
    [string]$Baseline = 'docs/coverage-baseline.txt',
    [double]$Tolerance = 0.5,
    # only files under this path fragment count (the report also covers src/ui,
    # src/engine, ... — the ratchet is on the core library)
    [string]$Scope = '\src\core\',
    [switch]$Update
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Cobertura)) { throw "coverage report not found: $Cobertura" }

[xml]$doc = Get-Content -LiteralPath $Cobertura
$pattern = [regex]::Escape($Scope)
$classes = @($doc.SelectNodes('//class'))
if ($classes.Count -eq 0) { throw "$Cobertura has no <class> entries (not a Cobertura report?)" }

$valid = 0
$covered = 0
$files = 0
foreach ($c in $classes) {
    if (-not $c.filename -or $c.filename -notmatch $pattern) { continue }
    $files++
    foreach ($line in $c.SelectNodes('lines/line')) {
        $valid++
        if ([int]$line.hits -gt 0) { $covered++ }
    }
}
if ($valid -eq 0) { throw "no instrumented lines under $Scope in $Cobertura" }

$pct = [math]::Round(100.0 * $covered / $valid, 2)
Write-Host "src/core line coverage: $pct% ($covered/$valid lines, $files files)"

$summary = $env:GITHUB_STEP_SUMMARY
if ($summary) { "### src/core line coverage: $pct%" | Add-Content -LiteralPath $summary }

$baselinePct = 0.0
if (Test-Path -LiteralPath $Baseline) {
    $m = Select-String -LiteralPath $Baseline -Pattern '^\s*core_line_coverage\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*$'
    if ($m) { $baselinePct = [double]$m.Matches[0].Groups[1].Value }
}
$floor = [math]::Round($baselinePct - $Tolerance, 2)

if ($Update) {
    $text = @(
        '# Line coverage of src/core, measured by the nightly coverage lane',
        '# (tools/coverage_ratchet.ps1 over the OpenCppCoverage Cobertura report).',
        '# A run fails when the value drops more than 0.5 points below this one;',
        '# raise it with -Update after an intentional improvement.',
        "core_line_coverage = $pct"
    ) -join "`n"
    Set-Content -LiteralPath $Baseline -Value ($text + "`n") -Encoding utf8 -NoNewline
    Write-Host "baseline updated: $pct%"
    exit 0
}

if ($baselinePct -le 0) {
    Write-Host "no baseline yet (core_line_coverage = 0); commit this value to ${Baseline}:"
    Write-Host "  powershell -NoProfile -File tools/coverage_ratchet.ps1 -Cobertura $Cobertura -Update"
    exit 0
}

if ($pct -lt $floor) {
    throw "src/core line coverage dropped to $pct% (baseline $baselinePct%, floor $floor%): " +
          "add tests for the new code, or re-baseline with -Update if the drop is intentional"
}
Write-Host "ok: $pct% >= floor $floor% (baseline $baselinePct%)"
if ($pct -gt $baselinePct) {
    Write-Host "coverage improved; re-baseline with -Update to lock it in"
}
