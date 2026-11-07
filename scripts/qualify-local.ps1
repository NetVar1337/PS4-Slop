# qualify-local.ps1 — offline checks, then the real `qualify` CLI.
# Example:
#   scripts/qualify-local.ps1 --evidence C:/research/my-hardware-tests.md `
#     --attest I_TESTED_THIS_EXACT_CONFIGURATION --approve debug_control `
#     --afterglow-directory C:/research/afterglow-web
[CmdletBinding(PositionalBinding=$false)]
param(
    [string]$Profile = 'profiles\ps4-1400.local.json',
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$QualifyArgs
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    if (-not (Test-Path $Profile)) { throw "$Profile missing; run scripts/setup-profile.ps1 first" }
    Write-Host '[qualify-local] 1/4 cargo test (offline fixture + unit tests)'
    cargo test --locked -j 2
    if ($LASTEXITCODE) { throw 'cargo test failed' }
    Write-Host '[qualify-local] 2/4 python adapter/ctl tests against the real broker'
    python -m unittest discover -q
    if ($LASTEXITCODE) { throw 'python tests failed' }
    $Bin = if (Test-Path 'target\debug\ps4-workbench.exe') { 'target\debug\ps4-workbench.exe' } else { 'target\release\ps4-workbench.exe' }
    if (-not (Test-Path $Bin)) { throw 'build the workbench first: cargo build --locked' }
    Write-Host '[qualify-local] 3/4 workbench validate'
    & $Bin --profile $Profile validate
    if ($LASTEXITCODE) { throw 'validate failed' }
    Write-Host '[qualify-local] 4/4 qualify CLI (no console contact; records your attestation)'
    & $Bin --profile $Profile qualify @QualifyArgs
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
