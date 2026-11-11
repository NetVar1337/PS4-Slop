# tools/screenshots.ps1 — regenerate docs/screenshots from the real UI.
# Requires a built engine + fixture (tools/build.ps1 -NoFrontend), app npm
# deps and app/e2e npm deps. Wraps app/e2e/run.mjs screenshots.
[CmdletBinding()]
param(
    # Skip the app/e2e dependency install step
    [switch]$SkipInstall
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$engine = Join-Path $root 'build\src\engine\reverse-slop-engine.exe'
$fixture = Join-Path $root 'build\src\app\SlopTarget.exe'
foreach ($exe in @($engine, $fixture)) {
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "missing $exe — build first: powershell -File tools/build.ps1 -NoFrontend"
    }
}

$vite = Join-Path $root 'app\node_modules\vite\bin\vite.js'
if (-not (Test-Path -LiteralPath $vite)) {
    Write-Host 'installing app npm deps...'
    npm --prefix (Join-Path $root 'app') ci --prefer-offline --no-audit --no-fund
}

if (-not $SkipInstall) {
    Write-Host 'installing app/e2e npm deps...'
    npm --prefix (Join-Path $root 'app\e2e') ci --prefer-offline --no-audit --no-fund
}

& node (Join-Path $root 'app\e2e\run.mjs') screenshots
if ($LASTEXITCODE -ne 0) { throw "screenshot run failed ($LASTEXITCODE)" }
Write-Host 'screenshots regenerated in docs/screenshots/'
