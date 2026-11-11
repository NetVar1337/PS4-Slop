#!/usr/bin/env pwsh
# slop.ps1 - single entry point for the whole PS4-Slop project.
#
# The repo is one project made of four runtimes that each keep their own build:
#   app      C++/Tauri desktop analyzer      (CMake + npm, this dir)
#   payload  ps4debug-NG debugger payload    (vendor/ps4debug-NG)
#   mcp      Python MCP servers for agents   (mcp/ps4-mcp, mcp/ps4debug-mcp)
#   exploit  afterglow-web browser jailbreak (exploit/afterglow-web)
#
# End-to-end flow: serve the exploit to the PS4 browser -> it loads the
# ps4debug-NG payload -> the app connects and debugs -> agents drive it via MCP.
#
# Usage: ./slop.ps1 <command>
#   app | payload | mcp | exploit | all | help

param([Parameter(Position = 0)][string]$Command = "help")

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

function Build-App {
    Write-Host "==> app: configure + build (ninja-msvc-release)" -ForegroundColor Cyan
    & cmake --preset ninja-msvc-release
    & cmake --build --preset ninja-msvc-release
    Write-Host "==> app: frontend (npm)" -ForegroundColor Cyan
    Push-Location (Join-Path $Root "app")
    try { & npm install; & npm run build } finally { Pop-Location }
}

function Build-Payload {
    Write-Host "==> payload: ps4debug-NG" -ForegroundColor Cyan
    Push-Location (Join-Path $Root "vendor/ps4debug-NG")
    try { & powershell -File ./build.ps1 } finally { Pop-Location }
}

function Setup-Mcp {
    Write-Host "==> mcp: venv + editable installs" -ForegroundColor Cyan
    $venv = Join-Path $Root ".venv"
    if (-not (Test-Path $venv)) { & python -m venv $venv }
    $pip = Join-Path $venv "Scripts/pip.exe"
    & $pip install -e (Join-Path $Root "mcp/ps4-mcp")
    & $pip install -e (Join-Path $Root "mcp/ps4debug-mcp")
    Write-Host "    installed. run a server e.g.:  .venv/Scripts/ps4debug-mcp" -ForegroundColor DarkGray
}

function Serve-Exploit {
    Write-Host "==> exploit: serving afterglow-web (point the PS4 browser here)" -ForegroundColor Cyan
    # serve.sh gets MIME + no-cache-on-.bin right; a stale payload freezes the
    # console, so reuse it rather than a plain http.server.
    Push-Location (Join-Path $Root "exploit/afterglow-web")
    try { & bash ./serve.sh } finally { Pop-Location }
}

switch ($Command.ToLower()) {
    "app"     { Build-App }
    "payload" { Build-Payload }
    "mcp"     { Setup-Mcp }
    "exploit" { Serve-Exploit }
    "all"     { Build-App; Build-Payload; Setup-Mcp;
                Write-Host "built app + payload, mcp ready. 'slop exploit' to serve the jailbreak." -ForegroundColor Green }
    default   {
        Get-Content $PSCommandPath | Select-String -Pattern "^#" | ForEach-Object { $_.Line -replace "^# ?", "" } |
            Select-Object -First 18 | ForEach-Object { Write-Host $_ }
    }
}
