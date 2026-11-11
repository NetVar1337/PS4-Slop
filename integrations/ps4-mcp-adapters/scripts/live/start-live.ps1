<#
.SYNOPSIS
  Start the PS4-Slop engine (MCP server on 8765) and the GDB Remote bridge so
  IDA, Ghidra, Binary Ninja and iaito can share one PS4 debug session.

.DESCRIPTION
  PS4-Slop owns the console connection through its built-in MCP server
  (http://127.0.0.1:8765/mcp). This script starts the engine if it is not
  already listening, then opens the GDB-RSP bridge (the `gdb` MCP tool) on
  127.0.0.1:2331 so a GDB/LLDB client can attach with:

      gdb -ex 'target remote 127.0.0.1:2331'

  The console itself is attached from the UI or with
  target.ps4_connect {host, pid} / debugger.ps4_attach — starting this script
  does not touch the console.

.EXAMPLE
  .\integrations\ps4-mcp-adapters\scripts\live\start-live.ps1
  .\integrations\ps4-mcp-adapters\scripts\live\start-live.ps1 -GdbPort 2331
  .\integrations\ps4-mcp-adapters\scripts\live\start-live.ps1 -Stop
#>
param(
    [int] $McpPort = 8765,
    [int] $GdbPort = 2331,
    [switch] $NoGdbBridge,
    [switch] $Stop
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
$exe = Join-Path $root 'build\src\engine\reverse-slop-engine.exe'
$logs = Join-Path $root 'build\live-logs'
$pidFile = Join-Path $logs 'started.pids'
New-Item -ItemType Directory -Force -Path $logs | Out-Null

function Test-Port([int] $Port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { $c.Connect('127.0.0.1', $Port); $c.Close(); return $true } catch { return $false }
}

function Invoke-Mcp([string] $Tool, [hashtable] $Arguments) {
    $body = @{ jsonrpc = '2.0'; id = 1; method = 'tools/call'
               params = @{ name = $Tool; arguments = $Arguments } } | ConvertTo-Json -Depth 8
    $r = Invoke-RestMethod -Uri "http://127.0.0.1:$McpPort/mcp" -Method Post -Body $body -ContentType 'application/json'
    if ($r.error) { throw "MCP error: $($r.error.message)" }
    return ($r.result.content[0].text | ConvertFrom-Json)
}

if ($Stop) {
    if (Test-Path $pidFile) {
        Get-Content $pidFile | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
        Remove-Item $pidFile
    }
    Write-Host 'Stopped the processes started by this script (detach in your debugger first).'
    return
}

if (-not (Test-Path $exe)) { throw "Engine not built: $exe (run tools/build.ps1 -NoFrontend first)" }

if (-not (Test-Port $McpPort)) {
    Write-Host "Starting PS4-Slop engine (MCP on 127.0.0.1:$McpPort)..."
    $p = Start-Process -FilePath $exe -ArgumentList "--mcp-port", $McpPort -PassThru -WorkingDirectory $root
    Add-Content $pidFile $p.Id
    $deadline = Get-Date
    while (-not (Test-Port $McpPort)) {
        if ((Get-Date).AddSeconds(-30) -lt $deadline) { } else { throw 'engine did not open the MCP port within 30 s' }
        Start-Sleep -Milliseconds 250
    }
} else {
    Write-Host "MCP server already listening on 127.0.0.1:$McpPort"
}

if (-not $NoGdbBridge) {
    if (Test-Port $GdbPort) {
        Write-Host "GDB-RSP bridge already listening on 127.0.0.1:$GdbPort"
    } else {
        $res = Invoke-Mcp 'gdb' @{ action = 'start'; port = $GdbPort; bind = '127.0.0.1'; allow_writes = $false }
        if ($res.running -ne $true) { throw "gdb.start failed: $($res | ConvertTo-Json -Depth 4)" }
        Write-Host "GDB-RSP bridge listening on 127.0.0.1:$GdbPort  (gdb -ex 'target remote 127.0.0.1:$GdbPort')"
        Write-Host 'Attach the console first: target.ps4_connect {host, pid} then debugger.ps4_attach {pid}.'
    }
}
