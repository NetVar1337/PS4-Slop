# start-broker.ps1 — start the shared broker for ps4_mcp/ctl.py and the
# IDA/Ghidra/Binja adapters. Mutating tools still require profile permissions
# plus a matching qualification record.
[CmdletBinding()]
param(
    [string]$Profile = 'profiles\ps4-1400.local.json',
    [ValidateSet('static','read-only','debug','full')][string]$Toolset = 'full',
    [int]$Port = 24600,
    [string]$TokenFile = 'profiles\broker-token.local'
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Bin = if (Test-Path (Join-Path $Root 'target\release\ps4-mcp.exe')) { Join-Path $Root 'target\release\ps4-mcp.exe' } else { Join-Path $Root 'target\debug\ps4-mcp.exe' }
if (-not (Test-Path $Bin)) { throw 'build first: cargo build --release' }
Write-Host "[start-broker] profile=$Profile toolset=$Toolset port=$Port token=$TokenFile"
& $Bin --profile $Profile --toolset $Toolset broker --port $Port --token-file $TokenFile
exit $LASTEXITCODE
