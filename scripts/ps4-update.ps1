# ps4-update.ps1 — "PS4 Update" alias: check for and install the latest ps4-mcp release.
# Usage:
#   scripts\ps4-update.ps1              # interactive (asks y/N)
#   scripts\ps4-update.ps1 --yes        # unattended
#
# To install as a permanent PowerShell alias named "PS4-Update":
#   Add-Content $PROFILE "`nfunction PS4-Update { & '$PSScriptRoot\ps4-update.ps1' @args }"
[CmdletBinding(PositionalBinding=$false)]
param([switch]$Yes)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Bin = if (Test-Path (Join-Path $Root 'target\release\ps4-mcp.exe')) {
    Join-Path $Root 'target\release\ps4-mcp.exe'
} elseif (Test-Path (Join-Path $Root 'target\debug\ps4-mcp.exe')) {
    Join-Path $Root 'target\debug\ps4-mcp.exe'
} else {
    $null
}
if (-not $Bin) {
    throw "ps4-mcp.exe not found — build first: cargo build --release"
}
$UpdateArgs = @('update')
if ($Yes) { $UpdateArgs += '--yes' }
& $Bin @UpdateArgs
exit $LASTEXITCODE
