# setup-profile.ps1 — create profiles/ps4-1400.local.json from the safe template.
[CmdletBinding()]
param([string]$ConsoleHost, [switch]$Force)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Src = Join-Path $Root 'profiles\ps4-1400.json'
$Dst = Join-Path $Root 'profiles\ps4-1400.local.json'
if ((Test-Path $Dst) -and -not $Force) { throw "$Dst already exists; use -Force to overwrite" }
Copy-Item $Src $Dst
if ($ConsoleHost) {
    $json = Get-Content $Dst -Raw | ConvertFrom-Json
    $json.host = $ConsoleHost
    [System.IO.File]::WriteAllText($Dst, ($json | ConvertTo-Json -Depth 32), [System.Text.UTF8Encoding]::new($false))
}
Write-Host '[setup-profile] Local profile created. Next steps (docs/QUALIFICATION.md):'
Write-Host '  1. Record the REAL Afterglow commit / HEN build in profiles/ps4-1400.local.json.'
Write-Host '  2. ps4-workbench --profile profiles/ps4-1400.local.json afterglow-verify --directory C:/path/to/afterglow-web'
Write-Host '  3. Load ps4debug-NG manually, then: ps4-workbench --profile ... preflight --probe'
Write-Host '  4. Enable only tested permissions, then: scripts/qualify-local.ps1 --evidence ... --attest I_TESTED_THIS_EXACT_CONFIGURATION --approve ...'
