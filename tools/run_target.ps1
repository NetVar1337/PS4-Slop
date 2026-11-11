[CmdletBinding()]
param(
    # SlopTarget.exe; defaults to the build tree next to this checkout
    [string]$Target = (Join-Path (Split-Path -Parent $PSScriptRoot) 'build\src\app\SlopTarget.exe'),
    # How long the target runs before it is told to quit
    [int]$RunMilliseconds = 3000
)
# Smoke-runs the SlopTarget fixture: starts it, lets it publish its report,
# asks it to quit, then prints its stdout and the head of its JSON report.
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Target)) {
    throw "SlopTarget not found at $Target (build target slop_target, or pass -Target)"
}
$psi = [System.Diagnostics.ProcessStartInfo]::new($Target)
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$proc = [System.Diagnostics.Process]::Start($psi)
$outTask = $proc.StandardOutput.ReadToEndAsync()
Start-Sleep -Milliseconds $RunMilliseconds
$proc.StandardInput.WriteLine('quit')
$proc.StandardInput.Close()
if (-not $proc.WaitForExit(5000)) {
    $proc.Kill()
    throw 'SlopTarget did not exit within 5 s of quit'
}
Write-Host $outTask.Result
$jsonPath = Join-Path $env:TEMP "sloptarget-$($proc.Id).json"
if (Test-Path -LiteralPath $jsonPath) {
    Write-Host '--- JSON OK ---'
    Get-Content -LiteralPath $jsonPath | Select-Object -First 5
} else {
    Write-Host "--- JSON NOT found: $jsonPath ---"
    exit 1
}
