<#
.SYNOPSIS
  Start the shared broker plus GDB Remote bridges so IDA, Ghidra, Binary Ninja and iaito can debug one PS4 process.

.DESCRIPTION
  One broker owns the console debugger connection. Port 1234 is the controlling bridge (breakpoints, step,
  continue, detach). Ports 1235.. are observer bridges (registers/memory/maps only) for additional tools.
  Connecting a debugger to the controller is what attaches; starting this script does not touch the console.

  Requires debug_control enabled in the profile plus a matching hardware qualification (docs/QUALIFICATION.md).

.EXAMPLE
  .\integrations\live\start-live.ps1 -TargetPid 72 -Observers 3
  .\integrations\live\start-live.ps1 -Stop      # ends only the processes this script started
#>
param(
    [int] $TargetPid,
    [int] $Observers = 0,
    [int] $Port = 1234,
    [string] $Profile = (Join-Path $PSScriptRoot '..\..\profiles\ps4-1400.json'),
    [string] $CallbackAddress,
    [switch] $Stop
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$exe = Join-Path $root 'target\release\ps4-mcp.exe'
$logs = Join-Path $root 'workspace\live-logs'
$pidFile = Join-Path $logs 'started.pids'

if ($Stop) {
    if (Test-Path $pidFile) {
        Get-Content $pidFile | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
        Remove-Item $pidFile
    }
    Write-Host 'Stopped the broker/bridges started by this script (detach in your debugger first).'
    return
}
if (-not $TargetPid) { throw '-TargetPid is required (an observed PS4 process id)' }
if (-not (Test-Path $exe)) { throw 'Build first: cargo build --release --bins' }
$Profile = (Resolve-Path $Profile).Path
$consoleHost = (Get-Content $Profile -Raw | ConvertFrom-Json).host

# The PS4 calls the PC back on TCP 755: use the local IPv4 that routes to the console.
if (-not $CallbackAddress) {
    $CallbackAddress = (Find-NetRoute -RemoteIPAddress $consoleHost | Where-Object IPAddress | Select-Object -First 1).IPAddress
}
# Name kept from before the rename so existing firewall rules still match.
$rule = 'PS4 workbench debug callback (TCP 755)'
if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($admin) {
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Protocol TCP -LocalPort 755 `
            -RemoteAddress $consoleHost -Program $exe -Action Allow -Profile Any | Out-Null
        Write-Host "Firewall: allowed TCP 755 from $consoleHost only"
    } else {
        Write-Warning "Run once as administrator to allow the PS4 callback on TCP 755 from $consoleHost"
    }
}

New-Item -ItemType Directory -Force $logs | Out-Null
function Start-Hidden($name, $arguments) {
    $process = Start-Process $exe -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput "$logs\$name.out.log" -RedirectStandardError "$logs\$name.log"
    Add-Content $pidFile $process.Id
}
function Test-Port($p) {
    $client = [Net.Sockets.TcpClient]::new()
    try { $client.ConnectAsync('127.0.0.1', $p).Wait(300) -and $client.Connected } catch { $false } finally { $client.Dispose() }
}
function Wait-Port($p) {
    foreach ($i in 1..100) { if (Test-Port $p) { return }; Start-Sleep -Milliseconds 200 }
    throw "Port $p did not open; see $logs"
}

if (-not (Test-Port 8765)) {
    Start-Hidden 'broker' @('--profile', "`"$Profile`"", 'broker')
    Wait-Port 8765
}
$bridge = @('--profile', "`"$Profile`"", 'gdb-server', '--pid', $TargetPid, '--listen-address', $CallbackAddress)
Start-Hidden 'gdb-controller' ($bridge + @('--port', $Port, '--client-id', 'gdb-controller'))
Wait-Port $Port
foreach ($n in 1..$Observers) {
    if ($Observers -lt 1) { break }
    $p = $Port + $n
    Start-Hidden "gdb-observer-$n" ($bridge + @('--port', $p, '--client-id', "gdb-observer-$n", '--observer'))
    Wait-Port $p
}

$gdb = 'C:\msys64\mingw64\bin\gdb-multiarch.exe'
$ports = if ($Observers -gt 0) { "controller $Port, observers $($Port + 1)-$($Port + $Observers)" } else { "controller $Port" }
Write-Host @"

PS4 $consoleHost  pid $TargetPid  callback $CallbackAddress`:755   bridges on 127.0.0.1: $ports

  IDA Pro       Debugger > Switch debugger > Remote GDB debugger; Debugger > Process options: host 127.0.0.1, port <port>;
                Debugger > Attach to process > pid $TargetPid
  Ghidra        Debugger tool, launcher 'gdb remote': gdb command $gdb, Target remote, Host 127.0.0.1, Port <port>
  Binary Ninja  Debugger > Connect to Remote Process: adapter LLDB, host 127.0.0.1, port <port> (stub type gdb-remote)
  iaito         File > Open, enable Debug, file: gdb://127.0.0.1:<port>/$TargetPid

Attach the controller first; observers can only read. Logs: $logs
Stop: .\integrations\live\start-live.ps1 -Stop
"@
