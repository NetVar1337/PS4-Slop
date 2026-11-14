# tools/check_binaries.ps1
# Release-artifact hardening gate: every shipped .exe must carry the
# mitigation flags we build with, and must not import or expose anything the
# build does not expect (a new import or section means a new dependency, a
# dropped /MT, or code injected after the build).
#
#   powershell -NoProfile -File tools/check_binaries.ps1 -Path build\src\engine\reverse-slop-engine.exe
#   powershell -NoProfile -File tools/check_binaries.ps1 -Path dist\SlopStation\SlopStation.exe -AllowImport KERNEL32.dll,USER32.dll
#
# Runs in release.yml before publish. Needs dumpbin (the Visual Studio C++
# toolset), located through vswhere like tools/build.ps1.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Path,
    [string[]]$AllowImport = @(
        'ADVAPI32.dll', 'bcrypt.dll', 'CRYPT32.dll', 'dbghelp.dll', 'GDI32.dll',
        'IPHLPAPI.DLL', 'KERNEL32.dll', 'ncrypt.dll', 'ole32.dll', 'Secur32.dll',
        'SHELL32.dll', 'USER32.dll', 'WS2_32.dll'
    ),
    [string[]]$AllowSection = @('.text', '.rdata', '.data', '.pdata', '.fptable', '.rsrc', '.reloc'),
    # DllCharacteristics lines dumpbin prints for the flags we require
    [string[]]$RequireFlag = @(
        'Dynamic base', 'NX compatible', 'High Entropy Virtual Addresses',
        'Control Flow Guard', 'CET compatible'
    ),
    [string]$VsRoot = $env:SLOP_VS_ROOT
)

$ErrorActionPreference = 'Stop'

if (-not $VsRoot) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $VsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    }
}
if (-not $VsRoot -or -not (Test-Path -LiteralPath (Join-Path $VsRoot 'VC\Auxiliary\Build\vcvars64.bat'))) {
    throw 'Visual Studio with C++ tools not found (pass -VsRoot or set SLOP_VS_ROOT)'
}
$vcvars = Join-Path $VsRoot 'VC\Auxiliary\Build\vcvars64.bat'
cmd /c "call `"$vcvars`" > NUL 2>&1 && set" | ForEach-Object {
    if ($_ -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        Set-Item -Path ("Env:" + $Matches[1]) -Value $Matches[2]
    }
}

$problems = @()
foreach ($file in $Path) {
    if (-not (Test-Path -LiteralPath $file)) { throw "binary not found: $file" }
    $file = [IO.Path]::GetFullPath($file)
    Write-Host "==> $file"

    $headers = & dumpbin /nologo /headers $file
    if ($LASTEXITCODE -ne 0) { throw "dumpbin /headers failed for $file" }
    $imports = & dumpbin /nologo /imports $file
    if ($LASTEXITCODE -ne 0) { throw "dumpbin /imports failed for $file" }

    $text = ($headers -join "`n")
    foreach ($flag in $RequireFlag) {
        if ($text -notmatch [regex]::Escape($flag)) {
            $problems += "$file : missing mitigation flag '$flag'"
        }
    }

    # "   .text name" -> .text  (section names are the only lines ending in " name")
    $sections = @($headers | Where-Object { $_ -match '^\s*(\.[A-Za-z0-9_$]+)\s+name\s*$' } |
        ForEach-Object { $Matches[1] })
    foreach ($s in $sections) {
        if ($AllowSection -notcontains $s) { $problems += "$file : unexpected section '$s'" }
    }

    # import table entries: "    KERNEL32.dll" (delay imports print the same way)
    $dlls = @($imports | Where-Object { $_ -match '^\s{4}([A-Za-z0-9_.-]+\.dll)\s*$' } |
        ForEach-Object { $Matches[1] } | Sort-Object -Unique)
    if ($dlls.Count -eq 0) { $problems += "$file : no imports parsed (dumpbin output format changed?)" }
    foreach ($d in $dlls) {
        if ($AllowImport -notcontains $d) { $problems += "$file : unexpected import '$d'" }
    }

    Write-Host ("    flags:    " + (($RequireFlag | Where-Object { $text -match [regex]::Escape($_) }) -join ', '))
    Write-Host ("    sections: " + ($sections -join ' '))
    Write-Host ("    imports:  " + ($dlls -join ' '))
}

if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Host "FAIL: $_" }
    throw "$($problems.Count) binary hardening problem(s)"
}
Write-Host "==> every binary carries the required mitigations and imports nothing unexpected"
