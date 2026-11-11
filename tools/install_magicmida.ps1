[CmdletBinding()]
param(
    # defaults to %LOCALAPPDATA%\reverse-slop\tools\magicmida\<version>
    [string]$InstallRoot,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
# Single version source: tools/magicmida-version.txt. Line 1 is the release
# (read by CMake as SLOP_MAGICMIDA_VERSION, build.ps1 and the CI cache key),
# the following `<arch> <sha256>` lines pin that release's packages.
$versionLines = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'magicmida-version.txt') | Where-Object { $_.Trim() })
$release = $versionLines[0].Trim()
$sha = @{}
foreach ($line in $versionLines | Select-Object -Skip 1) {
    $arch, $hash = $line.Trim() -split '\s+', 2
    $sha[$arch] = $hash.ToLowerInvariant()
}
foreach ($arch in 'x86', 'x64') {
    if (-not $sha[$arch]) { throw "tools/magicmida-version.txt has no SHA-256 line for $arch" }
}
if (-not $InstallRoot) {
    if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is not set; pass -InstallRoot explicitly' }
    $InstallRoot = Join-Path $env:LOCALAPPDATA "reverse-slop\tools\magicmida\$release"
}
$packages = @(
    @{
        Arch = 'x86'
        Url = "https://github.com/Hendi48/Magicmida/releases/download/$release/Magicmida.zip"
        Sha256 = $sha['x86']
    },
    @{
        Arch = 'x64'
        Url = "https://github.com/Hendi48/Magicmida/releases/download/$release/Magicmida64.zip"
        Sha256 = $sha['x64']
    }
)

$tempRoot = Join-Path $env:TEMP "reverse-slop-magicmida-$PID"
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    foreach ($package in $packages) {
        $destination = Join-Path $InstallRoot $package.Arch
        if ((Test-Path -LiteralPath (Join-Path $destination 'Magicmida.exe')) -and -not $Force) {
            Write-Host "==> $($package.Arch) already installed: $destination"
            continue
        }

        $archive = Join-Path $tempRoot "$($package.Arch).zip"
        Write-Host "==> downloading Magicmida $($package.Arch) $release"
        Invoke-WebRequest -Uri $package.Url -OutFile $archive -UseBasicParsing
        $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $package.Sha256) {
            throw "SHA-256 mismatch for $($package.Arch): expected $($package.Sha256), got $actual"
        }

        if (Test-Path -LiteralPath $destination) {
            Remove-Item -LiteralPath $destination -Recurse -Force
        }
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Expand-Archive -LiteralPath $archive -DestinationPath $destination -Force
        Write-Host "==> installed $($package.Arch): $destination"
    }

    $sourceNotice = @(
        "Magicmida $release is GPLv3 software maintained at:",
        'https://github.com/Hendi48/Magicmida',
        '',
        'The downloaded x64 package contains ScyllaHide components:',
        'https://github.com/x64dbg/ScyllaHide',
        '',
        'Use the corresponding tagged source when redistributing these binaries.'
    )
    Set-Content -LiteralPath (Join-Path $InstallRoot 'SOURCE.txt') -Value $sourceNotice -Encoding ASCII
    Write-Host "==> Magicmida ready: $InstallRoot"
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
