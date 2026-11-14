$ErrorActionPreference = 'Stop'

# Tauri's NSIS installer is per-user (installMode: currentUser), so there is no
# machine-wide install to switch to; /S is the silent switch.
$packageArgs = @{
    packageName    = 'slopstation'
    fileType       = 'exe'
    url64bit       = '__SETUP_URL__'
    checksum64     = '__SETUP_SHA256__'
    checksumType64 = 'sha256'
    silentArgs     = '/S'
    validExitCodes = @(0)
}

Install-ChocolateyPackage @packageArgs
