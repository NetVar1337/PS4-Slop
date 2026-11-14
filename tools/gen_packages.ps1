# tools/gen_packages.ps1 — fill the winget / Scoop / Chocolatey manifests from a
# release's SHA256SUMS.
#
#   powershell -File tools/gen_packages.ps1 -Version 0.2.3 -Sums SHA256SUMS -OutDir _packages
#   powershell -File tools/gen_packages.ps1 -Version 0.2.3            # downloads the sums
#
# The templates in packaging/ carry __PLACEHOLDER__ tokens (see packaging/README.md);
# this script substitutes them and fails if any token survives, so a manifest can never
# ship with a stale version or a zero hash.
[CmdletBinding()]
param(
    # Product version, without the leading v (default: the VERSION file)
    [string]$Version,
    # Release tag (default: v<Version>)
    [string]$Tag,
    # SHA256SUMS file for the release (default: download it with gh)
    [string]$Sums,
    # Where the filled manifests go (default: _packages)
    [string]$OutDir = '_packages',
    # GitHub repo slug
    [string]$Repo = 'NetVar1337/SlopStation',
    # Release date for the winget manifest (default: today, UTC)
    [string]$ReleaseDate
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (-not $Version) {
    $Version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -TotalCount 1).Trim()
}
if (-not $Tag) { $Tag = "v$Version" }
if (-not $ReleaseDate) { $ReleaseDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd') }
if ($Version -notmatch '^\d+\.\d+\.\d+([-.][0-9A-Za-z.]+)?$') {
    throw "bad version '$Version' (expected x.y.z)"
}

# ---- SHA256SUMS ------------------------------------------------------------
# "<sha256>  <file name>" per line, as the release workflow writes it.
$tmp = $null
try {
    if (-not $Sums) {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) "slop-sums-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        Write-Host "downloading SHA256SUMS for $Tag from $Repo..."
        gh release download $Tag -R $Repo -p SHA256SUMS -D $tmp
        if ($LASTEXITCODE -ne 0) { throw "gh release download $Tag failed ($LASTEXITCODE)" }
        $Sums = Join-Path $tmp 'SHA256SUMS'
    }
    if (-not (Test-Path -LiteralPath $Sums)) { throw "no SHA256SUMS at $Sums" }

    $hashes = @{}
    foreach ($line in Get-Content -LiteralPath $Sums) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') {
            $hashes[$Matches[2]] = $Matches[1].ToLowerInvariant()
        }
    }
    if ($hashes.Count -eq 0) { throw "no hashes parsed from $Sums" }

    # asset names come from .github/workflows/release.yml: the installer carries the
    # bare version, the portable zip carries the tag
    $setupName = @($hashes.Keys | Where-Object { $_ -like "*_${Version}_x64-setup.exe" })
    $zipName   = @($hashes.Keys | Where-Object { $_ -like "*portable-$Tag.zip" })
    if ($setupName.Count -ne 1) {
        throw "expected one *_${Version}_x64-setup.exe in SHA256SUMS, found: $($setupName -join ', ')"
    }
    if ($zipName.Count -ne 1) {
        throw "expected one *portable-$Tag.zip in SHA256SUMS, found: $($zipName -join ', ')"
    }
    $setupName = $setupName[0]
    $zipName   = $zipName[0]

    $base = "https://github.com/$Repo/releases/download/$Tag"
    $tokens = @{
        '__VERSION__'      = $Version
        '__TAG__'          = $Tag
        '__RELEASE_DATE__' = $ReleaseDate
        '__SETUP_URL__'    = "$base/$setupName"
        '__SETUP_SHA256__' = $hashes[$setupName].ToUpperInvariant()   # winget convention
        '__ZIP_URL__'      = "$base/$zipName"
        '__ZIP_SHA256__'   = $hashes[$zipName]
    }

    # ---- templates ---------------------------------------------------------
    $out = if ([IO.Path]::IsPathRooted($OutDir)) { [IO.Path]::GetFullPath($OutDir) }
           else { [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $OutDir)) }
    if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $out | Out-Null

    $pkgRoot = Join-Path $root 'packaging'
    $prefix = $pkgRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $files = @(Get-ChildItem -LiteralPath $pkgRoot -Recurse -File |
        Where-Object { $_.Extension -in @('.yaml', '.json', '.nuspec', '.ps1') })
    if ($files.Count -eq 0) { throw 'no templates under packaging/' }

    # Windows PowerShell 5.1 has no [IO.Path]::GetRelativePath and no utf8NoBOM
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($prefix.Length)
        $text = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
        foreach ($k in $tokens.Keys) { $text = $text.Replace($k, $tokens[$k]) }
        if ($text -match '__[A-Z0-9_]+__') {
            throw "$rel still has a placeholder after substitution: $($Matches[0])"
        }
        $dest = Join-Path $out $rel
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
        [IO.File]::WriteAllText($dest, $text, $utf8)
        Write-Host "  $rel"
    }

    # ---- self-check --------------------------------------------------------
    # the generated manifests must carry the version and the real hashes
    $wingetInstaller = Get-Content -LiteralPath (Join-Path $out 'winget/NetVar1337.SlopStation.installer.yaml') -Raw
    foreach ($needle in @("PackageVersion: $Version", $tokens['__SETUP_SHA256__'], $setupName)) {
        if (-not $wingetInstaller.Contains($needle)) { throw "winget installer manifest is missing '$needle'" }
    }
    $scoop = Get-Content -LiteralPath (Join-Path $out 'scoop/slopstation.json') -Raw | ConvertFrom-Json
    if ($scoop.version -ne $Version) { throw "scoop version is $($scoop.version), expected $Version" }
    if ($scoop.architecture.'64bit'.hash -ne $tokens['__ZIP_SHA256__']) {
        throw 'scoop hash does not match the portable zip'
    }
    $nuspec = Get-Content -LiteralPath (Join-Path $out 'choco/slopstation.nuspec') -Raw
    if (-not $nuspec.Contains("<version>$Version</version>")) { throw 'nuspec version is wrong' }
    [xml]$null = $nuspec   # well-formedness

    Write-Host "manifests for $Version ($Tag) written to $out"
    Write-Host "  installer: $setupName  $($tokens['__SETUP_SHA256__'])"
    Write-Host "  portable : $zipName  $($tokens['__ZIP_SHA256__'])"
}
finally {
    if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}
