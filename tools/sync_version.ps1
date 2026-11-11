[CmdletBinding()]
param(
    # Report mismatches and exit 1 instead of rewriting (CI)
    [switch]$Check,
    # Additionally require this git tag (v1.2.3 or 1.2.3) to equal VERSION
    [string]$Tag = ''
)
# The root VERSION file is the single product version. CMake reads it directly
# (project VERSION, VERSIONINFO, manifests); this script copies it into the
# version fields of the frontend/Tauri manifests and lockfiles, touching only
# those fields (no reformatting).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -TotalCount 1).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw "VERSION must be MAJOR.MINOR.PATCH, got '$version'" }

# file -> regex whose group 2 is the version; group 1/3 are kept verbatim.
# Every pattern must match exactly `Count` times.
$targets = @(
    @{ Path = 'app/package.json'; Count = 1
       Pattern = '(?m)^(  "version":\s*")([^"]*)(")' },
    @{ Path = 'app/package-lock.json'; Count = 1
       Pattern = '(?s)(\A\{\s*"name":\s*"[^"]*",\s*"version":\s*")([^"]*)(")' },
    @{ Path = 'app/package-lock.json'; Count = 1
       Pattern = '(?s)("packages":\s*\{\s*"":\s*\{\s*"name":\s*"[^"]*",\s*"version":\s*")([^"]*)(")' },
    @{ Path = 'app/src-tauri/tauri.conf.json'; Count = 1
       Pattern = '(?m)^(  "version":\s*")([^"]*)(")' },
    @{ Path = 'app/src-tauri/Cargo.toml'; Count = 1
       Pattern = '(?ms)\A(.*?^\[package\][^\[]*?^version\s*=\s*")([^"]*)(")' },
    @{ Path = 'app/src-tauri/Cargo.lock'; Count = 1
       Pattern = '(?m)(^name = "reverse-slop-ui"\r?\nversion = ")([^"]*)(")' },
    @{ Path = 'README.md'; Count = 1
       Pattern = '(img\.shields\.io/badge/version-)(\d+\.\d+\.\d+)(-)' }
)

$bad = @()
foreach ($t in $targets) {
    $file = Join-Path $root $t.Path
    $text = [IO.File]::ReadAllText($file)
    $found = [regex]::Matches($text, $t.Pattern)
    if ($found.Count -ne $t.Count) {
        throw "$($t.Path): expected $($t.Count) version field(s), matched $($found.Count); update tools/sync_version.ps1"
    }
    $stale = @($found | Where-Object { $_.Groups[2].Value -ne $version })
    if (-not $stale) { continue }
    if ($Check) {
        $bad += "$($t.Path): $(($stale | ForEach-Object { $_.Groups[2].Value }) -join ', ') != $version"
        continue
    }
    $text = [regex]::Replace($text, $t.Pattern, { param($m) $m.Groups[1].Value + $version + $m.Groups[3].Value })
    [IO.File]::WriteAllText($file, $text, [Text.UTF8Encoding]::new($false))
    Write-Host "updated $($t.Path) -> $version"
}

if ($Tag) {
    $tagVersion = $Tag -replace '^refs/tags/', '' -replace '^v', ''
    if ($tagVersion -ne $version) { $bad += "tag '$Tag' != VERSION $version" }
}

if ($bad) {
    $bad | ForEach-Object { Write-Host "version mismatch: $_" }
    Write-Host 'run: pwsh tools/sync_version.ps1  (after editing VERSION)'
    exit 1
}
if ($Check) { Write-Host "versions consistent: $version" }
