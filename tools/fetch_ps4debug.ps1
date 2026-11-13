# tools/fetch_ps4debug.ps1
# Fetch the latest ps4debug-NG release payload for bundling. The release job
# runs this before the Tauri bundle, so every build carries the newest payload
# without pinning a tag in the repo.
[CmdletBinding()]
param(
    # Re-download even when the manifest already names the latest tag
    [switch]$Force,
    # Destination directory (default: build/ps4debug-ng)
    [string]$OutDir = ''
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $repoRoot 'build/ps4debug-ng' }
$api = 'https://api.github.com/repos/Pharaoh2k/ps4debug-NG/releases/latest'
$headers = @{ 'User-Agent' = 'SlopStation-build'; 'Accept' = 'application/vnd.github+json' }
# CI passes the workflow token: unauthenticated runner IPs share a 60/h limit.
if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $env:GITHUB_TOKEN" }

Write-Host "==> ps4debug-NG: querying $api"
$release = Invoke-RestMethod -Uri $api -Headers $headers
$tag = [string]$release.tag_name
if (-not $tag) { throw 'ps4debug-NG latest release has no tag' }

$asset = @($release.assets | Where-Object { $_.name -match '\.bin$' } | Select-Object -First 1)
if ($asset.Count -ne 1) {
    throw "ps4debug-NG $tag has no .bin asset (assets: $((@($release.assets | ForEach-Object name)) -join ', '))"
}
$asset = $asset[0]

$manifestPath = Join-Path $OutDir 'manifest.json'
if (-not $Force -and (Test-Path -LiteralPath $manifestPath)) {
    $old = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $bin = Join-Path $OutDir 'ps4debug-ng.bin'
    if ($old.tag -eq $tag -and (Test-Path -LiteralPath $bin)) {
        Write-Host "==> ps4debug-NG $tag already staged"
        exit 0
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$binPath = Join-Path $OutDir 'ps4debug-ng.bin'
Write-Host "==> ps4debug-NG ${tag}: $($asset.name) ($([math]::Round($asset.size / 1MB, 1)) MB)"
Invoke-WebRequest -Uri $asset.browser_download_url -Headers $headers -OutFile $binPath -UseBasicParsing

# GPLv3 payload: ship the license text and the source pointer next to it.
$licensePath = Join-Path $OutDir 'LICENSE.ps4debug-NG.txt'
try {
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Pharaoh2k/ps4debug-NG/master/LICENSE.txt' -Headers $headers -OutFile $licensePath -UseBasicParsing
} catch {
    Write-Warning "could not fetch the ps4debug-NG license: $($_.Exception.Message)"
}

$sha = (Get-FileHash -LiteralPath $binPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [ordered]@{
    repo         = 'Pharaoh2k/ps4debug-NG'
    tag          = $tag
    name         = [string]$release.name
    published_at = [string]$release.published_at
    asset        = [string]$asset.name
    url          = [string]$asset.browser_download_url
    sha256       = $sha
    fetched_at   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    license      = 'GPL-3.0'
    source       = 'https://github.com/Pharaoh2k/ps4debug-NG'
}
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
Write-Host "==> ps4debug-NG ${tag} staged: $binPath (sha256 $sha)"
