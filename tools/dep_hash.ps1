[CmdletBinding()]
param(
    # One or more archive URLs (FetchContent URL lines in cmake/deps.cmake)
    [Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Url
)
# Prints the `URL_HASH SHA256=...` line for each URL so a dependency bump in
# cmake/deps.cmake can update URL and hash together.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$tmp = Join-Path ([IO.Path]::GetTempPath()) "slop-dep-hash-$PID"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    foreach ($u in $Url) {
        $file = Join-Path $tmp ([IO.Path]::GetRandomFileName())
        Invoke-WebRequest -Uri $u -OutFile $file -UseBasicParsing
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Output "$u"
        Write-Output "    URL_HASH SHA256=$hash"
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
