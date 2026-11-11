[CmdletBinding()]
param(
    # Build tree with compile_commands.json (CMAKE_EXPORT_COMPILE_COMMANDS is on)
    [string]$BuildDir = '',
    # Regex over repo-relative source paths to analyze (first-party code only)
    [string]$Include = '^src/(core|engine|ui|app|live|target|tests)/.*\.(cpp|cc|cxx)$',
    [int]$Jobs = [Environment]::ProcessorCount,
    # clang-tidy.exe; defaults to the one shipped with Visual Studio's LLVM tools
    [string]$ClangTidy = ''
)
# Runs clang-tidy (config: .clang-tidy) over every first-party translation unit
# in compile_commands.json, in parallel. Exits 1 when any file produces an
# error-level finding (WarningsAsErrors) or clang-tidy fails on a file.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $BuildDir) { $BuildDir = Join-Path $root 'build' }
$db = Join-Path $BuildDir 'compile_commands.json'
if (-not (Test-Path -LiteralPath $db)) { throw "missing ${db}: configure the build first" }

if (-not $ClangTidy) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vs = & $vswhere -latest -products * -property installationPath
    $ClangTidy = Join-Path $vs 'VC\Tools\Llvm\x64\bin\clang-tidy.exe'
}
if (-not (Test-Path -LiteralPath $ClangTidy)) {
    throw "clang-tidy not found at $ClangTidy (install the VS 'C++ Clang tools' component or pass -ClangTidy)"
}

$rootNorm = $root.Replace('\', '/').TrimEnd('/') + '/'
$files = @(Get-Content -LiteralPath $db -Raw | ConvertFrom-Json | ForEach-Object {
    $f = $_.file.Replace('\', '/')
    $rel = if ($f.StartsWith($rootNorm, [StringComparison]::OrdinalIgnoreCase)) { $f.Substring($rootNorm.Length) } else { $f }
    if ($rel -match $Include) { $f }
} | Sort-Object -Unique)
if ($files.Count -eq 0) { throw "no translation unit matched '$Include'" }
Write-Host "==> clang-tidy: $($files.Count) files, $Jobs jobs, $ClangTidy"

$results = $files | ForEach-Object -ThrottleLimit $Jobs -Parallel {
    $out = & $using:ClangTidy -p $using:BuildDir --quiet $_ 2>&1 | Out-String
    [pscustomobject]@{ File = $_; Exit = $LASTEXITCODE; Output = $out }
}

$failed = 0
$warnings = 0
foreach ($r in $results | Sort-Object File) {
    $text = $r.Output.Trim()
    $warnings += ([regex]::Matches($text, ': warning: ')).Count
    if ($r.Exit -ne 0) {
        $failed++
        Write-Host "::group::FAIL $($r.File)"
        Write-Host $text
        Write-Host '::endgroup::'
    } elseif ($text -match ': warning: ') {
        Write-Host "::group::warnings $($r.File)"
        Write-Host $text
        Write-Host '::endgroup::'
    }
}
Write-Host "==> clang-tidy: $($files.Count) files, $warnings warnings, $failed files with errors"
if ($failed -gt 0) { exit 1 }
