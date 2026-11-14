# Front-end <-> engine wire contract: spawn the built engine with a throwaway
# token and run app/scripts/check-api.mjs against its tools/list schema.
param([string]$Engine = (Join-Path $PSScriptRoot '..\build\src\engine\reverse-slop-engine.exe'))
$ErrorActionPreference = 'Stop'
$env:SLOP_MCP_TOKEN = [guid]::NewGuid().ToString('N')
$out = Join-Path ([IO.Path]::GetTempPath()) "slop-check-api-$PID.txt"
$p = Start-Process -FilePath $Engine -ArgumentList '--no-onboard', '--port', '0', '--parent-pid', $PID `
    -PassThru -NoNewWindow -RedirectStandardOutput $out
try {
    $port = $null
    for ($i = 0; $i -lt 120 -and -not $port; $i++) {
        Start-Sleep -Milliseconds 500
        if ($p.HasExited) { throw "engine exited early (code $($p.ExitCode))" }
        $m = Select-String -LiteralPath $out -Pattern '^SLOP_ENGINE_READY (\d+)' -ErrorAction SilentlyContinue
        if ($m) { $port = $m.Matches[0].Groups[1].Value }
    }
    if (-not $port) { throw 'no SLOP_ENGINE_READY within 60 s' }
    Push-Location (Join-Path $PSScriptRoot '..\app')
    try { node scripts/check-api.mjs $port; if ($LASTEXITCODE) { throw "check-api failed ($LASTEXITCODE)" } }
    finally { Pop-Location }
} finally {
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
    Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
}
