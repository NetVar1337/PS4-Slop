# tools/record_demo.ps1 — capture the connect -> scan -> freeze demo.
#
# There is no checked-in GIF. This script produces the frames and the ffmpeg command;
# whether a GIF exists is decided by running it, not by this file.
#
#   powershell -File tools/record_demo.ps1                 # frames only
#   powershell -File tools/record_demo.ps1 -Encode         # frames + GIF (needs ffmpeg)
#
# What it actually does today:
#   1. runs `node app/e2e/run.mjs screenshots` (real engine + SlopTarget fixture +
#      headless Chrome) with SLOP_E2E_OUT pointed at -FramesDir, so the PNGs come from
#      the real UI;
#   2. writes frames.txt (ffmpeg concat list) and the exact ffmpeg command.
#
# What it does NOT do: it does not record a live interaction. The e2e driver's
# screenshots mode captures a fixed set of views (workspace, memory, disassembly,
# strings, debugger, pe, scripts, settings, command-palette, theme-nord), not a
# connect -> scan -> freeze sequence. For a true recording, either
#   - drive the UI by hand and capture with OBS/ScreenToGif (see the recipe below), or
#   - add a `demo` mode to app/e2e/run.mjs that takes a screenshot after each step
#     (attach -> scan First -> scan Next -> watch_add -> freeze) and then run this
#     script with -SkipCapture against that frame directory.
[CmdletBinding()]
param(
    # Where the PNG frames live / are written
    [string]$FramesDir,
    # Frames per second for the encoded animation (0.5 = one frame every 2 s)
    [double]$Fps = 1,
    # Run ffmpeg when it is on PATH
    [switch]$Encode,
    # Reuse the frames already in -FramesDir instead of re-capturing
    [switch]$SkipCapture,
    # Skip the app/e2e npm install step
    [switch]$SkipInstall
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $FramesDir) { $FramesDir = Join-Path $root 'docs/demo/frames' }

$ffmpeg = Get-Command ffmpeg -ErrorAction SilentlyContinue
$gif = Join-Path (Split-Path -Parent $FramesDir) 'slopstation-demo.gif'

if (-not $SkipCapture) {
    $engine = Join-Path $root 'build\src\engine\reverse-slop-engine.exe'
    $fixture = Join-Path $root 'build\src\app\SlopTarget.exe'
    foreach ($exe in @($engine, $fixture)) {
        if (-not (Test-Path -LiteralPath $exe)) {
            throw "missing $exe - build first: powershell -File tools/build.ps1 -NoFrontend"
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $root 'app\node_modules\vite\bin\vite.js'))) {
        Write-Host 'installing app npm deps...'
        npm --prefix (Join-Path $root 'app') ci --prefer-offline --no-audit --no-fund
    }
    if (-not $SkipInstall) {
        Write-Host 'installing app/e2e npm deps...'
        npm --prefix (Join-Path $root 'app\e2e') ci --prefer-offline --no-audit --no-fund
    }

    New-Item -ItemType Directory -Force -Path $FramesDir | Out-Null
    $env:SLOP_E2E_OUT = $FramesDir
    try {
        Write-Host "capturing frames into $FramesDir ..."
        & node (Join-Path $root 'app\e2e\run.mjs') screenshots
        if ($LASTEXITCODE -ne 0) { throw "screenshot run failed ($LASTEXITCODE)" }
    }
    finally {
        Remove-Item Env:SLOP_E2E_OUT -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Path -LiteralPath $FramesDir)) { throw "no frame directory at $FramesDir" }
$frames = @(Get-ChildItem -LiteralPath $FramesDir -Filter '*.png' -File | Sort-Object Name)
if ($frames.Count -eq 0) { throw "no PNG frames in $FramesDir" }

# ffmpeg concat list: one frame per line, held for 1/fps seconds
$list = Join-Path $FramesDir 'frames.txt'
$hold = 1.0 / $Fps
$lines = foreach ($f in $frames) {
    "file '$($f.FullName -replace '\\', '/')'"
    "duration $hold"
}
$lines += "file '$($frames[-1].FullName -replace '\\', '/')'"   # concat demuxer needs the last frame twice
Set-Content -LiteralPath $list -Value $lines -Encoding ascii

$filter = "fps=$Fps,scale=1280:-1:flags=lanczos,split[a][b];[a]palettegen[p];[b][p]paletteuse"
$ffmpegArgs = @(
    '-y', '-f', 'concat', '-safe', '0', '-i', "`"$list`"",
    '-vf', "`"$filter`"", '-loop', '0', "`"$gif`""
)

Write-Host ''
Write-Host "$($frames.Count) frames in $FramesDir"
Write-Host "concat list: $list"
Write-Host 'ffmpeg command:'
Write-Host "  ffmpeg $($ffmpegArgs -join ' ')"

if ($Encode) {
    if (-not $ffmpeg) {
        Write-Host ''
        Write-Host 'ffmpeg not on PATH - install it (winget install Gyan.FFmpeg) or run the command above elsewhere.'
        exit 2
    }
    & ffmpeg @ffmpegArgs
    if ($LASTEXITCODE -ne 0) { throw "ffmpeg failed ($LASTEXITCODE)" }
    Write-Host "wrote $gif"
}
else {
    Write-Host ''
    Write-Host 'frames only (-Encode was not passed): no GIF was produced.'
}

Write-Host @'

Manual recipe for a true connect -> scan -> freeze recording
------------------------------------------------------------
1. powershell -File tools/build.ps1 -NoFrontend      # engine + SlopTarget.exe
2. .\build\src\app\SlopTarget.exe                    # note the values.* addresses
3. Launch the app, Targets -> "List this PC's processes instead" -> attach SlopTarget.
4. Start a capture (OBS window capture, or ScreenToGif at 10 fps, 1280x800).
5. Scanner: width u32, kind exact, value 100 -> First.
   In the SlopTarget console: "auto 2" so health decreases, then type the new value -> Next.
6. Add a hit to the watchlist, toggle Freeze, show the value holding.
7. Stop the capture, export as GIF (or PNG sequence) and drop it in docs/demo/.
Keep the host process list hidden before recording - it is real machine data.
'@
