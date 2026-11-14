# tools/analyze_ratchet.ps1
# MSVC /analyze ratchet: the nightly analyze lane logs every finding; this
# script fails the lane when a finding appears that is not in the committed
# baseline (docs/analyze-baseline.txt), so the standing backlog cannot grow.
#
#   powershell -NoProfile -File tools/analyze_ratchet.ps1 -Log analyze.log
#   powershell -NoProfile -File tools/analyze_ratchet.ps1 -Log analyze.log -Update
#
# A finding's identity is its warning code plus the message text (the file and
# line are dropped: they move whenever code above them changes, which would
# make the baseline churn without a new defect). -Update rewrites the baseline
# from the run, which is how an intentional fix or a new accepted finding is
# recorded.

[CmdletBinding()]
param(
    [string]$Log = 'analyze.log',
    [string]$Baseline = 'docs/analyze-baseline.txt',
    [switch]$Update
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Log)) { throw "analyze log not found: $Log" }

# C6xxx (code analysis), C26xxx (C++ Core Guidelines), C28xxx (lifetime)
$found = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
foreach ($line in Get-Content -LiteralPath $Log) {
    $m = [regex]::Match($line, 'warning (C(?:6|26|28)\d{3}):\s*(.*)$')
    if (-not $m.Success) { continue }
    $message = ($m.Groups[2].Value -replace '\s+', ' ').Trim()
    [void]$found.Add("$($m.Groups[1].Value) $message")
}

$known = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
if (Test-Path -LiteralPath $Baseline) {
    foreach ($line in Get-Content -LiteralPath $Baseline) {
        $t = $line.Trim()
        if ($t -and -not $t.StartsWith('#')) { [void]$known.Add($t) }
    }
}

Write-Host "/analyze: $($found.Count) unique finding(s), baseline has $($known.Count)"

if ($Update) {
    $text = @(
        '# MSVC /analyze findings accepted at the time of writing, one per line:',
        '#   <warning code> <message>',
        '# tools/analyze_ratchet.ps1 fails the nightly lane on any finding that is',
        '# not listed here. Regenerate with -Update after fixing or accepting one.',
        ''
    ) + @($found)
    Set-Content -LiteralPath $Baseline -Value $text -Encoding utf8
    Write-Host "baseline rewritten: $($found.Count) finding(s)"
    exit 0
}

$new = @($found | Where-Object { -not $known.Contains($_) })
if ($new.Count -gt 0) {
    $new | ForEach-Object { Write-Host "NEW: $_" }
    throw "$($new.Count) new /analyze finding(s); fix them or record them with -Update"
}

$fixed = @($known | Where-Object { -not $found.Contains($_) })
if ($fixed.Count -gt 0) {
    Write-Host "$($fixed.Count) baseline finding(s) no longer reported; re-baseline with -Update"
}
Write-Host '==> no new /analyze findings'
