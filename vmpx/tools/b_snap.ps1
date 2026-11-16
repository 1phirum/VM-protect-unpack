# b_snap.ps1 - launch, snapshot private context, run rebuilt OEP with restore.
param([switch]$Elevated)

$ErrorActionPreference = 'Continue'
$root   = 'D:\cracker\vmpx'
$target = 'D:\cracker\UnlockTool-2026-11-10-0.exe'
$exe    = Join-Path $root 'vmpx.exe'
$proc   = 'UnlockTool-2026-11-10-0'

if (-not $Elevated) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a -Wait
    exit $LASTEXITCODE
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$art   = Join-Path $root "artifacts\bsnap-$stamp"
New-Item -ItemType Directory -Force -Path $art | Out-Null
$log   = Join-Path $art 'run.log'
function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }

function Kill-Name([string]$name) {
    Get-Process -Name $name -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 900
}

function Wait-Login([int]$targetId) {
    for ($i = 0; $i -lt 40; $i++) {
        $p = Get-Process -Id $targetId -ErrorAction SilentlyContinue
        if (-not $p) { return 'exited' }
        $w = (& $exe windows --pid $targetId 2>&1 | Out-String)
        if ($w -match 'TFormLogin') { return 'login' }
        Start-Sleep -Milliseconds 500
    }
    return 'timeout'
}

Kill-Name $proc
$launchOut = (& $exe launch --exe $target --wait-ms 180000 2>&1 | Out-String)
Log $launchOut.Trim()
$targetPid = 0
if ($launchOut -match 'created pid=(\d+)') { $targetPid = [int]$Matches[1] }
if (-not $targetPid) { Log 'STATUS fail no-target-pid'; exit 1 }

$status = (& $exe agentstatus --pid $targetPid 2>&1 | Out-String)
Log $status.Trim()

$snap = Join-Path $art 'snap.bin'
$snapOut = (& $exe snap --pid $targetPid --out $snap 2>&1 | Out-String)
Log $snapOut.Trim()
if (-not (Test-Path $snap)) { Log 'STATUS fail no-snapshot'; Kill-Name $proc; exit 1 }

# Prefer the newest OEP rebuild; fall back to the known artifact name.
$boep = Get-ChildItem (Join-Path $root 'artifacts') -Directory -Filter 'boep-*' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
$candidates = @()
if ($boep) {
    $candidates += (Join-Path $boep.FullName 'rebuilt-oep-clean.exe')
    $candidates += (Join-Path $boep.FullName 'rebuilt-oep-fd2ae0.exe')
}

foreach ($cand in $candidates) {
    if (-not (Test-Path $cand)) { Log ("STATUS missing " + $cand); continue }
    $name = Split-Path $cand -Leaf
    $runOut = (& $exe run --snap $snap --exe $cand 2>&1 | Out-String)
    Log ("RUN " + $name)
    Log $runOut.Trim()
    $childPid = 0
    if ($runOut -match 'STATUS run ok pid=(\d+)') { $childPid = [int]$Matches[1] }
    if (-not $childPid) { Log ("STATUS " + $name + " no-child"); continue }

    $state = Wait-Login $childPid
    $line = "STATUS " + $name + " " + $state + " pid=" + $childPid
    $p = Get-Process -Id $childPid -ErrorAction SilentlyContinue
    if ($p) {
        $p.Refresh()
        if ($p.MainWindowTitle) { $line += (' title="' + $p.MainWindowTitle + '"') }
        $w = (& $exe windows --pid $childPid 2>&1 | Out-String)
        if ($w -match 'TFormLogin') { $line += ' login' }
    } else {
        $line += ' gone'
    }
    Log $line
    if ($p) { Get-Process -Id $childPid -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 700
}

Kill-Name $proc
Log ("ARTIFACTS " + $art)
exit 0
