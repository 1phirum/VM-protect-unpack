# watch_test.ps1 - exercise the agent guard-page/API memory monitor.
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
$art   = Join-Path $root "artifacts\watch-$stamp"
New-Item -ItemType Directory -Force -Path $art | Out-Null
$log   = Join-Path $art 'watch.log'
function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }

Get-Process -Name $proc -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$launch = (& $exe launch --exe $target --wait-ms 45000 2>&1 | Out-String)
Log $launch.Trim()
$targetPid = 0
if ($launch -match 'created pid=(\d+)') { $targetPid = [int]$Matches[1] }
if (-not $targetPid) { Log 'STATUS no-target-pid'; exit 1 }

$status = (& $exe agentstatus --pid $targetPid 2>&1 | Out-String)
Log $status.Trim()

$mm = (& $exe memmap --pid $targetPid --min-kb 4 2>&1 | Out-String)
$addr = 0
foreach ($line in ($mm -split "`r?`n")) {
    if ($line -match '^\s+([0-9A-Fa-f]{8})\s+[0-9A-Fa-f]{8}\s+\d+K\s+CMIT\s+PRV\s+RW') {
        $addr = [Convert]::ToUInt64($Matches[1], 16)
        break
    }
}
Log ("WATCH-ADDR " + ('0x{0:X8}' -f $addr))

if ($addr -ne 0) {
    $w = (& $exe watch --pid $targetPid --addr $addr --size 0x1000 --mode rw --seconds 3 --out (Join-Path $art 'guard.txt') 2>&1 | Out-String)
    Log $w.Trim()
}

$wi = (& $exe watch --pid $targetPid --seconds 1 --out (Join-Path $art 'api.txt') 2>&1 | Out-String)
Log $wi.Trim()

$after = (& $exe agentstatus --pid $targetPid 2>&1 | Out-String)
Log $after.Trim()

Get-Process -Id $targetPid -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Log ("ARTIFACTS " + $art)
exit 0
