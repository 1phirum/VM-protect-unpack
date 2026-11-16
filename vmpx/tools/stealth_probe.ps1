# stealth_probe.ps1 - verify parent spoof + stealth agent status.
param([switch]$Elevated)

$ErrorActionPreference = 'Continue'
$root   = 'D:\cracker\vmpx'
$target = 'D:\cracker\UnlockTool-2026-11-10-0.exe'
$exe    = Join-Path $root 'vmpx.exe'
$proc   = 'UnlockTool-2026-11-10-0'

if (-not $Elevated) {
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
    Start-Process powershell.exe -Verb RunAs -ArgumentList $args -Wait
    exit $LASTEXITCODE
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$art   = Join-Path $root "artifacts\stealth-$stamp"
New-Item -ItemType Directory -Force -Path $art | Out-Null
$log   = Join-Path $art 'run.log'
function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }

Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$out = (& $exe launch --exe $target --wait-ms 180000 2>&1 | Out-String)
Log $out.Trim()

$targetPid = 0
if ($out -match 'created pid=(\d+)') { $targetPid = [int]$Matches[1] }
if (-not $targetPid) { Log 'STATUS stealth fail no-pid'; exit 1 }

Start-Sleep -Seconds 2
$status = (& $exe agentstatus --pid $targetPid 2>&1 | Out-String)
Log $status.Trim()

$w = (& $exe windows --pid $targetPid 2>&1 | Out-String)
Log $w.Trim()

$oepOut = Join-Path $art 'oep.txt'
$o = (& $exe oep --pid $targetPid --out $oepOut 2>&1 | Out-String)
Log $o.Trim()
if (Test-Path $oepOut) { Log (Get-Content $oepOut -Raw) }

$tp = Get-CimInstance Win32_Process -Filter "ProcessId=$targetPid" -ErrorAction SilentlyContinue
if ($tp) {
    Log "process parent=$($tp.ParentProcessId) name=$($tp.Name)"
    $pp = Get-CimInstance Win32_Process -Filter "ProcessId=$($tp.ParentProcessId)" -ErrorAction SilentlyContinue
    if ($pp) { Log "parent name=$($pp.Name)" }
}

Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Log "ARTIFACTS $art"
exit 0
