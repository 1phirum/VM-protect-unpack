# probe_extra.ps1 - inspect live memory around the rebuilt crash address.
param([switch]$Elevated)

$ErrorActionPreference = 'Continue'
$root   = 'D:\cracker\vmpx'
$target = 'D:\cracker\UnlockTool-2026-11-10-0.exe'
$exe    = Join-Path $root 'vmpx.exe'

if (-not $Elevated) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a -Wait
    exit $LASTEXITCODE
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$art = Join-Path $root "artifacts\probe-$stamp"
New-Item -ItemType Directory -Force -Path $art | Out-Null
$log = Join-Path $art 'probe.log'
function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }

Get-Process -Name 'UnlockTool-2026-11-10-0' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$out = (& $exe launch --exe $target --wait-ms 180000 2>&1 | Out-String)
Log $out.Trim()
$created = 0
if ($out -match 'created pid=(\d+)') { $created = [int]$Matches[1] }
if (-not $created) { Log 'STATUS probe fail no-pid'; exit 1 }

Log '--- modules ---'
Log ((& $exe modules --pid $created 2>&1 | Out-String).Trim())
Log '--- map near 0x1DB127D0 ---'
Log ((& $exe memmap --pid $created --near 0x1DB127D0 --radius 0x8000000 --all 2>&1 | Out-String).Trim())
Log '--- bytes near 0x1DB127A0 ---'
Log ((& $exe peek --pid $created --addr 0x1DB127A0 --size 256 2>&1 | Out-String).Trim())
Log '--- private allocations >= 256K ---'
Log ((& $exe memmap --pid $created --private --min-kb 256 2>&1 | Out-String).Trim())

Get-Process -Name 'UnlockTool-2026-11-10-0' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Log "ARTIFACTS $art"
