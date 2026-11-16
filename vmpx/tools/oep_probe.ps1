# oep_probe.ps1 - launch the target, attach cdb, dump every thread stack.
param([switch]$Elevated)

$ErrorActionPreference = 'Continue'
$root   = 'D:\cracker\vmpx'
$target = 'D:\cracker\UnlockTool-2026-11-10-0.exe'
$exe    = Join-Path $root 'vmpx.exe'
$cdb    = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe'

if (-not $Elevated) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a -Wait
    exit $LASTEXITCODE
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$art = Join-Path $root "artifacts\oep-$stamp"
New-Item -ItemType Directory -Force -Path $art | Out-Null
$log = Join-Path $art 'oep.log'
function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }

Get-Process -Name 'UnlockTool-2026-11-10-0' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$out = (& $exe launch --exe $target --wait-ms 180000 2>&1 | Out-String)
Log $out.Trim()
$created = 0
if ($out -match 'created pid=(\d+)') { $created = [int]$Matches[1] }
if (-not $created) { Log 'STATUS oep fail no-pid'; exit 1 }

$cdbOut = Join-Path $art 'threads.txt'
$argLine = '-p ' + $created + ' -c "~*kb 40; lm; q"'
$p = Start-Process -FilePath $cdb -ArgumentList $argLine -RedirectStandardOutput $cdbOut -RedirectStandardError (Join-Path $art 'threads.err.txt') -NoNewWindow -PassThru -Wait
Log "cdb exit=$($p.ExitCode)"
if (Test-Path $cdbOut) { Log (Get-Content $cdbOut -Raw) }

Get-Process -Name 'UnlockTool-2026-11-10-0' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Log "ARTIFACTS $art"
