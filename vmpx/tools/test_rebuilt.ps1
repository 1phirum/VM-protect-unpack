# test_rebuilt.ps1 - run a rebuilt candidate elevated and report exit code / windows.
param([Parameter(Mandatory=$true)][string]$Path, [switch]$Elevated)
$ErrorActionPreference = 'Continue'

if (-not $Elevated) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Path', "`"$Path`"", '-Elevated')
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a -Wait
    exit $LASTEXITCODE
}

$log = Join-Path (Split-Path $Path) 'test-rebuilt.log'
function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }

Log "run $Path $(Get-Date -Format o)"
$p = Start-Process -FilePath $Path -PassThru
if (-not $p) { Log 'start failed'; exit 1 }
Log "pid=$($p.Id)"
Start-Sleep -Seconds 5
$alive = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
if ($alive) {
    Log 'alive after 5s'
    $w = (& 'D:\cracker\vmpx\vmpx.exe' windows --pid $p.Id 2>&1 | Out-String)
    Log $w.Trim()
    Start-Sleep -Seconds 10
    $alive = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
    if ($alive) { Log 'alive after 15s'; Stop-Process -Id $p.Id -Force; Log 'killed' }
    else { Log "exit=$($p.ExitCode)" }
} else {
    $p.Refresh()
    Log "exit=$($p.ExitCode) (0x$('{0:X8}' -f $p.ExitCode))"
}
