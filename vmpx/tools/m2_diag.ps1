# m2_diag.ps1 - launch once, sample windows/agent status over time.
param([switch]$Elevated)

$ErrorActionPreference = 'Continue'
$root   = 'D:\cracker\vmpx'
$target = 'D:\cracker\UnlockTool-2026-11-10-0.exe'
$exe    = Join-Path $root 'vmpx.exe'
$name   = 'UnlockTool-2026-11-10-0'

if (-not $Elevated) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a -Wait
    exit $LASTEXITCODE
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$art   = Join-Path $root "artifacts\diag-$stamp"
New-Item -ItemType Directory -Force -Path $art | Out-Null
$log   = Join-Path $art 'diag.log'
function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }

function Sample([string]$tag) {
    Log "--- $tag $(Get-Date -Format HH:mm:ss) ---"
    $procs = Get-CimInstance Win32_Process -Filter "Name='$name.exe'" -ErrorAction SilentlyContinue
    if (-not $procs) { Log '  no target process'; return }
    foreach ($p in $procs) {
        Log ("  pid={0} ppid={1}" -f $p.ProcessId, $p.ParentProcessId)
        $w = (& $exe windows --pid $p.ProcessId 2>&1 | Out-String)
        Log ($w.TrimEnd())
        $s = (& $exe agentstatus --pid $p.ProcessId 2>&1 | Out-String)
        Log ($s.TrimEnd())
    }
}

Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 1000

$launch = (& $exe launch --exe $target --wait-ms 60000 2>&1 | Out-String)
Log $launch.TrimEnd()

$created = 0
if ($launch -match 'created pid=(\d+)') { $created = [int]$Matches[1] }
Log "created=$created"
Sample 'immediately'
Start-Sleep -Seconds 30
Sample 'after 30s'
Start-Sleep -Seconds 60
Sample 'after 90s'

Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Log "ARTIFACTS $art"
