# b_oep.ps1 - one elevated round: launch, dump, rebuild at candidate OEPs, test.
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
$art   = Join-Path $root "artifacts\boep-$stamp"
New-Item -ItemType Directory -Force -Path $art | Out-Null
$log   = Join-Path $art 'run.log'
function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }

function Kill-Target {
    Get-Process -Name $proc -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 900
}

function Wait-Login([int]$targetId) {
    for ($i = 0; $i -lt 30; $i++) {
        $p = Get-Process -Id $targetId -ErrorAction SilentlyContinue
        if (-not $p) { return "exited" }
        $w = (& $exe windows --pid $targetId 2>&1 | Out-String)
        if ($w -match 'TFormLogin') { return "login" }
        Start-Sleep -Milliseconds 1000
    }
    return "timeout"
}

Kill-Target
$launchOut = (& $exe launch --exe $target --wait-ms 180000 2>&1 | Out-String)
Log $launchOut.Trim()
$targetPid = 0
if ($launchOut -match 'created pid=(\d+)') { $targetPid = [int]$Matches[1] }
if (-not $targetPid) { Log 'STATUS fail no-target-pid'; exit 1 }

$status = (& $exe agentstatus --pid $targetPid 2>&1 | Out-String)
Log $status.Trim()

$dump = Join-Path $art 'live.bin'
$dumpOut = (& $exe dump --pid $targetPid --out $dump 2>&1 | Out-String)
Log $dumpOut.Trim()
if (-not (Test-Path $dump)) { Log 'STATUS fail no-dump'; Kill-Target; exit 1 }

$entries = @(
    @{ name = 'oep-fd2ae0'; value = '0xFD2AE0'; clean = $false },
    @{ name = 'oep-clean'; value = '0xFD2AE0'; clean = $true },
    @{ name = 'frame-146e3cc'; value = '0x146E3CC'; clean = $false },
    @{ name = 'original'; value = '0x0'; clean = $false },
    @{ name = 'original-clean'; value = '0x0'; clean = $true }
)

foreach ($e in $entries) {
    $out = Join-Path $art ("rebuilt-" + $e.name + ".exe")
    $rb = @('rebuild', '--live', $dump, '--out', $out, '--file', $target, '--pid', $targetPid)
    if ($e.value -ne '0x0') { $rb += @('--entry', $e.value) }
    if ($e.clean) { $rb += '--clean-data' }
    $rbOut = (& $exe @rb 2>&1 | Out-String)
    Log ("REBUILD " + $e.name + " entry=" + $e.value)
    Log $rbOut.Trim()
    if (-not (Test-Path $out)) { Log ("STATUS " + $e.name + " fail no-output"); continue }

    $p = Start-Process -FilePath $out -PassThru -ErrorAction SilentlyContinue
    if (-not $p) { Log ("STATUS " + $e.name + " fail start"); continue }
    Start-Sleep -Milliseconds 1200
    $r = Wait-Login $p.Id
    $line = "STATUS " + $e.name + " " + $r + " pid=" + $p.Id
    if ($p.HasExited) {
        $p.WaitForExit()
        $code = [uint32]$p.ExitCode
        $line += (" exit=0x{0:X8}" -f $code)
    }
    Log $line
    Get-Process -Id $p.Id -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

Kill-Target
Log ("ARTIFACTS " + $art)
exit 0
