# m2_run.ps1 - stage B: launch elevated target, dump, rebuild, verify.
# Self-elevates once; writes artifacts/m2-<stamp>/run.log + MANIFEST.txt.

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
$art   = Join-Path $root "artifacts\m2-$stamp"
New-Item -ItemType Directory -Force -Path $art | Out-Null
$log   = Join-Path $art 'run.log'

function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }
function Kill-Target {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 900
}

Log "M2 start $(Get-Date -Format o)"
Kill-Target

$out = (& $exe launch --exe $target --wait-ms 180000 2>&1 | Out-String)
Log $out.Trim()

$targetPid = 0
if ($out -match 'created pid=(\d+)') { $targetPid = [int]$Matches[1] }
if (-not $targetPid) {
    Log "STATUS m2 fail no-created-pid"
    Kill-Target
    exit 1
}
$tp = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
if (-not $tp) {
    Log "STATUS m2 fail target-exited pid=$targetPid"
    exit 1
}
Log "target pid=$targetPid"
Start-Sleep -Seconds 2

$status = (& $exe agentstatus --pid $targetPid 2>&1 | Out-String)
Log $status.Trim()

$live   = Join-Path $art 'live.bin'
$rebuilt = Join-Path $art 'rebuilt.exe'

$dump = (& $exe dump --pid $targetPid --out $live --max-mb 700 2>&1 | Out-String)
Log $dump.Trim()
if (-not (Test-Path $live)) {
    Log "STATUS m2 fail no-dump"
    Kill-Target
    exit 1
}

$rebuild = (& $exe rebuild --live $live --out $rebuilt --file $target --pid $targetPid 2>&1 | Out-String)
Log $rebuild.Trim()
if (-not (Test-Path $rebuilt)) {
    Log "STATUS m2 fail no-rebuild"
    Kill-Target
    exit 1
}

$info = (& $exe info $rebuilt 2>&1 | Out-String)
Log $info.Trim()
$imports = (& $exe imports $rebuilt --limit 40 2>&1 | Out-String)
Log $imports.Trim()

Kill-Target
$relaunch = (& $exe launch --exe $rebuilt --no-armor --wait-ms 120000 2>&1 | Out-String)
Log $relaunch.Trim()
$rebuiltUp = ($relaunch -match 'class="TFormLogin"')
$rebuiltPid = 0
if ($relaunch -match 'created pid=(\d+)') { $rebuiltPid = [int]$Matches[1] }
if ($rebuiltPid) {
    $w = (& $exe windows --pid $rebuiltPid 2>&1 | Out-String)
    Log $w.Trim()
}
Get-Process -Name 'rebuilt' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$lines = Get-ChildItem $art -File | Where-Object { $_.Name -ne 'MANIFEST.txt' } | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
}
Set-Content -Path (Join-Path $art 'MANIFEST.txt') -Value $lines

$importCount = 0
if ($imports -match '\[\\+\]\s+(\d+) modules,\s+(\d+) imported functions') {
    $importCount = [int]$Matches[2]
}
$verdict = if ($info -match 'image size' -and $importCount -ge 20 -and $rebuiltUp) { 'PASS' } else { 'PARTIAL' }
Log "RESULT rebuilt=$rebuilt imports=$importCount window=$rebuiltUp verdict=$verdict"
Log "ARTIFACTS $art"
exit 0

