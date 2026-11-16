# run_snap_test.ps1 - test an existing snapshot against an OEP rebuild.
param([switch]$Elevated)
$ErrorActionPreference = 'Continue'
$root = 'D:\cracker\vmpx'
$exe  = Join-Path $root 'vmpx.exe'

if (-not $Elevated) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a -Wait
    exit $LASTEXITCODE
}
$sd = Get-ChildItem (Join-Path $root 'artifacts') -Directory -Filter 'bsnap-*' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
$bd = Get-ChildItem (Join-Path $root 'artifacts') -Directory -Filter 'boep-*' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $sd -or -not $bd) { Write-Host 'missing artifacts'; exit 1 }
$log = Join-Path $sd.FullName 'snaptest.log'
function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }

foreach ($name in @('rebuilt-oep-clean.exe','rebuilt-oep-fd2ae0.exe')) {
    $cand = Join-Path $bd.FullName $name
    if (-not (Test-Path $cand)) { Log ("missing " + $name); continue }
    $out = (& $exe run --snap (Join-Path $sd.FullName 'snap.bin') --exe $cand 2>&1 | Out-String)
    Log ("RUN " + $name); Log $out.Trim()
    $child = 0
    if ($out -match 'STATUS run ok pid=(\d+)') { $child = [int]$Matches[1] }
    if (-not $child) { continue }
    $state = 'timeout'
    for ($i=0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        $p = Get-Process -Id $child -ErrorAction SilentlyContinue
        if (-not $p) { $state = 'exited'; break }
        $w = (& $exe windows --pid $child 2>&1 | Out-String)
        if ($w -match 'TFormLogin') { $state = 'login'; break }
    }
    Log ("STATUS " + $name + " " + $state + " pid=" + $child)
    Get-Process -Id $child -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600
}
Log 'DONE'
exit 0
