# gate_a.ps1 - stage A gate: 5 armored runs, 5 control runs, status check
# Run elevated. Writes artifacts/m1-<stamp>/gate.log + MANIFEST.txt.

$ErrorActionPreference = 'Continue'
$root   = 'D:\cracker\vmpx'
$target = 'D:\cracker\UnlockTool-2026-11-10-0.exe'
$exe    = Join-Path $root 'vmpx.exe'
$proc   = 'UnlockTool-2026-11-10-0'

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$art   = Join-Path $root "artifacts\m1-$stamp"
New-Item -ItemType Directory -Force -Path $art | Out-Null
$log   = Join-Path $art 'gate.log'

function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }

function Kill-Target {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 900
}

function Run-One([bool]$armor) {
    try {
        Kill-Target
        $cmdArgs = @('launch', '--exe', $target)
        if (-not $armor) { $cmdArgs += '--no-armor' }
        $out = (& $exe @cmdArgs 2>&1 | Out-String)
        $ok = $out -match '\[\+\] window up'
        $status = ''
        if ($armor) {
            $tp = Get-Process -Name $proc -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($tp) {
                Start-Sleep -Seconds 2
                $status = (& $exe agentstatus --pid $tp.Id 2>&1 | Out-String)
            }
        }
        return [pscustomobject]@{ Window = $ok; Output = $out; Status = $status }
    } catch {
        Log ('run exception: ' + $_.Exception.Message)
        return [pscustomobject]@{ Window = $false; Output = ''; Status = '' }
    }
}

Log "gate A start $(Get-Date -Format o)"
Log "target $target"
Log "image $(Get-Item $target | Select-Object -ExpandProperty Length) bytes"

$armorOk = 0
$controlOk = 0

for ($i = 1; $i -le 5; $i++) {
    $r = Run-One $true
    Log ("armor run {0}: window={1}" -f $i, $r.Window)
    Log $r.Output.Trim()
    if ($r.Status) { Log $r.Status.Trim() }

    $hooks = 0; $hidden = 0; $parent = 0
    if ($r.Status -match 'hooks=(\d+)')  { $hooks  = [int]$Matches[1] }
    if ($r.Status -match 'hidden=(\d+)') { $hidden = [int]$Matches[1] }
    if ($r.Status -match 'parent=(\d+)') { $parent = [int]$Matches[1] }
    if ($r.Window -and $hooks -ge 24 -and $hidden -eq 1 -and $parent -gt 0) { $armorOk++ }
    Kill-Target
}

for ($i = 1; $i -le 5; $i++) {
    $r = Run-One $false
    Log ("control run {0}: window={1}" -f $i, $r.Window)
    Log $r.Output.Trim()
    if ($r.Window) { $controlOk++ }
    Kill-Target
}

$verdict = if ($armorOk -eq 5 -and $controlOk -eq 5) { 'PASS' } else { 'FAIL' }
Log ("RESULT armor={0}/5 control={1}/5 verdict={2}" -f $armorOk, $controlOk, $verdict)

if (Test-Path (Join-Path $root 'artifacts\agent.log')) {
    Copy-Item (Join-Path $root 'artifacts\agent.log') (Join-Path $art 'agent.log')
}

$lines = Get-ChildItem $art -File | Where-Object { $_.Name -ne 'MANIFEST.txt' } | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
}
Set-Content -Path (Join-Path $art 'MANIFEST.txt') -Value $lines

exit $(if ($verdict -eq 'PASS') { 0 } else { 1 })
