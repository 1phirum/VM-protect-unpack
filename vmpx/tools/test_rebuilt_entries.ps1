# test_rebuilt_entries.ps1 - run existing rebuilt candidates and gate on TFormLogin.
param([switch]$Elevated)

$ErrorActionPreference = 'Continue'
$root = 'D:\cracker\vmpx'
$exe  = Join-Path $root 'vmpx.exe'

if (-not $Elevated) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a -Wait
    exit $LASTEXITCODE
}

$dir = Get-ChildItem (Join-Path $root 'artifacts') -Directory -Filter 'boep-*' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $dir) { Write-Host 'no boep dir'; exit 1 }
$log = Join-Path $dir.FullName 'test.log'
function Log([string]$s) { Write-Host $s; Add-Content -Path $log -Value $s }
Log ("DIR " + $dir.FullName)

$files = @(
    'rebuilt-oep-fd2ae0.exe',
    'rebuilt-frame-146e3cc.exe',
    'rebuilt-winmain-24ac84.exe',
    'rebuilt-original.exe'
)

foreach ($name in $files) {
    $path = Join-Path $dir.FullName $name
    if (-not (Test-Path $path)) { Log ("STATUS " + $name + " missing"); continue }

    $p = Start-Process -FilePath $path -PassThru -ErrorAction SilentlyContinue
    if (-not $p) { Log ("STATUS " + $name + " start-failed"); continue }

    $state = 'timeout'
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        if ($p.HasExited) { $state = 'exited'; break }
        $w = (& $exe windows --pid $p.Id 2>&1 | Out-String)
        if ($w -match 'TFormLogin') { $state = 'login'; break }
    }
    $line = "STATUS " + $name + " " + $state + " pid=" + $p.Id
    if ($p.HasExited) {
        $code = [uint32]$p.ExitCode
        $line += (" exit=0x{0:X8}" -f $code)
    } else {
        $p.Refresh()
        if ($p.MainWindowTitle) { $line += (' title="' + $p.MainWindowTitle + '"') }
    }
    Log $line
    Get-Process -Id $p.Id -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
}
Log 'DONE'
exit 0
