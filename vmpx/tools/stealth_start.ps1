param([switch]$Elevated)

$root = 'D:\cracker\vmpx'
if (-not $Elevated) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Elevated'
    ) -Wait
    exit
}

Get-Process -Name 'UnlockTool-2026-11-10-0','vmpx' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$art = Join-Path $root "artifacts\stealth-detached-$stamp"
New-Item -ItemType Directory -Force -Path $art | Out-Null
$stdout = Join-Path $art 'launch.out.txt'
$stderr = Join-Path $art 'launch.err.txt'
$args = @('launch', '--exe', 'D:\cracker\UnlockTool-2026-11-10-0.exe', '--wait-ms', '180000')
$p = Start-Process -FilePath (Join-Path $root 'vmpx.exe') -ArgumentList $args `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
Set-Content -Path (Join-Path $art 'launcher.pid') -Value $p.Id
Set-Content -Path (Join-Path $root 'artifacts\stealth-current.txt') -Value $art
