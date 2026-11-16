# cdb_rebuilt.ps1 - run a candidate under cdb x86 elevated, capture crash context.
param([Parameter(Mandatory=$true)][string]$Path, [switch]$Elevated)

if (-not $Elevated) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Path', "`"$Path`"", '-Elevated')
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a -Wait
    exit $LASTEXITCODE
}

$cdb = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe'
$dir = Split-Path $Path
$out = Join-Path $dir 'cdb.out.txt'
$err = Join-Path $dir 'cdb.err.txt'
$argLine = '-o -c "g; .ecxr; r; kb; u .; q" "' + $Path + '"'
$p = Start-Process -FilePath $cdb -ArgumentList $argLine -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru -Wait
"exit=$($p.ExitCode)" | Add-Content -Path $out
