@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo [-] run-oep12 requires an elevated shell
    exit /b 8
)

taskkill /F /IM rebuilt-oep2.exe >nul 2>&1

set "VMPX_RUN_DEBUG=1"
set "LOG=artifacts\stageb-login\run-oep12.log"
".\vmpx.exe" run --snap artifacts\stageb-login\oep-oep.vxsn --exe artifacts\stageb-login\rebuilt-oep2.exe --ctx artifacts\stageb-login\oep-oep.vxsn.ctx > "%LOG%" 2>&1
set "RUN_RC=%ERRORLEVEL%"

echo RUN_RC=%RUN_RC%
echo --- tail ---
powershell -NoProfile -Command "Get-Content -LiteralPath '%LOG%' -Tail 12"
echo --- gate ---
powershell -NoProfile -ExecutionPolicy Bypass -File tests\check_run_log.ps1 -Log "%LOG%" -Expect terminal-exception
set "GATE_RC=%ERRORLEVEL%"
echo GATE_RC=%GATE_RC%

if not "%GATE_RC%"=="0" exit /b %GATE_RC%
exit /b %RUN_RC%
