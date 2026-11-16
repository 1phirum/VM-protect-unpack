@echo off
setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VCVARS="

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%i\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars32.bat"
    )
)

if not defined VCVARS if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
if not defined VCVARS if exist "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat"

if not defined VCVARS (
    echo [-] vcvars32.bat not found
    exit /b 1
)

call "%VCVARS%" >nul
cd /d "%~dp0"

rem --- agent first: the host embeds the built DLL as an RCDATA resource ---
cl /nologo /std:c11 /W4 /O2 /MT /LD /I include /I src /Fe:vmpxagent.dll ^
    src\trace\agent.c src\trace\peb.c src\trace\status.c src\trace\logfile.c ^
    src\armor\stealth\state.c src\armor\stealth\resolve.c ^
    src\armor\stealth\hook.c src\armor\stealth\install.c ^
    src\unpack\hook\watch.c ^
    src\unpack\deobf\dynamic\control\control.c ^
    src\unpack\deobf\dynamic\control\checksum.c ^
    src\unpack\deobf\dynamic\oep\oep.c ^
    src\unpack\deobf\dynamic\memdelta\memdelta.c ^
    src\unpack\deobf\dynamic\codecov\codecov.c ^
    src\unpack\deobf\dynamic\threadctx\threadctx.c ^
    src\unpack\deobf\dynamic\vmtrans\vmtrans.c ^
    src\armor\stealth\h_process.c src\armor\stealth\h_system.c ^
    src\armor\stealth\h_memory.c src\armor\stealth\h_thread.c ^
    src\armor\stealth\h_time.c src\armor\stealth\h_debug.c ^
    src\armor\stealth\h_window.c ^
    src\util\log.c /link user32.lib
if errorlevel 1 exit /b 1

rem --- single-file host: agent payload + version info ---
rc /nologo /fo resources.res resources.rc
if errorlevel 1 exit /b 1

cl /nologo /std:c11 /W4 /O2 /MT /I include /I src /Fe:vmpx.exe ^
    src\main.c ^
    src\util\args.c src\util\bin.c src\util\str.c src\util\file.c src\util\log.c ^
    src\util\agent_embed.c ^
    src\pe\hdr.c src\pe\pe.c src\pe\live_exports.c src\pe\iat_ctx.c ^
    src\pe\iat_table.c src\pe\iat.c src\pe\iat_cast.c src\pe\rebuild.c ^
    src\proc\proc.c src\proc\modules.c src\proc\mem.c src\proc\inject.c ^
    src\armor\elev.c src\armor\winwait.c src\armor\parent.c src\armor\launch.c ^
    src\unpack\mempe.c src\unpack\dump.c src\unpack\meta.c src\unpack\result.c ^
    src\unpack\memory\mapfile.c src\unpack\memory\file_writer.c ^
    src\unpack\memory\proc_reader.c src\unpack\memory\crc32.c ^
    src\unpack\memory\peb_modules.c src\unpack\memory\budget.c ^
    src\unpack\memory\arena.c src\unpack\memory\region_map.c ^
    src\unpack\sanity.c src\unpack\imports.c ^
    src\unpack\snapshot\snap_file.c src\unpack\snapshot\capture.c ^
    src\unpack\snapshot\rebase.c src\unpack\snapshot\restore.c ^
    src\unpack\snapshot\restore_input.c src\unpack\snapshot\restore_map.c ^
    src\unpack\snapshot\restore_modules.c src\unpack\snapshot\restore_context.c ^
    src\unpack\snapshot\restore_tls.c src\unpack\snapshot\debug.c ^
    src\unpack\deobf\dynamic\report\report.c ^
    src\unpack\deobf\dynamic\control\codec.c ^
    src\unpack\deobf\dynamic\report\loss_ledger.c ^
    src\unpack\deobf\dynamic\strings\runtime_strings.c ^
    src\unpack\deobf\dynamic\profile\profile.c ^
    src\unpack\deobf\dynamic\session\session.c ^
    src\unpack\deobf\dynamic\session\session_write.c ^
    src\unpack\deobf\dynamic\session\session_bridge.c ^
    src\util\json_parse.c src\util\json_access.c ^
    src\cmd\cmd_info.c src\cmd\cmd_imports.c src\cmd\cmd_launch.c ^
    src\cmd\cmd_modules.c src\cmd\cmd_inject.c src\cmd\cmd_dump.c ^
    src\cmd\cmd_liveimports.c src\cmd\cmd_peek.c src\cmd\cmd_poke.c ^
    src\cmd\cmd_agentstatus.c src\cmd\cmd_rebuild.c src\cmd\cmd_windows.c src\cmd\cmd_memmap.c ^
    src\cmd\cmd_oep.c src\cmd\cmd_oepcap.c src\cmd\cmd_snap.c src\cmd\cmd_run.c ^
    src\cmd\cmd_deobf.c src\cmd\cmd_watch.c ^
    resources.res ^
    /link shell32.lib advapi32.lib user32.lib psapi.lib bcrypt.lib
if errorlevel 1 exit /b 1

echo [+] built %CD%\vmpx.exe (single file, agent embedded)
