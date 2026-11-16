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
cd /d "%~dp0\.."

cl /nologo /std:c11 /W4 /O2 /MT /I include /I src /Fe:tests\memory_test.exe ^
    tests\memory_test.c src\unpack\memory\budget.c ^
    src\unpack\memory\arena.c src\unpack\memory\region_map.c ^
    src\unpack\memory\proc_reader.c
if errorlevel 1 exit /b 1

tests\memory_test.exe
