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

cl /nologo /std:c11 /W4 /O2 /I include /I src /Fe:tests\profile_test.exe ^
    tests\profile_test.c src\unpack\deobf\dynamic\profile\profile.c ^
    src\util\json_parse.c src\util\json_access.c
if errorlevel 1 exit /b 1

tests\profile_test.exe
