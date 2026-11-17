@echo off
setlocal
cd /d "%~dp0"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo vswhere.exe not found - install Visual Studio with the "Desktop development with C++" workload.
    exit /b 1
)

for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -prerelease -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
    echo No Visual Studio installation with the C++ build tools found.
    exit /b 1
)

call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 exit /b 1

if not exist build mkdir build
pushd build

rc.exe /nologo /fo MonarchChecker.res "..\resource.rc"
if errorlevel 1 (popd & exit /b 1)

cl.exe /nologo /std:c++17 /W4 /EHsc /utf-8 /O2 /MT /D_CRT_SECURE_NO_WARNINGS ^
    "..\main.cpp" MonarchChecker.res ^
    /Fe:MonarchChecker.exe ^
    /link /SUBSYSTEM:CONSOLE /ENTRY:wmainCRTStartup user32.lib ^
    "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
if errorlevel 1 (popd & exit /b 1)

popd
echo.
echo Done: %~dp0build\MonarchChecker.exe
