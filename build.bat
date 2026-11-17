@echo off
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -prerelease -requires Microsoft.Component.MSBuild -find MSBuild\Current\Bin\amd64\MSBuild.exe`) do set "MSB=%%i"
if not defined MSB (echo MSBuild nicht gefunden - Visual Studio 2026 mit "Desktopentwicklung mit C++" installieren. & exit /b 1)
"%MSB%" "%~dp0MonarchChecker.vcxproj" /p:Configuration=Release /p:Platform=x64 /m /nologo /v:m
if errorlevel 1 exit /b 1
echo.
echo Fertig: %~dp0x64\Release\MonarchChecker.exe
