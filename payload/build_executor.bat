@echo off
REM Build the executor payload DLL (the core that runs inside the client).
REM Result: payload\nr_executor.dll  (x64, statically linked CRT).
REM
REM Same vswhere discovery as build_payload.bat -- the toolchain path is written
REM to a temp file and read back, because a for /f would break on the ")" in
REM "ProgramFiles(x86)".
setlocal
cd /d "%~dp0"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo BUILD FAILED: vswhere not found -- install Visual Studio Build Tools
  exit /b 1
)

set "TMPPATH=%TEMP%\nr_vspath.txt"
"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TMPPATH%" 2>nul
set "VS="
set /p VS=<"%TMPPATH%"
del /q "%TMPPATH%" 2>nul

if "%VS%"=="" (
  echo BUILD FAILED: no MSVC x64 toolset installed
  exit /b 1
)

call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul || (
  echo BUILD FAILED: vcvars64.bat did not run
  exit /b 1
)

REM /LD  DLL            /MT  static CRT (client needs no VC runtime)
REM /O2  optimise       /W4  strict warnings
REM user32/advapi32 are pulled in by the CRT; nothing else is needed.
cl /nologo /LD /O2 /MT /W4 /GS- nr_executor.c /Fe:nr_executor.dll /Fo:nr_executor.obj /link /DLL /ENTRY:DllMain
if errorlevel 1 (
  echo BUILD FAILED: cl.exe returned an error
  del /q nr_executor.obj nr_executor.exp nr_executor.lib 2>nul
  exit /b 1
)

del /q nr_executor.obj nr_executor.exp nr_executor.lib 2>nul
echo.
echo done --^> %CD%\nr_executor.dll
echo.
echo next: the app writes nr_executor.cfg (addresses) beside the DLL before loading.
endlocal
exit /b 0
