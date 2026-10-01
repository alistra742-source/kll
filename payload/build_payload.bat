@echo off
REM Build the injectable payload with the MSVC toolchain, discovered via vswhere.
REM Result: payload\nr_beacon.dll  (x64, statically linked CRT, no runtime deps)
REM
REM The toolchain path is written to a temp file and read back rather than
REM captured with for /f: the ")" in "ProgramFiles(x86)" would otherwise close
REM the for's parenthesised block early and truncate the path.
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

REM /LD  build a DLL        /MT  static CRT (target needs no VC runtime)
REM /O2  optimise           /W4  strict warnings
REM user32.lib supplies wsprintfA; everything else comes from the static CRT.
cl /nologo /LD /O2 /MT /W4 nr_beacon.c /Fe:nr_beacon.dll /Fo:nr_beacon.obj /link /DLL user32.lib
if errorlevel 1 (
  echo BUILD FAILED: cl.exe returned an error
  del /q nr_beacon.obj nr_beacon.exp nr_beacon.lib 2>nul
  exit /b 1
)

del /q nr_beacon.obj nr_beacon.exp nr_beacon.lib 2>nul
echo built %CD%\nr_beacon.dll
endlocal
exit /b 0
