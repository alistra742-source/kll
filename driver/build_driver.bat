@echo off
REM Build the NightRelay kernel driver with the WDK toolchain.
REM Result: driver\nightrelay.sys  (x64, WDM).
REM
REM Requires: Visual Studio Build Tools (C++ x64) AND the Windows Driver Kit (WDK)
REM for the same VS version. Install both from the VS Installer -- the WDK shows
REM up as an individual component once the C++ workload is present.
REM
REM Toolchain path is written to a temp file and read back rather than captured
REM with for /f: the ")" in "ProgramFiles(x86)" would close the for's
REM parenthesised block early and truncate the path (same trap build_payload.bat
REM documents).
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

set "WDKROOT=%ProgramFiles(x86)%\Windows Kits\10"
if not exist "%WDKROOT%" (
  echo BUILD FAILED: WDK not found at %WDKROOT% -- add the Windows Driver Kit component
  exit /b 1
)

REM Newest WDK version directory that actually carries the kernel-mode headers.
set "WDKVER="
for /f "delims=" %%V in ('dir /b /ad /o-n "%WDKROOT%\Include" 2^>nul') do (
  if exist "%WDKROOT%\Include\%%V\km" if not defined WDKVER set "WDKVER=%%V"
)
if "%WDKVER%"=="" (
  echo BUILD FAILED: no kernel-mode headers under %WDKROOT%\Include
  exit /b 1
)
echo using WDK %WDKVER%

call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul || (
  echo BUILD FAILED: vcvars64.bat did not run
  exit /b 1
)

set "KMINC=%WDKROOT%\Include\%WDKVER%\km"
set "SHAREDINC=%WDKROOT%\Include\%WDKVER%\shared"
set "KMLIB=%WDKROOT%\Lib\%WDKVER%\km\x64"

REM /kernel        apply kernel-mode defaults (no CRT, right /GS and alignment)
REM /W4            strict warnings, must be clean
REM /GS-           no stack cookie: kernel has no CRT to source it from
REM /GS999999999   move the buffer-security cookie probe out of the way
echo [1/2] compiling...
cl /nologo /kernel /GS- /Gs999999999 /GR- /EHs- /O2 /W4 /c nightrelay_drv.c ^
  /I"%KMINC%" /I"%SHAREDINC%" ^
  /Fo:nightrelay_drv.obj || goto :err
cl /nologo /kernel /GS- /Gs999999999 /GR- /EHs- /O2 /W4 /c nr_stealth.c ^
  /I"%KMINC%" /I"%SHAREDINC%" ^
  /Fo:nr_stealth.obj || goto :err

echo [2/2] linking...
link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /MACHINE:X64 ^
  /OUT:nightrelay.sys nightrelay_drv.obj nr_stealth.obj ^
  /LIBPATH:"%KMLIB%" ntoskrnl.lib hal.lib wdm.lib BufferOverflowFastFailK.lib || goto :err

if exist nightrelay_drv.obj del /q nightrelay_drv.obj
if exist nr_stealth.obj del /q nr_stealth.obj
echo built %CD%\nightrelay.sys
endlocal
exit /b 0

:err
echo.
echo BUILD FAILED (see above)
REM If the link step cannot find a library, add it with /DEFAULTLIB:<name>.lib
REM rather than guessing -- the WDK's own DriverWorks sample shows the same set.
endlocal
exit /b 1
