@echo off
REM Package the NightRelay driver for Microsoft attestation signing.
REM Result: driver\nightrelay.cab  -- the file you upload to Partner Center.
REM
REM The CAB contains nightrelay.inf + nightrelay.sys + nightrelay.cat. Attestation
REM signing requires a driver *package*; a bare .sys is rejected.
REM
REM Requires: the WDK (build + MakeCat/Inf2Cat) and a built nightrelay.sys.
REM Run build_driver.bat first, or let this call it.
setlocal
cd /d "%~dp0"

set "WDKROOT=%ProgramFiles(x86)%\Windows Kits\10"
if not exist "%WDKROOT%" (
  echo BUILD FAILED: WDK not found at %WDKROOT%
  exit /b 1
)

REM newest version dir that carries the kernel headers
set "WDKVER="
for /f "delims=" %%V in ('dir /b /ad /o-n "%WDKROOT%\Include" 2^>nul') do (
  if exist "%WDKROOT%\Include\%%V\km" if not defined WDKVER set "WDKVER=%%V"
)
if "%WDKVER%"=="" (
  echo BUILD FAILED: no kernel headers under %WDKROOT%\Include -- install the WDK
  exit /b 1
)
echo using WDK %WDKVER%

echo [1/4] building the driver...
call build_driver.bat || (
  echo PACKAGE FAILED: driver did not build
  exit /b 1
)
if not exist nightrelay.sys (
  echo PACKAGE FAILED: nightrelay.sys missing after build
  exit /b 1
)

echo [2/4] generating the catalog...
REM Inf2Cat signs nothing; it produces the catalog the package is described by.
REM /driver tells it we are packaging a driver install set.
"%WDKROOT%\bin\%WDKVER%\x64\Inf2Cat.exe" /driver:"%CD%" /os:10_X64,10_NI_X64 /verbose
if errorlevel 1 (
  echo PACKAGE FAILED: Inf2Cat could not build the catalog -- check nightrelay.inf
  exit /b 1
)

echo [3/4] writing the cab directive...
> nightrelay.ddf echo .OPTION EXPLICIT
>> nightrelay.ddf echo .Set CabinetNameTemplate=nightrelay.cab
>> nightrelay.ddf echo .Set DiskDirectoryTemplate=.
>> nightrelay.ddf echo .Set CompressionType=MSZIP
>> nightrelay.ddf echo .Set Cabinet=on
>> nightrelay.ddf echo .Set Compress=on
>> nightrelay.ddf echo nightrelay.inf
>> nightrelay.ddf echo nightrelay.sys
>> nightrelay.ddf echo nightrelay.cat

echo [4/4] packing...
makecab /f nightrelay.ddf >nul
if errorlevel 1 (
  echo PACKAGE FAILED: makecab returned an error
  del /q nightrelay.ddf 2>nul
  exit /b 1
)

del /q nightrelay.ddf setup.inf 2>nul
echo.
echo done --^> %CD%\nightrelay.cab
echo upload this CAB at Partner Center -^> Hardware dashboard -^> Submit new driver
endlocal
exit /b 0
