@echo off
REM Build the standalone NightRelay.exe (Windows 10/11, 64-bit).
REM Result: dist\NightRelay.exe -- a single file, no Python required on the target.
setlocal
cd /d "%~dp0"

set PY=%~1
if "%PY%"=="" set PY=python

echo [1/4] checking interpreter...
"%PY%" -c "import sys;print('python',sys.version.split()[0],sys.maxsize>2**32 and 'x64' or 'x86')" || goto :err

echo [2/4] installing build deps...
REM numpy        -> vectorised proof-of-work solver (1000x faster than scalar)
REM pycryptodome -> Keccak-256 for verifying the PoW variant
REM pywebview    -> the native WebView2 window (no browser chrome)
"%PY%" -m pip install --disable-pip-version-check -q --upgrade ^
  pyinstaller flask requests pillow numpy pycryptodome pywebview || goto :err

echo [3/4] generating icon...
"%PY%" assets\make_icon.py || echo    (icon generation skipped)

echo [4/4] building...
"%PY%" -m PyInstaller --noconfirm --clean --onefile --noconsole ^
  --name NightRelay ^
  --paths . ^
  --add-data "ui;ui" ^
  --hidden-import nr.config --hidden-import nr.roblox --hidden-import nr.fflags ^
  --hidden-import nr.library --hidden-import nr.trust --hidden-import nr.deepseek ^
  --hidden-import nr.executor ^
  --hidden-import nr.server --hidden-import nr.pow ^
  --hidden-import nr.bridge --hidden-import nr.discovery ^
  --hidden-import nr.selftest_engine --hidden-import nr.loader_lua ^
  --hidden-import webview --hidden-import webview.platforms.winforms ^
  --hidden-import clr --collect-submodules webview ^
  --icon assets\nightrelay.ico ^
  nightrelay.py || goto :err

echo.
echo done --^> %CD%\dist\NightRelay.exe
echo.
endlocal
exit /b 0

:err
echo.
echo BUILD FAILED (see above)
endlocal
exit /b 1
