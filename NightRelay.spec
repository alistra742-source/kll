# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['nr.config', 'nr.roblox', 'nr.fflags', 'nr.library', 'nr.trust', 'nr.deepseek', 'nr.executor', 'nr.server', 'nr.pow', 'nr.bridge', 'nr.discovery', 'nr.selftest_engine', 'nr.loader_lua', 'webview', 'webview.platforms.winforms', 'clr']
hiddenimports += collect_submodules('webview')


a = Analysis(
    ['nightrelay.py'],
    pathex=['.'],
    binaries=[],
    datas=[('ui', 'ui')],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NightRelay',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets/nightrelay.ico'],
)
