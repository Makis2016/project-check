# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：Windows / macOS 单文件可执行程序。"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules

ROOT = Path(SPECPATH).resolve().parent

datas = [
    (str(ROOT / "frontend" / "dist"), "frontend/dist"),
    (str(ROOT / "backend" / "scanner" / "cve_db.json"), "backend/scanner"),
]
binaries = []
hiddenimports = collect_submodules("backend") + collect_submodules("uvicorn") + [
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "yaml",
    "socksio",
]

try:
    webview_datas, webview_binaries, webview_hidden = collect_all("webview")
except Exception:
    webview_hidden = ["webview"]
else:
    datas += webview_datas
    binaries += webview_binaries
    hiddenimports += webview_hidden

analysis = Analysis(
    [str(ROOT / "desktop" / "main.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "pytest"],
    noarchive=False,
)

pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="VulnLens",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

if sys.platform == "darwin":
    exe = BUNDLE(
        exe,
        name="VulnLens.app",
        icon=None,
        bundle_identifier="com.vulnlens.app",
        info_plist={
            "CFBundleName": "VulnLens",
            "CFBundleDisplayName": "VulnLens",
            "CFBundleShortVersionString": "1.2.0",
            "NSHighResolutionCapable": True,
        },
    )
