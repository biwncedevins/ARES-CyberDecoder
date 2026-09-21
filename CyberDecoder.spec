# -*- mode: python ; coding: utf-8 -*-
# بناء: pyinstaller CyberDecoder.spec --noconfirm
import sys

ICON = "assets/icon.ico" if sys.platform == "win32" else "assets/icon.png"

a = Analysis(
    ["main.py"],
    pathex=["."],
    datas=[("assets/icon.ico", "assets"), ("assets/icon.png", "assets")],
    hiddenimports=[],
    excludes=[
        "tkinter", "unittest", "pydoc", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
        "PySide6.QtQml", "PySide6.QtQuick", "PySide6.Qt3DCore", "PySide6.QtMultimedia",
        "PySide6.QtNetwork", "PySide6.QtSql", "PySide6.QtCharts", "PySide6.QtDataVisualization",
        "PySide6.QtPdf", "PySide6.QtSvg", "PySide6.QtBluetooth", "PySide6.QtSensors",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="CyberDecoder",
    icon=ICON,
    console=False,        # بدون نافذة سوداء
    upx=False,
    disable_windowed_traceback=False,
)
