# PyInstaller spec for Cuttix — run with:
#     pyinstaller scripts/cuttix.spec
#
# Produces a single-file binary under dist/cuttix that bundles the
# Python runtime, scapy, PyQt6, reportlab, and the OUI/top-ports
# data files. The entry point is cuttix.cli.main:cli, which dispatches
# to both the CLI subcommands and the `gui` command.
# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


PROJECT_ROOT = Path(SPECPATH).resolve().parent
ASSETS_DIR = PROJECT_ROOT / "assets"


# bundle the OUI + top-ports data files at the location cuttix expects
datas = [
    (str(ASSETS_DIR / "oui.csv"), "assets"),
    (str(ASSETS_DIR / "top_ports.json"), "assets"),
]
datas += collect_data_files("scapy", includes=["**/*.py", "**/*.json"])

hiddenimports = [
    *collect_submodules("cuttix"),
    "scapy.all",
    "scapy.layers.inet",
    "scapy.layers.l2",
    "scapy.layers.dhcp",
    "scapy.layers.dns",
    "click",
    "reportlab.pdfgen",
    "reportlab.lib",
    "reportlab.platypus",
    "PyQt6",
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
]


a = Analysis(
    [str(PROJECT_ROOT / "cuttix" / "cli" / "main.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Drop stuff we never import to slim the binary down
        "tkinter", "matplotlib", "pandas", "IPython", "jupyter",
    ],
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
    name="cuttix",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
