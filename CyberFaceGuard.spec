
# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

# ============================================================
# PROJECT PATHS
# ============================================================

project_dir = Path(SPECPATH).resolve()

main_script = project_dir / "main.py"
icon_path = project_dir / "assets" / "cyberfaceguard.ico"
assets_dir = project_dir / "assets"
models_dir = project_dir / "models"
keys_dir = project_dir / "keys"
public_key_path = keys_dir / "public_key.pem"

# ============================================================
# VALIDATE REQUIRED FILES
# ============================================================

required_files = [
    main_script,
    icon_path,
    public_key_path,
]

for file_path in required_files:
    if not file_path.is_file():
        raise FileNotFoundError(
            f"Required file not found: {file_path}"
        )

# ============================================================
# APPLICATION DATA FILES
# ============================================================

datas = [
    (str(public_key_path), "keys"),
]

# Include assets and face-recognition models
for folder in (assets_dir, models_dir):
    if folder.is_dir():
        datas.append(
            (str(folder), folder.name)
        )

# ============================================================
# DEPENDENCIES
# ============================================================

binaries = []
hiddenimports = []

# ============================================================
# ANALYSIS
# ============================================================

a = Analysis(
    [str(main_script)],
    pathex=[str(project_dir)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# ============================================================
# PYTHON ARCHIVE
# ============================================================

pyz = PYZ(a.pure)

# ============================================================
# EXECUTABLE
# ============================================================

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CyberFaceGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_path),
)

# ============================================================
# COLLECT DISTRIBUTION FILES
# ============================================================

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="CyberFaceGuard",
)
