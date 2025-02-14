# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.win32.versioninfo import VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable, StringStruct, VarFileInfo, VarStruct

block_cipher = None

# 添加版本信息
version_info = VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=(2025, 2, 14, 1),
        prodvers=(2025, 2, 14, 1),
        mask=0x3f,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0)
    ),
    kids=[
        StringFileInfo([
            StringTable(
                u'040904B0',
                [StringStruct(u'FileDescription', u'Crazy Cursor Tool'),
                 StringStruct(u'FileVersion', u'2025.2.14.1'),
                 StringStruct(u'InternalName', u'crazy_cursor'),
                 StringStruct(u'LegalCopyright', u'Copyright (c) 2025'),
                 StringStruct(u'OriginalFilename', u'crazy_cursor.exe'),
                 StringStruct(u'ProductName', u'Crazy Cursor'),
                 StringStruct(u'ProductVersion', u'2025.2.14.1')])
        ]),
        VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
    ]
)

a = Analysis(
    ['crazy_cursor.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'psutil',
        'requests',
        'sqlite3',
        'winreg',
        'json',
        'logging',
        'platform',
        'subprocess',
        'time',
        're',
        'dataclasses',
        'pathlib',
        'typing',
        'base64',
        'uuid',
        'hashlib',
        'dotenv'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['.env'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure, 
    a.zipped_data,
    cipher=block_cipher
)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='crazy_cursor',
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
    version_info=version_info,  # 使用 version_info 对象
    icon=None
) 