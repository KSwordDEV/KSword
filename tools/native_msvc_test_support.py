"""Locate native HostX64 test dependencies using explicit paths and VS metadata."""
from pathlib import Path
import os
import subprocess


def find_msvc_developer_environment() -> Path:
    candidates = []
    if os.environ.get('VSINSTALLDIR'):
        candidates.append(Path(os.environ['VSINSTALLDIR']) / 'Common7/Tools/VsDevCmd.bat')
    program_roots = [Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')),
                     Path(os.environ.get('ProgramFiles', 'C:/Program Files'))]
    for prefix in program_roots:
        for edition in ('Enterprise', 'BuildTools', 'Professional', 'Community'):
            candidates.append(prefix / 'Microsoft Visual Studio/2022' / edition / 'Common7/Tools/VsDevCmd.bat')
    candidates.append(Path('D:/Software/VS/Common7/Tools/VsDevCmd.bat'))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    for prefix in program_roots:
        locator = prefix / 'Microsoft Visual Studio/Installer/vswhere.exe'
        if not locator.is_file():
            continue
        result = subprocess.run([str(locator), '-latest', '-products', '*', '-requires',
                                 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'],
                                text=True, capture_output=True, check=True, timeout=15)
        for line in result.stdout.splitlines():
            candidate = Path(line.strip()) / 'Common7/Tools/VsDevCmd.bat'
            if candidate.is_file():
                return candidate.resolve()
    raise SystemExit('HostX64 MSVC developer environment not found. Set VSINSTALLDIR to the Visual Studio installation.')


def qt_root(value=None) -> Path:
    root = Path(__file__).resolve().parents[1]
    requested = value
    if requested is None:
        requested = next((os.environ[name] for name in ('KSWORD_QT_DIR', 'QT_ROOT_DIR', 'QT_DIR') if os.environ.get(name)), None)
    candidates = [Path(requested)] if requested is not None else [root / '.deps/Qt/6.9.3/msvc2022_64', Path('D:/Software/Qt/6.9.3/msvc2022_64')]
    for candidate in candidates:
        if (candidate / 'include/QtCore/QCoreApplication').is_file() and (candidate / 'lib/Qt6Core.lib').is_file():
            return candidate.resolve()
    raise SystemExit('Native MSVC Qt root not found. Pass --qt or set QT_ROOT_DIR to the Qt prefix containing include and lib.')
