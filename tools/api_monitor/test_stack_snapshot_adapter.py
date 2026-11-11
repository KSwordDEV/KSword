"""Exercise the production Qt adapter without a GUI or external process."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
qt = root / '.deps/Qt/6.9.3/msvc2022_64'
if not qt.exists():
    qt = Path('D:/Software/Qt/6.9.3/msvc2022_64')
with tempfile.TemporaryDirectory(prefix='ksword_stack_snapshot_qt_') as temp:
    work = Path(temp)
    exe = work / 'stack_snapshot_adapter.exe'
    subprocess.run(['cl', '/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', '/utf-8', '/MD',
                    '/Zc:__cplusplus', '/I' + str(root), '/I' + str(root / 'Ksword5.1/Ksword5.1'),
                    '/I' + str(qt / 'include'), '/I' + str(qt / 'include/QtCore'),
                    str(root / 'tools/api_monitor/stack_snapshot_adapter_test.cpp'),
                    str(root / 'Ksword5.1/Ksword5.1/UI/AsyncOperation.cpp'),
                    '/Fo:' + str(work) + os.sep, '/Fe:' + str(exe),
                    '/link', str(qt / 'lib/Qt6Core.lib'), '/IMPLIB:' + str(work / 'stack_snapshot_adapter.lib')], check=True)
    env = os.environ.copy()
    key = next(k for k in env if k.lower() == 'path')
    env[key] = str(qt / 'bin') + os.pathsep + env[key]
    subprocess.run([str(exe)], env=env, check=True, timeout=20)
