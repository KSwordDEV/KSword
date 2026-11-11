"""Run the production ABI value decoder with x64 QtCore."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
qt = root / '.deps/Qt/6.9.3/msvc2022_64'
if not qt.exists():
    qt = Path('D:/Software/Qt/6.9.3/msvc2022_64')
with tempfile.TemporaryDirectory(prefix='ksword_api_decode_') as temporary:
    directory = Path(temporary)
    exe = directory / 'decode.exe'
    subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/MD', '/Zc:__cplusplus',
                    '/I' + str(qt / 'include'), '/I' + str(qt / 'include/QtCore'),
                    '/I' + str(root / 'Ksword5.1/Ksword5.1'),
                    str(root / 'tools/api_monitor/parameter_decode_test.cpp'),
                    '/Fo:' + str(directory / 'decode.obj'), '/Fe:' + str(exe),
                    '/link', str(qt / 'lib/Qt6Core.lib')], check=True)
    env = os.environ.copy()
    key = next(key for key in env if key.lower() == 'path')
    env[key] = str(qt / 'bin') + os.pathsep + env[key]
    subprocess.run([str(exe)], env=env, check=True, timeout=30)
