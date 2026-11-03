"""Compile and exercise the production QtCore signature catalog."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
qt = root / '.deps/Qt/6.9.3/msvc2022_64'
if not qt.exists():
    qt = Path('D:/Software/Qt/6.9.3/msvc2022_64')
with tempfile.TemporaryDirectory(prefix='ksword_api_signature_') as temporary:
    directory = Path(temporary)
    exe = directory / 'signature.exe'
    subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/MD', '/Zc:__cplusplus',
                    '/I' + str(qt / 'include'), '/I' + str(qt / 'include/QtCore'),
                    '/I' + str(root / 'Ksword5.1/Ksword5.1'),
                    str(root / 'tools/api_monitor/signature_catalog_test.cpp'),
                    '/Fo:' + str(directory / 'signature.obj'), '/Fe:' + str(exe),
                    '/link', str(qt / 'lib/Qt6Core.lib')], check=True)
    env = os.environ.copy()
    key = next(key for key in env if key.lower() == 'path')
    env[key] = str(qt / 'bin') + os.pathsep + env[key]
    subprocess.run([str(exe), *sys.argv[1:]], cwd=root, env=env, check=True, timeout=30)
