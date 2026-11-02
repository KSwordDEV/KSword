"""Verify the production archive against real concurrent packet writes."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
qt = root / '.deps/Qt/6.9.3/msvc2022_64'
if not qt.exists():
    qt = Path('D:/Software/Qt/6.9.3/msvc2022_64')
with tempfile.TemporaryDirectory(prefix='ksword_api_archive_') as temporary:
    directory = Path(temporary)
    exe = directory / 'archive_test.exe'
    subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/MD', '/Zc:__cplusplus',
                    '/I' + str(qt / 'include'), '/I' + str(qt / 'include/QtCore'),
                    '/I' + str(root / 'Ksword5.1/Ksword5.1'),
                    str(root / 'tools/api_monitor/archive_writer_test.cpp'),
                    '/Fo:' + str(directory / 'archive.obj'), '/Fe:' + str(exe),
                    '/link', str(qt / 'lib/Qt6Core.lib')], check=True)
    env = os.environ.copy()
    key = next(k for k in env if k.lower() == 'path')
    env[key] = str(qt / 'bin') + os.pathsep + env[key]
    subprocess.run([str(exe)], env=env, check=True, timeout=60)
