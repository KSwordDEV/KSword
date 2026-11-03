"""Exercise caller identity and asynchronous snapshots using only this test process."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
qt = root / '.deps/Qt/6.9.3/msvc2022_64'
if not qt.exists():
    qt = Path('D:/Software/Qt/6.9.3/msvc2022_64')
with tempfile.TemporaryDirectory(prefix='ksword_caller_snapshot_') as temporary:
    work = Path(temporary)
    env = os.environ.copy()
    key = next(name for name in env if name.lower() == 'path')
    env[key] = str(qt / 'bin') + os.pathsep + env[key]
    for name, use_qt in (('caller_snapshot_test', False), ('caller_snapshot_adapter_test', True)):
        exe = work / (name + '.exe')
        command = ['cl', '/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', '/utf-8', '/MD',
                   '/Zc:__cplusplus', '/I' + str(root)]
        if use_qt:
            command += ['/I' + str(root / 'Ksword5.1/Ksword5.1'), '/I' + str(qt / 'include'),
                        '/I' + str(qt / 'include/QtCore')]
        command += [str(root / 'tools/api_monitor' / (name + '.cpp')),
                    '/Fo:' + str(work / (name + '.obj')), '/Fe:' + str(exe)]
        if use_qt:
            command += ['/link', str(qt / 'lib/Qt6Core.lib')]
        subprocess.run(command, cwd=root, env=env, check=True)
        subprocess.run([str(exe)], cwd=root, env=env, check=True, timeout=20)
