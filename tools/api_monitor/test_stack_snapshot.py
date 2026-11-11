"""Compile and exercise asynchronous stack mapping against this process only."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='ksword_stack_snapshot_') as temp:
    work = Path(temp)
    executable = work / 'stack_snapshot.exe'
    subprocess.run(['cl', '/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', '/utf-8', '/MD',
                    '/Zc:__cplusplus', '/I' + str(root), str(root / 'tools/api_monitor/stack_snapshot_test.cpp'),
                    '/Fo:' + str(work / 'stack_snapshot.obj'), '/Fe:' + str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=20)
