"""Build and test bounded call-time stack payloads in this test process only."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='ksword_callstack_') as temporary:
    work = Path(temporary)
    exe = work / 'callstack.exe'
    subprocess.run(['cl', '/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', '/utf-8', '/MD',
                    '/I' + str(root), str(root / 'tools/api_monitor/callstack_test.cpp'),
                    str(root / 'tools/api_monitor/callstack_test_other.cpp'),
                    '/Fo:' + str(work) + os.sep, '/Fe:' + str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=20, env=os.environ.copy())
print('PASS: bounded call-time stack payload and full-detail preservation')
