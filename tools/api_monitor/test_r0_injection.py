"""Verify the production R0 adapter with a fake driver; never injects a process."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='ksword_r0_adapter_') as temp:
    directory = Path(temp)
    executable = directory / 'test.exe'
    subprocess.run(['cl', '/nologo', '/EHsc', '/std:c++20', '/W4', '/WX', '/utf-8', '/MD',
                    '/I' + str(root), str(root / 'tools/api_monitor/r0_injection_test.cpp'),
                    '/Fo:' + str(directory / 'test.obj'), '/Fe:' + str(executable),
                    '/link', 'Advapi32.lib'], check=True)
    subprocess.run([str(executable)], check=True, timeout=30, env=os.environ.copy())
