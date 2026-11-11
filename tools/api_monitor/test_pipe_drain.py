"""Exercise the production drain reader on real byte-mode Windows pipes."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='ksword_pipe_drain_') as tmp:
    folder = Path(tmp)
    executable = folder / 'drain.exe'
    subprocess.run(['cl', '/nologo', '/EHsc', '/std:c++20', '/W4', '/WX', '/utf-8',
                    '/I' + str(root), str(root / 'tools/api_monitor/pipe_drain_test.cpp'),
                    '/Fo:' + str(folder / 'drain.obj'), '/Fe:' + str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=15)
