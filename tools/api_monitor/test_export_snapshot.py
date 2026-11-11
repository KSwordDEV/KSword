"""Verify nearest-export lookup without touching another process or network."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='ksword_export_snapshot_') as temp:
    work = Path(temp)
    executable = work / 'export_snapshot.exe'
    subprocess.run(['cl', '/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', '/utf-8', '/MD',
                    '/Zc:__cplusplus', '/I' + str(root), str(root / 'tools/api_monitor/export_snapshot_test.cpp'),
                    '/Fo:' + str(work / 'export_snapshot.obj'), '/Fe:' + str(executable),
                    '/link', '/IMPLIB:' + str(work / 'export_snapshot.lib')], check=True)
    subprocess.run([str(executable)], check=True, timeout=20)
