"""Compile and test CLI-native filtering and bounded density without injection."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='ksword_cli_view_') as temp:
    path = Path(temp)
    exe = path / 'view.exe'
    subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/W4','/WX','/MD',
                    '/I'+str(root),str(root/'tools/api_monitor/cli_view_test.cpp'),
                    '/Fo:'+str(path/'view.obj'),'/Fe:'+str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=30,env=os.environ.copy())
