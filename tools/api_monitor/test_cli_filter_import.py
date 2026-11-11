"""Exercise the production Qt-free GUI filter importer on x86 or x64."""
import os
from pathlib import Path
import subprocess
import tempfile

root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='ksword_cli_filter_') as temp:
    work=Path(temp); exe=work/'filter.exe'
    subprocess.run(['cl','/nologo','/std:c++20','/Zc:__cplusplus','/EHsc','/utf-8','/W4','/WX','/MD',
        '/I'+str(root),str(root/'tools/api_monitor/cli_filter_import_test.cpp'),
        str(root/'shared/evidence/EvidenceJson.cpp'),str(root/'shared/evidence/LosslessValue.cpp'),
        '/Fo:'+str(work)+os.sep,'/Fe:'+str(exe)],check=True)
    subprocess.run([str(exe),str(work)],check=True,timeout=30)
