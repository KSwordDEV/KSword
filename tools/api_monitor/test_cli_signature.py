"""Parse the production signature catalog using the Qt-free CLI implementation."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='ksword_cli_signatures_') as temp:
    work=Path(temp); exe=work/'signature.exe'
    subprocess.run(['cl','/nologo','/std:c++20','/Zc:__cplusplus','/EHsc','/utf-8','/W4','/WX','/MD',
        '/I'+str(root),str(root/'tools/api_monitor/cli_signature_test.cpp'),
        str(root/'shared/evidence/EvidenceJson.cpp'),str(root/'shared/evidence/LosslessValue.cpp'),
        '/Fo:'+str(work)+os.sep,'/Fe:'+str(exe),'/link','Advapi32.lib'],check=True)
    catalog = Path(sys.argv[1]) if len(sys.argv) > 1 else root/'APIMonitor_x64/api_monitor_definitions.json'
    subprocess.run([str(exe),str(catalog),*(['--candidate'] if len(sys.argv) > 1 else [])],check=True,timeout=30)
    for schema in ('2', '"1"', 'null'):
        malformed=work/'invalid.json'
        malformed.write_text('{"schema_version":1,"apis":[],"reference_signatures":{"schema_version":'+schema+',"status":"unverified","entries":[]}}',encoding='utf-8')
        subprocess.run([str(exe),str(malformed),'--invalid'],check=True,timeout=30)
