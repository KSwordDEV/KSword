"""Verify SDK ABI on both architectures and generated wrappers on owned objects."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import generate_definitions

ROOT = Path(__file__).resolve().parents[2]
DEV = Path(os.environ.get('KSWORD_VSDEVCMD', r'D:\Software\VS\Common7\Tools\VsDevCmd.bat'))

def main():
    catalog = json.loads((ROOT / 'APIMonitor_x64/api_monitor_definitions.json').read_text(encoding='utf-8'))['apis']
    apis = [a for a in catalog if 760 <= a['id'] <= 800]
    assert len(apis) == 41 and len({a['id'] for a in apis}) == len(apis)
    assert all(760 <= a['id'] <= 839 and a['category'] in {'Service','Security','Crypto','Com'} for a in apis)
    lines = ['#define _WIN32_WINNT 0x0A00', '#include <windows.h>', '#include <bcrypt.h>', '#include <objbase.h>', '#include <type_traits>']
    for api in apis:
        types = ', '.join(p['type'] for p in api['parameters'])
        lines.append(f'static_assert(std::is_same_v<decltype(&::{api["export"]}), {api["return_type"]} (WINAPI*)({types})>, "{api["export"]}");')
    assert DEV.exists(), f'VS developer environment not found: {DEV}'
    with tempfile.TemporaryDirectory() as temp:
        cpp=Path(temp)/'signatures.cpp'; cpp.write_text('\n'.join(lines)+'\n',encoding='utf-8')
        selected=[a for a in apis if a['export'] in {'CoCreateGuid','CopySid','BCryptGetProperty'}]
        fixture=(ROOT/'tools/api_monitor/service_security_expansion_fixture.cpp').read_text(encoding='utf-8-sig')
        fixture=fixture.replace('// GENERATED_WRAPPERS','\n'.join(generate_definitions.wrapper(a) for a in selected))
        live=Path(temp)/'fixture.cpp'; live.write_text(fixture,encoding='utf-8')
        for arch in ('x86','x64'):
            batch=Path(temp)/(arch+'.cmd')
            command=f'call "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul && cl /nologo /std:c++17 /EHsc /c "{cpp}" /Fo"{temp}\\{arch}.obj" && cl /nologo /std:c++17 /EHsc /I"{ROOT}" "{live}" /Fe"{temp}\\fixture-{arch}.exe" /Fo"{temp}\\fixture-{arch}.obj" advapi32.lib bcrypt.lib ole32.lib && "{temp}\\fixture-{arch}.exe"'
            batch.write_text('@echo off\n'+command+'\n',encoding='utf-8')
            subprocess.run(['cmd.exe','/d','/c',str(batch)],check=True,cwd=ROOT)
            print(f'{arch}: {len(apis)} SDK signatures and generated wrapper calls passed')

if __name__ == '__main__': main()
