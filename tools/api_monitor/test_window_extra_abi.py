"""Verify second window batch against both installed Microsoft SDK ABIs."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEV = Path(os.environ.get('KSWORD_VSDEVCMD', r'D:\Software\VS\Common7\Tools\VsDevCmd.bat'))

def main():
    catalog = json.loads((ROOT / 'APIMonitor_x64/api_monitor_definitions.json').read_text(encoding='utf-8'))['apis']
    apis = [a for a in catalog if 801 <= a['id'] <= 823]
    assert len(apis) == 23 and {a['id'] for a in apis} == set(range(801,824))
    assert all(a['category'] == 'Window' and a['return']['error_source'] == 'none' for a in apis)
    lines = ['#include <windows.h>', '#include <type_traits>']
    for api in apis:
        types = ', '.join(p['type'] for p in api['parameters'])
        lines += [f'using Expected{api["export"]} = BOOL (WINAPI*)({types});', f'static_assert(std::is_same_v<Expected{api["export"]}, decltype(&::{api["export"]})>, "{api["export"]}");']
    with tempfile.TemporaryDirectory() as temp:
        cpp = Path(temp) / 'menu_abi.cpp'
        cpp.write_text('\n'.join(lines), encoding='utf-8')
        for arch in ('x86','x64'):
            bat = Path(temp) / (arch + '.cmd')
            bat.write_text(f'@echo off\ncall "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul && cl /nologo /std:c++17 /c "{cpp}" /Fo"{temp}\\{arch}.obj"\n', encoding='utf-8')
            subprocess.run(['cmd.exe','/d','/c',str(bat)], check=True, cwd=ROOT)
            print(f'{arch}: {len(apis)} menu SDK signatures match')
if __name__ == '__main__':
    main()
