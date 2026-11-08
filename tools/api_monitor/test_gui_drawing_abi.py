"""Compare GUI drawing catalog signatures with the installed Win32 and Win64 SDK."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEV = Path(os.environ.get('KSWORD_VSDEVCMD', r'D:\Software\VS\Common7\Tools\VsDevCmd.bat'))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidates', action='store_true', help='verify the pre-integration candidate array')
    args = parser.parse_args()
    if args.candidates:
        catalog = json.loads((ROOT / '.codex-build-logs/gui-drawing-candidates.json').read_text(encoding='utf-8'))
    else:
        catalog = json.loads((ROOT / 'APIMonitor_x64/api_monitor_definitions.json').read_text(encoding='utf-8'))['apis']
    apis = [api for api in catalog if 950 <= api['id'] <= 993]
    assert len(apis) == 44 and {api['id'] for api in apis} == set(range(950, 994))
    assert all(api['category'] == 'Gui' and api['return']['error_source'] == 'none' for api in apis)
    lines = ['#include <windows.h>', '#include <type_traits>']
    for api in apis:
        types = ', '.join(p['type'] for p in api['parameters'])
        lines += [f'using Expected{api["export"]} = {api["return_type"]} (WINAPI*)({types});',
                  f'static_assert(std::is_same_v<Expected{api["export"]}, decltype(&::{api["export"]})>, "{api["export"]}");']
    with tempfile.TemporaryDirectory() as temp:
        cpp = Path(temp) / 'gui_drawing_abi.cpp'
        cpp.write_text('\n'.join(lines), encoding='utf-8')
        for arch in ('x86', 'x64'):
            bat = Path(temp) / (arch + '.cmd')
            bat.write_text(f'@echo off\ncall "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul && cl /nologo /std:c++17 /c "{cpp}" /Fo"{temp}\\{arch}.obj"\n', encoding='utf-8')
            subprocess.run(['cmd.exe', '/d', '/c', str(bat)], check=True, cwd=ROOT)
            print(f'{arch}: {len(apis)} GUI drawing SDK signatures match')

if __name__ == '__main__':
    main()
