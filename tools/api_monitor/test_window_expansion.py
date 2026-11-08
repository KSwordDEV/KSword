"""Check window expansion against the installed Microsoft SDK on x86 and x64.

This checks SDK declarations and isolated generated wrappers; it does not test
Agent injection or the event transport.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_definitions

ROOT = Path(__file__).resolve().parents[2]
DEV = Path(os.environ.get('KSWORD_VSDEVCMD', r'D:\Software\VS\Common7\Tools\VsDevCmd.bat'))


def main():
    catalog = ROOT / 'APIMonitor_x64/api_monitor_definitions.json'
    catalog_apis = json.loads(catalog.read_text(encoding='utf-8'))['apis']
    apis = [a for a in catalog_apis if 642 <= a['id'] <= 683]
    assert len(apis) == 42
    assert len({a['id'] for a in apis}) == len(apis)
    assert {a['id'] for a in apis} == set(range(642, 684))
    gui_exports = {'GetDC', 'ReleaseDC', 'InvalidateRect', 'ValidateRect', 'RedrawWindow', 'UpdateWindow', 'PrintWindow'}
    assert all(a['category'] == ('Gui' if a['export'] in gui_exports else 'Window') for a in apis)
    assert next(a for a in apis if a['export'] == 'ClientToScreen')['return']['error_source'] == 'none'
    assert all(a['return_type'] == 'BOOL' and a['wrapper']['policy'] == 'bool' for a in apis)
    assert DEV.exists(), f'VS developer environment not found: {DEV}'
    lines = ['#include <windows.h>', '#include <type_traits>']
    for api in apis:
        types = ', '.join(p['type'] for p in api['parameters'])
        lines.append(f'using Expected{api["export"]} = BOOL (WINAPI*)({types});')
        lines.append(f'static_assert(std::is_same_v<Expected{api["export"]}, decltype(&::{api["export"]})>, "{api["export"]}");')
    with tempfile.TemporaryDirectory() as temp:
        cpp = Path(temp) / 'window_signatures.cpp'
        cpp.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        fixture = (ROOT / 'tools/api_monitor/window_expansion_fixture.cpp').read_text(encoding='utf-8-sig')
        selected = [a for a in apis if a['export'] in {'GetWindowRect', 'SetWindowTextW', 'ClientToScreen'}]
        fixture = fixture.replace('// GENERATED_WRAPPERS', '\n'.join(generate_definitions.wrapper(a) for a in selected))
        live = Path(temp) / 'window_fixture.cpp'
        live.write_text(fixture, encoding='utf-8')
        for arch in ('x86', 'x64'):
            command = f'call "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul && cl /nologo /std:c++17 /EHsc /c "{cpp}" /Fo"{temp}\\{arch}.obj"'
            batch = Path(temp) / (arch + '.cmd')
            batch.write_text('@echo off\n' + command + '\n', encoding='utf-8')
            subprocess.run(['cmd.exe', '/d', '/c', str(batch)], check=True, cwd=ROOT)
            command = f'call "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul && cl /nologo /std:c++17 /EHsc /I"{ROOT}" "{live}" /Fe"{temp}\\fixture-{arch}.exe" /Fo"{temp}\\fixture-{arch}.obj" user32.lib && "{temp}\\fixture-{arch}.exe"'
            batch.write_text('@echo off\n' + command + '\n', encoding='utf-8')
            subprocess.run(['cmd.exe', '/d', '/c', str(batch)], check=True, cwd=ROOT)
            print(f'{arch}: {len(apis)} SDK signatures and representative generated wrapper calls passed')


if __name__ == '__main__':
    main()
