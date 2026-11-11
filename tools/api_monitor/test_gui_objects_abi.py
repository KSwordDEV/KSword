"""Compile the GDI object signatures against both installed Windows SDK ABIs."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEV = Path(os.environ.get('KSWORD_VSDEVCMD', r'D:\Software\VS\Common7\Tools\VsDevCmd.bat'))

def main():
    catalog = json.loads((ROOT / 'APIMonitor_x64/api_monitor_definitions.json').read_text(encoding='utf8'))['apis']
    apis = [a for a in catalog if 900 <= a['id'] <= 932]
    if not apis:
        apis = json.loads((ROOT / '.codex-build-logs/gui-objects-candidates.json').read_text(encoding='utf8'))
    assert {a['id'] for a in apis} == set(range(900, 933))
    assert all(a['category'] == 'Gui' and a['return']['error_source'] == 'none' for a in apis)
    lines = ['#include <Windows.h>', '#include <type_traits>']
    for a in apis:
        name = a['export']; types = ', '.join(p['type'] for p in a['parameters'])
        lines += [f'using Expected{name} = {a["return_type"]} (WINAPI*)({types});',
                  f'static_assert(std::is_same_v<Expected{name}, decltype(&::{name})>, "{name}");']
    with tempfile.TemporaryDirectory() as temp:
        cpp = Path(temp) / 'gui_objects.cpp'; cpp.write_text('\n'.join(lines), encoding='utf8')
        for arch in ('x86', 'x64'):
            batch = Path(temp) / (arch + '.cmd')
            batch.write_text(f'@echo off\ncall "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul && cl /nologo /std:c++17 /c "{cpp}" /Fo"{temp}\\{arch}.obj"\n', encoding='utf8')
            subprocess.run(['cmd.exe', '/d', '/c', str(batch)], check=True, cwd=ROOT)
            print(f'{arch}: {len(apis)} GDI SDK signatures match')

if __name__ == '__main__':
    main()
