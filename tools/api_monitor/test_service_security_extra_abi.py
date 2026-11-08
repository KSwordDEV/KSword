"""Check expansion declarations against the installed Windows SDK for both ABIs."""
import json, os, subprocess, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
DEV = Path(os.environ.get('KSWORD_VSDEVCMD', r'D:\Software\VS\Common7\Tools\VsDevCmd.bat'))
def main():
    catalog=json.loads((ROOT/'APIMonitor_x64/api_monitor_definitions.json').read_text(encoding='utf8'))['apis']
    apis=[a for a in catalog if 860 <= a['id'] <= 879]
    assert len(apis)==20 and len({a['id'] for a in apis})==20
    lines=['#define _WIN32_WINNT 0x0A00','#include <windows.h>','#include <objbase.h>','#include <type_traits>']
    for a in apis:
        types=', '.join(p['type'] for p in a['parameters'])
        lines.append(f'static_assert(std::is_same_v<decltype(&::{a["export"]}), {a["return_type"]} (WINAPI*)({types})>, "{a["export"]}");')
    with tempfile.TemporaryDirectory() as temp:
        cpp=Path(temp)/'extra.cpp'; cpp.write_text('\n'.join(lines),encoding='utf8')
        for arch in ('x86','x64'):
            cmd=Path(temp)/(arch+'.cmd'); cmd.write_text(f'@echo off\ncall "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul && cl /nologo /std:c++17 /c "{cpp}" /Fo"{temp}\\{arch}.obj"\n',encoding='utf8')
            subprocess.run(['cmd.exe','/d','/c',str(cmd)],cwd=ROOT,check=True)
            print(f'{arch}: {len(apis)} SDK signatures match',flush=True)
if __name__=='__main__': main()
