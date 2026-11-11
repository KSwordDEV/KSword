"""Compile every extra memory/thread/process declaration against the installed SDK."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[2]
DEV=Path(os.environ.get('KSWORD_VSDEVCMD',r'D:\Software\VS\Common7\Tools\VsDevCmd.bat'))

def main():
 catalog=json.loads((ROOT/'APIMonitor_x64/api_monitor_definitions.json').read_text(encoding='utf8'))['apis']
 merged=[a for a in catalog if 830 <= a['id'] <= 851]
 apis=merged
 assert len(apis)==22 and len({a['id'] for a in apis})==22
 lines=['#define _WIN32_WINNT 0x0A00','#define PSAPI_VERSION 2','#include <Windows.h>','#include <psapi.h>','#include <memoryapi.h>','#include <realtimeapiset.h>','#include <type_traits>']
 for a in apis:
  types=', '.join(p['type'] for p in a['parameters']); name=a['export']
  lines += [f'using Expected{name} = {a["return_type"]} (WINAPI*)({types});', f'static_assert(std::is_same_v<Expected{name}, decltype(&::{name})>, "{name}");']
 with tempfile.TemporaryDirectory() as temp:
  cpp=Path(temp)/'signatures.cpp'; cpp.write_text('\n'.join(lines)+'\n',encoding='utf8')
  for arch in ('x86','x64'):
   batch=Path(temp)/(arch+'.cmd'); batch.write_text(f'@echo off\ncall "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul && cl /nologo /std:c++17 /EHsc /c "{cpp}" /Fo"{temp}\\{arch}.obj"\n',encoding='utf8')
   subprocess.run(['cmd.exe','/d','/c',str(batch)],check=True,cwd=ROOT)
   print(f'{arch}: {len(apis)} SDK signatures match')
if __name__=='__main__': main()
