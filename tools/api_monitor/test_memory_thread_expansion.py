"""Validate memory/thread declarations and exercise the production agent in an owned process."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEV = Path(os.environ.get('KSWORD_VSDEVCMD', r'D:\Software\VS\Common7\Tools\VsDevCmd.bat'))


def signatures():
    catalog = ROOT / 'APIMonitor_x64/api_monitor_definitions.json'
    merged = [a for a in json.loads(catalog.read_text(encoding='utf-8'))['apis'] if 700 <= a['id'] <= 731]
    apis = merged
    assert len(apis) == 32 and len({a['id'] for a in apis}) == 32
    assert all(700 <= a['id'] <= 759 and a['category'] in {'Memory', 'Thread'} for a in apis)
    lines = ['#define _WIN32_WINNT 0x0A00', '#include <windows.h>', '#include <enclaveapi.h>', '#include <processtopologyapi.h>', '#include <type_traits>']
    for api in apis:
        types = ', '.join(p['type'] for p in api['parameters'])
        lines += [f'using Expected{api["export"]} = {api["return_type"]} (WINAPI*)({types});',
                  f'static_assert(std::is_same_v<Expected{api["export"]}, decltype(&::{api["export"]})>, "{api["export"]}");']
    assert DEV.exists(), f'VS developer environment not found: {DEV}'
    with tempfile.TemporaryDirectory() as temp:
        cpp = Path(temp) / 'signatures.cpp'
        cpp.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        for arch in ('x86', 'x64'):
            command = f'call "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul && cl /nologo /std:c++17 /EHsc /c "{cpp}" /Fo"{temp}\\{arch}.obj"'
            batch = Path(temp) / (arch + '.cmd')
            batch.write_text('@echo off\n' + command + '\n', encoding='utf-8')
            subprocess.run(['cmd.exe', '/d', '/c', str(batch)], check=True, cwd=ROOT)
            print(f'{arch}: {len(apis)} SDK signatures match')


SOURCE = r"""
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <cstdio>
using Query = BOOL (WINAPI*)(HANDLE, PBOOL);
using Lock = BOOL (WINAPI*)(LPVOID, SIZE_T);
struct Result { BOOL ok; DWORD error; };
Result query(Query fn, HANDLE h) { BOOL output=FALSE; SetLastError(0x5a5a); BOOL ok=fn(h,&output); return {ok,GetLastError()}; }
Result lock(Lock fn, void* p) { SetLastError(0x5a5a); BOOL ok=fn(p,4096); return {ok,GetLastError()}; }
int wmain(int argc,wchar_t** argv) {
 if(argc!=2)return 1;
 auto kb=GetModuleHandleW(L"KernelBase.dll");
 auto q=reinterpret_cast<Query>(GetProcAddress(kb,"GetThreadPriorityBoost"));
 auto l=reinterpret_cast<Lock>(GetProcAddress(kb,"VirtualLock"));
 if(!q || !l)return 2;
 auto mem=VirtualAlloc(nullptr,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); if(!mem)return 3;
 auto success=query(q,GetCurrentThread()), failure=query(q,INVALID_HANDLE_VALUE), locked=lock(l,mem);
 if(!success.ok || failure.ok || !locked.ok || !VirtualUnlock(mem,4096))return 4;
 printf("%lu\n",GetCurrentProcessId()); fflush(stdout);
 for(int c;(c=getchar())!=EOF;) {
  if(c=='L' && !LoadLibraryW(argv[1]))return 5;
  if(c=='X') {
   auto s=query(q,GetCurrentThread()), f=query(q,INVALID_HANDLE_VALUE), v=lock(l,mem);
   if(s.ok!=success.ok || s.error!=success.error || f.ok!=failure.ok || f.error!=failure.error || v.ok!=locked.ok || v.error!=locked.error)return 6;
   if(!VirtualUnlock(mem,4096))return 7;
   printf("RESULT %lu %lu %lu %lu %lu %lu\n",s.ok,s.error,f.ok,f.error,v.ok,v.error);
   printf("DONE\n"); fflush(stdout);
  }
  if(c=='Q') {VirtualFree(mem,0,MEM_RELEASE);return 0;}
 }
 return 0;
}
"""


def live():
    from live_fixture_support import LiveFixture
    with LiveFixture(SOURCE, {'enable_file': 0, 'enable_memory': 1, 'enable_thread': 1}) as fixture:
        fixture.wait_for(lambda f: any(e.api == 'HooksInstalled' for e in f.events))
        fixture.command('X')
        result = fixture.process.stdout.readline().decode().split()
        assert result[0] == 'RESULT', result
        success, success_error, failure, failure_error, locked, lock_error = map(int, result[1:])
        assert fixture.process.stdout.readline().strip() == b'DONE'
        fixture.wait_for(lambda f: len([e for e in f.events if e.kind == 0 and e.api == 'GetThreadPriorityBoost']) >= 2 and any(e.api == 'VirtualLock' for e in f.events))
        query = [e for e in fixture.events if e.kind == 0 and e.api == 'GetThreadPriorityBoost']
        lock = next(e for e in fixture.events if e.kind == 0 and e.api == 'VirtualLock')
        for event, value, status in [(query[-2], success, 0), (query[-1], failure, failure_error), (lock, locked, 0)]:
            assert event.index == 0x52545631 and event.count == 0x44555231
            assert event.address == value and event.result == status and event.revision < 600000000
            assert 'arg1=' in event.detail
        assert 'thread=' in query[-1].detail and 'address=' in lock.detail
    print('PASS: owned process preserves successful/failing return and LastError, records named arguments and duration')


if __name__ == '__main__':
    signatures()
    live()
