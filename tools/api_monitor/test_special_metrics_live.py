"""Verify actual metrics from the candidate agent in an owned target process."""
from live_fixture_support import LiveFixture

source = r'''
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdio>
#include <cstdint>
using NtQuery = LONG (NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
int wmain(int argc, wchar_t** argv) {
 if (argc!=2) return 1; printf("%lu\n",GetCurrentProcessId()); fflush(stdout);
 for(int c;(c=getchar())!=EOF;){
  if(c=='L' && !LoadLibraryW(argv[1])) return 2;
  if(c=='X') {
   SetLastError(0x1551); DWORD attrs=GetFileAttributesW(L"Z:\\ksword_special_missing\\entry"); DWORD error=GetLastError();
   HKEY result=nullptr; SetLastError(0x1552); LSTATUS registry=RegOpenKeyExW(HKEY_CURRENT_USER,L"ksword_special_missing",0,KEY_READ,&result); DWORD regError=GetLastError();
   auto query=reinterpret_cast<NtQuery>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess"));
   ULONG returned=0; ULONG_PTR info[6]{}; SetLastError(0x1553); LONG nt=query(GetCurrentProcess(),0,info,sizeof(info),&returned); DWORD ntError=GetLastError();
   printf("VALUES %lu %lu %ld %lu %ld %lu\n",attrs,error,registry,regError,nt,ntError);fflush(stdout);
  }
  if(c=='Q')return 0;
 }return 0;
}
'''
with LiveFixture(source, {'enable_file': 1, 'enable_registry': 1, 'enable_process': 1}, link_arguments=('Advapi32.lib',)) as fixture:
    fixture.wait_for(lambda f: any(e.api == 'HooksInstalled' for e in f.events))
    fixture.events.clear()
    fixture.command('X')
    label, attrs, error, registry, reg_error, nt, nt_error = fixture.process.stdout.readline().decode().strip().split()
    assert label == 'VALUES'
    attrs, error, registry, reg_error, nt, nt_error = map(int, (attrs, error, registry, reg_error, nt, nt_error))
    assert attrs == 0xffffffff and error != 0 and registry != 0 and reg_error == 0x1552
    assert nt == 0 and nt_error == 0x1553
    names = ['GetFileAttributesW', 'RegOpenKeyExW', 'NtQueryInformationProcess']
    fixture.wait_for(lambda f: all(any(e.kind == 0 and e.api == name for e in f.events) for name in names))
    expected = dict(zip(names, (attrs, registry, nt)))
    for name in names:
        events = [e for e in fixture.events if e.kind == 0 and e.api == name]
        assert any(e.index == 0x52545631 and e.count == 0x44555231
                   and e.address == expected[name] & 0xffffffff and e.revision < 600000000
                   for e in events), (name, [(e.index, e.count, e.address, e.revision) for e in events])
print('PASS: real file, registry and NT special return bits, measured duration and caller error state')
