"""Verify native failures, malformed rows, signed fields and recycled-PID paths."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <Windows.h>
FARPROC WINAPI FixtureResolve(HMODULE,LPCSTR);
BOOL WINAPI FixtureImage(HANDLE,DWORD,LPWSTR,PDWORD);
#define GetProcAddress FixtureResolve
#define QueryFullProcessImageNameW FixtureImage
'''
SOURCE = r'''
#include "mock.h"
#undef GetProcAddress
#include "ENUMERATOR"
#undef QueryFullProcessImageNameW
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cstring>
static std::wstring mode;
static unsigned imageCalls;
static LONG NTAPI FixtureQuery(ULONG,PVOID raw,ULONG size,PULONG required) {
    if(mode==L"denied")return static_cast<LONG>(0xc0000022);
    using Row=ks::r3::process::KSYSTEM_PROCESS_INFORMATION;
    const std::wstring name=L"fixture.exe";*required=static_cast<ULONG>(sizeof(Row)+(name.size()+1)*sizeof(wchar_t));
    if(size<*required)return static_cast<LONG>(0xc0000004);
    auto* row=static_cast<Row*>(raw);*row={};row->UniqueProcessId=reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(GetCurrentProcessId()));
    FILETIME created{},exit{},kernel{},user{};GetProcessTimes(GetCurrentProcess(),&created,&exit,&kernel,&user);
    row->CreateTime.QuadPart=(static_cast<ULONGLONG>(created.dwHighDateTime)<<32)|created.dwLowDateTime;
    if(mode==L"identity")++row->CreateTime.QuadPart;
    row->BasePriority=-2;row->UserTime.QuadPart=9007199254740993LL;row->WorkingSetSize=123456;
    row->ImageName.Length=static_cast<USHORT>(name.size()*sizeof(wchar_t));row->ImageName.Buffer=reinterpret_cast<wchar_t*>(row+1);
    std::memcpy(row->ImageName.Buffer,name.c_str(),(name.size()+1)*sizeof(wchar_t));
    if(mode==L"offset")row->NextEntryOffset=1;
    if(mode==L"name")row->ImageName.Buffer=reinterpret_cast<wchar_t*>(1);
    return 0;
}
FARPROC WINAPI FixtureResolve(HMODULE module,LPCSTR name) {
    if(std::strcmp(name,"NtQuerySystemInformation")==0)return mode==L"unavailable"?nullptr:reinterpret_cast<FARPROC>(FixtureQuery);
    return GetProcAddress(module,name);
}
BOOL WINAPI FixtureImage(HANDLE p,DWORD flags,LPWSTR text,PDWORD size) {++imageCalls;return QueryFullProcessImageNameW(p,flags,text,size);}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
    ks::cli::registerProcessEnumeration();const int rc=ks::cli::dispatchR3(argc,argv).value_or(1);
    if(mode==L"identity" && imageCalls!=0)return 9;
    return rc;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-process-enum-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        source = SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix())
        source = source.replace('ENUMERATOR', (ROOT / 'shared/usermode/backend/process/ProcessEnumerator.cpp').as_posix())
        # The native implementation is compiled in this TU so the fixture uses
        # exactly its private native row layout rather than duplicating the ABI.
        (directory / 'fixture.cpp').write_text(source)
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3ProcessEnumeration.cpp', 'shared/usermode/backend/NtApi.cpp']
        binary = directory / 'fixture.exe'
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / file) for file in sources], '/Fe:' + str(binary)], cwd=directory, check=True)
        def run(mode, code):
            result = subprocess.run([str(binary), mode, 'process', 'enum', '--backend', 'r3', '--json'], capture_output=True, timeout=15)
            assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)['data']
        valid = run('valid', 0)
        assert valid['complete'] and valid['processes'][0]['basePriority'] == -2
        assert valid['processes'][0]['userTime100ns'] == '9007199254740993'
        assert run('denied', 3)['ntStatus'] == '0xc0000022'
        assert run('unavailable', 5)['ntStatus'] == '0xc000007a'
        assert run('offset', 4)['malformed'] and run('name', 4)['malformed']
        recycled = run('identity', 6)['processes'][0]
        assert recycled['path'] is None and recycled['pathWin32Error'] == 13
        print('R3_PROCESS_ENUM_FIXTURE_PASS NT errors, malformed rows, counters and recycled-PID enrichment')


if __name__ == '__main__':
    main()
