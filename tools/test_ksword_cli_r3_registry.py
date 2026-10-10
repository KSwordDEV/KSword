"""Exercise production registry rename with API fixtures; never changes a real key."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <Windows.h>
LSTATUS WINAPI FixtureOpen(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY);
LSTATUS WINAPI FixtureClose(HKEY);
LSTATUS WINAPI FixtureQuery(HKEY,LPCWSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);
LSTATUS WINAPI FixtureSet(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD);
LSTATUS WINAPI FixtureDelete(HKEY,LPCWSTR);
#define RegOpenKeyExW FixtureOpen
#define RegCloseKey FixtureClose
#define RegQueryValueExW FixtureQuery
#define RegSetValueExW FixtureSet
#define RegDeleteValueW FixtureDelete
'''
SOURCE = r'''
#include "mock.h"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cstring>
#include <cwchar>
static unsigned writes,deletes;
static bool copied;
LSTATUS WINAPI FixtureOpen(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY key) {*key=reinterpret_cast<HKEY>(123);return ERROR_SUCCESS;}
LSTATUS WINAPI FixtureClose(HKEY) {return ERROR_SUCCESS;}
LSTATUS WINAPI FixtureQuery(HKEY,LPCWSTR name,LPDWORD,LPDWORD type,LPBYTE data,LPDWORD bytes) {
    if(!name || (_wcsicmp(name,L"old")!=0 && (!copied || _wcsicmp(name,L"new")!=0))) return ERROR_FILE_NOT_FOUND;
    static const BYTE value[]{0,255,34,92}; *type=REG_BINARY;
    if(data) {if(*bytes<sizeof(value)) {*bytes=sizeof(value);return ERROR_MORE_DATA;}std::memcpy(data,value,sizeof(value));}
    *bytes=sizeof(value);return ERROR_SUCCESS;
}
LSTATUS WINAPI FixtureSet(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD) {++writes;copied=true;return ERROR_SUCCESS;}
LSTATUS WINAPI FixtureDelete(HKEY,LPCWSTR) {++deletes;return ERROR_ACCESS_DENIED;}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    ks::cli::registerRegistryMutations();const auto result=ks::cli::dispatchR3(argc,argv).value_or(1);
    const bool same=std::wcscmp(argv[9],L"OLD")==0;
    if(same ? writes!=0 || deletes!=0 : writes!=1 || deletes!=1) return 9;
    return result;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-registry-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        source = SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix())
        (directory / 'fixture.cpp').write_text(source)
        binary = directory / 'fixture.exe'
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3RegistryMutations.cpp', 'KswordCLI/R3Input.cpp',
                   'shared/usermode/backend/registry/RegistryMutations.cpp',
                   'shared/usermode/backend/registry/RegistryBrowse.cpp', 'shared/usermode/backend/registry/RegistryModel.cpp']
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / source) for source in sources], '/Fe:' + str(binary), '/link', 'Advapi32.lib'], cwd=directory, check=True)
        def run(new, code):
            result = subprocess.run([str(binary), 'registry', 'value', 'rename', '--path', r'HKLM\Software\Fixture',
                                     '--old-name', 'old', '--new-name', new, '--confirm', '--json'], capture_output=True, timeout=10)
            assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)['data']
        partial = run('new', 6)
        assert partial['partial'] and partial['win32Error'] == 5 and not partial['requestSucceeded']
        assert partial['result']['oldPostcheck']['present'] and partial['result']['newPostcheck']['present']
        assert partial['result']['newPostcheck']['dataHex'] == '00ff225c'
        unchanged = run('OLD', 0)
        assert unchanged['unchanged'] and unchanged['verified'] and unchanged['result']['oldPostcheck']['present']
        print('R3_REGISTRY_FIXTURE_PASS copy/delete partial failure, same-name no-op, exact bytes')


if __name__ == '__main__':
    main()
