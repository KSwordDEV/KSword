"""Check native failure status and Restart Manager session release."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <Windows.h>
#include <Aclapi.h>
#include <restartmanager.h>
DWORD WINAPI FixtureSet(LPWSTR,SE_OBJECT_TYPE,SECURITY_INFORMATION,PSID,PSID,PACL,PACL);
DWORD WINAPI FixtureStart(DWORD*,DWORD,WCHAR[]);
DWORD WINAPI FixtureRegister(DWORD,UINT,LPCWSTR[],UINT,RM_UNIQUE_PROCESS[],UINT,LPCWSTR[]);
DWORD WINAPI FixtureList(DWORD,UINT*,UINT*,RM_PROCESS_INFO[],LPDWORD);
DWORD WINAPI FixtureEnd(DWORD);
#define SetNamedSecurityInfoW FixtureSet
#define RmStartSession FixtureStart
#define RmRegisterResources FixtureRegister
#define RmGetList FixtureList
#define RmEndSession FixtureEnd
'''
SOURCE = r'''
#include "mock.h"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
static unsigned ended;
DWORD WINAPI FixtureSet(LPWSTR,SE_OBJECT_TYPE,SECURITY_INFORMATION,PSID,PSID,PACL,PACL) {return ERROR_ACCESS_DENIED;}
DWORD WINAPI FixtureStart(DWORD* session,DWORD,WCHAR[]) {*session=123;return ERROR_SUCCESS;}
DWORD WINAPI FixtureRegister(DWORD,UINT,LPCWSTR[],UINT,RM_UNIQUE_PROCESS[],UINT,LPCWSTR[]) {return ERROR_ACCESS_DENIED;}
DWORD WINAPI FixtureList(DWORD,UINT*,UINT*,RM_PROCESS_INFO[],LPDWORD) {return ERROR_INVALID_FUNCTION;}
DWORD WINAPI FixtureEnd(DWORD session) {if(session==123)++ended;return ERROR_SUCCESS;}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    ks::cli::registerFileOwnership();const int rc=ks::cli::dispatchR3(argc,argv).value_or(1);
    if(std::wstring(argv[2])==L"locks" && ended!=1)return 9;
    return rc;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-ownership-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        (directory / 'fixture.cpp').write_text(SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix()))
        target = directory / 'data.txt'
        target.write_bytes(b'123')
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3FileOwnership.cpp',
                   'shared/usermode/backend/file/Ownership.cpp', 'shared/usermode/backend/file/PathNavigator.cpp']
        binary = directory / 'fixture.exe'
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / source) for source in sources], '/Fe:' + str(binary), '/link', 'Advapi32.lib'], cwd=directory, check=True)
        for args in (['file', 'ownership', 'take', '--confirm'], ['file', 'locks', 'query']):
            result = subprocess.run([str(binary), *args, '--path', str(target), '--json'], capture_output=True, timeout=15)
            assert result.returncode == 3, (result.returncode, result.stdout, result.stderr)
            document = json.loads(result.stdout)
            assert document['status'] == 'failed' and document['data']['win32Error'] == 5
            if args[1] == 'ownership':
                assert not document['data']['requestSucceeded'] and not document['data']['verified']
        print('R3_OWNERSHIP_FIXTURE_PASS access denied status and RM session release')


if __name__ == '__main__':
    main()
