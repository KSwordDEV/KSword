"""Verify partial token evidence and failed restoration using production R3 code.

Only the fixture's own token is touched. Sources, binaries and logs are external.
"""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <Windows.h>
BOOL WINAPI FixtureGetTokenInformation(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID,DWORD,PDWORD);
BOOL WINAPI FixtureAdjustTokenPrivileges(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
#define GetTokenInformation FixtureGetTokenInformation
#define AdjustTokenPrivileges FixtureAdjustTokenPrivileges
'''
SOURCE = r'''
#include "mock.h"
#undef GetTokenInformation
#undef AdjustTokenPrivileges
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
static std::wstring mode;
static unsigned adjustments;
BOOL WINAPI FixtureGetTokenInformation(HANDLE t,TOKEN_INFORMATION_CLASS c,LPVOID b,DWORD n,PDWORD r) {
    if(mode==L"partial" && c==TokenElevation) {*r=0;SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return GetTokenInformation(t,c,b,n,r);
}
BOOL WINAPI FixtureAdjustTokenPrivileges(HANDLE t,BOOL all,PTOKEN_PRIVILEGES next,DWORD n,PTOKEN_PRIVILEGES old,PDWORD r) {
    if(mode==L"restore" && ++adjustments==2) {SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return AdjustTokenPrivileges(t,all,next,n,old,r);
}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    mode=argv[1];for(int i=1;i+1<argc;i++)argv[i]=argv[i+1];--argc;
    ks::cli::registerPrivilege([](std::vector<std::wstring> words) {
        words.insert(words.begin(),L"fixture.exe");std::vector<wchar_t*> args;
        for(auto& word:words)args.push_back(word.data());args.push_back(nullptr);
        int count=static_cast<int>(words.size());return ks::cli::dispatchR3(count,args.data()).value_or(1);
    });
    return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-privilege-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        (directory / 'fixture.cpp').write_text(SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix()))
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3Privilege.cpp'] + [
            'shared/usermode/backend/privilege/' + name + '.cpp'
            for name in ('PrivilegeEnumerator', 'PrivilegeActions', 'PrivilegeTypes')]
        binary = directory / 'fixture.exe'
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / source) for source in sources], '/Fe:' + str(binary), '/link', 'Advapi32.lib'],
                       cwd=directory, check=True)
        def run(args, code):
            result = subprocess.run([str(binary), *args], capture_output=True, timeout=15)
            assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)
        partial = run(['partial', 'privilege', 'query', '--json'], 6)
        assert partial['status'] == 'partial' and partial['data']['token']['elevated'] is None
        assert partial['data']['queryErrors'] == [{'informationClass': 20, 'win32Error': 5}]
        restore = run(['restore', 'privilege', 'run', '--disable', 'SeChangeNotifyPrivilege', '--json', '--',
                       'privilege', 'query', '--name', 'SeChangeNotifyPrivilege', '--json'], 6)['data']
        assert restore['executed'] and restore['exitCode'] == 0 and not restore['restored']
        assert restore['adjustments'][0]['verified'] and not restore['restorations'][0]['verified']
        assert restore['restorations'][0]['win32Error'] == 5
        assert not json.loads(restore['stdout'])['data']['privileges'][0]['enabled']
        print('R3_PRIVILEGE_FIXTURE_PASS unknown elevation, partial evidence, failed restoration')


if __name__ == '__main__':
    main()
