"""Validate interrupted enumeration and drive-buffer growth with SDK fixtures."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <Windows.h>
BOOL WINAPI FixtureNext(HANDLE,LPWIN32_FIND_DATAW);
DWORD WINAPI FixtureDrives(DWORD,LPWSTR);
#define FindNextFileW FixtureNext
#define GetLogicalDriveStringsW FixtureDrives
'''
SOURCE = r'''
#include "mock.h"
#undef FindNextFileW
#undef GetLogicalDriveStringsW
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
static std::wstring mode;
BOOL WINAPI FixtureNext(HANDLE h,LPWIN32_FIND_DATAW data) {
    if(mode==L"partial" && std::wstring(data->cFileName)!=L"." && std::wstring(data->cFileName)!=L"..") {
        SetLastError(ERROR_ACCESS_DENIED);return FALSE;
    }
    return FindNextFileW(h,data);
}
DWORD WINAPI FixtureDrives(DWORD size,LPWSTR text) {
    if(mode==L"drives" && size) {SetLastError(ERROR_SUCCESS);return size+1;}
    return GetLogicalDriveStringsW(size,text);
}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
    ks::cli::registerFileDirectory();return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-directory-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        (directory / 'fixture.cpp').write_text(SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix()))
        data = directory / 'data'
        data.mkdir()
        (data / 'example.txt').write_bytes(b'12345')
        binary = directory / 'fixture.exe'
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3FileDirectory.cpp',
                   'shared/usermode/backend/file/Directory.cpp', 'shared/usermode/backend/file/PathNavigator.cpp']
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / source) for source in sources], '/Fe:' + str(binary)], cwd=directory, check=True)
        def run(args, code):
            result = subprocess.run([str(binary), *args], capture_output=True, timeout=15)
            assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)['data']
        partial = run(['partial', 'file', 'directory', 'enum', '--path', str(data), '--json'], 6)
        assert not partial['complete'] and partial['win32Error'] == 5 and partial['totalCount'] == 1
        assert partial['entries'][0]['name'] == 'example.txt' and partial['entries'][0]['sizeBytes'] == '5'
        growth = run(['drives', 'file', 'directory', 'drives', 'enum', '--json'], 3)
        assert growth['win32Error'] == 234 and not growth['complete']
        print('R3_DIRECTORY_FIXTURE_PASS partial rows preserved, drive buffer growth cannot succeed')


if __name__ == '__main__':
    main()
