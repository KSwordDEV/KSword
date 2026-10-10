"""Verify snapshot short reads and read failures cannot become successful fallback."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <Windows.h>
BOOL WINAPI FixtureRead(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
#define ReadFile FixtureRead
'''
SOURCE = r'''
#include "mock.h"
#undef ReadFile
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
static std::wstring mode;
static unsigned reads;
BOOL WINAPI FixtureRead(HANDLE file,LPVOID data,DWORD size,LPDWORD read,LPOVERLAPPED async) {
    if(++reads>1) {*read=0;if(mode==L"error"){SetLastError(ERROR_CRC);return FALSE;}return TRUE;}
    return ReadFile(file,data,size>4?4:size,read,async);
}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
    ks::cli::registerFilePe();return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-pe-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        (directory / 'fixture.cpp').write_text(SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix()))
        data = directory / 'example.bin'
        data.write_bytes(bytes(range(64)))
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3FilePe.cpp',
                   'shared/usermode/backend/file/PeSnapshot.cpp', 'shared/usermode/backend/file/FileAnalysis.cpp',
                   'shared/usermode/backend/file/PathNavigator.cpp', 'Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.cpp',
                   'Ksword5.1/Ksword5.1/ksword/string/string.cpp']
        binary = directory / 'fixture.exe'
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / source) for source in sources], '/Fe:' + str(binary), '/link', 'Advapi32.lib'], cwd=directory, check=True)
        for mode, error in [('eof', 38), ('error', 23)]:
            result = subprocess.run([str(binary), mode, 'file', 'pe', 'query', '--path', str(data), '--json'], capture_output=True, timeout=15)
            assert result.returncode == 3, (result.returncode, result.stdout, result.stderr)
            document = json.loads(result.stdout)
            assert document['status'] == 'failed' and document['data']['win32Error'] == error
            assert document['data']['bytesRead'] == '4' and document['data']['snapshotSize'] == '64'
            assert not document['data']['deepAvailable'] and not document['data']['header']['available']
        print('R3_PE_FIXTURE_PASS early EOF and failed read retain errors and reject false fallback success')


if __name__ == '__main__':
    main()
