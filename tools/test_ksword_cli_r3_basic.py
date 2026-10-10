"""Exercise real basic queries with failed SDK reads and valid empty/false fields."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "REGISTRY"
#include "SUPPORT"
#include <fcntl.h>
#include <io.h>
#include <cassert>
static std::wstring mode;
static BOOL WINAPI memoryInfo(HANDLE h, PPROCESS_MEMORY_COUNTERS c, DWORD n) {
    if (mode == L"memory-denied") {SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return GetProcessMemoryInfo(h,c,n);
}
static BOOL WINAPI tokenInfo(HANDLE h,TOKEN_INFORMATION_CLASS c,LPVOID p,DWORD n,PDWORD returned) {
    if (mode == L"token-denied") {SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return GetTokenInformation(h,c,p,n,returned);
}
#undef GetProcessMemoryInfo
#define GetProcessMemoryInfo memoryInfo
#define GetTokenInformation tokenInfo
#define CollectBasicInfo RealCollectBasicInfo
#include "BASICCPP"
#undef CollectBasicInfo
#undef GetTokenInformation
#undef GetProcessMemoryInfo
namespace ks::r3::process_detail {
ProcessBasicInfo CollectBasicInfo(DWORD pid,bool& opened) {
    auto info = RealCollectBasicInfo(pid,opened);
    if (mode == L"open-denied") {opened=false;info.evidence[L"open"]={false,true,false,ERROR_ACCESS_DENIED};}
    if (mode == L"empty-false") {
        info.commandLine=L"<empty command line>";
        info.evidence[L"command-line"].available=true;
        info.evidence[L"command-line"].emptyValue=true;
        info.isAdmin=false;info.evidence[L"elevation"].available=true;
    }
    if (mode == L"short-native") {
        info.evidence[L"native-basic"]={false,false,true,0,0};
        info.pebAddressKnown=false;
    }
    return info;
}
}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
    using namespace ks::r3::process_detail;
    ProcessQueryEvidence evidence;
    UNICODE_STRING remote{};
    assert(detail::ReadRemoteUnicodeString(GetCurrentProcess(),remote,&evidence).empty());
    assert(evidence.available && evidence.emptyValue);
    remote.Length=3;remote.Buffer=reinterpret_cast<PWSTR>(1);
    (void)detail::ReadRemoteUnicodeString(GetCurrentProcess(),remote,&evidence);
    assert(!evidence.available && evidence.win32Error==ERROR_INVALID_DATA);
    remote.Length=4;
    (void)detail::ReadRemoteUnicodeString(GetCurrentProcess(),remote,&evidence);
    assert(!evidence.available && evidence.win32ErrorKnown);
    const auto self=std::to_wstring(GetCurrentProcessId());
    for(int i=1;i+1<argc;++i)if(std::wstring(argv[i])==L"--pid")argv[i+1]=const_cast<wchar_t*>(self.c_str());
    ks::cli::registerProcessBasic();return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-basic-') as temp:
        directory = Path(temp)
        source = SOURCE
        for key, path in {'REGISTRY':'KswordCLI/CommandRegistry.h',
                          'SUPPORT':'shared/usermode/backend/process/ProcessBasicInfoSupport.h',
                          'BASICCPP':'shared/usermode/backend/process/ProcessBasicInfo.cpp'}.items():
            source = source.replace(key, (ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source)
        sources = ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3ProcessBasic.cpp','shared/usermode/backend/Common.cpp']
        binary = directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(directory/'fixture.cpp'),*[str(ROOT/path) for path in sources],'/Fe:'+str(binary),
                        '/link','Advapi32.lib','Psapi.lib'],cwd=directory,check=True)
        def run(mode):
            result = subprocess.run([str(binary),mode,'process','detail','basic','query','--pid','self','--json'],capture_output=True,timeout=15)
            assert result.returncode in (0,3,6), (result.returncode,result.stdout,result.stderr)
            data=json.loads(result.stdout)['data']
            if mode=='open-denied':
                assert result.returncode==3 and data['win32Error']==5
                return result.returncode, {}
            return result.returncode, {row['name']:row for row in data['fields']}
        run('open-denied')
        code, fields=run('memory-denied')
        assert code==6
        for name in ('working-set','private-bytes'):
            assert fields[name]['value'] is None and fields[name]['win32Error']==5
        code, fields=run('token-denied')
        assert code==6
        for name in ('user','integrity','elevated'):
            assert fields[name]['value'] is None and fields[name]['win32Error']==5
        _,fields=run('empty-false')
        assert fields['command-line']['available'] and fields['command-line']['value']==''
        assert fields['elevated']['available'] and fields['elevated']['value'] is False
        code,fields=run('short-native')
        assert code==6 and fields['peb']['value'] is None and fields['peb']['ntStatus']=='0x0'
        print('R3_BASIC_FIXTURE_PASS denied SDK queries are null, valid empty/false values remain available, short native evidence is unavailable')


if __name__ == '__main__':
    main()
