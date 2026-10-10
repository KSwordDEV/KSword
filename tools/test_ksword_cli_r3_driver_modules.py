"""Native module snapshot layout, redaction, growth, trust state and source routing."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include "HEADER"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <cstring>
namespace b=ks::r3::driver;
static std::wstring mode;
static int psapiCalls=0,ntCalls=0,trustCalls=0,trustCloses=0;
namespace ks::r3::common {
NtApi::NtApi():querySystemInformation_(nullptr){}
bool NtApi::available()const{return mode!=L"missing";}
LONG NtApi::querySystemInformation(SystemInformationClass,void* buffer,ULONG size,ULONG* returned)const{
 ++ntCalls;if(mode==L"positive")return 258;if(mode==L"denied")return static_cast<LONG>(0xC0000022);
 if(mode==L"budget"){*returned=0xffffffff;return static_cast<LONG>(0xC0000004);}
 auto* m=static_cast<b::KRTL_PROCESS_MODULES*>(buffer);m->NumberOfModules=mode==L"empty"?0:1;
 *returned=static_cast<ULONG>(offsetof(b::KRTL_PROCESS_MODULES,Modules)+m->NumberOfModules*sizeof(b::KRTL_PROCESS_MODULE_INFORMATION));
 if(mode==L"bad-count"){m->NumberOfModules=0xffffffff;return 0;}
 if(mode==L"bad-length"){*returned=size+1;return 0;}
 if(m->NumberOfModules){auto& r=m->Modules[0];r.ImageBase=reinterpret_cast<PVOID>(mode==L"redacted"?0:mode==L"overflow"?0xfffffffffffffff0:0xffff800012340000);
 r.ImageSize=4096;const char* path="C:\\FixtureDriver.sys";memcpy(r.FullPathName,path,strlen(path)+1);}
 return 0;
}
}
static BOOL WINAPI enumeration(LPVOID* values,DWORD size,LPDWORD needed){
 ++psapiCalls;*needed=(mode==L"grow"?4096:mode==L"ps-empty"?0:1)*sizeof(LPVOID);
 if(mode==L"ps-denied"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 if(mode==L"ps-malformed"){*needed=3;return TRUE;}
 if(size>=*needed)for(DWORD i=0;i<*needed/sizeof(LPVOID);++i)values[i]=mode==L"ps-redacted"?nullptr:reinterpret_cast<PVOID>(0xffff800012340000ull+i*0x10000ull);
 return TRUE;
}
static DWORD WINAPI name(LPVOID base,LPWSTR dest,DWORD size){assert(base);return wcscpy_s(dest,size,L"FixtureDriver.sys")==0?17:0;}
static DWORD WINAPI path(LPVOID base,LPWSTR dest,DWORD size){assert(base);if(mode==L"path-denied"){SetLastError(ERROR_ACCESS_DENIED);return 0;}return wcscpy_s(dest,size,L"C:\\FixtureDriver.sys")==0?20:0;}
static DWORD WINAPI attributes(LPCWSTR){if(mode==L"file-denied"){SetLastError(ERROR_ACCESS_DENIED);return INVALID_FILE_ATTRIBUTES;}return FILE_ATTRIBUTE_NORMAL;}
static LONG WINAPI verify(HWND,GUID*,LPVOID value){auto* data=static_cast<WINTRUST_DATA*>(value);if(data->dwStateAction==WTD_STATEACTION_CLOSE){++trustCloses;return 0;}++trustCalls;return mode==L"signature-unavailable"?TRUST_E_PROVIDER_UNKNOWN:mode==L"unsigned"?TRUST_E_NOSIGNATURE:0;}
#define K32EnumDeviceDrivers enumeration
#define K32GetDeviceDriverBaseNameW name
#define K32GetDeviceDriverFileNameW path
#define GetFileAttributesW attributes
#define WinVerifyTrust verify
#include "CPP"
#undef WinVerifyTrust
#undef GetFileAttributesW
#undef K32GetDeviceDriverFileNameW
#undef K32GetDeviceDriverBaseNameW
#undef K32EnumDeviceDrivers
int wmain(int argc,wchar_t* argv[]){
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 ks::cli::registerDriverModules();const auto rc=ks::cli::dispatchR3(argc,argv).value_or(1);
 assert(trustCalls==trustCloses);if(mode==L"grow")assert(psapiCalls==2);if(mode==L"positive")assert(psapiCalls==0);
 if(mode==L"denied")assert(ntCalls==1&&psapiCalls==1);if(mode==L"bad-count")assert(psapiCalls==0);
 return rc;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-driver-') as temp:
        directory=Path(temp);source=SOURCE
        for key,path in {'HEADER':'shared/usermode/backend/driver/DriverQueries.h','REGISTRY':'KswordCLI/CommandRegistry.h',
                         'CPP':'shared/usermode/backend/driver/DriverQueries.cpp'}.items():source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(directory/'fixture.cpp'),*[str(ROOT/path) for path in ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3DriverModules.cpp','shared/usermode/backend/driver/DriverFormatting.cpp']],
                        '/Fe:'+str(binary),'/link','Advapi32.lib','Psapi.lib','Wintrust.lib'],cwd=directory,check=True)
        def run(mode,code,source='nt',detail=False,signature='off',limit='10000'):
            args=[str(binary),mode,'driver','modules','query' if detail else 'enum','--source',source,'--signature',signature,'--limit',limit,'--json']
            if detail:args+=['--name','FixtureDriver.sys']
            result=subprocess.run(args,capture_output=True,timeout=15)
            assert result.returncode==code,(mode,result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)['data']
        assert run('valid',0)['modules'][0]['imageSize']=='4096'
        assert run('empty',0)['enumeratedCount']=='0'
        assert run('redacted',6)['modules'][0]['baseAddress'] is None
        assert run('bad-count',4,source='auto')['sources'][0]['malformed']
        assert run('bad-length',4)['sources'][0]['malformed']
        assert run('overflow',4)['modules'][0]['endAddressExclusive'] is None
        assert run('positive',3)['sources'][0]['ntStatus']=='0x102'
        assert run('budget',3)['sources'][0]['win32Error']==234
        assert run('missing',5)['sources'][0]['unsupported']
        fallback=run('denied',6,source='auto');assert len(fallback['sources'])==2 and fallback['selectedSource']=='psapi'
        assert run('grow',6,source='psapi')['enumeratedCount']=='4096'
        assert run('ps-empty',0,source='psapi')['enumeratedCount']=='0'
        assert run('ps-redacted',5,source='psapi')['modules'][0]['name'] is None
        assert run('ps-redacted',5,source='psapi',detail=True)['matchedCount']=='0'
        assert run('ps-malformed',4,source='psapi')['sources'][0]['malformed']
        assert run('ps-denied',3,source='psapi')['sources'][0]['win32Error']==5
        assert run('path-denied',6,source='psapi')['modules'][0]['pathWin32Error']==5
        assert run('valid',0,detail=True,signature='on')['modules'][0]['signature']['available']
        unsigned=run('unsigned',0,detail=True,signature='on')['modules'][0]['signature'];assert unsigned['status']=='no-embedded-signature' and not unsigned['catalogVerification']
        unavailable=run('signature-unavailable',6,detail=True,signature='on')['modules'][0]['signature']
        assert unavailable['trustStatus']=='0x800b0001',unavailable
        assert run('file-denied',6,detail=True,signature='on')['modules'][0]['signature']['fileWin32Error']==5
        print('R3_DRIVER_FIXTURE_PASS layout/growth/redaction/empty/native status/fallback/trust ownership')

if __name__=='__main__':main()
