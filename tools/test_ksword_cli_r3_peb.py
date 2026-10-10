"""PEB short reads/empty strings, bounded environment and affinity evidence."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include "PEBHEADER"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <cstring>
static std::wstring mode;
namespace b=ks::r3::process_detail::peb;
static b::Peb64Lite peb;
static b::RtlUserProcessParameters64Lite parameters;
static wchar_t command[]=L"fixture args",image[]=L"C:\Fixture.exe",directory[]=L"C:\Fixture\\";
static wchar_t environment[]=L"A=1\0B=two\0\0";
static int environmentReads=0;
static LONG NTAPI nativeQuery(HANDLE,ULONG c,PVOID data,ULONG n,PULONG length) {
 if(mode==L"positive")return 258;
 if(c==0){b::ProcessBasicInformationLite value{};value.pebBaseAddress=&peb;value.uniqueProcessId=GetCurrentProcessId();
  assert(n==sizeof(value));std::memcpy(data,&value,sizeof(value));if(length)*length=mode==L"short-native"?8:sizeof(value);return 0;}
 if(c==26){assert(n==sizeof(ULONG_PTR));std::memset(data,0,n);if(length)*length=n;return 0;}
 return static_cast<LONG>(0xc0000003);
}
static FARPROC WINAPI resolve(HMODULE m,LPCSTR name){if(std::string(name)=="NtQueryInformationProcess")return reinterpret_cast<FARPROC>(nativeQuery);return GetProcAddress(m,name);}
static BOOL WINAPI memoryRead(HANDLE h,LPCVOID address,LPVOID out,SIZE_T n,SIZE_T* read) {
 if(mode==L"short-string" && address==command){std::memcpy(out,command,2);*read=2;return TRUE;}
 if(mode==L"header-denied" && address==&peb){*read=0;SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 if(mode==L"environment-unclosed" && n==b::kEnvironmentChunkBytes && reinterpret_cast<std::uintptr_t>(address)>=reinterpret_cast<std::uintptr_t>(environment) &&
  reinterpret_cast<std::uintptr_t>(address)-reinterpret_cast<std::uintptr_t>(environment)<b::kMaxEnvironmentBytes){
  ++environmentReads;auto* chars=static_cast<wchar_t*>(out);for(SIZE_T i=0;i<n/2;++i)chars[i]=L'x';*read=n;return TRUE;}
 return ReadProcessMemory(h,address,out,n,read);
}
static SIZE_T WINAPI regionQuery(HANDLE h,LPCVOID address,PMEMORY_BASIC_INFORMATION data,SIZE_T n) {
 if(mode==L"short-region"){std::memset(data,0,n);return 8;}
 return VirtualQueryEx(h,address,data,n);
}
static BOOL WINAPI setAffinity(HANDLE,DWORD_PTR){if(mode==L"affinity-denied"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return TRUE;}
#define GetProcAddress resolve
#define ReadProcessMemory memoryRead
#define VirtualQueryEx regionQuery
#define SetProcessAffinityMask setAffinity
#include "PEBCPP"
#undef SetProcessAffinityMask
#undef VirtualQueryEx
#undef ReadProcessMemory
#undef GetProcAddress
int wmain(int argc,wchar_t* argv[]) {
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 peb.processParameters=reinterpret_cast<std::uintptr_t>(&parameters);peb.imageBaseAddress=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
 parameters.commandLine={static_cast<USHORT>(sizeof(command)-2),static_cast<USHORT>(sizeof(command)),0,reinterpret_cast<std::uintptr_t>(command)};
 parameters.imagePathName={static_cast<USHORT>(sizeof(image)-2),static_cast<USHORT>(sizeof(image)),0,reinterpret_cast<std::uintptr_t>(image)};
 parameters.currentDirectory.dosPath={static_cast<USHORT>(sizeof(directory)-2),static_cast<USHORT>(sizeof(directory)),0,reinterpret_cast<std::uintptr_t>(directory)};
 parameters.environment=reinterpret_cast<std::uintptr_t>(environment);
 if(mode==L"empty"){parameters.commandLine.length=0;parameters.commandLine.buffer=0;}
 DWORD_PTR original=0,system=0;assert(GetProcessAffinityMask(GetCurrentProcess(),&original,&system));
 auto mask=original&(~original+1);if(mask==original)mask=(system&~original)&(~(system&~original)+1);if(!mask)mask=2;
 const auto pid=std::to_wstring(GetCurrentProcessId()),requested=std::to_wstring(mask),address=std::to_wstring(peb.imageBaseAddress);
 for(int i=1;i+1<argc;++i){if(std::wstring(argv[i])==L"--pid")argv[i+1]=const_cast<wchar_t*>(pid.c_str());
  if(std::wstring(argv[i])==L"--mask")argv[i+1]=const_cast<wchar_t*>(requested.c_str());
  if(std::wstring(argv[i])==L"--address")argv[i+1]=const_cast<wchar_t*>(address.c_str());}
 ks::cli::registerProcessPeb();const auto result=ks::cli::dispatchR3(argc,argv).value_or(1);
 if(mode==L"environment-unclosed")assert(environmentReads==32);
 return result;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-peb-') as temp:
        directory=Path(temp);source=SOURCE
        for key,path in {'PEBHEADER':'shared/usermode/backend/process/ProcessPeb.h','REGISTRY':'KswordCLI/CommandRegistry.h',
                         'PEBCPP':'shared/usermode/backend/process/ProcessPeb.cpp'}.items():source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        sources=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3ProcessPeb.cpp','shared/usermode/backend/process/ThreadActions.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(directory/'fixture.cpp'),*[str(ROOT/path) for path in sources],'/Fe:'+str(binary),'/link','Advapi32.lib','Psapi.lib'],cwd=directory,check=True)
        def run(mode,path,code,extra=()):
            result=subprocess.run([str(binary),mode,'process',*path,'--pid','self',*extra,'--json'],capture_output=True,timeout=15)
            assert result.returncode==code,(result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)['data']
        short=run('short-string',['peb','query'],6)
        assert short['headerKnown'] and short['parametersKnown'] and short['commandLine']['value'] is None
        assert short['commandLine']['evidence']['win32Error']==299
        empty=run('empty',['peb','query'],0)
        assert empty['commandLine']['value']=='' and empty['commandLine']['evidence']['available']
        denied=run('header-denied',['peb','query'],3)
        assert not denied['headerKnown'] and denied['beingDebugged'] is None and denied['readEvidence']['header']['win32Error']==5
        assert run('short-native',['peb','query'],4)['nativeQuery']['win32Error']==13
        assert run('positive',['peb','query'],3)['nativeQuery']['ntStatus']=='0x102'
        environment=run('environment-unclosed',['peb','environment','query'],6)
        assert not environment['complete'] and environment['budgetLimited'] and environment['bytesRead']=='131072'
        region=run('short-region',['memory','regions','query'],4,['--address','self'])
        assert region['region'] is None and region['win32Error']==13
        failed=run('affinity-denied',['settings','set-affinity'],3,['--mask','desired','--confirm'])
        assert not failed['requestSucceeded'] and failed['win32Error']==5 and not failed['verified']
        ignored=run('affinity-ignored',['settings','set-affinity'],6,['--mask','desired','--confirm'])
        assert ignored['requestSucceeded'] and not ignored['verified'] and ignored['after']['mask']!=ignored['requestedMask']
        print('R3_PEB_FIXTURE_PASS partial/empty strings, failed header, short/positive native query, exact environment budget, malformed region and affinity readback')


if __name__=='__main__':
    main()
