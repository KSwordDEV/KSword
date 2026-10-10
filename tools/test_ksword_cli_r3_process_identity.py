"""All four production identity adapters: time guards, real name vs fallback and handle lifetime."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
HANDLE WINAPI FixtureOpen(DWORD,BOOL,DWORD);BOOL WINAPI FixtureTimes(HANDLE,LPFILETIME,LPFILETIME,LPFILETIME,LPFILETIME);DWORD WINAPI FixtureWait(HANDLE,DWORD);BOOL WINAPI FixtureClose(HANDLE);BOOL WINAPI FixtureImage(HANDLE,DWORD,LPWSTR,PDWORD);
#define OpenProcess FixtureOpen
#define GetProcessTimes FixtureTimes
#define WaitForSingleObject FixtureWait
#define CloseHandle FixtureClose
#define QueryFullProcessImageNameW FixtureImage
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include "IDENTITY"
#include <cassert>
#include <set>
#include <fcntl.h>
#include <io.h>
static std::wstring mode;static std::set<HANDLE> live;static std::uintptr_t serial=0;static int waits=0,queries=0;
static HANDLE h(std::uintptr_t value){return reinterpret_cast<HANDLE>(value);}
namespace ks::r3::process_detail::detail {std::wstring Win32ErrorText(const wchar_t*,DWORD){return L"success / identity stable";}}
HANDLE WINAPI FixtureOpen(DWORD access,BOOL inherit,DWORD pid){assert(pid==77&&!inherit&&(access==PROCESS_QUERY_LIMITED_INFORMATION||access==(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE)));++serial;
 if(mode==L"open-denied"||mode==L"name-open-denied"&&serial>=4){SetLastError(5);return nullptr;}auto handle=h(serial);assert(live.insert(handle).second);return handle;}
BOOL WINAPI FixtureTimes(HANDLE handle,LPFILETIME created,LPFILETIME exited,LPFILETIME kernel,LPFILETIME user){assert(live.count(handle));*exited=*kernel=*user={};if(mode==L"time-denied"||mode==L"navigation-time-denied"&&handle==h(3)){SetLastError(5);return FALSE;}
 const auto value=mode==L"zero-time"?0ULL:134000000000000000ULL+(mode==L"detail-reused"&&handle==h(2)||mode==L"image-reused"&&reinterpret_cast<std::uintptr_t>(handle)>=4?1:0);created->dwLowDateTime=static_cast<DWORD>(value);created->dwHighDateTime=static_cast<DWORD>(value>>32);return TRUE;}
DWORD WINAPI FixtureWait(HANDLE handle,DWORD duration){assert(live.count(handle)&&duration==0);++waits;if(mode==L"wait-denied"){SetLastError(5);return WAIT_FAILED;}return mode==L"exited"||mode==L"exit-after"&&waits>=4?WAIT_OBJECT_0:WAIT_TIMEOUT;}
BOOL WINAPI FixtureClose(HANDLE handle){assert(live.erase(handle)==1);if(mode==L"close-denied"&&handle==h(3)){SetLastError(5);return FALSE;}return TRUE;}
BOOL WINAPI FixtureImage(HANDLE handle,DWORD flags,LPWSTR buffer,PDWORD length){assert(live.count(handle)&&flags==0);++queries;if(mode==L"image-denied"){SetLastError(5);return FALSE;}
 const std::wstring path=mode==L"long-name"?L"C:\\"+std::wstring(1100,L'x')+L".exe":mode==L"different-paths"&&handle==h(5)?L"C:\\Changed.exe":L"C:\\Fixture\u6d4b.exe";
 if(path.size()>=*length){SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE;}memcpy(buffer,path.data(),path.size()*2);*length=mode==L"bad-length"?40000:mode==L"zero-name"?0:static_cast<DWORD>(path.size());return TRUE;}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;ks::cli::registerProcessIdentity();const auto code=ks::cli::dispatchR3(argc,argv).value_or(1);assert(live.empty());if(mode==L"exited"||mode==L"detail-reused"||mode==L"navigation-time-denied")assert(queries==0);return code;}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-process-identity-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8');source=SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('IDENTITY',(ROOT/'shared/usermode/backend/process/ProcessDetailIdentity.h').as_posix());(directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3ProcessIdentity.cpp','shared/usermode/backend/process/ProcessNavigationIdentity.cpp','shared/usermode/backend/process/ProcessDetailIdentity.cpp','shared/usermode/backend/process/ProcessEvidenceName.cpp','shared/usermode/backend/process/EventProcessImagePath.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'process','identity','query','--pid','77','--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['identityVerified'] and valid['target']['creationTime']=='134000000000000000' and valid['name']=='Fixture\u6d4b.exe' and valid['imagePath']==r'C:\Fixture\u6d4b.exe'.replace('\\u6d4b','\u6d4b')
        for mode in ('open-denied','time-denied','zero-time','wait-denied','exited','detail-reused','navigation-time-denied','image-reused','exit-after'):run(mode,3)
        assert not run('valid',3,('--creation-time','134000000000000001'))['target']['identityMatched']
        for mode in ('image-denied','name-open-denied','long-name','different-paths','close-denied'):run(mode,6)
        denied=run('image-denied',6);assert denied['name'] is None and denied['nameDisplayFallback']=='PID 77' and denied['imagePath'] is None
        for mode in ('bad-length','zero-name'):run(mode,4)
        print('R3_PROCESS_IDENTITY_FIXTURE_PASS all four samplers, retained handle/time/liveness guards, no names after identity failure, real Unicode vs PID fallback, image limits/consistency and owned closures independent of UI text')
if __name__=='__main__':main()
