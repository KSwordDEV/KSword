"""Module list growth/metadata faults and remote-operation result semantics."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include "REGISTRY"
#include "ACTIONSHEADER"
#include <psapi.h>
#include <tlhelp32.h>
#include <fcntl.h>
#include <io.h>
#include <algorithm>
#include <sstream>
static std::wstring mode;
static BOOL WINAPI fakeEnum(HANDLE h,HMODULE* modules,DWORD capacity,LPDWORD needed,DWORD flags) {
 if(mode==L"malformed"){*needed=1;return TRUE;}
 if(mode==L"denied"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 if(mode==L"growth"){
  for(DWORD i=0;i<capacity/sizeof(HMODULE);++i)modules[i]=GetModuleHandleW(nullptr);
  *needed=capacity+sizeof(HMODULE);return TRUE;
 }
 return EnumProcessModulesEx(h,modules,capacity,needed,flags);
}
static BOOL WINAPI fakeInfo(HANDLE h,HMODULE m,LPMODULEINFO info,DWORD n) {
 if(mode==L"info-denied"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 return GetModuleInformation(h,m,info,n);
}
static DWORD WINAPI fakePath(HANDLE h,HMODULE m,LPWSTR path,DWORD n) {
 if(mode==L"path-denied"){SetLastError(ERROR_ACCESS_DENIED);return 0;}
 if(mode==L"path-truncated"){std::fill(path,path+n,L'a');return n;}
 return GetModuleFileNameExW(h,m,path,n);
}
static FARPROC WINAPI fakeProc(HMODULE module,LPCSTR name) {
 const std::string text=name;
 if(text=="K32EnumProcessModulesEx" || text=="EnumProcessModulesEx")return reinterpret_cast<FARPROC>(fakeEnum);
 if(text=="K32GetModuleInformation" || text=="GetModuleInformation")return reinterpret_cast<FARPROC>(fakeInfo);
 if(text=="K32GetModuleFileNameExW" || text=="GetModuleFileNameExW")return reinterpret_cast<FARPROC>(fakePath);
 return GetProcAddress(module,name);
}
#define GetProcAddress fakeProc
#include "MODULESCPP"
#undef GetProcAddress
static DWORD WINAPI remoteResult(void*){return mode==L"free-zero"?0:1;}
static HANDLE WINAPI fakeRemote(HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD) {
 if(mode==L"remote-denied"){SetLastError(ERROR_ACCESS_DENIED);return nullptr;}
 return CreateThread(nullptr,0,remoteResult,nullptr,0,nullptr);
}
static DWORD WINAPI fakeWait(HANDLE h,DWORD milliseconds) {return mode==L"timeout"?WAIT_TIMEOUT:WaitForSingleObject(h,milliseconds);}
#define CreateRemoteThread fakeRemote
#define WaitForSingleObject fakeWait
#include "ACTIONSCPP"
#undef WaitForSingleObject
#undef CreateRemoteThread
int wmain(int argc,wchar_t* argv[]) {
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 const auto pid=std::to_wstring(GetCurrentProcessId()),base=std::to_wstring(reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)));
 for(int i=1;i+1<argc;++i){if(std::wstring(argv[i])==L"--pid")argv[i+1]=const_cast<wchar_t*>(pid.c_str());
  if(std::wstring(argv[i])==L"--base")argv[i+1]=const_cast<wchar_t*>(base.c_str());}
 ks::cli::registerProcessModules();return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-modules-') as temp:
        directory=Path(temp);source=SOURCE
        for key,path in {'REGISTRY':'KswordCLI/CommandRegistry.h','ACTIONSHEADER':'shared/usermode/backend/process/ModuleActions.h',
                         'MODULESCPP':'shared/usermode/backend/process/ProcessModules.cpp','ACTIONSCPP':'shared/usermode/backend/process/ModuleActions.cpp'}.items():
            source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        sources=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3ProcessModules.cpp','KswordCLI/R3ProcessThreads.cpp',
                 'shared/usermode/backend/process/ProcessBasicInfo.cpp','shared/usermode/backend/process/ProcessThreads.cpp',
                 'shared/usermode/backend/process/ThreadActions.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(directory/'fixture.cpp'),*[str(ROOT/path) for path in sources],'/Fe:'+str(binary),'/link','Advapi32.lib','Psapi.lib'],cwd=directory,check=True)
        def run(mode,verb,code):
            args=[str(binary),mode,'process','module',verb,'--pid','self']
            if verb=='unload':args+=['--base','self','--confirm']
            result=subprocess.run(args+['--json'],capture_output=True,timeout=15)
            assert result.returncode==code,(result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)['data']
        malformed=run('malformed','enum',4)
        assert malformed['enumeration']['malformed'] and malformed['enumeration']['win32Error']==13
        assert run('denied','enum',3)['enumeration']['win32Error']==5
        growth=run('growth','enum',6)
        assert not growth['enumeration']['complete'] and growth['enumeration']['win32Error']==234 and growth['returnedCount']==259
        assert all(row['base'] for row in growth['modules'])
        for mode in ('info-denied','path-denied','path-truncated'):
            rows=run(mode,'enum',6)['modules']
            assert rows
            for row in rows:
                if mode=='info-denied':assert row['base'] is None and row['imageSize'] is None and row['infoEvidence']['win32Error']==5
                else:assert row['path'] is None and row['name'] is None and row['pathEvidence']['win32Error']==(5 if mode=='path-denied' else 234)
        failed=run('remote-denied','unload',3)
        assert not failed['remoteThreadCreated'] and not failed['requestSucceeded'] and failed['win32Error']==5
        zero=run('free-zero','unload',3)
        assert zero['remoteThreadCreated'] and zero['freeLibraryResult']==0 and not zero['requestSucceeded']
        timeout=run('timeout','unload',6)
        assert timeout['remoteThreadCreated'] and timeout['waitResult']==258 and timeout['freeLibraryResult'] is None and not timeout['verified']
        remaining=run('remaining','unload',6)
        assert remaining['requestSucceeded'] and remaining['freeLibraryResult']==1 and remaining['observed']['basePresent'] and not remaining['verified']
        print('R3_MODULES_FIXTURE_PASS changing counts, malformed size, denied/truncated metadata, remote failure/timeout and remaining module')


if __name__=='__main__':
    main()
