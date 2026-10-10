"""Thread SDK faults, stale identity and write/rollback result semantics."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "REGISTRY"
#include "ACTIONSHEADER"
#include <tlhelp32.h>
#include <fcntl.h>
#include <io.h>
#include <cassert>
static std::wstring mode;
static int writes=0;
static DWORD WINAPI fakeSuspend(HANDLE){++writes;if(mode==L"denied"){SetLastError(ERROR_ACCESS_DENIED);return DWORD(-1);}return 0;}
#define SuspendThread fakeSuspend
#define SetDetailThreadAffinity RealSetDetailThreadAffinity
#include "ACTIONSCPP"
#undef SetDetailThreadAffinity
#undef SuspendThread
namespace ks::r3::process_detail {
ProcessDetailActionResult SetDetailThreadAffinity(DWORD tid,ULONGLONG,DWORD,ULONGLONG,const ksword::thread_affinity_r3::Rule&) {
 ProcessDetailActionResult r;r.identityMatched=true;r.writeAttempted=true;r.writeSucceeded=true;r.rollbackAttempted=true;
 r.rollbackSucceeded=mode==L"rollback-ok";r.statusText=L"success / 已成功设置";
 if(mode==L"rollback-failed"){const auto h=OpenThread(THREAD_TERMINATE|SYNCHRONIZE,FALSE,tid);TerminateThread(h,1);WaitForSingleObject(h,2000);CloseHandle(h);}
 return r;
}
}
static LONG NTAPI fakeNtThread(HANDLE,LONG,PVOID,ULONG,PULONG){return 258;}
static FARPROC WINAPI fakeProc(HMODULE m,LPCSTR name) {
 if(mode==L"positive" && std::string(name)=="NtQueryInformationThread")return reinterpret_cast<FARPROC>(fakeNtThread);
 return GetProcAddress(m,name);
}
static bool ownSeen=false;
static BOOL WINAPI fakeNext(HANDLE h,LPTHREADENTRY32 e) {
 if(mode==L"partial" && ownSeen){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 const BOOL ok=Thread32Next(h,e);if(ok && e->th32OwnerProcessID==GetCurrentProcessId())ownSeen=true;return ok;
}
#define GetProcAddress fakeProc
#define Thread32Next fakeNext
#include "THREADSCPP"
#undef Thread32Next
#undef GetProcAddress
static DWORD WINAPI worker(void* event){WaitForSingleObject(static_cast<HANDLE>(event),INFINITE);return 0;}
int wmain(int argc,wchar_t* argv[]) {
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 const HANDLE event=CreateEventW(nullptr,TRUE,FALSE,nullptr);DWORD tid=0;const HANDLE thread=CreateThread(nullptr,0,worker,event,0,&tid);
 FILETIME c{},x{},k{},u{};assert(GetThreadTimes(thread,&c,&x,&k,&u));
 const auto self=std::to_wstring(GetCurrentProcessId()),id=std::to_wstring(tid);
 const auto birth=std::to_wstring((static_cast<ULONGLONG>(c.dwHighDateTime)<<32)|c.dwLowDateTime);
 const auto wrong=std::to_wstring(std::stoull(birth)+1);
 for(int i=1;i+1<argc;++i){const std::wstring arg=argv[i];if(arg==L"--pid")argv[i+1]=const_cast<wchar_t*>(self.c_str());
  if(arg==L"--tid")argv[i+1]=const_cast<wchar_t*>(id.c_str());if(arg==L"--thread-creation-time")argv[i+1]=const_cast<wchar_t*>((mode==L"mismatch"?wrong:birth).c_str());}
 ks::cli::registerProcessThreads();const auto result=ks::cli::dispatchR3(argc,argv).value_or(1);
 if(mode==L"mismatch")assert(writes==0);
 SetEvent(event);WaitForSingleObject(thread,2000);CloseHandle(thread);CloseHandle(event);return result;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-threads-') as temp:
        directory=Path(temp);source=SOURCE
        for key,path in {'REGISTRY':'KswordCLI/CommandRegistry.h','THREADSUPPORT':'shared/usermode/backend/process/ProcessThreadsSupport.h',
                         'ACTIONSHEADER':'shared/usermode/backend/process/ThreadActions.h','ACTIONSCPP':'shared/usermode/backend/process/ThreadActions.cpp',
                         'THREADSCPP':'shared/usermode/backend/process/ProcessThreads.cpp'}.items():
            source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8')
        binary=directory/'fixture.exe'
        sources=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3ProcessThreads.cpp','shared/usermode/backend/process/ProcessBasicInfo.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(directory/'fixture.cpp'),*[str(ROOT/path) for path in sources],'/Fe:'+str(binary),'/link','Advapi32.lib','Psapi.lib'],cwd=directory,check=True)
        def run(mode,verb,code,extra=()):
            arguments=[str(binary),mode,'process','thread',verb,'--pid','self']
            if verb!='enum':arguments+=['--tid','self','--thread-creation-time','self','--confirm']
            result=subprocess.run(arguments+list(extra)+['--json'],capture_output=True,timeout=15)
            assert result.returncode==code,(result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)
        failed=run('denied','suspend',3)['data']
        assert not failed['requestSucceeded'] and failed['win32Error']==5 and not failed['verified']
        partial=run('unchanged','suspend',6)['data']
        assert partial['requestSucceeded'] and not partial['verified'] and partial['observed']['after']['count']==0
        assert not run('mismatch','suspend',3)['data']['target']['identityMatched']
        positive=run('positive','enum',6)['data']
        for row in positive['threads']:
            assert row['startAddress'] is None and row['suspendCount'] is None
            assert row['startEvidence']['ntStatus']=='0x102' and not row['startEvidence']['available']
        partial=run('partial','enum',6)['data']
        assert not partial['complete'] and partial['win32Error']==5 and partial['returnedCount']>0
        for mode,code in [('rollback-failed',6),('rollback-ok',3)]:
            data=run(mode,'set-affinity',code,['--processors','0:0'])['data']
            assert not data['requestSucceeded'] and not data['verified'] and data['writeSucceeded'] and data['rollbackAttempted']
            assert data['rollbackSucceeded']==(mode=='rollback-ok')
            assert data['rollbackVerified']==(mode=='rollback-ok')
        print('R3_THREADS_FIXTURE_PASS SDK failure, unconfirmed success, identity no-op, positive NT status, partial enumeration and rollback results')


if __name__=='__main__':
    main()
