"""Real signaled thread handles are skipped; live access failures remain fail-closed."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = r'''
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <atomic>
#include <cstring>
#include <cstdio>
static HANDLE dead=nullptr,live=nullptr;
static DWORD deadId=0;
static bool race=false,denyLive=false;
static unsigned deadWaits=0,deadSuspends=0,deadContexts=0;
static std::atomic_bool running{true};
DWORD WINAPI Done(void*){return 0;}
DWORD WINAPI Alive(void*){while(running)Sleep(1);return 0;}
LONG NTAPI TestNext(HANDLE,HANDLE cursor,ACCESS_MASK,ULONG,ULONG,HANDLE* output){
 HANDLE source=nullptr;
 if(!cursor)source=dead;
 else if(GetThreadId(cursor)==deadId)source=live;
 else return static_cast<LONG>(0x8000001a);
 return DuplicateHandle(GetCurrentProcess(),source,GetCurrentProcess(),output,0,FALSE,DUPLICATE_SAME_ACCESS)?0:static_cast<LONG>(0xc0000022);
}
FARPROC WINAPI TestProc(HMODULE module,LPCSTR name){if(strcmp(name,"NtGetNextThread")==0)return reinterpret_cast<FARPROC>(&TestNext);return ::GetProcAddress(module,name);}
DWORD WINAPI TestWait(HANDLE thread,DWORD timeout){if(GetThreadId(thread)==deadId&&race&&deadWaits++==0)return WAIT_TIMEOUT;return ::WaitForSingleObject(thread,timeout);}
DWORD WINAPI TestSuspend(HANDLE thread){
 if(GetThreadId(thread)==deadId)++deadSuspends;
 if(denyLive&&GetThreadId(thread)!=deadId){SetLastError(ERROR_ACCESS_DENIED);return static_cast<DWORD>(-1);}
 return ::SuspendThread(thread);
}
BOOL WINAPI TestContext(HANDLE thread,CONTEXT* context){if(GetThreadId(thread)==deadId)++deadContexts;return ::GetThreadContext(thread,context);}
#define GetProcAddress TestProc
#define WaitForSingleObject TestWait
#define SuspendThread TestSuspend
#define GetThreadContext TestContext
#include "ENGINE"
#undef GetProcAddress
#undef WaitForSingleObject
#undef SuspendThread
#undef GetThreadContext
#define CHECK(x) do{if(!(x)){printf("FAIL %d %s\n",__LINE__,#x);return 1;}}while(0)
int main(){
 dead=CreateThread(nullptr,0,Done,nullptr,0,&deadId);CHECK(dead&&WaitForSingleObject(dead,5000)==WAIT_OBJECT_0);
 live=CreateThread(nullptr,0,Alive,nullptr,0,nullptr);CHECK(live);
 bool first=false,second=false,denied=false;
 {apimon::detail::ThreadPatchGuard guard;first=guard.CaptureContexts()&&guard.AllowsPatch(reinterpret_cast<void*>(65536),16);}
 const auto previous=SuspendThread(live);if(previous!=static_cast<DWORD>(-1))ResumeThread(live);
 race=true;
 {apimon::detail::ThreadPatchGuard guard;second=guard.CaptureContexts();}
 denyLive=true;
 {apimon::detail::ThreadPatchGuard guard;denied=!guard.CaptureContexts()&&!guard.FailureText().empty();}
 running=false;WaitForSingleObject(live,5000);CloseHandle(live);CloseHandle(dead);
 CHECK(first&&second&&denied&&previous==0&&deadSuspends==1&&deadContexts==0);
 puts("PASS: terminated handles and exit/suspend race skipped; live thread failure rejected; suspended threads resumed");
}
'''.replace("ENGINE", (root / "APIMonitor_x64/hook/HookEngine.cpp").as_posix())
with tempfile.TemporaryDirectory(prefix="ksword_dead_threads_") as temporary:
    folder = Path(temporary)
    cpp = folder / "fixture.cpp"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["cl", "/nologo", "/EHsc", "/std:c++17", "/utf-8", "/I" + str(root / "APIMonitor_x64"),
                    str(cpp), "/Fe:" + str(folder / "fixture.exe"), "/Fo:" + str(folder / "fixture.obj")], check=True)
    subprocess.run([str(folder / "fixture.exe")], check=True, timeout=15)
