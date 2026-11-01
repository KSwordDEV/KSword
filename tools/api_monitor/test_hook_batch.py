"""Execute prepared patches, cancellation, shared entries and bulk restore in production."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = r'''
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <thread>
#include <atomic>
#include <cstdio>
static bool failRestore=false;
static unsigned failContext=0;
BOOL WINAPI TestContext(HANDLE thread,CONTEXT* context){
 if(failContext){--failContext;SetLastError(ERROR_INVALID_HANDLE);return FALSE;}
 return ::GetThreadContext(thread,context);
}
BOOL WINAPI TestProtect(void* address,SIZE_T size,DWORD protection,DWORD* old){
 if(failRestore&&protection!=PAGE_EXECUTE_READWRITE){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 return ::VirtualProtect(address,size,protection,old);
}
#define VirtualProtect TestProtect
#define GetThreadContext TestContext
#include "ENGINE"
#undef VirtualProtect
#undef GetThreadContext
using namespace apimon;
using Fn=int(*)();
int Detour(){return 77;}
static bool cancelled=false;
bool Stop(){return cancelled;}
static void* busyOriginal=nullptr;
static std::atomic_bool entered{false},releaseCall{false};
int Busy(){entered=true;while(!releaseCall)std::this_thread::yield();return reinterpret_cast<Fn>(busyOriginal)()+1;}
#define CHECK(x) do{if(!(x)){printf("FAIL %d %s\n",__LINE__,#x);return 1;}}while(0)
int main(){
 auto* memory=static_cast<unsigned char*>(VirtualAlloc(nullptr,65536,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));CHECK(memory);
 for(unsigned i=0;i<256;++i){auto* f=memory+i*64;memset(f,0x90,14);f[14]=0xb8;f[15]=42;memset(f+16,0,3);f[19]=0xc3;}
 std::vector<InlineHookRecord> records(128);std::vector<void*> originals(128);std::wstring error;
 {InlineHookInstallBatch batch;
  for(unsigned i=0;i<128;++i){CHECK(InstallInlineHookAtAddress(memory+i*64,(void*)&Detour,&records[i],&originals[i],&error)==InlineHookInstallResult::Installed);CHECK(reinterpret_cast<Fn>(memory+i*64)()==42);}
  CHECK(batch.commit());
 }
 for(unsigned i=0;i<128;++i){CHECK(reinterpret_cast<Fn>(memory+i*64)()==77);CHECK(reinterpret_cast<Fn>(originals[i])()==42);}
 CHECK(RestoreAllInlineHookEntries());
 for(unsigned i=0;i<128;++i){CHECK(UninstallInlineHook(&records[i]));CHECK(!records[i].installed);CHECK(reinterpret_cast<Fn>(memory+i*64)()==42);CHECK(reinterpret_cast<Fn>(originals[i])()==42);}
 InlineHookRecord first,alias;void* a=nullptr;void* b=nullptr;
 {InlineHookInstallBatch batch;CHECK(InstallInlineHookAtAddress(memory,(void*)&Detour,&first,&a,&error)==InlineHookInstallResult::Installed);CHECK(InstallInlineHookAtAddress(memory,(void*)&Detour,&alias,&b,&error)==InlineHookInstallResult::Installed);CHECK(a==b&&batch.commit());}
 CHECK(UninstallInlineHook(&first));CHECK(reinterpret_cast<Fn>(memory)()==77);CHECK(UninstallInlineHook(&alias));CHECK(reinterpret_cast<Fn>(memory)()==42);
 InlineHookRecord stopped;void* unused=nullptr;
 {ScopedHookInstallCancellation cancellation(&Stop);InlineHookInstallBatch batch;CHECK(InstallInlineHookAtAddress(memory,(void*)&Detour,&stopped,&unused,&error)==InlineHookInstallResult::Installed);cancelled=true;CHECK(!batch.commit());}
 CHECK(!stopped.installed&&!stopped.removed&&reinterpret_cast<Fn>(memory)()==42);cancelled=false;
 InlineHookRecord changed;void* retired=nullptr;
 {InlineHookInstallBatch batch;CHECK(InstallInlineHookAtAddress(memory,(void*)&Detour,&changed,&retired,&error)==InlineHookInstallResult::Installed);memory[0]=0xcc;CHECK(!batch.commit());}
 CHECK(!changed.installed&&memory[0]==0xcc);memory[0]=0x90;
 InlineHookRecord busy;
 CHECK(InstallInlineHookAtAddress(memory,(void*)&Busy,&busy,&busyOriginal,&error)==InlineHookInstallResult::Installed);
 int observed=0;std::thread caller([&]{observed=reinterpret_cast<Fn>(memory)();});while(!entered)std::this_thread::yield();
 const bool restored=RestoreAllInlineHookEntries();const bool removed=restored&&UninstallInlineHook(&busy);
 releaseCall=true;caller.join();CHECK(restored&&removed&&observed==43);CHECK(reinterpret_cast<Fn>(busyOriginal)()==42);
 DWORD old=0;CHECK(VirtualProtect(memory,65536,PAGE_EXECUTE_READ,&old));
 InlineHookRecord protectionFailure;void* protectionOriginal=nullptr;
 {InlineHookInstallBatch batch;CHECK(InstallInlineHookAtAddress(memory,(void*)&Detour,&protectionFailure,&protectionOriginal,&error)==InlineHookInstallResult::Installed);failRestore=true;CHECK(!batch.commit());}
 CHECK(protectionFailure.installed&&reinterpret_cast<Fn>(memory)()==77);
 CHECK(!RestoreAllInlineHookEntries()); // failed protection must remain pending
 failRestore=false;CHECK(RestoreAllInlineHookEntries());CHECK(UninstallInlineHook(&protectionFailure));
 MEMORY_BASIC_INFORMATION mbi{};CHECK(VirtualQuery(memory,&mbi,sizeof(mbi))&&mbi.Protect==PAGE_EXECUTE_READ);
 {InlineHookInstallBatch batch;CHECK(InstallInlineHookAtAddress(memory,(void*)&Detour,&protectionFailure,&protectionOriginal,&error)==InlineHookInstallResult::Installed);CHECK(batch.commit());}
 failRestore=true;CHECK(!RestoreAllInlineHookEntries());CHECK(reinterpret_cast<Fn>(memory)()==42);
 failRestore=false;CHECK(RestoreAllInlineHookEntries());CHECK(UninstallInlineHook(&protectionFailure));
 CHECK(VirtualQuery(memory,&mbi,sizeof(mbi))&&mbi.Protect==PAGE_EXECUTE_READ);
 std::atomic_bool running{true};std::thread transient([&]{while(running)std::this_thread::yield();});
 InlineHookRecord retried;void* retryOriginal=nullptr;bool committed=false;
 {InlineHookInstallBatch batch;const bool prepared=InstallInlineHookAtAddress(memory,(void*)&Detour,&retried,&retryOriginal,&error)==InlineHookInstallResult::Installed;failContext=1;committed=prepared&&batch.commit();}
 const bool didRetry=committed&&failContext==0&&retried.installed;
 const bool retryRemoved=RestoreAllInlineHookEntries()&&UninstallInlineHook(&retried);
 running=false;transient.join();CHECK(didRetry&&retryRemoved);
 puts("PASS: batch activation/restore, aliases, cancellation, entry changes, in-flight lifetime and failed protection retry");
}
'''
source = source.replace("ENGINE", (root / "APIMonitor_x64/hook/HookEngine.cpp").as_posix())
with tempfile.TemporaryDirectory(prefix="ksword_hook_batch_") as temporary:
    folder = Path(temporary)
    cpp = folder / "fixture.cpp"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["cl", "/nologo", "/EHsc", "/std:c++17", "/utf-8", "/I"+str(root/"APIMonitor_x64"),
                    str(cpp), "/Fe:"+str(folder/"fixture.exe"), "/Fo:"+str(folder/"fixture.obj")], check=True)
    subprocess.run([str(folder/"fixture.exe")], check=True, timeout=30)
