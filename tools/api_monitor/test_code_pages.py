"""Real x86 code pages retain large free ranges and independently sealed siblings."""
from pathlib import Path
import shutil
import subprocess
import tempfile
from compiler_environment import target_environment

root = Path(__file__).resolve().parents[2]
source = r'''
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdio>
#include <atomic>
#include <thread>
#include <vector>
static unsigned reserves=0;
static bool rejectCommit=false;
LPVOID WINAPI CountedAlloc(LPVOID address,SIZE_T size,DWORD type,DWORD protection){
 if(type&MEM_RESERVE)++reserves;
 if(rejectCommit&&type==MEM_COMMIT){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return nullptr;}
 return ::VirtualAlloc(address,size,type,protection);
}
#define VirtualAlloc CountedAlloc
#include "ALLOCATOR"
#undef VirtualAlloc
using namespace apimon::detail;
#define CHECK(x) do{if(!(x)){printf("FAIL %d %s\n",__LINE__,#x);return 1;}}while(0)
int main(){
 static_assert(sizeof(void*)==4);
 std::vector<unsigned char*> pages;pages.reserve(8192);
 for(unsigned i=0;i<8192;++i){auto* p=AllocateCodePage();CHECK(p);pages.push_back(p);p[0]=0xb8;*reinterpret_cast<unsigned*>(p+1)=42;p[5]=0xc3;DWORD old=0;CHECK(VirtualProtect(p,4096,PAGE_EXECUTE_READ,&old));}
 CHECK(reserves==512);
 auto* large=VirtualAlloc(nullptr,64*1024*1024,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(large);VirtualFree(large,0,MEM_RELEASE);
 auto* pending=AllocateCodePage();CHECK(pending);CHECK(ReleaseCodePage(pending));
 rejectCommit=true;CHECK(!AllocateCodePage());rejectCommit=false;CHECK(AllocateCodePage()==pending);
 CHECK(reinterpret_cast<int(*)()>(pages[0])()==42&&reinterpret_cast<int(*)()>(pages.back())()==42);
 MEMORY_BASIC_INFORMATION info{};CHECK(VirtualQuery(pages[0],&info,sizeof(info))&&info.Protect==PAGE_EXECUTE_READ);
 // Freeing an unpublished sibling must not release the published arena.
 auto* sibling=AllocateCodePage();CHECK(sibling&&ReleaseCodePage(sibling));CHECK(reinterpret_cast<int(*)()>(pages.back())()==42);
 std::atomic_bool valid{true};std::vector<std::thread> callers;
 for(unsigned i=0;i<4;++i)callers.emplace_back([&]{for(unsigned j=0;j<256;++j){auto* p=AllocateCodePage();if(!p||!ReleaseCodePage(p))valid=false;}});
 for(auto& t:callers)t.join();CHECK(valid);
 puts("PASS: 8192 x86 code pages use 512 arenas, 64MiB contiguous allocation survives, failure reuse and RX siblings retained");
}
'''.replace("ALLOCATOR", (root / "APIMonitor_x64/hook/CodePageAllocator.h").as_posix())
environment = target_environment("x86")
compiler = shutil.which("cl", path=environment["PATH"])
with tempfile.TemporaryDirectory(prefix="ksword_code_pages_") as temporary:
    folder = Path(temporary)
    cpp = folder / "fixture.cpp"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run([compiler, "/nologo", "/EHsc", "/std:c++17", "/utf-8", str(cpp),
                    "/Fe:" + str(folder / "fixture.exe"), "/Fo:" + str(folder / "fixture.obj")], env=environment, check=True)
    subprocess.run([str(folder / "fixture.exe")], check=True, timeout=30)
