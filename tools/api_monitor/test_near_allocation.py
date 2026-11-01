"""Production near walker skips occupied regions, handles races and cancellation."""
from pathlib import Path
import subprocess
import tempfile

root=Path(__file__).resolve().parents[2]
source=r'''
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
using Allocate2=PVOID(WINAPI*)(HANDLE,PVOID,SIZE_T,ULONG,ULONG,MEM_EXTENDED_PARAMETER*,ULONG);
static unsigned systemCalls=0, systemSuccesses=0;
static Allocate2 nativeAllocate=nullptr;
PVOID WINAPI CheckedAllocate(HANDLE process,PVOID base,SIZE_T size,ULONG type,ULONG protection,MEM_EXTENDED_PARAMETER* parameters,ULONG count){
 ++systemCalls;
 if(count!=1 || parameters[0].Type!=MemExtendedParameterAddressRequirements)ExitProcess(91);
 const auto* requirements=static_cast<const MEM_ADDRESS_REQUIREMENTS*>(parameters[0].Pointer);
 if((reinterpret_cast<uintptr_t>(requirements->LowestStartingAddress)&65535)!=0
   ||(reinterpret_cast<uintptr_t>(requirements->HighestEndingAddress)&65535)!=65535)ExitProcess(92);
 auto* result=nativeAllocate(process,base,size,type,protection,parameters,count);if(result)++systemSuccesses;return result;
}
FARPROC WINAPI CheckedProc(HMODULE module,LPCSTR name){
 const auto result=::GetProcAddress(module,name);
 if(std::strcmp(name,"VirtualAlloc2")!=0)return result;
 std::memcpy(&nativeAllocate,&result,sizeof(result));
 FARPROC checked=nullptr;auto function=&CheckedAllocate;std::memcpy(&checked,&function,sizeof(checked));return checked;
}
#define GetProcAddress CheckedProc
#include "HEADER"
#undef GetProcAddress
static bool cancelled=false;
bool Stop(){return cancelled;}
#define CHECK(x) do{if(!(x)){printf("FAIL %d %s\n",__LINE__,#x);return 1;}}while(0)
int main(){
 constexpr uintptr_t base=0x10000000, end=0x30000000, center=0x20000000;
 unsigned queries=0,allocations=0;
 auto query=[&](const void* address,MEMORY_BASIC_INFORMATION* r){++queries;auto p=reinterpret_cast<uintptr_t>(address);
  r->BaseAddress=reinterpret_cast<void*>(p>=base&&p<end?base:p&~uintptr_t{65535});r->RegionSize=p>=base&&p<end?end-base:65536;r->State=p>=base&&p<end?MEM_RESERVE:MEM_FREE;return true;};
 auto allocate=[&](void* p){++allocations;return static_cast<unsigned char*>(p);};
 auto* memory=apimon::detail::FindNearFreeRegion(center,65536,0x7fffffff,65536,query,allocate,&Stop);
 CHECK(memory&&queries<=3&&allocations==1);CHECK(reinterpret_cast<uintptr_t>(memory)<base||reinterpret_cast<uintptr_t>(memory)>=end);
 cancelled=true;queries=0;CHECK(!apimon::detail::FindNearFreeRegion(center,65536,0x7fffffff,65536,query,allocate,&Stop)&&queries==0);cancelled=false;
 unsigned failures=0;auto raced=[&](void* p)->unsigned char*{if(!failures++)return nullptr;return static_cast<unsigned char*>(p);};
 CHECK(apimon::detail::FindNearFreeRegion(center,65536,0x7fffffff,65536,query,raced,&Stop)&&failures==2);
#ifdef _WIN64
 auto* actual=apimon::detail::AllocateNearAddress(reinterpret_cast<void*>(&main),nullptr);CHECK(actual);
 const auto distance=reinterpret_cast<intptr_t>(actual)-reinterpret_cast<intptr_t>(&main);CHECK(distance<0x80000000ll&&distance>-0x80000000ll);VirtualFree(actual,0,MEM_RELEASE);
 CHECK(systemCalls==1&&systemSuccesses==1);
#endif
 puts("PASS: 512MiB region skipped in <=3 queries, cancellation, race, and VirtualAlloc2 succeeds without fallback");
}
'''.replace("HEADER",(root/"APIMonitor_x64/hook/NearAllocation.h").as_posix())
with tempfile.TemporaryDirectory(prefix="ksword_near_alloc_") as temporary:
    folder=Path(temporary);cpp=folder/"fixture.cpp";cpp.write_text(source,encoding="utf-8")
    subprocess.run(["cl","/nologo","/EHsc","/std:c++17","/utf-8",str(cpp),"/Fe:"+str(folder/"fixture.exe"),"/Fo:"+str(folder/"fixture.obj")],check=True)
    subprocess.run([str(folder/"fixture.exe")],check=True,timeout=15)
