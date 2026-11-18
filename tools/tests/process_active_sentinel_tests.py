"""Exercise the production active-list terminator proof with guarded synthetic links and PE sections."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/"tools"))
from test_driver_candidate_reference import function


PRE = r'''
#include <windows.h>
#include <winternl.h>
#include <cassert>
#include <cstring>
#include <cstdio>
#include "WIRE"
#define KSW_IMAGE_SECTION_NAME_CHARS 9
#define KSW_IMAGE_SECTION_RESULT_UNKNOWN 0
#define KSW_IMAGE_SECTION_RESULT_EXECUTABLE 1
#define KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE 2
#define KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS 3
#define KSW_IMAGE_SECTION_MAX_SECTIONS 96
#define RtlCompareMemory(a,b,n) (std::memcmp(a,b,n)==0 ? (n) : 0U)
struct KSW_HOOK_SYSTEM_MODULE_ENTRY {PVOID ImageBase; ULONG ImageSize;};
alignas(4096) static unsigned char image[16384];
#define PsGetProcessId (image + 0x1000)
static bool failPE=false;
static unsigned reads=0, failAt=0, changeAt=0, imageReads=0;
static LIST_ENTRY sys, fixtureFirst, fixturePrev, pool;
static auto* sentinel=reinterpret_cast<LIST_ENTRY*>(image+0x2040);
static KSW_DYN_MODULE_IDENTITY_PACKET fixtureNt;
static IMAGE_NT_HEADERS* ntHdr(){return reinterpret_cast<IMAGE_NT_HEADERS*>(image+0x80);}
static IMAGE_SECTION_HEADER* section(){return IMAGE_FIRST_SECTION(ntHdr());}
static BOOLEAN KswordARKHookReadImageBytes(const KSW_HOOK_SYSTEM_MODULE_ENTRY* m,ULONG r,void* out,SIZE_T n){
    ++imageReads;
    if(failPE||m->ImageBase!=image||n>m->ImageSize||r>m->ImageSize-n) return FALSE;
    std::memcpy(out,image+r,n);return TRUE;
}
static BOOLEAN KswordARKHookReadImageNtHeaders(const KSW_HOOK_SYSTEM_MODULE_ENTRY* m,IMAGE_NT_HEADERS* ntOut){
    return KswordARKHookReadImageBytes(m,0x80,ntOut,sizeof(*ntOut)) && ntOut->Signature==IMAGE_NT_SIGNATURE;
}
static BOOLEAN KswordARKHookAddRvaOffset(ULONG r,ULONG i,ULONG s,ULONG* end){
    const auto result=r+ULONGLONG(i)*s; if(result>0xffffffffULL)return FALSE;
    *end=static_cast<ULONG>(result);return TRUE;
}
static bool KswordARKCrossViewPointerAligned(ULONG_PTR p){return p && !(p&7);}
static NTSTATUS KswordARKCrossViewReadMemory(const void* p,void* out,SIZE_T n){
    if(++reads==failAt || (p!=sentinel && p!=&sys && p!=&fixturePrev && p!=&pool))return -1;
    std::memcpy(out,p,n);
    if (changeAt==reads && n==sizeof(LIST_ENTRY)) static_cast<LIST_ENTRY*>(out)->Blink=nullptr;
    return 0;
}
static NTSTATUS KswordARKCrossViewReadPointerAddress(const void* p,PVOID* out){
    return KswordARKCrossViewReadMemory(p,out,sizeof(*out));
}
'''

TEST = r'''
static void setup(){
    reads=failAt=changeAt=imageReads=0;failPE=false;
    memset(image,0,sizeof(image)); auto* dos=reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    dos->e_magic=IMAGE_DOS_SIGNATURE; dos->e_lfanew=0x80;
    ntHdr()->Signature=IMAGE_NT_SIGNATURE; ntHdr()->FileHeader.NumberOfSections=1;
    ntHdr()->FileHeader.SizeOfOptionalHeader=sizeof(IMAGE_OPTIONAL_HEADER);
    auto* s=section(); memcpy(s->Name,".data",6);s->VirtualAddress=0x2000;s->Misc.VirtualSize=0x800;
    s->Characteristics=IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_CNT_INITIALIZED_DATA;
    fixtureNt={}; fixtureNt.present=1;fixtureNt.classId=KSW_DYN_PROFILE_CLASS_NTOSKRNL;
    fixtureNt.imageBase=reinterpret_cast<ULONG_PTR>(image);fixtureNt.sizeOfImage=sizeof(image);
    sys={&fixtureFirst,sentinel}; fixtureFirst={&fixturePrev,&sys}; fixturePrev={sentinel,&fixtureFirst}; *sentinel={&sys,&fixturePrev};
}
static bool valid(){return KswProcessVerifiedActiveSentinel(&fixtureNt,&sys,&fixtureFirst,sentinel,&fixturePrev,sentinel)!=FALSE;}
int main(){
    setup(); assert(valid() && reads==4 && imageReads<=4);
    for(unsigned i=1;i<=4;++i){setup();failAt=i;assert(!valid());}
    setup();changeAt=4;assert(!valid());
    setup();sys.Blink=&fixturePrev;assert(!valid());
    setup();sys.Flink=&fixturePrev;assert(!valid());
    setup();fixturePrev.Flink=&sys;assert(!valid());
    setup();sentinel->Blink=&fixtureFirst;assert(!valid());
    setup();sentinel->Flink=&fixtureFirst;assert(!valid());
    setup();assert(!KswProcessVerifiedActiveSentinel(&fixtureNt,&sys,&fixtureFirst,nullptr,&fixturePrev,sentinel));
    setup();pool={&sys,&fixturePrev};fixturePrev.Flink=&pool;sys.Blink=&pool;
    assert(!KswProcessVerifiedActiveSentinel(&fixtureNt,&sys,&fixtureFirst,&pool,&fixturePrev,&pool));
    setup();assert(!KswProcessVerifiedActiveSentinel(&fixtureNt,&sys,&fixtureFirst,sentinel,sentinel,sentinel));
    setup();fixtureNt.present=0;assert(!valid());setup();++fixtureNt.classId;assert(!valid());
    setup();fixtureNt.imageBase+=0x1800;assert(!valid());
    for(ULONG bit:{IMAGE_SCN_MEM_EXECUTE+0UL, IMAGE_SCN_CNT_CODE+0UL, IMAGE_SCN_MEM_DISCARDABLE+0UL}){
        setup();section()->Characteristics|=bit;assert(!valid());
    }
    for(ULONG bit:{IMAGE_SCN_MEM_READ+0UL, IMAGE_SCN_MEM_WRITE+0UL, IMAGE_SCN_CNT_INITIALIZED_DATA+0UL}){
        setup();section()->Characteristics&=~bit;assert(!valid());
    }
    setup();section()->Misc.VirtualSize=0x48;assert(!valid()); // fixtureFirst byte fits, second pointer does not
    setup();memcpy(section()->Name,".fake",6);assert(!valid());
    setup();failPE=true;assert(!valid());setup();ntHdr()->FileHeader.NumberOfSections=97;assert(!valid());
    setup();sys={sentinel,sentinel};*sentinel={&sys,&sys};
    assert(KswProcessVerifiedActiveSentinel(&fixtureNt,&sys,sentinel,sentinel,&sys,sentinel));
    puts("ACTIVE_SENTINEL_PROOF_PASS");
}
'''

if __name__ == "__main__":
    out = ROOT/"tools/tests/x64/Release"
    obj = out/"ActiveSentinel/obj"
    obj.mkdir(parents=True, exist_ok=True)
    section = "KswordARKDriver/src/features/kernel/kernel_image_section_map.c"
    cross = "KswordARKDriver/src/features/process/process_crossview.c"
    production = "\n".join((function(section, "KswordARKImageCopySectionName"), function(section, "KswImageClassifyRange"),
                            function(section, "KswordARKImageContainsStaticWritableList"), function(cross, "KswProcessVerifiedActiveSentinel")))
    src = obj/"sentinel_fixture.cpp"
    src.write_text("#include <initializer_list>\n"+PRE.replace('"WIRE"','"'+(ROOT/"shared/driver/KswordArkDynDataIoctl.h").as_posix()+'"')+
                   production+TEST,encoding="utf-8")
    exe = out/"process_active_sentinel_tests.exe"
    subprocess.run(["cl","/nologo","/std:c++20","/W4","/WX","/EHsc","/utf-8",str(src),"/Fe:"+str(exe)],cwd=obj,check=True)
    subprocess.run([str(exe)],cwd=obj,check=True)
