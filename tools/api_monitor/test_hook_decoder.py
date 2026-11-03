"""Execute production x64 relocation against benign machine-code fixtures."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[2]
code=r'''
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdio>
#include <initializer_list>
static bool rejectNear=false;
static unsigned queryCount=0;
static SIZE_T WINAPI FixtureQuery(LPCVOID address,PMEMORY_BASIC_INFORMATION info,SIZE_T size){
 ++queryCount;return ::VirtualQuery(address,info,size);
}
static LPVOID WINAPI FixtureAlloc(LPVOID p,SIZE_T size,DWORD type,DWORD protect) {
 if (rejectNear && p) return nullptr;
 return VirtualAlloc(p,size,type,protect);
}
#define VirtualAlloc FixtureAlloc
static FARPROC WINAPI FixtureExport(HMODULE module,LPCSTR name){return strcmp(name,"VirtualAlloc2")==0?nullptr:GetProcAddress(module,name);}
#define GetProcAddress FixtureExport
#define VirtualQuery FixtureQuery
#include "ENGINE"
#undef VirtualQuery
#undef GetProcAddress
#undef VirtualAlloc
using Function=int(*)();
static void* original=nullptr;
int Detour(){return reinterpret_cast<Function>(original)()+1;}
int DifferentDetour(){return 0;}
#define CHECK(x) do {if(!(x)){printf("FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
void put(unsigned char* p,std::initializer_list<unsigned char> bytes){memcpy(p,bytes.begin(),bytes.size());}
void rel(unsigned char* p,unsigned char* target,size_t size,size_t position){int32_t d=static_cast<int32_t>(target-(p+size));memcpy(p+position,&d,4);}
int main(){
 struct Case {std::initializer_list<unsigned char> bytes;size_t length;bool rip;};
 Case decoder[]={{{0x80,0xF9,0x90},3,false},{{0x80,0xF9},0,false},{{0x66,0x81,0xC0,1,0},5,false},
 {{0x66,0xC7,0xC0,1,0},5,false},{{0x66,0x48,0x81,0xC0,1,0,0,0},8,false},{{0x66,0x68,1,0},4,false},
 {{0x67,0x8B,0x05,1,0,0,0},0,false},{{0x48,0x8B,0x05,1,0,0,0},7,true},{{0xE8,0,0,0,0},5,false},
 {{0x48,0xFF,0x15,1,0,0,0},7,true},{{0x48,0xFF,0x15,1,0,0},0,false},
 {{0x48,0xFF,0x25,1,0,0,0},0,false},{{0x48,0xFF,0xD0},0,false},{{0xF3,0x48,0xFF,0x15,1,0,0,0},0,false},
 {{0xF6,0x04,0x25,8,3,0xFE,0x7F,1},8,false},{{0xF3,0x0F,0x1E,0xFA},4,false},{{0xC5,0xF8,0x77},0,false},
 {{0x0F,0x85,1,0,0,0},6,false},{{0x75,0},2,false},{{0xEB,0},2,false},{{0xE9,0,0,0,0},5,false}};
 for(const auto& c:decoder){auto d=apimon::DecodeInstruction(c.bytes.begin(),c.bytes.size());CHECK(d.length==c.length);CHECK(d.ripRelative==c.rip);}
 auto* block=static_cast<unsigned char*>(VirtualAlloc(nullptr,65536,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));CHECK(block);
 unsigned char inspected[32]{};queryCount=0;CHECK(apimon::ReadCode(block,inspected,sizeof(inspected))==32&&queryCount==1);
 std::wstring error;
 for(int index=0;index<9;++index){
  auto* p=block+index*1024;memset(p,0x90,1024);
  int expected=42;
  switch(index){
   case 0: put(p,{0x48,0x8B,0x05,0,0,0,0,0xC3});rel(p,p+128,7,3);{uint64_t v=42;memcpy(p+128,&v,8);}break;
   case 1: put(p,{0xE8,0,0,0,0,0x83,0xC0,1,0xC3});rel(p,p+128,5,1);put(p+128,{0xB8,42,0,0,0,0xC3});expected=43;break;
   case 2: put(p,{0x31,0xC0,0x74,0,0xB8,42,0,0,0,0xC3});break;
   case 3: put(p,{0x31,0xC0,0x75,0xFC,0xB8,42,0,0,0,0xC3});break;
   case 4: put(p,{0x31,0xC0,0x90,0xEB,5,0xB8,1,0,0,0,0xB8,42,0,0,0,0xC3});break;
   case 5: put(p,{0x31,0xC0,0x0F,0x84,0,0,0,0,0xB8,1,0,0,0,0xC3});rel(p+2,p+128,6,2);put(p+128,{0xB8,42,0,0,0,0xC3});break;
   case 6: put(p,{0xF3,0x0F,0x1E,0xFA,0xB8,42,0,0,0,0xC3});break;
   case 7: put(p,{0x31,0xC0,0xE9,0,0,0,0});rel(p+2,p+128,5,1);put(p+128,{0xB8,42,0,0,0,0xC3});break;
   // RIP-relative indirect CALL is copied into the trampoline with its
   // memory operand retargeted to the same import slot. The nested callee
   // returns into the relocated continuation before the original function.
   case 8: put(p,{0x48,0xFF,0x15,0,0,0,0,0x83,0xC0,1,0xC3});rel(p,p+128,7,3);
    put(p+160,{0xB8,42,0,0,0,0xC3});{auto* target=p+160;memcpy(p+128,&target,sizeof(target));}expected=43;break;
  }
  CHECK(reinterpret_cast<Function>(p)()==expected);
  apimon::InlineHookRecord hook;
  auto result=apimon::InstallInlineHookAtAddress(p,reinterpret_cast<void*>(&Detour),&hook,&original,&error);
  if(result!=apimon::InlineHookInstallResult::Installed){wprintf(L"case %d %s\n",index,error.c_str());return 1;}
  CHECK(hook.patchSize>=5&&hook.patchSize<=9);
  CHECK(reinterpret_cast<Function>(original)()==expected);CHECK(reinterpret_cast<Function>(p)()==expected+1);
  if(index==6){CHECK(memcmp(p,"\xF3\x0F\x1E\xFA",4)==0);CHECK(memcmp(original,"\xF3\x0F\x1E\xFA",4)==0);}
  CHECK(apimon::UninstallInlineHook(&hook));CHECK(reinterpret_cast<Function>(p)()==expected);
  CHECK(reinterpret_cast<Function>(original)()==expected);
 }
 auto* p=block+8192;put(p,{0xB8,42,0,0,0,0xC3});
 apimon::InlineHookRecord owner,shared,conflict;void* second=nullptr,*bad=nullptr;
 CHECK(apimon::InstallInlineHookAtAddress(p,(void*)&Detour,&owner,&original,&error)==apimon::InlineHookInstallResult::Installed);
 CHECK(apimon::InstallInlineHookAtAddress(p,(void*)&Detour,&shared,&second,&error)==apimon::InlineHookInstallResult::Installed);
 CHECK(shared.sharedEntry&&second==original);
 CHECK(apimon::InstallInlineHookAtAddress(p,(void*)&DifferentDetour,&conflict,&bad,&error)==apimon::InlineHookInstallResult::PermanentFailure);
 CHECK(error.find(L"conflict")!=std::wstring::npos&&bad==nullptr);
 apimon::InlineHookRecord overlap;
 CHECK(apimon::InstallInlineHookAtAddress(p+2,(void*)&Detour,&overlap,&bad,&error)==apimon::InlineHookInstallResult::PermanentFailure);
 CHECK(apimon::UninstallInlineHook(&owner));CHECK(reinterpret_cast<Function>(p)()==43);
 CHECK(apimon::UninstallInlineHook(&shared));CHECK(reinterpret_cast<Function>(p)()==42);
 // Interior target and malformed/short prologues are rejected without guessing.
 auto* invalid=block+9216;put(invalid,{0x74,1,0xB8,42,0,0,0,0xC3});
 apimon::InlineHookRecord middle;
 CHECK(apimon::InstallInlineHookAtAddress(invalid,(void*)&Detour,&middle,&bad,&error)==apimon::InlineHookInstallResult::PermanentFailure);
 CHECK(error.find(L"middle")!=std::wstring::npos&&error.find(L"offset=0")!=std::wstring::npos);
 put(invalid,{0x31,0xC0,0xC3});apimon::InlineHookRecord shortEntry;
 CHECK(apimon::InstallInlineHookAtAddress(invalid,(void*)&Detour,&shortEntry,&bad,&error)==apimon::InlineHookInstallResult::PermanentFailure);
 put(invalid,{0xEB,0xFE});apimon::InlineHookRecord cycle;
 CHECK(apimon::InstallInlineHookAtAddress(invalid,(void*)&Detour,&cycle,&bad,&error)==apimon::InlineHookInstallResult::PermanentFailure);
 CHECK(error.find(L"cycle")!=std::wstring::npos);
 put(invalid,{0x67,0x8B,0x05,0,0,0,0});apimon::InlineHookRecord override;
 CHECK(apimon::InstallInlineHookAtAddress(invalid,(void*)&Detour,&override,&bad,&error)==apimon::InlineHookInstallResult::PermanentFailure);
 // Test deterministic distantEntry-relocation rejection independently of ASLR placement.
 unsigned char rip[]={0x48,0x8B,0x05,0x80,0,0,0},out[64]{};size_t emitted=0,offset=0;const wchar_t* reason=nullptr;
 std::vector<apimon::InstructionDescription> descriptions{apimon::DecodeInstruction(rip,sizeof(rip))};
 CHECK(!apimon::BuildRelocatedCode(rip,0x100000000,7,out,0x200000000,descriptions,&emitted,&offset,&reason));
 CHECK(wcsstr(reason,L"disp32"));
 // An indirect-call import slot inside the overwritten patch must fail;
 // callers must not execute a trampoline with a changed pointer value.
 unsigned char callSlotOverlap[]={0x48,0xFF,0x15,0xF9,0xFF,0xFF,0xFF};
 descriptions={apimon::DecodeInstruction(callSlotOverlap,sizeof(callSlotOverlap))};reason=nullptr;
 CHECK(!apimon::BuildRelocatedCode(callSlotOverlap,0x100000000,7,out,0x100001000,descriptions,&emitted,&offset,&reason));
 CHECK(wcsstr(reason,L"overlaps"));
 // Slot begins four bytes before the patch but its eight-byte pointer ends
 // inside the patch: this must be rejected too.
 unsigned char callSlotTailOverlap[]={0x48,0xFF,0x15,0xF5,0xFF,0xFF,0xFF};
 descriptions={apimon::DecodeInstruction(callSlotTailOverlap,sizeof(callSlotTailOverlap))};reason=nullptr;
 CHECK(!apimon::BuildRelocatedCode(callSlotTailOverlap,0x100000000,7,out,0x100001000,descriptions,&emitted,&offset,&reason));
 CHECK(wcsstr(reason,L"overlaps"));
 // Also reject import slots that cannot be represented from the trampoline.
 unsigned char farCall[]={0x48,0xFF,0x15,0x80,0,0,0};
 descriptions={apimon::DecodeInstruction(farCall,sizeof(farCall))};reason=nullptr;
 CHECK(!apimon::BuildRelocatedCode(farCall,0x100000000,7,out,0x200000000,descriptions,&emitted,&offset,&reason));
 CHECK(wcsstr(reason,L"disp32"));
 // Allocation fallback may only overwrite a verified 14-byte prologue.
 rejectNear=true;auto* distantEntry=block+10240;memset(distantEntry,0x90,14);put(distantEntry+14,{0xB8,42,0,0,0,0xC3});apimon::InlineHookRecord fallback;
 CHECK(apimon::InstallInlineHookAtAddress(distantEntry,(void*)&Detour,&fallback,&original,&error)==apimon::InlineHookInstallResult::Installed);
 CHECK(fallback.patchSize==14&&distantEntry[0]==0xFF);CHECK(reinterpret_cast<Function>(distantEntry)()==43);CHECK(apimon::UninstallInlineHook(&fallback));
 put(distantEntry,{0xB8,42,0,0,0,0xC3});apimon::InlineHookRecord unsafeFar;
 CHECK(apimon::InstallInlineHookAtAddress(distantEntry,(void*)&Detour,&unsafeFar,&bad,&error)==apimon::InlineHookInstallResult::PermanentFailure);
 rejectNear=false;
 auto* denied=VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);apimon::InlineHookRecord unreadable;
 CHECK(apimon::InstallInlineHookAtAddress(denied,(void*)&Detour,&unreadable,&bad,&error)==apimon::InlineHookInstallResult::PermanentFailure);
 CHECK(error.find(L"unreadable")!=std::wstring::npos);
 auto* boundary=static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));DWORD old=0;
 put(boundary+4093,{0x31,0xC0,0x90});VirtualProtect(boundary+4096,4096,PAGE_NOACCESS,&old);apimon::InlineHookRecord suffix;
 memset(inspected,0xa5,sizeof(inspected));queryCount=0;CHECK(apimon::ReadCode(boundary+4093,inspected,sizeof(inspected))==3&&queryCount==2&&inspected[3]==0xa5);
 CHECK(apimon::InstallInlineHookAtAddress(boundary+4093,(void*)&Detour,&suffix,&bad,&error)==apimon::InlineHookInstallResult::PermanentFailure);
 printf("PASS: descriptor cases; executable RIP/CALL/JMP/Jcc relocation, internal targets, ENDBR, conflicts, fallback, unreadable pages and retired code\n");
}
'''.replace('ENGINE',(root/'APIMonitor_x64/hook/HookEngine.cpp').as_posix())
with tempfile.TemporaryDirectory(prefix='ksword_relocation_') as temporary:
 folder=Path(temporary);cpp=folder/'fixture.cpp';cpp.write_text(code,encoding='utf-8')
 subprocess.run(['cl','/nologo','/EHsc','/std:c++17','/utf-8','/I'+str(root/'APIMonitor_x64'),str(cpp),'/Fe:'+str(folder/'fixture.exe'),'/Fo:'+str(folder/'fixture.obj')],check=True)
 subprocess.run([str(folder/'fixture.exe')],check=True,timeout=90)
