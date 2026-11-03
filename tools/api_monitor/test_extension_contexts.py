"""Production engine/dispatchers: distinct provider addresses, conflicts and pending discovery."""
from pathlib import Path
import subprocess
import tempfile
import generate_definitions

root = Path(__file__).resolve().parents[2]
safe = (root / "APIMonitor_x64/hook/AsyncIoHandlers.inc").read_text().split("        void CaptureDatagramCompletion")[0]
code = r'''
#include <cstdio>
#include "pch.h"
#include <mswsock.h>
#include "ENGINE"
#include "TRACKER"
#include "THUNK"
namespace apimon {
 std::uint64_t session=1;
 std::uint64_t CurrentMonitorSessionIdentity(){return session;}
 bool StopRequested(){return false;}
 std::uint32_t RuntimeApiId(const wchar_t*,const wchar_t*){return 42;}
 bool SendMonitorEventRaw(ks::winapi_monitor::EventCategory,const wchar_t*,const wchar_t*,std::int32_t,const wchar_t*,
  ks::winapi_monitor::EventResultKind,ks::winapi_monitor::EventKind,std::uint64_t,std::uint32_t){return true;}
 namespace {
  class ScopedHookGuard{public:bool bypass()const{return false;}};
  struct ApiCallClock {};
  struct ApiCallDuration { bool valid = true; std::uint64_t ticks100ns = 1; };
  ApiCallClock BeginApiCallClock(){return {};}
  ApiCallDuration EndApiCallClock(const ApiCallClock&){return {};}
  template<typename T> std::uint64_t ApiReturnBits(T value){std::uint64_t bits=0;memcpy(&bits,&value,sizeof(value));return bits;}
  std::uint64_t observedReturn=0;std::uint32_t observedId=0;bool observedDuration=false,observedHasReturn=false;
  bool SendRawEventWithMetrics(ks::winapi_monitor::EventCategory,const wchar_t*,const wchar_t*,long,
      const wchar_t*,bool hasReturn,std::uint64_t bits,const ApiCallDuration& duration,std::uint32_t apiId=0){
      observedReturn=bits;observedId=apiId;observedDuration=duration.valid;observedHasReturn=hasReturn;return true;}
  struct ExtensionContext;
  #include "ApiMonitorExtensionDeclarations.inc"
  SAFE
  bool CategoryEnabled(ks::winapi_monitor::EventCategory){return true;}
  std::uint64_t SumWsaBufferLength(const WSABUF*,DWORD){return 0;}
  void* PrepareIoCallback(const IoToken&,LPOVERLAPPED_COMPLETION_ROUTINE,LPWSAOVERLAPPED_COMPLETION_ROUTINE){return nullptr;}
  void* returnedAddress=nullptr;bool pending=false;
  int WSAAPI TestIoctl(SOCKET,DWORD,LPVOID,DWORD,LPVOID output,DWORD,LPDWORD bytes,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE){
   *static_cast<void**>(output)=returnedAddress;*bytes=sizeof(void*);WSASetLastError(pending?WSA_IO_PENDING:2345);return pending?SOCKET_ERROR:0;
  }
  auto g_wsaIoctlOriginal=&TestIoctl;
  #include "HANDLERS"
 }
}
using namespace apimon;using namespace ks::winapi_monitor;
#define CHECK(x) do{if(!(x)){printf("FAIL %d\n",__LINE__);return 1;}}while(0)
void* Code(unsigned value){auto* code=static_cast<unsigned char*>(VirtualAlloc(nullptr,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
 code[0]=0xB8;memcpy(code+1,&value,4);
#ifdef _M_IX86
 code[5]=0xC2;code[6]=32;code[7]=0; // AcceptEx: eight 32-bit stdcall arguments
#else
 code[5]=0xC3;
#endif
 DWORD protect=0;VirtualProtect(code,4096,PAGE_EXECUTE_READ,&protect);return code;}
int main(){
 const GUID accept=WSAID_ACCEPTEX,connect=WSAID_CONNECTEX;void* first=Code(21),*second=Code(22),*third=Code(23);
 DiscoverExtension(accept,first);DiscoverExtension(accept,first);CHECK(g_extensions.size()==1&&g_extensions[0]->record.installed);
 DiscoverExtension(accept,second);CHECK(g_extensions.size()==2&&g_extensions[1]->record.installed);
 OVERLAPPED ov{};DWORD bytes=0;char buffer[128]{};
 auto call=[&](void* pointer){return reinterpret_cast<AcceptExFn>(pointer)(1,2,buffer,3,4,5,&bytes,&ov);};
 CHECK(call(first)==21&&observedHasReturn&&observedReturn==21&&observedId!=0&&observedDuration);
 CHECK(call(second)==22&&observedReturn==22&&observedId!=0&&observedDuration); // immutable originals and actual return
 DiscoverExtension(connect,first);CHECK(g_extensions.size()==3&&!g_extensions[2]->record.installed&&g_extensions[2]->record.permanentlyDisabled);
 CHECK(call(first)==21);std::vector<ApiMonitorEventPacket> rows;AppendExtensionCoverage(rows);
 CHECK(std::count_if(rows.begin(),rows.end(),[](auto& r){return r.coverageState==static_cast<unsigned>(CoverageState::Installed);})==2);
 CHECK(std::any_of(rows.begin(),rows.end(),[](auto& r){return r.coverageState==static_cast<unsigned>(CoverageState::Unsupported); }));
 returnedAddress=third;pending=true;void* applicationPointer=nullptr;DWORD returnedBytes=0;
 CHECK(HookedWSAIoctl(100,SIO_GET_EXTENSION_FUNCTION_POINTER,const_cast<GUID*>(&accept),sizeof(accept),&applicationPointer,sizeof(applicationPointer),&returnedBytes,&ov,nullptr)==SOCKET_ERROR);
 CHECK(WSAGetLastError()==WSA_IO_PENDING&&applicationPointer==third&&g_extensions.size()==3);
 ObserveIoResult(100,&ov,true,0,sizeof(void*));CHECK(applicationPointer==third&&g_extensions.size()==4&&g_extensions.back()->record.installed&&call(third)==23);
 auto oldDetour=g_extensions[0]->detour;CHECK(UninstallExtensionHooks());CHECK(call(first)==21&&call(second)==22&&call(third)==23);
 CHECK(call(oldDetour)==21); // a published detour still owns its original trampoline after stop
 ++session;DiscoverExtension(accept,first);CHECK(g_extensions.size()==5&&g_extensions.back()->record.installed&&call(first)==21);
 CHECK(UninstallExtensionHooks());
 printf("PASS: distinct provider originals, unchanged app pointers, idempotent discovery, incompatible aliases, async ioctl discovery and retired detours\n");
}
'''
for name, file in [("ENGINE", "APIMonitor_x64/hook/HookEngine.cpp"), ("TRACKER", "APIMonitor_x64/core/MonitorAsyncIo.cpp"),
                   ("THUNK", "APIMonitor_x64/hook/ContextThunk.h"), ("HANDLERS", "APIMonitor_x64/hook/WinsockExtensionHandlers.inc")]:
    code = code.replace(name, (root / file).as_posix())
code = code.replace("SAFE", safe)
with tempfile.TemporaryDirectory(prefix="ksword_extension_contexts_") as temp:
    folder = Path(temp)
    generate_definitions.generate(root / "APIMonitor_x64/api_monitor_definitions.json", folder)
    cpp = folder / "fixture.cpp"
    cpp.write_text(code, encoding="utf-8")
    subprocess.run(["cl", "/nologo", "/EHsc", "/std:c++17", "/utf-8", "/I" + str(root / "APIMonitor_x64"), "/I" + str(folder),
                    str(cpp), "/Fe:" + str(folder / "fixture.exe"), "/Fo:" + str(folder / "fixture.obj"), "/link", "Ws2_32.lib"], check=True)
    subprocess.run([str(folder / "fixture.exe")], check=True, timeout=30)
