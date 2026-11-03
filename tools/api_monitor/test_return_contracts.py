"""An invalid handle is a failed pipe/mailslot creation, preserving the original error."""
from live_fixture_support import LiveFixture
from pathlib import Path
import json
import subprocess
import tempfile
import generate_definitions

catalog = json.loads((Path(__file__).resolve().parents[2] / "APIMonitor_x64/api_monitor_definitions.json").read_bytes())
names = ["CreateNamedPipeW", "CreateNamedPipeA", "CreateMailslotW", "CreateMailslotA"]
cpp = r'''
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
namespace ks::winapi_monitor {constexpr unsigned kMaxDetailChars=320;enum class EventCategory{File};}
struct ScopedHookGuard{bool bypass()const{return false;}};
bool failure=true;long observed=-1;
template <typename T> std::uint64_t ApiReturnBits(T value){std::uint64_t bits{};static_assert(sizeof(value)<=sizeof(bits));memcpy(&bits,&value,sizeof(value));return bits;}
template <size_t N> void AppendWideText(wchar_t (&)[N],const wchar_t*){}
template <size_t N> void AppendHexText(wchar_t (&)[N],std::uint64_t){}
int BeginApiCallClock(){const DWORD error=GetLastError();SetLastError(error);return 0;}
int EndApiCallClock(int){const DWORD error=GetLastError();SetLastError(error);return 0;}
void SendRawEventWithMetrics(ks::winapi_monitor::EventCategory,const wchar_t*,const wchar_t*,long status,const wchar_t*,bool,std::uint64_t,int){observed=status;SetLastError(9999);}
'''
calls = "int main(){\n"
for api in (a for a in catalog["apis"] if a["export"] in names):
    signature = generate_definitions.signature(api)
    result = "resultHandle"
    cpp += f"HANDLE WINAPI Mock{api['export']}({signature}){{SetLastError(failure?1234:7654);return failure?INVALID_HANDLE_VALUE:reinterpret_cast<HANDLE>(42);}}\n"
    cpp += f"auto {api['binding']['original']}=&Mock{api['export']};\n"
    cpp += f"void {api['wrapper']['capture_handler']}(wchar_t (&)[320], {signature}, HANDLE {result}){{SetLastError(8888);}}\n"
    cpp += generate_definitions.wrapper(api)
    args = ", ".join("nullptr" if p["type"].startswith(("LP", "P")) else "0" for p in api["parameters"])
    calls += f"failure=true;if({api['binding']['hook']}({args})!=INVALID_HANDLE_VALUE||observed!=1234||GetLastError()!=1234)return 1;\n"
    calls += f"failure=false;if({api['binding']['hook']}({args})!=reinterpret_cast<HANDLE>(42)||observed!=0||GetLastError()!=7654)return 2;\n"
cpp += calls + 'printf("PASS: four generated invalid-handle success/error contracts\\n");return 0;}\n'
with tempfile.TemporaryDirectory(prefix="ksword_return_contracts_") as temp:
    folder = Path(temp)
    (folder / "fixture.cpp").write_text(cpp, encoding="utf-8")
    subprocess.run(["cl", "/nologo", "/EHsc", "/std:c++17", str(folder / "fixture.cpp"),
                    "/Fe:" + str(folder / "fixture.exe"), "/Fo:" + str(folder / "fixture.obj")], check=True)
    subprocess.run([str(folder / "fixture.exe")], check=True, timeout=30)

source = r'''
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdio>
int wmain(int argc,wchar_t** argv){if(argc!=2)return 1;printf("%lu\n",GetCurrentProcessId());fflush(stdout);
 for(int c;(c=getchar())!=EOF;){
  if(c=='L'){if(!LoadLibraryW(argv[1]))return 2;}
  if(c=='X'){
   DWORD errors[4]{};SetLastError(1234);
   if(CreateNamedPipeW(L"invalid_owned_fixture",PIPE_ACCESS_DUPLEX,PIPE_TYPE_BYTE,1,4096,4096,0,nullptr)!=INVALID_HANDLE_VALUE)return 10;errors[0]=GetLastError();
   if(CreateNamedPipeA("invalid_owned_fixture",PIPE_ACCESS_DUPLEX,PIPE_TYPE_BYTE,1,4096,4096,0,nullptr)!=INVALID_HANDLE_VALUE)return 11;errors[1]=GetLastError();
   if(CreateMailslotW(L"invalid_owned_fixture",0,0,nullptr)!=INVALID_HANDLE_VALUE)return 12;errors[2]=GetLastError();
   if(CreateMailslotA("invalid_owned_fixture",0,0,nullptr)!=INVALID_HANDLE_VALUE)return 13;errors[3]=GetLastError();
   printf("%lu %lu %lu %lu\n",errors[0],errors[1],errors[2],errors[3]);fflush(stdout);
  }if(c=='Q')return 0;
 }return 0;
}
'''
with LiveFixture(source) as fixture:
    fixture.wait_for(lambda f: bool(f.snapshots) and any(e.api == "HooksInstalled" for e in f.events))
    fixture.command("X")
    installed = {r.api for r in fixture.snapshots[-1][1] if r.api in names and r.state in (0, 1)}
    assert installed, "at least one real creation entry must be available"
    fixture.wait_for(lambda f: installed <= {e.api for e in f.events})
    errors = [int(value) for value in fixture.process.stdout.readline().split()]
    assert len(errors) == 4 and all(errors)
    assert all(next(e.result for e in fixture.events if e.api == name) == errors[index]
               for index, name in enumerate(names) if name in installed)
print("PASS: INVALID_HANDLE_VALUE creation failures preserve return/error values and report actual failure status")
