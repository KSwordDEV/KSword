"""Production worker boundary contains allocation failures and never fakes cleanup success."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
agent = (root / "APIMonitor_x64/MonitorAgent.cpp").read_text(encoding="utf-8-sig")
boundary = agent[agent.index("        DWORD WINAPI MonitorWorkerBody(LPVOID parameterValue);"):agent.index("        DWORD WINAPI MonitorWorkerBody(LPVOID parameterValue)\n")]
source = r'''
#include "PROTOCOL"
#include <new>
#include <stdexcept>
#include <cstdio>
namespace apimon {
static unsigned mode=0,attempts=0,events=0,removedEvents=0,drains=0,stops=0;
static bool requested=false;
static constexpr DWORD kSessionActivePollMs=1;
struct ScopedInlineHookInternalBypass {};
void RequestStop(){requested=true;}
bool SendMonitorEventRaw(ks::winapi_monitor::EventCategory,const wchar_t*,const wchar_t*,DWORD,const wchar_t*){++events;return true;}
bool UninstallConfiguredHooks(){++attempts;return mode!=3&&attempts>1;}
void SendHooksRemovedEvent(const wchar_t*){++removedEvents;}
bool DrainMonitorPipeServer(){++drains;return true;}
void StopMonitorPipeServer(){++stops;}
BOUNDARY
DWORD WINAPI MonitorWorkerBody(LPVOID){if(!mode)return 17;if(mode==2)throw std::runtime_error("fixture");throw std::bad_alloc();}
}
#define CHECK(x) do{if(!(x)){printf("FAIL %d %s\n",__LINE__,#x);return 1;}}while(0)
int main(){using namespace apimon;
 CHECK(MonitorWorkerThread(nullptr)==17&&!requested&&!events);
 for(mode=1;mode<=3;++mode){attempts=events=removedEvents=drains=stops=0;requested=false;
  const auto result=MonitorWorkerThread(nullptr);
  CHECK(result==(mode==2?ERROR_UNHANDLED_EXCEPTION:ERROR_NOT_ENOUGH_MEMORY));
  CHECK(requested&&events==1&&drains==1&&stops==1);
  CHECK(mode==3?(attempts==3&&removedEvents==0):(attempts==2&&removedEvents==1));
 }
 puts("PASS: allocation/unknown worker exceptions contained; safe restoration retried; failed cleanup never acknowledged");
}
'''.replace("PROTOCOL", (root / "shared/WinApiMonitorProtocol.h").as_posix()).replace("BOUNDARY", boundary)
with tempfile.TemporaryDirectory(prefix="ksword_worker_failure_") as temporary:
    folder = Path(temporary)
    cpp = folder / "fixture.cpp"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["cl", "/nologo", "/EHsc", "/std:c++17", "/utf-8", str(cpp),
                    "/Fe:" + str(folder / "fixture.exe"), "/Fo:" + str(folder / "fixture.obj")], check=True)
    subprocess.run([str(folder / "fixture.exe")], check=True, timeout=10)
