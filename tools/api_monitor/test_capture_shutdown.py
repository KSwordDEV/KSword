"""Production CLI reader drains EOF and detects missing final coverage/truncated packets."""
from pathlib import Path
import os
import subprocess
import tempfile

if os.environ.get("KSWORD_APIMON_ARCH") == "x86":
    print("SKIP: capture host is x64; x86 CLI uses the unsupported-host stub")
    raise SystemExit(0)
root = Path(__file__).resolve().parents[2]
capture = (root / "shared/ApiMonitorCapture.cpp").read_text(encoding="utf-8-sig")
helpers = capture[capture.index("struct Handle {"):capture.index("std::wstring uniqueSession()")]
reader = capture[capture.index("struct Reader {"):capture.index("class Capture {")]
methods = capture[capture.index("void Capture::consume("):capture.index("void Capture::discoverChildren()")]
source = r'''
#define NOMINMAX
#include "CAPTURE_HEADER"
#include "PLATFORM_HEADER"
#include <algorithm>
#include <cstdio>
#include <cwchar>
namespace ks::winapi_monitor {
HELPERS
READER
class Capture {
public:
 CaptureRequest request;
 CaptureResult result;
 bool stopping=false;
 std::vector<DWORD> pendingChildren;
 void error(const std::wstring& value){result.errors.push_back(value);}
 void consume(Reader&,const ApiMonitorEventPacket&);
 void pollReader(Reader&);
};
METHODS
}
using namespace ks::winapi_monitor;
#define CHECK(x) do{if(!(x)){printf("FAIL %d %s\n",__LINE__,#x);return 1;}}while(0)
int run(unsigned mode){
 const auto name=L"\\\\.\\pipe\\KswordCaptureClose_"+std::to_wstring(GetCurrentProcessId());
 HANDLE server=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_OUTBOUND,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT,1,65536,65536,0,nullptr);
 CHECK(server!=INVALID_HANDLE_VALUE);
 Reader reader;reader.evidence.pid=GetCurrentProcessId();reader.evidence.session=123;
 reader.process.reset(OpenProcess(SYNCHRONIZE,FALSE,GetCurrentProcessId()));
 reader.receiver=std::make_unique<CoverageSnapshotReceiver>(reader.evidence.pid,123);
 reader.pipe.reset(CreateFileW(name.c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr));
 CHECK(reader.pipe.value!=INVALID_HANDLE_VALUE);CHECK(ConnectNamedPipe(server,nullptr)||GetLastError()==ERROR_PIPE_CONNECTED);
 Capture capture;ApiMonitorEventPacket packet{};packet.pid=reader.evidence.pid;packet.sessionIdentity=123;
 packet.category=static_cast<unsigned>(EventCategory::Internal);wcscpy_s(packet.moduleName,L"Agent");wcscpy_s(packet.apiName,L"HooksRemoved");packet.snapshotRevision=mode==1?8:7;
 DWORD count=0;
 if(mode==4){wcscpy_s(packet.apiName,L"AgentFailure");CHECK(WriteFile(server,&packet,sizeof(packet),&count,nullptr));wcscpy_s(packet.apiName,L"HooksRemoved");}
 if(mode!=3)CHECK(WriteFile(server,&packet,sizeof(packet),&count,nullptr)&&count==sizeof(packet));
 packet.snapshotRevision=7;packet.eventKind=static_cast<unsigned>(EventKind::CoverageBegin);
 CHECK(WriteFile(server,&packet,sizeof(packet),&count,nullptr));
 packet.eventKind=static_cast<unsigned>(EventKind::CoverageEnd);
 CHECK(WriteFile(server,&packet,sizeof(packet),&count,nullptr));
 if(mode==2)CHECK(WriteFile(server,&packet,17,&count,nullptr));
 CloseHandle(server);
 for(unsigned i=0;i<20&&!reader.disconnected;++i){capture.pollReader(reader);Sleep(1);}
 CHECK(reader.disconnected&&reader.evidence.coverageComplete&&reader.evidence.revision==7);
 if(mode==0)CHECK(!reader.evidence.coverageStale&&!reader.evidence.pipeError&&reader.evidence.finalRevision==7);
 if(mode==1)CHECK(reader.evidence.coverageStale&&!reader.evidence.pipeError&&reader.evidence.finalRevision==8);
 if(mode==2)CHECK(reader.evidence.coverageStale&&reader.evidence.pipeError&&capture.result.invalidPackets==1);
 if(mode==3)CHECK(reader.evidence.coverageStale&&reader.evidence.pipeError&&!reader.evidence.removed);
 if(mode==4)CHECK(!capture.result.errors.empty()&&reader.evidence.removed);
 return 0;
}
int main(){for(unsigned mode=0;mode<5;++mode)if(run(mode))return 1;
 puts("PASS: production capture EOF, final revision mismatch, truncated packet and premature close");}
'''
source = (source.replace("CAPTURE_HEADER", (root / "shared/ApiMonitorCapture.h").as_posix())
          .replace("PLATFORM_HEADER", (root / "shared/ApiMonitorInjection.h").as_posix())
          .replace("HELPERS", helpers).replace("READER", reader).replace("METHODS", methods))
with tempfile.TemporaryDirectory(prefix="ksword_capture_close_") as temporary:
    folder = Path(temporary)
    cpp = folder / "fixture.cpp"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["cl", "/nologo", "/EHsc", "/std:c++20", "/utf-8", str(cpp),
                    "/Fe:" + str(folder / "fixture.exe"), "/Fo:" + str(folder / "fixture.obj"),
                    "/link", "Advapi32.lib"], check=True)
    subprocess.run([str(folder / "fixture.exe")], check=True, timeout=15)
