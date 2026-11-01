"""Production close routine: unread final coverage survives graceful server close."""
from pathlib import Path
import subprocess
import tempfile

root=Path(__file__).resolve().parents[2]
pipe=(root/"APIMonitor_x64/core/MonitorPipe.cpp").read_text(encoding="utf-8-sig")
begin=pipe.index("        void ClosePipeLocked(")
end=pipe.index("        // WritePendingPacketLocked",begin)
close=pipe[begin:end]
source=r'''
#define NOMINMAX
#include <Windows.h>
#include <atomic>
#include <thread>
#include <cstdio>
#include "COVERAGE"
#include "DIAGNOSTICS"
static std::atomic_uintptr_t g_pipeHandleValue{0};
static HANDLE g_pipeHandle=INVALID_HANDLE_VALUE;
CLOSE
using namespace ks::winapi_monitor;
int run(bool discard){
 const auto name=L"\\\\.\\pipe\\KswordCloseTest_"+std::to_wstring(GetCurrentProcessId())+(discard?L"_discard":L"_keep");
 HANDLE server=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_OUTBOUND,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT,1,65536,65536,0,nullptr);
 HANDLE written=CreateEventW(nullptr,TRUE,FALSE,nullptr),peeked=CreateEventW(nullptr,TRUE,FALSE,nullptr),closed=CreateEventW(nullptr,TRUE,FALSE,nullptr);
 std::atomic_bool writeOk{true};
 std::thread writer([&]{
  ConnectNamedPipe(server,nullptr);ApiMonitorEventPacket p{};p.pid=42;p.sessionIdentity=123;
  DWORD count=0;auto send=[&]{if(!WriteFile(server,&p,sizeof(p),&count,nullptr)||count!=sizeof(p))writeOk=false;};
  wcscpy_s(p.apiName,L"HooksRemoved");p.snapshotRevision=7;send();
  p.eventKind=static_cast<unsigned>(EventKind::CoverageBegin);p.snapshotCount=5;p.snapshotRevision=7;send();
  p.eventKind=static_cast<unsigned>(EventKind::CoverageItem);for(unsigned i=0;i<5;++i){p.snapshotIndex=i;send();}
  p.eventKind=static_cast<unsigned>(EventKind::CoverageEnd);p.snapshotIndex=5;send();
  SetEvent(written);WaitForSingleObject(peeked,10000);g_pipeHandle=server;g_pipeHandleValue=reinterpret_cast<uintptr_t>(server);
  ClosePipeLocked(discard);SetEvent(closed);
 });
 HANDLE client=CreateFileW(name.c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);ApiMonitorEventPacket p{};DWORD count=0;
 const bool removed=ReadFile(client,&p,sizeof(p),&count,nullptr)&&count==sizeof(p)&&wcscmp(p.apiName,L"HooksRemoved")==0;
 WaitForSingleObject(written,10000);DWORD available=0;const bool peekOk=PeekNamedPipe(client,nullptr,0,nullptr,&available,nullptr)!=FALSE;
 SetEvent(peeked);WaitForSingleObject(closed,10000);CoverageSnapshotReceiver receiver(42,123);unsigned packets=0;DWORD error=0;
 while(ReadFile(client,&p,sizeof(p),&count,nullptr)&&count){if(count!=sizeof(p)){error=ERROR_INVALID_DATA;break;}receiver.consume(p);++packets;}
 if(!error)error=GetLastError();CloseHandle(client);writer.join();CloseHandle(written);CloseHandle(peeked);CloseHandle(closed);
 printf("discard=%d peekBytes=%lu packets=%u complete=%d eofError=%lu\n",discard?1:0,available,packets,receiver.stale()?0:1,error);
 return !writeOk||!removed||!peekOk||available!=7000||(discard?(packets!=0||!receiver.stale()):(packets!=7||receiver.stale()||receiver.revision()!=7));
}
int main(){if(run(true)||run(false))return 1;puts("PASS: Peek/read disconnect race reproduced; graceful close retains final ordered snapshot");}
'''.replace("COVERAGE",(root/"shared/ApiMonitorCoverage.h").as_posix()).replace("DIAGNOSTICS",(root/"APIMonitor_x64/core/MonitorDiagnostics.h").as_posix()).replace("CLOSE",close)
with tempfile.TemporaryDirectory(prefix="ksword_pipe_shutdown_") as temporary:
    folder=Path(temporary);cpp=folder/"fixture.cpp";cpp.write_text(source,encoding="utf-8")
    subprocess.run(["cl","/nologo","/EHsc","/std:c++17","/utf-8",str(cpp),"/Fe:"+str(folder/"fixture.exe"),"/Fo:"+str(folder/"fixture.obj")],check=True)
    subprocess.run([str(folder/"fixture.exe")],check=True,timeout=30)
