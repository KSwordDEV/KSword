from pathlib import Path
import os
"""Owned UDP overlapped requests retain endpoint details and completion callbacks."""
from live_fixture_support import LiveFixture

def candidate_agent():
    root = Path(__file__).resolve().parents[2]
    architecture = os.environ.get("KSWORD_APIMON_ARCH", "x64")
    folder = Path(os.environ.get("KSWORD_APIMON_TEST_AGENT_DIR", str(root / "Ksword5.1/x64/Release")))
    return folder / ("APIMonitor_" + architecture + ".dll")


source = r'''
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <Windows.h>
#include <cstdio>
#include <cstring>
static unsigned callbacks=0;static OVERLAPPED* expected=nullptr;static bool bad=false;
void CALLBACK Done(DWORD error,DWORD bytes,OVERLAPPED* ov,DWORD flags){bad=error||bytes!=8||ov!=expected||flags;++callbacks;}
int Run(){WSADATA wsa{};if(WSAStartup(MAKEWORD(2,2),&wsa))return 10;
 SOCKET receiver=WSASocketW(AF_INET,SOCK_DGRAM,IPPROTO_UDP,nullptr,0,WSA_FLAG_OVERLAPPED),sender=WSASocketW(AF_INET,SOCK_DGRAM,IPPROTO_UDP,nullptr,0,WSA_FLAG_OVERLAPPED);
 sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 if(bind(receiver,reinterpret_cast<sockaddr*>(&address),sizeof(address)))return 11;
 int size=sizeof(address);if(getsockname(receiver,reinterpret_cast<sockaddr*>(&address),&size))return 12;
 char input[8]{},output[8]="fixture";WSABUF receive{8,input},sendBuffer{8,output};DWORD bytes=0,flags=0;
 sockaddr_in from{};int fromLength=sizeof(from);OVERLAPPED read{},write{};expected=&read;
 write.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
 if(WSARecvFrom(receiver,&receive,1,&bytes,&flags,reinterpret_cast<sockaddr*>(&from),&fromLength,&read,Done)!=SOCKET_ERROR||WSAGetLastError()!=WSA_IO_PENDING)return 13;
 int result=WSASendTo(sender,&sendBuffer,1,&bytes,0,reinterpret_cast<sockaddr*>(&address),size,&write,nullptr);
 if(result&&WSAGetLastError()!=WSA_IO_PENDING)return 14;
 if(!WSAGetOverlappedResult(sender,&write,&bytes,TRUE,&flags)||bytes!=8||flags)return 15;
 for(unsigned i=0;!callbacks&&i<100;++i)SleepEx(50,TRUE);
 if(callbacks!=1||bad||fromLength!=sizeof(from)||from.sin_addr.s_addr!=htonl(INADDR_LOOPBACK)||memcmp(input,output,8))return 16;
 CloseHandle(write.hEvent);closesocket(receiver);closesocket(sender);WSACleanup();return 0;}
int wmain(int argc,wchar_t** argv){if(argc!=2)return 1;printf("%lu\n",GetCurrentProcessId());fflush(stdout);
 for(int c;(c=getchar())!=EOF;){if(c=='L'){if(!LoadLibraryW(argv[1]))return 2;}if(c=='X'){int result=Run();if(result)return result;printf("DONE\n");fflush(stdout);}if(c=='Q')return 0;}return 0;}
'''
with LiveFixture(source, {"enable_file": 0, "enable_network": 1}, agent=candidate_agent()) as fixture:
    fixture.wait_for(lambda f: bool(f.snapshots) and any(e.api == "HooksInstalled" for e in f.events))
    fixture.command("X")
    fixture.wait_for(lambda f: all(any(e.api == api and e.kind == 3 for e in f.events)
                                 for api in ("WSARecvFrom", "WSASendTo")))
    assert fixture.process.stdout.readline().strip() == b"DONE"
    for api in ("WSARecvFrom", "WSASendTo"):
        call = next(e for e in fixture.events if e.api == api and e.kind == 0)
        submits = [e for e in fixture.events if e.api == api and e.kind == 1]
        completions = [e for e in fixture.events if e.api == api and e.kind == 3]
        assert len(submits) == len(completions) == 1
        assert "transferred=unknown" in call.detail, call.detail
        assert "bytes=unknown" in submits[0].detail, submits[0].detail
        assert submits[0].operation == completions[0].operation != 0
        assert completions[0].result == 0
        if "bytes=8" not in completions[0].detail:
            # Immediate success can leave bytes unobserved; later reuse makes
            # attribution unsafe, so retain the explicit unknown.
            assert api == "WSASendTo" and "bytes=unknown" in completions[0].detail, completions[0].detail
        endpoint = completions[0] if api == "WSARecvFrom" else call
        assert "remote=127.0.0.1:" in endpoint.detail, (api, endpoint.detail)
print("PASS: UDP endpoint capture, overlapped operation IDs and original completion callback")
