from pathlib import Path
import os
"""Discover all seven actual provider functions and exercise TCP/UDP loopback traffic."""
from live_fixture_support import LiveFixture

def candidate_agent():
    root = Path(__file__).resolve().parents[2]
    architecture = os.environ.get("KSWORD_APIMON_ARCH", "x64")
    folder = Path(os.environ.get("KSWORD_APIMON_TEST_AGENT_DIR", str(root / "Ksword5.1/x64/Release")))
    return folder / ("APIMonitor_" + architecture + ".dll")


source = r'''
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <mswsock.h>
#include <Windows.h>
#include <cstdio>
#include <cstring>
static unsigned callbacks=0;static OVERLAPPED* expected=nullptr;static bool bad=false;
void CALLBACK Done(DWORD error,DWORD bytes,OVERLAPPED* ov,DWORD flags){if(error||bytes!=8||ov!=expected||flags)bad=true;++callbacks;}
template<class T>bool Get(SOCKET socket,GUID guid,T& function){DWORD bytes=0; OVERLAPPED ov{};ov.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr); int r=WSAIoctl(socket,SIO_GET_EXTENSION_FUNCTION_POINTER,&guid,sizeof(guid),&function,sizeof(function),&bytes,&ov,nullptr);CloseHandle(ov.hEvent);return r==0&&bytes==sizeof(function)&&function;}
bool Wait(SOCKET socket,OVERLAPPED& ov,DWORD expectedBytes){DWORD bytes=0,flags=0;return WSAGetOverlappedResult(socket,&ov,&bytes,TRUE,&flags)&&bytes==expectedBytes;}
int Run(){
 WSADATA wsa{};if(WSAStartup(MAKEWORD(2,2),&wsa))return 10;
 SOCKET listener=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,nullptr,0,WSA_FLAG_OVERLAPPED);
 SOCKET accepted=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,nullptr,0,WSA_FLAG_OVERLAPPED);
 SOCKET client=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,nullptr,0,WSA_FLAG_OVERLAPPED);
 LPFN_ACCEPTEX acceptEx=nullptr,again=nullptr;LPFN_CONNECTEX connectEx=nullptr;
 LPFN_GETACCEPTEXSOCKADDRS addresses=nullptr;LPFN_TRANSMITFILE transmitFile=nullptr;LPFN_TRANSMITPACKETS transmitPackets=nullptr;
 LPFN_WSARECVMSG receiveMsg=nullptr;LPFN_WSASENDMSG sendMsg=nullptr;
 if(!Get(listener,GUID WSAID_ACCEPTEX,acceptEx)||!Get(listener,GUID WSAID_ACCEPTEX,again)||again!=acceptEx)return 11;
 if(!Get(client,GUID WSAID_CONNECTEX,connectEx)||!Get(listener,GUID WSAID_GETACCEPTEXSOCKADDRS,addresses))return 12;
 if(!Get(client,GUID WSAID_TRANSMITFILE,transmitFile)||!Get(client,GUID WSAID_TRANSMITPACKETS,transmitPackets))return 13;
 if(!Get(client,GUID WSAID_WSARECVMSG,receiveMsg)||!Get(client,GUID WSAID_WSASENDMSG,sendMsg))return 14;
 sockaddr_in local{};local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 if(bind(listener,reinterpret_cast<sockaddr*>(&local),sizeof(local))||listen(listener,1))return 15;
 int length=sizeof(local);getsockname(listener,reinterpret_cast<sockaddr*>(&local),&length);
 sockaddr_in any{};any.sin_family=AF_INET;any.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 if(bind(client,reinterpret_cast<sockaddr*>(&any),sizeof(any)))return 16;
 char buffer[128]{};OVERLAPPED acceptedOv{},connectedOv{};
 acceptedOv.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);connectedOv.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);DWORD bytes=0;
 if(!acceptEx(listener,accepted,buffer,0,32,32,&bytes,&acceptedOv)&&WSAGetLastError()!=WSA_IO_PENDING)return 17;
 if(!connectEx(client,reinterpret_cast<sockaddr*>(&local),length,nullptr,0,&bytes,&connectedOv)&&WSAGetLastError()!=WSA_IO_PENDING)return 18;
 if(!Wait(listener,acceptedOv,0)||!Wait(client,connectedOv,0))return 19;
 setsockopt(accepted,SOL_SOCKET,SO_UPDATE_ACCEPT_CONTEXT,reinterpret_cast<char*>(&listener),sizeof(listener));
 setsockopt(client,SOL_SOCKET,SO_UPDATE_CONNECT_CONTEXT,nullptr,0);
 sockaddr* localResult=nullptr; sockaddr* remoteResult=nullptr;int localSize=0,remoteSize=0;
 WSASetLastError(1234);addresses(buffer,0,32,32,&localResult,&localSize,&remoteResult,&remoteSize);
 if(!localResult||!remoteResult||localResult->sa_family!=AF_INET||remoteResult->sa_family!=AF_INET||localSize!=sizeof(sockaddr_in)||remoteSize!=sizeof(sockaddr_in)||WSAGetLastError()!=1234)return 20;
 WCHAR dir[MAX_PATH]{},path[MAX_PATH]{};GetTempPathW(MAX_PATH,dir);GetTempFileNameW(dir,L"kse",0,path);
 HANDLE file=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_DELETE_ON_CLOSE,nullptr);if(file==INVALID_HANDLE_VALUE)return 21;
 char data[8]="fixture";WriteFile(file,data,8,&bytes,nullptr);SetFilePointer(file,0,nullptr,FILE_BEGIN);
 OVERLAPPED transmitted{};transmitted.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
 if(!transmitFile(client,file,8,0,&transmitted,nullptr,0)&&WSAGetLastError()!=WSA_IO_PENDING)return 22;
 if(!Wait(client,transmitted,8)||recv(accepted,buffer,8,MSG_WAITALL)!=8||memcmp(buffer,data,8))return 23;
 TRANSMIT_PACKETS_ELEMENT packet{};packet.dwElFlags=TP_ELEMENT_MEMORY|TP_ELEMENT_EOP;packet.cLength=8;packet.pBuffer=data;
 OVERLAPPED packetsOv{};packetsOv.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
 if(!transmitPackets(client,&packet,1,0,&packetsOv,0)&&WSAGetLastError()!=WSA_IO_PENDING)return 24;
 if(!Wait(client,packetsOv,8)||recv(accepted,buffer,8,MSG_WAITALL)!=8||memcmp(buffer,data,8))return 25;
 SOCKET udpRead=WSASocketW(AF_INET,SOCK_DGRAM,IPPROTO_UDP,nullptr,0,WSA_FLAG_OVERLAPPED),udpWrite=WSASocketW(AF_INET,SOCK_DGRAM,IPPROTO_UDP,nullptr,0,WSA_FLAG_OVERLAPPED);
 any.sin_port=0;if(bind(udpRead,reinterpret_cast<sockaddr*>(&any),sizeof(any)))return 26;
 length=sizeof(any);getsockname(udpRead,reinterpret_cast<sockaddr*>(&any),&length);
 LPFN_WSASENDMSG udpSend=nullptr;if(!Get(udpWrite,GUID WSAID_WSASENDMSG,udpSend))return 27;
 WSABUF readBuffer{8,buffer},writeBuffer{8,data};sockaddr_in from{};
 WSAMSG readMessage{};readMessage.name=reinterpret_cast<sockaddr*>(&from);readMessage.namelen=sizeof(from);readMessage.lpBuffers=&readBuffer;readMessage.dwBufferCount=1;
 WSAMSG writeMessage{};writeMessage.name=reinterpret_cast<sockaddr*>(&any);writeMessage.namelen=sizeof(any);writeMessage.lpBuffers=&writeBuffer;writeMessage.dwBufferCount=1;
 OVERLAPPED recvOv{},sendOv{};sendOv.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);expected=&recvOv;
 if(receiveMsg(udpRead,&readMessage,&bytes,&recvOv,Done)&&WSAGetLastError()!=WSA_IO_PENDING)return 28;
 if(udpSend(udpWrite,&writeMessage,0,&bytes,&sendOv,nullptr)&&WSAGetLastError()!=WSA_IO_PENDING)return 29;
 if(!Wait(udpWrite,sendOv,8))return 30;
 for(unsigned i=0;!callbacks&&i<100;++i)SleepEx(50,TRUE);if(callbacks!=1||bad||memcmp(buffer,data,8))return 31;
 CloseHandle(acceptedOv.hEvent);CloseHandle(connectedOv.hEvent);CloseHandle(transmitted.hEvent);CloseHandle(packetsOv.hEvent);CloseHandle(sendOv.hEvent);CloseHandle(file);
 closesocket(udpRead);closesocket(udpWrite);closesocket(accepted);closesocket(client);closesocket(listener);WSACleanup();return 0;
}
int wmain(int argc,wchar_t** argv){if(argc!=2)return 1;printf("%lu\n",GetCurrentProcessId());fflush(stdout);
 for(int c;(c=getchar())!=EOF;){if(c=='L'){if(!LoadLibraryW(argv[1]))return 2;}if(c=='X'){int result=Run();if(result)return result;printf("DONE\n");fflush(stdout);}if(c=='Q')return 0;}return 0;}
'''
with LiveFixture(source, {"enable_network": 1}, agent=candidate_agent()) as fixture:
    fixture.wait_for(lambda f: bool(f.snapshots) and any(e.api == "HooksInstalled" for e in f.events))
    initial = [r for r in fixture.snapshots[-1][1] if r.hook_kind == 3]
    assert len(initial) == 7 and all(r.state == 3 for r in initial)
    fixture.command("X")
    names = {"AcceptEx", "ConnectEx", "WSARecvMsg", "WSASendMsg", "TransmitFile", "TransmitPackets", "GetAcceptExSockaddrs"}
    fixture.wait_for(lambda f: names <= {e.api for e in f.events})
    assert fixture.process.stdout.readline().strip() == b"DONE"
    fixture.wait_for(lambda f: names <= {r.api for r in f.snapshots[-1][1] if r.hook_kind == 3 and r.state in (0, 1)})
    rows = [r for r in fixture.snapshots[-1][1] if r.hook_kind == 3]
    assert len(rows) == len({(r.api_id, r.address) for r in rows}), "same-address discovery is idempotent"
    assert all(635 <= e.api_id <= 641 and e.detail for e in fixture.events if e.api in names)
    for api in ("WSARecvMsg", "WSASendMsg"):
        rows = [e for e in fixture.events if e.api == api and e.kind == 0]
        assert rows and "bytes=unknown" in rows[0].detail, (api, [e.detail for e in rows])
    assert "flags=unknown" in next(e.detail for e in fixture.events if e.api == "WSARecvMsg" and e.kind == 0)
    ioctl = [e for e in fixture.events if e.api == "WSAIoctl" and e.kind == 0]
    assert ioctl and any("returned=" + str(8 if os.environ.get("KSWORD_APIMON_ARCH", "x64") == "x64" else 4) in e.detail for e in ioctl), [e.detail for e in ioctl]

    fixture.wait_for(lambda f: len([e for e in f.events if e.api in names and e.kind == 3]) >= 6)
print("PASS: seven real Winsock extensions, stable returned pointers, repeated discovery, TCP/UDP and async completions")
