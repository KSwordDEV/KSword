from pathlib import Path
import os
"""Real x64 file, completion-port, APC, cancellation and loopback socket requests."""
from collections import defaultdict
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
static unsigned callbacks=0;static OVERLAPPED* expected=nullptr;static bool badCallback=false;
static HANDLE callbackFile=nullptr;static OVERLAPPED late{};static char data[16]="fixture";
void CALLBACK FileDone(DWORD error,DWORD bytes,OVERLAPPED* ov){if(error||bytes!=8||ov!=expected)badCallback=true;++callbacks;}
void CALLBACK SocketDone(DWORD error,DWORD bytes,OVERLAPPED* ov,DWORD flags){if(error||bytes!=8||ov!=expected||flags)badCallback=true;++callbacks;}
int Run(){
 WCHAR directory[MAX_PATH]{},path[MAX_PATH]{};GetTempPathW(MAX_PATH,directory);GetTempFileNameW(directory,L"ksm",0,path);
 HANDLE file=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|FILE_FLAG_DELETE_ON_CLOSE,nullptr);
 if(file==INVALID_HANDLE_VALUE)return 10;
 HANDLE port=CreateIoCompletionPort(file,nullptr,123,0);if(!port)return 11;
 OVERLAPPED write{};DWORD bytes=0;ULONG_PTR key=0;OVERLAPPED* completed=nullptr;
 BOOL result=WriteFile(file,data,8,&bytes,&write);if(!result&&GetLastError()!=ERROR_IO_PENDING)return 12;
 if(!GetQueuedCompletionStatus(port,&bytes,&key,&completed,5000)||completed!=&write||bytes!=8||key!=123)return 13;
 if(!GetOverlappedResult(file,&write,&bytes,TRUE)||bytes!=8)return 14;
 if(!GetOverlappedResultEx(file,&write,&bytes,5000,FALSE)||bytes!=8)return 15;
 OVERLAPPED read{};char received[16]{};result=ReadFile(file,received,8,&bytes,&read);if(!result&&GetLastError()!=ERROR_IO_PENDING)return 16;
 OVERLAPPED_ENTRY entries[4]{};ULONG removed=0;
 if(!GetQueuedCompletionStatusEx(port,entries,4,&removed,5000,FALSE)||removed!=1||entries[0].lpOverlapped!=&read||entries[0].dwNumberOfBytesTransferred!=8||memcmp(data,received,8))return 17;
 if(!SetFileCompletionNotificationModes(file,FILE_SKIP_COMPLETION_PORT_ON_SUCCESS))return 18;
 OVERLAPPED skip{};result=WriteFile(file,data,8,&bytes,&skip);if(!result){if(GetLastError()!=ERROR_IO_PENDING)return 19;if(!GetQueuedCompletionStatus(port,&bytes,&key,&completed,5000))return 20;}
 callbackFile=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);
 if(callbackFile==INVALID_HANDLE_VALUE)return 21;
 OVERLAPPED exWrite{};expected=&exWrite;unsigned before=callbacks;
 if(!WriteFileEx(callbackFile,data,8,&exWrite,FileDone))return 22;
 for(unsigned i=0;callbacks==before&&i<100;++i)SleepEx(50,TRUE);if(callbacks!=before+1||badCallback)return 23;
 OVERLAPPED exRead{};expected=&exRead;before=callbacks;
 if(!ReadFileEx(callbackFile,received,8,&exRead,FileDone))return 24;
 for(unsigned i=0;callbacks==before&&i<100;++i)SleepEx(50,TRUE);if(callbacks!=before+1||badCallback)return 25;
 WCHAR pipeName[128]{};swprintf_s(pipeName,L"\\\\.\\pipe\\KswordOwnedAsync_%lu",GetCurrentProcessId());
 HANDLE server=CreateNamedPipeW(pipeName,PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED,PIPE_TYPE_BYTE|PIPE_WAIT,1,4096,4096,0,nullptr);
 HANDLE client=CreateFileW(pipeName,GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);if(server==INVALID_HANDLE_VALUE||client==INVALID_HANDLE_VALUE)return 26;
 OVERLAPPED cancel{};cancel.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
 if(ReadFile(server,received,8,&bytes,&cancel)||GetLastError()!=ERROR_IO_PENDING)return 27;
 if(!CancelIoEx(server,&cancel))return 28;
 if(GetOverlappedResult(server,&cancel,&bytes,TRUE)||GetLastError()!=ERROR_OPERATION_ABORTED)return 29;
 ResetEvent(cancel.hEvent);if(ReadFile(server,received,8,&bytes,&cancel)||GetLastError()!=ERROR_IO_PENDING)return 30;
 if(!CancelIo(server))return 31;
 if(GetOverlappedResult(server,&cancel,&bytes,TRUE)||GetLastError()!=ERROR_OPERATION_ABORTED)return 32;
 CloseHandle(cancel.hEvent);CloseHandle(client);CloseHandle(server);CloseHandle(file);CloseHandle(port);
 WSADATA wsa{};if(WSAStartup(MAKEWORD(2,2),&wsa))return 33;
 SOCKET listener=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,nullptr,0,WSA_FLAG_OVERLAPPED),sender=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,nullptr,0,WSA_FLAG_OVERLAPPED);
 sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 if(bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address))||listen(listener,1))return 34;
 int size=sizeof(address);getsockname(listener,reinterpret_cast<sockaddr*>(&address),&size);if(connect(sender,reinterpret_cast<sockaddr*>(&address),size))return 35;
 SOCKET receiver=accept(listener,nullptr,nullptr);if(receiver==INVALID_SOCKET)return 36;
 OVERLAPPED socketRead{},socketWrite{};socketRead.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);socketWrite.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
 WSABUF input{8,received},output{8,data};DWORD flags=0;
 int request=WSARecv(receiver,&input,1,&bytes,&flags,&socketRead,nullptr);if(request&&WSAGetLastError()!=WSA_IO_PENDING)return 37;
 request=WSASend(sender,&output,1,&bytes,0,&socketWrite,nullptr);if(request&&WSAGetLastError()!=WSA_IO_PENDING)return 38;
 if(!WSAGetOverlappedResult(receiver,&socketRead,&bytes,TRUE,&flags)||bytes!=8||flags||memcmp(data,received,8))return 39;
 if(!WSAGetOverlappedResult(sender,&socketWrite,&bytes,TRUE,&flags)||bytes!=8)return 40;
 OVERLAPPED socketCallback{};expected=&socketCallback;before=callbacks;flags=0;
 request=WSARecv(receiver,&input,1,&bytes,&flags,&socketCallback,SocketDone);if(request&&WSAGetLastError()!=WSA_IO_PENDING)return 41;
 if(send(sender,data,8,0)!=8)return 42;
 for(unsigned i=0;callbacks==before&&i<100;++i)SleepEx(50,TRUE);if(callbacks!=before+1||badCallback)return 43;
 CloseHandle(socketRead.hEvent);CloseHandle(socketWrite.hEvent);closesocket(receiver);closesocket(sender);closesocket(listener);WSACleanup();
 return 0;
}
int wmain(int argc,wchar_t** argv){
 if(argc!=2)return 1;printf("%lu\n",GetCurrentProcessId());fflush(stdout);
 for(int c;(c=getchar())!=EOF;){
  if(c=='L'){if(!LoadLibraryW(argv[1]))return 2;}
  if(c=='X'){int result=Run();if(result)return result;printf("DONE\n");fflush(stdout);}
  if(c=='P'){expected=&late;if(!ReadFileEx(callbackFile,data,8,&late,FileDone))return 44;printf("QUEUED\n");fflush(stdout);}
  if(c=='A'){unsigned before=callbacks;for(unsigned i=0;callbacks==before&&i<100;++i)SleepEx(50,TRUE);if(callbacks!=before+1||badCallback)return 45;CloseHandle(callbackFile);printf("FORWARDED\n");fflush(stdout);}
  if(c=='Q')return 0;
 }return 0;
}
'''
with LiveFixture(source, {"enable_network": 1}, agent=candidate_agent()) as fixture:
    fixture.wait_for(lambda f: bool(f.snapshots) and any(e.api == "HooksInstalled" for e in f.events))
    fixture.command("X")
    fixture.wait_for(lambda f: any(e.api == "WSARecv" and e.kind == 3 for e in f.events))
    assert fixture.process.stdout.readline().strip() == b"DONE"
    fixture.wait_for(lambda f: len([e for e in f.events if e.kind == 3]) >= 10)
    metric_names = ("WSASocketW", "WSASend", "WSARecv", "send", "WSAGetOverlappedResult", "closesocket", "ReadFileEx", "WriteFileEx")
    fixture.wait_for(lambda f: all(any(e.kind == 0 and e.api == name for e in f.events) for name in metric_names))
    for name in metric_names:
        rows = [e for e in fixture.events if e.kind == 0 and e.api == name]
        assert any(e.index == 0x52545631 and e.count == 0x44555231 and e.revision < 600000000 for e in rows), name
    for name in ("ReadFileEx", "WriteFileEx"):
        calls = [e for e in fixture.events if e.kind == 0 and e.api == name]
        assert calls and calls[0].operation != 0, name
        assert any(e.kind == 1 and e.operation == calls[0].operation for e in fixture.events), name
    operations = defaultdict(list)
    for event in fixture.events:
        if event.operation:
            operations[event.operation].append(event)
    assert len(operations) >= 10
    for events in operations.values():
        assert events[0].kind == 1, "submission must precede racing completion"
        assert len([e for e in events if e.kind == 3]) == 1, f"exactly one completion per observed request: {[(e.api,e.operation,e.kind,e.result) for e in events]}"
        assert len({e.api_id for e in events}) == 1
    assert len([e for e in fixture.events if e.kind == 3 and e.result == 995]) == 2
    assert len([e for e in fixture.events if e.kind == 4]) == 2
    fixture.command("P")
    fixture.wait_for(lambda f: len([e for e in f.events if e.api == "ReadFileEx" and e.kind == 1]) >= 2)
    assert fixture.process.stdout.readline().strip() == b"QUEUED"
    fixture.stop.write_text("stop")
    fixture.wait_for(lambda f: any(e.api == "HooksRemoved" for e in f.events))
    fixture.command("A")
    assert fixture.process.stdout.readline().strip() == b"FORWARDED"
print("PASS: real file/IOCP/APC/cancel/loopback requests, unique completion IDs and application callback after stop")
