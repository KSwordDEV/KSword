from pathlib import Path
import os
from live_fixture_support import LiveFixture
root=Path(__file__).resolve().parents[2]
arch=os.environ.get("KSWORD_APIMON_ARCH","x64")
agent=Path(os.environ.get("KSWORD_APIMON_TEST_AGENT_DIR", str(root / "Ksword5.1/x64/Release"))) / ("APIMonitor_"+arch+".dll")
source=r"""
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <Windows.h>
#include <cstdio>
static int Test(int* first, int* second, int* fail) {
 WSASetLastError(4242); SOCKET s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); *first=WSAGetLastError();
 if(s==INVALID_SOCKET)return 10;
 WSASetLastError(4243); int v=closesocket(s); *second=WSAGetLastError(); if(v)return 11;
 WSASetLastError(4244); v=send(INVALID_SOCKET,"x",1,0); *fail=WSAGetLastError(); if(v!=SOCKET_ERROR)return 12;
 return 0;
}
int wmain(int argc,wchar_t** argv){
 if(argc!=2)return 1; WSADATA d{}; if(WSAStartup(MAKEWORD(2,2),&d))return 2;
 int a=0,b=0,c=0; if(Test(&a,&b,&c))return 3; printf("%lu\n",GetCurrentProcessId());fflush(stdout);
 for(int ch;(ch=getchar())!=EOF;){if(ch=='L'&&!LoadLibraryW(argv[1]))return 4;
 if(ch=='X'){int x=0,y=0,z=0; if(Test(&x,&y,&z))return 5; printf("VALUES %d %d %d %d %d %d\n",a,b,c,x,y,z);fflush(stdout);}
 if(ch=='Q'){WSACleanup();return 0;}}return 0;
}
"""
with LiveFixture(source, {'enable_file':0,'enable_network':1}, agent=agent) as fixture:
    # The constructor consumes PID, so baseline must be provided separately.
    fixture.wait_for(lambda f:any(e.api=='HooksInstalled' for e in f.events))
    fixture.command('X')
    line=fixture.process.stdout.readline().decode().strip()
    assert line.startswith('VALUES '),line
    values=list(map(int,line.split()[1:]))
    assert values[:3]==values[3:] and values[2]==10038,values
    fixture.wait_for(lambda f: all(any(e.api==name and e.kind==0 for e in f.events) for name in ('socket','closesocket','send')))
print('PASS live socket/send success and failure errors')
