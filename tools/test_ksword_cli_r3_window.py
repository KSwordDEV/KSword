"""Native window field failures, owner changes and request/readback semantics."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
BOOL WINAPI FixtureIsWindow(HWND);
DWORD WINAPI FixtureOwner(HWND,LPDWORD);
BOOL WINAPI FixtureInfo(HWND,PWINDOWINFO);
BOOL WINAPI FixtureRect(HWND,LPRECT);
LONG_PTR WINAPI FixtureLong(HWND,int);
int WINAPI FixtureLength(HWND);
int WINAPI FixtureTitle(HWND,LPWSTR,int);
int WINAPI FixtureClass(HWND,LPWSTR,int);
BOOL WINAPI FixtureVisible(HWND);
BOOL WINAPI FixtureEnabled(HWND);
BOOL WINAPI FixtureIconic(HWND);
BOOL WINAPI FixtureZoomed(HWND);
BOOL WINAPI FixtureUnicode(HWND);
BOOL WINAPI FixtureEnum(WNDENUMPROC,LPARAM);
BOOL WINAPI FixtureShow(HWND,int);
BOOL WINAPI FixtureForeground(HWND);
HWND WINAPI FixtureCurrentForeground();
BOOL WINAPI FixturePost(HWND,UINT,WPARAM,LPARAM);
#define IsWindow FixtureIsWindow
#define GetWindowThreadProcessId FixtureOwner
#define GetWindowInfo FixtureInfo
#define GetWindowRect FixtureRect
#define GetClientRect FixtureRect
#define GetWindowLongPtrW FixtureLong
#define GetWindowTextLengthW FixtureLength
#define GetWindowTextW FixtureTitle
#define GetClassNameW FixtureClass
#define IsWindowVisible FixtureVisible
#define IsWindowEnabled FixtureEnabled
#define IsIconic FixtureIconic
#define IsZoomed FixtureZoomed
#define IsWindowUnicode FixtureUnicode
#define EnumWindows FixtureEnum
#define ShowWindowAsync FixtureShow
#define ShowWindow FixtureShow
#define SetForegroundWindow FixtureForeground
#define GetForegroundWindow FixtureCurrentForeground
#define PostMessageW FixturePost
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <string>
static std::wstring mode;
static const HWND window=reinterpret_cast<HWND>(0x1234);
static bool live=true,iconic=false,zoomed=false,foreground=false,visible=true;
static int owners=0,actions=0;
BOOL WINAPI FixtureIsWindow(HWND h){return h==window&&live;}
DWORD WINAPI FixtureOwner(HWND h,LPDWORD pid){if(!FixtureIsWindow(h)){SetLastError(ERROR_INVALID_WINDOW_HANDLE);return 0;}++owners;if(pid)*pid=GetCurrentProcessId()+(mode==L"owner-change"&&owners>=2?1:0);return GetCurrentThreadId();}
BOOL WINAPI FixtureInfo(HWND,PWINDOWINFO info){if(mode==L"fallback"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}info->dwStyle=WS_OVERLAPPEDWINDOW;info->dwExStyle=0;info->rcWindow={10,20,300,200};info->rcClient={18,40,292,192};return TRUE;}
BOOL WINAPI FixtureRect(HWND,LPRECT rect){*rect={0,0,200,100};return TRUE;}
LONG_PTR WINAPI FixtureLong(HWND,int){return 0;}
int WINAPI FixtureLength(HWND){return mode==L"empty-title"?0:mode==L"long-title"?40000:12;}
int WINAPI FixtureTitle(HWND,LPWSTR value,int size){if(mode==L"title-denied"){SetLastError(ERROR_ACCESS_DENIED);return 0;}const std::wstring text=mode==L"long-title"?std::wstring(40000,L'x'):L"FixtureTitle";const int length=(std::min)(size-1,static_cast<int>(text.size()));memcpy(value,text.data(),length*sizeof(wchar_t));value[length]=0;return length;}
int WINAPI FixtureClass(HWND,LPWSTR value,int size){const wchar_t* text=mode==L"shell"?L"WorkerW":L"CliFixtureWindow";wcscpy_s(value,size,text);return static_cast<int>(wcslen(text));}
BOOL WINAPI FixtureVisible(HWND){return visible;}BOOL WINAPI FixtureEnabled(HWND){return TRUE;}BOOL WINAPI FixtureIconic(HWND){return iconic;}BOOL WINAPI FixtureZoomed(HWND){return zoomed;}BOOL WINAPI FixtureUnicode(HWND){return TRUE;}
BOOL WINAPI FixtureEnum(WNDENUMPROC callback,LPARAM data){if(mode==L"enum-denied"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}if(mode==L"empty-list")return TRUE;callback(window,data);if(mode==L"enum-partial"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return TRUE;}
BOOL WINAPI FixtureShow(HWND,int command){++actions;if(mode==L"show-denied"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}if(mode==L"pending-show")return TRUE;visible=true;iconic=command==SW_MINIMIZE;zoomed=command==SW_MAXIMIZE;return TRUE;}
BOOL WINAPI FixtureForeground(HWND){++actions;if(mode==L"foreground-denied"||mode==L"foreground-partial")return FALSE;foreground=true;return TRUE;}
HWND WINAPI FixtureCurrentForeground(){return foreground?window:nullptr;}
BOOL WINAPI FixturePost(HWND,UINT message,WPARAM,LPARAM){assert(message==WM_CLOSE);++actions;if(mode==L"post-denied"){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}if(mode!=L"ignored-close")live=false;return TRUE;}
static std::wstring time(HANDLE h,bool thread){FILETIME creation{},exit{},kernel{},user{};assert(thread?GetThreadTimes(h,&creation,&exit,&kernel,&user):GetProcessTimes(h,&creation,&exit,&kernel,&user));return std::to_wstring(static_cast<std::uint64_t>(creation.dwHighDateTime)<<32|creation.dwLowDateTime);}
int wmain(int argc,wchar_t* argv[]){
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];iconic=mode==L"foreground-partial";visible=mode!=L"hidden";for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 const auto pid=std::to_wstring(GetCurrentProcessId()),tid=std::to_wstring(GetCurrentThreadId()),processTime=time(GetCurrentProcess(),false),threadTime=time(GetCurrentThread(),true);
 for(int i=1;i+1<argc;++i){const std::wstring key=argv[i];const std::wstring* replacement=key==L"--pid"?&pid:key==L"--tid"?&tid:key==L"--creation-time"?&processTime:key==L"--thread-creation-time"?&threadTime:nullptr;if(replacement&&std::wstring(argv[i+1])==L"self")argv[i+1]=const_cast<wchar_t*>(replacement->c_str());}
 ks::cli::registerWindow();const auto result=ks::cli::dispatchR3(argc,argv).value_or(1);if(mode==L"owner-change")assert(actions==0);return result;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-window-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        (directory/'fixture.cpp').write_text(SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()),encoding='utf-8');binary=directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),
                        *[str(ROOT/path) for path in ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Window.cpp','shared/usermode/backend/window/WindowEnumerator.cpp','shared/usermode/backend/window/WindowActions.cpp','shared/usermode/backend/window/WindowFormatting.cpp','shared/usermode/backend/Common.cpp']],
                        '/Fe:'+str(binary),'/link','Advapi32.lib','User32.lib'],cwd=directory,check=True)
        def run(mode,code,path,extra=()):
            result=subprocess.run([str(binary),mode,*path,'--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:1500],result.stderr)
            return json.loads(result.stdout)['data']
        query=['window','detail','query'];hwnd=['--hwnd','0x1234']
        valid=run('valid',0,query,hwnd)['window'];assert valid['title']=='FixtureTitle' and valid['processCreationTime'] and valid['threadCreationTime'] and valid['clientRectCoordinates']=='screen'
        empty=run('empty-title',0,query,hwnd)['window'];assert empty['title']=='' and empty['evidence']['title']['empty']
        denied=run('title-denied',6,query,hwnd)['window'];assert denied['title'] is None and denied['evidence']['title']['win32Error']==5
        long=run('long-title',6,query,hwnd)['window'];assert len(long['title'])==32767 and long['evidence']['title']['truncated']
        fallback=run('fallback',0,query,hwnd)['window'];assert fallback['style']=='0x0' and fallback['clientRectCoordinates']=='client' and fallback['evidence']['windowInfo']['win32Error']==5
        enum=['window','enum'];assert run('empty-list',0,enum)['matchedCount']=='0'
        assert run('shell',0,enum)['shellFilteredCount']==1
        assert run('enum-denied',3,enum)['win32Error']==5
        partial=run('enum-partial',6,enum);assert not partial['complete'] and partial['returnedCount']==1
        assert run('owner-change',6,enum)['skippedCount']==1
        guard=hwnd+['--pid','self','--tid','self','--creation-time','self','--thread-creation-time','self','--wait-ms','0']
        manage=['window','manage']
        minimum=run('valid',0,manage+['minimize'],guard);assert minimum['verified'] and minimum['after']['minimized']
        maximum=run('valid',0,manage+['maximize'],guard);assert maximum['verified'] and maximum['after']['maximized']
        restore=run('valid',0,manage+['restore'],guard);assert restore['alreadySatisfied'] and not restore['attempted']
        hidden=run('hidden',0,manage+['restore'],guard);assert not hidden['alreadySatisfied'] and hidden['attempted'] and hidden['after']['visible']
        assert run('pending-show',6,manage+['minimize'],guard)['requestAccepted']
        assert run('show-denied',3,manage+['minimize'],guard)['win32Error']==5
        assert run('valid',0,manage+['foreground'],guard)['verified']
        policy=run('foreground-denied',3,manage+['foreground'],guard);assert not policy['verified'] and policy['win32Error'] is None
        mixed=run('foreground-partial',6,manage+['foreground'],guard);assert mixed['restoreAccepted'] and not mixed['requestAccepted'] and not mixed['verified']
        closed=run('valid',0,manage+['close'],guard);assert closed['verified'] and not closed['windowExists']
        ignored=run('ignored-close',6,manage+['close'],guard);assert ignored['requestAccepted'] and not ignored['verified'] and ignored['windowExists']
        assert run('post-denied',3,manage+['close'],guard)['win32Error']==5
        assert not run('owner-change',3,manage+['minimize'],guard)['attempted']
        print('R3_WINDOW_FIXTURE_PASS field absence/denial/truncation/fallback, enumeration/owner races, actual effects vs requests and foreground/UIPI limits')

if __name__=='__main__':main()
