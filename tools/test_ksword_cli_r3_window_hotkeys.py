"""Faults, thread ownership, cancellation and successful hotkey release evidence."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
BOOL WINAPI FixtureRegister(HWND,int,UINT,UINT);BOOL WINAPI FixtureUnregister(HWND,int);
BOOL WINAPI FixtureControl(PHANDLER_ROUTINE,BOOL);
#define RegisterHotKey FixtureRegister
#define UnregisterHotKey FixtureUnregister
#define SetConsoleCtrlHandler FixtureControl
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <string>
static std::wstring mode;static DWORD owner=0;static int registrations=0,releases=0;static bool active=false;
static PHANDLER_ROUTINE control=nullptr;static HANDLE thread=nullptr;
BOOL WINAPI FixtureControl(PHANDLER_ROUTINE handler,BOOL add){control=add?handler:nullptr;return TRUE;}
BOOL WINAPI FixtureRegister(HWND hwnd,int id,UINT,UINT vk){assert(!hwnd&&id==0x4b57&&vk!=VK_F12&&!active);++registrations;
 if(!owner){owner=GetCurrentThreadId();thread=OpenThread(SYNCHRONIZE,FALSE,owner);assert(thread&&owner!=GetProcessId(GetCurrentProcess()));}assert(owner==GetCurrentThreadId());
 if(mode==L"denied"){SetLastError(5);return FALSE;}if(mode==L"ambiguous"){SetLastError(0);return FALSE;}if(mode==L"unsupported"){SetLastError(50);return FALSE;}
 if(mode==L"occupied"||mode==L"mixed"&&registrations==1){SetLastError(1409);return FALSE;}
 if(mode==L"mixed-unknown"&&registrations==1){SetLastError(5);return FALSE;}
 active=true;if(mode==L"cancel"){assert(control);control(CTRL_C_EVENT);}if(mode==L"deadline")Sleep(8100);return TRUE;
}
BOOL WINAPI FixtureUnregister(HWND hwnd,int id){assert(!hwnd&&id==0x4b57&&active&&owner==GetCurrentThreadId());++releases;if(mode==L"release-fail"){SetLastError(5);return FALSE;}active=false;return TRUE;}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 ks::cli::registerWindowHotkeys();const auto code=ks::cli::dispatchR3(argc,argv).value_or(1);
 if(thread){assert(WaitForSingleObject(thread,0)==WAIT_OBJECT_0);CloseHandle(thread);}if(mode==L"release-fail")assert(registrations==1&&releases==1);else assert(!active);
 if(mode==L"reserved")assert(registrations==0&&releases==0);return code;}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-global-hotkeys-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8');(directory/'fixture.cpp').write_text(SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()),encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3WindowHotkeys.cpp','shared/usermode/backend/window/GlobalHotkeyProbe.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','User32.lib'],cwd=directory,check=True)
        def run(mode,code,scan=False,extra=()):
            args=['scan'] if scan else ['probe','--key','F12' if mode=='reserved' else 'F23','--modifiers','ctrl+alt+shift']
            result=subprocess.run([str(binary),mode,'window','hotkeys',*args,'--json',*extra],capture_output=True,timeout=15)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:1500],result.stderr);return json.loads(result.stdout)['data']
        entry=run('valid',0)['entries'][0];assert entry['registered'] and entry['unregistered'] and entry['registrationPossible'] and entry['modifiers']=='0x7'
        occupied=run('occupied',0)['entries'][0];assert occupied['classification']=='occupied-or-reserved' and occupied['registerWin32Error']==1409 and occupied['ownerPid'] is None and not occupied['unregisterAttempted']
        for mode,error in [('denied',5),('ambiguous',0),('unsupported',50)]:
            unknown=run(mode,5)['entries'][0];assert unknown['classification']=='unknown' and unknown['registrationPossible'] is None and unknown['registerWin32Error']==error
        assert not run('reserved',5)['entries'][0]['attempted']
        partial=run('release-fail',6,True);assert partial['cleanupFailed'] and partial['returnedCount']=='1' and partial['entries'][0]['unregisterWin32Error']==5
        assert run('valid',6,True,('--limit','2'))['limited']
        assert run('cancel',6,True)['cancelled']
        assert run('deadline',6,True)['limited']
        matrix=run('mixed',0,True);assert matrix['complete'] and matrix['returnedCount']=='1320' and matrix['reservedCount']=='15' and matrix['occupiedOrReservedCount']=='1'
        assert run('mixed-unknown',6,True)['unknownCount']=='1'
        print('R3_GLOBAL_HOTKEY_FIXTURE_PASS native registration errors, reservation, strict same-thread release, joined thread lifetime, release failure stop, cancellation and operation budgets')
if __name__=='__main__':main()
