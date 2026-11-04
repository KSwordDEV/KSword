"""Window Band and hotkey commands against controlled transport/window fixtures."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''
#pragma once
#include <Windows.h>
BOOL WINAPI FixtureIsWindow(HWND);
DWORD WINAPI FixtureOwner(HWND, LPDWORD);
LRESULT WINAPI FixtureMessage(HWND,UINT,WPARAM,LPARAM,UINT,UINT,PDWORD_PTR);
#define IsWindow FixtureIsWindow
#define GetWindowThreadProcessId FixtureOwner
#define SendMessageTimeoutW FixtureMessage
'''
SOURCE = r'''
#include "mock.h"
#include "REGISTRY"
#include "DRIVER"
#include <shobjidl.h>
#include <objbase.h>
#include <fcntl.h>
#include <io.h>
#include <cassert>

static std::wstring mode;
static unsigned mutations=0, bandCalls=0, writes=0;
static WORD hotkey=0x0241;
BOOL WINAPI FixtureIsWindow(HWND w) { return w==reinterpret_cast<HWND>(0x1234); }
DWORD WINAPI FixtureOwner(HWND, LPDWORD p) { if(p)*p=GetCurrentProcessId();return GetCurrentThreadId(); }
LRESULT WINAPI FixtureMessage(HWND,UINT message,WPARAM,LPARAM,UINT,UINT,PDWORD_PTR value) {
    if(message==WM_GETHOTKEY){if(mode==L"read-fail")return 0;*value=hotkey;return 1;}
    assert(message==WM_SETHOTKEY); ++writes;
    if(mode==L"write-timeout")return 0;
    if(mode==L"reject"){*value=0;return 1;}
    *value=1;if(mode!=L"no-readback")hotkey=0;return 1;
}
namespace ksword::ark {
KeyboardHotkeyEnumResult DriverClient::enumerateKeyboardHotkeys(std::uint32_t pid,unsigned long,unsigned long) const {
    KeyboardHotkeyEnumResult r{};r.io.ok=true;r.version=KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION;
    r.status=mode==L"partial"?KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL:KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK;
    if(mutations && mode!=L"still-present")return r;
    r.totalCount=r.returnedCount=1;KeyboardHotkeyEntry e{};e.source=KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_HOTKEY_TABLE;
    e.processId=pid;e.threadId=GetCurrentThreadId();e.sessionId=0;e.hotkeyObject=0x77;e.snapshotHash=0x99;
    e.sessionGlobals=0x123;e.threadInfo=0x456;e.entryFlags=KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_MAIN|KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_MUTABLE;
    if(mode==L"unsafe")e.entryFlags|=KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_HAS_CHILDREN;
    r.entries.push_back(e);return r;
}
KeyboardHotkeyMutationResult DriverClient::mutateKeyboardHotkey(const KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY& e,unsigned long op,unsigned long,unsigned long) const {
    assert(e.hotkeyObject==0x77 && e.snapshotHash==0x99 && e.sessionId==0 && e.threadInfo==0x456);
    assert(op==KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_DELETE);++mutations;KeyboardHotkeyMutationResult r{};r.io.ok=true;
    r.response.status=KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK;
    r.response.responseFlags=KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_IDENTITY_VALIDATED|KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CALLER_VALIDATED|
        KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_SNAPSHOT_VALIDATED|KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CHANGED;return r;
}
WindowBandResult DriverClient::controlWindowBand(KSWORD_ARK_WINDOW_BAND_REQUEST q) const {
    ++bandCalls;WindowBandResult r{};r.io.ok=true;r.response.version=KSWORD_ARK_WINDOW_BAND_VERSION;
    if(mode==L"band-unsupported"){r.response.lastStatus=static_cast<long>(0xc00000bbU);return r;}
    if(q.operation==KSW_BAND_SET){assert(q.confirmation==KSW_BAND_CONFIRMED && q.expectedObject==0x777 && q.expectedBand==1 && q.newBand==2);}
    r.response.flags=KSW_BAND_VERIFIED|KSW_BAND_POSITION_VERIFIED;
    if(q.operation==KSW_BAND_SET)r.response.flags|=KSW_BAND_CHANGED;
    r.response.windowObject=0x777;r.response.previousBand=1;r.response.currentBand=q.operation==KSW_BAND_SET?2:1;return r;
}
}
namespace ks::cli {void registerWindowAdvanced();}
static std::wstring created(HANDLE h,bool thread) {
    FILETIME c{},e{},k{},u{};assert(thread?GetThreadTimes(h,&c,&e,&k,&u):GetProcessTimes(h,&c,&e,&k,&u));
    return std::to_wstring((static_cast<std::uint64_t>(c.dwHighDateTime)<<32)|c.dwLowDateTime);
}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];
    if(mode==L"create-link") {
        assert(SUCCEEDED(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED)));
        IShellLinkW* link=nullptr;IPersistFile* persist=nullptr;
        assert(SUCCEEDED(CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&link))));
        wchar_t path[32768]{};assert(GetModuleFileNameW(nullptr,path,32768));
        assert(SUCCEEDED(link->SetPath(path)));assert(SUCCEEDED(link->SetHotkey(0x241)));
        assert(SUCCEEDED(link->QueryInterface(IID_PPV_ARGS(&persist))));assert(SUCCEEDED(persist->Save(argv[2],TRUE)));
        persist->Release();link->Release();CoUninitialize();return 0;
    }
    for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
    const auto pid=std::to_wstring(GetCurrentProcessId()), tid=std::to_wstring(GetCurrentThreadId());
    const auto pt=created(GetCurrentProcess(),false),tt=created(GetCurrentThread(),true);
    for(int i=1;i+1<argc;++i){const std::wstring k=argv[i];const std::wstring* v=k==L"--pid"?&pid:k==L"--tid"?&tid:
        k==L"--creation-time"?&pt:k==L"--thread-creation-time"?&tt:nullptr;
        if(v && std::wstring(argv[i+1])==L"self")argv[i+1]=const_cast<wchar_t*>(v->c_str());}
    ks::cli::registerWindowAdvanced();const auto rc=ks::cli::dispatchR3(argc,argv).value_or(1);
    if(mode==L"unsafe"||mode==L"partial"||mode==L"stale")assert(!mutations);
    if(mode==L"stale-window")assert(!writes);return rc;
}
'''
LIVE_SOURCE = r'''
#include "REGISTRY"
#include "DRIVER"
#include <fcntl.h>
#include <io.h>
namespace ksword::ark {
KeyboardHotkeyEnumResult DriverClient::enumerateKeyboardHotkeys(std::uint32_t,unsigned long,unsigned long) const {return {};}
KeyboardHotkeyMutationResult DriverClient::mutateKeyboardHotkey(const KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY&,unsigned long,unsigned long,unsigned long) const {return {};}
WindowBandResult DriverClient::controlWindowBand(KSWORD_ARK_WINDOW_BAND_REQUEST) const {return {};}
}
namespace ks::cli {void registerWindowAdvanced();}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    ks::cli::registerWindowAdvanced();return ks::cli::dispatchR3(argc,argv).value_or(1);}
'''
OWNER_SOURCE = r'''
#include <Windows.h>
#include <cstdint>
#include <cstdio>
static unsigned long long stamp(HANDLE h,bool thread){FILETIME c{},e{},k{},u{};
    if(!(thread?GetThreadTimes(h,&c,&e,&k,&u):GetProcessTimes(h,&c,&e,&k,&u)))return 0;
    return (static_cast<unsigned long long>(c.dwHighDateTime)<<32)|c.dwLowDateTime;}
int wmain(){
    HWND window=CreateWindowExW(0,L"STATIC",L"Ksword CLI isolated hotkey",WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,CW_USEDEFAULT,200,100,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    if(!window)return 2;
    const auto set=SendMessageW(window,WM_SETHOTKEY,0x0241,0);
    if(set<=0 || LOWORD(SendMessageW(window,WM_GETHOTKEY,0,0))!=0x0241)return 3;
    printf("%llu %lu %lu %llu %llu\n",static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(window)),
        GetCurrentProcessId(),GetCurrentThreadId(),stamp(GetCurrentProcess(),false),stamp(GetCurrentThread(),true));fflush(stdout);
    MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);
        if(!IsWindow(window))break;}
    return 0;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix="ksword-window-advanced-") as temp:
        directory=Path(temp)
        (directory/"mock.h").write_text(MOCK,encoding="utf-8")
        source=SOURCE.replace("REGISTRY",(ROOT/"KswordCLI/CommandRegistry.h").as_posix()).replace("DRIVER",(ROOT/"Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h").as_posix())
        (directory/"fixture.cpp").write_text(source,encoding="utf-8")
        binary=directory/"fixture.exe"
        subprocess.run(["cl","/nologo","/std:c++20","/EHsc","/utf-8","/O2","/DNOMINMAX","/FI"+str(directory/"mock.h"),str(directory/"fixture.cpp"),
            str(ROOT/"KswordCLI/WindowAdvancedCommand.cpp"),str(ROOT/"KswordCLI/CommandRegistry.cpp"),str(ROOT/"shared/usermode/backend/Common.cpp"),"/Fe:"+str(binary),"/link","User32.lib","Ole32.lib","Shell32.lib","Uuid.lib"],cwd=directory,check=True)
        identity=["--pid","self","--creation-time","self","--tid","self"]
        window=["--hwnd","0x1234",*identity,"--thread-creation-time","self"]
        def run(mode,code,args):
            p=subprocess.run([str(binary),mode,*args,"--json"],capture_output=True,timeout=10)
            assert p.returncode==code,(mode,p.returncode,p.stdout,p.stderr)
            return json.loads(p.stdout.decode("utf-8"))
        enum=run("normal",0,["window","hotkeys","registrations","enum","--pid","self"])
        assert enum["backend"]=="r0" and enum["data"]["entries"][0]["sessionId"]==0
        clear=["window","hotkeys","registrations","clear",*identity,"--session-id","0","--object","0x77","--snapshot-hash","0x99","--confirm"]
        assert run("normal",0,clear)["data"]["verified"]
        assert run("unsafe",5,clear)["data"]["attempted"] is False
        assert run("partial",5,clear)["data"]["attempted"] is False
        assert run("still-present",6,clear)["data"]["objectStillPresent"] is True
        stale=clear.copy();stale[stale.index("0x99")]="0x98"
        assert run("stale",3,stale)["data"]["attempted"] is False
        activation=["window","hotkeys","activation","clear",*window,"--expected-hotkey","0x241","--confirm"]
        assert run("normal",0,["window","hotkeys","activation","query",*window])["data"]["rawHotkey"]==0x241
        assert run("normal",0,activation)["data"]["verified"]
        assert not run("write-timeout",6,activation)["data"]["verified"]
        assert run("no-readback",6,activation)["data"]["after"]==0x241
        old=activation.copy();old[old.index("0x241")]="0x242"
        assert not run("stale-window",3,old)["data"]["attempted"]
        assert run("normal",0,["window","band","probe"])["data"]["verified"]
        assert run("band-unsupported",5,["window","band","probe"])["data"]["verified"] is False
        assert run("normal",0,["window","band","query",*window])["data"]["windowObject"]=="0x777"
        setband=["window","band","set",*window,"--expected-band","1","--new-band","2","--window-object","0x777","--confirm"]
        assert run("normal",0,setband)["data"]["positionVerified"]
        link=directory/"test.lnk"
        subprocess.run([str(binary),"create-link",str(link)],check=True,timeout=10)
        info=run("normal",0,["window","hotkeys","shortcut","query","--path",str(link)])["data"]
        assert info["hotkey"]==0x241 and info["identityStable"]
        ident=info["identity"]
        shortcut=["window","hotkeys","shortcut","clear","--path",str(link),"--pid","self","--creation-time","self",
            "--volume-serial",ident["volumeSerial"],"--file-id",ident["fileId"],"--size",ident["size"],
            "--last-write-time",ident["lastWriteTime"],"--target",info["target"],"--expected-hotkey","0x241","--confirm"]
        stale=shortcut.copy();stale[stale.index(ident["fileId"])]=hex(int(ident["fileId"],16)+1)
        assert not run("normal",3,stale)["data"]["attempted"]
        assert run("normal",0,shortcut)["data"]["verified"]
        assert run("normal",0,["window","hotkeys","shortcut","query","--path",str(link)])["data"]["hotkey"]==0
        live_source=LIVE_SOURCE.replace("REGISTRY",(ROOT/"KswordCLI/CommandRegistry.h").as_posix()).replace("DRIVER",(ROOT/"Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h").as_posix())
        (directory/"live.cpp").write_text(live_source,encoding="utf-8")
        (directory/"owner.cpp").write_text(OWNER_SOURCE,encoding="utf-8")
        live=directory/"live.exe";owner_binary=directory/"owner.exe"
        subprocess.run(["cl","/nologo","/std:c++20","/EHsc","/utf-8","/O2","/DNOMINMAX",str(directory/"live.cpp"),str(ROOT/"KswordCLI/WindowAdvancedCommand.cpp"),
            str(ROOT/"KswordCLI/CommandRegistry.cpp"),str(ROOT/"shared/usermode/backend/Common.cpp"),"/Fe:"+str(live),"/link","User32.lib","Ole32.lib","Shell32.lib","Uuid.lib"],cwd=directory,check=True)
        subprocess.run(["cl","/nologo","/std:c++20","/EHsc","/utf-8","/O2",str(directory/"owner.cpp"),"/Fe:"+str(owner_binary),"/link","User32.lib"],cwd=directory,check=True)
        owner=subprocess.Popen([str(owner_binary)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW,text=True)
        hwnd=None
        try:
            line=owner.stdout.readline().strip()
            assert line,(owner.poll(),owner.stderr.read())
            hwnd,pid,tid,pt,tt=line.split()
            command=[str(live),"window","hotkeys","activation","clear","--hwnd",hwnd,"--pid",pid,"--tid",tid,
                "--creation-time",pt,"--thread-creation-time",tt,"--expected-hotkey","0x241","--confirm","--json"]
            query=[str(live),"window","hotkeys","activation","query","--hwnd",hwnd,"--pid",pid,"--tid",tid,
                "--creation-time",pt,"--thread-creation-time",tt,"--json"]
            observed=subprocess.run(query,capture_output=True,timeout=10,check=True)
            assert json.loads(observed.stdout.decode("utf-8"))["data"]["rawHotkey"]==0x241
            result=subprocess.run(command,capture_output=True,timeout=10)
            assert result.returncode==0,(result.returncode,result.stdout,result.stderr)
            assert json.loads(result.stdout.decode("utf-8"))["data"]["verified"]
        finally:
            import ctypes
            if owner.poll() is None:
                if hwnd: ctypes.windll.user32.PostMessageW(ctypes.c_void_p(int(hwnd)),0x10,0,0)
                try: owner.wait(timeout=3)
                except subprocess.TimeoutExpired: owner.terminate();owner.wait(timeout=3)
    print("WINDOW_ADVANCED_PASS: identity, session zero, stale/unsafe rows, Band, real shortcut and real window")

if __name__=="__main__":
    main()
