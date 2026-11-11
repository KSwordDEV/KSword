"""Pause/resume actual hooks in an owned process, including initially paused startup."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
from live_fixture_support import LiveFixture, ARCHITECTURE, kernel

kernel.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel.CreateEventW.restype = wintypes.HANDLE
kernel.SetEvent.argtypes = [wintypes.HANDLE]
kernel.ResetEvent.argtypes = [wintypes.HANDLE]
root = Path(__file__).resolve().parents[2]
agent = Path(os.environ.get("KSWORD_PAUSE_AGENT", root / f"Ksword5.1/x64/Release/APIMonitor_{ARCHITECTURE}.dll"))

with tempfile.TemporaryDirectory(prefix="ksword_pause_provider_") as temp:
    folder = Path(temp)
    cpp = folder / "provider.cpp"
    cpp.write_text('#include <Windows.h>\nextern "C" __declspec(noinline) DWORD WINAPI FixturePause(DWORD x){return x+7;}\n', encoding="utf-8")
    exports = folder / "provider.def"
    exports.write_text("EXPORTS\n" + ("FixturePause=_FixturePause@4" if ARCHITECTURE == "x86" else "FixturePause") + "\n", encoding="utf-8")
    provider = folder / "ksword_pause_provider.dll"
    subprocess.run(["cl", "/nologo", "/LD", "/Od", "/MT", str(cpp), "/Fo:" + str(folder / "provider.obj"),
                    "/link", "/INCREMENTAL:NO", "/OUT:" + str(provider), "/IMPLIB:" + str(folder / "provider.lib"), "/DEF:" + str(exports)], check=True)
    source = r'''
#include <Windows.h>
#include <cstdio>
#include <cstring>
int wmain(int argc,wchar_t** argv){
 if(argc!=2)return 1; auto provider=LoadLibraryW(L"PROVIDER"); if(!provider)return 2;
 using Fn=DWORD(WINAPI*)(DWORD); auto fn=(Fn)GetProcAddress(provider,"FixturePause"); if(!fn)return 3;
 unsigned char original[5]; memcpy(original,(void*)fn,5); printf("%lu\n",GetCurrentProcessId());fflush(stdout);
 for(int c;(c=getchar())!=EOF;){if(c=='L'){if(!LoadLibraryW(argv[1]))return 4;}
  if(c=='X'){DWORD result=fn(9);printf("%lu %d\n",result,memcmp(original,(void*)fn,5)==0);fflush(stdout);}
  if(c=='Q')return 0;}return 0;}
'''.replace("PROVIDER", provider.as_posix())

    def run(initial):
        name = "Local\\KswordPauseTest_" + uuid.uuid4().hex
        event = kernel.CreateEventW(None, True, initial, name)
        assert event, ctypes.get_last_error()
        cfg = {"enable_file": 0, "enable_process": 1, "enable_raw_fallback": 1,
               "raw_modules": provider.name, "pause_event_name": name}
        try:
            with LiveFixture(source, cfg, agent=agent) as fixture:
                fixture.wait_for(lambda f: any(e.api == "PauseControlReady" for e in f.events))
                fixture.wait_for(lambda f: any(e.api == ("HooksPaused" if initial else "HooksInstalled") for e in f.events), timeout=30)
                if not initial:
                    fixture.wait_for(lambda f: bool(f.snapshots))
                    rows = [(r.module, r.api, r.state, r.detail) for r in fixture.snapshots[-1][1] if r.api == "FixturePause"]
                    assert rows and any(r[2] in (0, 1) for r in rows), rows
                def invoke(expect_original):
                    fixture.command("X")
                    values = fixture.process.stdout.readline().decode().strip().split()
                    assert values == ["16", "1" if expect_original else "0"], values
                if not initial:
                    invoke(False)
                    fixture.wait_for(lambda f: any(e.api == "FixturePause" for e in f.events))
                    assert kernel.SetEvent(event)
                    fixture.wait_for(lambda f: any(e.api == "HooksPaused" for e in f.events), timeout=30)
                invoke(True)
                fixture.pump()
                before = sum(e.api == "FixturePause" for e in fixture.events)
                for _ in range(10): invoke(True)
                time.sleep(0.3); fixture.pump()
                assert sum(e.api == "FixturePause" for e in fixture.events) == before
                assert kernel.ResetEvent(event)
                fixture.wait_for(lambda f: any(e.api == "HooksResumed" for e in f.events), timeout=30)
                invoke(False)
                fixture.wait_for(lambda f: sum(e.api == "FixturePause" for e in f.events) > before)
                assert kernel.SetEvent(event)
                fixture.wait_for(lambda f: sum(e.api == "HooksPaused" for e in f.events) >= 2, timeout=30)
                invoke(True)
        finally:
            kernel.CloseHandle(event)

    run(False)
    run(True)
    name = "Local\\KswordPauseShared_" + uuid.uuid4().hex
    event = kernel.CreateEventW(None, True, False, name)
    assert event
    cfg = {"enable_file": 0, "enable_process": 1, "enable_raw_fallback": 1,
           "raw_modules": provider.name, "pause_event_name": name}
    try:
        with LiveFixture(source, cfg, agent=agent) as first, LiveFixture(source, cfg, agent=agent) as second:
            for fixture in (first, second):
                fixture.wait_for(lambda f: any(e.api == "HooksInstalled" for e in f.events), timeout=30)
            assert kernel.SetEvent(event)
            for fixture in (first, second):
                fixture.wait_for(lambda f: any(e.api == "HooksPaused" for e in f.events), timeout=30)
                fixture.command("X")
                assert fixture.process.stdout.readline().decode().strip() == "16 1"
            assert kernel.ResetEvent(event)
            for fixture in (first, second):
                fixture.wait_for(lambda f: any(e.api == "HooksResumed" for e in f.events), timeout=30)
                fixture.command("X")
                assert fixture.process.stdout.readline().decode().strip() == "16 0"
    finally:
        kernel.CloseHandle(event)
print(f"PASS: {ARCHITECTURE} pause physically restores entries, suppresses events, resumes and stops")
