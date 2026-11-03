"""Real provider exports: Raw ABI preservation and explicit x86 Fake cleanup."""
from pathlib import Path
import subprocess
import tempfile
import re
from live_fixture_support import LiveFixture, ARCHITECTURE

with tempfile.TemporaryDirectory(prefix="ksword_owned_abi_") as temporary:
    directory = Path(temporary)
    snapshot_cpp = directory / "snapshot.cpp"
    snapshot_cpp.write_text(r'''
#include <Windows.h>
#include <cstdint>
#include "APIMonitor_x64/hook/RawAbiSnapshot.h"
int main(){const std::uintptr_t marker=0x12345678; auto heap=(std::uintptr_t*)HeapAlloc(GetProcessHeap(),0,sizeof(std::uintptr_t));
 if(!heap)return 1; *heap=marker; const bool ok=apimon::ReadRawReturnAddress(&marker)==marker
  && apimon::ReadRawReturnAddress(heap)==0 && apimon::ReadRawReturnAddress(nullptr)==0;
 HeapFree(GetProcessHeap(),0,heap); return ok?0:2;}
''', encoding="utf-8")
    snapshot_exe = directory / "snapshot.exe"
    subprocess.run(["cl", "/nologo", "/std:c++17", "/EHsc", "/MT", "/I" + str(Path(__file__).resolve().parents[2]),
                    str(snapshot_cpp), "/Fo:" + str(directory / "snapshot.obj"), "/Fe:" + str(snapshot_exe)], check=True)
    subprocess.run([str(snapshot_exe)], check=True, timeout=5)
    cpp = directory / "provider.cpp"
    cpp.write_text(r'''
#include <Windows.h>
extern "C" __declspec(noinline) DWORD WINAPI FixtureRaw(DWORD a,DWORD b,DWORD,DWORD,DWORD,DWORD){SetLastError(9876);return a*10+b;}
extern "C" __declspec(noinline) DWORD WINAPI FixtureTrigger(DWORD a,DWORD b){return FixtureRaw(a,b,5,6,7,8)+1;}
extern "C" __declspec(noinline) DWORD WINAPI FixtureFake(DWORD a,DWORD b){return a*10+b;}
extern "C" __declspec(noinline) DWORD WINAPI FixtureUnsafe(DWORD a,DWORD b){return a*10+b;}
''', encoding="utf-8")
    exports = directory / "provider.def"
    names = ("FixtureRaw", "FixtureFake", "FixtureUnsafe", "FixtureTrigger")
    exports.write_text("EXPORTS\n" + "\n".join(
        f"{name}=_{name}@{24 if name == 'FixtureRaw' else 8}" if ARCHITECTURE == "x86" else name for name in names), encoding="utf-8")
    library = directory / "ksword_owned_abi.dll"
    subprocess.run(["cl", "/nologo", "/LD", "/Od", "/MT", str(cpp), "/Fo:" + str(directory / "provider.obj"),
                    "/link", "/OUT:" + str(library), "/IMPLIB:" + str(directory / "provider.lib"), "/DEF:" + str(exports)], check=True)
    forward_cpp = directory / "forward.cpp"
    forward_cpp.write_text("#include <Windows.h>\nBOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID){return TRUE;}\n", encoding="utf-8")
    forward_def = directory / "forward.def"
    forward_def.write_text("LIBRARY ksword_owned_forwarder\nEXPORTS\nFixtureForwarded=ksword_owned_abi.FixtureRaw\n", encoding="utf-8")
    forward_library = directory / "ksword_owned_forwarder.dll"
    subprocess.run(["cl", "/nologo", "/LD", "/Od", "/MT", str(forward_cpp), "/Fo:" + str(directory / "forward.obj"),
                    "/link", "/OUT:" + str(forward_library), "/IMPLIB:" + str(directory / "forward.lib"), "/DEF:" + str(forward_def), str(directory / "provider.lib")], check=True)
    source = r'''
#include <Windows.h>
#include <cstdio>
static DWORD ImageSize(HMODULE m){auto dos=(PIMAGE_DOS_HEADER)m;return ((PIMAGE_NT_HEADERS)((char*)m+dos->e_lfanew))->OptionalHeader.SizeOfImage;}
int wmain(int argc,wchar_t** argv){if(argc!=2)return 1;auto provider=LoadLibraryW(L"PROVIDER");if(!provider)return 2;
 using Fn=DWORD(WINAPI*)(DWORD,DWORD); using RawFn=DWORD(WINAPI*)(DWORD,DWORD,DWORD,DWORD,DWORD,DWORD);
 auto raw=(RawFn)GetProcAddress(provider,"FixtureRaw"); auto trigger=(Fn)GetProcAddress(provider,"FixtureTrigger");
 auto forwardModule=LoadLibraryW(L"FORWARD"); if(!forwardModule)return 5;
 auto forwarded=(RawFn)GetProcAddress(forwardModule,"FixtureForwarded"); if(!forwarded||forwarded!=raw||!trigger)return 6;
 auto fake=(Fn)GetProcAddress(provider,"FixtureFake"),unsafe=(Fn)GetProcAddress(provider,"FixtureUnsafe");
 if(!raw||!fake||!unsafe)return 3;printf("%lu\n",GetCurrentProcessId());fflush(stdout);
 for(int c;(c=getchar())!=EOF;){if(c=='L'){if(!LoadLibraryW(argv[1]))return 4;}if(c=='X'){
  for(unsigned i=0;i<50;++i){SetLastError(0);if(raw(3,4,5,6,7,8)!=34||GetLastError()!=9876)return 10;
   if(fake(3,4)!=99||GetLastError()!=4567)return 11;}
#ifdef _M_IX86
  if(unsafe(5,4)!=54)return 12;
#else
  if(unsafe(5,4)!=99)return 12;
#endif
  if(trigger(3,4)!=35||forwarded(3,4,5,6,7,8)!=34)return 13;
  auto exe=GetModuleHandleW(nullptr);printf("DONE %llu %lu %llu %lu\n",(unsigned long long)(ULONG_PTR)exe,ImageSize(exe),(unsigned long long)(ULONG_PTR)provider,ImageSize(provider));fflush(stdout);}if(c=='Q')return 0;}return 0;}
'''.replace("PROVIDER", library.as_posix()).replace("FORWARD", forward_library.as_posix())
    config = {"enable_file": 0, "enable_process": 1, "enable_raw_fallback": 1, "raw_modules": library.name,
              "fake_success_enabled": 1, "fake_success_raw_fallback": 1,
              "fake_success_rules": f"{library.name}|FixtureFake|dword|99|win32|4567|8;;"
                                    f"{library.name}|FixtureUnsafe|dword|99|none|0"}
    with LiveFixture(source, config) as fixture:
        fixture.wait_for(lambda f: bool(f.snapshots) and any(e.api == "HooksInstalled" for e in f.events))
        rows = fixture.snapshots[-1][1]
        assert any(r.api == "FixtureRaw" and r.hook_kind == 1 and r.state in (0, 1) for r in rows)
        assert any(r.api == "FixtureFake" and r.hook_kind == 2 and r.state in (0, 1) for r in rows), [(r.api, r.hook_kind, r.state, r.detail) for r in rows if r.module.lower() == library.name]
        if ARCHITECTURE == "x86":
            assert any(r.api == "FixtureUnsafe" and r.hook_kind == 2 and r.state == 7 and "ABI" in r.detail for r in rows)
        fixture.command("X")
        fixture.wait_for(lambda f: any(e.api == "FixtureFake" and "original=skipped" in e.detail for e in f.events))
        done = fixture.process.stdout.readline().strip().split()
        assert len(done) == 5 and done[0] == b"DONE", done
        exe_base, exe_size, dll_base, dll_size = map(int, done[1:])
        fixture.wait_for(lambda f: sum(e.api == "FixtureRaw" for e in f.events) >= 52)
        raw_events = [e for e in fixture.events if e.api == "FixtureRaw"]
        def caller(event):
            match = re.search(r"(?:^| )caller=(0x[0-9A-Fa-f]+)(?: |$)", event.detail)
            assert match, event.detail
            return int(match.group(1), 16)
        callers = [caller(event) for event in raw_events]
        assert sum(exe_base <= value < exe_base + exe_size for value in callers) >= 51, callers
        assert any(dll_base <= value < dll_base + dll_size for value in callers), callers
        raw = raw_events[0]
        assert raw.result_kind == 1 and raw.api_id >= 0x80000000
        if ARCHITECTURE == "x86":
            assert "stackSlots=[0x3,0x4,0x5,0x6" in raw.detail, raw.detail
        else:
            assert "RCX=0x3 RDX=0x4 R8=0x5 R9=0x6" in raw.detail, raw.detail
            slots = re.search(r"stackSlots=\[(0x[0-9A-F]+),(0x[0-9A-F]+)", raw.detail)
            assert slots and int(slots.group(1), 16) & 0xffffffff == 7 and int(slots.group(2), 16) & 0xffffffff == 8, raw.detail
print(f"PASS: {ARCHITECTURE} real Raw/Fake exports, direct/nested/forwarded callers, original arguments/errors and unknown cleanup rejection")
