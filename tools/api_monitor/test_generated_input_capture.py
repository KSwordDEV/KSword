"""Exercise generated entry snapshots without injecting into any process."""
import json
from pathlib import Path
import subprocess
import tempfile

import generate_definitions

root = Path(__file__).resolve().parents[2]
catalog = json.loads((root / 'APIMonitor_x64/api_monitor_definitions.json').read_bytes())
apis = [a for a in catalog['apis'] if a['export'] in {
    'DeleteFileA', 'DeleteFileW', 'RemoveDirectoryA', 'RemoveDirectoryW'}]
assert len(apis) == 4
prefix = r'''
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>
#include <cwchar>
#include <cstdio>
#include <cstring>
namespace ks::winapi_monitor { constexpr unsigned kMaxDetailChars=320; enum class EventCategory{File,Process}; }
struct ScopedHookGuard { bool bypass() const { return false; } };
template <size_t N> void AppendWideText(wchar_t (&dest)[N], const wchar_t* value, size_t max = (size_t)-1) {
    SetLastError(999); size_t pos = wcslen(dest); if (!value) return;
    for (size_t i=0; i<max && value[i] && pos+1<N; ++i) dest[pos++]=value[i]; dest[pos]=0;
}
template <size_t N> void AppendAnsiText(wchar_t (&dest)[N], const char* value, size_t max = (size_t)-1) {
    SetLastError(999); size_t pos = wcslen(dest); if (!value) return;
    for (size_t i=0; i<max && value[i] && pos+1<N; ++i) dest[pos++]=(unsigned char)value[i]; dest[pos]=0;
}
template <size_t N> void AppendHexText(wchar_t (&dest)[N], std::uint64_t value) {
    wchar_t buffer[32]{}; swprintf_s(buffer, L"0x%llX", value); AppendWideText(dest, buffer);
}
template <typename T> std::uint64_t ApiReturnBits(T value) {
    static_assert(sizeof(value) <= sizeof(std::uint64_t)); std::uint64_t bits{}; memcpy(&bits, &value, sizeof(value)); return bits;
}
int BeginApiCallClock(){return 0;}
int EndApiCallClock(int){return 0;}
wchar_t captured[320]{}; DWORD entrySeen=0;
void SendRawEventWithMetrics(ks::winapi_monitor::EventCategory,const wchar_t*,const wchar_t*,long,const wchar_t* value,bool,std::uint64_t,int) {
    wcscpy_s(captured, value); SetLastError(333);
}
'''
calls = 'int main(){\n'
for api in apis:
    name = api['export']
    wide = name.endswith('W')
    literal = 'L"before"' if wide else '"before"'
    char_type = 'wchar_t' if wide else 'char'
    changed = "L'X'" if wide else "'X'"
    sig = generate_definitions.signature(api)
    prefix += f'''BOOL WINAPI Mock{name}({sig}) {{ entrySeen=GetLastError(); const_cast<{char_type}*>(pathPointer)[0]={changed}; SetLastError(222); return TRUE; }}
auto {api['binding']['original']}=&Mock{name};
void {api['wrapper']['capture_handler']}(wchar_t (&buffer)[320], {sig}, BOOL resultValue) {{ AppendWideText(buffer,L"post"); }}
'''
    prefix += generate_definitions.wrapper(api)
    calls += f'''{{ {char_type} path[]={literal}; captured[0]=0; SetLastError(111); if (!{api['binding']['hook']}(path)) return 1;
if (entrySeen!=111 || GetLastError()!=222 || !wcsstr(captured,L"input_before.path=before") || !wcsstr(captured,L"arg1=0x")) return 2; }}
'''
api = next(a for a in catalog['apis'] if a['export'] == 'VirtualProtect' and a['wrapper']['kind'] == 'generated')
prefix += r'''int outputMode=0;
BOOL WINAPI MockVirtualProtect(LPVOID baseAddress, SIZE_T sizeValue, DWORD newProtect, PDWORD oldProtectPointer) {
entrySeen=GetLastError(); if (outputMode==0) *oldProtectPointer=0x20; SetLastError(222); return outputMode!=1; }
auto g_virtualProtectOriginal=&MockVirtualProtect;
void CaptureVirtualProtect(wchar_t (&buffer)[320], LPVOID baseAddress, SIZE_T sizeValue, DWORD newProtect, PDWORD oldProtectPointer, BOOL resultValue) {
if (outputMode==3) { for (int i=0;i<319;++i) buffer[i]=L'X'; buffer[319]=0; } else AppendWideText(buffer,L"post"); }
'''
prefix += generate_definitions.wrapper(api)
calls += r'''{ DWORD prior=0; captured[0]=0; SetLastError(111);
if (!HookedVirtualProtect(nullptr, 0x1000, 0x40, &prior)) return 3;
if (entrySeen!=111 || GetLastError()!=222 || prior!=0x20 || !wcsstr(captured,L"arg2=0x1000") || !wcsstr(captured,L"arg3=0x40") || !wcsstr(captured,L"out_after.oldProtectPointer=0x20")) return 4;
outputMode=1; prior=0x44; SetLastError(111); if (HookedVirtualProtect(nullptr,0x1000,0x40,&prior)) return 5;
if (prior!=0x44 || !wcsstr(captured,L"out_after.oldProtectPointer=<unavailable>") || GetLastError()!=222) return 6;
outputMode=2; SetLastError(111); if (!HookedVirtualProtect(nullptr,0x1000,0x40,nullptr)) return 7;
if (!wcsstr(captured,L"out_after.oldProtectPointer=<unavailable>") || GetLastError()!=222) return 8;
SetLastError(111); if (!HookedVirtualProtect(nullptr,0x1000,0x40,reinterpret_cast<PDWORD>(1))) return 9;
if (!wcsstr(captured,L"out_after.oldProtectPointer=<unreadable>") || GetLastError()!=222) return 10;
outputMode=3; if (!HookedVirtualProtect(nullptr,0x1000,0x40,&prior)) return 11;
if (!wcsstr(captured,L"<possibly-truncated>")) return 12; }
'''
source = prefix + calls + 'puts("PASS: entry snapshot, mutated input and error preservation"); return 0;}\n'
with tempfile.TemporaryDirectory(prefix='ksword_generated_pre_') as temporary:
    work = Path(temporary)
    (work / 'fixture.cpp').write_text(source, encoding='utf-8')
    subprocess.run(['cl', '/nologo', '/EHsc', '/std:c++17', str(work / 'fixture.cpp'),
                    '/Fe:' + str(work / 'fixture.exe'), '/Fo:' + str(work / 'fixture.obj')], check=True)
    subprocess.run([str(work / 'fixture.exe')], check=True, timeout=20)
