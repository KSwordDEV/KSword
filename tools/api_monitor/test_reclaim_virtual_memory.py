"""Compile the actual special handler with a mock callee on x86 and x64."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEV = Path(os.environ.get('KSWORD_VSDEVCMD', r'D:\Software\VS\Common7\Tools\VsDevCmd.bat'))

PRELUDE = r'''
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cassert>
namespace ks { namespace winapi_monitor { constexpr size_t kMaxDetailChars=320; enum class EventCategory {Memory}; }}
static DWORD mockResult=0; static bool bypass=false; static unsigned sent=0;
static std::int32_t eventStatus=0; static std::uint64_t eventBits=0; static bool hasReturn=false;
static unsigned eventDuration=0; static wchar_t eventDetail[320]{};
struct ScopedHookGuard { bool bypass() const { return ::bypass; } };
template<class T> std::uint64_t ApiReturnBits(T x) { std::uint64_t b=0; std::memcpy(&b,&x,sizeof(x)); return b; }
void AppendWideText(wchar_t (&b)[320], const wchar_t* s) { wcscat_s(b,s); }
void AppendHexText(wchar_t (&b)[320], std::uint64_t value) { wchar_t s[32]{}; swprintf_s(s,L"%llx",static_cast<unsigned long long>(value)); wcscat_s(b,s); }
unsigned BeginApiCallClock() { SetLastError(11); return 10; }
unsigned EndApiCallClock(unsigned c) { SetLastError(12); return c+7; }
DWORD WINAPI Original(const void* p, SIZE_T n) { assert(p==reinterpret_cast<void*>(0x1234) && n==4096); SetLastError(0x5a5a); return mockResult; }
auto g_reclaimVirtualMemoryOriginal=&Original;
void SendRawEventWithMetrics(ks::winapi_monitor::EventCategory category, const wchar_t* module, const wchar_t* api,
 std::int32_t status, wchar_t (&detail)[320], bool has, std::uint64_t bits, unsigned duration) {
 assert(category==ks::winapi_monitor::EventCategory::Memory && wcscmp(module,L"KernelBase")==0 && wcscmp(api,L"ReclaimVirtualMemory")==0);
 ++sent; eventStatus=status; eventBits=bits; hasReturn=has; eventDuration=duration; wcscpy_s(eventDetail,detail); SetLastError(13);
}
'''
TEST = r'''
int main() {
 for (DWORD expected : {DWORD(ERROR_SUCCESS), DWORD(ERROR_BUSY), DWORD(ERROR_INVALID_PARAMETER)}) {
  mockResult=expected; sent=0; SetLastError(3);
  DWORD result=HookedReclaimVirtualMemory(reinterpret_cast<void*>(0x1234),4096);
  DWORD error=GetLastError();
  assert(result==expected && error==0x5a5a && sent==1 && hasReturn && eventBits==expected && eventDuration==17);
  assert(eventStatus==(expected==ERROR_SUCCESS || expected==ERROR_BUSY ? 0 : static_cast<std::int32_t>(expected)));
  assert((wcsstr(eventDetail,L"reclaimed_discarded=1")!=nullptr)==(expected==ERROR_BUSY));
  assert(wcsstr(eventDetail,L"address=") && wcsstr(eventDetail,L"size=") && wcsstr(eventDetail,L"arg1="));
 }
 bypass=true; sent=0; mockResult=ERROR_BUSY;
 assert(HookedReclaimVirtualMemory(reinterpret_cast<void*>(0x1234),4096)==ERROR_BUSY && sent==0 && GetLastError()==0x5a5a);
}
'''

def main():
    source=(ROOT/'APIMonitor_x64/hook/ApiMemoryThreadExtraCaptureFormatters.inc').read_text(encoding='utf8')
    start=source.index('void CaptureReclaimVirtualMemory(')
    end=source.index('void CaptureDiscardVirtualMemory(', start)
    fixture=PRELUDE+'\n#include <initializer_list>\n'+source[start:end]+TEST
    with tempfile.TemporaryDirectory() as temp:
        cpp=Path(temp)/'reclaim.cpp'; cpp.write_text(fixture,encoding='utf8')
        for arch in ('x86','x64'):
            batch=Path(temp)/(arch+'.cmd')
            command=f'call "{DEV}" -no_logo -host_arch=x64 -arch={arch} >nul && cl /nologo /std:c++17 /EHsc "{cpp}" /Fo"{temp}\\{arch}.obj" /Fe"{temp}\\{arch}.exe" && "{temp}\\{arch}.exe"'
            batch.write_text('@echo off\n'+command+'\n',encoding='utf8')
            subprocess.run(['cmd.exe','/d','/c',str(batch)],cwd=ROOT,check=True)
            print(f'{arch}: ERROR_SUCCESS, ERROR_BUSY, ERROR_INVALID_PARAMETER and bypass passed')

if __name__=='__main__': main()
