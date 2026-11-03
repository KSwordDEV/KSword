"""Compile selected production async wrappers against deterministic owned stubs."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'APIMonitor_x64/hook/AsyncIoHandlers.inc').read_text(encoding='utf-8')
targets = (root / 'APIMonitor_x64/hook/HookTargets.cpp').read_text(encoding='utf-8')
clock = 'struct ApiCallClock' + targets.split('struct ApiCallClock', 1)[1].split('        bool SendRawEventWithMetrics', 1)[0]
functions = []
for name in ('GetOverlappedResult', 'WSAGetOverlappedResult', 'CancelIo'):
    match = re.search(r'\bBOOL\s+(?:WINAPI|WSAAPI)\s+Hooked' + name
                      + r'\([^\n]*\)\s*\{.*?\n        \}', source, re.S)
    if not match:
        raise ValueError('missing wrapper ' + name)
    functions.append(match.group())

code = r'''
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <cstdio>
namespace ks::winapi_monitor { enum class EventCategory { File, Network }; }
struct ScopedHookGuard { bool bypass() const { return false; } };
struct Config { bool enableFile = true; }; Config ActiveConfig() { return {}; }
template<class T> T SafeIoValue(const T* p) { return p ? *p : T{}; }
template<class... T> void ObserveIoResult(T...) {}
template<class... T> void ObserveIoCancellation(T...) {}
CLOCK
std::uint64_t captured = 0; bool measured = false; long status = 0;
bool SendRawEventWithMetrics(ks::winapi_monitor::EventCategory,const wchar_t*,const wchar_t*,long e,
  const wchar_t*, bool hasReturn, std::uint64_t bits, const ApiCallDuration& duration) {
  if (!hasReturn) return false; captured=bits; measured=duration.valid; status=e; SetLastError(555); return true;
}
BOOL WINAPI Overlapped(HANDLE,LPOVERLAPPED,LPDWORD,BOOL) { SetLastError(1234); return FALSE; }
BOOL WSAAPI WsaOverlapped(SOCKET,LPWSAOVERLAPPED,LPDWORD,BOOL,LPDWORD) { WSASetLastError(WSA_IO_PENDING); return FALSE; }
BOOL WINAPI Cancel(HANDLE) { SetLastError(4321); return TRUE; }
auto g_getOverlappedResultOriginal=&Overlapped;
auto g_wSAGetOverlappedResultOriginal=&WsaOverlapped;
auto g_cancelIoOriginal=&Cancel;
FUNCTIONS
int main() {
 DWORD bytes=0, flags=0; OVERLAPPED ov{};
 SetLastError(17); if (HookedGetOverlappedResult(nullptr,&ov,&bytes,FALSE) || GetLastError()!=1234 || captured!=0 || !measured || status!=1234) return 1;
 WSASetLastError(18); if (HookedWSAGetOverlappedResult(1,&ov,&bytes,FALSE,&flags) || WSAGetLastError()!=WSA_IO_PENDING || captured!=0 || !measured || status!=WSA_IO_PENDING) return 2;
 SetLastError(19); if (!HookedCancelIo(nullptr) || GetLastError()!=4321 || captured!=1 || !measured || status!=0) return 3;
 puts("PASS: async BOOL results, measured duration, status and Win32/WSA error preservation");
}
'''.replace('CLOCK', clock).replace('FUNCTIONS', '\n'.join(functions))
with tempfile.TemporaryDirectory(prefix='ksword_special_metrics_') as temp:
    work = Path(temp)
    cpp = work / 'fixture.cpp'
    cpp.write_text(code, encoding='utf-8')
    exe = work / 'fixture.exe'
    subprocess.run(['cl', '/nologo', '/EHsc', '/std:c++17', '/utf-8', str(cpp),
                    '/Fe:' + str(exe), '/Fo:' + str(work / 'fixture.obj'),
                    '/link', 'Ws2_32.lib'], check=True)
    subprocess.run([str(exe)], check=True, timeout=20)
