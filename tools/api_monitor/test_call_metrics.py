"""Exercise production call timing and return-bit helpers without injection."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'APIMonitor_x64/hook/HookTargets.cpp').read_text(encoding='utf-8')
helpers = source[source.index('        struct ApiCallClock'):source.index('        bool SendRawEventWithMetrics')]
program = r'''
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <cstdio>
// HELPERS
int main() {
    SetLastError(0x1234);
    const auto begin = BeginApiCallClock();
    if (GetLastError() != 0x1234) return 1;
    Sleep(5);
    SetLastError(0x4321);
    const auto elapsed = EndApiCallClock(begin);
    if (GetLastError() != 0x4321 || !elapsed.valid || elapsed.ticks100ns < 10000 || elapsed.ticks100ns > 100000000) return 2;
    ApiCallClock invalid{};
    if (EndApiCallClock(invalid).valid || GetLastError() != 0x4321) return 3;
    const int neg = -1;
    if (ApiReturnBits(neg) != 0xffffffffULL) return 4;
    void* ptr = reinterpret_cast<void*>(static_cast<uintptr_t>(0x1234));
    if (ApiReturnBits(ptr) != 0x1234) return 5;
    printf("PASS: elapsed time, missing clock, return bits and last-error preservation\n");
}
'''.replace('// HELPERS', helpers)

with tempfile.TemporaryDirectory(prefix='ksword_call_metrics_') as temp:
    directory = Path(temp)
    source_path = directory / 'metrics.cpp'
    source_path.write_text(program, encoding='utf-8')
    exe = directory / 'metrics.exe'
    subprocess.run(['cl', '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/utf-8',
                    str(source_path), '/Fe:' + str(exe), '/Fo:' + str(directory / 'metrics.obj')], check=True)
    subprocess.run([str(exe)], check=True, timeout=20)
