"""Validate explicitly marked CreateFile returns against self-owned real target calls."""
import ctypes
import os
from live_fixture_support import LiveFixture

source = r"""
#define _WIN32_WINNT 0x0602
#include <Windows.h>
#include <cstdint>
#include <cstdio>
static void printResult(const char* name, HANDLE value, DWORD error) {
    printf("%s %llx %lu\n", name, static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(value)), error);
    if (value != INVALID_HANDLE_VALUE) CloseHandle(value);
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 1;
    SetLastError(0x5a5a); HANDLE beforeSuccess = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD baselineSuccess = GetLastError(); if (beforeSuccess != INVALID_HANDLE_VALUE) CloseHandle(beforeSuccess);
    SetLastError(0x5a5a); HANDLE beforeFailure = CreateFileW(L"Z:\\ksword_return_missing_9324\\missing", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD baselineFailure = GetLastError(); if (beforeFailure != INVALID_HANDLE_VALUE) CloseHandle(beforeFailure);
    printf("%lu\n", GetCurrentProcessId()); fflush(stdout);
    for (int c; (c = getchar()) != EOF;) {
        if (c == 'L' && !LoadLibraryW(argv[1])) return 2;
        if (c == 'X') {
            SetLastError(0x5a5a); HANDLE wa = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            DWORD we = GetLastError(); if (we != baselineSuccess) return 10; printResult("W_OK", wa, we);
            SetLastError(0x5a5a); HANDLE aa = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            DWORD ae = GetLastError(); printResult("A_OK", aa, ae);
            SetLastError(0x5a5a); HANDLE wf = CreateFileW(L"Z:\\ksword_return_missing_9324\\missing", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            DWORD fe = GetLastError(); if (fe != baselineFailure) return 11; printResult("W_FAIL", wf, fe);
            auto proc = reinterpret_cast<decltype(&CreateFile2)>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CreateFile2"));
            if (proc) {
                SetLastError(0x5a5a); HANDLE c2 = proc(L"NUL", GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, OPEN_EXISTING, nullptr);
                DWORD ce = GetLastError(); printResult("C2_OK", c2, ce);
            } else printf("C2_SKIP 0 0\n");
            printf("DONE\n"); fflush(stdout);
        }
        if (c == 'Q') return 0;
    }
    return 0;
}
"""
with LiveFixture(source) as fixture:
    fixture.wait_for(lambda f: any(e.api == "HooksInstalled" for e in f.events))
    fixture.command("X")
    expected = {}
    while True:
        line = fixture.process.stdout.readline().decode().strip()
        if line == "DONE": break
        label, value, error = line.split()
        expected[label] = (int(value, 16), int(error))
    assert expected["W_OK"][0] not in (0, (1 << (32 if os.environ.get("KSWORD_APIMON_ARCH") == "x86" else 64)) - 1)
    assert expected["W_FAIL"][1] != 0
    expected_count = 3 if "C2_SKIP" in expected else 4
    def matching(f):
        return [e for e in f.events if e.kind == 0 and e.api in ("CreateFileA", "CreateFileW", "CreateFile2")
                and (e.detail.startswith("path=NUL ") or "ksword_return_missing_9324" in e.detail)]
    fixture.wait_for(lambda f: len(matching(f)) >= expected_count)
    found = {}
    for event in matching(fixture):
        if event.api == "CreateFileW": label = "W_FAIL" if "ksword_return_missing_9324" in event.detail else "W_OK"
        elif event.api == "CreateFileA": label = "A_OK"
        else: label = "C2_OK"
        found[label] = event
    for label in ("W_OK", "A_OK", "W_FAIL") + (() if "C2_SKIP" in expected else ("C2_OK",)):
        event = found[label]
        assert event.index == 0x52545631, (label, hex(event.index))
        assert event.count == 0x44555231, (label, hex(event.count))
        assert event.revision < 60 * 10_000_000, (label, event.revision)
        assert event.address == expected[label][0], (label, hex(event.address), hex(expected[label][0]))
        assert event.result == (expected[label][1] if label.endswith("FAIL") else 0), (label, event.result, expected[label][1])
    # Control packets do not acquire a return value marker.
    assert all(e.index != 0x52545631 for e in fixture.events if e.api == "HooksInstalled")
print("PASS: explicit 64-bit return metadata matches real CreateFile handles and preserves error status")
