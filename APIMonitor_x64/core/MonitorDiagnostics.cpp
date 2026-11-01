#include "pch.h"
#include "MonitorDiagnostics.h"

#if KSWORD_APIMON_DIAGNOSTICS
#include "../hook/HookEngine.h"
#include <cstdio>

namespace apimon::diagnostic {
namespace {
std::atomic_uint64_t counters[static_cast<std::size_t>(Counter::Count)]{};
std::atomic_uint64_t started{0};
SRWLOCK outputLock = SRWLOCK_INIT;
std::uint64_t ticks() { LARGE_INTEGER value{}; ::QueryPerformanceCounter(&value); return static_cast<std::uint64_t>(value.QuadPart); }
double milliseconds(Counter counter) {
    LARGE_INTEGER frequency{}; ::QueryPerformanceFrequency(&frequency);
    return 1000.0 * static_cast<double>(counters[static_cast<std::size_t>(counter)].load()) / static_cast<double>(frequency.QuadPart);
}
std::uint64_t value(Counter counter) { return counters[static_cast<std::size_t>(counter)].load(); }
}
Timer::Timer(Counter counterValue) : counter(counterValue), start(ticks()) {}
Timer::~Timer() { add(counter, ticks() - start); }
void add(Counter counter, std::uint64_t amount) { counters[static_cast<std::size_t>(counter)].fetch_add(amount, std::memory_order_relaxed); }
void reset() { for (auto& counter : counters) counter.store(0); started.store(::GetTickCount64()); }
void mark(const char* phase, std::uint64_t first, std::uint64_t second) {
    // Never call from a suspended-thread patch window: logging can take CRT or
    // filesystem locks. Timers/counters in that window use QPC/atomics only.
    ScopedInlineHookInternalBypass bypass;
    wchar_t path[MAX_PATH]{};
    swprintf_s(path,L"C:\\Windows\\Temp\\KswordApiMon\\profile_%lu.jsonl",::GetCurrentProcessId());
    char line[2048]{};
    const auto length = sprintf_s(line,
        "{\"phase\":\"%s\",\"pid\":%lu,\"elapsedMs\":%llu,\"nearCalls\":%llu,\"nearQueries\":%llu,\"nearMs\":%.3f,\"installCalls\":%llu,\"installMs\":%.3f,\"suspendMs\":%.3f,\"contextMs\":%.3f,\"resumeMs\":%.3f,\"pipeBytes\":%llu,\"first\":%llu,\"second\":%llu}\n",
        phase,::GetCurrentProcessId(),::GetTickCount64()-started.load(),value(Counter::NearCalls),value(Counter::NearQueries),milliseconds(Counter::NearTicks),
        value(Counter::InstallCalls),milliseconds(Counter::InstallTicks),milliseconds(Counter::SuspendTicks),milliseconds(Counter::ContextTicks),milliseconds(Counter::ResumeTicks),value(Counter::PipeBytes),first,second);
    if (length <= 0) return;
    ::AcquireSRWLockExclusive(&outputLock);
    HANDLE file=::CreateFileW(path,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file!=INVALID_HANDLE_VALUE){DWORD written=0;::WriteFile(file,line,static_cast<DWORD>(length),&written,nullptr);::CloseHandle(file);}
    ::ReleaseSRWLockExclusive(&outputLock);
}
}
#endif
