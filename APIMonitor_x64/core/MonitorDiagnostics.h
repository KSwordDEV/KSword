#pragma once

// Opt-in investigation only. Disabled builds have no counters, file I/O,
// profiling strings or argument evaluation from these instrumentation sites.
#ifndef KSWORD_APIMON_DIAGNOSTICS
#define KSWORD_APIMON_DIAGNOSTICS 0
#endif

#if KSWORD_APIMON_DIAGNOSTICS
#include <cstdint>
namespace apimon::diagnostic {
enum class Counter { NearTicks, InstallTicks, SuspendTicks, ContextTicks, ResumeTicks,
    NearQueries, NearCalls, InstallCalls, PipeBytes, Count };
void reset();
void add(Counter counter, std::uint64_t value = 1);
void mark(const char* phase, std::uint64_t first = 0, std::uint64_t second = 0);
class Timer {
public:
    explicit Timer(Counter counter);
    ~Timer();
private:
    Counter counter;
    std::uint64_t start;
};
}
#define APIMON_DIAG_JOIN2(a,b) a##b
#define APIMON_DIAG_JOIN(a,b) APIMON_DIAG_JOIN2(a,b)
#define APIMON_DIAG_SCOPE(counter) ::apimon::diagnostic::Timer APIMON_DIAG_JOIN(apimonTimer_,__LINE__)(::apimon::diagnostic::Counter::counter)
#define APIMON_DIAG_ADD(counter,value) ::apimon::diagnostic::add(::apimon::diagnostic::Counter::counter,value)
#define APIMON_DIAG_MARK(phase,first,second) ::apimon::diagnostic::mark(phase,first,second)
#define APIMON_DIAG_RESET() ::apimon::diagnostic::reset()
#else
#define APIMON_DIAG_SCOPE(counter) ((void)0)
#define APIMON_DIAG_ADD(counter,value) ((void)0)
#define APIMON_DIAG_MARK(phase,first,second) ((void)0)
#define APIMON_DIAG_RESET() ((void)0)
#endif
