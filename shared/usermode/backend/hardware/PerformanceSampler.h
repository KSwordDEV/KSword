#pragma once

#include "HardwareStatsTypes.h"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace ks::r3::hardware_stats {

// PerformanceScope selects which PDH objects a sampler opens. Opening only what
// a tab renders matters because every counter in a query is collected on every
// PdhCollectQueryData call, and the PhysicalDisk wildcard alone costs more than
// the whole system group on a machine with many volumes.
enum class PerformanceScope {
    System,
    PhysicalDisk
};

// PerformanceSampler owns one PDH query and turns it into display rows.
//
// Every method is safe to call from a worker thread and only from a worker
// thread: PdhOpenQuery and the first PdhCollectQueryData routinely take hundreds
// of milliseconds (the perflib providers are loaded and primed on that call),
// and rate counters additionally need the sampler to wait out a sampling
// interval before their first usable value exists. Doing either on the UI thread
// freezes the window.
//
// The object is reference-counted by its owners so an in-flight background
// sample keeps it alive even if the page window is destroyed mid-collection.
class PerformanceSampler final {
public:
    explicit PerformanceSampler(PerformanceScope scope);
    ~PerformanceSampler();

    PerformanceSampler(const PerformanceSampler&) = delete;
    PerformanceSampler& operator=(const PerformanceSampler&) = delete;

    // sample runs one collection pass. The first call also opens the query and
    // waits one sampling interval so rate counters return real numbers instead
    // of PDH_INVALID_DATA; output is a snapshot that is safe to move to the UI
    // thread.
    PerformanceSnapshot sample();

private:
    struct Counter;

    bool ensureOpen(std::wstring& diagnostic);
    void closeQuery();
    bool addCounter(const wchar_t* englishPath, Counter& counter);
    void collectSystemMetrics(PerformanceSnapshot& snapshot);
    void collectDiskRows(PerformanceSnapshot& snapshot);

private:
    struct Impl;
    std::mutex mutex_;
    PerformanceScope scope_;
    std::unique_ptr<Impl> impl_;
};

// MakePerformanceSampler creates a shared sampler. Input is the scope; output is
// never null.
std::shared_ptr<PerformanceSampler> MakePerformanceSampler(PerformanceScope scope);

} // namespace ks::r3::hardware_stats
