#pragma once
#include "PerformanceSampler.h"
#include <pdh.h>
#include <pdhmsg.h>
#include <array>
#include <map>
#include <utility>
namespace ks::r3::hardware_stats::detail {
constexpr DWORD kPrimingIntervalMs = 1000;
enum class MetricFormat {
    Percent,
    Bytes,
    MegabytesAsBytes,   // PDH reports Available MBytes; the table shows bytes.
    BytesPerSecond,
    Count,
    Rate,
    Decimal,
    UpTime
};
enum class SystemCounterId {
    CpuTotal,
    CpuUser,
    CpuPrivileged,
    CpuInterrupts,
    CpuDpcQueued,
    MemAvailable,
    MemCommitted,
    MemCommitLimit,
    MemCommitPercent,
    MemCache,
    MemPoolPaged,
    MemPoolNonpaged,
    MemPagesPerSecond,
    MemPageFaults,
    DiskCurrentQueue,
    DiskAverageQueue,
    DiskBusyPercent,
    DiskReadBytes,
    DiskWriteBytes,
    DiskReads,
    DiskWrites,
    SystemProcesses,
    SystemThreads,
    SystemContextSwitches,
    SystemUpTime,
    Count
};
struct ScalarCounterSpec {
    const wchar_t* path;
    const wchar_t* alternatePath;
    const wchar_t* group;
    const wchar_t* name;
    MetricFormat format;
    bool uncapped;
};
const std::array<ScalarCounterSpec, static_cast<std::size_t>(SystemCounterId::Count)>& ScalarSpecs();
enum class DiskCounterId {
    ReadBytes,
    WriteBytes,
    Reads,
    Writes,
    CurrentQueue,
    AverageQueue,
    BusyPercent,
    ReadLatency,
    WriteLatency,
    Count
};
const std::array<const wchar_t*, static_cast<std::size_t>(DiskCounterId::Count)>& DiskCounterPaths();
std::wstring ToLowerCopy(const std::wstring& text);
const std::map<std::wstring, DWORD>& EnglishCounterIndexMap();
std::wstring LocalizedPerfName(const std::wstring& englishName);
bool SplitCounterPath(const std::wstring& path,
    std::wstring& objectName,
    std::wstring& instanceName,
    std::wstring& counterName);
std::wstring LocalizeCounterPath(const std::wstring& englishPath);
bool CompareInstanceNames(const std::wstring& left, const std::wstring& right);
std::wstring FormatMetricValue(const MetricFormat format, const double value);
void AppendStaticMetric(PerformanceSnapshot& snapshot,
    const wchar_t* group,
    const wchar_t* name,
    const std::wstring& value,
    const wchar_t* source,
    const double numericValue);
void AppendSystemStaticMetrics(PerformanceSnapshot& snapshot);
bool ReadScalar(const PDH_HCOUNTER handle, const bool uncapped, double& value);
std::vector<std::pair<std::wstring, double>> ReadArray(const PDH_HCOUNTER handle, const bool uncapped);
std::shared_ptr<PerformanceSampler> MakePerformanceSampler(const PerformanceScope scope);
}
namespace ks::r3::hardware_stats {
struct PerformanceSampler::Counter {
    PDH_HCOUNTER handle = nullptr;
    std::wstring englishPath;
    std::wstring resolvedPath;
    bool localized = false;
    bool available = false;
};
struct PerformanceSampler::Impl {
    PDH_HQUERY query = nullptr;
    bool opened = false;
    bool primed = false;
    std::size_t localizedCount = 0;
    std::size_t missingCount = 0;
    std::vector<Counter> scalars;
    Counter cpuPerCore;
    Counter gpuEngine;
    Counter networkReceived;
    Counter networkSent;
    std::vector<Counter> diskCounters;
};
}
