#include "PerformanceSamplerSupport.h"

#include <pdh.h>
#include <pdhmsg.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <map>
#include <utility>
#include <cmath>
#include <cstring>

// PDH is not in the project-wide link line because this is the only module that
// samples performance counters. Declaring the dependency here keeps the addition
// next to the code that needs it.
#pragma comment(lib, "Pdh.lib")

namespace ks::r3::hardware_stats {
using namespace detail;
namespace detail {

// Rate counters are a delta between two collections, so the first collection
// only establishes a baseline. Waiting one interval before the second one is
// what makes the very first table the user sees carry real numbers instead of a
// column of dashes that silently fills in a second later.


// MetricFormat picks the renderer for one scalar counter.




// ScalarCounterSpec is one non-wildcard counter and how to display it. The
// alternate path exists because "Processor Information" replaced "Processor" as
// the correct object on machines with processor groups, while the older object
// is still the only one present in some virtualized guests.


const std::array<ScalarCounterSpec, static_cast<std::size_t>(SystemCounterId::Count)>& ScalarSpecs() {
    static const std::array<ScalarCounterSpec, static_cast<std::size_t>(SystemCounterId::Count)> specs = { {
        { L"\\Processor Information(_Total)\\% Processor Time", L"\\Processor(_Total)\\% Processor Time",
          L"CPU", L"总占用率", MetricFormat::Percent, false },
        { L"\\Processor Information(_Total)\\% User Time", L"\\Processor(_Total)\\% User Time",
          L"CPU", L"用户态占用率", MetricFormat::Percent, false },
        { L"\\Processor Information(_Total)\\% Privileged Time", L"\\Processor(_Total)\\% Privileged Time",
          L"CPU", L"内核态占用率", MetricFormat::Percent, false },
        { L"\\Processor Information(_Total)\\Interrupts/sec", L"\\Processor(_Total)\\Interrupts/sec",
          L"CPU", L"中断速率", MetricFormat::Rate, false },
        { L"\\Processor Information(_Total)\\DPCs Queued/sec", L"\\Processor(_Total)\\DPCs Queued/sec",
          L"CPU", L"DPC 入队速率", MetricFormat::Rate, false },

        { L"\\Memory\\Available MBytes", nullptr, L"内存", L"可用物理内存", MetricFormat::MegabytesAsBytes, false },
        { L"\\Memory\\Committed Bytes", nullptr, L"内存", L"已提交内存", MetricFormat::Bytes, false },
        { L"\\Memory\\Commit Limit", nullptr, L"内存", L"提交上限", MetricFormat::Bytes, false },
        { L"\\Memory\\% Committed Bytes In Use", nullptr, L"内存", L"提交使用率", MetricFormat::Percent, false },
        { L"\\Memory\\Cache Bytes", nullptr, L"内存", L"系统缓存", MetricFormat::Bytes, false },
        { L"\\Memory\\Pool Paged Bytes", nullptr, L"内存", L"分页池", MetricFormat::Bytes, false },
        { L"\\Memory\\Pool Nonpaged Bytes", nullptr, L"内存", L"非分页池", MetricFormat::Bytes, false },
        { L"\\Memory\\Pages/sec", nullptr, L"内存", L"页面调度速率", MetricFormat::Rate, false },
        { L"\\Memory\\Page Faults/sec", nullptr, L"内存", L"缺页速率", MetricFormat::Rate, false },

        { L"\\PhysicalDisk(_Total)\\Current Disk Queue Length", nullptr, L"磁盘", L"当前队列长度", MetricFormat::Decimal, false },
        { L"\\PhysicalDisk(_Total)\\Avg. Disk Queue Length", nullptr, L"磁盘", L"平均队列长度", MetricFormat::Decimal, false },
        { L"\\PhysicalDisk(_Total)\\% Disk Time", nullptr, L"磁盘", L"磁盘忙碌比例", MetricFormat::Percent, true },
        { L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec", nullptr, L"磁盘", L"读取吞吐", MetricFormat::BytesPerSecond, false },
        { L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec", nullptr, L"磁盘", L"写入吞吐", MetricFormat::BytesPerSecond, false },
        { L"\\PhysicalDisk(_Total)\\Disk Reads/sec", nullptr, L"磁盘", L"读取 IOPS", MetricFormat::Rate, false },
        { L"\\PhysicalDisk(_Total)\\Disk Writes/sec", nullptr, L"磁盘", L"写入 IOPS", MetricFormat::Rate, false },

        { L"\\System\\Processes", nullptr, L"系统", L"进程数", MetricFormat::Count, false },
        { L"\\System\\Threads", nullptr, L"系统", L"线程数", MetricFormat::Count, false },
        { L"\\System\\Context Switches/sec", nullptr, L"系统", L"上下文切换速率", MetricFormat::Rate, false },
        { L"\\System\\System Up Time", nullptr, L"系统", L"系统运行时间", MetricFormat::UpTime, false },
    } };
    return specs;
}



const std::array<const wchar_t*, static_cast<std::size_t>(DiskCounterId::Count)>& DiskCounterPaths() {
    static const std::array<const wchar_t*, static_cast<std::size_t>(DiskCounterId::Count)> paths = { {
        L"\\PhysicalDisk(*)\\Disk Read Bytes/sec",
        L"\\PhysicalDisk(*)\\Disk Write Bytes/sec",
        L"\\PhysicalDisk(*)\\Disk Reads/sec",
        L"\\PhysicalDisk(*)\\Disk Writes/sec",
        L"\\PhysicalDisk(*)\\Current Disk Queue Length",
        L"\\PhysicalDisk(*)\\Avg. Disk Queue Length",
        L"\\PhysicalDisk(*)\\% Disk Time",
        L"\\PhysicalDisk(*)\\Avg. Disk sec/Read",
        L"\\PhysicalDisk(*)\\Avg. Disk sec/Write",
    } };
    return paths;
}

std::wstring ToLowerCopy(const std::wstring& text) {
    std::wstring lowered = text;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](const wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
    });
    return lowered;
}

// EnglishCounterIndexMap reads the English perflib name table exactly once.
//
// Perflib stores its name tables per language under a numeric subkey, and 009 is
// always US English regardless of the installed UI language. The table alternates
// index and name, so it gives the English-name-to-index direction that
// PdhLookupPerfNameByIndexW cannot provide on its own. This is the only way to
// reach a localized counter name without hard-coding counter indexes, which are
// not contractually stable across Windows releases.
const std::map<std::wstring, DWORD>& EnglishCounterIndexMap() {
    static const std::map<std::wstring, DWORD> table = []() -> std::map<std::wstring, DWORD> {
        std::map<std::wstring, DWORD> result;
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\009",
                0,
                KEY_QUERY_VALUE,
                &key) != ERROR_SUCCESS) {
            return result;
        }

        DWORD type = 0;
        DWORD bytes = 0;
        if (::RegQueryValueExW(key, L"Counter", nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
            type != REG_MULTI_SZ || bytes < sizeof(wchar_t)) {
            ::RegCloseKey(key);
            return result;
        }

        std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 2, L'\0');
        if (::RegQueryValueExW(key, L"Counter", nullptr, &type,
                reinterpret_cast<LPBYTE>(buffer.data()), &bytes) != ERROR_SUCCESS) {
            ::RegCloseKey(key);
            return result;
        }
        ::RegCloseKey(key);

        const wchar_t* cursor = buffer.data();
        const wchar_t* end = buffer.data() + buffer.size();
        while (cursor < end && *cursor) {
            const std::wstring indexText(cursor);
            cursor += indexText.size() + 1;
            if (cursor >= end || !*cursor) {
                break;
            }
            const std::wstring name(cursor);
            cursor += name.size() + 1;

            wchar_t* parseEnd = nullptr;
            const unsigned long index = std::wcstoul(indexText.c_str(), &parseEnd, 10);
            if (index == 0 || parseEnd == indexText.c_str() || name.empty()) {
                continue;
            }
            // Perflib repeats some names across indexes; the first entry wins so
            // the mapping stays deterministic between runs.
            result.emplace(ToLowerCopy(name), static_cast<DWORD>(index));
        }
        return result;
    }();
    return table;
}

// LocalizedPerfName translates one English object or counter name into the name
// the local machine actually publishes. Output is empty when the name is unknown
// to perflib, which is the signal to abandon the fallback rather than build a
// half-translated path.
std::wstring LocalizedPerfName(const std::wstring& englishName) {
    const auto& table = EnglishCounterIndexMap();
    const auto found = table.find(ToLowerCopy(englishName));
    if (found == table.end()) {
        return {};
    }

    DWORD size = 0;
    ::PdhLookupPerfNameByIndexW(nullptr, found->second, nullptr, &size);
    if (size == 0) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(size) + 1, L'\0');
    if (::PdhLookupPerfNameByIndexW(nullptr, found->second, buffer.data(), &size) != ERROR_SUCCESS) {
        return {};
    }
    return std::wstring(buffer.data());
}

// SplitCounterPath breaks "\Object(Instance)\Counter" into its parts. Output is
// false for anything that is not a two-segment local counter path, which is all
// this module ever builds.
bool SplitCounterPath(const std::wstring& path,
    std::wstring& objectName,
    std::wstring& instanceName,
    std::wstring& counterName) {
    if (path.size() < 4 || path.front() != L'\\') {
        return false;
    }
    const std::size_t lastSeparator = path.rfind(L'\\');
    if (lastSeparator == 0 || lastSeparator + 1 >= path.size()) {
        return false;
    }

    counterName = path.substr(lastSeparator + 1);
    std::wstring objectPart = path.substr(1, lastSeparator - 1);
    instanceName.clear();
    if (!objectPart.empty() && objectPart.back() == L')') {
        const std::size_t open = objectPart.find(L'(');
        if (open != std::wstring::npos) {
            instanceName = objectPart.substr(open + 1, objectPart.size() - open - 2);
            objectPart = objectPart.substr(0, open);
        }
    }
    objectName = objectPart;
    return !objectName.empty() && !counterName.empty();
}

// LocalizeCounterPath rebuilds an English path in the machine's own language.
// Instance names are deliberately left alone: perflib localizes object and
// counter names but instances such as "_Total", "0 C:" or an adapter description
// are data, not translatable resources.
std::wstring LocalizeCounterPath(const std::wstring& englishPath) {
    std::wstring objectName;
    std::wstring instanceName;
    std::wstring counterName;
    if (!SplitCounterPath(englishPath, objectName, instanceName, counterName)) {
        return {};
    }

    std::wstring localizedObject = LocalizedPerfName(objectName);
    std::wstring localizedCounter = LocalizedPerfName(counterName);
    if (localizedObject.empty() || localizedCounter.empty()) {
        return {};
    }

    PDH_COUNTER_PATH_ELEMENTS_W elements{};
    elements.szMachineName = nullptr;
    elements.szObjectName = localizedObject.data();
    elements.szInstanceName = instanceName.empty() ? nullptr : instanceName.data();
    elements.szParentInstance = nullptr;
    elements.dwInstanceIndex = static_cast<DWORD>(-1);
    elements.szCounterName = localizedCounter.data();

    DWORD size = 0;
    if (::PdhMakeCounterPathW(&elements, nullptr, &size, 0) != PDH_MORE_DATA || size == 0) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(size) + 1, L'\0');
    if (::PdhMakeCounterPathW(&elements, buffer.data(), &size, 0) != ERROR_SUCCESS) {
        return {};
    }
    return std::wstring(buffer.data());
}

// CompareInstanceNames orders PDH instance names the way a person reads them.
// Instances like "0,10" and "0,2" or "10 D:" and "2 C:" would otherwise sort
// lexicographically and interleave the cores and disks out of order.
bool CompareInstanceNames(const std::wstring& left, const std::wstring& right) {
    std::size_t leftIndex = 0;
    std::size_t rightIndex = 0;
    while (leftIndex < left.size() && rightIndex < right.size()) {
        const bool leftDigit = std::iswdigit(left[leftIndex]) != 0;
        const bool rightDigit = std::iswdigit(right[rightIndex]) != 0;
        if (leftDigit && rightDigit) {
            unsigned long long leftValue = 0;
            unsigned long long rightValue = 0;
            while (leftIndex < left.size() && std::iswdigit(left[leftIndex])) {
                leftValue = leftValue * 10ULL + static_cast<unsigned long long>(left[leftIndex] - L'0');
                ++leftIndex;
            }
            while (rightIndex < right.size() && std::iswdigit(right[rightIndex])) {
                rightValue = rightValue * 10ULL + static_cast<unsigned long long>(right[rightIndex] - L'0');
                ++rightIndex;
            }
            if (leftValue != rightValue) {
                return leftValue < rightValue;
            }
            continue;
        }
        const wchar_t leftChar = static_cast<wchar_t>(std::towlower(left[leftIndex]));
        const wchar_t rightChar = static_cast<wchar_t>(std::towlower(right[rightIndex]));
        if (leftChar != rightChar) {
            return leftChar < rightChar;
        }
        ++leftIndex;
        ++rightIndex;
    }
    return left.size() < right.size();
}

std::wstring FormatMetricValue(const MetricFormat format, const double value) {
    switch (format) {
    case MetricFormat::Percent:
        return FormatPercent(value);
    case MetricFormat::Bytes:
        return FormatByteSize(value);
    case MetricFormat::MegabytesAsBytes:
        return FormatByteSize(value * 1024.0 * 1024.0);
    case MetricFormat::BytesPerSecond:
        return FormatByteRate(value);
    case MetricFormat::Count:
        return FormatCount(value);
    case MetricFormat::Rate:
        return FormatRate(value);
    case MetricFormat::UpTime:
        return FormatUpTime(value);
    case MetricFormat::Decimal:
    default:
        return FormatDecimal(value);
    }
}

// AppendStaticMetric adds a row that does not come from PDH at all. Physical RAM
// and the logical processor count are reported by the plain Win32 APIs, which
// answer even on machines where the performance counter registry is damaged --
// exactly the machines where an all-PDH table would be empty and useless.
void AppendStaticMetric(PerformanceSnapshot& snapshot,
    const wchar_t* group,
    const wchar_t* name,
    const std::wstring& value,
    const wchar_t* source,
    const double numericValue) {
    PerformanceMetricRow row{};
    row.group = group;
    row.name = name;
    row.value = value;
    row.source = source;
    row.numericValue = numericValue;
    row.valid = true;row.evidence.available = true;row.evidence.complete = true;
    snapshot.metrics.push_back(std::move(row));
}

void AppendSystemStaticMetrics(PerformanceSnapshot& snapshot) {
    const auto source = [&snapshot](const wchar_t* id,const wchar_t* path,const wchar_t* group,bool success) {
        PerformanceEvidence e;e.available = success;e.complete = success;e.statusKnown = true;e.status = success ? ERROR_SUCCESS : ::GetLastError();
        snapshot.sources.push_back({id,path,e,group,L"win32"});
    };
    const DWORD logicalProcessors = ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    source(L"logical-processors",L"GetActiveProcessorCount",L"cpu",logicalProcessors != 0);
    if (logicalProcessors != 0) {
        AppendStaticMetric(snapshot, L"CPU", L"逻辑处理器数",
            FormatCount(static_cast<double>(logicalProcessors)), L"GetActiveProcessorCount",
            static_cast<double>(logicalProcessors));
        auto& row = snapshot.metrics.back();row.id = L"logical-processors";row.groupId = L"cpu";row.unit = L"count";row.exactInteger = true;row.integerValue = logicalProcessors;
    }
    const WORD processorGroups = ::GetActiveProcessorGroupCount();
    source(L"processor-groups",L"GetActiveProcessorGroupCount",L"cpu",processorGroups != 0);
    if (processorGroups != 0) {
        AppendStaticMetric(snapshot, L"CPU", L"处理器组数",
            FormatCount(static_cast<double>(processorGroups)), L"GetActiveProcessorGroupCount",
            static_cast<double>(processorGroups));
        auto& row = snapshot.metrics.back();row.id = L"processor-groups";row.groupId = L"cpu";row.unit = L"count";row.exactInteger = true;row.integerValue = processorGroups;
    }

    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    const bool memoryKnown = ::GlobalMemoryStatusEx(&memory) != FALSE;
    source(L"physical-memory",L"GlobalMemoryStatusEx",L"memory",memoryKnown);
    if (memoryKnown) {
        const double total = static_cast<double>(memory.ullTotalPhys);
        const double available = static_cast<double>(memory.ullAvailPhys);
        AppendStaticMetric(snapshot, L"内存", L"物理内存总量", FormatByteSize(total),
            L"GlobalMemoryStatusEx", total);
        {auto& row = snapshot.metrics.back();row.id = L"physical-memory-total";row.groupId = L"memory";row.unit = L"bytes";row.exactInteger = true;row.integerValue = memory.ullTotalPhys;}
        AppendStaticMetric(snapshot, L"内存", L"物理内存已用", FormatByteSize(total - available),
            L"GlobalMemoryStatusEx", total - available);
        {auto& row = snapshot.metrics.back();row.id = L"physical-memory-used";row.groupId = L"memory";row.unit = L"bytes";row.exactInteger = true;row.integerValue = memory.ullTotalPhys-memory.ullAvailPhys;}
        AppendStaticMetric(snapshot, L"内存", L"物理内存使用率",
            FormatPercent(static_cast<double>(memory.dwMemoryLoad)), L"GlobalMemoryStatusEx",
            static_cast<double>(memory.dwMemoryLoad));
        {auto& row = snapshot.metrics.back();row.id = L"physical-memory-load";row.groupId = L"memory";row.unit = L"percent";}
    }
}

} // namespace

// Counter pairs one PDH handle with the path that actually produced it. The
// resolved path is kept for display because it is the only visible evidence of
// whether the English or the localized route was taken.




namespace detail {

// ReadScalar formats one counter handle. Output is false when PDH has no usable
// value for this pass, which happens legitimately for a rate counter whose
// instance appeared between two collections.
bool ReadScalar(const PDH_HCOUNTER handle, const bool uncapped, double& value,PerformanceEvidence* output) {
    PerformanceEvidence local;auto& e = output ? *output : local;e = {};
    if (!handle) {
        return false;
    }
    PDH_FMT_COUNTERVALUE formatted{};
    const DWORD format = PDH_FMT_DOUBLE | (uncapped ? PDH_FMT_NOCAP100 : 0u);
    const PDH_STATUS status = ::PdhGetFormattedCounterValue(handle, format, nullptr, &formatted);
    e.statusKnown = true;e.status = status;e.cStatusKnown = status == ERROR_SUCCESS || status == PDH_INVALID_DATA;e.cStatus = formatted.CStatus;
    if (status != ERROR_SUCCESS || (formatted.CStatus != PDH_CSTATUS_VALID_DATA && formatted.CStatus != PDH_CSTATUS_NEW_DATA)) {
        return false;
    }
    if (!std::isfinite(formatted.doubleValue)) {e.malformed = true;return false;}
    value = formatted.doubleValue;e.available = true;e.complete = true;
    return true;
}

// ReadArray expands one wildcard counter into instance/value pairs.
std::vector<std::pair<std::wstring, double>> ReadArray(const PDH_HCOUNTER handle,const bool uncapped,PerformanceEvidence* output) {
    PerformanceEvidence local;auto& e = output ? *output : local;e = {};
    std::vector<std::pair<std::wstring,double>> values;if (!handle) return values;
    DWORD needed = 0,count = 0;const DWORD format = PDH_FMT_DOUBLE | (uncapped ? PDH_FMT_NOCAP100 : 0u);
    e.status = ::PdhGetFormattedCounterArrayW(handle,format,&needed,&count,nullptr);e.statusKnown = true;
    if (e.status == ERROR_SUCCESS && !count) {e.complete = true;e.available = true;e.empty = true;return values;}
    if (e.status != PDH_MORE_DATA) return values;
    for (int attempt = 0;attempt<4;++attempt) {
        if (!needed || needed>16u*1024*1024) {e.status = PDH_MORE_DATA;return values;}
        std::vector<BYTE> raw(needed,BYTE{0});DWORD size = needed;
        auto* items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(raw.data());
        e.status = ::PdhGetFormattedCounterArrayW(handle,format,&size,&count,items);
        if (e.status == PDH_MORE_DATA) {if (size<=needed) return values;needed = size;continue;}
        if (e.status != ERROR_SUCCESS) return values;
        if (size>raw.size() || count>size/sizeof(*items)) {e.malformed = true;return values;}
        e.returnedCount = count;e.complete = true;e.available = true;e.empty = !count;
        const auto begin = reinterpret_cast<std::uintptr_t>(raw.data()),end = begin+size;
        for (DWORD i = 0;i<count;++i) {
            const auto& item = items[i];
            if (item.FmtValue.CStatus != PDH_CSTATUS_VALID_DATA && item.FmtValue.CStatus != PDH_CSTATUS_NEW_DATA) {
                ++e.skippedCount;e.complete = false;e.cStatusKnown = true;e.cStatus = item.FmtValue.CStatus;continue;
            }
            const auto address = reinterpret_cast<std::uintptr_t>(item.szName);
            if (!std::isfinite(item.FmtValue.doubleValue) || address<begin+count*sizeof(*items) || address>=end || address%alignof(wchar_t)) {e.malformed = true;e.complete = false;continue;}
            const auto chars = (end-address)/sizeof(wchar_t);const auto finish = std::find(item.szName,item.szName+chars,L'\0');
            if (finish == item.szName+chars) {e.malformed = true;e.complete = false;continue;}
            values.emplace_back(std::wstring(item.szName,finish),item.FmtValue.doubleValue);
        }
        return values;
    }
    return values;
}

} // namespace

PerformanceSampler::PerformanceSampler(const PerformanceScope scope)
    : scope_(scope), impl_(std::make_unique<Impl>()) {
}

PerformanceSampler::~PerformanceSampler() {
    std::scoped_lock lock(mutex_);
    closeQuery();
}

PerformanceEvidence PerformanceSampler::close() {
    std::scoped_lock lock(mutex_);PerformanceEvidence e;e.statusKnown = impl_ && impl_->query;
    e.status = closeQuery();e.available = e.status == ERROR_SUCCESS;e.complete = e.available;return e;
}
DWORD PerformanceSampler::closeQuery() {
    DWORD status = ERROR_SUCCESS;
    if (impl_ && impl_->query) {
        // Closing the query releases every counter handle it owns, so the
        // per-counter handles are only cleared, never closed individually.
        status = ::PdhCloseQuery(impl_->query);
        impl_->query = nullptr;
    }
    if (impl_) {
        impl_->opened = false;
        impl_->primed = false;
        impl_->scalars.clear();
        impl_->diskCounters.clear();
        impl_->cpuPerCore = Counter{};
        impl_->gpuEngine = Counter{};
        impl_->networkReceived = Counter{};
        impl_->networkSent = Counter{};
    }
    return status;
}

bool PerformanceSampler::addCounter(const wchar_t* englishPath, Counter& counter) {
    counter = Counter{};
    if (!impl_ || !impl_->query || !englishPath) {
        return false;
    }
    counter.englishPath = englishPath;

    // PdhAddEnglishCounterW is the documented contract for locale-independent
    // paths and is tried first. Hard-coding the English text into PdhAddCounterW
    // instead would fail on every non-English Windows, because the counter and
    // object names in a path are localized resources.
    PDH_HCOUNTER handle = nullptr;
    counter.addStatus = ::PdhAddEnglishCounterW(impl_->query, englishPath, 0, &handle);
    if (counter.addStatus == ERROR_SUCCESS && handle) {
        counter.handle = handle;
        counter.resolvedPath = englishPath;
        counter.available = true;
        return true;
    }

    // The English mapping lives in the Perflib 009 registry table, which can be
    // missing or corrupt on systems where the counters were rebuilt by hand. In
    // that case the same path is reassembled in the machine's own language and
    // added through the ordinary PdhAddCounterW.
    const std::wstring localizedPath = LocalizeCounterPath(englishPath);
    if (localizedPath.empty()) {
        return false;
    }
    handle = nullptr;
    counter.addStatus = ::PdhAddCounterW(impl_->query, localizedPath.c_str(), 0, &handle);
    if (counter.addStatus != ERROR_SUCCESS || !handle) {
        return false;
    }
    counter.handle = handle;
    counter.resolvedPath = localizedPath;
    counter.localized = true;
    counter.available = true;
    if (impl_) {
        ++impl_->localizedCount;
    }
    return true;
}

bool PerformanceSampler::ensureOpen(std::wstring& diagnostic) {
    if (impl_->opened && impl_->query) {
        return true;
    }

    closeQuery();
    const PDH_STATUS status = ::PdhOpenQueryW(nullptr, 0, &impl_->query);
    impl_->queryStatus = status;impl_->queryStatusKnown = true;
    if (status != ERROR_SUCCESS || !impl_->query) {
        impl_->query = nullptr;
        // PDH returns its own status codes rather than Win32 error codes, so the
        // raw value is shown instead of being run through FormatMessage, which
        // would print an unrelated system message for the same number.
        wchar_t code[32] = {};
        swprintf_s(code, L"0x%08lX", static_cast<unsigned long>(status));
        diagnostic = L"PdhOpenQueryW 失败（" + std::wstring(code) + L"），性能计数器不可用。";
        return false;
    }

    impl_->localizedCount = 0;
    impl_->missingCount = 0;

    if (scope_ == PerformanceScope::System) {
        const auto& specs = ScalarSpecs();
        impl_->scalars.resize(specs.size());
        for (std::size_t index = 0; index < specs.size(); ++index) {
            if (!addCounter(specs[index].path, impl_->scalars[index]) &&
                specs[index].alternatePath != nullptr) {
                addCounter(specs[index].alternatePath, impl_->scalars[index]);
            }
            if (!impl_->scalars[index].available) {
                ++impl_->missingCount;
            }
        }
        if (!addCounter(L"\\Processor Information(*)\\% Processor Time", impl_->cpuPerCore)) {
            addCounter(L"\\Processor(*)\\% Processor Time", impl_->cpuPerCore);
        }
        if (!addCounter(L"\\GPU Engine(*)\\Utilization Percentage", impl_->gpuEngine)) {
            ++impl_->missingCount;
        }
        addCounter(L"\\Network Interface(*)\\Bytes Received/sec", impl_->networkReceived);
        addCounter(L"\\Network Interface(*)\\Bytes Sent/sec", impl_->networkSent);
    } else {
        const auto& paths = DiskCounterPaths();
        impl_->diskCounters.resize(paths.size());
        for (std::size_t index = 0; index < paths.size(); ++index) {
            if (!addCounter(paths[index], impl_->diskCounters[index])) {
                ++impl_->missingCount;
            }
        }
    }

    // A query with no counters cannot be collected, and PDH reports that as a
    // generic failure later; failing here names the real problem instead.
    const bool anyCounter = std::any_of(impl_->scalars.begin(), impl_->scalars.end(),
                               [](const Counter& counter) { return counter.available; }) ||
        std::any_of(impl_->diskCounters.begin(), impl_->diskCounters.end(),
            [](const Counter& counter) { return counter.available; }) ||
        impl_->cpuPerCore.available || impl_->gpuEngine.available || impl_->networkReceived.available || impl_->networkSent.available;
    if (!anyCounter) {
        closeQuery();
        diagnostic = L"没有任何性能计数器可用，系统的 Perflib 计数器表可能已损坏（可用管理员权限运行 lodctr /R 重建）。";
        return false;
    }

    impl_->baselineStatus = ::PdhCollectQueryData(impl_->query);impl_->baselineStatusKnown = true;
    impl_->opened = true;
    impl_->primed = false;
    return true;
}

void PerformanceSampler::collectSystemMetrics(PerformanceSnapshot& snapshot) {
    AppendSystemStaticMetrics(snapshot);

    static const wchar_t* ids[] = {L"cpu-total",L"cpu-user",L"cpu-privileged",L"cpu-interrupts",L"cpu-dpc-queued",L"memory-available",L"memory-committed",L"memory-commit-limit",L"memory-commit-percent",L"memory-cache",L"memory-paged-pool",L"memory-nonpaged-pool",L"memory-pages",L"memory-page-faults",L"disk-current-queue",L"disk-average-queue",L"disk-busy",L"disk-read-bytes",L"disk-write-bytes",L"disk-reads",L"disk-writes",L"system-processes",L"system-threads",L"system-context-switches",L"system-uptime"};
    const auto& specs = ScalarSpecs();
    static_assert(std::size(ids) == static_cast<std::size_t>(SystemCounterId::Count));
    for (std::size_t index = 0; index < specs.size() && index < impl_->scalars.size(); ++index) {
        const Counter& counter = impl_->scalars[index];
        PerformanceMetricRow row{};
        row.id = ids[index];row.groupId = index<5 ? L"cpu" : index<14 ? L"memory" : index<21 ? L"disk" : L"system";
        switch (specs[index].format) {
        case MetricFormat::Percent:row.unit = L"percent";break;case MetricFormat::Bytes:row.unit = L"bytes";break;
        case MetricFormat::MegabytesAsBytes:row.unit = L"mebibytes";break;case MetricFormat::BytesPerSecond:row.unit = L"bytes-per-second";break;
        case MetricFormat::Count:row.unit = L"count";break;case MetricFormat::Rate:row.unit = L"per-second";break;
        case MetricFormat::UpTime:row.unit = L"seconds";break;default:row.unit = L"queue-length";break;
        }
        row.group = specs[index].group;
        row.name = specs[index].name;
        row.source = counter.available ? counter.resolvedPath : std::wstring(specs[index].path);
        double value = 0.0;
        if (counter.available && ReadScalar(counter.handle, specs[index].uncapped, value,&row.evidence)) {
            row.numericValue = value;
            row.value = FormatMetricValue(specs[index].format, value);
            row.valid = true;
        } else {
            row.value = counter.available ? L"正在采样…" : L"不可用";
        }
        if (!counter.available) {row.evidence.statusKnown = true;row.evidence.status = counter.addStatus;}
        snapshot.metrics.push_back(std::move(row));
    }

    if (impl_->cpuPerCore.available) {
        PerformanceEvidence evidence;auto cores = ReadArray(impl_->cpuPerCore.handle, false,&evidence);
        snapshot.sources.push_back({L"cpu-cores",impl_->cpuPerCore.resolvedPath,evidence,L"cpu"});
        // "Processor Information" publishes both a per-group rollup ("0,_Total")
        // and a machine-wide one ("_Total"); both are already reported as the CPU
        // total, so leaving them in would double-count the per-core section.
        cores.erase(std::remove_if(cores.begin(), cores.end(),
                        [](const std::pair<std::wstring, double>& item) {
                            return item.first.empty() ||
                                item.first.find(L"_Total") != std::wstring::npos;
                        }),
            cores.end());
        std::sort(cores.begin(), cores.end(),
            [](const std::pair<std::wstring, double>& left, const std::pair<std::wstring, double>& right) {
                return CompareInstanceNames(left.first, right.first);
            });
        for (const auto& core : cores) {
            PerformanceMetricRow row{};
            row.id = L"cpu-core";row.groupId = L"cpu";row.unit = L"percent";row.instance = core.first;row.evidence = evidence;
            row.group = L"CPU 每核";
            row.name = L"核心 " + core.first;
            row.numericValue = core.second;
            row.value = FormatPercent(core.second);
            row.source = impl_->cpuPerCore.resolvedPath;
            row.valid = true;
            snapshot.metrics.push_back(std::move(row));
        }
    } else {
        PerformanceEvidence e;e.statusKnown = true;e.status = impl_->cpuPerCore.addStatus;
        snapshot.sources.push_back({L"cpu-cores",impl_->cpuPerCore.englishPath,e,L"cpu"});
    }

    // GPU Engine publishes one counter instance per active engine. These values
    // are concurrent, so summing them would invent a "total GPU" percentage.
    // Lite reports the maximum sampled engine instead and preserves both the
    // counter-unavailable and no-instance states as explicit non-values.
    {
        PerformanceMetricRow row{};
        row.id = L"gpu-max-engine";row.groupId = L"gpu";row.unit = L"percent";
        row.group = L"GPU";
        row.name = L"最大引擎利用率（非总和）";
        row.source = impl_->gpuEngine.available
            ? impl_->gpuEngine.resolvedPath
            : L"\\GPU Engine(*)\\Utilization Percentage";
        if (!impl_->gpuEngine.available) {
            row.evidence.statusKnown = true;row.evidence.status = impl_->gpuEngine.addStatus;
            row.value = L"未提供（GPU Engine 性能计数器不可用）";
        } else {
            const auto engines = ReadArray(impl_->gpuEngine.handle, false,&row.evidence);
            if (engines.empty()) {
                row.value = L"未枚举到 GPU 引擎实例";
            } else {
                const auto peak = std::max_element(engines.begin(), engines.end(),
                    [](const std::pair<std::wstring, double>& left, const std::pair<std::wstring, double>& right) {
                        return left.second < right.second;
                    });
                row.instance = peak->first;row.numericValue = std::clamp(peak->second, 0.0, 100.0);
                row.value = FormatPercent(row.numericValue) + L"（" + peak->first + L"）";
                row.valid = true;
            }
        }
        snapshot.metrics.push_back(std::move(row));
    }

    if (impl_->networkReceived.available || impl_->networkSent.available) {
        PerformanceEvidence receivedEvidence,sentEvidence;
        const auto received = ReadArray(impl_->networkReceived.handle, false,&receivedEvidence);
        const auto sent = ReadArray(impl_->networkSent.handle, false,&sentEvidence);
        if (!impl_->networkReceived.available) {receivedEvidence.statusKnown = true;receivedEvidence.status = impl_->networkReceived.addStatus;}
        if (!impl_->networkSent.available) {sentEvidence.statusKnown = true;sentEvidence.status = impl_->networkSent.addStatus;}
        snapshot.sources.push_back({L"network-received",impl_->networkReceived.resolvedPath,receivedEvidence,L"network"});
        snapshot.sources.push_back({L"network-sent",impl_->networkSent.resolvedPath,sentEvidence,L"network"});
        std::map<std::wstring, std::pair<double, double>> adapters;
        for (const auto& item : received) {
            adapters[item.first].first = item.second;
        }
        for (const auto& item : sent) {
            adapters[item.first].second = item.second;
        }

        double totalReceived = 0.0;
        double totalSent = 0.0;
        for (const auto& adapter : adapters) {
            totalReceived += adapter.second.first;
            totalSent += adapter.second.second;
        }
        AppendStaticMetric(snapshot, L"网络", L"接收合计", FormatByteRate(totalReceived),
            impl_->networkReceived.resolvedPath.c_str(), totalReceived);
        snapshot.metrics.back().id = L"network-received-total";snapshot.metrics.back().groupId = L"network";snapshot.metrics.back().unit = L"bytes-per-second";snapshot.metrics.back().valid = receivedEvidence.complete;snapshot.metrics.back().evidence = receivedEvidence;
        AppendStaticMetric(snapshot, L"网络", L"发送合计", FormatByteRate(totalSent),
            impl_->networkSent.resolvedPath.c_str(), totalSent);
        snapshot.metrics.back().id = L"network-sent-total";snapshot.metrics.back().groupId = L"network";snapshot.metrics.back().unit = L"bytes-per-second";snapshot.metrics.back().valid = sentEvidence.complete;snapshot.metrics.back().evidence = sentEvidence;

        std::vector<std::pair<std::wstring, std::pair<double, double>>> ordered(adapters.begin(), adapters.end());
        std::sort(ordered.begin(), ordered.end(), [](const auto& left, const auto& right) {
            const double leftTotal = left.second.first + left.second.second;
            const double rightTotal = right.second.first + right.second.second;
            if (leftTotal != rightTotal) {
                return leftTotal > rightTotal;
            }
            return CompareInstanceNames(left.first, right.first);
        });
        for (const auto& adapter : ordered) {
            PerformanceMetricRow row{};
            row.id = L"network-adapter";row.groupId = L"network";row.unit = L"bytes-per-second";row.instance = adapter.first;
            row.receivedKnown = std::any_of(received.begin(),received.end(),[&](const auto& v){return v.first==adapter.first;});
            row.sentKnown = std::any_of(sent.begin(),sent.end(),[&](const auto& v){return v.first==adapter.first;});
            row.received = adapter.second.first;row.sent = adapter.second.second;
            row.group = L"网络";
            row.name = adapter.first;
            row.numericValue = adapter.second.first + adapter.second.second;
            row.value = L"↓ " + FormatByteRate(adapter.second.first) +
                L"   ↑ " + FormatByteRate(adapter.second.second);
            row.source = impl_->networkReceived.available
                ? impl_->networkReceived.resolvedPath
                : impl_->networkSent.resolvedPath;
            row.valid = row.receivedKnown && row.sentKnown;row.evidence.complete = row.valid;row.evidence.available = row.valid;
            snapshot.metrics.push_back(std::move(row));
        }
    } else {
        for (const auto& pair:{std::pair{L"network-received",&impl_->networkReceived},std::pair{L"network-sent",&impl_->networkSent}}) {
            PerformanceEvidence e;e.statusKnown = true;e.status = pair.second->addStatus;
            snapshot.sources.push_back({pair.first,pair.second->englishPath,e,L"network"});
        }
    }
}

PerformanceSnapshot PerformanceSampler::sample() {
    std::scoped_lock lock(mutex_);
    PerformanceSnapshot snapshot{};
    if (!impl_) {
        snapshot.diagnosticText = L"性能采样器未初始化。";
        return snapshot;
    }

    std::wstring diagnostic;
    if (!ensureOpen(diagnostic)) {
        snapshot.queryStatusKnown = impl_->queryStatusKnown;snapshot.queryStatus = impl_->queryStatus;
        if (scope_ == PerformanceScope::System) AppendSystemStaticMetrics(snapshot);
        snapshot.diagnosticText = diagnostic;
        return snapshot;
    }

    snapshot.queryOpened = true;snapshot.queryStatusKnown = impl_->queryStatusKnown;snapshot.queryStatus = impl_->queryStatus;
    snapshot.baselineStatusKnown = impl_->baselineStatusKnown;snapshot.baselineStatus = impl_->baselineStatus;
    if (!impl_->primed) {
        ::Sleep(kPrimingIntervalMs);
        impl_->primed = true;
    }

    const PDH_STATUS status = ::PdhCollectQueryData(impl_->query);
    snapshot.collectStatusKnown = true;snapshot.collectStatus = status;
    if (status != ERROR_SUCCESS) {
        // A collection failure is usually a transient provider fault; dropping
        // the query makes the next pass rebuild it instead of returning the same
        // error forever.
        closeQuery();
        if (scope_ == PerformanceScope::System) AppendSystemStaticMetrics(snapshot);
        snapshot.diagnosticText = L"PdhCollectQueryData 失败，已丢弃当前查询并将在下次采样时重建。";
        return snapshot;
    }

    if (scope_ == PerformanceScope::System) {
        collectSystemMetrics(snapshot);
    } else {
        collectDiskRows(snapshot);
    }

    snapshot.success = true;
    if (impl_->localizedCount > 0) {
        snapshot.counterResolutionText = L"计数器路径：本地化回退 " + std::to_wstring(impl_->localizedCount) + L" 项";
    } else {
        snapshot.counterResolutionText = L"计数器路径：英文名解析";
    }
    if (impl_->missingCount > 0) {
        snapshot.counterResolutionText += L"，缺失 " + std::to_wstring(impl_->missingCount) + L" 项";
    }
    return snapshot;
}

std::shared_ptr<PerformanceSampler> MakePerformanceSampler(const PerformanceScope scope) {
    return std::make_shared<PerformanceSampler>(scope);
}

} // namespace ks::r3::hardware_stats
