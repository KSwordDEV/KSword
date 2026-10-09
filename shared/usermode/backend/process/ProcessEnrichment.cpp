#include "ProcessEnrichment.h"
#include "ProcessDetails.h"
#include "ProcessExtraQueries.h"
#include <algorithm>
#include <unordered_set>
#include <cwchar>
namespace ks::r3::process {
std::wstring ProcessStableKey(const DWORD processId, const ULONGLONG creationTime100ns) {
    return L"pid:" + std::to_wstring(processId) + L"#" + std::to_wstring(creationTime100ns);
}
std::wstring FormatByteSize(ULONGLONG bytes) {
    const wchar_t* suffixes[] = { L"B", L"KiB", L"MiB", L"GiB", L"TiB" };
    double value = static_cast<double>(bytes);
    int suffix = 0;
    while (value >= 1024.0 && suffix < 4) {
        value /= 1024.0;
        ++suffix;
    }
    wchar_t buffer[64]{};
    if (suffix == 0) {
        ::swprintf_s(buffer, L"%llu %s", static_cast<unsigned long long>(bytes), suffixes[suffix]);
    } else {
        ::swprintf_s(buffer, L"%.1f %s", value, suffixes[suffix]);
    }
    return buffer;
}
void ApplyMainProcessDetails(std::vector<ProcessSnapshotRow>& rows,
    const std::vector<ProcessFieldId>& columns,
    std::unordered_map<std::wstring, std::string>& signatureCache, bool needsStatic) {
    const std::uint32_t demand = DetailDemandForColumns(columns);
    const auto has = [&columns](ProcessFieldId id) {
        return std::find(columns.begin(), columns.end(), id) != columns.end();
    };
    const auto records = ks::process::EnumerateProcesses(ks::process::ProcessEnumStrategy::Auto, nullptr, demand);
    std::unordered_map<std::uint32_t, const ks::process::ProcessRecord*> byPid;
    for (const auto& record : records) byPid[record.pid] = &record;
    std::unordered_set<std::wstring> liveKeys;
    std::size_t signatureBudget = 24;
    for (auto& row : rows) {
        const auto found = byPid.find(row.processId);
        if (found == byPid.end() || row.r0KernelOnly) continue;
        ks::process::ProcessRecord details = *found->second;
        if (row.creationTime100ns != 0 && row.creationTime100ns != details.creationTime100ns) continue;
        const auto key = ProcessStableKey(row.processId, row.creationTime100ns);
        liveKeys.insert(key);
        if (needsStatic) {
            const bool verifySignature = has(ProcessFieldId::Signature) && signatureBudget > 0 &&
                signatureCache.find(key) == signatureCache.end() && row.processId > 4 && !row.imagePath.empty();
            if (verifySignature) --signatureBudget;
            ks::process::FillProcessStaticDetails(details, verifySignature);
            // Inaccessible rows must not consume the entire signing budget
            // every round and starve ordinary processes further down the list.
            if (verifySignature && !details.staticDetailsReady) ++signatureBudget;
            ks::process::FillProcessOnDemandDetails(details, demand, nullptr);
            QueryProcessExtraDetails(details, demand, has(ProcessFieldId::PowerThrottling));
            // A new handle may have resolved a recycled PID while we queried.
            if (row.processId > 4) {
                HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row.processId);
                FILETIME created{}, exited{}, kernel{}, user{};
                const bool ok = process && ::GetProcessTimes(process, &created, &exited, &kernel, &user);
                if (process) ::CloseHandle(process);
                const ULONGLONG actual = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32U) | created.dwLowDateTime;
                if (ok && actual != row.creationTime100ns) continue;
            }
            if (verifySignature && details.staticDetailsReady && !details.signatureState.empty())
                signatureCache[key] = details.signatureState;
            const auto signature = signatureCache.find(key);
            if (signature != signatureCache.end()) details.signatureState = signature->second;
        }
        if (has(ProcessFieldId::PplLevel) || has(ProcessFieldId::Protection) || has(ProcessFieldId::Ppl)) {
            details.protectionLevelKnown = ks::process::QueryProcessProtectionLevelByPid(
                details.pid, &details.protectionLevel, &details.protectionLevelText, nullptr);
        }
        ApplyProcessDetailRecord(row, details);
        if (details.gpuMemoryKnown) {
            row.detailTexts[static_cast<std::uint8_t>(ProcessFieldId::GpuDedicatedMemory)] = FormatByteSize(details.gpuDedicatedMemoryBytes);
            row.detailTexts[static_cast<std::uint8_t>(ProcessFieldId::GpuSharedMemory)] = FormatByteSize(details.gpuSharedMemoryBytes);
        }
        if (!details.gpuMemoryKnown) {
            row.detailTexts[static_cast<std::uint8_t>(ProcessFieldId::GpuDedicatedMemory)] = L"计数器不支持或查询失败";
            row.detailTexts[static_cast<std::uint8_t>(ProcessFieldId::GpuSharedMemory)] = L"计数器不支持或查询失败";
        }
    }
    std::erase_if(signatureCache, [&liveKeys](const auto& entry) { return liveKeys.find(entry.first) == liveKeys.end(); });
}
}
