#pragma once
#include "ProcessFields.h"
#include <unordered_map>
#include <functional>
#include "ProcessExtraQueries.h"
namespace ks::r3::process {
std::wstring ProcessStableKey(DWORD processId, ULONGLONG creationTime100ns);
std::wstring FormatByteSize(ULONGLONG bytes);
struct ProcessDetailEvidence {
    ks::process::ProcessRecord record;
    std::uint32_t resolvedDemand = 0;
    ProcessExtraEvidence extra;
};
void ApplyMainProcessDetails(std::vector<ProcessSnapshotRow>& rows, const std::vector<ProcessFieldId>& columns, std::unordered_map<std::wstring, std::string>& signatureCache, bool needsStatic,
    const std::function<void(const ProcessDetailEvidence&)>& observe = {});
}
