#pragma once
#include "ProcessFields.h"
#include <unordered_map>
namespace ks::r3::process {
std::wstring ProcessStableKey(DWORD processId, ULONGLONG creationTime100ns);
std::wstring FormatByteSize(ULONGLONG bytes);
void ApplyMainProcessDetails(std::vector<ProcessSnapshotRow>& rows, const std::vector<ProcessFieldId>& columns, std::unordered_map<std::wstring, std::string>& signatureCache, bool needsStatic);
}
