#pragma once
#include "../Common.h"
#include "KernelTypes.h"
#include <winternl.h>
#include <array>
#include <deque>
#include <functional>
#include <set>
#include <string_view>
#include <unordered_map>
#include "ObjectNamespace.h"
#include "ObjectDirectory.h"
#include "SymbolicLinks.h"
#include "DeviceDriverObjects.h"
#include "BaseNamedObjects.h"
#include "CommunicationEndpoints.h"
#include "ObjectTypes.h"
#include "NamedPipes.h"
#include "AtomTable.h"
namespace ks::r3::kernel {
constexpr std::size_t kMaxExportRows = 512;
std::pair<LONG, std::vector<std::byte>> QueryGrowable(const std::function<LONG(PVOID, ULONG, PULONG)>& query, ULONG initialSize);
void AppendNtQueryRow(QueryPacket& packet, const std::wstring& filter, const std::wstring& category, const std::wstring& functionName, ULONG infoClass, LONG status, std::size_t bytes, const std::wstring& detail);
void AppendNtdllExportRows(QueryPacket& packet, const std::wstring& filter);
KernelOperationResult QueryNtQueryLegacy(const KernelRequest& request);
}
