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
struct NativeQueryBuffer {LONG status=0;ULONG returnedBytes=0,allocatedBytes=0,attempts=0;bool limited=false,malformed=false;std::vector<std::byte> bytes;};
NativeQueryBuffer QueryBounded(const std::function<LONG(PVOID,ULONG,PULONG)>& query,ULONG initialSize);
struct NtQueryPreset {std::wstring category,name,function;ULONG infoClass=0,initialSize=4096;};
const std::vector<NtQueryPreset>& NtQueryPresets();
struct NtQueryEvidence {NtQueryPreset preset;bool apiAvailable=false,attempted=false;NativeQueryBuffer result;};
struct NtQuerySnapshot {DWORD processId=0,threadId=0;bool tokenOpenAttempted=false,tokenOpened=false,tokenMalformed=false,tokenCloseAttempted=false,tokenClosed=false;DWORD tokenOpenError=0,tokenCloseError=0;std::vector<NtQueryEvidence> queries;};
NtQuerySnapshot CollectNtQueries(const std::wstring& category={},const std::wstring& name={});
struct NtExportEntry {std::wstring name;ULONG ordinal=0,rva=0;bool forwarded=false;};
struct NtExportsSnapshot {bool moduleAvailable=false,complete=false,limited=false,malformed=false;DWORD win32Error=0,imageBytes=0;ULONG namedExports=0;std::vector<NtExportEntry> entries;};
NtExportsSnapshot CollectNtQueryExports();
std::pair<LONG, std::vector<std::byte>> QueryGrowable(const std::function<LONG(PVOID, ULONG, PULONG)>& query, ULONG initialSize);
void AppendNtQueryRow(QueryPacket& packet, const std::wstring& filter, const std::wstring& category, const std::wstring& functionName, ULONG infoClass, LONG status, std::size_t bytes, const std::wstring& detail);
void AppendNtdllExportRows(QueryPacket& packet, const std::wstring& filter);
KernelOperationResult QueryNtQueryLegacy(const KernelRequest& request);
}
