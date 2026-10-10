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
namespace ks::r3::kernel {
constexpr ULONG kObjectTypesInformation = 3;
constexpr std::size_t kMaxTypeRows = 256;
struct KOBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
};
bool MatchesColumnsFilter(const KernelResultRow& row, const std::wstring& filter);
struct ObjectTypeEntry {std::wstring name;KOBJECT_TYPE_INFORMATION info{};};
struct ObjectTypesSnapshot {
    bool apiAvailable=false,attempted=false,complete=false,limited=false,malformed=false;
    LONG status=0;ULONG returnedBytes=0,bufferBytes=0,reportedCount=0;
    std::vector<ObjectTypeEntry> entries;
};
ObjectTypesSnapshot CollectObjectTypes();
std::uintptr_t AlignPointer(const std::uintptr_t value);
KernelOperationResult QueryObjectTypeMatrixR3(const KernelRequest& request, const std::function<void(QueryPacket&)>& appendR0);
}
