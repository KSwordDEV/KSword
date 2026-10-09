#include "ObjectTypes.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
bool MatchesColumnsFilter(const KernelResultRow& row, const std::wstring& filter) {
    if (filter.empty()) {
        return true;
    }
    if (ContainsI(row.detailText, filter)) {
        return true;
    }
    for (const auto& column : row.columns) {
        if (ContainsI(column.first, filter) || ContainsI(column.second, filter)) {
            return true;
        }
    }
    return false;
}
std::uintptr_t AlignPointer(const std::uintptr_t value) {
    const std::uintptr_t align = sizeof(void*) - 1;
    return (value + align) & ~align;
}
KernelOperationResult QueryObjectTypeMatrixR3(const KernelRequest& request, const std::function<void(QueryPacket&)>& appendR0) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    if (!runtime.queryObject) {
        packet.warnings.push_back(L"NtQueryObject 不可用。");
        if (appendR0) { appendR0(packet); }
        return MakeResult(request.featureId, !packet.rows.empty(), L"对象类型矩阵", std::move(packet));
    }

    ULONG bufferSize = 256 * 1024;
    std::vector<std::byte> buffer;
    LONG status = kStatusInfoLengthMismatch;
    for (int attempt = 0; attempt < 6; ++attempt) {
        buffer.assign(bufferSize, std::byte{});
        ULONG returned = 0;
        status = runtime.queryObject(nullptr, kObjectTypesInformation, buffer.data(), bufferSize, &returned);
        if (IsSuccessStatus(status)) {
            break;
        }
        if (!IsRetryStatus(status)) {
            break;
        }
        bufferSize = std::max<ULONG>(bufferSize * 2, returned + 0x10000);
    }

    if (!IsSuccessStatus(status) || buffer.size() < sizeof(ULONG)) {
        packet.warnings.push_back(std::wstring(L"NtQueryObject(ObjectTypesInformation) 失败，NTSTATUS=") + StatusText(status));
        if (appendR0) { appendR0(packet); }
        return MakeResult(request.featureId, !packet.rows.empty(), L"对象类型矩阵", std::move(packet));
    }

    const ULONG count = *reinterpret_cast<const ULONG*>(buffer.data());
    std::uintptr_t cursor = AlignPointer(reinterpret_cast<std::uintptr_t>(buffer.data() + sizeof(ULONG)));
    const std::uintptr_t end = reinterpret_cast<std::uintptr_t>(buffer.data() + buffer.size());
    const std::size_t limit = std::min<std::size_t>(count, kMaxTypeRows);
    for (std::size_t index = 0; index < limit && cursor + sizeof(KOBJECT_TYPE_INFORMATION) <= end; ++index) {
        const auto* typeInfo = reinterpret_cast<const KOBJECT_TYPE_INFORMATION*>(cursor);
        const std::wstring typeName = CountedString(typeInfo->TypeName);
        KernelResultRow row = Row({
            { L"Index", std::to_wstring(index) },
            { L"TypeIndex", std::to_wstring(typeInfo->TypeIndex) },
            { L"Type", typeName.empty() ? L"<unknown>" : typeName },
            { L"Objects", std::to_wstring(typeInfo->TotalNumberOfObjects) },
            { L"Handles", std::to_wstring(typeInfo->TotalNumberOfHandles) },
            { L"HighObjects", std::to_wstring(typeInfo->HighWaterNumberOfObjects) },
            { L"HighHandles", std::to_wstring(typeInfo->HighWaterNumberOfHandles) },
            { L"PagedPool", std::to_wstring(typeInfo->TotalPagedPoolUsage) },
            { L"NonPagedPool", std::to_wstring(typeInfo->TotalNonPagedPoolUsage) },
            { L"NamePool", std::to_wstring(typeInfo->TotalNamePoolUsage) },
            { L"HandleTable", std::to_wstring(typeInfo->TotalHandleTableUsage) },
            { L"HighPagedPool", std::to_wstring(typeInfo->HighWaterPagedPoolUsage) },
            { L"HighNonPagedPool", std::to_wstring(typeInfo->HighWaterNonPagedPoolUsage) },
            { L"ValidAccess", HexText(typeInfo->ValidAccessMask) },
            { L"InvalidAttributes", HexText(typeInfo->InvalidAttributes) },
            { L"GenericRead", HexText(typeInfo->GenericMapping.GenericRead) },
            { L"GenericWrite", HexText(typeInfo->GenericMapping.GenericWrite) },
            { L"GenericExecute", HexText(typeInfo->GenericMapping.GenericExecute) },
            { L"GenericAll", HexText(typeInfo->GenericMapping.GenericAll) },
            { L"SecurityRequired", typeInfo->SecurityRequired ? L"true" : L"false" },
            { L"MaintainHandleCount", typeInfo->MaintainHandleCount ? L"true" : L"false" },
            { L"PoolType", std::to_wstring(typeInfo->PoolType) },
            { L"DefaultPagedCharge", std::to_wstring(typeInfo->DefaultPagedPoolCharge) },
            { L"DefaultNonPagedCharge", std::to_wstring(typeInfo->DefaultNonPagedPoolCharge) },
        });
        if (MatchesColumnsFilter(row, request.filterText)) {
            packet.rows.push_back(std::move(row));
        }

        cursor += sizeof(KOBJECT_TYPE_INFORMATION);
        cursor += typeInfo->TypeName.MaximumLength;
        cursor = AlignPointer(cursor);
    }

    if (count > limit) {
        packet.warnings.push_back(std::wstring(L"对象类型数量 ") + std::to_wstring(count) + L"，本次显示前 " + std::to_wstring(limit) + L" 项。");
    }
    if (appendR0) { appendR0(packet); }
    return MakeResult(request.featureId, !packet.rows.empty(), L"对象类型矩阵", std::move(packet));
}
}
