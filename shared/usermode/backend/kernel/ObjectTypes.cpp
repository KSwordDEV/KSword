#include "ObjectTypes.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
ObjectTypesSnapshot CollectObjectTypes(){
    ObjectTypesSnapshot result;const auto& runtime=Runtime();result.apiAvailable=runtime.queryObject!=nullptr;if(!result.apiAvailable)return result;
    ULONG size=256*1024;std::vector<std::byte> buffer;
    for(int attempt=0;attempt<8;++attempt){buffer.assign(size,std::byte{});result.attempted=true;result.returnedBytes=0;result.bufferBytes=size;
        result.status=runtime.queryObject(nullptr,kObjectTypesInformation,buffer.data(),size,&result.returnedBytes);
        if(result.status==0)break;if(!IsRetryStatus(result.status))return result;
        const auto next=(std::max<std::uint64_t>)(std::uint64_t(size)*2,std::uint64_t(result.returnedBytes)+65536);
        if(next>16u*1024u*1024u){result.limited=true;return result;}size=static_cast<ULONG>(next);
    }
    if(result.status!=0){result.limited=IsRetryStatus(result.status);return result;}
    if(result.returnedBytes<sizeof(ULONG)||result.returnedBytes>buffer.size()){result.malformed=true;return result;}
    memcpy(&result.reportedCount,buffer.data(),sizeof(ULONG));
    const auto begin=reinterpret_cast<std::uintptr_t>(buffer.data()),end=begin+result.returnedBytes;auto cursor=AlignPointer(begin+sizeof(ULONG));
    const auto count=(std::min<std::size_t>)(result.reportedCount,kMaxTypeRows);
    for(std::size_t index=0;index<count;++index){
        if(cursor>end||end-cursor<sizeof(KOBJECT_TYPE_INFORMATION)){result.malformed=true;break;}
        KOBJECT_TYPE_INFORMATION value{};memcpy(&value,reinterpret_cast<const void*>(cursor),sizeof(value));const auto& text=value.TypeName;const auto address=reinterpret_cast<std::uintptr_t>(text.Buffer);
        if((text.Length&1)||(text.MaximumLength&1)||text.Length>text.MaximumLength||address<cursor+sizeof(value)||address>end||text.MaximumLength>end-address||text.MaximumLength>end-cursor-sizeof(value)||(address&1)||value.SecurityRequired>1||value.MaintainHandleCount>1){result.malformed=true;break;}
        ObjectTypeEntry entry;entry.name.assign(text.Buffer,text.Length/sizeof(wchar_t));entry.info=value;entry.info.TypeName={};result.entries.push_back(std::move(entry));
        cursor=AlignPointer(cursor+sizeof(value)+text.MaximumLength);
    }
    result.limited=result.reportedCount>count;result.complete=!result.malformed&&!result.limited&&result.entries.size()==result.reportedCount;return result;
}
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
    QueryPacket packet;
    const auto snapshot=CollectObjectTypes();
    if (!snapshot.apiAvailable) {
        packet.warnings.push_back(L"NtQueryObject 不可用。");
        if (appendR0) { appendR0(packet); }
        return MakeResult(request.featureId, !packet.rows.empty(), L"对象类型矩阵", std::move(packet));
    }

    if (snapshot.status!=0||snapshot.malformed) {
        packet.warnings.push_back(std::wstring(L"NtQueryObject(ObjectTypesInformation) 失败，NTSTATUS=") + StatusText(snapshot.status));
        if (appendR0) { appendR0(packet); }
        return MakeResult(request.featureId, !packet.rows.empty(), L"对象类型矩阵", std::move(packet));
    }

    const ULONG count=snapshot.reportedCount;const auto limit=snapshot.entries.size();
    for (std::size_t index=0;index<limit;++index) {
        const auto* typeInfo=&snapshot.entries[index].info;
        const std::wstring& typeName=snapshot.entries[index].name;
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

    }

    if (count > limit) {
        packet.warnings.push_back(std::wstring(L"对象类型数量 ") + std::to_wstring(count) + L"，本次显示前 " + std::to_wstring(limit) + L" 项。");
    }
    if (appendR0) { appendR0(packet); }
    return MakeResult(request.featureId, !packet.rows.empty(), L"对象类型矩阵", std::move(packet));
}
}
