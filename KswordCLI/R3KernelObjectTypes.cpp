#include "R3KernelShared.h"
#include "../shared/usermode/backend/kernel/ObjectTypes.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::kernel;
Json row(const b::ObjectTypeEntry& e){const auto& v=e.info;
    return Json::object({{L"type",Json::string(e.name)},{L"typeIndex",Json::number(v.TypeIndex)},
        {L"objects",Json::count(v.TotalNumberOfObjects)},{L"handles",Json::count(v.TotalNumberOfHandles)},
        {L"pagedPoolBytes",Json::count(v.TotalPagedPoolUsage)},{L"nonPagedPoolBytes",Json::count(v.TotalNonPagedPoolUsage)},
        {L"namePoolBytes",Json::count(v.TotalNamePoolUsage)},{L"handleTableBytes",Json::count(v.TotalHandleTableUsage)},
        {L"highObjects",Json::count(v.HighWaterNumberOfObjects)},{L"highHandles",Json::count(v.HighWaterNumberOfHandles)},
        {L"highPagedPoolBytes",Json::count(v.HighWaterPagedPoolUsage)},{L"highNonPagedPoolBytes",Json::count(v.HighWaterNonPagedPoolUsage)},
        {L"highNamePoolBytes",Json::count(v.HighWaterNamePoolUsage)},{L"highHandleTableBytes",Json::count(v.HighWaterHandleTableUsage)},
        {L"invalidAttributes",Json::hex(v.InvalidAttributes)},{L"validAccessMask",Json::hex(v.ValidAccessMask)},
        {L"genericRead",Json::hex(v.GenericMapping.GenericRead)},{L"genericWrite",Json::hex(v.GenericMapping.GenericWrite)},
        {L"genericExecute",Json::hex(v.GenericMapping.GenericExecute)},{L"genericAll",Json::hex(v.GenericMapping.GenericAll)},
        {L"securityRequired",Json::boolean(v.SecurityRequired!=0)},{L"maintainHandleCount",Json::boolean(v.MaintainHandleCount!=0)},
        {L"poolType",Json::number(v.PoolType)},{L"defaultPagedPoolCharge",Json::count(v.DefaultPagedPoolCharge)},
        {L"defaultNonPagedPoolCharge",Json::count(v.DefaultNonPagedPoolCharge)}});
}
Result enumerate(const Args& a){const auto filter=a.get(L"--filter");const auto limit=a.u32(L"--limit",256);if(!limit||limit>256)throw std::invalid_argument("--limit must be 1..256");
    const auto snapshot=b::CollectObjectTypes();std::size_t matched=0;std::vector<Json> rows;
    for(const auto& e:snapshot.entries){if(!b::ContainsI(e.name,filter))continue;++matched;if(rows.size()<limit)rows.push_back(row(e));}
    const bool unsupported=snapshot.status==static_cast<LONG>(0xc00000bbUL)||snapshot.status==static_cast<LONG>(0xc0000002UL)||snapshot.status==static_cast<LONG>(0xc000007aUL);
    return {snapshot.malformed?4:!snapshot.apiAvailable||unsupported?5:snapshot.limited||matched>rows.size()?6:snapshot.status!=0?3:!snapshot.complete?6:0,
        Json::object({{L"source",Json::string(L"NtQueryObject(ObjectTypesInformation), shared typed R3 matrix; no R0 callback")},
            {L"filter",Json::string(filter)},{L"apiAvailable",Json::boolean(snapshot.apiAvailable)},{L"attempted",Json::boolean(snapshot.attempted)},
            {L"ntStatus",snapshot.attempted?kernel::status(snapshot.status):Json{}},{L"returnedBytes",Json::count(snapshot.returnedBytes)},{L"bufferBytes",Json::count(snapshot.bufferBytes)},
            {L"complete",Json::boolean(snapshot.complete)},{L"limited",Json::boolean(snapshot.limited)},{L"malformed",Json::boolean(snapshot.malformed)},
            {L"reportedCount",snapshot.status==0&&snapshot.attempted?Json::count(snapshot.reportedCount):Json{}},{L"parsedCount",Json::count(snapshot.entries.size())},
            {L"matchedCount",Json::count(matched)},{L"returnedCount",Json::count(rows.size())},{L"truncated",Json::boolean(matched>rows.size())},{L"types",Json::array(rows)}}),
        {L"System object type counters are observations at query time; counts can change between calls. R3 supplies names, type indexes, counters and access mappings, not kernel ObjectType addresses, callback lists or R0-only procedure pointers. No automatic R0 collection. Invalid native record/string bounds fail as malformed, not as a successful shortened matrix."}};
}
}
void registerKernelObjectTypes(){addCommand({L"kernel object-types enum",L"KswordCLI.exe kernel object-types enum [--filter TEXT] [--limit N] [--backend r3] [--json]",
    L"Query shared R3 object-type counters and access mappings.",
    L"Optional: --filter case-insensitive type name substring; --limit 1..256 output rows (256); --backend r3; --json.",
    L"Output: source/API/attempted/NTSTATUS/returned and buffer bytes, completeness/budget/malformed, reported/parsed/matched/returned counts, truncation, types. Each type has name/index, current and high-water object/handle/pool/name/handle-table counters (decimal strings), invalid attributes/access/generic mappings (hex), security/handle-count flags, pool type and default charges. Buffer growth capped at 16 MiB/8 attempts; matrix prefix capped at 256; strict status zero and native record/string bounds. Complete valid empty 0, API/class unavailable 5, native failure 3, malformed 4, collection/output limits 6. No kernel addresses/procedure pointers, R0 callback or driver open; existing r0 object-types remains unchanged. Help performs no NtQueryObject.",enumerate});}
}
