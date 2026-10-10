#include "R3KernelShared.h"
#include "../shared/usermode/backend/kernel/AtomTable.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::kernel;
Json name(const b::AtomNameEvidence& e){return Json::object({{L"attempted",Json::boolean(e.attempted)},{L"available",e.attempted?Json::boolean(e.available):Json{}},
    {L"absent",e.attempted?Json::boolean(e.absent):Json{}},{L"win32Error",e.attempted?Json::number(e.error):Json{}},{L"malformed",Json::boolean(e.malformed)},
    {L"name",e.available?Json::string(e.name):Json{}}});}
Result enumerate(const Args& a){const auto scope=a.get(L"--scope",L"all"),filter=a.get(L"--filter");if(scope!=L"all"&&scope!=L"global"&&scope!=L"clipboard")throw std::invalid_argument("--scope must be all, global or clipboard");
    b::AtomQueryOptions options;options.first=a.u32(L"--start-id",0xc000);options.last=a.u32(L"--end-id",0xffff);options.global=scope!=L"clipboard";options.clipboard=scope!=L"global";
    if(options.first<0xc000||options.last>0xffff||options.first>options.last)throw std::invalid_argument("atom ID range must be within 0xc000..0xffff, start <= end");
    const auto duration=a.u32(L"--duration-ms",8000),limit=a.u32(L"--limit",16384);if(duration<100||duration>30000)throw std::invalid_argument("--duration-ms must be 100..30000");if(!limit||limit>16384)throw std::invalid_argument("--limit must be 1..16384");
    Cancellation cancel;options.cancelled=[token=cancel.token]{return token->load(std::memory_order_relaxed);};options.deadlineTick=::GetTickCount64()+duration;
    const auto snapshot=b::CollectAtoms(options);std::size_t matched=0;std::vector<Json> rows;
    for(const auto& e:snapshot.entries){if(!b::ContainsI(e.global.name,filter)&&!b::ContainsI(e.clipboard.name,filter)&&!b::ContainsI(b::HexText(e.id),filter))continue;++matched;if(rows.size()<limit)rows.push_back(Json::object({
        {L"id",Json::number(e.id)},{L"hexId",Json::hex(e.id)},{L"global",name(e.global)},{L"clipboard",name(e.clipboard)},
        {L"sameName",e.global.available&&e.clipboard.available?Json::boolean(_wcsicmp(e.global.name.c_str(),e.clipboard.name.c_str())==0):Json{}}}));}
    return {snapshot.malformed?4:snapshot.failedQueries&&!snapshot.globalFound&&!snapshot.clipboardFound?5:!snapshot.complete||snapshot.failedQueries||matched>rows.size()?6:0,
        Json::object({{L"source",Json::string(L"shared GlobalGetAtomNameW / GetClipboardFormatNameW string-ID range")},{L"scope",Json::string(scope)},{L"filter",Json::string(filter)},
            {L"startId",Json::hex(options.first)},{L"endId",Json::hex(options.last)},{L"completeRange",Json::boolean(snapshot.complete)},{L"evidenceComplete",Json::boolean(snapshot.complete&&!snapshot.failedQueries&&!snapshot.malformed)},
            {L"limited",Json::boolean(snapshot.limited)},{L"cancelled",Json::boolean(snapshot.cancelled)},{L"malformed",Json::boolean(snapshot.malformed)},
            {L"scannedIdCount",Json::count(snapshot.scannedIds)},{L"globalNameCount",Json::count(snapshot.globalFound)},{L"clipboardNameCount",Json::count(snapshot.clipboardFound)},
            {L"failedQueryCount",Json::count(snapshot.failedQueries)},{L"matchedCount",Json::count(matched)},{L"returnedCount",Json::count(rows.size())},{L"truncated",Json::boolean(matched>rows.size())},{L"atoms",Json::array(rows)}}),
        {L"String atom/registered clipboard-format ID observations only (0xc000..0xffff). Global and clipboard names for an ID are separate evidence and may differ. Unallocated IDs with documented invalid-handle/parameter/not-found errors are valid holes, not failed enumeration. Unexpected/zero-error failed queries remain unavailable. No local process atom-table traversal, integer atom/predefined clipboard formats, ownership/refcount inference, atom creation/deletion or clipboard open/read/write. Help does not scan IDs."}};
}
}
void registerKernelAtoms(){addCommand({L"kernel atoms enum",L"KswordCLI.exe kernel atoms enum [--scope all|global|clipboard] [--start-id N] [--end-id N] [--filter TEXT] [--duration-ms N] [--limit N] [--backend r3] [--json]",
    L"Enumerate shared R3 string atom and registered clipboard-format names.",
    L"Optional: --scope all|global|clipboard (all); --start-id/--end-id within 0xc000..0xffff (entire range, start <= end); --filter case-insensitive name/hex ID substring; --duration-ms 100..30000 (8000); --limit 1..16384 output IDs (16384); --backend r3; --json.",
    L"Output: scope/range/filter, completeRange/evidenceComplete, budget/cancel/malformed, scanned/global/clipboard/failed/matched/returned counts, truncation and atoms with numeric/hex IDs, separate attempted/available/absent/Win32-error/name evidence and nullable sameName. A queried hole can succeed with empty results; unqueried/not-applicable and unavailable are null. Complete valid empty 0, unexpected failure without names 5, mixed query failures/budget/cancel/output truncation 6, malformed API length 4. No process-local/integer atoms, predefined clipboard formats, inferred owners/refcounts, writes or R0 fallback. Help performs no scan.",enumerate});}
}
