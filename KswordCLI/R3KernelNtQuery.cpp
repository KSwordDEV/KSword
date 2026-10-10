#include "R3KernelShared.h"
#include "../shared/usermode/backend/kernel/NtQuery.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::kernel;
bool unsupported(LONG s){return s==static_cast<LONG>(0xc00000bbUL)||s==static_cast<LONG>(0xc0000002UL)||s==static_cast<LONG>(0xc0000003UL)||s==static_cast<LONG>(0xc000007aUL);}
Result query(const std::wstring& category={},const std::wstring& preset={}){const auto snapshot=b::CollectNtQueries(category,preset);std::vector<Json> rows;std::size_t success=0,failures=0,missing=0;bool malformed=snapshot.tokenMalformed,limited=false;
    for(const auto& e:snapshot.queries){const auto& r=e.result;const bool ok=e.attempted&&r.status==0&&!r.malformed&&!r.limited;success+=ok;malformed=malformed||r.malformed;limited=limited||r.limited;
        if(!ok){if(!e.apiAvailable||(e.attempted&&unsupported(r.status)))++missing;else ++failures;}
        rows.push_back(Json::object({{L"category",Json::string(e.preset.category)},{L"preset",Json::string(e.preset.name)},{L"function",Json::string(e.preset.function)},{L"informationClass",Json::number(e.preset.infoClass)},
            {L"apiAvailable",Json::boolean(e.apiAvailable)},{L"attempted",Json::boolean(e.attempted)},{L"success",Json::boolean(ok)},{L"ntStatus",e.attempted?kernel::status(r.status):Json{}},
            {L"returnedBytes",e.attempted?Json::count(r.returnedBytes):Json{}},{L"allocatedBytes",e.attempted?Json::count(r.allocatedBytes):Json{}},{L"attemptCount",Json::count(r.attempts)},
            {L"limited",Json::boolean(r.limited)},{L"malformed",Json::boolean(r.malformed)}}));}
    const bool closeFailed=snapshot.tokenCloseAttempted&&!snapshot.tokenClosed;
    return {malformed?4:limited||closeFailed?6:success==rows.size()?0:success?6:failures?3:5,
        Json::object({{L"source",Json::string(L"shared fixed native query presets; current CLI process/thread/token only")},
            {L"selfProcessId",Json::number(snapshot.processId)},{L"selfThreadId",Json::number(snapshot.threadId)},{L"category",category.empty()?Json{}:Json::string(category)},{L"preset",preset.empty()?Json{}:Json::string(preset)},
            {L"queryCount",Json::count(rows.size())},{L"successCount",Json::count(success)},{L"failedCount",Json::count(failures)},{L"unavailableCount",Json::count(missing)},
            {L"limited",Json::boolean(limited)},{L"malformed",Json::boolean(malformed)},{L"queries",Json::array(rows)},
            {L"token",Json::object({{L"openAttempted",Json::boolean(snapshot.tokenOpenAttempted)},{L"opened",snapshot.tokenOpenAttempted?Json::boolean(snapshot.tokenOpened):Json{}},
                {L"openWin32Error",snapshot.tokenOpenAttempted?Json::number(snapshot.tokenOpenError):Json{}},{L"closeAttempted",Json::boolean(snapshot.tokenCloseAttempted)},
                {L"closed",snapshot.tokenCloseAttempted?Json::boolean(snapshot.tokenClosed):Json{}},{L"closeWin32Error",snapshot.tokenCloseAttempted?Json::number(snapshot.tokenCloseError):Json{}}})}}),
        {L"Safe existing preset probes, not an arbitrary class/handle dispatch. Native success/status, actual returned byte length and allocated capacity are distinct. Fixed-size length mismatches may shrink to the returned requirement; grow/retry is capped at 16 MiB/6 calls. Raw pointer-bearing buffers are not interpreted or serialized. A probe succeeding does not prove a security/state property. Current pseudo handles are borrowed; the owned query token closes before output. No target PID, mutation, kernel call or R0 fallback."}};
}
Result exports(const Args& a){const auto filter=a.get(L"--filter");const auto limit=a.u32(L"--limit",512);if(!limit||limit>512)throw std::invalid_argument("--limit must be 1..512");const auto snapshot=b::CollectNtQueryExports();std::size_t matched=0;std::vector<Json> rows;
    for(const auto& e:snapshot.entries){if(!b::ContainsI(e.name,filter))continue;++matched;if(rows.size()<limit)rows.push_back(Json::object({{L"name",Json::string(e.name)},{L"ordinal",Json::number(e.ordinal)},{L"rva",Json::hex(e.rva)},{L"forwarded",Json::boolean(e.forwarded)}}));}
    return {snapshot.malformed?4:!snapshot.moduleAvailable?5:snapshot.win32Error?3:snapshot.limited||matched>rows.size()?6:!snapshot.complete?5:0,
        Json::object({{L"source",Json::string(L"shared bounded copy of current loaded ntdll PE export directory")},{L"filter",Json::string(filter)},
            {L"moduleAvailable",Json::boolean(snapshot.moduleAvailable)},{L"imageBytes",Json::count(snapshot.imageBytes)},{L"win32Error",Json::number(snapshot.win32Error)},
            {L"complete",Json::boolean(snapshot.complete)},{L"limited",Json::boolean(snapshot.limited)},{L"malformed",Json::boolean(snapshot.malformed)},
            {L"namedExportCount",Json::count(snapshot.namedExports)},{L"ntQueryExportCount",Json::count(snapshot.entries.size())},{L"matchedCount",Json::count(matched)},
            {L"returnedCount",Json::count(rows.size())},{L"truncated",Json::boolean(matched>rows.size())},{L"exports",Json::array(rows)}}),
        {L"NtQuery-prefixed exported names/RVAs in this CLI's loaded ntdll. An export is not evidence that any class is supported, safe to call, hook-free or present in another process. Export table/arrays/strings/ordinals/function RVAs are checked within an owned image copy (maximum 64 MiB); borrowed DLL handle is not freed. No export invocation, arbitrary module input or R0 fallback."}};
}
}
void registerKernelNtQuery(){
    const std::wstring notes=L"Output: self process/thread identity, named preset/API/class, attempted/success/actual NTSTATUS, returned bytes vs allocated capacity, attempts/limits/malformed, aggregate counts and owned token open/close evidence. Only existing fixed safe system/current process/current thread/current token/current process-object presets. No arbitrary class/PID/handle or payload decoding, security-state inference, modification or R0 fallback. Strict native status zero; complete calls 0, mixed calls/cleanup/limits 6, all failed calls 3, API/class unavailable 5, invalid native lengths 4. Help does not query native APIs.";
    addCommand({L"kernel nt-query query",L"KswordCLI.exe kernel nt-query query [--backend r3] [--json]",L"Probe all 18 existing safe native query presets.",L"Optional: --backend r3; --json.",notes,[](const Args&){return query();}});
    for(const auto& p:b::NtQueryPresets()){const auto path=L"kernel nt-query "+p.category+L" "+p.name+L" query";
        addCommand({path,L"KswordCLI.exe "+path+L" [--backend r3] [--json]",L"Probe "+p.function+L" "+p.name+L" on the existing safe query scope.",L"Optional: --backend r3; --json.",notes,[category=p.category,name=p.name](const Args&){return query(category,name);}});}
    addCommand({L"kernel nt-query exports enum",L"KswordCLI.exe kernel nt-query exports enum [--filter TEXT] [--limit N] [--backend r3] [--json]",L"List NtQuery-prefixed exports of this CLI's loaded ntdll.",
        L"Optional: --filter case-insensitive export name substring; --limit 1..512 (512); --backend r3; --json.",
        L"Output: module/image/read/PE status, named/NtQuery/matched/returned counts, completeness/limits/truncation, export name/ordinal/RVA (hex)/forwarded flag. Bounded image copy and PE tables/strings; not export invocation or integrity verification. Complete valid empty 0, unavailable module 5, image read failure 3, malformed PE 4, collection/output limits 6. No arbitrary module input or R0 fallback; help does not inspect loaded images.",exports});
}
}
