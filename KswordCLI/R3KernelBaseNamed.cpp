#include "R3KernelShared.h"
#include "../shared/usermode/backend/kernel/BaseNamedObjects.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::kernel;
Result enumerate(const Args& a){const auto scope=a.get(L"--scope",L"all"),filter=a.get(L"--filter");if(scope!=L"all"&&scope!=L"global"&&scope!=L"session")throw std::invalid_argument("--scope must be all, global or session");
    if((scope==L"session")!=a.has(L"--session-id"))throw std::invalid_argument("--session-id is required only for --scope session");const auto session=a.u32(L"--session-id",0);
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");Cancellation cancel;const auto options=kernel::options(a,cancel);
    std::vector<std::wstring> roots,warnings;std::vector<Json> rows,sources;Json discoveryJson;b::DirectoryQueryEvidence discovery;DWORD sessionError=0;bool sessionKnown=false,partial=false,malformed=false;
    if(scope==L"all"){roots=b::BaseNamedObjectRoots(&discovery,&sessionError,options,&sessionKnown);discoveryJson=kernel::source(discovery,partial,malformed);partial=partial||!sessionKnown;}
    else roots={scope==L"global"?L"\\BaseNamedObjects":L"\\Sessions\\"+std::to_wstring(session)+L"\\BaseNamedObjects"};
    std::size_t scanned=0,readable=0,enumerated=0,matched=0;bool api=false,limited=discovery.limited;
    for(const auto& root:roots){if(cancel.token->load(std::memory_order_relaxed)||::GetTickCount64()>=options.deadlineTick){limited=true;break;}
        b::DirectoryQueryEvidence evidence;const auto entries=b::EnumerateDirectoryFlat(b::Runtime(),root,warnings,&evidence,options);++scanned;api=api||evidence.apiAvailable;
        if(evidence.complete||!entries.empty())++readable;limited=limited||evidence.limited;enumerated+=entries.size();sources.push_back(kernel::source(evidence,partial,malformed));
        for(const auto& e:entries){kernel::observeEntry(e,partial,malformed);if(!b::MatchesDirectoryFilter(e,filter))continue;++matched;if(rows.size()<limit)rows.push_back(kernel::entry(e,root,0,partial,malformed));}}
    limited=limited||scanned<roots.size();const bool cancelled=cancel.token->load(std::memory_order_relaxed);
    return {malformed?4:!api&&!sources.empty()?5:!readable&&!limited&&!cancelled?3:partial||limited||cancelled||matched>rows.size()?6:0,
        Json::object({{L"source",Json::string(L"shared BaseNamedObjects root + discovered session BaseNamedObjects directories")},
            {L"scope",Json::string(scope)},{L"sessionId",scope==L"session"?Json::number(session):Json{}},{L"filter",Json::string(filter)},{L"roots",Json::strings(roots)},
            {L"sessionDiscovery",discoveryJson},{L"currentSessionKnown",scope==L"all"?Json::boolean(sessionKnown):Json{}},{L"currentSessionWin32Error",scope==L"all"?Json::number(sessionError):Json{}},
            {L"sources",Json::array(sources)},{L"scannedRootCount",Json::count(scanned)},{L"enumeratedCount",Json::count(enumerated)},
            {L"matchedCount",Json::count(matched)},{L"returnedCount",Json::count(rows.size())},{L"truncated",Json::boolean(matched>rows.size())},
            {L"limited",Json::boolean(limited)},{L"cancelled",Json::boolean(cancelled)},{L"malformed",Json::boolean(malformed)},{L"objects",Json::array(rows)}}),
        {L"Named-object registrations and directory/link evidence; no ownership PID or kernel address inference, object creation/control, private namespace bypass or R0 fallback. Global selects the literal native BaseNamedObjects root; session selects the explicit Sessions/SID path. Discovery fallback keeps session 0/current candidates and reports incomplete discovery instead of claiming a complete session list."}};
}
}
void registerKernelBaseNamed(){addCommand({L"kernel base-named-objects enum",L"KswordCLI.exe kernel base-named-objects enum [--scope all|global|session] [--session-id N] [--filter TEXT] [--max-entries N] [--duration-ms N] [--limit N] [--backend r3] [--json]",
    L"Enumerate R3 BaseNamedObjects and explicit/discovered session roots.",
    L"Optional: --scope all|global|session (all); --session-id uint32 required only for session (0 allowed); --filter case-insensitive path/name/type/target substring; --max-entries 1..100000 per directory (100000); --duration-ms 100..30000 entire sweep (8000); --limit 1..100000 displayed entries (1000); --backend r3; --json.",
    L"Output: scope/session/roots, typed session discovery and current-session availability, source open/query/close/completeness, counts, limits/cancel/malformed and namespace objects. Global is the literal BaseNamedObjects native root, not a claim about every application namespace. Session roots may be denied/absent; native statuses remain explicit. Non-directory/link types have null unsupported metadata fields. Complete valid empty/filter-empty 0, incomplete discovery/roots/metadata/close/truncation/limits 6, selected/all unreadable roots 3, unavailable directory API 5, malformed 4. No owner PID/kernel address inference, object creation/set/control or R0 fallback. Help performs no session discovery or queries.",enumerate});}
}
