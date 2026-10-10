#include "R3KernelShared.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::kernel;
Result enumerate(const Args& a){const auto root=a.has(L"--root")?kernel::path(a):std::wstring{};const auto filter=a.get(L"--filter");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");
    Cancellation cancel;const auto options=kernel::options(a,cancel);std::vector<std::wstring> roots,warnings;std::vector<Json> rows,sources;
    b::DirectoryQueryEvidence discovery;DWORD sessionError=0;bool partial=false,malformed=false,sessionKnown=false;Json discoveryJson;
    if(!root.empty())roots.push_back(root);else{roots=b::CommonNamespaceRoots(&discovery,&sessionError,options,&sessionKnown);discoveryJson=kernel::source(discovery,partial,malformed);partial=partial||!sessionKnown;}
    std::size_t opened=0,readable=0,matched=0,enumerated=0,scannedRoots=0;bool api=false,sourceLimited=discovery.limited,unsupportedOnly=true;
    for(const auto& directory:roots){if(cancel.token->load(std::memory_order_relaxed)){partial=true;break;}if(::GetTickCount64()>=options.deadlineTick){partial=true;break;}
        b::DirectoryQueryEvidence evidence;const auto entries=b::EnumerateDirectoryFlat(b::Runtime(),directory,warnings,&evidence,options);
        api=api||evidence.apiAvailable;sourceLimited=sourceLimited||evidence.limited;if(evidence.opened)++opened;++scannedRoots;enumerated+=entries.size();sources.push_back(kernel::source(evidence,partial,malformed));
        if(evidence.complete||!entries.empty())++readable;const auto error=evidence.opened?evidence.lastQueryStatus:evidence.openStatus;
        unsupportedOnly=unsupportedOnly&&(!evidence.apiAvailable||error==static_cast<LONG>(0xc0000002UL)||error==static_cast<LONG>(0xc00000bbUL)||error==static_cast<LONG>(0xc000007aUL));
        for(const auto& e:entries){kernel::observeEntry(e,partial,malformed);if(!b::MatchesDirectoryFilter(e,filter))continue;++matched;if(rows.size()<limit)rows.push_back(kernel::entry(e,directory,0,partial,malformed));}
    }
    const bool cancelled=cancel.token->load(std::memory_order_relaxed),limited=scannedRoots<roots.size()||sourceLimited;
    const int code=malformed?4:!api&&!sources.empty()?5:!readable&&!limited&&!cancelled?(unsupportedOnly?5:3):partial||limited||cancelled||matched>rows.size()?6:0;
    return {code,Json::object({{L"source",Json::string(L"shared NtOpenDirectoryObject/NtQueryDirectoryObject namespace overview, R3 only")},
        {L"requestedRoot",root.empty()?Json{}:Json::string(root)},{L"filter",Json::string(filter)},{L"roots",Json::strings(roots)},
        {L"sessionDiscovery",discoveryJson},{L"currentSessionKnown",root.empty()?Json::boolean(sessionKnown):Json{}},{L"currentSessionWin32Error",root.empty()?Json::number(sessionError):Json{}},{L"sources",Json::array(sources)},
        {L"requestedRootCount",Json::count(roots.size())},{L"scannedRootCount",Json::count(scannedRoots)},{L"openedRootCount",Json::count(opened)},
        {L"enumeratedCount",Json::count(enumerated)},{L"matchedCount",Json::count(matched)},{L"returnedCount",Json::count(rows.size())},{L"truncated",Json::boolean(matched>rows.size())},
        {L"limited",Json::boolean(limited)},{L"cancelled",Json::boolean(cancelled)},{L"malformed",Json::boolean(malformed)},{L"entries",Json::array(rows)}}),
        {L"Native object-manager names and point-in-time directory/link metadata, not kernel object addresses or a complete hidden-object inventory. Only directories and symbolic links are opened for metadata; other types have null probe fields. Counts include this query's transient handle/reference. Optional/common roots may be absent or denied and preserve NTSTATUS as partial evidence; a selected root failure is failed. No R0 fallback, object mutation or UI navigation."}};
}
}
void registerKernelNamespace(){
    addFamily(L"kernel",L"R3 native object-manager and kernel evidence queries.");
    addCommand({L"kernel namespace enum",L"KswordCLI.exe kernel namespace enum [--root PATH] [--filter TEXT] [--max-entries N] [--duration-ms N] [--limit N] [--backend r3] [--json]",L"Enumerate native namespace roots or direct children of a selected root.",
        L"Optional: --root native object path (leading backslash, <=32766 UTF-16 units); --filter substring across path/name/type/target (case insensitive); --max-entries 1..100000 per directory (100000); --duration-ms 100..30000 entire sweep (8000); --limit 1..100000 displayed entries (1000); --backend r3; --json.",
        L"Output: common/selected roots and session discovery, sources with API/open/query/close evidence and complete/limited/cancelled/cycle/malformed, counts, entries with parent/name/type/path, directory/link metadata open/basic/target statuses and availability, counts/access/attributes/pool bytes and closure. Handles/addresses are not inferred; uint64 counts decimal strings, flags/status hex, unknown null. Non-directory/link types deliberately not opened. Complete valid empty enumeration 0, filtered empty 0 only with complete sources; optional-root/metadata failure, truncation, limits/cancel 6; selected/all root failure 3, missing directory APIs 5, malformed buffers 4. Query buffers <=4 MiB, symlink strings <=65534 bytes, bound/check counted strings and basic reply length, detect repeating entries. Budget between native calls; dynamic namespace may change. Counts include transient query references. Read-only; no recursive traversal, arbitrary NtOpen type, R0 or UI navigation. Help performs no queries.",enumerate});
}
}
