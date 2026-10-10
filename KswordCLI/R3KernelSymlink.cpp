#include "R3KernelShared.h"
#include "../shared/usermode/backend/kernel/SymbolicLinks.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::kernel;
bool unsupported(LONG status){return status==static_cast<LONG>(0xc00000bbUL)||status==static_cast<LONG>(0xc0000002UL)||status==static_cast<LONG>(0xc000007aUL);}
Result query(const Args& a){const auto path=kernel::path(a,L"--path");const auto e=b::QueryOneSymbolicLink(path);bool partial=false,malformed=false;
    const auto data=kernel::entry(e,path,0,partial,malformed);const bool badHandle=e.openAttempted&&e.openStatus==b::kStatusSuccess&&!e.canOpen;
    const int code=malformed||badHandle?4:!e.openAttempted?5:!e.canOpen?(unsupported(e.openStatus)?5:3):!e.target.available?(!e.target.attempted||unsupported(e.target.status)?5:e.target.attempted&&e.target.status!=b::kStatusSuccess&&!e.target.limited?3:6):partial?6:0;
    return {code,Json::object({{L"source",Json::string(L"shared NtOpenSymbolicLinkObject/NtQuerySymbolicLinkObject + optional basic metadata")},
        {L"requestedPath",Json::string(path)},{L"nameDerivedFromRequest",Json::boolean(true)},{L"link",data}}),
        {L"Original counted target string, not a claim that the target exists or can be opened. No target traversal, link create/delete/set or R0 fallback. Basic counts include the transient query handle; fields reflect native status and unknown values stay null."}};
}
Result enumerate(const Args& a){const auto root=a.has(L"--root")?kernel::path(a):std::wstring{},filter=a.get(L"--filter"),targetFilter=a.get(L"--target-filter");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");Cancellation cancel;auto options=kernel::options(a,cancel);options.probeDirectories=false;
    std::vector<std::wstring> roots,warnings;std::vector<Json> rows,sources;b::DirectoryQueryEvidence discovery;DWORD sessionError=0;bool sessionKnown=false,partial=false,malformed=false;Json discoveryJson;
    if(!root.empty())roots.push_back(root);else{roots=b::CommonNamespaceRoots(&discovery,&sessionError,options,&sessionKnown);discoveryJson=kernel::source(discovery,partial,malformed);partial=partial||!sessionKnown;}
    std::size_t scannedRoots=0,readable=0,links=0,matched=0,unknownTargetMatches=0;bool api=false,limited=discovery.limited;
    for(const auto& directory:roots){if(cancel.token->load(std::memory_order_relaxed)||::GetTickCount64()>=options.deadlineTick){partial=true;break;}
        b::DirectoryQueryEvidence evidence;const auto entries=b::EnumerateDirectoryFlat(b::Runtime(),directory,warnings,&evidence,options);++scannedRoots;
        api=api||evidence.apiAvailable;if(evidence.complete||!entries.empty())++readable;limited=limited||evidence.limited;sources.push_back(kernel::source(evidence,partial,malformed));
        for(const auto& e:entries){if(e.typeName!=L"SymbolicLink")continue;++links;kernel::observeEntry(e,partial,malformed);
            if(!e.target.available&&(!filter.empty()||!targetFilter.empty())){++unknownTargetMatches;partial=true;}
            if(!b::MatchesDirectoryFilter(e,filter)||(!targetFilter.empty()&&(!e.target.available||!b::ContainsI(e.targetPath,targetFilter))))continue;
            ++matched;if(rows.size()<limit)rows.push_back(kernel::entry(e,directory,0,partial,malformed));}
    }
    limited=limited||scannedRoots<roots.size();const bool cancelled=cancel.token->load(std::memory_order_relaxed);
    const int code=malformed?4:!api&&!sources.empty()?5:!readable&&!limited&&!cancelled?3:partial||limited||cancelled||matched>rows.size()?6:0;
    return {code,Json::object({{L"source",Json::string(L"shared native directory symbolic-link enumeration and counted target queries")},
        {L"requestedRoot",root.empty()?Json{}:Json::string(root)},{L"filter",Json::string(filter)},{L"targetFilter",Json::string(targetFilter)},
        {L"sessionDiscovery",discoveryJson},{L"currentSessionKnown",root.empty()?Json::boolean(sessionKnown):Json{}},{L"currentSessionWin32Error",root.empty()?Json::number(sessionError):Json{}},
        {L"requestedRootCount",Json::count(roots.size())},{L"scannedRootCount",Json::count(scannedRoots)},{L"symbolicLinkCount",Json::count(links)},
        {L"matchedCount",Json::count(matched)},{L"unknownTargetFilterCount",Json::count(unknownTargetMatches)},{L"returnedCount",Json::count(rows.size())},
        {L"truncated",Json::boolean(matched>rows.size())},{L"limited",Json::boolean(limited)},{L"cancelled",Json::boolean(cancelled)},
        {L"malformed",Json::boolean(malformed)},{L"sources",Json::array(sources)},{L"links",Json::array(rows)}}),
        {L"Targets are counted native strings and may name nonexistent or inaccessible objects. Filters cannot prove exclusion when targets are unavailable, so unknown target filtering stays partial. Directories are enumerated but not opened for extra metadata in this link-specific view. No symlink traversal, mutation or R0 fallback."}};
}
}
void registerKernelSymlink(){
    addCommand({L"kernel symlink query",L"KswordCLI.exe kernel symlink query --path PATH [--backend r3] [--json]",L"Read one native symbolic-link target and its available basic metadata.",
        L"Required: --path native absolute object path, <=32766 UTF-16 units. Optional: --backend r3, --json.",
        L"Output: requestedPath, nameDerivedFromRequest and typed link/open/basic/target/close evidence from namespace schema. Empty successfully queried target is an empty string; missing target evidence null. Target capacity <=65534 bytes; validate counted pointer/length and preserve raw NTSTATUS. Open/query failure 3, absent open API 5, malformed 4, basic/target budget or close limitation 6, complete query 0. Query closes its handle before output; no create/delete/set, target open/traversal, DOS-path proof or R0. Help performs no calls.",query});
    addCommand({L"kernel symlink enum",L"KswordCLI.exe kernel symlink enum [--root PATH] [--filter TEXT] [--target-filter TEXT] [--max-entries N] [--duration-ms N] [--limit N] [--backend r3] [--json]",L"Enumerate symbolic links under native common roots or one selected directory.",
        L"Optional: --root native absolute directory path; --filter case-insensitive name/path/type/target substring; --target-filter case-insensitive target substring; --max-entries 1..100000 per directory (100000); --duration-ms 100..30000 entire sweep (8000); --limit 1..100000 displayed links (1000); --backend r3; --json.",
        L"Output: root/session discovery, source native open/query/close completeness, symbolicLink/matched/returned counts, unknownTargetFilterCount, truncation/limits/cancel/malformed and typed links. Unknown targets cannot prove filter exclusion and produce partial. Complete valid empty link result 0, partial roots/metadata/filters/closure/truncation 6, failed roots/no readable results 3, directory API absent 5, malformed 4. Reads direct entries only, does not follow link targets or mutate/R0. Directory metadata probes omitted; only link metadata requested. Help performs no calls.",enumerate});
}
}
