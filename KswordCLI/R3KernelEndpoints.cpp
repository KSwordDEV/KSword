#include "R3KernelShared.h"
#include "../shared/usermode/backend/kernel/CommunicationEndpoints.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::kernel;
Result enumerate(const Args& a){b::RecursiveDirectoryOptions options;options.root=a.has(L"--root")?kernel::path(a,L"--root"):std::wstring{};options.filter=a.get(L"--filter");
    options.maxDepth=a.u32(L"--max-depth",3);if(options.maxDepth>32)throw std::invalid_argument("--max-depth must be 0..32");
    options.maxRows=a.u32(L"--max-rows",2500);if(!options.maxRows||options.maxRows>2500)throw std::invalid_argument("--max-rows must be 1..2500");
    options.maxScannedRows=a.u32(L"--max-scanned-entries",10000);if(!options.maxScannedRows||options.maxScannedRows>10000)throw std::invalid_argument("--max-scanned-entries must be 1..10000");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>2500)throw std::invalid_argument("--limit must be 1..2500");Cancellation cancel;options.directory=kernel::options(a,cancel);
    b::DirectoryQueryEvidence discovery;DWORD sessionError=0;bool sessionKnown=false;
    const auto roots=options.root.empty()?b::CommonNamespaceRoots(&discovery,&sessionError,options.directory,&sessionKnown):std::vector<std::wstring>{options.root};
    b::RecursiveDirectorySnapshot snapshot;snapshot.complete=true;std::size_t scannedRoots=0;
    for(const auto& root:roots){if(snapshot.rows.size()>=options.maxRows||snapshot.scannedRows>=options.maxScannedRows){snapshot.limited=true;break;}
        auto request=options;request.root=root;request.maxRows-=static_cast<DWORD>(snapshot.rows.size());request.maxScannedRows-=snapshot.scannedRows;
        auto part=b::CollectCommunicationEndpoints(request);++scannedRoots;snapshot.complete=snapshot.complete&&part.complete;snapshot.limited=snapshot.limited||part.limited;snapshot.cancelled=snapshot.cancelled||part.cancelled;snapshot.malformed=snapshot.malformed||part.malformed;snapshot.metadataPartial=snapshot.metadataPartial||part.metadataPartial;
        snapshot.scannedRows+=part.scannedRows;snapshot.matchedObserved+=part.matchedObserved;snapshot.depthBoundaryCount+=part.depthBoundaryCount;snapshot.deduplicatedPaths+=part.deduplicatedPaths;
        snapshot.rows.insert(snapshot.rows.end(),part.rows.begin(),part.rows.end());snapshot.sources.insert(snapshot.sources.end(),part.sources.begin(),part.sources.end());
        if(part.limited||part.cancelled||part.malformed)break;
    }
    snapshot.complete=snapshot.complete&&scannedRoots==roots.size();bool partial=!snapshot.complete||snapshot.metadataPartial,malformed=snapshot.malformed;Json discoveryJson;if(options.root.empty()){discoveryJson=kernel::source(discovery,partial,malformed);partial=partial||!sessionKnown;}std::vector<Json> rows,sources;std::size_t readable=0;
    bool api=false,unsupportedOnly=true;for(const auto& e:snapshot.sources){sources.push_back(kernel::source(e,partial,malformed));api=api||e.apiAvailable;if(e.complete||e.queried)++readable;
        const auto error=e.opened?e.lastQueryStatus:e.openStatus;unsupportedOnly=unsupportedOnly&&(!e.apiAvailable||error==static_cast<LONG>(0xc0000002UL)||error==static_cast<LONG>(0xc00000bbUL)||error==static_cast<LONG>(0xc000007aUL));}
    for(const auto& r:snapshot.rows){kernel::observeEntry(r.entry,partial,malformed);if(rows.size()<limit)rows.push_back(kernel::entry(r.entry,options.root,r.depth,partial,malformed));}
    const bool truncated=snapshot.rows.size()>rows.size();const int code=malformed?4:!api&&!snapshot.sources.empty()?5:!readable&&!snapshot.limited&&!snapshot.cancelled?(unsupportedOnly?5:3):partial||truncated?6:0;
    return {code,Json::object({{L"source",Json::string(L"shared named communication types, native object-directory traversal; no symbolic-link traversal")},
        {L"root",options.root.empty()?Json{}:Json::string(options.root)},{L"roots",Json::strings(roots)},{L"sessionDiscovery",discoveryJson},{L"currentSessionKnown",options.root.empty()?Json::boolean(sessionKnown):Json{}},{L"filter",Json::string(options.filter)},{L"maxDepth",Json::number(options.maxDepth)},{L"completeWithinDepth",Json::boolean(snapshot.complete)},
        {L"metadataComplete",Json::boolean(!snapshot.metadataPartial)},
        {L"limited",Json::boolean(snapshot.limited)},{L"cancelled",Json::boolean(snapshot.cancelled)},{L"malformed",Json::boolean(malformed)},
        {L"scannedDirectoryCount",Json::count(snapshot.sources.size())},{L"scannedEntryCount",Json::count(snapshot.scannedRows)},
        {L"matchedObservedCount",Json::count(snapshot.matchedObserved)},{L"storedCount",Json::count(snapshot.rows.size())},{L"returnedCount",Json::count(rows.size())},
        {L"depthBoundaryDirectoryCount",Json::count(snapshot.depthBoundaryCount)},{L"deduplicatedPathCount",Json::count(snapshot.deduplicatedPaths)},
        {L"truncated",Json::boolean(truncated)},{L"sources",Json::array(sources)},{L"entries",Json::array(rows)}}),
        {L"Depth 0 lists direct children; each next directory source increments depth. The depth boundary defines requested scope, not a claim that deeper objects do not exist. Filters select rows and do not prune directory traversal. matchedObservedCount is a prefix count if any budget interrupted collection. Only shared IsCommunicationType entries are returned (ALPC/Port, WaitCompletionPacket, TpWorkerFactory, Event, Section, Mutant, Semaphore, IoCompletion, Timer, Job, Keyed Event); no owner/client/server or payload inference. Only Directory entries are queued; symbolic links are not followed. Native metadata/closure limitations remain explicit; no mutation or R0 fallback."}};
}
}
void registerKernelEndpoints(){
    addCommand({L"kernel endpoints enum",L"KswordCLI.exe kernel endpoints enum [--root PATH] [--max-depth N] [--filter TEXT] [--max-rows N] [--max-scanned-entries N] [--max-entries N] [--duration-ms N] [--limit N] [--backend r3] [--json]",L"Enumerate named IPC/synchronization objects within explicit native directory scope.",
        L"Optional: --root native absolute path (default shared common/session roots); --max-depth 0..32 (3; direct entries at depth 0); --filter case-insensitive path/name/type/target substring; --max-rows 1..2500 (2500 stored matches); --max-scanned-entries 1..10000 (10000 traversal entries); --max-entries 1..100000 per directory (100000); --duration-ms 100..30000 entire sweep (8000); --limit 1..2500 displayed rows (1000); --backend r3; --json.",
        L"Output: root/depth/filter, completeWithinDepth/metadataComplete, budget/cancel/malformed, scanned directories/entries, matchedObserved/stored/returned counts, depth-boundary/deduplicated-path counts, source open/query/close evidence and typed namespace entries. BFS, only Directory entries recurse; symlinks not followed. Filters do not prune traversal. Depth boundary is requested view scope; actual row/scan/time limits produce 6. Counts after interruption are observed prefixes. Native API absence 5; selected/all directory failure without rows 3; malformed 4; complete valid empty view 0; metadata/close/partial/output truncation 6. Same bounded native strings/basic replies and handle ownership as namespace enum. No arbitrary opener, kernel addresses, object changes, R0 or UI navigation. Help performs no native calls.",enumerate});
}
}
