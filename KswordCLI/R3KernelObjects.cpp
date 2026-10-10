#include "R3KernelShared.h"
#include "../shared/usermode/backend/kernel/DeviceDriverObjects.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::kernel;
Result enumerate(const Args& a){const auto scope=a.get(L"--scope",L"all"),kind=a.get(L"--kind",L"all"),filter=a.get(L"--filter");
    if(scope!=L"all"&&scope!=L"device"&&scope!=L"driver"&&scope!=L"filesystem"&&scope!=L"filters")throw std::invalid_argument("--scope must be all, device, driver, filesystem or filters");
    if(kind!=L"all"&&kind!=L"device"&&kind!=L"driver")throw std::invalid_argument("--kind must be all, device or driver");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");Cancellation cancel;const auto options=kernel::options(a,cancel);
    auto roots=b::DeviceDriverObjectRoots();if(scope!=L"all")roots={scope==L"device"?L"\\Device":scope==L"driver"?L"\\Driver":scope==L"filesystem"?L"\\FileSystem":L"\\FileSystem\\Filters"};
    std::vector<Json> rows,sources;std::vector<std::wstring> warnings;std::size_t scannedRoots=0,readable=0,enumerated=0,matched=0;bool partial=false,malformed=false,api=false,limited=false;
    for(const auto& root:roots){if(cancel.token->load(std::memory_order_relaxed)||::GetTickCount64()>=options.deadlineTick){limited=true;break;}
        b::DirectoryQueryEvidence evidence;const auto entries=b::EnumerateDirectoryFlat(b::Runtime(),root,warnings,&evidence,options);++scannedRoots;api=api||evidence.apiAvailable;
        if(evidence.complete||!entries.empty())++readable;limited=limited||evidence.limited;enumerated+=entries.size();sources.push_back(kernel::source(evidence,partial,malformed));
        for(const auto& e:entries){kernel::observeEntry(e,partial,malformed);if(kind!=L"all"&&_wcsicmp(e.typeName.c_str(),kind==L"driver"?L"Driver":L"Device"))continue;if(!b::MatchesDirectoryFilter(e,filter))continue;++matched;
            if(rows.size()<limit)rows.push_back(kernel::entry(e,root,0,partial,malformed));}}
    const bool cancelled=cancel.token->load(std::memory_order_relaxed);limited=limited||scannedRoots<roots.size();
    return {malformed?4:!api&&!sources.empty()?5:!readable&&!limited&&!cancelled?3:partial||limited||cancelled||matched>rows.size()?6:0,
        Json::object({{L"source",Json::string(L"shared Device/Driver/FileSystem native object-namespace directories")},{L"scope",Json::string(scope)},
            {L"kindFilter",Json::string(kind)},{L"filter",Json::string(filter)},{L"roots",Json::strings(roots)},{L"sources",Json::array(sources)},
            {L"scannedRootCount",Json::count(scannedRoots)},{L"enumeratedCount",Json::count(enumerated)},{L"matchedCount",Json::count(matched)},{L"returnedCount",Json::count(rows.size())},
            {L"truncated",Json::boolean(matched>rows.size())},{L"limited",Json::boolean(limited)},{L"cancelled",Json::boolean(cancelled)},{L"malformed",Json::boolean(malformed)},{L"objects",Json::array(rows)}}),
        {L"Namespace registration names/types, not DRIVER_OBJECT/DEVICE_OBJECT addresses, dispatch tables, loaded-module image metadata or device capabilities. Device/Driver objects are not opened by this backend; probe fields stay null. Directory/link supplemental evidence remains available where supported. No device IOCTL, object mutation, driver load/unload or R0 fallback."}};
}
}
void registerKernelObjects(){addCommand({L"kernel objects enum",L"KswordCLI.exe kernel objects enum [--scope SCOPE] [--kind KIND] [--filter TEXT] [--max-entries N] [--duration-ms N] [--limit N] [--backend r3] [--json]",
    L"Enumerate R3 Device/Driver/FileSystem object registration names.",
    L"Optional: --scope all|device|driver|filesystem|filters (all); --kind all|device|driver (all); --filter case-insensitive path/name/type/target substring; --max-entries 1..100000 per directory (100000); --duration-ms 100..30000 entire sweep (8000); --limit 1..100000 displayed rows (1000); --backend r3; --json.",
    L"Output: selected roots, native source open/query/close completeness, enumeration/matching/display counts, limits/cancel/malformed and namespace object entries. Directories/links have optional typed basic/target evidence; Device/Driver types have null opener/count fields because no safe dedicated NtOpen API is implemented. This enumerates registrations, not kernel pointers, dispatch routines, loaded driver images or device IOCTL support. Existing R0 driver object/detail and R3 driver module commands keep their meaning. Complete empty/filter-empty 0, missing/denied root or metadata/close/truncation/limits partial 6, all/selected root failure 3, unavailable directory APIs 5, malformed 4. Read-only, no load/unload/control/R0 fallback; help performs no calls.",enumerate});}
}
