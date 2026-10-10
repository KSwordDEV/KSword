#include "R3KernelShared.h"
#include "../shared/usermode/backend/kernel/NamedPipes.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::kernel;
bool unsupported(LONG value){return value==static_cast<LONG>(0xc00000bbUL)||value==static_cast<LONG>(0xc0000002UL)||value==static_cast<LONG>(0xc000007aUL);}
Result enumerate(const Args& a){const auto directory=a.get(L"--directory",L"all"),filter=a.get(L"--filter");if(directory!=L"all"&&directory!=L"device"&&directory!=L"dos")throw std::invalid_argument("--directory must be all, device or dos");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");Cancellation cancel;const auto options=kernel::options(a,cancel);
    std::vector<std::wstring> paths;if(directory!=L"dos")paths.push_back(L"\\Device\\NamedPipe");if(directory!=L"device")paths.push_back(L"\\??\\PIPE");
    bool partial=false,malformed=false,limited=false,api=false,unsupportedOnly=true;std::size_t readable=0,scanned=0,matched=0;std::vector<Json> rows,sources,ioResults;
    for(const auto& path:paths){const auto snapshot=b::CollectNamedPipes(path,options);const auto& e=snapshot.evidence;api=api||e.apiAvailable;unsupportedOnly=unsupportedOnly&&(!e.apiAvailable||unsupported(e.opened?e.lastQueryStatus:e.openStatus));limited=limited||e.limited;if(e.complete||!snapshot.entries.empty())++readable;scanned+=snapshot.entries.size();sources.push_back(kernel::source(e,partial,malformed));
        ioResults.push_back(Json::object({{L"path",Json::string(path)},{L"ntStatus",e.openAttempted?kernel::status(snapshot.ioStatus):Json{}},{L"information",e.openAttempted?Json::count(snapshot.information):Json{}}}));
        for(const auto& entry:snapshot.entries){const auto fullPath=b::JoinObjectPath(path,entry.name);if(!b::ContainsI(entry.name,filter)&&!b::ContainsI(fullPath,filter))continue;++matched;if(rows.size()>=limit)continue;const auto& v=entry.info;
            rows.push_back(Json::object({{L"name",Json::string(entry.name)},{L"directory",Json::string(path)},{L"ntPath",Json::string(fullPath)},{L"win32Path",Json::string(L"\\\\.\\pipe\\"+entry.name)},
                {L"attributes",Json::hex(v.FileAttributes)},{L"sizeBytes",Json::string(std::to_wstring(v.EndOfFile.QuadPart))},{L"allocationBytes",Json::string(std::to_wstring(v.AllocationSize.QuadPart))},
                {L"creationTime",Json::string(std::to_wstring(v.CreationTime.QuadPart))},{L"lastAccessTime",Json::string(std::to_wstring(v.LastAccessTime.QuadPart))},
                {L"lastWriteTime",Json::string(std::to_wstring(v.LastWriteTime.QuadPart))},{L"changeTime",Json::string(std::to_wstring(v.ChangeTime.QuadPart))}}));}
    }
    return {malformed?4:!api?5:!readable&&!limited&&!cancel.token->load()?(unsupportedOnly?5:3):partial||matched>rows.size()?6:0,
        Json::object({{L"source",Json::string(L"shared NtOpenFile/NtQueryDirectoryFile named-pipe directory metadata")},{L"directory",Json::string(directory)},{L"filter",Json::string(filter)},
            {L"sources",Json::array(sources)},{L"ioResults",Json::array(ioResults)},{L"enumeratedCount",Json::count(scanned)},{L"matchedCount",Json::count(matched)},{L"returnedCount",Json::count(rows.size())},
            {L"truncated",Json::boolean(matched>rows.size())},{L"limited",Json::boolean(limited)},{L"malformed",Json::boolean(malformed)},{L"pipes",Json::array(rows)}}),
        {L"The Device and DOS roots may alias the same pipe; rows retain the directory source and are not counted as unique connections. Enumeration does not open pipe instances or read/write messages. Names are live registrations; no owner PID, security descriptor, instance count or payload inference. Raw native time/size values are decimal strings."}};
}
Result probe(const Args& a){const auto path=kernel::path(a,L"--path");if(!((b::StartsWithI(path,L"\\Device\\NamedPipe\\")&&path.size()>18)||(b::StartsWithI(path,L"\\??\\PIPE\\")&&path.size()>9)))throw std::invalid_argument("--path must name a pipe under the native Device/NamedPipe or DOS PIPE root");if(!a.has(L"--confirm"))throw std::invalid_argument("--confirm is required for a pipe instance open probe");
    const auto snapshot=b::ProbeNamedPipe(path);bool partial=false,malformed=false;const auto source=kernel::source(snapshot.evidence,partial,malformed);const auto& basic=snapshot.basic;
    const int code=snapshot.evidence.malformed?4:!snapshot.evidence.apiAvailable||unsupported(snapshot.evidence.openStatus)?5:!snapshot.evidence.opened?3:!snapshot.evidence.complete||!snapshot.evidence.closed||!basic.available?6:0;
    return {code,Json::object({{L"target",Json::string(path)},{L"action",Json::string(L"open-read-attributes")},{L"source",source},{L"requestSucceeded",Json::boolean(snapshot.evidence.opened&&snapshot.evidence.complete)},
        {L"ioNtStatus",snapshot.evidence.openAttempted?kernel::status(snapshot.ioStatus):Json{}},{L"information",snapshot.evidence.openAttempted?Json::count(snapshot.information):Json{}},
        {L"basic",Json::object({{L"attempted",Json::boolean(basic.attempted)},{L"available",Json::boolean(basic.available)},{L"ntStatus",basic.attempted?kernel::status(basic.status):Json{}},
            {L"returnedBytes",Json::count(basic.returned)},{L"malformed",Json::boolean(basic.malformed)},{L"handleCount",basic.available?Json::count(basic.value.HandleCount):Json{}},
            {L"pointerCount",basic.available?Json::count(basic.value.PointerCount):Json{}},{L"grantedAccess",basic.available?Json::hex(basic.value.GrantedAccess):Json{}}})}}),
        {L"FILE_READ_ATTRIBUTES|SYNCHRONIZE only; no message read/write or impersonation. Opening a named-pipe instance can affect its availability/connection state; confirmation is mandatory. Counters include this temporary reference. The owned handle is closed before output; no persistent connection or owner PID inference."}};
}
}
void registerKernelPipes(){addCommand({L"kernel pipes enum",L"KswordCLI.exe kernel pipes enum [--directory all|device|dos] [--filter TEXT] [--max-entries N] [--duration-ms N] [--limit N] [--backend r3] [--json]",
    L"Enumerate R3 named-pipe directory metadata without opening pipe instances.",L"Optional: --directory all|device|dos (all); --filter case-insensitive name/native path substring; --max-entries 1..100000 per directory (100000); --duration-ms 100..30000 sweep budget (8000); --limit 1..100000 (1000); --backend r3; --json.",
    L"Output: directory/filter, source API/open/query/close/completeness and limits, enumerated/matched/returned counts, truncation, pipes with names/native/Win32 paths, attributes (hex), size/allocation and raw native time fields (decimal strings). Two roots may alias the same objects. Actual IO_STATUS_BLOCK byte counts and linked record offsets/name lengths are validated; 128 KiB batches, duplicate-page/entry/time/cancel bounds. No owner PID/message/instance inference. Complete valid empty 0; API absent 5; all native failures 3; malformed 4; partial/close/limits/truncation 6. No R0 fallback.",enumerate});
    addCommand({L"kernel pipes probe",L"KswordCLI.exe kernel pipes probe --path PATH --confirm [--backend r3] [--json]",L"Open and close a native pipe with read-attributes access and report actual evidence.",
        L"Required: --path full native Device/NamedPipe or DOS PIPE path; --confirm. Optional: --backend r3; --json.",
        L"Output: target/action, typed open/close evidence, requestSucceeded, IO NTSTATUS/Information and basic object counts/access with native query status. Read-attributes opening may affect pipe instance availability/connection state. No message read/write/impersonation. Owned handle closes before output. Strict status zero; API unavailable 5, native open failure 3, malformed 4, missing basic/IO/close evidence 6, successful open/query/close 0. No R0 fallback; help performs no native calls.",probe});}
}
