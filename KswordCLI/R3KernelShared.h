#pragma once
#include "CommandRegistry.h"
#include "../shared/usermode/backend/kernel/ObjectNamespace.h"
#include <stdexcept>
namespace ks::cli::kernel {
namespace b=ks::r3::kernel;
inline std::wstring path(const Args& a,const wchar_t* option=L"--root",const std::wstring& fallback={}){
    const auto value=a.has(option)?a.require(option):fallback;if(value.empty()||value.front()!=L'\\'||value.size()>32766)throw std::invalid_argument("native object path must start with backslash and contain 1..32766 UTF-16 units");return value;
}
inline Json status(LONG value){return Json::hex(static_cast<ULONG>(value));}
inline Json source(const b::DirectoryQueryEvidence& e,bool& partial,bool& malformed){partial=partial||!e.complete||e.limited||e.cancelled||e.cycle||(e.closeAttempted&&!e.closed);malformed=malformed||e.malformed;
    return Json::object({{L"path",Json::string(e.path)},{L"depth",Json::number(e.depth)},{L"apiAvailable",Json::boolean(e.apiAvailable)},{L"openAttempted",Json::boolean(e.openAttempted)},
        {L"opened",Json::boolean(e.opened)},{L"openNtStatus",e.openAttempted?status(e.openStatus):Json{}},{L"queryAttempted",Json::boolean(e.queryAttempted)},
        {L"lastQueryNtStatus",e.queryAttempted?status(e.lastQueryStatus):Json{}},{L"lastReturnedBytes",e.queryAttempted?Json::count(e.returned):Json{}},
        {L"enumeratedCount",Json::count(e.queried)},{L"complete",Json::boolean(e.complete)},{L"limited",Json::boolean(e.limited)},{L"cancelled",Json::boolean(e.cancelled)},
        {L"cycle",Json::boolean(e.cycle)},{L"malformed",Json::boolean(e.malformed)},{L"closeAttempted",Json::boolean(e.closeAttempted)},
        {L"closed",e.closeAttempted?Json::boolean(e.closed):Json{}},{L"closeWin32Error",e.closeAttempted?Json::number(e.closeError):Json{}}});
}
inline void observeEntry(const b::DirectoryEntry& e,bool& partial,bool& malformed){
    const bool probeSupported=e.typeName==L"Directory"||e.typeName==L"SymbolicLink";
    partial=partial||(e.metadataRequested&&probeSupported&&(!e.canOpen||!e.basic.available))||(e.metadataRequested&&e.typeName==L"SymbolicLink"&&!e.target.available)||(e.closeAttempted&&!e.closed);
    malformed=malformed||e.basic.malformed||e.target.malformed;
}
inline Json entry(const b::DirectoryEntry& e,const std::wstring& root,std::uint32_t depth,bool& partial,bool& malformed){
    const bool probeSupported=e.typeName==L"Directory"||e.typeName==L"SymbolicLink";observeEntry(e,partial,malformed);
    const auto& v=e.basic.value;
    return Json::object({{L"root",Json::string(root)},{L"depth",Json::number(depth)},{L"parentPath",Json::string(e.parentPath)},
        {L"name",Json::string(e.name)},{L"type",Json::string(e.typeName)},{L"fullPath",Json::string(e.fullPath)},{L"metadataProbeSupported",Json::boolean(probeSupported)},
        {L"metadataProbeRequested",Json::boolean(e.metadataRequested)},
        {L"openAttempted",Json::boolean(e.openAttempted)},{L"opened",probeSupported?Json::boolean(e.canOpen):Json{}},{L"openNtStatus",e.openAttempted?status(e.openStatus):Json{}},
        {L"basic",Json::object({{L"attempted",Json::boolean(e.basic.attempted)},{L"available",Json::boolean(e.basic.available)},
            {L"ntStatus",e.basic.attempted?status(e.basic.status):Json{}},{L"returnedBytes",e.basic.attempted?Json::count(e.basic.returned):Json{}},{L"malformed",Json::boolean(e.basic.malformed)},
            {L"handleCount",e.basic.available?Json::count(v.HandleCount):Json{}},{L"pointerCount",e.basic.available?Json::count(v.PointerCount):Json{}},
            {L"attributes",e.basic.available?Json::hex(v.Attributes):Json{}},{L"grantedAccess",e.basic.available?Json::hex(v.GrantedAccess):Json{}},
            {L"pagedPoolBytes",e.basic.available?Json::count(v.PagedPoolUsage):Json{}},{L"nonPagedPoolBytes",e.basic.available?Json::count(v.NonPagedPoolUsage):Json{}}})},
        {L"symlinkTarget",Json::object({{L"attempted",Json::boolean(e.target.attempted)},{L"available",Json::boolean(e.target.available)},
            {L"ntStatus",e.target.attempted?status(e.target.status):Json{}},{L"requiredBytes",e.target.attempted?Json::count(e.target.required):Json{}},
            {L"malformed",Json::boolean(e.target.malformed)},{L"limited",Json::boolean(e.target.limited)},{L"value",e.target.available?Json::string(e.targetPath):Json{}}})},
        {L"closeAttempted",Json::boolean(e.closeAttempted)},{L"closed",e.closeAttempted?Json::boolean(e.closed):Json{}},{L"closeWin32Error",e.closeAttempted?Json::number(e.closeError):Json{}},
        {L"statusDisplay",Json::string(e.statusText)}});
}
inline b::DirectoryQueryOptions options(const Args& a,const Cancellation& cancel){b::DirectoryQueryOptions options;
    options.maxEntries=a.u32(L"--max-entries",100000);options.maxDurationMs=a.u32(L"--duration-ms",8000);
    if(!options.maxEntries||options.maxEntries>100000)throw std::invalid_argument("--max-entries must be 1..100000");if(options.maxDurationMs<100||options.maxDurationMs>30000)throw std::invalid_argument("--duration-ms must be 100..30000");
    options.deadlineTick=::GetTickCount64()+options.maxDurationMs;options.cancelled=[token=cancel.token]{return token->load(std::memory_order_relaxed);};return options;
}
}
