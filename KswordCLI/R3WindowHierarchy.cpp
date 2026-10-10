#include "R3WindowShared.h"
#include "../shared/usermode/backend/window/WindowEnumerator.h"
#include "../shared/usermode/backend/window/WindowHierarchy.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::window_tools;
Json value(const b::HierarchyField& f) {
    if(!f.available)return {};
    switch(f.kind){
    case b::HierarchyValueKind::Pointer:return Json::hex(f.number);
    case b::HierarchyValueKind::Boolean:return Json::boolean(f.number!=0);
    case b::HierarchyValueKind::Signed:return Json::signedNumber(static_cast<std::int32_t>(f.signedNumber));
    case b::HierarchyValueKind::Text:return Json::string(f.text);
    case b::HierarchyValueKind::Strings:return Json::strings(f.strings);
    case b::HierarchyValueKind::Point:return Json::object({{L"x",Json::signedNumber(f.point.x)},{L"y",Json::signedNumber(f.point.y)}});
    case b::HierarchyValueKind::Rectangle:return Json::object({{L"left",Json::signedNumber(f.rectangle.left)},{L"top",Json::signedNumber(f.rectangle.top)},
        {L"right",Json::signedNumber(f.rectangle.right)},{L"bottom",Json::signedNumber(f.rectangle.bottom)}});
    default:
        if(f.name==L"style"||f.name==L"exStyle"||f.name==L"classStyle"||f.name==L"callerClassStyle"||f.name==L"cloaked"||f.name==L"displayAffinity"||f.name==L"layeredFlags"||f.name==L"layeredColorKey"||f.name==L"classAtom")return Json::hex(f.number);
        return Json::count(f.number);
    }
}
Result query(const Args& a) {
    if(a.has(L"--pid"))(void)a.u32(L"--pid");if(a.has(L"--tid"))(void)a.u32(L"--tid");
    if(a.has(L"--creation-time")&&(!a.has(L"--pid")||!a.integer(L"--creation-time")))throw std::invalid_argument("positive --creation-time requires --pid");
    if(a.has(L"--thread-creation-time")&&(!a.has(L"--tid")||!a.integer(L"--thread-creation-time")))throw std::invalid_argument("positive --thread-creation-time requires --tid");
    const auto handle=window::hwnd(a);const auto before=ks::r3::window::QueryWindowDetails(handle);
    const auto matches=[&](const ks::r3::window::WindowDetail& d){return d.found&&(!a.has(L"--pid")||d.row.processId==a.u32(L"--pid"))&&
        (!a.has(L"--tid")||d.row.threadId==a.u32(L"--tid"))&&(!a.has(L"--creation-time")||d.row.processCreationTime==a.integer(L"--creation-time"))&&
        (!a.has(L"--thread-creation-time")||d.row.threadCreationTime==a.integer(L"--thread-creation-time"));};
    if(!matches(before))return {3,Json::object({{L"identityMatched",Json::boolean(false)}}),{L"Window or supplied owner identity is unavailable/mismatched."}};
    const auto snapshot=b::QueryHierarchySnapshot(handle);const auto after=ks::r3::window::QueryWindowDetails(handle);
    const bool stable=snapshot.found&&snapshot.stable&&matches(after)&&before.row.processId==snapshot.processId&&before.row.threadId==snapshot.threadId&&
        before.row.processId==after.row.processId&&before.row.threadId==after.row.threadId&&before.row.processCreationTime==after.row.processCreationTime&&before.row.threadCreationTime==after.row.threadCreationTime;
    bool partial=!snapshot.chainComplete||!snapshot.zComplete||snapshot.zIndex<0;std::vector<Json> fields,chain;DWORD unavailable=0;
    for(const auto& f:snapshot.fields){if(!f.available&&!f.notApplicable){partial=true;++unavailable;}
        fields.push_back(Json::object({{L"name",Json::string(f.name)},{L"available",Json::boolean(f.available)},{L"notApplicable",Json::boolean(f.notApplicable)},
            {L"value",value(f)},{L"errorDomain",f.domain.empty()?Json{}:Json::string(f.domain)},
            {L"error",f.errorKnown?(f.domain==L"hresult"?Json::hex(f.error):Json::number(f.error)):Json{}}}));}
    for(const auto h:snapshot.parentChain)chain.push_back(Json::hex(reinterpret_cast<std::uintptr_t>(h)));
    return {!stable?3:partial?6:0,Json::object({{L"source",Json::string(L"Win32 hierarchy/class/geometry + optional DPI and DWM APIs")},
        {L"hwnd",Json::hex(reinterpret_cast<std::uintptr_t>(handle))},{L"pid",Json::number(snapshot.processId)},{L"tid",Json::number(snapshot.threadId)},
        {L"identityMatched",Json::boolean(stable)},{L"remoteProcedureValuesOpaque",Json::boolean(snapshot.processId!=::GetCurrentProcessId())},
        {L"fieldCount",Json::number(static_cast<DWORD>(fields.size()))},{L"unavailableFieldCount",Json::number(unavailable)},
        {L"parentChain",Json::array(chain)},{L"parentChainComplete",Json::boolean(snapshot.chainComplete)},
        {L"parentChainCycle",Json::boolean(snapshot.chainCycle)},{L"parentChainLimited",Json::boolean(snapshot.chainLimited)},
        {L"parentChainWin32Error",snapshot.chainError?Json::number(snapshot.chainError):Json{}},
        {L"topLevelZIndexZeroBased",snapshot.zIndex<0?Json{}:Json::signedNumber(snapshot.zIndex)},{L"topLevelZCount",Json::number(snapshot.zCount)},
        {L"zComplete",Json::boolean(snapshot.zComplete)},{L"zCycle",Json::boolean(snapshot.zCycle)},{L"zLimited",Json::boolean(snapshot.zLimited)},
        {L"zWin32Error",snapshot.zError?Json::number(snapshot.zError):Json{}},
        {L"fields",Json::array(fields)}}),!stable?std::vector<std::wstring>{L"Target owner identity changed during collection."}:partial?
        std::vector<std::wstring>{L"Some requested fields or ancestry/Z-order evidence were unavailable or limited. Caller-local class lookup is not the target's class registration; remote procedure values can be system proxies. No subclassing conclusion is inferred."}:std::vector<std::wstring>{}};
}
}
void registerWindowHierarchy() {
    addCommand({L"window hierarchy query",L"KswordCLI.exe window hierarchy query --hwnd HWND [--pid PID] [--tid TID] [--creation-time FILETIME] [--thread-creation-time FILETIME] [--backend r3] [--json]",
        L"Query R3 window ancestry, Z-order, styles, class, geometry, DPI and DWM evidence.",
        L"Required: --hwnd. Optional: --pid, --tid, --creation-time (positive, requires --pid), --thread-creation-time (positive, requires --tid), --backend r3, --json.",
        L"Output: identity stability, named typed fields with availability/notApplicable/native error domains, parent chain (32 max), zero-based top-level Z index/count and completeness (100000/8 seconds between calls). Values are null when unavailable; handles/addresses/flags hex strings, counts decimal strings, rectangles/points signed coordinates. Includes parent/root/rootOwner/owner/neighbors, styles and decoded bits, class atom/procedure/extra bytes, caller-visible class lookup, window/client rect/client origin, DPI context/awareness/value, DWM cloak/frame bounds, affinity/layered attributes. Zero context DPI may be nonfixed/notApplicable. API absence is unavailable, never guessed DPI 96 or cloak 0. Remote procedure values may be proxies, no subclass inference; caller class lookup is not remote class ownership. Win32 rects follow caller DPI context; DWM frame bounds are physical screen pixels. Read-only, caller desktop, no UIA traversal, desktop switch or R0 fallback. Partial/cycle/limits return 6, missing/mismatched/changed target 3. Help performs no queries.",query});
}
}
