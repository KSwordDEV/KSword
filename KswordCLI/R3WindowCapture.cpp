#include "R3WindowShared.h"
#include "../shared/usermode/backend/window/WindowEnumerator.h"
#include "../shared/usermode/backend/window/CaptureProtection.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::window_tools;
struct Platform {
    OSVERSIONINFOW version{};
    LONG status=static_cast<LONG>(0xc000007a);
    bool available=false;
    Json json()const{return Json::object({{L"source",Json::string(L"RtlGetVersion")},{L"available",Json::boolean(available)},
        {L"ntStatus",Json::hex(static_cast<DWORD>(status))},{L"major",available?Json::number(version.dwMajorVersion):Json{}},
        {L"minor",available?Json::number(version.dwMinorVersion):Json{}},{L"build",available?Json::number(version.dwBuildNumber):Json{}}});}
};
Platform platform(){Platform p;p.version.dwOSVersionInfoSize=sizeof(p.version);
    using Query=LONG(NTAPI*)(OSVERSIONINFOW*);const auto fn=reinterpret_cast<Query>(::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),"RtlGetVersion"));
    if(fn){p.status=fn(&p.version);p.available=p.status==0;}return p;}
Json affinity(const b::DisplayAffinityEvidence& e) {
    const auto mode=e.affinity==WDA_NONE?L"none":e.affinity==WDA_MONITOR?L"monitor":e.affinity==WDA_EXCLUDEFROMCAPTURE?L"exclude":L"unknown";
    return Json::object({{L"attempted",Json::boolean(e.attempted)},{L"available",Json::boolean(e.available)},
        {L"value",e.available?Json::hex(e.affinity):Json{}},{L"mode",e.available?Json::string(mode):Json{}},
        {L"win32Error",e.error?Json::number(e.error):Json{}}});
}
Result query(const Args& a) {
    if(a.has(L"--pid"))(void)a.u32(L"--pid");if(a.has(L"--tid"))(void)a.u32(L"--tid");
    if(a.has(L"--creation-time")&&(!a.has(L"--pid")||!a.integer(L"--creation-time")))throw std::invalid_argument("positive --creation-time requires --pid");
    if(a.has(L"--thread-creation-time")&&(!a.has(L"--tid")||!a.integer(L"--thread-creation-time")))throw std::invalid_argument("positive --thread-creation-time requires --tid");
    const auto handle=window::hwnd(a);const auto before=ks::r3::window::QueryWindowDetails(handle);
    const auto matches=[&](const ks::r3::window::WindowDetail& d){return d.found&&(!a.has(L"--pid")||d.row.processId==a.u32(L"--pid"))&&
        (!a.has(L"--tid")||d.row.threadId==a.u32(L"--tid"))&&(!a.has(L"--creation-time")||d.row.processCreationTime==a.integer(L"--creation-time"))&&
        (!a.has(L"--thread-creation-time")||d.row.threadCreationTime==a.integer(L"--thread-creation-time"));};
    if(!matches(before))return {3,Json::object({{L"hwnd",Json::hex(reinterpret_cast<std::uintptr_t>(handle))},{L"identityMatched",Json::boolean(false)}}),{L"Window or supplied owner identity is unavailable/mismatched."}};
    const auto value=b::QueryDisplayAffinity(handle);const auto after=ks::r3::window::QueryWindowDetails(handle);
    const bool stable=matches(after)&&before.row.processId==after.row.processId&&before.row.threadId==after.row.threadId&&
        before.row.processCreationTime==after.row.processCreationTime&&before.row.threadCreationTime==after.row.threadCreationTime;
    const auto style=before.row.evidence.find(L"exStyle");const bool known=style!=before.row.evidence.end()&&style->second.available;
    return {!stable?3:value.available?0:5,Json::object({{L"source",Json::string(L"GetWindowDisplayAffinity")},
        {L"hwnd",Json::hex(reinterpret_cast<std::uintptr_t>(handle))},{L"pid",Json::number(before.row.processId)},{L"tid",Json::number(before.row.threadId)},
        {L"identityMatched",Json::boolean(stable)},{L"layered",known?Json::boolean((before.row.exStyle&WS_EX_LAYERED)!=0):Json{}},
        {L"callerPid",Json::number(::GetCurrentProcessId())},{L"callerOwnsWindow",Json::boolean(before.row.processId==::GetCurrentProcessId())},
        {L"affinity",affinity(value)}}),!stable?std::vector<std::wstring>{L"Window owner identity changed during query."}:value.available?std::vector<std::wstring>{}:
        std::vector<std::wstring>{L"Display affinity is unavailable; the API requires suitable layered-window/DWM context. Unknown values are not WDA_NONE."}};
}
Result set(const Args& a) {
    const auto mode=a.require(L"--mode");DWORD requested;
    if(mode==L"none")requested=WDA_NONE;else if(mode==L"monitor")requested=WDA_MONITOR;else if(mode==L"exclude")requested=WDA_EXCLUDEFROMCAPTURE;else throw std::invalid_argument("--mode must be none, monitor or exclude");
    window::Lease lease(a);
    if(!lease.matches||!lease.ownerMatches())return {3,Json::object({{L"target",lease.json()},{L"attempted",Json::boolean(false)}}),{L"Window/process/thread identity does not match or has exited."}};
    const bool owned=lease.process.pid==::GetCurrentProcessId(),top=::GetAncestor(lease.handle,GA_ROOT)==lease.handle;
    if(!owned||!top)return {5,Json::object({{L"target",lease.json()},{L"requestedMode",Json::string(mode)},
        {L"callerPid",Json::number(::GetCurrentProcessId())},{L"callerOwnsWindow",Json::boolean(owned)},
        {L"topLevel",Json::boolean(top)},{L"attempted",Json::boolean(false)}}),
        {L"SetWindowDisplayAffinity requires a top-level HWND owned by the calling process. Standalone CLI does not own other applications' windows; R3 cannot set them and does not inject or fall back to R0."}};
    const auto os=platform();
    if(requested==WDA_EXCLUDEFROMCAPTURE&&(!os.available||!(os.version.dwMajorVersion>10||(os.version.dwMajorVersion==10&&os.version.dwBuildNumber>=19041))))
        return {5,Json::object({{L"target",lease.json()},{L"requestedMode",Json::string(mode)},{L"platform",os.json()},
            {L"attempted",Json::boolean(false)}}),{L"WDA_EXCLUDEFROMCAPTURE semantics require Windows 10 2004 (build 19041). An older or unknown platform is not treated as confirmed exclusion, even if it accepts the attribute."}};
    const auto before=b::QueryDisplayAffinity(lease.handle);b::DisplayAffinityWriteEvidence result;
    if(!lease.ownerMatches())return {3,Json::object({{L"target",lease.json()},{L"attempted",Json::boolean(false)}}),{L"Target changed before submission."}};
    const auto display=b::ApplyDisplayAffinity(lease.handle,requested,&result);const bool stable=lease.ownerMatches();
    const bool verified=result.accepted&&result.after.available&&result.after.affinity==requested&&stable;
    const int code=!result.accepted?(result.error==ERROR_NOT_SUPPORTED||result.error==ERROR_CALL_NOT_IMPLEMENTED?5:3):verified?0:6;
    return {code,Json::object({{L"target",lease.json()},{L"platform",os.json()},{L"requestedMode",Json::string(mode)},{L"requestedValue",Json::hex(requested)},
        {L"callerOwnsWindow",Json::boolean(owned)},{L"topLevel",Json::boolean(top)},{L"attempted",Json::boolean(result.attempted)},
        {L"accepted",Json::boolean(result.accepted)},{L"win32Error",result.error?Json::number(result.error):Json{}},
        {L"before",affinity(before)},{L"after",affinity(result.after)},{L"ownerStillMatches",Json::boolean(stable)},
        {L"verified",Json::boolean(verified)},{L"display",Json::string(display)}}),code?std::vector<std::wstring>{L"Native request failed, was downgraded, lacked readback or lost owner identity. WDA_EXCLUDEFROMCAPTURE needs Windows 10 2004; policy attribute is not a pixel-capture validation."}:std::vector<std::wstring>{}};
}
}
void registerWindowCapture() {
    addCommand({L"window capture query",L"KswordCLI.exe window capture query --hwnd HWND [--pid PID] [--tid TID] [--creation-time FILETIME] [--thread-creation-time FILETIME] [--backend r3] [--json]",
        L"Query R3 window display-affinity policy across process boundaries.",
        L"Required: --hwnd. Optional: --pid, --tid, --creation-time (positive, requires --pid), --thread-creation-time (positive, requires --tid), --backend r3, --json.",
        L"Output: window owner/caller identities, stable match, layered flag and actual GetWindowDisplayAffinity availability/value/mode/error. Suitable layered-window and DWM composition context is required. Unknown does not mean WDA_NONE; unavailable query returns 5, owner change/mismatch 3. Reports policy only, not a capture-pixel proof. No driver, R0 fallback or help-side query.",query});
    addCommand({L"window capture set",L"KswordCLI.exe window capture set --hwnd HWND --pid PID --tid TID --creation-time FILETIME --thread-creation-time FILETIME --mode none|monitor|exclude [--backend r3] [--json]",
        L"Set and verify display affinity only in the owning-process context.",
        L"Required: --hwnd, --pid, --tid, --creation-time, --thread-creation-time, --mode none|monitor|exclude. Optional: --backend r3, --json.",
        L"Output: guarded target, RtlGetVersion platform evidence, requested value, actual API acceptance/error, before/after readback and verified effect. The backend supports only the caller's top-level HWND: standalone CLI cannot set another application's window and returns 5 without a write. Same-process consumer/fixture context can exercise the adapter; no window injection or R0 extension is added. Process/thread handles are retained and ownership rechecked; same-thread HWND reuse remains a Win32 limitation. WDA_EXCLUDEFROMCAPTURE (0x11) requires known Windows 10 2004/build 19041 or later; older/unknown platforms return 5 before writing. Downgrade/readback failure returns 6, actual set failure 3/unsupported 5, match 0. Help does not set/query attributes.",set});
}
}
