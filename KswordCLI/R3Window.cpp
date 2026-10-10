#include "R3WindowShared.h"
#include "../shared/usermode/backend/window/WindowEnumerator.h"
#include "../shared/usermode/backend/window/WindowActions.h"
#include <algorithm>
#include <chrono>
#include <thread>
namespace ks::cli {
namespace {
namespace b=ks::r3::window;
Json rect(const RECT& r){return Json::object({{L"left",Json::signedNumber(r.left)},{L"top",Json::signedNumber(r.top)},{L"right",Json::signedNumber(r.right)},{L"bottom",Json::signedNumber(r.bottom)}});}
Json row(const b::WindowSnapshotRow& r) {
    const auto known=[&](const wchar_t* id){const auto e=r.evidence.find(id);return e!=r.evidence.end()&&e->second.available;};
    std::vector<std::pair<std::wstring,Json>> fields;
    for(const auto& [id,e]:r.evidence)fields.push_back({id,Json::object({{L"available",Json::boolean(e.available)},{L"empty",Json::boolean(e.empty)},
        {L"truncated",Json::boolean(e.truncated)},{L"win32Error",e.error?Json::number(e.error):Json{}}})});
    return Json::object({{L"hwnd",Json::hex(reinterpret_cast<std::uintptr_t>(r.hwnd))},{L"pid",Json::number(r.processId)},{L"tid",Json::number(r.threadId)},
        {L"processCreationTime",known(L"processIdentity")&&r.processCreationTime?Json::count(r.processCreationTime):Json{}},
        {L"threadCreationTime",known(L"threadIdentity")&&r.threadCreationTime?Json::count(r.threadCreationTime):Json{}},
        {L"title",known(L"title")?Json::string(r.title):Json{}},{L"class",known(L"class")?Json::string(r.className):Json{}},
        {L"processImagePath",known(L"processImagePath")?Json::string(r.processImagePath):Json{}},
        {L"visible",Json::boolean(r.visible)},{L"enabled",Json::boolean(r.enabled)},{L"minimized",Json::boolean(r.minimized)},
        {L"maximized",Json::boolean(r.maximized)},{L"unicode",Json::boolean(r.unicode)},
        {L"style",known(L"style")?Json::hex(r.style):Json{}},{L"exStyle",known(L"exStyle")?Json::hex(r.exStyle):Json{}},
        {L"windowRect",known(L"windowRect")?rect(r.windowRect):Json{}},{L"clientRect",known(L"clientRect")?rect(r.clientRect):Json{}},
        {L"clientRectCoordinates",Json::string(r.clientRectInScreenCoordinates?L"screen":L"client")},{L"evidence",Json::object(fields)}});
}
bool partial(const b::WindowSnapshotRow& r){for(const auto& [id,e]:r.evidence)if(id!=L"windowInfo"&&(!e.available||e.truncated))return true;return false;}
void validateReadGuards(const Args& a) {
    if(a.has(L"--pid"))(void)a.u32(L"--pid");if(a.has(L"--tid"))(void)a.u32(L"--tid");
    if(a.has(L"--creation-time")&&(!a.has(L"--pid")||!a.integer(L"--creation-time")))throw std::invalid_argument("positive --creation-time requires --pid");
    if(a.has(L"--thread-creation-time")&&(!a.has(L"--tid")||!a.integer(L"--thread-creation-time")))throw std::invalid_argument("positive --thread-creation-time requires --tid");
}
bool matches(const b::WindowSnapshotRow& r,const Args& a){return (!a.has(L"--pid")||r.processId==a.u32(L"--pid"))&&(!a.has(L"--tid")||r.threadId==a.u32(L"--tid"))&&
    (!a.has(L"--creation-time")||r.processCreationTime==a.integer(L"--creation-time"))&&(!a.has(L"--thread-creation-time")||r.threadCreationTime==a.integer(L"--thread-creation-time"));}
Result detail(const Args& a) {
    validateReadGuards(a);const auto target=window::hwnd(a);const auto d=b::QueryWindowDetails(target);
    const bool identity=d.found&&matches(d.row,a);
    return {!identity?3:partial(d.row)?6:0,Json::object({{L"source",Json::string(L"live Win32 window properties")},
        {L"hwnd",Json::hex(reinterpret_cast<std::uintptr_t>(target))},{L"found",Json::boolean(d.found)},
        {L"identityMatched",Json::boolean(identity)},{L"win32Error",d.win32Error?Json::number(d.win32Error):Json{}},{L"window",d.found?row(d.row):Json{}}}),
        !identity?std::vector<std::wstring>{L"Window no longer exists or supplied owner/creation-time identity does not match."}:
        partial(d.row)?std::vector<std::wstring>{L"Some window fields were inaccessible or truncated; empty titles are distinguished from failed reads."}:std::vector<std::wstring>{}};
}
Result enumerate(const Args& a) {
    const auto sort=a.get(L"--sort",L"stacking"),visible=a.get(L"--visible",L"all");
    if(sort!=L"stacking"&&sort!=L"process")throw std::invalid_argument("--sort must be stacking or process");
    if(visible!=L"all"&&visible!=L"yes"&&visible!=L"no")throw std::invalid_argument("--visible must be all, yes or no");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");
    if(a.has(L"--pid"))(void)a.u32(L"--pid");auto snapshot=b::EnumerateTopLevelWindows();
    if(sort==L"process")std::stable_sort(snapshot.rows.begin(),snapshot.rows.end(),[](const auto& l,const auto& r){return l.processId<r.processId;});
    std::vector<Json> rows;std::size_t matched=0;bool missing=false;
    for(const auto& r:snapshot.rows){if(a.has(L"--pid")&&r.processId!=a.u32(L"--pid"))continue;
        if(visible!=L"all"&&(visible==L"yes")!=r.visible)continue;++matched;missing=missing||partial(r);if(rows.size()<limit)rows.push_back(row(r));}
    const bool truncated=matched>rows.size();const int code=!snapshot.success&&snapshot.rows.empty()?3:!snapshot.complete||snapshot.skippedCount||missing||truncated?6:0;
    return {code,Json::object({{L"source",Json::string(L"EnumWindows on caller desktop; shell infrastructure filtered")},
        {L"complete",Json::boolean(snapshot.complete)},{L"limited",Json::boolean(snapshot.limited)},
        {L"win32Error",snapshot.win32Error?Json::number(snapshot.win32Error):Json{}},{L"examinedCount",Json::number(snapshot.examinedCount)},
        {L"skippedCount",Json::number(snapshot.skippedCount)},{L"shellFilteredCount",Json::number(snapshot.shellFilteredCount)},
        {L"matchedCount",Json::count(matched)},{L"returnedCount",Json::number(static_cast<DWORD>(rows.size()))},{L"truncated",Json::boolean(truncated)},
        {L"windows",Json::array(rows)}}),code?std::vector<std::wstring>{L"Some windows/fields were unavailable, changed identity or exceeded capture/output budgets."}:std::vector<std::wstring>{}};
}
Result action(const Args& a,const std::wstring& verb) {
    window::Lease lease(a);const auto wait=a.u32(L"--wait-ms",2000);if(wait>10000)throw std::invalid_argument("--wait-ms must be 0..10000");
    if(!lease.matches||!lease.ownerMatches())return {3,Json::object({{L"target",lease.json()},{L"action",Json::string(verb)},{L"attempted",Json::boolean(false)}}),{L"Window/process/thread identity is unavailable, mismatched or exited."}};
    const auto before=b::QueryWindowDetails(lease.handle);if(!before.found||!lease.ownerMatches())return {3,Json::object({{L"target",lease.json()}}),{L"Target changed before submission."}};
    const auto satisfied=[&](){if(!lease.ownerMatches()||!::IsWindowVisible(lease.handle))return false;
        if(verb==L"minimize")return ::IsIconic(lease.handle)!=FALSE;
        if(verb==L"maximize")return ::IsZoomed(lease.handle)!=FALSE;
        if(verb==L"restore")return !::IsIconic(lease.handle)&&!::IsZoomed(lease.handle);
        if(verb==L"foreground")return ::GetForegroundWindow()==lease.handle&&!::IsIconic(lease.handle);
        return false;};
    const bool already=satisfied();b::WindowActionResult result;
    if(!already) {
        if(!lease.ownerMatches())return {3,Json::object({{L"target",lease.json()}}),{L"Target changed before submission."}};
        if(verb==L"minimize")result=b::MinimizeWindow(lease.handle,true);
        else if(verb==L"maximize")result=b::MaximizeWindow(lease.handle,true);
        else if(verb==L"restore")result=b::RestoreWindow(lease.handle,true);
        else if(verb==L"foreground")result=b::BringWindowToFront(lease.handle,true);
        else result=b::CloseWindowGracefully(lease.handle);
    }
    const auto complete=[&](){return verb==L"close"?(!::IsWindow(lease.handle)||!lease.ownersAlive()):satisfied();};
    bool verified=already||complete();const auto until=std::chrono::steady_clock::now()+std::chrono::milliseconds(wait);
    if(result.requestAccepted||result.restoreAccepted)while(!verified&&std::chrono::steady_clock::now()<until){
        if(verb!=L"close"&&!lease.ownerMatches())break;std::this_thread::sleep_for(std::chrono::milliseconds(25));verified=complete();}
    const auto after=lease.ownerMatches()?b::QueryWindowDetails(lease.handle):b::WindowDetail{};
    const int code=already?0:!result.requestAccepted?(result.restoreAccepted?6:3):verified?0:6;
    return {code,Json::object({{L"target",lease.json()},{L"action",Json::string(verb)},{L"alreadySatisfied",Json::boolean(already)},
        {L"attempted",Json::boolean(result.attempted)},{L"requestAccepted",result.requestAcceptedKnown?Json::boolean(result.requestAccepted):Json{}},
        {L"nativeReturn",result.attempted?Json::count(static_cast<std::uint64_t>(result.nativeReturn)):Json{}},
        {L"win32Error",result.errorKnown?Json::number(result.win32Error):Json{}},{L"restoreAttempted",Json::boolean(result.restoreAttempted)},
        {L"restoreAccepted",result.restoreAttempted?Json::boolean(result.restoreAccepted):Json{}},{L"restoreWin32Error",result.restoreError?Json::number(result.restoreError):Json{}},
        {L"verified",Json::boolean(verified&&(already||result.requestAccepted))},{L"ownerStillMatches",Json::boolean(lease.ownerMatches())},
        {L"ownersAlive",Json::boolean(lease.ownersAlive())},{L"windowExists",Json::boolean(::IsWindow(lease.handle)!=FALSE)},
        {L"foregroundWindow",Json::hex(reinterpret_cast<std::uintptr_t>(::GetForegroundWindow()))},
        {L"before",row(before.row)},{L"after",after.found?row(after.row):Json{}},{L"requestDisplay",Json::string(result.message)}}),
        code?std::vector<std::wstring>{L"Native request failed or the requested effect was not confirmed. A queued request may complete later; foreground policy and UIPI are respected."}:std::vector<std::wstring>{}};
}
}
void registerWindow() {
    const auto queryNotes=L"Output: HWND/PID/TID, process/thread FILETIME creation identities, caption/class/path, state, styles, rectangles and per-field evidence. Valid empty title is an empty string; read failure is null. WINDOWINFO clientRect is in screen coordinates; fallback GetClientRect uses client coordinates and is labelled. Only caller desktop top-level windows; Progman/WorkerW/Shell_TrayWnd excluded from enumeration. HWNDs are transient; same-thread HWND reuse has no Win32 generation token. No R0 fallback. Capture budget 100000 candidates/8 seconds between native calls; title 32767 chars, class 511 chars. Missing/truncated fields return 6; valid empty lists succeed.";
    addCommand({L"window enum",L"KswordCLI.exe window enum [--pid PID] [--visible all|yes|no] [--sort stacking|process] [--limit N] [--backend r3] [--json]",
        L"Enumerate R3 top-level application windows on the caller desktop.",L"Optional: --pid, --visible (all), --sort (stacking), --limit (1..100000, default 1000), --backend r3, --json.",queryNotes,enumerate});
    const auto options=L"Required: --hwnd. Optional: --pid, --tid, --creation-time (positive, requires --pid), --thread-creation-time (positive, requires --tid), --backend r3, --json.";
    addCommand({L"window detail",L"KswordCLI.exe window detail --hwnd HWND --backend r3 [--pid PID] [--tid TID] [--creation-time FILETIME] [--thread-creation-time FILETIME] [--json]",
        L"Read R3 window details; default invocation retains R0.",options,queryNotes,detail});
    addCommand({L"window detail query",L"KswordCLI.exe window detail query --hwnd HWND [--pid PID] [--tid TID] [--creation-time FILETIME] [--thread-creation-time FILETIME] [--backend r3] [--json]",
        L"Query R3 window details with optional owner identity guards.",options,queryNotes,detail});
    for(const auto* verb:{L"minimize",L"maximize",L"restore",L"foreground",L"close"})addCommand({std::wstring(L"window manage ")+verb,
        std::wstring(L"KswordCLI.exe window manage ")+verb+L" --hwnd HWND --pid PID --tid TID --creation-time FILETIME --thread-creation-time FILETIME [--wait-ms MS] [--backend r3] [--json]",
        std::wstring(L"Request and verify R3 window ")+verb+L".",
        L"Required: --hwnd, --pid, --tid, --creation-time, --thread-creation-time. Optional: --wait-ms (0..10000, default 2000), --backend r3, --json.",
        L"Output: target identity, before/after, request acceptance/native return/error, optional restore submission, actual verified effect and liveness. Retains process/thread handles and rechecks HWND owner before/after; same-thread HWND reuse remains a Win32 limitation. ShowWindowAsync is used for display requests; its acceptance is not completion. WM_CLOSE may be ignored; posted but unverified effects return 6. Foreground policy/UIPI may deny requests; a missing Win32 error stays unknown. Already satisfied visible states succeed without a write; restoring a hidden normal window still submits the show request. No process termination, input-queue attachment, desktop switch or R0 fallback. Help does not submit requests.",[verb](const Args& a){return action(a,verb);}});
}
}
