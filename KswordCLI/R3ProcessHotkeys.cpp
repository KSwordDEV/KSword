#include "R3ProcessShared.h"
#include "../shared/usermode/backend/process/ProcessHotkeys.h"
#include "../shared/usermode/backend/process/ProcessEnumerator.h"
#include <algorithm>
namespace ks::cli {
namespace {
namespace backend = ks::r3::process_detail::hotkeys;
std::wstring source(backend::CandidateSource s) {
    switch (s) {case backend::CandidateSource::Window:return L"window";case backend::CandidateSource::Menu:return L"menu";
    case backend::CandidateSource::Accelerator:return L"accelerator";case backend::CandidateSource::Shortcut:return L"shortcut";default:return L"unknown";}
}
Json row(const backend::HotkeyCandidate& r) {
    const auto kind = r.keyKind == backend::KeyKind::VirtualKey ? L"virtual-key" : r.keyKind == backend::KeyKind::Character ? L"character" : L"menu-mnemonic";
    std::wstring keyText = r.hotkeyText;
    if (r.keyKind != backend::KeyKind::VirtualKey) {
        keyText.clear();if (r.modifiers & MOD_CONTROL) keyText+=L"Ctrl+";if (r.modifiers & MOD_SHIFT) keyText+=L"Shift+";
        if (r.modifiers & MOD_ALT) keyText+=L"Alt+";keyText+=static_cast<wchar_t>(r.virtualKey);
    }
    return Json::object({{L"pid",Json::number(r.processId)}, {L"tid",r.threadId?Json::number(r.threadId):Json{}}, {L"source",Json::string(source(r.source))},
        {L"window",r.window?Json::hex(r.window):Json{}}, {L"keyKind",Json::string(kind)}, {L"keyCode",Json::number(r.virtualKey)},
        {L"virtualKey",r.keyKind==backend::KeyKind::VirtualKey?Json::number(r.virtualKey):Json{}}, {L"modifiers",Json::hex(r.modifiers)},
        {L"hotkey",Json::string(keyText)}, {L"commandId",(r.source==backend::CandidateSource::Menu || r.source==backend::CandidateSource::Accelerator) && r.hotkeyId!=0xffffffff ? Json::number(r.hotkeyId):Json{}},
        {L"resourceName",r.source==backend::CandidateSource::Accelerator?Json::string(r.resourceName):Json{}},
        {L"shortcutPath",r.source==backend::CandidateSource::Shortcut?Json::string(r.shortcutPath):Json{}},
        {L"objectDisplay",Json::string(r.objectText)}, {L"detailDisplay",Json::string(r.detailText)}, {L"activeRegistration",Json{}}});
}
Json report(const std::wstring& name,const backend::ProbeReport& value) {
    std::vector<Json> failures;
    for (const auto& f:value.failures) {
        const Json code = !f.codeKnown?Json{}:f.domain==L"hresult"?Json::hex(static_cast<DWORD>(f.code)):f.domain==L"filesystem"?
            Json::signedNumber(static_cast<std::int32_t>(f.code)):Json::number(static_cast<DWORD>(f.code));
        failures.push_back(Json::object({{L"operation",Json::string(f.operation)}, {L"domain",Json::string(f.domain)}, {L"code",code}}));
    }
    return Json::object({{L"source",Json::string(name)}, {L"complete",Json::boolean(value.complete)}, {L"fatal",Json::boolean(value.fatal)},
        {L"limited",Json::boolean(value.limited)}, {L"malformed",Json::boolean(value.malformed)}, {L"absent",Json::boolean(value.absent)},
        {L"examinedCount",Json::number(value.examined)}, {L"staleWindows",Json::number(value.staleWindows)},
        {L"comStatus",value.comStatusKnown?Json::hex(static_cast<DWORD>(value.comStatus)):Json{}}, {L"comOwned",Json::boolean(value.comOwned)}, {L"failures",Json::array(failures)}});
}
Result query(const Args& args) {
    const auto selector=args.get(L"--source",L"all");
    if (selector!=L"all"&&selector!=L"windows"&&selector!=L"accelerators"&&selector!=L"shortcuts") throw std::invalid_argument("--source must be all, windows, accelerators or shortcuts");
    const auto limit=args.u32(L"--limit",1000);if (!limit || limit>10000) throw std::invalid_argument("--limit must be 1..10000");
    process::Lease lease(args);if (!lease.matches||!lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    DWORD imageError=0;const auto image=ks::r3::process::QueryProcessImagePath(lease.pid,lease.creationTime,&imageError);
    const auto slash=image.find_last_of(L"\\/");const auto name=image.empty()?L"PID "+std::to_wstring(lease.pid):slash==std::wstring::npos?image:image.substr(slash+1);
    std::vector<backend::HotkeyCandidate> candidates;std::unordered_set<std::wstring> dedupe;
    std::vector<Json> reports;bool partial=false,malformed=false;DWORD count=0,fatal=0;std::vector<std::wstring> diagnostics;
    for (const auto* kind:{L"windows",L"accelerators",L"shortcuts"}) {
        if (selector!=L"all"&&selector!=kind) continue;
        ++count;backend::ProbeReport state;std::wstring text;
        if (std::wstring(kind)==L"windows") backend::CollectWindowAndMenuHotkeys(lease.pid,name,candidates,dedupe,&state);
        else if (std::wstring(kind)==L"accelerators") backend::CollectAcceleratorHotkeys(lease.pid,name,image,candidates,dedupe,text,&state);
        else backend::CollectShortcutHotkeys(lease.pid,name,image,candidates,dedupe,text,&state);
        partial=partial||!state.complete;malformed=malformed||state.malformed;if (state.fatal) ++fatal;
        if (!text.empty()) diagnostics.push_back(text);reports.push_back(report(kind,state));
    }
    if (!lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Target exited during hotkey collection."}};
    std::vector<Json> rows;for (const auto& candidate:candidates) {if (rows.size()>=limit) break;rows.push_back(row(candidate));}
    const bool truncated=candidates.size()>rows.size();const int code=malformed?4:fatal==count?3:partial||truncated?6:0;
    if (code) diagnostics.push_back(L"Some selected sources were unavailable, malformed or limited; native source evidence is retained and this remains a candidate collection.");
    return {code,Json::object({{L"target",lease.json()}, {L"imagePath",image.empty()?Json{}:Json::string(image)}, {L"imagePathWin32Error",Json::number(imageError)},
        {L"scope",Json::string(L"caller-visible windows and menus; disk image accelerator declarations; caller desktop/programs/common-programs shortcuts")},
        {L"globalRegistrationInventory",Json::boolean(false)}, {L"matchedCount",Json::count(candidates.size())}, {L"returnedCount",Json::number(static_cast<DWORD>(rows.size()))},
        {L"truncated",Json::boolean(truncated)}, {L"sources",Json::array(reports)}, {L"candidates",Json::array(rows)}}),diagnostics};
}
}
void registerProcessHotkeys() {
    addCommand({L"process hotkeys enum",L"KswordCLI.exe process hotkeys enum --pid PID [--creation-time FILETIME] [--source all|windows|accelerators|shortcuts] [--limit N] [--backend r3] [--json]",
        L"Collect R3 window/menu/resource/shortcut hotkey candidates.",L"Required: --pid. Optional: --creation-time, --source (all), --limit (1..10000, default 1000), --backend r3, --json.",
        L"Output: target/image identity, declared scope, sources with completeness/budget/errors/COM ownership, candidates with source/window/keyKind/keyCode/virtualKey/modifiers/hotkey/commandId/resourceName/shortcutPath. These are candidates, not a global RegisterHotKey inventory; activeRegistration is unknown. Menus use mnemonics; non-VIRTKEY resources use characters. Caller profile/desktop and raw link path matching limit visibility. Per-source deadline checks 8 seconds, WM_GETHOTKEY timeout 500 ms, menu depth 64, shortcut cap 8000; COM/filesystem calls are not forcibly interrupted. Incomplete/limited data returns 6, malformed resources 4, fatal source acquisition 3. Valid empty selected sources succeed. No removal or R0 fallback.",query});
}
}
