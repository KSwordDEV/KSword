#include "CommandRegistry.h"
#include "../shared/usermode/backend/privilege/PrivilegeEnumerator.h"
#include "../shared/usermode/backend/privilege/PrivilegeActions.h"
#include <algorithm>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>

namespace ks::cli {
namespace {
namespace backend = ks::r3::privilege;
const backend::PrivilegeEntry* find(const backend::PrivilegeSnapshot& s, const std::wstring& name) {
    for (const auto& e : s.privileges) if (_wcsicmp(e.name.c_str(), name.c_str()) == 0) return &e;
    return nullptr;
}
Json token(const backend::TokenSummary& t) {
    return Json::object({{L"userName", Json::string(t.userName)}, {L"userSid", Json::string(t.userSid)},
        {L"integrityLevel", t.integrityLevel.empty() ? Json{} : Json::string(t.integrityLevel)},
        {L"tokenType", t.tokenType.empty() ? Json{} : Json::string(t.tokenType)},
        {L"elevated", t.elevationKnown ? Json::boolean(t.elevated) : Json{}},
        {L"uiAccess", t.uiAccessKnown ? Json::boolean(t.uiAccess) : Json{}},
        {L"enabledGroups", t.groupsKnown ? Json::strings(t.groups) : Json{}}});
}
Result query(const Args& args) {
    const auto name = args.get(L"--name"); const auto limit = args.u32(L"--limit");
    const auto snapshot = backend::EnumerateProcessPrivileges();
    std::vector<Json> rows, errors; std::uint32_t matched = 0;
    for (const auto& e : snapshot.privileges) {
        if (!name.empty() && _wcsicmp(name.c_str(), e.name.c_str()) != 0) continue;
        ++matched; if (limit && rows.size() >= limit) continue;
        const auto luid = (static_cast<std::uint64_t>(static_cast<DWORD>(e.luid.HighPart)) << 32) | e.luid.LowPart;
        rows.push_back(Json::object({{L"name", Json::string(e.name)}, {L"displayName", Json::string(e.displayName)},
            {L"luid", Json::hex(luid)}, {L"enabled", Json::boolean(e.enabled)},
            {L"enabledByDefault", Json::boolean(e.enabledByDefault)}, {L"removed", Json::boolean(e.removed)},
            {L"description", Json::string(e.description)}, {L"risk", Json::string(e.riskText)}}));
    }
    for (const auto& e : snapshot.queryErrors) errors.push_back(Json::object({
        {L"informationClass", Json::number(e.informationClass)}, {L"win32Error", Json::number(e.win32Error)}}));
    Result result{!snapshot.success ? 3 : snapshot.queryErrors.empty() ? 0 : 6};
    result.data = Json::object({{L"source", Json::string(L"current-process-token")}, {L"pid", Json::number(GetCurrentProcessId())},
        {L"token", token(snapshot.token)}, {L"win32Error", Json::number(snapshot.win32Error)}, {L"queryErrors", Json::array(errors)},
        {L"totalCount", Json::number(static_cast<std::uint32_t>(snapshot.privileges.size()))}, {L"matchedCount", Json::number(matched)},
        {L"returnedCount", Json::number(static_cast<std::uint32_t>(rows.size()))}, {L"privileges", Json::array(rows)}});
    if (!snapshot.diagnosticText.empty()) result.diagnostics.push_back(snapshot.diagnosticText);
    return result;
}
std::vector<std::pair<std::wstring, bool>> changes(const Args& args) {
    std::vector<std::pair<std::wstring, bool>> result; std::set<std::wstring> seen;
    for (const auto& key : {L"--enable", L"--disable"}) if (args.has(key)) {
        std::wistringstream input(args.get(key)); std::wstring name;
        while (std::getline(input, name, L',')) {
            if (name.empty() || name.find_first_of(L" \t\r\n") != std::wstring::npos) throw std::invalid_argument("empty or invalid privilege name");
            auto lower = name; std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
            if (!seen.insert(lower).second) throw std::invalid_argument("duplicate or conflicting privilege name");
            result.emplace_back(name, std::wstring(key) == L"--enable");
        }
        if (args.get(key).empty() || args.get(key).back() == L',') throw std::invalid_argument("empty privilege name");
    }
    if (result.empty()) throw std::invalid_argument("missing option --enable or --disable");
    if (args.tail.empty()) throw std::invalid_argument("missing -- followed by a CLI command");
    return result;
}
struct Scope {
    std::vector<std::pair<std::wstring, bool>> restore;
    ~Scope() { for (auto it = restore.rbegin(); it != restore.rend(); ++it) (void)backend::SetPrivilegeEnabled(it->first, it->second); }
};
struct Capture {
    std::wostringstream out, err;
    std::wstreambuf* previousOut = std::wcout.rdbuf(out.rdbuf());
    std::wstreambuf* previousErr = std::wcerr.rdbuf(err.rdbuf());
    ~Capture() { std::wcout.rdbuf(previousOut); std::wcerr.rdbuf(previousErr); }
};
Result run(const Args& args, const std::function<int(std::vector<std::wstring>)>& dispatch) {
    const auto requests = changes(args); const auto before = backend::EnumerateProcessPrivileges();
    if (!before.success) return {3, Json::object({{L"win32Error", Json::number(before.win32Error)}}), {before.diagnosticText}};
    Scope scope; Result result; std::vector<Json> adjustments, restorations;
    bool executed = false, restored = true; int nestedCode = 0; std::wstring out, err;
    for (const auto& [name, enabled] : requests) {
        const auto* original = find(before, name);
        // Register restoration before the call, including a rare failed call
        // that changed state. Unknown privileges cannot be granted by this API.
        if (original) scope.restore.emplace_back(name, original->enabled);
        const auto action = backend::SetPrivilegeEnabled(name, enabled);
        const auto after = backend::EnumerateProcessPrivileges(); const auto* observed = find(after, name);
        const bool verified = action.success && after.success && observed && observed->enabled == enabled;
        adjustments.push_back(Json::object({{L"name", Json::string(name)}, {L"requestedEnabled", Json::boolean(enabled)},
            {L"beforeEnabled", original ? Json::boolean(original->enabled) : Json{}}, {L"requestSucceeded", Json::boolean(action.success)},
            {L"observedEnabled", observed ? Json::boolean(observed->enabled) : Json{}}, {L"verified", Json::boolean(verified)},
            {L"win32Error", Json::number(action.win32Error)}}));
        if (!verified) { result.code = action.success ? 6 : 3; result.diagnostics.push_back(action.message); break; }
    }
    if (!result.code) {
        Capture capture; executed = true; nestedCode = dispatch(args.tail);
        out = capture.out.str(); err = capture.err.str(); result.code = nestedCode;
    }
    while (!scope.restore.empty()) {
        const auto [name, enabled] = scope.restore.back();
        const auto action = backend::SetPrivilegeEnabled(name, enabled);
        const auto after = backend::EnumerateProcessPrivileges(); const auto* observed = find(after, name);
        const bool verified = action.success && after.success && observed && observed->enabled == enabled;
        restorations.push_back(Json::object({{L"name", Json::string(name)}, {L"requestedEnabled", Json::boolean(enabled)},
            {L"requestSucceeded", Json::boolean(action.success)}, {L"observedEnabled", observed ? Json::boolean(observed->enabled) : Json{}},
            {L"verified", Json::boolean(verified)}, {L"win32Error", Json::number(action.win32Error)}}));
        restored &= verified; scope.restore.pop_back();
    }
    if (!restored) { if (!result.code) result.code = 6; result.diagnostics.push_back(L"Privilege restoration was not confirmed."); }
    result.data = Json::object({{L"source", Json::string(L"current-process-token")}, {L"pid", Json::number(GetCurrentProcessId())},
        {L"adjustments", Json::array(adjustments)}, {L"commandArguments", Json::strings(args.tail)}, {L"executed", Json::boolean(executed)},
        {L"exitCode", executed ? Json::number(nestedCode) : Json{}}, {L"stdout", Json::string(out)}, {L"stderr", Json::string(err)},
        {L"restorations", Json::array(restorations)}, {L"restored", Json::boolean(restored)}});
    return result;
}
}
void registerPrivilege(std::function<int(std::vector<std::wstring>)> dispatch) {
    addFamily(L"privilege", L"Inspect the current process token and run a CLI command with scoped privileges.");
    addCommand({L"privilege query", L"KswordCLI.exe privilege query [--name NAME] [--limit N] [--backend r3] [--json]",
        L"Read the current CLI process token and its assigned privileges.", L"Optional: --name exact privilege name, --limit display rows (0 = all), --backend r3, --json.",
        L"Fields: source, pid, token, privileges, queryErrors. Unknown token properties are null. No other process token is changed.", query});
    Command command{L"privilege run", L"KswordCLI.exe privilege run [--enable NAME[,NAME...]] [--disable NAME[,NAME...]] [--backend r3] [--json] -- <CLI command>",
        L"Adjust assigned privileges, execute one CLI command in this process, then restore the original states.",
        L"Required: --enable or --disable, -- followed by a CLI command. Optional: --backend r3, --json. Names cannot overlap.",
        L"Fields: pid, adjustments, executed, exitCode, stdout, stderr, restorations, restored. Cannot grant missing privileges. Child output is captured as text; outer JSON is one document. Child failure code is retained.",
        [dispatch](const Args& args) { return run(args, dispatch); }};
    command.acceptsTail = true; addCommand(std::move(command));
}
}
