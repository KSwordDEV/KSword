#include "R3StartupShared.h"
#include "../shared/usermode/backend/startup/StartupActions.h"
#include <algorithm>
#include <stdexcept>
namespace ks::cli {
namespace {
using namespace ks::r3::startup;
Result apply(const Args& args, const std::wstring& operation) {
    args.require(L"--id");
    const auto wanted = Json::hex(args.integer(L"--id")).display;
    if (operation != L"location" && !args.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
    const auto caller = startup::identity();
    if (caller.win32Error || caller.sid.empty()) return {3, Json::object({{L"identityWin32Error", Json::count(caller.win32Error)}}), {L"Caller identity could not be established."}};
    const auto before = EnumerateStartupSnapshot();
    std::vector<StartupEntry> matches;
    for (const auto& entry : before.entries) if (startup::id(entry, caller.sid) == wanted) matches.push_back(entry);
    if (matches.size() != 1) return {3, Json::object({{L"id", Json::string(wanted)}, {L"matchCount", Json::count(matches.size())}, {L"sourceErrors", startup::errors(before)}}), {L"Startup identifier must match exactly one current entry; refresh the enumeration."}};
    const auto entry = matches.front();
    if (operation == L"location") return {before.success && before.sourceErrors.empty() ? 0 : 6, startup::row(entry, caller.sid),
        before.success ? std::vector<std::wstring>{} : std::vector<std::wstring>{L"The source snapshot did not report success; the matched entry may be incomplete."}};
    const auto action = operation == L"enable" ? SetStartupEntryEnabled(entry, true) : operation == L"disable" ? SetStartupEntryEnabled(entry, false) : DeleteStartupEntry(entry);
    const auto after = EnumerateStartupSnapshot();
    std::vector<Json> observed;
    std::vector<StartupEntry> afterMatches;
    for (const auto& current : after.entries) if (startup::id(current, caller.sid) == wanted) { observed.push_back(startup::row(current, caller.sid)); afterMatches.push_back(current); }
    bool verified = false;
    if (operation == L"delete") verified = afterMatches.empty() && after.sourceErrors.empty();
    else if (afterMatches.size() == 1) verified = operation == L"enable" ? afterMatches.front().enabled : !afterMatches.front().enabled;
    const int code = action.status == StartupActionStatus::NotSupported ? 5 : !action.success ? 3 : verified ? 0 : 6;
    return {code, Json::object({
        {L"id", Json::string(wanted)}, {L"operation", Json::string(operation)}, {L"target", startup::row(entry, caller.sid)},
        {L"requestSucceeded", Json::boolean(action.success)}, {L"changed", Json::boolean(action.changed)},
        {L"status", Json::count(static_cast<std::uint32_t>(action.status))}, {L"errorCode", Json::count(action.errorCode)},
        {L"verified", Json::boolean(verified)}, {L"observed", Json::array(observed)},
        {L"observedTaskEnabled", entry.category == StartupCategory::Tasks && afterMatches.size() == 1 ? Json::boolean(afterMatches.front().enabled) : Json{}},
        {L"preservationSucceeded", entry.category == StartupCategory::Services && operation == L"disable" ? Json::boolean(action.success) : Json{}},
        {L"sourceErrors", startup::errors(after)}}),
        action.messageText.empty() ? std::vector<std::wstring>{} : std::vector<std::wstring>{startup::utf8(action.messageText)}};
}
}
void registerStartupActions() {
    for (const auto* operation : {L"enable", L"disable", L"delete"}) {
        const std::wstring word = operation;
        addCommand({L"startup " + word, L"KswordCLI.exe startup " + word + L" --id ID --confirm [--backend r3] [--json]",
            L"Apply startup " + word + L" to one freshly identified shared-backend entry and verify it.",
            L"Required: --id from startup enum, --confirm. Optional: --backend r3, --json.",
            L"The command re-enumerates before acting and matches the caller SID plus stable entry ID. Read-only or unsupported rows return exit 5; failed calls return 3; unconfirmed rereads return 6. Use help startup " + word + L" for fields and examples.",
            [word](const Args& args) { return apply(args, word); }});
    }
    addCommand({L"startup location query", L"KswordCLI.exe startup location query --id ID [--backend r3] [--json]",
        L"Read a startup entry's structured storage and management location.",
        L"Required: --id from startup enum. Optional: --backend r3, --json.",
        L"Read-only; does not launch Regedit, Explorer or Services. Use help startup location query for output fields.",
        [](const Args& args) { return apply(args, L"location"); }});
}
}
