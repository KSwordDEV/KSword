#include "R3StartupShared.h"
#include "../shared/usermode/backend/startup/StartupActions.h"
#include <algorithm>
#include <stdexcept>
namespace ks::cli {
namespace {
using namespace ks::r3::startup;
Result apply(const Args& args,const std::wstring& operation) {
    args.require(L"--id");const auto wanted=Json::hex(args.integer(L"--id")).display;
    if(operation!=L"location" && !args.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
    const auto identity=startup::identity();
    if(identity.win32Error || identity.sid.empty()) return {3,Json::object({{L"identityWin32Error",Json::number(identity.win32Error)}}),{L"Caller identity could not be established."}};
    const auto snapshot=EnumerateStartupEntries();std::vector<StartupEntry> matches;
    for(const auto& entry:snapshot.entries) if(startup::id(entry,identity.sid)==wanted) matches.push_back(entry);
    if(matches.size()!=1) return {3,Json::object({{L"id",Json::string(wanted)}, {L"matchCount",Json::number(static_cast<std::uint32_t>(matches.size()))}, {L"sourceErrors",startup::errors(snapshot)}}),
        {L"Startup identifier must match exactly one current entry; refresh the enumeration."}};
    const auto& entry=matches.front();
    if(operation==L"location") return {snapshot.sourceErrors.empty() ? 0 : 6,startup::row(entry,identity.sid),{}};
    const auto result=operation==L"enable" ? EnableStartupEntry(entry) : operation==L"disable" ? DisableStartupEntry(entry) : DeleteStartupEntry(entry);
    const auto after=EnumerateStartupEntries();std::vector<Json> observed;std::vector<StartupEntry> afterMatches;
    for(const auto& row:after.entries) if(startup::id(row,identity.sid)==wanted) {observed.push_back(startup::row(row,identity.sid));afterMatches.push_back(row);}
    bool verified=false;
    if(operation==L"delete") verified=afterMatches.empty() && after.sourceErrors.empty();
    else if(entry.kind==StartupEntryKind::ScheduledTaskFacade) verified=result.taskStateKnown && result.taskEnabled==(operation==L"enable");
    else if(afterMatches.size()==1) {
        const auto& row=afterMatches.front();
        if(entry.kind==StartupEntryKind::Service) verified=result.serviceTypeKnown && row.state!=StartupEntryState::Unknown && row.serviceStartType==result.expectedServiceStartType;
        else verified=row.state==(operation==L"enable" ? StartupEntryState::Active : StartupEntryState::Disabled) &&
            (entry.kind==StartupEntryKind::StartupFolder ? row.filePath==entry.filePath && row.disabledFilePath==entry.disabledFilePath : row.command==entry.command);
    }
    const int code=result.unsupported ? 5 : result.partial ? 6 : !result.success ? 3 : verified ? 0 : 6;
    return {code,Json::object({{L"id",Json::string(wanted)}, {L"operation",Json::string(operation)}, {L"target",startup::row(entry,identity.sid)},
        {L"requestSucceeded",Json::boolean(result.success)}, {L"win32Error",Json::number(result.win32Error)}, {L"hresult",Json::number(result.hresult)},
        {L"partial",Json::boolean(result.partial)}, {L"verified",Json::boolean(verified)}, {L"observed",Json::array(observed)},
        {L"observedTaskEnabled",result.taskStateKnown ? Json::boolean(result.taskEnabled) : Json{}},
        {L"preservationSucceeded",result.preservationKnown ? Json::boolean(result.preservationSucceeded) : Json{}}, {L"sourceErrors",startup::errors(after)}}),
        result.message.empty() ? std::vector<std::wstring>{} : std::vector<std::wstring>{result.message}};
}
}
void registerStartupActions() {
    for(const auto* operation:{L"enable",L"disable",L"delete"}) {
        const std::wstring word=operation;
        addCommand({L"startup "+word,L"KswordCLI.exe startup "+word+L" --id ID --confirm [--backend r3] [--json]",
            L"Apply startup "+word+L" to one freshly identified entry and verify it.",L"Required: --id from startup enum, --confirm. Optional: --backend r3, --json.",
            L"Driver/registry-only service observations remain read-only. Registry/folder entries use the existing parking stores; service enable restores its saved start type; tasks use Task Scheduler COM. Data: target, observed, verified, requestSucceeded, raw errors and preservation status.",[word](const Args& args){return apply(args,word);}});
    }
    addCommand({L"startup location query",L"KswordCLI.exe startup location query --id ID [--backend r3] [--json]",L"Read a startup entry's storage/management location.",
        L"Required: --id from startup enum. Optional: --backend r3, --json.",L"Read-only. Returns registry, file, service or task path metadata without launching a GUI application.",[](const Args& args){return apply(args,L"location");}});
}
}
