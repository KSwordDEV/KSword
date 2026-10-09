#include "CommandRegistry.h"
#include "../shared/usermode/backend/service/ServiceEnumerator.h"
#include "../shared/usermode/backend/service/ServiceActions.h"
#include <stdexcept>
namespace ks::cli {
namespace {
using namespace ks::r3::service;
int failure(std::uint32_t error) { return error == ERROR_NOT_SUPPORTED || error == ERROR_CALL_NOT_IMPLEMENTED ? 5 : 3; }
Json row(const ServiceEntry& value) {
    const auto status = [&](std::uint32_t number){return value.hasStatus ? Json::number(number) : Json{};};
    const auto config = [&](std::uint32_t number){return value.hasConfig ? Json::number(number) : Json{};};
    return Json::object({{L"name",Json::string(value.serviceName)}, {L"displayName",Json::string(value.displayName)},
        {L"description",value.hasDescription ? Json::string(value.description) : Json{}}, {L"hasStatus",Json::boolean(value.hasStatus)}, {L"hasConfig",Json::boolean(value.hasConfig)},
        {L"state",status(value.currentState)}, {L"pid",status(value.processId)}, {L"serviceType",value.hasStatus || value.hasConfig ? Json::number(value.serviceType) : Json{}},
        {L"controlsAccepted",status(value.controlsAccepted)}, {L"win32ExitCode",status(value.win32ExitCode)}, {L"serviceSpecificExitCode",status(value.serviceSpecificExitCode)},
        {L"checkPoint",status(value.checkPoint)}, {L"waitHint",status(value.waitHint)}, {L"startType",config(value.startType)}, {L"errorControl",config(value.errorControl)},
        {L"binaryPath",value.hasConfig ? Json::string(value.binaryPath) : Json{}}, {L"imagePath",value.hasConfig ? Json::string(ResolveServiceImagePathForBrowser(value.binaryPath)) : Json{}},
        {L"account",value.hasConfig ? Json::string(value.accountName) : Json{}}, {L"loadOrderGroup",value.hasConfig ? Json::string(value.loadOrderGroup) : Json{}},
        {L"dependencyServices",Json::strings(value.dependencyServiceNames)}, {L"dependencyGroups",Json::strings(value.dependencyLoadOrderGroups)},
        {L"delayedAutoStart",value.hasDelayedAutoStart ? Json::boolean(value.delayedAutoStart) : Json{}}, {L"risk",Json::string(value.riskText)}, {L"diagnostic",Json::string(value.diagnosticText)}});
}
Result enumerate(const Args& args) {
    const auto limit=args.u32(L"--limit",100); const auto snapshot=EnumerateServices(); std::vector<Json> rows; std::uint32_t matched=0; bool partial=false;
    for(const auto& value:snapshot.entries) {
        if(args.has(L"--name") && ::CompareStringOrdinal(value.serviceName.c_str(),-1,args.get(L"--name").c_str(),-1,TRUE)!=CSTR_EQUAL) continue;
        ++matched; partial |= !value.hasStatus || !value.hasConfig;
        if(rows.size()<limit) rows.push_back(row(value));
    }
    return {snapshot.success ? (partial ? 6 : 0) : failure(snapshot.win32Error), Json::object({{L"win32Error",Json::number(snapshot.win32Error)},
        {L"matchedCount",Json::number(matched)}, {L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))}, {L"truncated",Json::boolean(rows.size()<matched)}, {L"services",Json::array(rows)}}),
        snapshot.diagnosticText.empty() ? std::vector<std::wstring>{} : std::vector<std::wstring>{snapshot.diagnosticText}};
}
Json section(const ServiceDetailSection& value) {return Json::object({{L"availability",Json::string(ServiceDetailAvailabilityText(value.availability))}, {L"win32Error",Json::number(value.win32Error)}, {L"diagnostic",Json::string(value.diagnosticText)}});}
Result query(const Args& args,bool details) {
    const auto name=args.require(L"--name"); if(name.empty()) throw std::invalid_argument("empty service name");
    const auto snapshot=QuerySingleService(name);
    if(!snapshot.success || snapshot.entries.empty()) return {failure(snapshot.win32Error),Json::object({{L"name",Json::string(name)}, {L"win32Error",Json::number(snapshot.win32Error)}}), {snapshot.diagnosticText}};
    if(!details) return {0,row(snapshot.entries.front()),{}};
    const auto detail=QueryServiceReadOnlyDetails(snapshot.entries.front()); std::vector<Json> actions;
    for(const auto& action:detail.failureSettings.actions) actions.push_back(Json::object({{L"type",Json::number(action.actionType)}, {L"delayMs",Json::number(action.delayMs)}}));
    return {detail.failureSettingsStatus.availability==ServiceDetailAvailability::Available && detail.reverseDependenciesStatus.availability==ServiceDetailAvailability::Available ? 0 : 6,
        Json::object({{L"service",row(detail.entry)}, {L"failureSettingsStatus",section(detail.failureSettingsStatus)}, {L"reverseDependenciesStatus",section(detail.reverseDependenciesStatus)},
            {L"failureSettings",Json::object({{L"hasActions",Json::boolean(detail.failureSettings.hasFailureActions)}, {L"hasNonCrashFlag",Json::boolean(detail.failureSettings.hasFailureActionsFlag)},
                {L"resetPeriodSeconds",detail.failureSettings.hasFailureActions ? Json::number(detail.failureSettings.resetPeriodSeconds) : Json{}}, {L"command",Json::string(detail.failureSettings.command)},
                {L"rebootMessage",Json::string(detail.failureSettings.rebootMessage)}, {L"onNonCrash",detail.failureSettings.hasFailureActionsFlag ? Json::boolean(detail.failureSettings.failureActionsOnNonCrash) : Json{}}, {L"actions",Json::array(actions)}})},
            {L"dependents",Json::strings(detail.dependencies.directDependentServiceNames)}}),{}};
}
Result action(const Args& args,const std::wstring& operation) {
    const auto name=args.require(L"--name"); if(name.empty()) throw std::invalid_argument("empty service name");
    if((operation==L"stop" || operation==L"set-start-type") && !args.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
    ServiceActionResult result; std::uint32_t expectedState=0,expectedType=0; bool expectedDelayed=false;
    if(operation==L"start") {result=StartServiceEntry(name);expectedState=SERVICE_RUNNING;}
    else if(operation==L"stop") {result=StopServiceEntry(name);expectedState=SERVICE_STOPPED;}
    else if(operation==L"pause") {result=PauseServiceEntry(name);expectedState=SERVICE_PAUSED;}
    else if(operation==L"continue") {result=ContinueServiceEntry(name);expectedState=SERVICE_RUNNING;}
    else {
        const auto value=args.require(L"--type"); ServiceStartTypeChoice choice;
        if(value==L"automatic") {choice=ServiceStartTypeChoice::Automatic;expectedType=SERVICE_AUTO_START;}
        else if(value==L"delayed") {choice=ServiceStartTypeChoice::AutomaticDelayed;expectedType=SERVICE_AUTO_START;expectedDelayed=true;}
        else if(value==L"manual") {choice=ServiceStartTypeChoice::Manual;expectedType=SERVICE_DEMAND_START;}
        else if(value==L"disabled") {choice=ServiceStartTypeChoice::Disabled;expectedType=SERVICE_DISABLED;}
        else throw std::invalid_argument("invalid service --type");
        result=ApplyServiceStartType(name,choice);
    }
    const auto after=QuerySingleService(name); bool verified=after.success && !after.entries.empty();
    if(verified) {
        const auto& observed=after.entries.front();
        verified=expectedState ? observed.hasStatus && observed.currentState==expectedState : observed.hasConfig && observed.startType==expectedType &&
            (expectedType!=SERVICE_AUTO_START || (observed.hasDelayedAutoStart && observed.delayedAutoStart==expectedDelayed));
    }
    const int code=result.partial ? 6 : !result.success ? failure(result.win32Error) : verified ? 0 : 6;
    return {code,Json::object({{L"name",Json::string(name)}, {L"operation",Json::string(operation)}, {L"requestSucceeded",Json::boolean(result.success)},
        {L"win32Error",Json::number(result.win32Error)}, {L"verified",Json::boolean(verified)}, {L"postcheckWin32Error",Json::number(after.win32Error)},
        {L"postcheck",after.entries.empty() ? Json{} : row(after.entries.front())}}), result.message.empty() ? std::vector<std::wstring>{} : std::vector<std::wstring>{result.message}};
}
}
void registerService() {
    addFamily(L"service",L"Read SCM service/driver configuration and control service transitions through R3.");
    addCommand({L"service enum",L"KswordCLI.exe service enum [--name NAME] [--limit N] [--backend r3] [--json]",L"Enumerate Win32 and driver services.",L"Optional: --name exact SCM name, --limit (default 100), --backend r3, --json.",L"No driver required. Missing status/config fields are null; per-service diagnostics remain visible.",enumerate});
    addCommand({L"service query",L"KswordCLI.exe service query --name NAME [--backend r3] [--json]",L"Query one service's status and configuration.",L"Required: --name. Optional: --backend r3, --json.",L"Uses the short SCM service name, not display name. Unknown delayed-auto configuration is null.",[](const Args& args){return query(args,false);}});
    addCommand({L"service detail query",L"KswordCLI.exe service detail query --name NAME [--backend r3] [--json]",L"Read recovery actions and direct reverse dependencies.",L"Required: --name. Optional: --backend r3, --json.",L"Optional sections keep independent availability and raw Win32 status. No inferred transitive dependencies.",[](const Args& args){return query(args,true);}});
    for(const auto* operation:{L"start",L"stop",L"pause",L"continue",L"set-start-type"}) {
        const std::wstring word=operation;
        const bool confirm=word==L"stop" || word==L"set-start-type";
        addCommand({L"service "+word,L"KswordCLI.exe service "+word+L" --name NAME"+(word==L"set-start-type" ? L" --type automatic|delayed|manual|disabled" : L"")+(confirm ? L" --confirm" : L"")+L" [--backend r3] [--json]",
            L"Apply "+word+L" and verify the resulting SCM state.",L"Required: --name."+std::wstring(confirm ? L" --confirm." : L"")+(word==L"set-start-type" ? L" --type." : L"")+L" Optional: --backend r3, --json.",
            L"Administrator/access rights required. State transitions wait up to 30 seconds. Partial configuration or unconfirmed readback returns 6; actual errors are preserved.", [word](const Args& args){return action(args,word);}});
    }
}
}
