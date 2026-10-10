#include "R3StartupShared.h"
#include <sddl.h>
#include <algorithm>
#include <sstream>
#include <stdexcept>
namespace ks::cli::startup {
using namespace ks::r3::startup;
Identity identity() {
    Identity result;HANDLE token=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) {result.win32Error=GetLastError();return result;}
    struct Owner {HANDLE value;~Owner(){CloseHandle(value);}} owner{token};
    DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);
    std::vector<std::uint8_t> buffer(size);
    if(!GetTokenInformation(token,TokenUser,buffer.data(),size,&size)) {result.win32Error=GetLastError();return result;}
    wchar_t* sid=nullptr;
    if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid,&sid)) {result.win32Error=GetLastError();return result;}
    result.sid=sid;LocalFree(sid);return result;
}
const wchar_t* kind(StartupEntryKind value) {
    switch(value) {case StartupEntryKind::RegistryRun:return L"run";case StartupEntryKind::RegistryRunOnce:return L"run-once";
    case StartupEntryKind::StartupFolder:return L"folder";case StartupEntryKind::Service:return L"service";case StartupEntryKind::DriverService:return L"driver";
    case StartupEntryKind::RegistryOnlyService:return L"registry-only-service";default:return L"task";}
}
const wchar_t* state(StartupEntryState value) {
    switch(value) {case StartupEntryState::Active:return L"active";case StartupEntryState::Disabled:return L"disabled";case StartupEntryState::Manual:return L"manual";default:return L"unknown";}
}
const wchar_t* scope(StartupEntryScope value) {
    switch(value) {case StartupEntryScope::CurrentUser:return L"user";case StartupEntryScope::LocalMachine:return L"machine";case StartupEntryScope::AllUsers:return L"all-users";default:return L"unknown";}
}
std::wstring id(const StartupEntry& entry,const std::wstring& sid) {
    std::uint64_t hash=14695981039346656037ULL;
    const auto add=[&](const std::wstring& text) {for(const auto c:text) {hash^=static_cast<std::uint16_t>(c)&255;hash*=1099511628211ULL;hash^=static_cast<std::uint16_t>(c)>>8;hash*=1099511628211ULL;}hash^=0;hash*=1099511628211ULL;};
    add(sid);add(kind(entry.kind));add(scope(entry.scope));add(entry.registryRoot==HKEY_CURRENT_USER ? L"HKCU" : entry.registryRoot==HKEY_LOCAL_MACHINE ? L"HKLM" : L"");
    add(std::to_wstring(entry.registryView));add(entry.registrySubKey);add(entry.registryValueName);add(entry.filePath);add(entry.serviceName);add(entry.taskPath);
    return Json::hex(hash).display;
}
Json errors(const StartupEnumerationResult& snapshot) {
    std::vector<Json> rows;
    for(const auto& error:snapshot.sourceErrors) rows.push_back(Json::object({{L"source",Json::string(error.source)},
        {L"errorKind",Json::string(error.hresult ? L"hresult" : L"win32")}, {L"code",error.code ? Json::number(error.code) : Json{}}}));
    return Json::array(rows);
}
Json row(const StartupEntry& entry,const std::wstring& sid) {
    std::vector<Json> properties;for(const auto& property:entry.properties) properties.push_back(Json::object({{L"name",Json::string(property.name)}, {L"value",Json::string(property.value)}}));
    const bool readOnly=entry.kind==StartupEntryKind::DriverService || entry.kind==StartupEntryKind::RegistryOnlyService;
    return Json::object({{L"id",sid.empty() ? Json{} : Json::string(id(entry,sid))}, {L"kind",Json::string(kind(entry.kind))}, {L"scope",Json::string(scope(entry.scope))},
        {L"state",Json::string(state(entry.state))}, {L"name",Json::string(entry.name)}, {L"command",Json::string(entry.command)}, {L"location",Json::string(entry.location)},
        {L"description",Json::string(entry.description)}, {L"publisher",Json::string(entry.publisher)}, {L"readOnly",Json::boolean(readOnly)},
        {L"registryRoot",entry.registryRoot ? Json::string(entry.registryRoot==HKEY_CURRENT_USER ? L"HKCU" : L"HKLM") : Json{}},
        {L"registryView",entry.registryRoot ? Json::number(entry.registryView) : Json{}}, {L"registrySubKey",Json::string(entry.registrySubKey)},
        {L"registryValueName",Json::string(entry.registryValueName)}, {L"disabledRegistrySubKey",Json::string(entry.disabledRegistrySubKey)},
        {L"filePath",Json::string(entry.filePath)}, {L"disabledFilePath",Json::string(entry.disabledFilePath)}, {L"serviceName",Json::string(entry.serviceName)},
        {L"serviceStartType",!entry.serviceName.empty() && entry.state!=StartupEntryState::Unknown ? Json::number(entry.serviceStartType) : Json{}},
        {L"taskPath",Json::string(entry.taskPath)}, {L"properties",Json::array(properties)}});
}
}
namespace ks::cli {
void registerStartupEnumeration() {
    addFamily(L"startup",L"Inspect Run/RunOnce, startup folders, services and Task Scheduler file-store entries through R3.");
    addCommand({L"startup enum",L"KswordCLI.exe startup enum [--kind all|run|run-once|folder|service|driver|registry-only-service|task] [--scope all|user|machine|all-users|unknown] [--name NAME] [--limit N] [--backend r3] [--json]",
        L"Enumerate startup registration surfaces and retained disabled entries.",L"Optional: --kind, --scope (default all), --name exact name, --limit (default 100), --backend r3, --json.",
        L"No driver. Task file-store state is unknown; driver and registry-only service rows are read-only observations. IDs are stable within the caller SID and entry identity, excluding active/disabled state. Data: userSid, identityWin32Error, complete, sourceErrors, counts, entries.",
        [](const Args& args) {
            const auto kind=args.get(L"--kind",L"all"),scope=args.get(L"--scope",L"all");const auto limit=args.u32(L"--limit",100);
            const std::vector<std::wstring> kinds{L"all",L"run",L"run-once",L"folder",L"service",L"driver",L"registry-only-service",L"task"};
            const std::vector<std::wstring> scopes{L"all",L"user",L"machine",L"all-users",L"unknown"};
            if(std::find(kinds.begin(),kinds.end(),kind)==kinds.end() || std::find(scopes.begin(),scopes.end(),scope)==scopes.end()) throw std::invalid_argument("invalid startup kind or scope");
            const auto identity=startup::identity();const auto snapshot=ks::r3::startup::EnumerateStartupEntries();std::vector<Json> rows;std::uint32_t matched=0;
            for(const auto& entry:snapshot.entries) {
                if((kind!=L"all" && kind!=startup::kind(entry.kind)) || (scope!=L"all" && scope!=startup::scope(entry.scope)) || (args.has(L"--name") && entry.name!=args.get(L"--name"))) continue;
                ++matched;if(rows.size()<limit) rows.push_back(startup::row(entry,identity.sid));
            }
            const bool complete=snapshot.sourceErrors.empty() && identity.win32Error==0;
            return Result{snapshot.success ? (complete ? 0 : 6) : 3,Json::object({{L"userSid",Json::string(identity.sid)}, {L"identityWin32Error",Json::number(identity.win32Error)},
                {L"complete",Json::boolean(complete)}, {L"sourceErrors",startup::errors(snapshot)}, {L"matchedCount",Json::number(matched)},
                {L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))}, {L"displayTruncated",Json::boolean(rows.size()<matched)}, {L"entries",Json::array(rows)}}),
                snapshot.diagnosticText.empty() ? std::vector<std::wstring>{} : std::vector<std::wstring>{snapshot.diagnosticText}};
        }});
}
}
