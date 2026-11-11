#include "CommandRegistry.h"
#include "../shared/usermode/backend/service/ServiceEnumerator.h"
#include "../shared/usermode/backend/service/ServiceActions.h"
#include "../Ksword5.1/Ksword5.1/ksword/service/service.h"
#include "../shared/usermode/KswordArkServiceMode.h"
#include <algorithm>
#include <limits>
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

// SCM permits partial updates. Each write and the subsequent readback is kept
// separate so a description failure cannot hide an earlier config change.
struct Secret {
    std::vector<std::uint8_t> bytes;
    std::wstring value;
    ~Secret() {
        if (!bytes.empty()) ::SecureZeroMemory(bytes.data(), bytes.size());
        if (!value.empty()) ::SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
    }
};
std::wstring dependenciesMultiSz(const std::wstring& input) {
    std::wstring result;
    if (!input.empty()) {
        std::size_t begin=0;
        while (begin<input.size()) {
            const auto end=input.find(L';',begin);
            const auto item=input.substr(begin,end==std::wstring::npos?std::wstring::npos:end-begin);
            if (item.empty()) throw std::invalid_argument("empty dependency entry");
            result+=item; result.push_back(L'\0');
            if (end==std::wstring::npos) break;
            begin=end+1;
            if (begin==input.size()) throw std::invalid_argument("empty dependency entry");
        }
    }
    result.push_back(L'\0');
    if (result.size()==1) result.push_back(L'\0');
    return result;
}
Result configSet(const Args& args) {
    const auto name=args.require(L"--name");
    if (!args.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
    ks::service::ServiceConfigUpdate update{};
    update.changeServiceType=args.has(L"--service-type"); if(update.changeServiceType) update.serviceType=args.u32(L"--service-type");
    update.changeStartType=args.has(L"--start-type"); if(update.changeStartType) update.startType=args.u32(L"--start-type");
    update.changeErrorControl=args.has(L"--error-control"); if(update.changeErrorControl) update.errorControl=args.u32(L"--error-control");
    update.changeBinaryPath=args.has(L"--binary-path"); if(update.changeBinaryPath) update.binaryPath=args.require(L"--binary-path");
    update.changeLoadOrderGroup=args.has(L"--load-order-group"); if(update.changeLoadOrderGroup) update.loadOrderGroup=args.get(L"--load-order-group");
    if(args.has(L"--clear-dependencies") && (args.u32(L"--clear-dependencies")!=1 || args.has(L"--dependencies"))) throw std::invalid_argument("--clear-dependencies requires 1 and cannot be combined with --dependencies");
    update.changeDependencies=args.has(L"--dependencies")||args.has(L"--clear-dependencies"); if(update.changeDependencies) update.dependenciesMultiSz=dependenciesMultiSz(args.get(L"--dependencies"));
    update.changeAccount=args.has(L"--account"); if(update.changeAccount) update.accountName=args.require(L"--account");
    update.changeDisplayName=args.has(L"--display-name"); if(update.changeDisplayName) update.displayName=args.require(L"--display-name");
    if(args.has(L"--clear-description") && (args.u32(L"--clear-description")!=1 || args.has(L"--description"))) throw std::invalid_argument("--clear-description requires 1 and cannot be combined with --description");
    const bool description=args.has(L"--description")||args.has(L"--clear-description"), delayed=args.has(L"--delayed-auto");
    const auto delayedValue=args.u32(L"--delayed-auto",0); if(delayed && delayedValue>1) throw std::invalid_argument("--delayed-auto must be 0 or 1");
    Secret secret;
    if(args.has(L"--password-file")) {
        if(!update.changeAccount) throw std::invalid_argument("--password-file requires --account");
        auto payload=readPayloadFile(args.require(L"--password-file"));
        secret.bytes=std::move(payload.bytes);
        if(payload.win32Error) return {3,Json::object({{L"name",Json::string(name)},{L"win32Error",Json::number(payload.win32Error)}}),{L"Password file could not be read; no service change was attempted."}};
        if(secret.bytes.size()>4096 || std::find(secret.bytes.begin(),secret.bytes.end(),0)!=secret.bytes.end()) throw std::invalid_argument("password file must contain at most 4096 bytes of UTF-8 without NUL");
        if(!secret.bytes.empty()) {
            const int count=::MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,reinterpret_cast<const char*>(secret.bytes.data()),static_cast<int>(secret.bytes.size()),nullptr,0);
            if(count<=0) throw std::invalid_argument("password file is not UTF-8");
            secret.value.resize(static_cast<std::size_t>(count));
            if(::MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,reinterpret_cast<const char*>(secret.bytes.data()),static_cast<int>(secret.bytes.size()),secret.value.data(),count)!=count) throw std::invalid_argument("password file is not UTF-8");
        }
        update.changePassword=true; update.password=secret.value;
    }
    const bool primary=update.changeServiceType||update.changeStartType||update.changeErrorControl||update.changeBinaryPath||update.changeLoadOrderGroup||update.changeDependencies||update.changeAccount||update.changeDisplayName;
    if(!primary&&!description&&!delayed) throw std::invalid_argument("specify at least one service setting");
    std::string error; std::uint32_t win32=0; bool primaryOk=!primary,descriptionOk=!description,delayedOk=!delayed,anyApplied=false;
    if(primary) {primaryOk=ks::service::ChangeServiceConfiguration(name,update,&error,&win32); anyApplied=primaryOk;}
    if(!update.password.empty()) ::SecureZeroMemory(update.password.data(),update.password.size()*sizeof(wchar_t));
    if(primaryOk && description) {descriptionOk=ks::service::SetServiceDescription(name,args.get(L"--description"),&error,&win32); anyApplied|=descriptionOk;}
    if(primaryOk && descriptionOk && delayed) {delayedOk=ks::service::SetDelayedAutoStart(name,delayedValue!=0,&error,&win32); anyApplied|=delayedOk;}
    ks::service::ServiceRecord after{}; std::string readError; std::uint32_t readWin32=0;
    const bool readOk=ks::service::QueryServiceRecord(name,&after,&readError,&readWin32);
    bool verified=readOk && after.hasConfig;
    if(verified && update.changeServiceType) verified=after.config.serviceType==update.serviceType;
    if(verified && update.changeStartType) verified=after.config.startType==update.startType;
    if(verified && update.changeErrorControl) verified=after.config.errorControl==update.errorControl;
    if(verified && update.changeBinaryPath) verified=after.config.binaryPath==update.binaryPath;
    if(verified && update.changeLoadOrderGroup) verified=after.config.loadOrderGroup==update.loadOrderGroup;
    if(verified && update.changeDependencies) verified=after.config.dependenciesMultiSz==(args.get(L"--dependencies").empty()?std::wstring{}:update.dependenciesMultiSz);
    if(verified && update.changeAccount) verified=::CompareStringOrdinal(after.config.accountName.c_str(),-1,update.accountName.c_str(),-1,TRUE)==CSTR_EQUAL;
    if(verified && update.changeDisplayName) verified=after.config.displayName==update.displayName;
    if(verified && description) verified=after.hasDescription && after.description==args.get(L"--description");
    if(verified && delayed) verified=after.config.hasDelayedAutoStart && after.config.delayedAutoStart==(delayedValue!=0);
    // Windows never returns an account password; a successful write is not a verified password.
    if(update.changePassword) verified=false;
    const bool written=primaryOk&&descriptionOk&&delayedOk;
    const int code=!written ? (anyApplied?6:failure(win32)) : verified?0:6;
    return {code,Json::object({{L"name",Json::string(name)},{L"requestSucceeded",Json::boolean(written)},
        {L"primaryAttempted",Json::boolean(primary)},{L"primarySucceeded",Json::boolean(primaryOk)},
        {L"descriptionSucceeded",description?Json::boolean(descriptionOk):Json{}},{L"delayedSucceeded",delayed?Json::boolean(delayedOk):Json{}},
        {L"passwordWritten",update.changePassword?Json::boolean(primaryOk):Json{}},{L"passwordVerified",Json{}},
        {L"win32Error",Json::number(win32)},{L"readbackWin32Error",Json::number(readWin32)},{L"verified",Json::boolean(verified)}}),
        {L"SCM settings are separate writes; partial success is not rolled back. Passwords cannot be read back."}};
}
Result recoverySet(const Args& args) {
    const auto name=args.require(L"--name");
    if(!args.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
    for(const auto& pair: {std::pair{L"--clear-actions",L"--actions"},std::pair{L"--clear-command",L"--command"},std::pair{L"--clear-reboot-message",L"--reboot-message"}})
        if(args.has(pair.first) && (args.u32(pair.first)!=1 || args.has(pair.second))) throw std::invalid_argument("clear option requires 1 and cannot be combined with its value option");
    if(!args.has(L"--reset-seconds")&&!args.has(L"--actions")&&!args.has(L"--clear-actions")&&!args.has(L"--command")&&!args.has(L"--clear-command")&&!args.has(L"--reboot-message")&&!args.has(L"--clear-reboot-message")&&!args.has(L"--non-crash"))
        throw std::invalid_argument("specify at least one recovery setting");
    ks::service::FailureSettings desired{}; std::string error; std::uint32_t win32=0;
    if(!ks::service::QueryServiceFailureSettings(name,&desired,&error,&win32))
        return {failure(win32),Json::object({{L"name",Json::string(name)},{L"win32Error",Json::number(win32)}}),{L"Existing recovery settings could not be read; no write was attempted."}};
    if(!desired.hasFailureActions || !desired.hasFailureActionsFlag)
        return {5,Json::object({{L"name",Json::string(name)}}),{L"Existing recovery settings are incomplete; no write was attempted."}};
    if(args.has(L"--reset-seconds")) desired.resetPeriodSeconds=args.u32(L"--reset-seconds");
    if(args.has(L"--command")) desired.command=args.get(L"--command");
    if(args.has(L"--clear-command")) desired.command.clear();
    if(args.has(L"--reboot-message")) desired.rebootMessage=args.get(L"--reboot-message");
    if(args.has(L"--clear-reboot-message")) desired.rebootMessage.clear();
    if(args.has(L"--non-crash")) {const auto n=args.u32(L"--non-crash");if(n>1)throw std::invalid_argument("--non-crash must be 0 or 1");desired.failureActionsOnNonCrash=n!=0;}
    if(args.has(L"--clear-actions")) desired.actions.clear();
    if(args.has(L"--actions")) {
        const auto text=args.get(L"--actions");desired.actions.clear();std::size_t begin=0;
        while(begin<text.size()) {
            const auto end=text.find(L',',begin);const auto item=text.substr(begin,end==std::wstring::npos?std::wstring::npos:end-begin);
            const auto colon=item.find(L':');if(colon==std::wstring::npos || !colon || colon+1>=item.size()) throw std::invalid_argument("--actions requires type:delay-ms entries");
            const auto kind=item.substr(0,colon);std::uint32_t type=0;
            if(kind==L"none") type=SC_ACTION_NONE;else if(kind==L"restart") type=SC_ACTION_RESTART;else if(kind==L"reboot") type=SC_ACTION_REBOOT;else if(kind==L"run") type=SC_ACTION_RUN_COMMAND;else throw std::invalid_argument("invalid recovery action");
            Args number;number.values[L"--delay"]=item.substr(colon+1);desired.actions.push_back({type,number.u32(L"--delay")});
            if(desired.actions.size()>32) throw std::invalid_argument("at most 32 recovery actions");
            if(end==std::wstring::npos) break;begin=end+1;if(begin==text.size())throw std::invalid_argument("empty recovery action");
        }
    }
    const bool ok=ks::service::ApplyServiceFailureSettings(name,desired,&error,&win32);
    ks::service::FailureSettings after{};std::string readError;std::uint32_t readWin32=0;
    const bool readOk=ks::service::QueryServiceFailureSettings(name,&after,&readError,&readWin32);
    // SCM normalizes the reset period to zero after the final recovery action is cleared.
    const bool resetMatches=after.resetPeriodSeconds==desired.resetPeriodSeconds || (desired.actions.empty()&&!args.has(L"--reset-seconds"));
    bool verified=readOk&&after.hasFailureActions&&after.hasFailureActionsFlag&&resetMatches&&
        after.command==desired.command&&after.rebootMessage==desired.rebootMessage&&after.failureActionsOnNonCrash==desired.failureActionsOnNonCrash&&after.actions.size()==desired.actions.size();
    if(verified) for(std::size_t i=0;i<after.actions.size();++i) if(after.actions[i].type!=desired.actions[i].type||after.actions[i].delayMs!=desired.actions[i].delayMs){verified=false;break;}
    std::vector<Json> readActions;for(const auto& action:after.actions)readActions.push_back(Json::object({{L"type",Json::number(action.type)},{L"delayMs",Json::number(action.delayMs)}}));
    return {ok&&verified?0:6,Json::object({{L"name",Json::string(name)},{L"requestSucceeded",Json::boolean(ok)},
        {L"win32Error",Json::number(win32)},{L"readbackWin32Error",Json::number(readWin32)},{L"verified",Json::boolean(verified)},
        {L"readback",readOk?Json::object({{L"actionsAvailable",Json::boolean(after.hasFailureActions)},{L"nonCrashAvailable",Json::boolean(after.hasFailureActionsFlag)},
            {L"resetSeconds",Json::number(after.resetPeriodSeconds)},{L"command",Json::string(after.command)},{L"rebootMessage",Json::string(after.rebootMessage)},
            {L"nonCrash",Json::boolean(after.failureActionsOnNonCrash)},{L"actions",Json::array(readActions)}}):Json{}}}),
        {L"SCM recovery actions and the non-crash flag are separate writes; a failure may leave a partial update."}};
}

struct FileHandle {
    HANDLE value=INVALID_HANDLE_VALUE;
    ~FileHandle(){if(value!=INVALID_HANDLE_VALUE) ::CloseHandle(value);}
};
struct RegistryKey {
    HKEY value=nullptr;
    ~RegistryKey(){if(value) ::RegCloseKey(value);}
};
std::wstring serviceFilePath(const std::wstring& text) {
    if(text.empty()) return {};
    const std::wstring path=ResolveServiceImagePathForBrowser(text);
    if(path.empty()) return {};
    const bool driveAbsolute=path.size()>=3 && ((path[0]>=L'A'&&path[0]<=L'Z')||(path[0]>=L'a'&&path[0]<=L'z')) &&
        path[1]==L':' && (path[2]==L'\\'||path[2]==L'/');
    if(!driveAbsolute && !(path.size()>=2 && path[0]==L'\\' && path[1]==L'\\')) return {};
    const DWORD needed=::GetFullPathNameW(path.c_str(),0,nullptr,nullptr);
    if(!needed || needed>32768) return {};
    std::wstring full(needed,L'\0');const DWORD written=::GetFullPathNameW(path.c_str(),needed,full.data(),nullptr);
    if(!written || written>=needed) return {};
    full.resize(written);return full;
}
bool samePath(const std::wstring& a,const std::wstring& b) {
    return ::CompareStringOrdinal(a.c_str(),-1,b.c_str(),-1,TRUE)==CSTR_EQUAL;
}
// Missing registry values are normal; inaccessible or malformed ones make the
// reference scan incomplete and prevent the combined deletion.
bool readRegistryText(HKEY key,const wchar_t* subkey,const wchar_t* value,std::wstring& output,DWORD& error) {
    DWORD bytes=0;error=::RegGetValueW(key,subkey,value,RRF_RT_REG_SZ|RRF_RT_REG_EXPAND_SZ,nullptr,nullptr,&bytes);
    if(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND){output.clear();error=ERROR_SUCCESS;return true;}
    if(error!=ERROR_SUCCESS || bytes>65536 || bytes%sizeof(wchar_t)) return false;
    std::vector<wchar_t> data(bytes/sizeof(wchar_t)+1,L'\0');
    error=::RegGetValueW(key,subkey,value,RRF_RT_REG_SZ|RRF_RT_REG_EXPAND_SZ,nullptr,data.data(),&bytes);
    if(error!=ERROR_SUCCESS) return false;
    output.assign(data.data());return true;
}
bool queryServiceDll(const std::wstring& name,std::wstring& output,DWORD& error) {
    RegistryKey root;error=::RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services",0,KEY_READ,&root.value);
    if(error!=ERROR_SUCCESS)return false;
    return readRegistryText(root.value,(name+L"\\Parameters").c_str(),L"ServiceDll",output,error);
}
struct RegistryServiceSnapshot { DWORD type=0;std::wstring image,dll; };
bool queryRegistryService(const std::wstring& name,RegistryServiceSnapshot& output,DWORD& error) {
    RegistryKey root;error=::RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services",0,KEY_READ,&root.value);
    if(error!=ERROR_SUCCESS)return false;
    RegistryKey key;error=::RegOpenKeyExW(root.value,name.c_str(),0,KEY_READ,&key.value);if(error!=ERROR_SUCCESS)return false;
    DWORD bytes=sizeof(output.type);
    error=::RegGetValueW(key.value,nullptr,L"Type",RRF_RT_REG_DWORD,nullptr,&output.type,&bytes);
    if(error==ERROR_FILE_NOT_FOUND){error=ERROR_SUCCESS;output.type=0;}else if(error!=ERROR_SUCCESS)return false;
    return readRegistryText(key.value,nullptr,L"ImagePath",output.image,error)&&readRegistryText(key.value,L"Parameters",L"ServiceDll",output.dll,error);
}
bool isOtherReference(const std::wstring& text,const std::wstring& target,const BY_HANDLE_FILE_INFORMATION& targetId,DWORD& error) {
    error=ERROR_SUCCESS;
    const auto path=serviceFilePath(text);if(path.empty())return false;
    if(samePath(path,target))return true;
    FileHandle candidate;candidate.value=::CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(candidate.value==INVALID_HANDLE_VALUE){
        error=::GetLastError();
        if(error==ERROR_FILE_NOT_FOUND||error==ERROR_PATH_NOT_FOUND||error==ERROR_INVALID_NAME)error=ERROR_SUCCESS;
        return false;
    }
    BY_HANDLE_FILE_INFORMATION id{};
    if(!::GetFileInformationByHandle(candidate.value,&id)){error=::GetLastError();return false;}
    return id.dwVolumeSerialNumber==targetId.dwVolumeSerialNumber &&
        id.nFileIndexHigh==targetId.nFileIndexHigh && id.nFileIndexLow==targetId.nFileIndexLow;
}
bool scanServiceFileReferences(const std::wstring& targetName,const std::wstring& targetPath,
    const BY_HANDLE_FILE_INFORMATION& targetId,std::wstring& other,DWORD& error) {
    RegistryKey root;error=::RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services",0,KEY_ENUMERATE_SUB_KEYS,&root.value);
    if(error!=ERROR_SUCCESS)return false;
    for(DWORD index=0;;++index) {
        wchar_t child[256]{};DWORD count=static_cast<DWORD>(std::size(child));
        error=::RegEnumKeyExW(root.value,index,child,&count,nullptr,nullptr,nullptr,nullptr);
        if(error==ERROR_NO_MORE_ITEMS){error=ERROR_SUCCESS;break;}if(error!=ERROR_SUCCESS)return false;
        const std::wstring name(child,count);if(samePath(name,targetName))continue;
        RegistryKey key;error=::RegOpenKeyExW(root.value,name.c_str(),0,KEY_QUERY_VALUE,&key.value);if(error!=ERROR_SUCCESS)return false;
        std::wstring image,dll;
        if(!readRegistryText(key.value,nullptr,L"ImagePath",image,error)||!readRegistryText(key.value,L"Parameters",L"ServiceDll",dll,error))return false;
        if(isOtherReference(image,targetPath,targetId,error)){other=name;error=ERROR_SHARING_VIOLATION;return false;}if(error!=ERROR_SUCCESS)return false;
        if(isOtherReference(dll,targetPath,targetId,error)){other=name;error=ERROR_SHARING_VIOLATION;return false;}if(error!=ERROR_SUCCESS)return false;
    }
    std::vector<ks::service::ServiceRecord> services;std::string message;std::uint32_t nativeError=0;
    if(!ks::service::EnumerateServiceRecords(SERVICE_TYPE_ALL,SERVICE_STATE_ALL,&services,&message,&nativeError)){error=nativeError;return false;}
    for(const auto& service:services) {
        if(samePath(service.serviceName,targetName)||!service.hasConfig)continue;
        if(isOtherReference(service.config.binaryPath,targetPath,targetId,error)){other=service.serviceName;error=ERROR_SHARING_VIOLATION;return false;}if(error!=ERROR_SUCCESS)return false;
    }
    return true;
}
Result deleteService(const Args& args) {
    const auto name=args.require(L"--name");if(!args.has(L"--confirm"))throw std::invalid_argument("missing option --confirm");
    if(name.find_first_of(L"\\/")!=std::wstring::npos)throw std::invalid_argument("service name cannot contain a path separator");
    const auto removeFile=args.u32(L"--delete-file",0);if(removeFile>1)throw std::invalid_argument("--delete-file must be 0 or 1");
    if(removeFile && !args.has(L"--expected-file"))throw std::invalid_argument("--expected-file is required when --delete-file is 1");
    if(!removeFile && args.has(L"--expected-file"))throw std::invalid_argument("--expected-file requires --delete-file 1");
    ks::service::ServiceRecord before{};std::string message;std::uint32_t win32=0;DWORD scanError=0;
    const bool scmPresent=ks::service::QueryServiceRecord(name,&before,&message,&win32);
    RegistryServiceSnapshot registryBefore{};
    if(!scmPresent) {
        if(win32!=ERROR_SERVICE_DOES_NOT_EXIST || !queryRegistryService(name,registryBefore,scanError))
            return {failure(win32),Json::object({{L"name",Json::string(name)},{L"win32Error",Json::number(win32)},{L"registryWin32Error",Json::number(scanError)}}),{L"Neither an SCM service nor a verified registry-only service was available; no deletion was attempted."}};
        if(ksword::ark::isKswordArkService(name) && !ksword::ark::queryServiceProfile().scmManagementAllowed())
            return {3,Json::object({{L"name",Json::string(name)}}),{L"KswordARK is protected by its active or unknown PnP service profile."}};
        before.config.serviceType=registryBefore.type;before.config.binaryPath=registryBefore.image;before.status.currentState=SERVICE_STOPPED;
    }
    std::wstring filePath,other;FileHandle file;BY_HANDLE_FILE_INFORMATION fileId{};
    if(removeFile) {
        std::wstring raw=before.config.binaryPath;
        if(!scmPresent && (before.config.serviceType&SERVICE_WIN32_SHARE_PROCESS)!=0) raw=registryBefore.dll;
        else if((before.config.serviceType&SERVICE_WIN32_SHARE_PROCESS)!=0) {
            if(!queryServiceDll(name,raw,scanError))return {3,Json::object({{L"name",Json::string(name)},{L"win32Error",Json::number(scanError)}}),{L"The service DLL path could not be verified; nothing was deleted."}};
        }
        filePath=serviceFilePath(raw);const auto expected=serviceFilePath(args.require(L"--expected-file"));
        if(filePath.empty()||expected.empty()||!samePath(filePath,expected))return {3,Json::object({{L"name",Json::string(name)},{L"file",Json::string(filePath)}}),{L"The expected file does not match the current service image; nothing was deleted."}};
        file.value=::CreateFileW(filePath.c_str(),DELETE|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(file.value==INVALID_HANDLE_VALUE){const DWORD error=::GetLastError();return {failure(error),Json::object({{L"name",Json::string(name)},{L"file",Json::string(filePath)},{L"win32Error",Json::number(error)}}),{L"Could not open the service file for identity-checked deletion."}};}
        if(!::GetFileInformationByHandle(file.value,&fileId) || (fileId.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))!=0)
            return {3,Json::object({{L"name",Json::string(name)},{L"file",Json::string(filePath)}}),{L"The target is not a verified ordinary file; nothing was deleted."}};
        if(!scanServiceFileReferences(name,filePath,fileId,other,scanError))return {3,Json::object({{L"name",Json::string(name)},{L"file",Json::string(filePath)},{L"otherService",other.empty()?Json{}:Json::string(other)},{L"win32Error",Json::number(scanError)}}),{L"Another service references this file or the reference scan was incomplete; nothing was deleted."}};
        if(scmPresent && before.status.currentState!=SERVICE_STOPPED) {
            ks::service::ServiceStatus status{};
            if(!ks::service::StopServiceByName(name,10000,SERVICE_STOPPED,&status,&message,&win32)||status.currentState!=SERVICE_STOPPED)
                return {3,Json::object({{L"name",Json::string(name)},{L"win32Error",Json::number(win32)}}),{L"The service was not confirmed stopped; neither registration nor file was deleted."}};
        }
        ks::service::ServiceRecord current{};std::wstring liveRaw;
        if(scmPresent) {
            if(!ks::service::QueryServiceRecord(name,&current,&message,&win32)||!current.hasConfig||!current.hasStatus||current.status.currentState!=SERVICE_STOPPED||current.config.serviceType!=before.config.serviceType)
                return {3,Json::object({{L"name",Json::string(name)},{L"win32Error",Json::number(win32)}}),{L"The service changed or could not be revalidated after stopping; nothing was deleted."}};
            liveRaw=current.config.binaryPath;
            if((current.config.serviceType&SERVICE_WIN32_SHARE_PROCESS)!=0 && !queryServiceDll(name,liveRaw,scanError))return {3,Json::object({{L"name",Json::string(name)},{L"win32Error",Json::number(scanError)}}),{L"The service DLL could not be revalidated; nothing was deleted."}};
        } else {
            RegistryServiceSnapshot currentRegistry{};
            if(!queryRegistryService(name,currentRegistry,scanError)||currentRegistry.type!=registryBefore.type)
                return {3,Json::object({{L"name",Json::string(name)},{L"win32Error",Json::number(scanError)}}),{L"The registry-only service could not be revalidated; nothing was deleted."}};
            liveRaw=(currentRegistry.type&SERVICE_WIN32_SHARE_PROCESS)!=0?currentRegistry.dll:currentRegistry.image;
        }
        if(!samePath(serviceFilePath(liveRaw),filePath)||!scanServiceFileReferences(name,filePath,fileId,other,scanError))
            return {3,Json::object({{L"name",Json::string(name)},{L"win32Error",Json::number(scanError)}}),{L"The image path or file references changed; nothing was deleted."}};
    }
    bool registration=false;
    if(scmPresent) registration=ks::service::DeleteServiceByName(name,!removeFile,10000,&message,&win32);
    else {
        // Do not delete a registry key if the SCM service appeared after the first check.
        ks::service::ServiceRecord current{};
        if(ks::service::QueryServiceRecord(name,&current,&message,&win32)||win32!=ERROR_SERVICE_DOES_NOT_EXIST)
            return {3,Json::object({{L"name",Json::string(name)},{L"win32Error",Json::number(win32)}}),{L"SCM absence could not be revalidated; nothing was deleted."}};
        RegistryKey root;win32=::RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services",0,DELETE|KEY_ENUMERATE_SUB_KEYS|KEY_QUERY_VALUE|KEY_SET_VALUE,&root.value);
        if(win32==ERROR_SUCCESS)win32=::RegDeleteTreeW(root.value,name.c_str());
        registration=win32==ERROR_SUCCESS;
    }
    if(!registration)return {failure(win32),Json::object({{L"name",Json::string(name)},{L"registrationDeleteAccepted",Json::boolean(false)},{L"win32Error",Json::number(win32)}}),{L"Service deletion was rejected; no file deletion was attempted."}};
    bool fileAccepted=false;DWORD fileError=ERROR_SUCCESS;
    if(removeFile){FILE_DISPOSITION_INFO disposition{};disposition.DeleteFile=TRUE;fileAccepted=::SetFileInformationByHandle(file.value,FileDispositionInfo,&disposition,sizeof(disposition))!=FALSE;if(!fileAccepted)fileError=::GetLastError();}
    return {removeFile&&!fileAccepted?6:0,Json::object({{L"name",Json::string(name)},{L"registrationSource",Json::string(scmPresent?L"scm":L"registry-only")},{L"registrationDeleteAccepted",Json::boolean(true)},
        {L"file",removeFile?Json::string(filePath):Json{}},{L"fileDeleteAccepted",removeFile?Json::boolean(fileAccepted):Json{}},{L"fileWin32Error",Json::number(fileError)}}),
        {L"SCM deletion can remain pending until service handles close. File disposition is applied to the verified open handle; concurrent configuration changes remain possible."}};
}
}
void registerService() {
    addFamily(L"service",L"Read SCM service/driver configuration and control service transitions through R3.");
    addCommand({L"service enum",L"KswordCLI.exe service enum [--name NAME] [--limit N] [--backend r3] [--json]",L"Enumerate Win32 and driver services.",L"Optional: --name exact SCM name, --limit (default 100), --backend r3, --json.",L"No driver required. Missing status/config fields are null; per-service diagnostics remain visible.",enumerate});
    addCommand({L"service query",L"KswordCLI.exe service query --name NAME [--backend r3] [--json]",L"Query one service's status and configuration.",L"Required: --name. Optional: --backend r3, --json.",L"Uses the short SCM service name, not display name. Unknown delayed-auto configuration is null.",[](const Args& args){return query(args,false);}});
    addCommand({L"service detail query",L"KswordCLI.exe service detail query --name NAME [--backend r3] [--json]",L"Read recovery actions and direct reverse dependencies.",L"Required: --name. Optional: --backend r3, --json.",L"Optional sections keep independent availability and raw Win32 status. No inferred transitive dependencies.",[](const Args& args){return query(args,true);}});
    addCommand({L"service config set",L"KswordCLI.exe service config set --name NAME [--service-type N] [--start-type N] [--error-control N] [--binary-path PATH] [--load-order-group GROUP] [--dependencies LIST] [--clear-dependencies 1] [--account NAME] [--password-file PATH] [--display-name NAME] [--description TEXT] [--clear-description 1] [--delayed-auto 0|1] --confirm [--backend r3] [--json]",
        L"Apply selected SCM service settings and read them back.",L"Required: --name, --confirm and at least one setting. Dependencies are semicolon-separated; --clear-dependencies 1 and --clear-description 1 clear values. Password file is UTF-8 and requires --account.",
        L"SCM configuration, description and delayed-auto are separate writes; partial effects return 6. Password content is never returned and cannot be verified by readback. Native SCM constants are numeric. No automatic rollback.",configSet});
    addCommand({L"service recovery set",L"KswordCLI.exe service recovery set --name NAME [--reset-seconds N] [--actions LIST] [--clear-actions 1] [--command TEXT] [--clear-command 1] [--reboot-message TEXT] [--clear-reboot-message 1] [--non-crash 0|1] --confirm [--backend r3] [--json]",
        L"Update recovery actions and the non-crash failure flag.",L"Required: --name, --confirm and at least one setting. --actions is comma-separated none|restart|reboot|run:delay-ms. Clear options take 1 and cannot be combined with their value option.",
        L"Reads existing settings before applying omitted fields; SCM action settings and the non-crash flag are separate writes and partial failures return 6. Values are re-read and compared.",recoverySet});
    addCommand({L"service delete",L"KswordCLI.exe service delete --name NAME [--delete-file 0|1] [--expected-file PATH] --confirm [--backend r3] [--json]",
        L"Delete a service registration and optionally its verified service file.",L"Required: --name, --confirm. Optional: --delete-file 0|1 (0); --expected-file absolute PATH is required when deleting the file.",
        L"File deletion checks the service image, scans SCM and service-registry references, stops and rechecks the service, then marks the verified file handle for deletion. Shared files or incomplete scans are rejected. SCM/file deletion may remain pending; separate results are reported. No rollback.",deleteService});
    for(const auto* operation:{L"start",L"stop",L"pause",L"continue",L"set-start-type"}) {
        const std::wstring word=operation;
        const bool confirm=word==L"stop" || word==L"set-start-type";
        addCommand({L"service "+word,L"KswordCLI.exe service "+word+L" --name NAME"+(word==L"set-start-type" ? L" --type automatic|delayed|manual|disabled" : L"")+(confirm ? L" --confirm" : L"")+L" [--backend r3] [--json]",
            L"Apply "+word+L" and verify the resulting SCM state.",L"Required: --name."+std::wstring(confirm ? L" --confirm." : L"")+(word==L"set-start-type" ? L" --type." : L"")+L" Optional: --backend r3, --json.",
            L"Administrator/access rights required. State transitions wait up to 30 seconds. Partial configuration or unconfirmed readback returns 6; actual errors are preserved.", [word](const Args& args){return action(args,word);}});
    }
}
}
