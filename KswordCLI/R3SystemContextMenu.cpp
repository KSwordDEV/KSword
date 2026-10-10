#include "CommandRegistry.h"
#include "../shared/usermode/backend/system/ContextMenuScanner.h"
#include <algorithm>
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::system_tools;
bool equal(const std::wstring& a,const std::wstring& c){return _wcsicmp(a.c_str(),c.c_str())==0;}
std::wstring token(std::wstring path){std::replace(path.begin(),path.end(),L'\\',L'!');return path;}
bool matches(const b::ContextMenuEntry& e,const std::wstring& path){return equal(e.registrationPath,path)||(!e.enabled&&equal(e.backupKeyName,token(path)));}
Json entry(const b::ContextMenuEntry& e,bool& partial,bool& malformed){
    std::vector<std::pair<std::wstring,Json>> fields;for(const auto& [name,f]:e.fields){partial=partial||(!f.available&&!f.absent);malformed=malformed||f.malformed;
        fields.push_back({name,Json::object({{L"available",Json::boolean(f.available)},{L"absent",Json::boolean(f.absent)},{L"malformed",Json::boolean(f.malformed)},{L"limited",Json::boolean(f.limited)},
            {L"registryType",Json::number(f.type)},{L"win32Error",Json::number(static_cast<DWORD>(f.error))},{L"value",f.available?(f.numeric?Json::number(f.number):Json::string(f.text)):Json{}}})});}
    if(!e.moduleFile.empty()&&!e.modulePresenceKnown)partial=true;
    if(!e.enabled){for(const auto* name:{L"backupSource",L"backupKind"}){const auto f=e.fields.find(name);if(f==e.fields.end()||!f->second.available)partial=true;}}
    return Json::object({{L"registrationPath",Json::string(e.registrationPath)},{L"kind",Json::string(e.kind==b::ContextMenuKind::ShellVerb?L"verb":L"handler")},
        {L"scopeDisplay",Json::string(e.scopeText)},{L"name",Json::string(e.name)},{L"displayText",Json::string(e.displayText)},
        {L"enabledRegistration",Json::boolean(e.enabled)},{L"backupKeyName",e.backupKeyName.empty()?Json{}:Json::string(e.backupKeyName)},
        {L"clsidOrProgId",e.kind==b::ContextMenuKind::ShellExHandler&&!e.clsid.empty()?Json::string(e.clsid):Json{}},
        {L"modulePathOrCommand",e.modulePath.empty()?Json{}:Json::string(e.modulePath)},{L"moduleFileCandidate",e.moduleFile.empty()?Json{}:Json::string(e.moduleFile)},
        {L"candidateFileExists",e.modulePresenceKnown?Json::boolean(e.moduleExists):Json{}},{L"candidateAttributes",e.modulePresenceKnown&&e.moduleAttributes!=INVALID_FILE_ATTRIBUTES?Json::hex(e.moduleAttributes):Json{}},
        {L"candidateWin32Error",!e.moduleFile.empty()?Json::number(e.moduleWin32Error):Json{}},{L"fields",Json::object(fields)},{L"diagnosticDisplay",Json::string(e.diagnosticText)}});
}
Json sources(const b::ContextMenuScanResult& s,bool& partial,std::size_t& usable){std::vector<Json> rows;for(const auto& e:s.sources){if(e.opened||e.absent)++usable;
    partial=partial||!e.complete||e.limited||e.closeError!=ERROR_SUCCESS;rows.push_back(Json::object({{L"hive",Json::string(e.hive)},{L"path",Json::string(e.path)},
        {L"opened",Json::boolean(e.opened)},{L"absent",Json::boolean(e.absent)},{L"complete",Json::boolean(e.complete)},{L"limited",Json::boolean(e.limited)},
        {L"openWin32Error",Json::number(static_cast<DWORD>(e.openError))},{L"enumWin32Error",Json::number(static_cast<DWORD>(e.enumError))},
        {L"closeWin32Error",e.opened?Json::number(static_cast<DWORD>(e.closeError)):Json{}},{L"count",Json::count(e.count)}}));}return Json::array(rows);}
Result enumerate(const Args& a){
    const auto scope=a.get(L"--scope",L"all"),kind=a.get(L"--kind",L"all"),state=a.get(L"--state",L"all"),registration=a.get(L"--registration");
    if(scope!=L"all"&&scope!=L"file"&&scope!=L"directory"&&scope!=L"folder")throw std::invalid_argument("--scope must be all, file, directory or folder");
    if(kind!=L"all"&&kind!=L"handler"&&kind!=L"verb")throw std::invalid_argument("--kind must be all, handler or verb");
    if(state!=L"all"&&state!=L"enabled"&&state!=L"disabled")throw std::invalid_argument("--state must be all, enabled or disabled");
    if(a.has(L"--registration")&&!b::IsSupportedContextMenuPath(registration))throw std::invalid_argument("--registration must be one supported root's direct child");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");
    const auto snapshot=b::ScanContextMenuEntries();bool partial=false,malformed=false;std::size_t usable=0,matched=0;const auto source=sources(snapshot,partial,usable);std::vector<Json> rows;
    for(const auto& e:snapshot.entries){if(!registration.empty()&&!matches(e,registration))continue;
        if(kind!=L"all"&&(kind==L"verb")!=(e.kind==b::ContextMenuKind::ShellVerb))continue;if(state!=L"all"&&(state==L"enabled")!=e.enabled)continue;
        if(scope!=L"all"&&!equal(e.scopeText,scope==L"file"?L"*":scope==L"folder"?L"Folder":L"Directory"))continue;
        ++matched;const auto row=entry(e,partial,malformed);if(rows.size()<limit)rows.push_back(row);}
    return {malformed?4:!usable?3:partial||matched>rows.size()?6:0,Json::object({{L"source",Json::string(L"HKCR merged registration view + HKLM KSword backup store, caller registry view")},
        {L"elevatedDisplay",Json::boolean(snapshot.elevated)},{L"backupRoot",Json::string(b::ContextMenuBackupRootPath())},{L"sources",source},
        {L"snapshotCount",Json::count(snapshot.entries.size())},{L"matchedCount",Json::count(matched)},{L"returnedCount",Json::count(rows.size())},
        {L"truncated",Json::boolean(matched>rows.size())},{L"entries",Json::array(rows)}}),{L"Registration evidence only, not an active Explorer menu or loaded-module list. Candidate executable paths come from the backend's first-token extraction; relative/unquoted/ambiguous commands are not resolved as complete shell execution. Disabled entries retain backup metadata, not resolved live module details."}};
}
struct KeyState{bool known=false,present=false;LSTATUS status=0;};
KeyState exists(HKEY hive,const std::wstring& path){HKEY key=nullptr;KeyState value;value.status=::RegOpenKeyExW(hive,path.c_str(),0,KEY_READ,&key);
    value.present=value.status==ERROR_SUCCESS;value.known=value.present||value.status==ERROR_FILE_NOT_FOUND||value.status==ERROR_PATH_NOT_FOUND;
    if(key){const auto closed=::RegCloseKey(key);if(closed!=ERROR_SUCCESS){value.known=false;value.status=closed;}}return value;}
Json keyState(const KeyState& s){return Json::object({{L"known",Json::boolean(s.known)},{L"present",s.known?Json::boolean(s.present):Json{}},{L"win32Error",Json::number(static_cast<DWORD>(s.status))}});}
Result action(const Args& a,bool enable){
    const auto registration=a.require(L"--registration");if(!b::IsSupportedContextMenuPath(registration))throw std::invalid_argument("--registration must be one supported root's direct child");
    if(!a.has(L"--confirm"))throw std::invalid_argument("--confirm is required for registry modification");
    const auto user=exists(HKEY_CURRENT_USER,L"Software\\Classes\\"+registration),machine=exists(HKEY_LOCAL_MACHINE,L"Software\\Classes\\"+registration);
    if(!user.known||user.present||!machine.known)return {5,Json::object({{L"registrationPath",Json::string(registration)},{L"attempted",Json::boolean(false)},
        {L"userRegistration",keyState(user)},{L"machineRegistration",keyState(machine)}}),{L"CLI mutations require an unambiguous per-machine registration with no HKCU overlay. Per-user/unknown merged-view ownership is not supported by the existing HKLM backup format."}};
    const auto before=b::ScanContextMenuEntries();const b::ContextMenuEntry* selected=nullptr;bool live=false,disabled=false;
    for(const auto& e:before.entries)if(matches(e,registration)){live=live||e.enabled;disabled=disabled||!e.enabled;if(e.enabled!=enable){if(selected)return {3,Json::object({{L"attempted",Json::boolean(false)}}),{L"Ambiguous registration/backup entries."}};selected=&e;}}
    if(live&&disabled)return {3,Json::object({{L"attempted",Json::boolean(false)}}),{L"Live registration and backup coexist; resolve the conflict before mutation."}};
    if(!selected)return {3,Json::object({{L"attempted",Json::boolean(false)},{L"registrationPath",Json::string(registration)}}),{L"Requested live/backup entry not found; no registry mutation performed."}};
    if(!enable&&!machine.present)return {5,Json::object({{L"attempted",Json::boolean(false)}}),{L"Live target is not a confirmed per-machine registration."}};
    if(enable&&machine.present)return {3,Json::object({{L"attempted",Json::boolean(false)}}),{L"Restore destination already exists."}};
    if(enable){const auto source=selected->fields.find(L"backupSource"),kind=selected->fields.find(L"backupKind");if(source==selected->fields.end()||!source->second.available||!equal(source->second.text,registration)||kind==selected->fields.end()||!kind->second.available)
        return {4,Json::object({{L"attempted",Json::boolean(false)}}),{L"Backup source/kind metadata is missing or invalid; no restore attempted."}};}
    const auto result=enable?b::EnableContextMenuEntry(*selected):b::DisableContextMenuEntry(*selected);
    const auto afterMachine=exists(HKEY_LOCAL_MACHINE,L"Software\\Classes\\"+registration),afterUser=exists(HKEY_CURRENT_USER,L"Software\\Classes\\"+registration),afterBackup=result.backupPath.empty()?KeyState{}:exists(HKEY_LOCAL_MACHINE,result.backupPath);
    const bool verified=result.success&&afterMachine.known&&afterUser.known&&!afterUser.present&&afterBackup.known&&
        (enable?afterMachine.present&&result.copySucceeded&&result.backupDeleted&&!afterBackup.present:!afterMachine.present&&afterBackup.present&&result.copySucceeded&&result.metadataSucceeded&&result.sourceDeleted);
    std::vector<Json> calls;bool closeFailed=false;for(const auto& [name,status]:result.calls){closeFailed=closeFailed||(name==L"close-key"&&status!=ERROR_SUCCESS);calls.push_back(Json::object({{L"step",Json::string(name)},{L"win32Error",Json::number(static_cast<DWORD>(status))}}));}
    const bool changed=result.backupCreated||result.destinationCreated||result.sourceDeleted||result.copySucceeded;
    const int code=verified&&!closeFailed?0:changed?6:3;
    return {code,Json::object({{L"source",Json::string(L"shared HKCR subtree backup/delete or restore; CLI per-machine/no-overlay gate")},
        {L"registrationPath",Json::string(registration)},{L"action",Json::string(enable?L"enable":L"disable")},{L"attempted",Json::boolean(result.attempted)},
        {L"backendSucceeded",Json::boolean(result.success)},{L"stage",Json::string(result.stage)},{L"win32Error",Json::number(static_cast<DWORD>(result.error))},
        {L"backupPath",Json::string(result.backupPath)},{L"backupCreated",Json::boolean(result.backupCreated)},{L"dataCreated",Json::boolean(result.dataCreated)},
        {L"copySucceeded",Json::boolean(result.copySucceeded)},{L"metadataSucceeded",Json::boolean(result.metadataSucceeded)},{L"sourceDeleted",Json::boolean(result.sourceDeleted)},
        {L"destinationCreated",Json::boolean(result.destinationCreated)},{L"backupDeleted",Json::boolean(result.backupDeleted)},{L"backupRetained",Json::boolean(result.backupRetained)},
        {L"cleanupWin32Error",Json::number(static_cast<DWORD>(result.cleanupError))},{L"calls",Json::array(calls)},
        {L"afterMachineRegistration",keyState(afterMachine)},{L"afterUserRegistration",keyState(afterUser)},{L"afterBackup",keyState(afterBackup)},
        {L"verified",Json::boolean(verified)},{L"display",Json::string(result.message)}}),{L"Readback checks key presence and native copy/metadata/delete receipts; it does not prove Explorer refresh, activation or atomicity against concurrent registry edits. Backup remains on incomplete operations. No collision overwrite, per-user relocation or R0 fallback."}};
}
}
void registerSystemContextMenu(){
    addCommand({L"system context-menu enum",L"KswordCLI.exe system context-menu enum [--scope SCOPE] [--kind KIND] [--state STATE] [--registration PATH] [--limit N] [--backend r3] [--json]",L"Enumerate R3 shell handler/verb registrations and retained backups.",
        L"Optional: --scope all|file|directory|folder (all); --kind all|handler|verb (all); --state all|enabled|disabled (all); --registration direct registration path; --limit 1..100000 (1000); --backend r3; --json.",
        L"Output: HKCR/HKLM source open/enum/close/completeness/limit evidence, counts, backup root, entries with registry string types/status/availability, registration/backup state, CLSID or ProgID, raw module path/command, first-token moduleFileCandidate and candidate existence/error. Five roots only: */Directory/Folder shellex ContextMenuHandlers, */Directory shell. No COM activation, Explorer invocation or arbitrary extension traversal. HKCR is a caller-specific merged view, not physical-hive ownership. Disabled entries expose backup metadata. Missing optional keys may be valid; denied/limited fields/sources or output truncation 6, malformed 4, no readable sources 3. Each source walk 100000 keys/8 seconds between calls; registry strings 1 MiB. Help performs no scan.",enumerate});
    for(const bool enable:{false,true}){const auto name=enable?L"enable":L"disable";addCommand({std::wstring(L"system context-menu ")+name,
        std::wstring(L"KswordCLI.exe system context-menu ")+name+L" --registration PATH --confirm [--backend r3] [--json]",
        enable?L"Restore one backed-up machine shell registration.":L"Back up and remove one machine shell registration.",
        L"Required: --registration (one supported root's direct child), --confirm. Optional: --backend r3, --json.",
        L"Output: target/action, attempted, native stage/call statuses, backup/data/copy/metadata/delete/restore progress, cleanup/retention and independent key-presence readback/verified. CLI requires HKCU absence plus known HKLM state; per-user/ambiguous merged ownership returns 5 before mutation. Existing backup/live collision or restore destination refuses overwrite. Missing/invalid backup source/kind metadata 4. Backup metadata must all write successfully before source deletion. Native failure without side effects 3; side effects/incomplete readback/cleanup 6; only expected copy/delete/key-presence result and closes verified 0. Does not guarantee atomicity vs registry writers or Explorer refresh. Uses existing HKLM backup format; no delete-backup-only, COM execution or R0. Help never writes.",[enable](const Args& a){return action(a,enable);}});}
}
}
