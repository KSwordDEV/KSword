#include "R3FileShared.h"
#include "../shared/usermode/backend/file/FileMetadata.h"
#include <algorithm>
#include <cwctype>

namespace ks::cli {
namespace {
namespace meta = ks::r3::file::metadata;
Json snapshot(const meta::Snapshot& s) {
    return Json::object({{L"available",Json::boolean(s.ok)}, {L"win32Error",Json::number(s.error)},
        {L"volumeSerial",s.identity.known ? Json::hex(s.identity.volumeSerial) : Json{}},
        {L"fileId",s.identity.known ? Json::hex(s.identity.fileId) : Json{}},
        {L"attributes",s.ok ? Json::hex(s.basic.FileAttributes) : Json{}},
        {L"creationTime",s.ok ? Json::count(static_cast<std::uint64_t>(s.basic.CreationTime.QuadPart)) : Json{}},
        {L"accessTime",s.ok ? Json::count(static_cast<std::uint64_t>(s.basic.LastAccessTime.QuadPart)) : Json{}},
        {L"writeTime",s.ok ? Json::count(static_cast<std::uint64_t>(s.basic.LastWriteTime.QuadPart)) : Json{}},
        {L"changeTime",s.ok ? Json::count(static_cast<std::uint64_t>(s.basic.ChangeTime.QuadPart)) : Json{}}});
}
meta::Identity expectedIdentity(const Args& args) {
    (void)args.require(L"--volume-serial");(void)args.require(L"--file-id");
    return {true,args.u32(L"--volume-serial"),args.integer(L"--file-id")};
}
Result readBasic(const Args& args) {
    const auto path = file::path(args,L"--path");
    const auto result = meta::ReadBasic(path);
    return {result.ok ? 0 : 3, Json::object({{L"path",Json::string(path)}, {L"snapshot",snapshot(result)},
        {L"editableAttributeMask",Json::hex(meta::editableAttributeMask)}}),
        {L"Times are UTC FILETIME 100ns ticks. The final reparse point itself is opened; no target is followed."}};
}
Result writeBasic(const Args& args) {
    (void)args.require(L"--confirm");
    const auto path = file::path(args,L"--path");
    const auto expected=expectedIdentity(args);
    meta::BasicPatch patch;
    const std::array<const wchar_t*,4> options{L"--creation-time",L"--access-time",L"--write-time",L"--change-time"};
    bool selected = false;
    for (std::size_t i=0; i<options.size(); ++i) {
        if (args.has(options[i])) {patch.timeSelected[i]=true;patch.times[i]=args.integer(options[i]);selected=true;}
    }
    if (args.has(L"--attributes")) {patch.attributesSelected=true;patch.editableAttributes=args.u32(L"--attributes");selected=true;}
    if (!selected) throw std::invalid_argument("select at least one time or --attributes");
    if (patch.attributesSelected && (patch.editableAttributes & ~meta::editableAttributeMask)) throw std::invalid_argument("--attributes contains non-editable bits");
    for (std::size_t i=0;i<options.size();++i) if(patch.timeSelected[i] && !patch.times[i]) throw std::invalid_argument("time must be a nonzero FILETIME");
    const auto result=meta::WriteBasic(path,expected,patch);
    return {result.verified ? 0 : result.written ? 6 : 3,
        Json::object({{L"path",Json::string(path)}, {L"attempted",Json::boolean(result.attempted)},
            {L"written",Json::boolean(result.written)}, {L"verified",Json::boolean(result.verified)},
            {L"win32Error",Json::number(result.error)}, {L"before",snapshot(result.before)}, {L"after",snapshot(result.after)}}),
        {L"File identity is checked against the supplied volume serial and file ID on the same handle used to write and read back. Times may be rounded by the filesystem; no automatic rollback is performed."}};
}
Json named(const meta::NamedResult& result,bool includeBytes) {
    std::vector<Json> rows;
    for(const auto& entry:result.entries) rows.push_back(Json::object({{L"name",Json::string(entry.name)},
        {L"sizeBytes",entry.sizeKnown?Json::count(entry.size):Json{}},{L"needEa",Json::boolean(entry.needEa)},
        {L"dataHex",includeBytes?Json::bytes(entry.bytes,entry.bytes.size()):Json{}}}));
    return Json::object({{L"volumeSerial",result.identity.known?Json::hex(result.identity.volumeSerial):Json{}},
        {L"fileId",result.identity.known?Json::hex(result.identity.fileId):Json{}}, {L"win32Error",Json::number(result.error)},
        {L"success",Json::boolean(result.ok)}, {L"complete",Json::boolean(result.complete)}, {L"attempted",Json::boolean(result.attempted)},
        {L"written",Json::boolean(result.written)}, {L"verified",Json::boolean(result.verified)}, {L"entries",Json::array(rows)}});
}
int namedCode(const meta::NamedResult& result,bool write) {
    if(!result.written && (result.error==ERROR_NOT_SUPPORTED || result.error==ERROR_PROC_NOT_FOUND || result.error==ERROR_CALL_NOT_IMPLEMENTED)) return 5;
    if(write) return result.verified?0:result.written?6:3;
    return !result.ok?3:result.complete?0:6;
}
bool payload(const Args& args,std::vector<std::uint8_t>& bytes,DWORD& error) {
    if(args.has(L"--hex")==args.has(L"--data-file")) throw std::invalid_argument("specify exactly one of --hex and --data-file");
    if(args.has(L"--hex")) {bytes=parseHexPayload(args.get(L"--hex"));return true;}
    const auto file=readPayloadFile(args.require(L"--data-file"));
    if(file.win32Error) {error=file.win32Error;return false;}
    bytes=file.bytes;return true;
}
Result streams(const Args& args,const std::wstring& op) {
    const auto path=file::path(args,L"--path");meta::NamedResult result;
    if(op==L"list") result=meta::ListStreams(path);
    else if(op==L"read") {
        const auto limit=args.u32(L"--max-bytes",1048576);
        if(!limit || limit>64U*1024U*1024U) throw std::invalid_argument("--max-bytes must be 1..67108864");
        result=meta::ReadStream(path,args.require(L"--name"),limit);
    } else {
        (void)args.require(L"--confirm");const auto expected=expectedIdentity(args);
        std::vector<std::uint8_t> data;
        if(op!=L"write" || payload(args,data,result.error)) result=meta::WriteStream(path,expected,args.require(L"--name"),data,op==L"delete");
    }
    return {namedCode(result,op==L"write" || op==L"delete"),named(result,op==L"read"),
        {L"R3 named streams only. The base file identity is checked, and stream writes are read back. Path rebinding between base and stream open is not atomic; no rollback or backup is implied."}};
}
Result ea(const Args& args,const std::wstring& op) {
    const auto path=file::path(args,L"--path");meta::NamedResult result;
    if(op==L"list") result=meta::ListEa(path);
    else {
        (void)args.require(L"--confirm");const auto expected=expectedIdentity(args);
        std::vector<std::uint8_t> value;
        if(op==L"set" && !payload(args,value,result.error)) return {3,named(result,false),{L"Input data file could not be read; no EA was written."}};
        if(op==L"set" && value.empty()) throw std::invalid_argument("an empty EA value removes the attribute; use delete explicitly");
        const auto needEa=args.u32(L"--need-ea",0);if(needEa>1)throw std::invalid_argument("--need-ea must be 0 or 1");
        result=meta::WriteEa(path,expected,args.require(L"--name"),value,op==L"delete",needEa!=0);
    }
    return {namedCode(result,op!=L"list"),named(result,op==L"list"),
        {L"EA operations use the final file handle and read back the current value; unsupported filesystems and missing privileges return their native error. Empty EA values are deletion."}};
}
SECURITY_INFORMATION securityParts(const Args& args) {
    auto text=args.get(L"--parts",L"owner,group,dacl");
    std::transform(text.begin(),text.end(),text.begin(),[](wchar_t c){return static_cast<wchar_t>(std::towlower(c));});
    SECURITY_INFORMATION result=0;std::size_t start=0;
    while(start<text.size()) {
        const auto end=text.find(L',',start);const auto word=text.substr(start,end==std::wstring::npos?std::wstring::npos:end-start);
        if(word==L"owner")result|=OWNER_SECURITY_INFORMATION;else if(word==L"group")result|=GROUP_SECURITY_INFORMATION;
        else if(word==L"dacl")result|=DACL_SECURITY_INFORMATION;else if(word==L"sacl")result|=SACL_SECURITY_INFORMATION;
        else throw std::invalid_argument("--parts expects owner,group,dacl,sacl");
        if(end==std::wstring::npos)break;start=end+1;
    }
    if(!result || text.back()==L',')throw std::invalid_argument("--parts must not be empty");
    return result;
}
Result security(const Args& args,bool write) {
    const auto path=file::path(args,L"--path");const auto parts=securityParts(args);meta::SecurityResult result;
    if(write) {(void)args.require(L"--confirm");result=meta::WriteSecurity(path,expectedIdentity(args),parts,args.require(L"--sddl"));}
    else result=meta::ReadSecurity(path,parts);
    return {write?(result.verified?0:result.written?6:3):(result.ok?0:3),
        Json::object({{L"path",Json::string(path)}, {L"parts",Json::hex(parts)}, {L"volumeSerial",result.identity.known?Json::hex(result.identity.volumeSerial):Json{}},
            {L"fileId",result.identity.known?Json::hex(result.identity.fileId):Json{}},{L"attempted",Json::boolean(result.attempted)},
            {L"written",Json::boolean(result.written)},{L"verified",Json::boolean(result.verified)}, {L"win32Error",Json::number(result.error)},
            {L"sddl",result.ok?Json::string(result.sddl):Json{}}}),
        {L"SDDL owner, group, DACL and SACL are selected explicitly. SACL requires appropriate privileges. Identity, setting and readback use the same final reparse-point handle. No backup or rollback is implied."}};
}
Result shell(const Args& args,bool write) {
    const auto path=file::path(args,L"--path");meta::ShellResult result;
    if(write) {
        (void)args.require(L"--confirm");const auto expected=expectedIdentity(args);
        const auto backup=file::path(args,L"--backup");auto name=args.require(L"--name");const auto value=args.require(L"--value");
        std::transform(name.begin(),name.end(),name.begin(),[](wchar_t c){return static_cast<wchar_t>(std::towlower(c));});
        std::vector<std::wstring> values;
        if(name==L"authors" || name==L"keywords") {
            std::size_t start=0;
            while(start<=value.size()) {const auto end=value.find(L';',start);values.push_back(value.substr(start,end==std::wstring::npos?end:end-start));if(end==std::wstring::npos)break;start=end+1;}
        } else values.push_back(value);
        result=meta::WriteShell(path,expected,name,values,backup);
    } else result=meta::ReadShell(path);
    std::vector<Json> properties;bool allAvailable=true;
    for(const auto& property:result.properties) {allAvailable=allAvailable&&property.available;
        properties.push_back(Json::object({{L"name",Json::string(property.name)}, {L"available",Json::boolean(property.available)},
            {L"empty",Json::boolean(property.empty)},{L"hresult",Json::hex(static_cast<std::uint32_t>(property.hresult))},{L"values",Json::strings(property.values)}}));}
    const int code=write ? (result.verified?0:result.written || (result.attempted && !result.rollbackVerified)?6:3) : (!result.ok?3:allAvailable?0:6);
    return {code,Json::object({{L"path",Json::string(path)}, {L"volumeSerial",result.identity.known?Json::hex(result.identity.volumeSerial):Json{}},
        {L"fileId",result.identity.known?Json::hex(result.identity.fileId):Json{}},{L"win32Error",Json::number(result.error)},
        {L"hresult",Json::hex(static_cast<std::uint32_t>(result.hresult))}, {L"attempted",Json::boolean(result.attempted)},
        {L"written",Json::boolean(result.written)}, {L"verified",Json::boolean(result.verified)},
        {L"backupPath",result.backupPath.empty()?Json{}:Json::string(result.backupPath)}, {L"backupCreated",Json::boolean(result.backupCreated)},
        {L"afterVolumeSerial",result.afterIdentity.known?Json::hex(result.afterIdentity.volumeSerial):Json{}}, {L"afterFileId",result.afterIdentity.known?Json::hex(result.afterIdentity.fileId):Json{}},
        {L"rollbackAttempted",Json::boolean(result.rollbackAttempted)}, {L"rollbackVerified",Json::boolean(result.rollbackVerified)},
        {L"rollbackWin32Error",Json::number(result.rollbackError)}, {L"properties",Json::array(properties)}}),
        {L"Shell PropertyStore is path-based and may rewrite the file. A verified identity cannot make path lookup atomic. A failure after SetValue attempts same-identity content restore from the newly created backup; ACLs and alternate streams are not claimed restored."}};
}
Result peResource(const Args& args,const std::wstring& op) {
    const auto path=file::path(args,L"--path");const auto type=args.require(L"--type");const auto name=args.require(L"--name");
    const auto language=args.u32(L"--language",0);if(language>65535)throw std::invalid_argument("--language must fit a Windows LANGID");
    meta::ResourceResult result;std::size_t displayLimit=0;
    if(op==L"query") {
        displayLimit=args.u32(L"--max-bytes",1048576);if(!displayLimit || displayLimit>64U*1024U*1024U)throw std::invalid_argument("--max-bytes must be 1..67108864");
        result=meta::ReadPeResource(path,type,name,static_cast<WORD>(language));
    } else {
        (void)args.require(L"--confirm");const auto expected=expectedIdentity(args);std::vector<std::uint8_t> data;DWORD inputError=0;
        if(op==L"set" && !payload(args,data,inputError)) return {3,Json::object({{L"win32Error",Json::number(inputError)}}),{L"Input data file could not be read; no resource was updated."}};
        if(op==L"set" && data.empty())throw std::invalid_argument("an empty resource payload is a delete; use delete explicitly");
        result=meta::WritePeResource(path,expected,type,name,static_cast<WORD>(language),data,op==L"delete",file::path(args,L"--backup"));
    }
    const bool truncated=op==L"query" && result.bytes.size()>displayLimit;
    const int code=op==L"query" ? (!result.ok?(result.error==ERROR_NOT_SUPPORTED?5:3):truncated?6:0) :
        (result.verified?0:result.written || (result.attempted && !result.rollbackVerified)?6:(result.error==ERROR_NOT_SUPPORTED?5:3));
    return {code,Json::object({{L"path",Json::string(path)}, {L"type",Json::string(type)}, {L"name",Json::string(name)}, {L"language",Json::number(language)},
        {L"volumeSerial",result.identity.known?Json::hex(result.identity.volumeSerial):Json{}}, {L"fileId",result.identity.known?Json::hex(result.identity.fileId):Json{}},
        {L"present",result.ok?Json::boolean(result.present):Json{}}, {L"sizeBytes",result.present?Json::count(result.bytes.size()):Json{}},
        {L"dataHex",op==L"query" && result.present?Json::bytes(result.bytes,displayLimit):Json{}}, {L"displayTruncated",Json::boolean(truncated)},
        {L"win32Error",Json::number(result.error)}, {L"attempted",Json::boolean(result.attempted)}, {L"written",Json::boolean(result.written)},
        {L"verified",Json::boolean(result.verified)}, {L"backupPath",result.backupPath.empty()?Json{}:Json::string(result.backupPath)},
        {L"afterVolumeSerial",result.afterIdentity.known?Json::hex(result.afterIdentity.volumeSerial):Json{}}, {L"afterFileId",result.afterIdentity.known?Json::hex(result.afterIdentity.fileId):Json{}},
        {L"backupCreated",Json::boolean(result.backupCreated)}, {L"rollbackAttempted",Json::boolean(result.rollbackAttempted)},
        {L"rollbackVerified",Json::boolean(result.rollbackVerified)}, {L"rollbackWin32Error",Json::number(result.rollbackError)}}),
        {L"Resource update uses a Windows path-based transaction and may invalidate the executable's signature. A new backup is required; restoring content is attempted only on the same verified file identity. ACLs and alternate streams are not claimed restored."}};
}
}
void registerFileMetadata() {
    addCommand({L"file metadata query",L"KswordCLI.exe file metadata query --path PATH [--backend r3] [--json]",
        L"Read file identity, basic attributes and four timestamps.",L"Required: --path. Optional: --backend r3, --json.",
        L"Outputs volumeSerial/fileId for identity-checked writes; opens the final reparse point itself. Times are decimal UTC FILETIME ticks.",readBasic});
    addCommand({L"file metadata set",L"KswordCLI.exe file metadata set --path PATH --volume-serial N --file-id N [--creation-time N] [--access-time N] [--write-time N] [--change-time N] [--attributes MASK] --confirm [--backend r3] [--json]",
        L"Update selected basic attributes or timestamps for the same file identity.",
        L"Required: --path, --volume-serial, --file-id, --confirm and at least one time or --attributes. Optional: --backend r3, --json.",
        L"Use identity from file metadata query. Times are nonzero UTC FILETIME ticks. Attributes replace only READONLY/HIDDEN/SYSTEM/ARCHIVE/TEMPORARY/NOT_CONTENT_INDEXED; structural flags are preserved. Same-handle readback; unverified write returns 6. R3 only, no automatic rollback.",writeBasic});
    addCommand({L"file metadata streams list",L"KswordCLI.exe file metadata streams list --path PATH [--backend r3] [--json]",
        L"Enumerate named and default NTFS streams.",L"Required: --path. Optional: --backend r3, --json.",L"Outputs stream name and size; identity is checked before and after path-based enumeration.",[](const Args& a){return streams(a,L"list");}});
    addCommand({L"file metadata streams read",L"KswordCLI.exe file metadata streams read --path PATH --name NAME [--max-bytes N] [--backend r3] [--json]",
        L"Read a named data stream.",L"Required: --path, --name. Optional: --max-bytes 1..67108864 (1048576), --backend r3, --json.",L"The data stream name excludes colons and $DATA. A limited prefix returns partial 6.",[](const Args& a){return streams(a,L"read");}});
    for(const auto* op:{L"write",L"delete"}) {
        const std::wstring action=op;const auto payloadText=action==L"write"?L" (--hex HEX | --data-file PATH)":L"";
        addCommand({L"file metadata streams "+action,L"KswordCLI.exe file metadata streams "+action+L" --path PATH --name NAME --volume-serial N --file-id N"+payloadText+L" --confirm [--backend r3] [--json]",
            L"Update or delete one named data stream.",L"Required: --path, --name, identity, --confirm; write additionally requires exactly one payload. Optional: --backend r3, --json.",
        L"Final stream handle is identity checked before data changes. Creating a new stream is a path-based operation and can race path replacement; partial effects are reported. Reparse-point targets are unsupported. Readback verifies bytes or deletion. No rollback or backup.",[action](const Args& a){return streams(a,action);}});
    }
    addCommand({L"file metadata ea list",L"KswordCLI.exe file metadata ea list --path PATH [--backend r3] [--json]",
        L"Enumerate file extended attributes and raw values.",L"Required: --path. Optional: --backend r3, --json.",L"Names are UTF-8; invalid names fail rather than being altered. Queries are bounded to 1 MiB.",[](const Args& a){return ea(a,L"list");}});
    for(const auto* op:{L"set",L"delete"}) {
        const std::wstring action=op;const auto payloadText=action==L"set"?L" (--hex HEX | --data-file PATH) [--need-ea 0|1]":L"";
        addCommand({L"file metadata ea "+action,L"KswordCLI.exe file metadata ea "+action+L" --path PATH --name NAME --volume-serial N --file-id N"+payloadText+L" --confirm [--backend r3] [--json]",
            L"Set or delete an extended attribute.",L"Required: --path, --name, identity, --confirm; set additionally requires nonempty data. Optional: --backend r3, --json.",
            L"Names are encoded as UTF-8, values are limited to 65535 bytes. A zero-length EA means removal. Writes use the checked file handle and are read back; no backup or rollback.",[action](const Args& a){return ea(a,action);}});
    }
    addCommand({L"file metadata security query",L"KswordCLI.exe file metadata security query --path PATH [--parts LIST] [--backend r3] [--json]",
        L"Read the selected owner, group and ACL security descriptor as SDDL.",L"Required: --path. Optional: --parts owner,group,dacl,sacl (default owner,group,dacl), --backend r3, --json.",L"SACL access requires appropriate privileges; unavailable data is an error.",[](const Args& a){return security(a,false);}});
    addCommand({L"file metadata security set",L"KswordCLI.exe file metadata security set --path PATH --volume-serial N --file-id N --sddl SDDL [--parts LIST] --confirm [--backend r3] [--json]",
        L"Apply selected security descriptor components and read them back.",L"Required: --path, identity, --sddl, --confirm. Optional: --parts owner,group,dacl,sacl, --backend r3, --json.",
        L"Set only the specified components; SACL requires appropriate privileges. The identity and readback use the same handle. ACL bytes, SID and protected state are compared after writing; an unverified write is partial 6. No automatic backup or rollback.",[](const Args& a){return security(a,true);}});
    addCommand({L"file metadata shell query",L"KswordCLI.exe file metadata shell query --path PATH [--backend r3] [--json]",
        L"Read Shell title, subject, authors, keywords, comment, copyright and rating.",L"Required: --path. Optional: --backend r3, --json.",
        L"Each property has availability, empty state and HRESULT. Property handlers depend on file type. Reparse points are not followed.",[](const Args& a){return shell(a,false);}});
    addCommand({L"file metadata shell set",L"KswordCLI.exe file metadata shell set --path PATH --volume-serial N --file-id N --name NAME --value TEXT --backup PATH --confirm [--backend r3] [--json]",
        L"Set one Shell PropertyStore field with a new backup and readback.",L"Required: --path, identity, --name, --value, --backup, --confirm. Optional: --backend r3, --json.",
        L"NAME: title, subject, authors, keywords, comment, copyright or rating (0..99). Authors/keywords use semicolon-separated values. Backup path must not exist; a failed commit attempts same-identity content restore. PropertyStore is path-based; replacing the path is not atomic. No ACL/alternate-stream rollback guarantee.",[](const Args& a){return shell(a,true);}});
    addCommand({L"file metadata resource query",L"KswordCLI.exe file metadata resource query --path PATH --type TYPE --name NAME [--language N] [--max-bytes N] [--backend r3] [--json]",
        L"Read one PE resource by type, name and language without executing the image.",L"Required: --path, --type, --name. Optional: --language LANGID (0), --max-bytes 1..67108864 (1048576), --backend r3, --json.",
        L"TYPE and NAME accept text or #integer identifiers. An absent resource is reported as present=false. A limited output prefix returns 6.",[](const Args& a){return peResource(a,L"query");}});
    for(const auto* op:{L"set",L"delete"}) {
        const std::wstring action=op;const auto payloadText=action==L"set"?L" (--hex HEX | --data-file PATH)":L"";
        addCommand({L"file metadata resource "+action,L"KswordCLI.exe file metadata resource "+action+L" --path PATH --volume-serial N --file-id N --type TYPE --name NAME"+payloadText+L" --backup PATH [--language N] --confirm [--backend r3] [--json]",
            L"Update or delete one PE resource using a new backup.",L"Required: --path, identity, --type, --name, --backup, --confirm; set requires nonempty data. Optional: --language LANGID (0), --backend r3, --json.",
            L"Uses Begin/Update/EndUpdateResource on the path; a concurrent replacement cannot be made atomic. Updates may invalidate the file signature. Existing backup is never overwritten. Failed commit attempts content restore only when the original file identity still matches; ACLs and streams are not claimed restored.",[action](const Args& a){return peResource(a,action);}});
    }
}
}
