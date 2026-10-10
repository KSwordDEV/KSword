#include "CommandRegistry.h"
#include "../shared/usermode/backend/registry/RegistryBackend.h"
#include <algorithm>
#include <stdexcept>
namespace ks::cli {
namespace {
using namespace ks::r3::registry;
bool absent(std::uint32_t error) {return error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND;}
int failure(std::uint32_t error) {return error==ERROR_NOT_SUPPORTED || error==ERROR_CALL_NOT_IMPLEMENTED ? 5 : 3;}
Json value(const RegistryOperationResult& result) {
    return Json::object({{L"present",result.success ? Json::boolean(true) : absent(result.win32Error) ? Json::boolean(false) : Json{}},
        {L"win32Error",Json::number(result.win32Error)}, {L"type",result.success ? Json::number(result.valueType) : Json{}},
        {L"dataBytes",result.success ? Json::count(result.data.size()) : Json{}}, {L"dataHex",result.success ? Json::bytes(result.data,256) : Json{}},
        {L"dataTruncated",Json::boolean(result.data.size()>256)}});
}
Result finish(const RegistryOperationResult& action, bool verified, Json data) {
    return {action.partial ? 6 : !action.success ? failure(action.win32Error) : verified ? 0 : 6,
        Json::object({{L"requestSucceeded",Json::boolean(action.success)}, {L"win32Error",Json::number(action.win32Error)}, {L"partial",Json::boolean(action.partial)},
            {L"unchanged",Json::boolean(action.unchanged)}, {L"verified",Json::boolean(verified)}, {L"result",data}}),
        action.success ? std::vector<std::wstring>{} : std::vector<std::wstring>{action.statusText}};
}
std::uint32_t type(const Args& args) {
    const std::map<std::wstring,std::uint32_t> names{{L"none",REG_NONE},{L"sz",REG_SZ},{L"expand-sz",REG_EXPAND_SZ},{L"binary",REG_BINARY},{L"dword",REG_DWORD},{L"multi-sz",REG_MULTI_SZ},{L"qword",REG_QWORD}};
    const auto requested=args.require(L"--type"); const auto named=names.find(requested);
    return named==names.end() ? args.u32(L"--type") : named->second;
}
Result mutate(const Args& args,const std::wstring& operation) {
    const auto path=args.has(L"--path") ? args.require(L"--path") : args.require(L"--key");
    const auto parsed=ParseRegistryPath(path);
    if(!parsed.valid) throw std::invalid_argument("invalid registry path");
    if(!args.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
    if(operation==L"key-create" || operation==L"key-delete") {
        if(operation==L"key-delete" && parsed.subKey.empty()) throw std::invalid_argument("key deletion requires a non-root key");
        const auto result=operation==L"key-create" ? CreateRegistryKey(path) : DeleteRegistryKey(path);
        const auto after=EnumerateRegistryKey(path);
        const bool verified=operation==L"key-create" ? after.success : !after.success && absent(after.win32Error);
        return finish(result,verified,Json::object({{L"path",Json::string(path)}, {L"created",result.dispositionKnown ? Json::boolean(result.created) : Json{}},
            {L"postcheckPresent",after.success ? Json::boolean(true) : absent(after.win32Error) ? Json::boolean(false) : Json{}}, {L"postcheckWin32Error",Json::number(after.win32Error)}}));
    }
    const auto name=args.get(L"--name",args.get(L"--value"));
    if(operation==L"value-delete") {
        const auto result=DeleteRegistryValue(path,name); const auto after=ReadRegistryValue(path,name);
        return finish(result,!after.success && absent(after.win32Error),Json::object({{L"path",Json::string(path)}, {L"name",Json::string(name)}, {L"postcheck",value(after)}}));
    }
    if(operation==L"value-rename") {
        const auto old=args.has(L"--old-name") ? args.require(L"--old-name") : args.require(L"--old-value");
        const auto renamed=args.has(L"--new-name") ? args.require(L"--new-name") : args.require(L"--new-value");
        const auto before=ReadRegistryValue(path,old); const auto result=RenameRegistryValue(path,old,renamed);
        const auto oldAfter=ReadRegistryValue(path,old), newAfter=ReadRegistryValue(path,renamed);
        const bool same=::CompareStringOrdinal(old.c_str(),-1,renamed.c_str(),-1,TRUE)==CSTR_EQUAL;
        const bool verified=before.success && newAfter.success && before.valueType==newAfter.valueType && before.data==newAfter.data &&
            (same ? oldAfter.success : !oldAfter.success && absent(oldAfter.win32Error));
        return finish(result,verified,Json::object({{L"path",Json::string(path)}, {L"oldName",Json::string(old)}, {L"newName",Json::string(renamed)},
            {L"oldPostcheck",value(oldAfter)}, {L"newPostcheck",value(newAfter)}}));
    }
    const auto valueType=type(args);
    if(static_cast<int>(args.has(L"--text"))+static_cast<int>(args.has(L"--hex"))+static_cast<int>(args.has(L"--data-file"))!=1) throw std::invalid_argument("specify exactly one of --text, --hex or --data-file");
    std::vector<std::uint8_t> bytes;
    if(args.has(L"--hex")) bytes=parseHexPayload(args.get(L"--hex"));
    else if(args.has(L"--data-file")) {
        auto file=readPayloadFile(args.get(L"--data-file"));
        if(file.win32Error) return {3,Json::object({{L"path",Json::string(path)}, {L"dataFileWin32Error",Json::number(file.win32Error)}}),{L"Input payload could not be read; no registry write was attempted."}};
        bytes=std::move(file.bytes);
    } else if(valueType==REG_QWORD) {
        Args numeric;numeric.values[L"--number"]=args.get(L"--text"); const auto number=numeric.integer(L"--number");
        for(unsigned i=0;i<8;++i) bytes.push_back(static_cast<std::uint8_t>(number>>(i*8)));
    } else {
        if(valueType!=REG_SZ && valueType!=REG_EXPAND_SZ && valueType!=REG_MULTI_SZ && valueType!=REG_DWORD) throw std::invalid_argument("--text supports sz, expand-sz, multi-sz, dword and qword; use --hex or --data-file for raw types");
        std::wstring error;
        if(!ParseRegistryDataText(valueType,args.get(L"--text"),bytes,error)) throw std::invalid_argument("invalid registry text payload");
    }
    const auto result=WriteRegistryValue(path,name,valueType,bytes);const auto after=ReadRegistryValue(path,name);
    return finish(result,after.success && after.valueType==valueType && after.data==bytes,Json::object({{L"path",Json::string(path)}, {L"name",Json::string(name)},
        {L"requestedType",Json::number(valueType)}, {L"requestedBytes",Json::count(bytes.size())}, {L"postcheck",value(after)}}));
}
}
void registerRegistryMutations() {
    const auto notes=L"R3 only, no driver. Every operation re-reads its target. Partial or unconfirmed effects return 6. Value rename copies then deletes and may overwrite an existing target; it is not atomic.";
    for(const auto* operation:{L"create",L"delete"}) {
        const std::wstring word=operation;
        addCommand({L"registry key "+word,L"KswordCLI.exe registry key "+word+L" --path PATH --confirm [--backend r3] [--json]",L"Apply key "+word+L" and verify target presence.",L"Required: --path, --confirm. Optional: --backend r3, --json.",notes,[word](const Args& args){return mutate(args,L"key-"+word);}});
        addCommand({L"registry "+word+L"-key",L"KswordCLI.exe registry "+word+L"-key --key KEY --backend r3 --confirm [--json]",L"Apply key "+word+L" with the explicitly selected backend.",L"Required for R3: --key, --backend r3, --confirm. Optional: --json.",notes,[word](const Args& args){return mutate(args,L"key-"+word);}});
    }
    const auto payload=L" --type sz|expand-sz|multi-sz|dword|qword|binary|none|N (--text TEXT | --hex HEX | --data-file PATH) --confirm [--backend r3] [--json]";
    addCommand({L"registry value set",L"KswordCLI.exe registry value set --path PATH [--name NAME]"+std::wstring(payload),L"Write and verify one typed value.",L"Required: --path, --type, exactly one payload, --confirm. Optional: --name (default value), --backend r3, --json.",notes,[](const Args& args){return mutate(args,L"value-set");}});
    addCommand({L"registry set-value",L"KswordCLI.exe registry set-value --key KEY --backend r3 [--value NAME] --type TYPE (--text TEXT | --hex HEX | --data-file PATH) --confirm [--json]",L"Write and verify a value using R3.",L"Required for R3: --key, --backend r3, --type, payload, --confirm. Optional: --value, --json.",notes,[](const Args& args){return mutate(args,L"value-set");}});
    addCommand({L"registry value delete",L"KswordCLI.exe registry value delete --path PATH [--name NAME] --confirm [--backend r3] [--json]",L"Delete one value and verify its absence.",L"Required: --path, --confirm. Optional: --name (default value), --backend r3, --json.",notes,[](const Args& args){return mutate(args,L"value-delete");}});
    addCommand({L"registry delete-value",L"KswordCLI.exe registry delete-value --key KEY --backend r3 [--value NAME] --confirm [--json]",L"Delete one value using R3.",L"Required for R3: --key, --backend r3, --confirm. Optional: --value, --json.",notes,[](const Args& args){return mutate(args,L"value-delete");}});
    addCommand({L"registry value rename",L"KswordCLI.exe registry value rename --path PATH --old-name NAME --new-name NAME --confirm [--backend r3] [--json]",L"Copy a value to its new name, delete the old one, and verify both.",L"Required: --path, --old-name, --new-name, --confirm. Optional: --backend r3, --json.",notes,[](const Args& args){return mutate(args,L"value-rename");}});
    addCommand({L"registry rename-value",L"KswordCLI.exe registry rename-value --key KEY --backend r3 --old-value NAME --new-value NAME --confirm [--json]",L"Rename a value using R3.",L"Required for R3: --key, --backend r3, --old-value, --new-value, --confirm. Optional: --json.",notes,[](const Args& args){return mutate(args,L"value-rename");}});
}
}
