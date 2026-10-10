#include "CommandRegistry.h"
#include "../shared/usermode/backend/registry/RegistryBackend.h"
#include <algorithm>
#include <stdexcept>
namespace ks::cli {
namespace {
using namespace ks::r3::registry;
std::wstring path(const Args& args) {
    const auto value=args.has(L"--path") ? args.require(L"--path") : args.require(L"--key");
    if(!ParseRegistryPath(value).valid) throw std::invalid_argument("invalid registry path");
    return value;
}
Result enumerate(const Args& args) {
    const auto value=path(args); const auto limit=args.u32(L"--limit",100), bytes=args.u32(L"--max-value-data-bytes",256);
    const auto kind=args.get(L"--kind",L"all");
    if(kind!=L"all" && kind!=L"keys" && kind!=L"values") throw std::invalid_argument("invalid registry --kind");
    const auto snapshot=EnumerateRegistryKey(value); std::vector<Json> rows; std::uint32_t matched=0;
    for(const auto& entry:snapshot.rows) {
        const bool key=entry.kind==RegistryRowKind::SubKey;
        if((kind==L"keys" && !key) || (kind==L"values" && key)) continue;
        ++matched; if(rows.size()>=limit) continue;
        rows.push_back(Json::object({{L"kind",Json::string(key ? L"key" : L"value")}, {L"name",Json::string(entry.name)},
            {L"type",key ? Json{} : Json::number(entry.valueType)}, {L"typeName",Json::string(entry.typeText)},
            {L"dataText",key ? Json{} : Json::string(entry.dataText.substr(0,256))}, {L"dataBytes",key ? Json{} : Json::count(entry.data.size())},
            {L"dataHex",key ? Json{} : Json::bytes(entry.data,bytes)}, {L"dataTruncated",Json::boolean(entry.data.size()>bytes)},
            {L"textTruncated",Json::boolean(entry.dataText.size()>256)}}));
    }
    return {snapshot.success ? (snapshot.complete ? 0 : 6) : 3,
        Json::object({{L"path",Json::string(snapshot.displayPath)}, {L"kernelPath",Json::string(snapshot.kernelPath)}, {L"complete",Json::boolean(snapshot.complete)},
            {L"win32Error",Json::number(snapshot.win32Error)}, {L"matchedCount",Json::number(matched)}, {L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))},
            {L"displayTruncated",Json::boolean(rows.size()<matched)}, {L"entries",Json::array(rows)}}), snapshot.success ? std::vector<std::wstring>{} : std::vector<std::wstring>{snapshot.statusText}};
}
Result read(const Args& args) {
    const auto key=path(args), name=args.get(L"--name",args.get(L"--value")); const auto limit=args.u32(L"--max-data-bytes",256);
    const auto response=ReadRegistryValue(key,name);
    return {response.success ? 0 : 3,Json::object({{L"path",Json::string(key)}, {L"name",Json::string(name)}, {L"win32Error",Json::number(response.win32Error)},
        {L"type",response.success ? Json::number(response.valueType) : Json{}}, {L"typeName",response.success ? Json::string(RegistryTypeText(response.valueType)) : Json{}},
        {L"dataBytes",Json::count(response.data.size())}, {L"returnedBytes",Json::count(std::min(response.data.size(),static_cast<std::size_t>(limit)))},
        {L"dataTruncated",Json::boolean(response.data.size()>limit)}, {L"dataHex",Json::bytes(response.data,limit)},
        {L"dataText",response.success ? Json::string(FormatRegistryData(response.valueType,response.data).substr(0,256)) : Json{}}}),
        response.success ? std::vector<std::wstring>{} : std::vector<std::wstring>{response.statusText}};
}
}
void registerRegistryBrowse() {
    const auto enumNotes=L"Native x64 registry view; does not query R0. Data: path, kernelPath, complete, win32Error, counts and key/value entries. Display truncation is separate from enumeration completeness.";
    addCommand({L"registry key enum",L"KswordCLI.exe registry key enum --path PATH [--kind all|keys|values] [--limit N] [--max-value-data-bytes N] [--backend r3] [--json]",
        L"Read direct child keys and values.",L"Required: --path. Optional: --kind (default all), --limit (default 100), --max-value-data-bytes (default 256), --backend r3, --json.",enumNotes,enumerate});
    addCommand({L"registry value read",L"KswordCLI.exe registry value read --path PATH [--name NAME] [--max-data-bytes N] [--backend r3] [--json]",
        L"Read one value's type and exact raw bytes.",L"Required: --path. Optional: --name (default value when omitted), --max-data-bytes (default 256), --backend r3, --json.",
        L"Data: name, type, typeName, dataBytes, returnedBytes, dataTruncated, dataHex, dataText, win32Error. Text preview is capped at 256 characters.",read});
    addCommand({L"registry enum-key",L"KswordCLI.exe registry enum-key --key KEY --backend r3 [--kind all|keys|values] [--limit N] [--max-value-data-bytes N] [--json]",
        L"Read direct keys and values with the explicitly selected backend.",L"Required for R3: --key, --backend r3. Optional: --kind, --limit, --max-value-data-bytes, --json.",enumNotes,enumerate});
    addCommand({L"registry read-value",L"KswordCLI.exe registry read-value --key KEY --backend r3 [--value NAME] [--max-data-bytes N] [--json]",
        L"Read a value with the explicitly selected backend.",L"Required for R3: --key, --backend r3. Optional: --value, --max-data-bytes, --json.",L"Default/R0 syntax remains available below. R3 has no --flags or --hexdump switch; dataHex is always present.",read});
}
}
