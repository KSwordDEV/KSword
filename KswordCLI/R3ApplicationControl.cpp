#include "R3SecurityShared.h"
#include "../shared/usermode/backend/security/ApplicationControl.h"
#include <sddl.h>
#include <objbase.h>
#include <cwctype>
#include <stdexcept>

namespace ks::cli {
namespace {
namespace backend = ks::r3::security;

std::wstring lower(std::wstring value) {
    for (auto& c : value) c = static_cast<wchar_t>(std::towlower(c));
    return value;
}
void requireConfirm(const Args& args) {
    if (!args.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
}
std::wstring hash(const Args& args) {
    auto value = lower(args.require(L"--expected-hash"));
    if (value.size() != 64 || !std::all_of(value.begin(), value.end(), [](wchar_t c) {
        return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
    })) throw std::invalid_argument("--expected-hash must be a SHA-256 hex digest");
    return value;
}
std::wstring id(const Args& args) {
    auto value = args.require(L"--id");
    if (value.size() == 36) value = L"{" + value + L"}";
    GUID parsed{};
    if (value.size() != 38 || FAILED(CLSIDFromString(value.c_str(), &parsed)) || IsEqualGUID(parsed, GUID_NULL))
        throw std::invalid_argument("--id must be a nonzero GUID");
    return value;
}
std::wstring scope(const Args& args) {
    auto value = lower(args.get(L"--scope",L"local"));
    if (value != L"local" && value != L"effective") throw std::invalid_argument("--scope must be local or effective");
    return value;
}
std::wstring requiredText(const Args& args, const wchar_t* key) {
    const auto value = args.require(key);
    if (value.empty() || value.size() > 4096 || value.find(L'\0') != std::wstring::npos)
        throw std::invalid_argument("required text must be nonempty and at most 4096 UTF-16 characters");
    return value;
}
std::wstring sid(const Args& args) {
    const auto value = requiredText(args,L"--sid"); PSID parsed = nullptr;
    if (!ConvertStringSidToSidW(value.c_str(), &parsed)) throw std::invalid_argument("--sid must be a valid SID");
    const bool valid = IsValidSid(parsed) != FALSE; LocalFree(parsed);
    if (!valid) throw std::invalid_argument("--sid must be a valid SID");
    return value;
}
std::wstring collection(const Args& args) {
    const auto value = lower(args.require(L"--collection"));
    if (value == L"exe") return L"Exe"; if (value == L"msi") return L"Msi";
    if (value == L"script") return L"Script"; if (value == L"dll") return L"Dll";
    if (value == L"appx") return L"Appx";
    throw std::invalid_argument("--collection must be exe, msi, script, dll or appx");
}
std::wstring action(const Args& args) {
    const auto value = lower(args.require(L"--action"));
    if (value == L"allow") return L"Allow"; if (value == L"deny") return L"Deny";
    throw std::invalid_argument("--action must be allow or deny");
}
Result run(const backend::ApplicationControlRequest& request, bool mutating, const Args& args) {
    const auto timeout = args.u32(L"--timeout-ms",30000);
    if (timeout < 500 || timeout > 120000) throw std::invalid_argument("--timeout-ms must be 500..120000");
    const auto result = backend::RunApplicationControl(request,timeout);
    int code = !result.started ? 3 : result.outputTruncated ? 6 : result.timedOut || result.cancelled ||
        result.outputError || result.closeError || !result.waitCompleted || !result.exitCodeKnown ? (mutating ? 6 : 3) :
        result.exitCode == 0 ? 0 : result.exitCode == 5 ? 5 : result.exitCode == 6 ? 6 : 3;
    Json payload;
    if (!result.output.empty() && !result.outputTruncated && !result.decodeMalformed)
        payload = security::payload(result,code);
    else if (code == 0) code = mutating ? 6 : 4;
    return {code, Json::object({{L"source",Json::string(L"local Windows PowerShell AppLocker/Defender cmdlets")},
        {L"operation",Json::string(request.operation)}, {L"result",payload},
        {L"helper",Json::object({{L"started",Json::boolean(result.started)}, {L"waitCompleted",Json::boolean(result.waitCompleted)},
            {L"exitCode",result.exitCodeKnown ? Json::number(result.exitCode) : Json{}}, {L"win32Error",Json::number(result.win32Error)},
            {L"timedOut",Json::boolean(result.timedOut)}, {L"cancelled",Json::boolean(result.cancelled)},
            {L"outputTruncated",Json::boolean(result.outputTruncated)}, {L"decodeMalformed",Json::boolean(result.decodeMalformed)},
            {L"closeWin32Error",Json::number(result.closeError)}, {L"diagnostic",Json::string(result.errorText)}})}}),
        mutating ? std::vector<std::wstring>{L"An attempted or timed-out policy update can have partial effects; inspect the readback before retrying. Expected hashes detect stale snapshots but are not an atomic compare-and-swap."} : std::vector<std::wstring>{}};
}
Result invoke(const Args& args, const std::wstring& op) {
    backend::ApplicationControlRequest request; request.operation = op;
    auto& v = request.values;
    const bool mutating = op != L"applocker-enum" && op != L"defender-query";
    if (mutating) requireConfirm(args);
    if (op == L"applocker-enum") {
        v[L"scope"] = scope(args); const auto limit = args.u32(L"--limit",64);
        if (!limit || limit > 128) throw std::invalid_argument("--limit must be 1..128");
        v[L"limit"] = std::to_wstring(limit); if (args.has(L"--id")) v[L"id"] = id(args);
    } else if (op == L"applocker-export") {
        v[L"scope"] = scope(args); v[L"output"] = requiredText(args,L"--output");
    } else if (op == L"applocker-import") {
        v[L"input"] = requiredText(args,L"--input"); v[L"expected"] = hash(args);
    } else if (op == L"applocker-add" || op == L"applocker-update" || op == L"applocker-remove") {
        v[L"expected"] = hash(args);
        if (op == L"applocker-add") v[L"collection"] = collection(args); else v[L"id"] = id(args);
        if (op != L"applocker-remove") {
            v[L"name"] = requiredText(args,L"--name"); v[L"sid"] = sid(args); v[L"action"] = action(args);
            v[L"path"] = requiredText(args,L"--path"); v[L"description"] = args.get(L"--description");
        }
    } else if (op == L"defender-set") {
        v[L"expected"] = hash(args); v[L"setting"] = lower(args.require(L"--setting"));
        const auto number = args.u32(L"--value",MAXDWORD); if (!args.has(L"--value")) throw std::invalid_argument("missing option --value");
        if ((v[L"setting"] == L"realtime" && number > 1) ||
            ((v[L"setting"] == L"controlled-folder" || v[L"setting"] == L"pua" || v[L"setting"] == L"network") && number > 2) ||
            (v[L"setting"] != L"realtime" && v[L"setting"] != L"controlled-folder" && v[L"setting"] != L"pua" && v[L"setting"] != L"network"))
            throw std::invalid_argument("invalid --setting or --value");
        v[L"value"] = std::to_wstring(number);
    } else if (op == L"defender-asr-add" || op == L"defender-asr-set" || op == L"defender-asr-remove") {
        v[L"expected"] = hash(args); v[L"id"] = id(args).substr(1,36);
        if (op != L"defender-asr-remove") {
            if (!args.has(L"--value")) throw std::invalid_argument("missing option --value");
            const auto value = args.u32(L"--value");
            if (value != 0 && value != 1 && value != 2 && value != 6) throw std::invalid_argument("ASR --value must be 0, 1, 2 or 6");
            v[L"value"] = std::to_wstring(value);
        }
    }
    return run(request,mutating,args);
}
}

void registerApplicationControl() {
    const std::wstring extra = L" [--timeout-ms N] [--backend r3] [--json]";
    const std::wstring common = L"Uses fixed PowerShell cmdlets with encoded arguments. Expected SHA-256 comes from the current local-policy or Defender query; it detects stale snapshots but is not an atomic compare-and-swap. Writes require --confirm, return 6 when effects cannot be verified, and do not bypass OS policy or permissions.";
    const auto add = [&](const wchar_t* path, const wchar_t* params, const wchar_t* summary, const wchar_t* op) {
        addCommand({path,L"KswordCLI.exe " + std::wstring(path) + (params[0] ? L" " + std::wstring(params) : L"") + extra,summary,
            L"See syntax. --timeout-ms is 500..120000 (30000); --backend r3; --json.",common,
            [op](const Args& args){return invoke(args,op);}});
    };
    add(L"security applocker rules enum",L"[--scope local|effective] [--id GUID] [--limit N]",L"Enumerate detailed AppLocker rules and the policy hash.",L"applocker-enum");
    add(L"security applocker policy export",L"--output PATH [--scope local|effective] --confirm",L"Export complete policy XML without overwriting the destination.",L"applocker-export");
    add(L"security applocker policy import",L"--input PATH --expected-hash SHA256 --confirm",L"Replace the local AppLocker policy with XML after checking its snapshot hash.",L"applocker-import");
    add(L"security applocker rule add",L"--collection TYPE --name NAME --sid SID --action allow|deny --path PATH [--description TEXT] --expected-hash SHA256 --confirm",L"Add a local AppLocker path rule.",L"applocker-add");
    add(L"security applocker rule update",L"--id GUID --name NAME --sid SID --action allow|deny --path PATH [--description TEXT] --expected-hash SHA256 --confirm",L"Update a local AppLocker path rule.",L"applocker-update");
    add(L"security applocker rule delete",L"--id GUID --expected-hash SHA256 --confirm",L"Delete one local AppLocker rule by identity.",L"applocker-remove");
    add(L"security defender settings query",L"",L"Read Defender settings, ASR rules and their snapshot hash.",L"defender-query");
    add(L"security defender setting set",L"--setting controlled-folder|pua|network|realtime --value N --expected-hash SHA256 --confirm",L"Update one Defender setting and verify the readback.",L"defender-set");
    add(L"security defender asr add",L"--id GUID --value 0|1|2|6 --expected-hash SHA256 --confirm",L"Add one ASR rule and verify the readback.",L"defender-asr-add");
    add(L"security defender asr set",L"--id GUID --value 0|1|2|6 --expected-hash SHA256 --confirm",L"Update one ASR rule and verify the readback.",L"defender-asr-set");
    add(L"security defender asr delete",L"--id GUID --expected-hash SHA256 --confirm",L"Delete one ASR rule and verify the readback.",L"defender-asr-remove");
}
}
