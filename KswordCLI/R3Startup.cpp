#include "R3StartupShared.h"
#include <Windows.h>
#include <sddl.h>
#include <algorithm>
#include <cstdint>
#include <stdexcept>
namespace ks::cli::startup {
using namespace ks::r3::startup;
std::wstring utf8(const std::string& text) {
    if (text.empty()) return {};
    const int needed = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring result(static_cast<std::size_t>(needed), L'\0');
    return ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), needed) == needed ? result : std::wstring{};
}
Identity identity() {
    Identity result; HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) { result.win32Error = GetLastError(); return result; }
    struct Owner { HANDLE value; ~Owner() { CloseHandle(value); } } owner{ token };
    DWORD size = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<std::uint8_t> buffer(size);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) { result.win32Error = GetLastError(); return result; }
    wchar_t* sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid)) { result.win32Error = GetLastError(); return result; }
    result.sid = sid; LocalFree(sid); return result;
}
const wchar_t* category(StartupCategory value) {
    switch (value) {
    case StartupCategory::Logon: return L"logon";
    case StartupCategory::Services: return L"services";
    case StartupCategory::Drivers: return L"drivers";
    case StartupCategory::Tasks: return L"tasks";
    case StartupCategory::ImageHijack: return L"image-hijack";
    case StartupCategory::Registry: return L"registry";
    case StartupCategory::Wmi: return L"wmi";
    case StartupCategory::Hidden: return L"hidden";
    default: return L"all";
    }
}
const wchar_t* stage(StartupCategory value) { return category(value); }
const wchar_t* kind(const StartupEntry& entry) {
    const auto type = utf8(entry.sourceTypeText);
    if (entry.category == StartupCategory::Services) return L"service";
    if (entry.category == StartupCategory::Drivers) return L"driver";
    if (entry.category == StartupCategory::Tasks) return L"task";
    if (entry.category == StartupCategory::Logon) {
        if (type.find(L"Once") != std::wstring::npos || type.find(L"once") != std::wstring::npos) return L"run-once";
        if (type.find(L"Folder") != std::wstring::npos || type.find(L"folder") != std::wstring::npos) return L"folder";
        return L"run";
    }
    return category(entry.category);
}
const wchar_t* state(const StartupEntry& entry) {
    if (entry.category == StartupCategory::Tasks) return L"unknown";
    if (!entry.enabled) return L"disabled";
    if (entry.actionLocator.serviceStartMode == StartupScmStartMode::Manual) return L"manual";
    return L"active";
}
const wchar_t* scope(const StartupEntry& entry) {
    const auto location = utf8(entry.locationText);
    if (location.rfind(L"HKCU\\", 0) == 0) return L"user";
    if (location.rfind(L"HKLM\\", 0) == 0 || location.rfind(L"SCM\\", 0) == 0) return L"machine";
    if (utf8(entry.userText).find(L"公共") != std::wstring::npos) return L"all-users";
    return L"unknown";
}
std::wstring id(const StartupEntry& entry, const std::wstring& sid) {
    const std::string identity = entry.uniqueIdText.empty() ? entry.locationText + "|" + entry.itemNameText : entry.uniqueIdText;
    std::uint64_t hash = 14695981039346656037ULL;
    for (const wchar_t c : sid + L"|" + utf8(identity)) { hash ^= static_cast<std::uint16_t>(c); hash *= 1099511628211ULL; }
    return Json::hex(hash).display;
}
Json errors(const StartupEnumerationResult& snapshot) {
    std::vector<Json> rows;
    for (const auto& error : snapshot.sourceErrors) rows.push_back(Json::object({
        {L"source", Json::string(utf8(error.source))},
        {L"errorKind", Json::string(error.hresult ? L"hresult" : L"win32")},
        {L"code", error.code ? Json::count(error.code) : Json{}}}));
    return Json::array(rows);
}
Json row(const StartupEntry& entry, const std::wstring& sid) {
    const auto field = [](const std::string& text) { return Json::string(utf8(text)); };
    const bool readOnly = !entry.canEnable && !entry.canDisable && !entry.canDelete;
    return Json::object({
        {L"id", sid.empty() ? Json{} : Json::string(id(entry, sid))},
        {L"sourceUniqueId", field(entry.uniqueIdText)},
        {L"category", Json::string(category(entry.category))},
        {L"categoryDisplay", field(entry.categoryText)},
        {L"kind", Json::string(kind(entry))},
        {L"stage", Json::string(stage(entry.category))},
        {L"state", Json::string(state(entry))},
        {L"scope", Json::string(scope(entry))},
        {L"name", field(entry.itemNameText)},
        {L"command", field(entry.commandText)},
        {L"location", field(entry.locationText)},
        {L"locationGroup", field(entry.locationGroupText)},
        {L"sourceType", field(entry.sourceTypeText)},
        {L"sourceEnabled", Json::boolean(entry.enabled)},
        {L"publisher", field(entry.publisherText)},
        {L"imagePath", field(entry.imagePathText)},
        {L"user", field(entry.userText)},
        {L"detail", field(entry.detailText)},
        {L"riskLevel", Json::string(entry.riskLevel == StartupRiskLevel::Critical ? L"critical" : entry.riskLevel == StartupRiskLevel::Normal ? L"normal" : L"elevated")},
        {L"riskReasonCode", field(entry.riskReasonCode)},
        {L"riskReason", field(entry.riskReasonText)},
        {L"readOnly", Json::boolean(readOnly)},
        {L"canEnable", Json::boolean(entry.canEnable)},
        {L"canDisable", Json::boolean(entry.canDisable)},
        {L"canDelete", Json::boolean(entry.canDelete)},
        {L"deleteRegistryTree", Json::boolean(entry.deleteRegistryTree)},
        {L"canOpenFileLocation", Json::boolean(entry.canOpenFileLocation)},
        {L"canOpenRegistryLocation", Json::boolean(entry.canOpenRegistryLocation)},
        {L"actionKind", Json::count(static_cast<std::uint32_t>(entry.actionKind))},
        {L"registryRoot", entry.actionLocator.registryRoot == StartupRegistryRoot::CurrentUser ? Json::string(L"HKCU") : entry.actionLocator.registryRoot == StartupRegistryRoot::LocalMachine ? Json::string(L"HKLM") : Json{}},
        // StartupEntry does not carry a native WOW64 registry view; do not
        // turn the prior placeholder zero into a claimed observation.
        {L"registryView", Json{}},
        {L"registrySubKey", field(entry.actionLocator.registrySubKeyText)},
        {L"registryValueName", field(entry.actionLocator.registryValueNameText)},
        {L"displayRegistryValueName", field(entry.registryValueNameText)},
        {L"disabledRegistrySubKey", Json{}},
        {L"serviceName", field(entry.actionLocator.serviceNameText)},
        {L"serviceStartType", entry.actionKind == StartupActionKind::ScmStartType && entry.actionLocator.serviceStartMode != StartupScmStartMode::None ? Json::count(entry.actionLocator.serviceStartType) : Json{}},
        {L"serviceStartMode", entry.actionKind == StartupActionKind::ScmStartType ? Json::number(static_cast<std::uint32_t>(entry.actionLocator.serviceStartMode)) : Json{}},
        {L"taskPath", field(entry.actionLocator.taskPathText)},
        {L"filePath", field(entry.actionLocator.originalFilePathText)},
        {L"disabledFilePath", field(entry.actionLocator.parkedFilePathText)},
        {L"properties", Json{}}
    });
}
}
namespace ks::cli {
void registerStartupEnumeration() {
    addFamily(L"startup", L"Enumerate and inspect startup persistence through the shared R3 backend.");
    addCommand({L"startup enum",
        L"KswordCLI.exe startup enum [--category all|logon|services|drivers|tasks|image-hijack|registry|wmi|hidden] [--kind all|run|run-once|folder|service|driver|registry-only-service|task] [--scope all|user|machine|all-users|unknown] [--name NAME] [--limit N] [--backend r3] [--json]",
        L"Enumerate all nine startup source stages and return structured records.",
        L"Optional: --category and legacy --kind (default all), --scope (default all), --name exact UTF-16 display name, --limit (default 100), --backend r3, --json.",
        L"Stages: logon, services, drivers, tasks, image-hijack, registry, wmi, hidden. Each row includes stable id, sourceType, state, risk, action capabilities and structured locators. Legacy --kind values remain accepted for Run/RunOnce/folder/service/driver/task; registry-only-service and unknown remain documented read-only values. Driver/hidden/unavailable rows stay read-only. Exit 0 means complete; 6 means partial source errors; 3 means fatal enumeration or identity failure. Use help startup enum for the JSON field contract.",
        [](const Args& args) {
            auto categoryFilter = args.get(L"--category", L"all");
            const auto legacyKind = args.get(L"--kind", L"all");
            if (args.has(L"--kind") && categoryFilter == L"all") {
                if (legacyKind == L"run" || legacyKind == L"run-once" || legacyKind == L"folder") categoryFilter = L"logon";
                else if (legacyKind == L"service" || legacyKind == L"driver" || legacyKind == L"registry-only-service") categoryFilter = legacyKind == L"driver" ? L"drivers" : L"services";
                else if (legacyKind == L"task") categoryFilter = L"tasks";
                else if (legacyKind != L"all") throw std::invalid_argument("invalid startup kind");
            }
            const auto scopeFilter = args.get(L"--scope", L"all");
            const auto limit = args.u32(L"--limit", 100);
            const std::vector<std::wstring> categories{L"all",L"logon",L"services",L"drivers",L"tasks",L"image-hijack",L"registry",L"wmi",L"hidden"};
            const std::vector<std::wstring> scopes{L"all",L"user",L"machine",L"all-users",L"unknown"};
            if (std::find(categories.begin(), categories.end(), categoryFilter) == categories.end() || std::find(scopes.begin(), scopes.end(), scopeFilter) == scopes.end()) throw std::invalid_argument("invalid startup category or scope");
            const auto caller = startup::identity();
            const auto snapshot = ks::r3::startup::EnumerateStartupSnapshot();
            std::vector<Json> rows; std::uint32_t matched = 0;
            for (const auto& entry : snapshot.entries) {
                if (categoryFilter != L"all" && categoryFilter != startup::category(entry.category)) continue;
                if (args.has(L"--kind") && legacyKind != L"all" && legacyKind != startup::kind(entry)) continue;
                if (scopeFilter != L"all" && scopeFilter != startup::scope(entry)) continue;
                if (args.has(L"--name") && startup::utf8(entry.itemNameText) != args.get(L"--name")) continue;
                ++matched; if (rows.size() < limit) rows.push_back(startup::row(entry, caller.sid));
            }
            const bool complete = snapshot.success && snapshot.sourceErrors.empty() && caller.win32Error == 0;
            const std::vector<std::wstring> diagnostics = snapshot.diagnosticText.empty()
                ? std::vector<std::wstring>{}
                : std::vector<std::wstring>{startup::utf8(snapshot.diagnosticText)};
            return Result{complete ? 0 : (snapshot.success ? 6 : 3), Json::object({
                {L"userSid", Json::string(caller.sid)}, {L"identityWin32Error", Json::count(caller.win32Error)},
                {L"success", Json::boolean(snapshot.success)}, {L"complete", Json::boolean(complete)},
                {L"diagnostic", startup::utf8(snapshot.diagnosticText).empty() ? Json{} : Json::string(startup::utf8(snapshot.diagnosticText))},
                {L"sourceErrors", startup::errors(snapshot)}, {L"matchedCount", Json::count(matched)},
                {L"returnedCount", Json::count(rows.size())}, {L"displayTruncated", Json::boolean(rows.size() < matched)}, {L"entries", Json::array(rows)}}),
                diagnostics};
        }});
}
}
