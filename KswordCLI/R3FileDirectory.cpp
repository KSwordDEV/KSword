#include "CommandRegistry.h"
#include "../shared/usermode/backend/file/Directory.h"
#include "../shared/usermode/backend/file/PathNavigator.h"
#include <stdexcept>

namespace ks::cli {
namespace {
namespace backend = ks::r3::file;
Result enumerate(const Args& args, bool drives) {
    const auto limit = args.u32(L"--limit"); const auto kind = args.get(L"--kind", L"all");
    if (kind != L"all" && kind != L"directory" && kind != L"file") throw std::invalid_argument("invalid --kind (all|directory|file)");
    std::wstring path;
    if (!drives) {
        path = backend::PathNavigator::normalizeDirectoryPath(args.require(L"--path"));
        if (path.empty() || path.find_first_of(L"*?") != std::wstring::npos) throw std::invalid_argument("--path must name a directory without wildcards");
        const DWORD size = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
        if (!size) return {3, Json::object({{L"win32Error", Json::number(GetLastError())}})};
        std::wstring full(size, L'\0'); const DWORD written = GetFullPathNameW(path.c_str(), size, full.data(), nullptr);
        if (!written || written >= size) return {3, Json::object({{L"win32Error", Json::number(written ? ERROR_INSUFFICIENT_BUFFER : GetLastError())}})};
        full.resize(written); path = std::move(full);
    }
    const auto snapshot = drives ? backend::enumerateDrives() : backend::enumerateDirectory(path);
    std::vector<Json> rows; std::uint32_t matched = 0;
    for (const auto& entry : snapshot.entries) {
        const auto type = entry.kind == backend::FileEntryKind::Drive ? L"drive" : entry.kind == backend::FileEntryKind::Directory ? L"directory" : L"file";
        if (kind != L"all" && kind != type) continue;
        ++matched; if (limit && rows.size() >= limit) continue;
        const auto time = (static_cast<std::uint64_t>(entry.lastWriteTime.dwHighDateTime) << 32) | entry.lastWriteTime.dwLowDateTime;
        rows.push_back(Json::object({{L"kind", Json::string(type)}, {L"name", Json::string(entry.name)}, {L"path", Json::string(entry.fullPath)},
            {L"attributes", Json::hex(entry.attributes)}, {L"attributeText", Json::string(backend::formatAttributes(entry.attributes))},
            {L"sizeBytes", entry.kind == backend::FileEntryKind::File ? Json::count(entry.size) : Json{}},
            {L"lastWriteFileTime", time ? Json::count(time) : Json{}}, {L"lastWriteLocalTime", time ? Json::string(backend::formatLastWriteTime(entry.lastWriteTime)) : Json{}},
            {L"reparsePoint", Json::boolean(entry.reparsePoint)}}));
    }
    // An interrupted enumeration retains its rows and its actual failure.
    const bool complete = snapshot.errorCode == ERROR_SUCCESS;
    Result result{complete ? 0 : snapshot.entries.empty() ? 3 : 6};
    result.data = Json::object({{L"source", Json::string(drives ? L"GetLogicalDriveStringsW" : L"FindFirstFileW/FindNextFileW")},
        {L"path", Json::string(path)}, {L"virtualDriveRoot", Json::boolean(snapshot.virtualDriveRoot)}, {L"complete", Json::boolean(complete)},
        {L"win32Error", Json::number(snapshot.errorCode)}, {L"totalCount", Json::number(static_cast<std::uint32_t>(snapshot.entries.size()))},
        {L"matchedCount", Json::number(matched)}, {L"returnedCount", Json::number(static_cast<std::uint32_t>(rows.size()))}, {L"entries", Json::array(rows)}});
    if (!complete) result.diagnostics.push_back(snapshot.statusText);
    return result;
}
}
void registerFileDirectory() {
    addCommand({L"file directory enum", L"KswordCLI.exe file directory enum --path PATH [--kind all|directory|file] [--limit N] [--backend r3] [--json]",
        L"Enumerate the immediate children of one directory.", L"Required: --path. Optional: --kind, --limit (0 = all), --backend r3, --json.",
        L"Fields: path, complete, win32Error, entries with attributes, sizeBytes, FILETIME and reparsePoint. No recursion or reparse traversal. Paths expand environment variables and resolve relative names.",
        [](const Args& args) { return enumerate(args, false); }});
    addCommand({L"file directory drives enum", L"KswordCLI.exe file directory drives enum [--limit N] [--backend r3] [--json]",
        L"List logical drive names without probing their contents.", L"Optional: --limit (0 = all), --backend r3, --json.",
        L"Fields: virtualDriveRoot, complete, win32Error, entries. Does not claim drive readiness, capacity or hardware identity.",
        [](const Args& args) { return enumerate(args, true); }});
}
}
