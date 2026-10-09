#include "ContextMenuScanner.h"

#include "AdminState.h"

#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace ks::r3::system_tools {
namespace {

// kBackupRoot lives under HKLM rather than HKCU because the entries it protects
// are machine-wide registrations. Restoring a machine key from a per-user hive
// would silently turn a shared handler into a single-account one.
constexpr wchar_t kBackupRoot[] = L"SOFTWARE\\KswordARKLight\\ShellExtensionBackup";
constexpr wchar_t kBackupDataSubKey[] = L"Data";
constexpr wchar_t kBackupSourceValue[] = L"SourcePath";
constexpr wchar_t kBackupTimeValue[] = L"BackupTime";
constexpr wchar_t kBackupScopeValue[] = L"Scope";
constexpr wchar_t kBackupNameValue[] = L"Name";
constexpr wchar_t kBackupKindValue[] = L"Kind";

struct RegistrationRoot {
    const wchar_t* path;
    const wchar_t* scope;
    ContextMenuKind kind;
};

// The five registration points named by the module contract. Directory\shell and
// *\shell carry declarative verbs; the three shellex roots carry COM handlers
// that Explorer loads into its own address space, which is why they are the ones
// that actually destabilize the shell when they go bad.
constexpr RegistrationRoot kRegistrationRoots[] = {
    { L"*\\shellex\\ContextMenuHandlers", L"*", ContextMenuKind::ShellExHandler },
    { L"Directory\\shellex\\ContextMenuHandlers", L"Directory", ContextMenuKind::ShellExHandler },
    { L"Folder\\shellex\\ContextMenuHandlers", L"Folder", ContextMenuKind::ShellExHandler },
    { L"*\\shell", L"*", ContextMenuKind::ShellVerb },
    { L"Directory\\shell", L"Directory", ContextMenuKind::ShellVerb },
};

std::wstring ReadRegistryString(HKEY root, const std::wstring& subKey, const wchar_t* valueName) {
    DWORD size = 0;
    // RegGetValueW expands REG_EXPAND_SZ for us, which matters because most
    // InprocServer32 paths are written as %SystemRoot%-relative.
    LSTATUS status = ::RegGetValueW(root, subKey.c_str(), valueName,
        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, nullptr, &size);
    if (status != ERROR_SUCCESS || size < sizeof(wchar_t)) {
        return {};
    }
    std::wstring buffer(size / sizeof(wchar_t) + 1, L'\0');
    status = ::RegGetValueW(root, subKey.c_str(), valueName,
        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, buffer.data(), &size);
    if (status != ERROR_SUCCESS) {
        return {};
    }
    buffer.resize(::wcsnlen(buffer.c_str(), buffer.size()));
    return buffer;
}

std::vector<std::wstring> EnumerateSubKeyNames(HKEY root, const std::wstring& subKey) {
    std::vector<std::wstring> names;
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return names;
    }
    wchar_t name[512] = {};
    for (DWORD index = 0;; ++index) {
        DWORD length = static_cast<DWORD>(std::size(name));
        const LSTATUS status = ::RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr);
        if (status != ERROR_SUCCESS) {
            break;
        }
        names.emplace_back(name, length);
    }
    ::RegCloseKey(key);
    return names;
}

std::wstring TrimQuotes(std::wstring text) {
    while (!text.empty() && (text.front() == L' ' || text.front() == L'"')) {
        text.erase(text.begin());
    }
    while (!text.empty() && (text.back() == L' ' || text.back() == L'"')) {
        text.pop_back();
    }
    return text;
}

bool FileIsPresent(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// ExtractExecutablePath pulls the image out of a verb command line. A quoted
// first token is taken verbatim; an unquoted one stops at the first space, which
// is wrong for the minority of unquoted paths that contain spaces -- those are
// reported as missing rather than guessed at, because inventing a longer path
// would produce a confident wrong answer instead of a visible unknown.
std::wstring ExtractExecutablePath(const std::wstring& commandLine) {
    std::wstring trimmed = commandLine;
    while (!trimmed.empty() && trimmed.front() == L' ') {
        trimmed.erase(trimmed.begin());
    }
    if (trimmed.empty()) {
        return {};
    }
    std::wstring token;
    if (trimmed.front() == L'"') {
        const std::size_t closing = trimmed.find(L'"', 1);
        token = closing == std::wstring::npos ? trimmed.substr(1) : trimmed.substr(1, closing - 1);
    } else {
        const std::size_t space = trimmed.find(L' ');
        token = space == std::wstring::npos ? trimmed : trimmed.substr(0, space);
    }

    wchar_t expanded[MAX_PATH * 2] = {};
    const DWORD length = ::ExpandEnvironmentStringsW(token.c_str(), expanded, static_cast<DWORD>(std::size(expanded)));
    if (length > 0 && length <= std::size(expanded)) {
        return std::wstring(expanded);
    }
    return token;
}

std::wstring BackupTokenFor(const std::wstring& registrationPath) {
    std::wstring token = registrationPath;
    // A registry key name may contain anything except a backslash, so the path
    // separator is the only character that has to be folded away.
    std::replace(token.begin(), token.end(), L'\\', L'!');
    return token;
}

std::wstring CurrentTimestampText() {
    SYSTEMTIME now{};
    ::GetLocalTime(&now);
    std::wostringstream stream;
    stream << std::setfill(L'0')
        << now.wYear << L'-' << std::setw(2) << now.wMonth << L'-' << std::setw(2) << now.wDay
        << L' ' << std::setw(2) << now.wHour << L':' << std::setw(2) << now.wMinute
        << L':' << std::setw(2) << now.wSecond;
    return stream.str();
}

std::wstring ErrorText(const LSTATUS status) {
    LPWSTR buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(status), 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring text = L"错误码 " + std::to_wstring(status);
    if (length > 0 && buffer) {
        std::wstring detail(buffer, length);
        while (!detail.empty() && (detail.back() == L'\r' || detail.back() == L'\n' || detail.back() == L' ')) {
            detail.pop_back();
        }
        text += L"（" + detail + L"）";
    }
    if (buffer) {
        ::LocalFree(buffer);
    }
    return text;
}

// ResolveClsidDetails fills the CLSID-derived fields. The registration value can
// be a raw CLSID or a ProgID, and both spellings appear in the wild, so the
// ProgID indirection is followed rather than reported as unresolvable.
void ResolveClsidDetails(ContextMenuEntry& entry, const std::wstring& rawValue) {
    std::wstring clsid = TrimQuotes(rawValue);
    if (clsid.empty()) {
        entry.diagnosticText = L"注册项没有默认值，Explorer 无法据此加载处理程序。";
        return;
    }
    if (clsid.front() != L'{') {
        const std::wstring viaProgId = ReadRegistryString(HKEY_CLASSES_ROOT, clsid + L"\\CLSID", nullptr);
        if (viaProgId.empty()) {
            entry.clsid = clsid;
            entry.diagnosticText = L"默认值不是 CLSID，且无法通过 ProgID 解析。";
            return;
        }
        entry.diagnosticText = L"通过 ProgID " + clsid + L" 解析。";
        clsid = TrimQuotes(viaProgId);
    }
    entry.clsid = clsid;

    const std::wstring clsidKey = L"CLSID\\" + clsid;
    entry.displayText = ReadRegistryString(HKEY_CLASSES_ROOT, clsidKey, nullptr);

    // InprocServer32 holds a bare module path, so it is taken verbatim. Running
    // it through the command-line splitter would truncate every DLL under a
    // directory with a space in its name -- "C:\Program Files\..." being the
    // overwhelmingly common case -- and report a present module as missing.
    std::wstring server = ReadRegistryString(HKEY_CLASSES_ROOT, clsidKey + L"\\InprocServer32", nullptr);
    if (!server.empty()) {
        entry.modulePath = server;
        entry.moduleFile = TrimQuotes(server);
        entry.moduleExists = FileIsPresent(entry.moduleFile);
        return;
    }

    // A context-menu handler is normally in-process, but out-of-process
    // registrations do exist and hiding them would leave a blank row.
    // LocalServer32, unlike InprocServer32, really is a command line.
    server = ReadRegistryString(HKEY_CLASSES_ROOT, clsidKey + L"\\LocalServer32", nullptr);
    if (server.empty()) {
        entry.diagnosticText += entry.diagnosticText.empty() ? L"" : L" ";
        entry.diagnosticText += L"CLSID 未注册 InprocServer32/LocalServer32。";
        return;
    }
    entry.modulePath = server;
    entry.moduleFile = TrimQuotes(ExtractExecutablePath(server));
    entry.moduleExists = FileIsPresent(entry.moduleFile);
}

void ResolveVerbDetails(ContextMenuEntry& entry, const std::wstring& verbKeyPath) {
    entry.displayText = ReadRegistryString(HKEY_CLASSES_ROOT, verbKeyPath, L"MUIVerb");
    if (entry.displayText.empty()) {
        entry.displayText = ReadRegistryString(HKEY_CLASSES_ROOT, verbKeyPath, nullptr);
    }
    const std::wstring command = ReadRegistryString(HKEY_CLASSES_ROOT, verbKeyPath + L"\\command", nullptr);
    if (command.empty()) {
        // Modern verbs can delegate entirely to a COM object, in which case
        // there is no command line to check and "missing file" would be wrong.
        const std::wstring delegate = ReadRegistryString(HKEY_CLASSES_ROOT, verbKeyPath, L"DelegateExecute");
        entry.diagnosticText = delegate.empty()
            ? L"没有 command 子键。"
            : L"由 COM DelegateExecute " + delegate + L" 处理，无命令行。";
        return;
    }
    entry.modulePath = command;
    entry.moduleFile = TrimQuotes(ExtractExecutablePath(command));
    entry.moduleExists = FileIsPresent(entry.moduleFile);
}

// AppendBackupEntries lists what this tool has already removed. Without it a
// disabled handler would simply vanish from the page and there would be no way
// left in the UI to bring it back.
void AppendBackupEntries(ContextMenuScanResult& result) {
    const std::vector<std::wstring> tokens = EnumerateSubKeyNames(HKEY_LOCAL_MACHINE, kBackupRoot);
    for (const std::wstring& token : tokens) {
        const std::wstring backupKey = std::wstring(kBackupRoot) + L"\\" + token;
        ContextMenuEntry entry{};
        entry.enabled = false;
        entry.backupKeyName = token;
        entry.registrationPath = ReadRegistryString(HKEY_LOCAL_MACHINE, backupKey, kBackupSourceValue);
        entry.scopeText = ReadRegistryString(HKEY_LOCAL_MACHINE, backupKey, kBackupScopeValue);
        entry.name = ReadRegistryString(HKEY_LOCAL_MACHINE, backupKey, kBackupNameValue);
        DWORD kind = 0;
        DWORD kindSize = sizeof(kind);
        if (::RegGetValueW(HKEY_LOCAL_MACHINE, backupKey.c_str(), kBackupKindValue,
                RRF_RT_REG_DWORD, nullptr, &kind, &kindSize) == ERROR_SUCCESS) {
            entry.kind = kind == 1 ? ContextMenuKind::ShellVerb : ContextMenuKind::ShellExHandler;
        }
        const std::wstring dataKey = backupKey + L"\\" + kBackupDataSubKey;
        entry.clsid = TrimQuotes(ReadRegistryString(HKEY_LOCAL_MACHINE, dataKey, nullptr));
        const std::wstring backedUpAt = ReadRegistryString(HKEY_LOCAL_MACHINE, backupKey, kBackupTimeValue);
        entry.diagnosticText = backedUpAt.empty()
            ? L"已备份并从 HKCR 移除。"
            : L"已于 " + backedUpAt + L" 备份并从 HKCR 移除。";
        if (entry.registrationPath.empty()) {
            entry.registrationPath = token;
            entry.diagnosticText += L" 备份项缺少 SourcePath，无法自动还原。";
        }
        if (entry.name.empty()) {
            const std::size_t separator = entry.registrationPath.find_last_of(L'\\');
            entry.name = separator == std::wstring::npos
                ? entry.registrationPath
                : entry.registrationPath.substr(separator + 1);
        }
        result.entries.push_back(std::move(entry));
    }
}

} // namespace

std::wstring ContextMenuBackupRootPath() {
    return std::wstring(L"HKEY_LOCAL_MACHINE\\") + kBackupRoot;
}

ContextMenuScanResult ScanContextMenuEntries() {
    ContextMenuScanResult result{};
    result.elevated = ks::r3::common::IsRunningAsAdmin();

    for (const RegistrationRoot& root : kRegistrationRoots) {
        const std::vector<std::wstring> names = EnumerateSubKeyNames(HKEY_CLASSES_ROOT, root.path);
        for (const std::wstring& name : names) {
            ContextMenuEntry entry{};
            entry.kind = root.kind;
            entry.scopeText = root.scope;
            entry.name = name;
            entry.registrationPath = std::wstring(root.path) + L"\\" + name;
            if (root.kind == ContextMenuKind::ShellExHandler) {
                ResolveClsidDetails(entry, ReadRegistryString(HKEY_CLASSES_ROOT, entry.registrationPath, nullptr));
            } else {
                ResolveVerbDetails(entry, entry.registrationPath);
            }
            if (entry.displayText.empty()) {
                entry.displayText = name;
            }
            result.entries.push_back(std::move(entry));
        }
    }

    AppendBackupEntries(result);
    result.success = true;
    if (!result.elevated) {
        result.diagnosticText = L"当前未以管理员运行，禁用/启用会因权限不足失败。";
    }
    return result;
}

ContextMenuActionResult DisableContextMenuEntry(const ContextMenuEntry& entry) {
    ContextMenuActionResult result{};
    if (!entry.enabled) {
        result.message = L"该项已处于禁用状态。";
        return result;
    }
    if (entry.registrationPath.empty()) {
        result.message = L"注册路径为空，拒绝执行删除。";
        return result;
    }

    HKEY source = nullptr;
    LSTATUS status = ::RegOpenKeyExW(HKEY_CLASSES_ROOT, entry.registrationPath.c_str(), 0, KEY_READ, &source);
    if (status != ERROR_SUCCESS) {
        result.message = L"打开源注册项失败：" + ErrorText(status);
        return result;
    }

    const std::wstring token = BackupTokenFor(entry.registrationPath);
    const std::wstring backupKeyPath = std::wstring(kBackupRoot) + L"\\" + token;
    HKEY backupKey = nullptr;
    status = ::RegCreateKeyExW(HKEY_LOCAL_MACHINE, backupKeyPath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &backupKey, nullptr);
    if (status != ERROR_SUCCESS) {
        ::RegCloseKey(source);
        result.message = L"创建备份键失败（通常是未以管理员运行）：" + ErrorText(status);
        return result;
    }

    HKEY dataKey = nullptr;
    status = ::RegCreateKeyExW(backupKey, kBackupDataSubKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &dataKey, nullptr);
    if (status != ERROR_SUCCESS) {
        ::RegCloseKey(backupKey);
        ::RegCloseKey(source);
        result.message = L"创建备份数据键失败：" + ErrorText(status);
        return result;
    }

    // The copy has to succeed before anything is deleted; a half-written backup
    // followed by a successful delete would be an unrecoverable loss.
    status = ::RegCopyTreeW(source, nullptr, dataKey);
    ::RegCloseKey(dataKey);
    ::RegCloseKey(source);
    if (status != ERROR_SUCCESS) {
        ::RegCloseKey(backupKey);
        ::RegDeleteTreeW(HKEY_LOCAL_MACHINE, backupKeyPath.c_str());
        result.message = L"备份注册子树失败，未执行删除：" + ErrorText(status);
        return result;
    }

    const std::wstring timestamp = CurrentTimestampText();
    const DWORD kind = entry.kind == ContextMenuKind::ShellVerb ? 1u : 0u;
    ::RegSetValueExW(backupKey, kBackupSourceValue, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(entry.registrationPath.c_str()),
        static_cast<DWORD>((entry.registrationPath.size() + 1) * sizeof(wchar_t)));
    ::RegSetValueExW(backupKey, kBackupTimeValue, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(timestamp.c_str()),
        static_cast<DWORD>((timestamp.size() + 1) * sizeof(wchar_t)));
    ::RegSetValueExW(backupKey, kBackupScopeValue, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(entry.scopeText.c_str()),
        static_cast<DWORD>((entry.scopeText.size() + 1) * sizeof(wchar_t)));
    ::RegSetValueExW(backupKey, kBackupNameValue, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(entry.name.c_str()),
        static_cast<DWORD>((entry.name.size() + 1) * sizeof(wchar_t)));
    ::RegSetValueExW(backupKey, kBackupKindValue, 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&kind), sizeof(kind));
    ::RegCloseKey(backupKey);

    status = ::RegDeleteTreeW(HKEY_CLASSES_ROOT, entry.registrationPath.c_str());
    if (status != ERROR_SUCCESS) {
        // The backup is kept on failure: it is the only record that the delete
        // was attempted, and it costs nothing to leave in place.
        result.message = L"删除注册项失败（备份已保留）：" + ErrorText(status);
        return result;
    }

    result.success = true;
    result.message = L"已备份到 " + ContextMenuBackupRootPath() + L"\\" + token + L" 并从 HKCR 删除。";
    return result;
}

ContextMenuActionResult EnableContextMenuEntry(const ContextMenuEntry& entry) {
    ContextMenuActionResult result{};
    if (entry.enabled) {
        result.message = L"该项当前已启用。";
        return result;
    }
    const std::wstring token = entry.backupKeyName.empty()
        ? BackupTokenFor(entry.registrationPath)
        : entry.backupKeyName;
    const std::wstring backupKeyPath = std::wstring(kBackupRoot) + L"\\" + token;
    const std::wstring sourcePath = ReadRegistryString(HKEY_LOCAL_MACHINE, backupKeyPath, kBackupSourceValue);
    if (sourcePath.empty()) {
        result.message = L"备份项缺少 SourcePath，无法确定还原位置。";
        return result;
    }

    HKEY dataKey = nullptr;
    LSTATUS status = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        (backupKeyPath + L"\\" + kBackupDataSubKey).c_str(), 0, KEY_READ, &dataKey);
    if (status != ERROR_SUCCESS) {
        result.message = L"打开备份数据键失败：" + ErrorText(status);
        return result;
    }

    HKEY destination = nullptr;
    status = ::RegCreateKeyExW(HKEY_CLASSES_ROOT, sourcePath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &destination, nullptr);
    if (status != ERROR_SUCCESS) {
        ::RegCloseKey(dataKey);
        result.message = L"创建还原目标键失败（通常是未以管理员运行）：" + ErrorText(status);
        return result;
    }

    status = ::RegCopyTreeW(dataKey, nullptr, destination);
    ::RegCloseKey(destination);
    ::RegCloseKey(dataKey);
    if (status != ERROR_SUCCESS) {
        result.message = L"还原注册子树失败：" + ErrorText(status);
        return result;
    }

    // Only now is the backup redundant. Removing it earlier would open a window
    // where neither the live key nor the backup holds the full subtree.
    const LSTATUS cleanup = ::RegDeleteTreeW(HKEY_LOCAL_MACHINE, backupKeyPath.c_str());
    result.success = true;
    result.message = cleanup == ERROR_SUCCESS
        ? L"已还原到 HKCR\\" + sourcePath + L" 并清除备份。"
        : L"已还原到 HKCR\\" + sourcePath + L"，但备份清理失败：" + ErrorText(cleanup);
    return result;
}

} // namespace ks::r3::system_tools
