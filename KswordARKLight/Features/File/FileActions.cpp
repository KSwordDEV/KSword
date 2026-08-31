#include "FileActions.h"

#include "PathNavigator.h"

#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../../../Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.h"

#include <commdlg.h>
#include <filesystem>
#include <objbase.h>
#include <Aclapi.h>
#include <restartmanager.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <new>
#include <sstream>
#include <vector>

namespace Ksword::Features::File {
namespace {


// Utf8ToWide converts ArkDriverClient narrow diagnostics to UTF-16 UI text.
// Input is the driver-client message; processing uses strict UTF-8 first and a
// byte-wise fallback; output is safe for status labels and message boxes.
std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    const int required = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (required > 0) {
        std::wstring wide(static_cast<std::size_t>(required), L'\0');
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), wide.data(), required);
        return wide;
    }

    std::wstring fallback;
    fallback.reserve(text.size());
    for (const unsigned char ch : text) {
        fallback.push_back(static_cast<wchar_t>(ch));
    }
    return fallback;
}

// EnablePrivilege turns on one token privilege for the current process. Input is
// a privilege name such as SE_TAKE_OWNERSHIP_NAME; processing uses
// OpenProcessToken/AdjustTokenPrivileges; output reports whether the privilege
// is now enabled for the attempted operation.
bool EnablePrivilege(const wchar_t* privilegeName) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    if (!::LookupPrivilegeValueW(nullptr, privilegeName, &privileges.Privileges[0].Luid)) {
        ::CloseHandle(token);
        return false;
    }
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL adjusted = ::AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    const DWORD error = ::GetLastError();
    ::CloseHandle(token);
    return adjusted && error == ERROR_SUCCESS;
}

// HexText formats driver diagnostic addresses. Input is a 64-bit value; output
// is a compact uppercase hexadecimal string for result summaries.
std::wstring HexText(std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// BuildDriverNtPath mirrors the original FileDock conversion before calling R0.
// Inputs are Win32, extended-length, UNC, or existing NT-style paths; processing
// normalizes separators and applies the shared driver path convention; output is
// empty only when input is empty.
std::wstring BuildDriverNtPath(const std::wstring& path) {
    std::wstring nativePath = path;
    while (!nativePath.empty() && (nativePath.back() == L' ' || nativePath.back() == L'\t' || nativePath.back() == L'\r' || nativePath.back() == L'\n')) {
        nativePath.pop_back();
    }
    std::size_t first = 0;
    while (first < nativePath.size() && (nativePath[first] == L' ' || nativePath[first] == L'\t' || nativePath[first] == L'\r' || nativePath[first] == L'\n')) {
        ++first;
    }
    if (first > 0) {
        nativePath.erase(0, first);
    }
    for (wchar_t& ch : nativePath) {
        if (ch == L'/') {
            ch = L'\\';
        }
    }
    if (nativePath.empty()) {
        return {};
    }
    if (nativePath.rfind(L"\\??\\", 0) == 0) {
        return nativePath;
    }
    if (nativePath.rfind(L"\\\\?\\", 0) == 0) {
        return L"\\??\\" + nativePath.substr(4);
    }
    if (nativePath.rfind(L"\\Device\\", 0) == 0) {
        return nativePath;
    }
    if (nativePath.rfind(L"\\\\", 0) == 0) {
        return L"\\??\\UNC\\" + nativePath.substr(2);
    }
    return L"\\??\\" + nativePath;
}

// SectionKindText converts KSWORD_ARK_FILE_SECTION_KIND_* into display text.
// Input is a shared-protocol enum value; output is concise row text.
const wchar_t* SectionKindText(std::uint32_t value) {
    switch (value) {
    case KSWORD_ARK_FILE_SECTION_KIND_DATA: return L"Data";
    case KSWORD_ARK_FILE_SECTION_KIND_IMAGE: return L"Image";
    default: return L"Unknown";
    }
}

// ViewMapTypeText converts KSWORD_ARK_SECTION_MAP_TYPE_* into display text.
// Input is a shared-protocol mapping type; output is concise row text.
const wchar_t* ViewMapTypeText(std::uint32_t value) {
    switch (value) {
    case KSWORD_ARK_SECTION_MAP_TYPE_PROCESS: return L"Process";
    case KSWORD_ARK_SECTION_MAP_TYPE_SESSION: return L"Session";
    case KSWORD_ARK_SECTION_MAP_TYPE_SYSTEM_CACHE: return L"SystemCache";
    default: return L"Unknown";
    }
}

// FileSectionStatusText converts the R0 file-section query status. Input is a
// KSWORD_ARK_FILE_SECTION_QUERY_STATUS_* value; output matches the original UI
// diagnostics without depending on framework helpers.
const wchar_t* FileSectionStatusText(std::uint32_t value) {
    switch (value) {
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_OK: return L"OK";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_DYNDATA_MISSING: return L"DynData Missing";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OPEN_FAILED: return L"File Open Failed";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OBJECT_FAILED: return L"FileObject Failed";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_SECTION_POINTERS_MISSING: return L"SectionObjectPointer Missing";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_CONTROL_AREA_MISSING: return L"ControlArea Missing";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_MAPPING_QUERY_FAILED: return L"Mapping Query Failed";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_BUFFER_TOO_SMALL: return L"Buffer Too Small";
    default: return L"Unavailable";
    }
}

// SelectedPath returns the selected row's full path or an empty string. Input is
// a menu context; output is safe for Win32 APIs that require LPCWSTR paths.
std::wstring SelectedPath(const FileActionContext& context) {
    return context.hasSelection ? context.selectedEntry.fullPath : std::wstring{};
}

// ShellOpenPath delegates a path to ShellExecuteW. Inputs are owner/path; output
// is true when ShellExecuteW reports a value above 32.
bool ShellOpenPath(HWND owner, const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    const HINSTANCE rc = ::ShellExecuteW(owner, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(rc) > 32;
}

// OpenTerminalAtDirectory starts wt.exe or cmd.exe in a directory. Inputs are
// owner/current directory; processing never blocks waiting for the process;
// output is true if one ShellExecuteW launch succeeds.
bool OpenTerminalAtDirectory(HWND owner, const std::wstring& directory) {
    const std::wstring cwd = directory.empty() ? L"C:\\" : directory;
    HINSTANCE rc = ::ShellExecuteW(owner, L"open", L"wt.exe", nullptr, cwd.c_str(), SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(rc) > 32) {
        return true;
    }
    rc = ::ShellExecuteW(owner, L"open", L"cmd.exe", nullptr, cwd.c_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(rc) > 32;
}

// ShortPathForFile returns the DOS 8.3 path when the volume provides one. Input
// is a full path; output is empty when GetShortPathNameW fails.
std::wstring ShortPathForFile(const std::wstring& path) {
    const DWORD needed = ::GetShortPathNameW(path.c_str(), nullptr, 0);
    if (needed == 0) {
        return {};
    }
    std::wstring shortPath(needed + 1, L'\0');
    const DWORD written = ::GetShortPathNameW(path.c_str(), shortPath.data(), static_cast<DWORD>(shortPath.size()));
    if (written == 0 || written >= shortPath.size()) {
        return {};
    }
    shortPath.resize(written);
    return shortPath;
}

// ResolveLinkTarget reads a shell link target using IShellLink/IPersistFile.
// Input is a selected .lnk path; output is the resolved path or empty on
// unsupported file types/failures.
std::wstring ResolveLinkTarget(const std::wstring& path) {
    if (path.size() < 4 || _wcsicmp(path.c_str() + path.size() - 4, L".lnk") != 0) {
        return {};
    }
    const HRESULT initResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    const bool uninitializeCom = initResult == S_OK || initResult == S_FALSE;
    IShellLinkW* shellLink = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&shellLink));
    if (FAILED(hr) || shellLink == nullptr) {
        if (uninitializeCom) {
            ::CoUninitialize();
        }
        return {};
    }
    IPersistFile* persistFile = nullptr;
    hr = shellLink->QueryInterface(IID_PPV_ARGS(&persistFile));
    if (FAILED(hr) || persistFile == nullptr) {
        shellLink->Release();
        if (uninitializeCom) {
            ::CoUninitialize();
        }
        return {};
    }
    std::wstring target(MAX_PATH, L'\0');
    hr = persistFile->Load(path.c_str(), STGM_READ);
    if (SUCCEEDED(hr)) {
        WIN32_FIND_DATAW data{};
        hr = shellLink->GetPath(target.data(), static_cast<int>(target.size()), &data, SLGP_UNCPRIORITY);
    }
    persistFile->Release();
    shellLink->Release();
    if (uninitializeCom) {
        ::CoUninitialize();
    }
    if (FAILED(hr)) {
        return {};
    }
    target.resize(std::wcslen(target.c_str()));
    return target;
}

// ParentDirectoryOf returns the parent folder for a full path. Input is a file
// or directory path; output is empty if no separator exists.
std::wstring ParentDirectoryOf(const std::wstring& path) {
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return {};
    }
    return path.substr(0, slash);
}

// DisplayNameFromPath returns the leaf file name. Input is a full path; output
// is the whole input when no separator exists.
std::wstring DisplayNameFromPath(const std::wstring& path) {
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos || slash + 1 >= path.size()) {
        return path;
    }
    return path.substr(slash + 1);
}

// PickTargetFolder shows the standard shell folder picker. Inputs are the owner
// HWND and dialog title; processing uses IFileDialog with FOS_PICKFOLDERS so the
// file page stays Windows-API-only; output is the selected filesystem path or
// empty when the user cancels or the shell cannot resolve a path.
std::wstring PickTargetFolder(HWND owner, const wchar_t* title) {
    const HRESULT initResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    const bool uninitializeCom = initResult == S_OK || initResult == S_FALSE;
    IFileDialog* dialog = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog));
    if (FAILED(hr) || dialog == nullptr) {
        if (uninitializeCom) {
            ::CoUninitialize();
        }
        return {};
    }

    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    dialog->SetTitle(title);
    std::wstring selectedPath;
    hr = dialog->Show(owner);
    if (SUCCEEDED(hr)) {
        IShellItem* item = nullptr;
        hr = dialog->GetResult(&item);
        if (SUCCEEDED(hr) && item != nullptr) {
            PWSTR path = nullptr;
            hr = item->GetDisplayName(SIGDN_FILESYSPATH, &path);
            if (SUCCEEDED(hr) && path != nullptr) {
                selectedPath = path;
                ::CoTaskMemFree(path);
            }
            item->Release();
        }
    }
    dialog->Release();
    if (uninitializeCom) {
        ::CoUninitialize();
    }
    return selectedPath;
}

// CopyOrMovePathToFolder copies or moves the selected path into a user-selected
// target folder. Inputs are source path, destination directory, and move flag;
// processing uses std::filesystem so both files and directories are covered;
// output is a FileActionResult-style status through statusOut and a success bit.
bool CopyOrMovePathToFolder(
    const std::wstring& sourcePath,
    const std::wstring& targetFolder,
    bool move,
    std::wstring& statusOut) {
    if (sourcePath.empty() || targetFolder.empty()) {
        statusOut = L"源路径或目标文件夹为空。";
        return false;
    }

    std::error_code error;
    const std::filesystem::path source(sourcePath);
    const std::filesystem::path target = std::filesystem::path(targetFolder) / source.filename();
    if (move) {
        std::filesystem::rename(source, target, error);
        if (error) {
            std::filesystem::copy(source, target, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, error);
            if (!error) {
                std::filesystem::remove_all(source, error);
            }
        }
    } else {
        std::filesystem::copy(source, target, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, error);
    }

    if (error) {
        statusOut = std::wstring(move ? L"移动失败: " : L"复制失败: ") + std::wstring(error.message().begin(), error.message().end());
        return false;
    }
    statusOut = std::wstring(move ? L"已移动到: " : L"已复制到: ") + target.wstring();
    return true;
}

// TakeOwnershipPath sets the selected file or directory owner to the current
// user. Inputs are a Win32 path and owner HWND only for diagnostics; processing
// enables SeTakeOwnershipPrivilege and calls SetNamedSecurityInfoW; output is a
// concise status message for the File page.
std::wstring TakeOwnershipPath(const std::wstring& path) {
    if (path.empty()) {
        return L"路径为空，无法取得所有权。";
    }
    const bool privilegeEnabled = EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);

    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return L"OpenProcessToken 失败，错误 " + std::to_wstring(::GetLastError());
    }

    DWORD bytes = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    std::vector<BYTE> buffer(bytes);
    if (bytes == 0 || !::GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes)) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(token);
        return L"GetTokenInformation(TokenUser) 失败，错误 " + std::to_wstring(error);
    }
    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    const DWORD result = ::SetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        tokenUser->User.Sid,
        nullptr,
        nullptr,
        nullptr);
    ::CloseHandle(token);

    if (result == ERROR_SUCCESS) {
        return std::wstring(L"已取得所有权。") + (privilegeEnabled ? L"" : L"（SeTakeOwnershipPrivilege 未显式启用，但操作成功。）");
    }
    return std::wstring(L"取得所有权失败，错误 ") + std::to_wstring(result) +
        (privilegeEnabled ? L"" : L"；同时无法启用 SeTakeOwnershipPrivilege。");
}

// QueryFileLockers uses Restart Manager to list processes that currently hold
// the selected path. Inputs are a filesystem path; processing starts a temporary
// RM session and registers the file resource; output is a text report. It does
// not kill or unlock processes in the light build.
std::wstring QueryFileLockers(const std::wstring& path) {
    if (path.empty()) {
        return L"路径为空，无法扫描占用进程。";
    }

    DWORD session = 0;
    wchar_t sessionKey[CCH_RM_SESSION_KEY + 1]{};
    DWORD status = ::RmStartSession(&session, 0, sessionKey);
    if (status != ERROR_SUCCESS) {
        return L"RmStartSession 失败，错误 " + std::to_wstring(status);
    }

    const wchar_t* resources[] = { path.c_str() };
    status = ::RmRegisterResources(session, 1, resources, 0, nullptr, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        ::RmEndSession(session);
        return L"RmRegisterResources 失败，错误 " + std::to_wstring(status);
    }

    UINT needed = 0;
    UINT count = 0;
    DWORD reason = 0;
    status = ::RmGetList(session, &needed, &count, nullptr, &reason);
    std::vector<RM_PROCESS_INFO> processes(needed == 0 ? 1 : needed);
    count = static_cast<UINT>(processes.size());
    if (status == ERROR_MORE_DATA || status == ERROR_SUCCESS) {
        status = ::RmGetList(session, &needed, &count, processes.data(), &reason);
    }
    ::RmEndSession(session);

    if (status != ERROR_SUCCESS) {
        return L"RmGetList 失败，错误 " + std::to_wstring(status);
    }

    std::wostringstream report;
    report << L"文件解锁器(R3/R0) - Restart Manager 占用扫描\r\n\r\n"
           << L"目标: " << path << L"\r\n"
           << L"占用进程数: " << count << L"\r\n"
           << L"RebootReason: 0x" << std::hex << std::uppercase << reason << L"\r\n\r\n";
    if (count == 0) {
        report << L"未发现 Restart Manager 可见的占用进程。";
        return report.str();
    }
    for (UINT index = 0; index < count && index < processes.size(); ++index) {
        const RM_PROCESS_INFO& process = processes[index];
        report << L"PID=" << std::dec << process.Process.dwProcessId
               << L" App=" << process.strAppName
               << L" Service=" << process.strServiceShortName
               << L" Type=" << process.ApplicationType
               << L" Status=0x" << std::hex << std::uppercase << process.AppStatus
               << L"\r\n";
    }
    report << L"\r\n轻量版仅枚举占用者，不执行强制关闭/解锁。";
    return report.str();
}

// PromptForText uses a simple InputBox.exe fallback-free edit dialog based on
// DialogBoxIndirectParamW would be overkill here; instead it asks through a
// common save-file dialog seeded to the current parent. Input is the original
// path; output is the chosen destination path or empty when cancelled.
std::wstring PromptRenameTarget(HWND owner, const std::wstring& originalPath) {
    wchar_t path[MAX_PATH]{};
    const std::wstring leaf = DisplayNameFromPath(originalPath);
    const std::wstring parent = ParentDirectoryOf(originalPath);
    if (leaf.size() < std::size(path)) {
        ::wcsncpy_s(path, std::size(path), leaf.c_str(), _TRUNCATE);
    }
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFile = path;
    ofn.nMaxFile = static_cast<DWORD>(std::size(path));
    ofn.lpstrInitialDir = parent.empty() ? nullptr : parent.c_str();
    ofn.lpstrTitle = L"重命名为";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    if (!::GetSaveFileNameW(&ofn)) {
        return {};
    }
    return std::wstring(path);
}

// BytesToHex formats a binary buffer as uppercase hex. Input is bytes; output is
// compact text for hashes and previews.
std::wstring BytesToHex(const BYTE* data, DWORD bytes) {
    std::wostringstream stream;
    stream << std::uppercase << std::hex << std::setfill(L'0');
    for (DWORD index = 0; index < bytes; ++index) {
        stream << std::setw(2) << static_cast<unsigned int>(data[index]);
    }
    return stream.str();
}

// ComputeSha256 hashes a file using CryptoAPI. Input is file path; output is
// hash text or empty; errorOut receives a compact diagnostic when provided.
std::wstring ComputeSha256(const std::wstring& path, std::wstring* errorOut) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (errorOut) {
            *errorOut = L"CreateFileW error " + std::to_wstring(::GetLastError());
        }
        return {};
    }
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    if (!::CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !::CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        const DWORD error = ::GetLastError();
        if (hash) {
            ::CryptDestroyHash(hash);
        }
        if (provider) {
            ::CryptReleaseContext(provider, 0);
        }
        ::CloseHandle(file);
        if (errorOut) {
            *errorOut = L"CryptoAPI error " + std::to_wstring(error);
        }
        return {};
    }
    BYTE buffer[64 * 1024]{};
    DWORD read = 0;
    bool ok = true;
    while (::ReadFile(file, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        if (!::CryptHashData(hash, buffer, read, 0)) {
            ok = false;
            break;
        }
    }
    DWORD hashBytes = 32;
    BYTE hashValue[32]{};
    if (ok) {
        ok = ::CryptGetHashParam(hash, HP_HASHVAL, hashValue, &hashBytes, 0) != FALSE;
    }
    const DWORD error = ok ? ERROR_SUCCESS : ::GetLastError();
    ::CryptDestroyHash(hash);
    ::CryptReleaseContext(provider, 0);
    ::CloseHandle(file);
    if (!ok) {
        if (errorOut) {
            *errorOut = L"Hash read error " + std::to_wstring(error);
        }
        return {};
    }
    return BytesToHex(hashValue, hashBytes);
}

// ComputeFileEntropy samples a file and computes byte entropy. Inputs are path
// and max bytes; output is bits-per-byte, or negative on failure.
double ComputeFileEntropy(const std::wstring& path, std::uint64_t maxBytes, std::uint64_t* sampledOut) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return -1.0;
    }
    std::uint64_t counts[256]{};
    BYTE buffer[64 * 1024]{};
    DWORD read = 0;
    std::uint64_t total = 0;
    while (total < maxBytes && ::ReadFile(file, buffer, static_cast<DWORD>(std::min<std::uint64_t>(sizeof(buffer), maxBytes - total)), &read, nullptr) && read > 0) {
        for (DWORD index = 0; index < read; ++index) {
            ++counts[buffer[index]];
        }
        total += read;
    }
    ::CloseHandle(file);
    if (sampledOut) {
        *sampledOut = total;
    }
    if (total == 0) {
        return 0.0;
    }
    double entropy = 0.0;
    for (std::uint64_t count : counts) {
        if (count == 0) {
            continue;
        }
        const double p = static_cast<double>(count) / static_cast<double>(total);
        entropy -= p * (std::log(p) / std::log(2.0));
    }
    return entropy;
}

// HexPreview reads the first bytes of a file and returns a small hex/ascii dump.
// Input is path and byte limit; output is display text or empty on failure.
std::wstring HexPreview(const std::wstring& path, DWORD maxBytes) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return {};
    }
    std::vector<BYTE> buffer(maxBytes);
    DWORD read = 0;
    const BOOL ok = ::ReadFile(file, buffer.data(), maxBytes, &read, nullptr);
    ::CloseHandle(file);
    if (!ok) {
        return {};
    }
    std::wostringstream dump;
    dump << std::uppercase << std::hex << std::setfill(L'0');
    for (DWORD offset = 0; offset < read; offset += 16) {
        dump << std::setw(8) << offset << L"  ";
        for (DWORD index = 0; index < 16; ++index) {
            if (offset + index < read) {
                dump << std::setw(2) << static_cast<unsigned int>(buffer[offset + index]) << L' ';
            } else {
                dump << L"   ";
            }
        }
        dump << L" ";
        for (DWORD index = 0; index < 16 && offset + index < read; ++index) {
            const BYTE ch = buffer[offset + index];
            dump << (ch >= 32 && ch < 127 ? static_cast<wchar_t>(ch) : L'.');
        }
        dump << L"\r\n";
    }
    return dump.str();
}

// VerifyEmbeddedSignature checks Authenticode trust through WinVerifyTrust.
// Inputs are the selected file path; processing asks the OS trust provider
// without UI; output is a compact status line for the retained signature menu.
std::wstring VerifyEmbeddedSignature(const std::wstring& path) {
    if (path.empty()) {
        return L"路径为空，无法检查签名。";
    }

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = ::WinVerifyTrust(nullptr, &policy, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)::WinVerifyTrust(nullptr, &policy, &trustData);

    if (status == ERROR_SUCCESS) {
        return L"数字签名验证通过。";
    }
    if (status == TRUST_E_NOSIGNATURE) {
        return L"文件没有嵌入式 Authenticode 签名。";
    }
    if (status == CERT_E_EXPIRED) {
        return L"数字签名证书已过期。";
    }
    if (status == TRUST_E_BAD_DIGEST) {
        return L"数字签名摘要不匹配，文件可能已被修改。";
    }
    return L"数字签名验证失败，状态 0x" + HexText(static_cast<std::uint32_t>(status));
}

// BuildPeHeaderSummary preserves Lite's original small PE-header reader. It
// deliberately reads only the DOS/NT/File/Optional header fields, so callers
// can still inspect files which are unsuitable for the bounded deep parser.
std::wstring BuildPeHeaderSummary(const std::wstring& path) {
    HANDLE file = ::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return L"打开文件失败，错误 " + std::to_wstring(::GetLastError());
    }

    IMAGE_DOS_HEADER dos{};
    DWORD read = 0;
    if (!::ReadFile(file, &dos, sizeof(dos), &read, nullptr) ||
        read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        ::CloseHandle(file);
        return L"不是有效的 PE 文件：DOS 头无效。";
    }
    if (::SetFilePointer(file, dos.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
        ::GetLastError() != ERROR_SUCCESS) {
        ::CloseHandle(file);
        return L"定位 NT 头失败，错误 " + std::to_wstring(::GetLastError());
    }

    DWORD signature = 0;
    IMAGE_FILE_HEADER fileHeader{};
    if (!::ReadFile(file, &signature, sizeof(signature), &read, nullptr) ||
        read != sizeof(signature) || signature != IMAGE_NT_SIGNATURE ||
        !::ReadFile(file, &fileHeader, sizeof(fileHeader), &read, nullptr) ||
        read != sizeof(fileHeader)) {
        ::CloseHandle(file);
        return L"不是有效的 PE 文件：NT 头无效。";
    }

    WORD optionalMagic = 0;
    if (!::ReadFile(file, &optionalMagic, sizeof(optionalMagic), &read, nullptr) ||
        read != sizeof(optionalMagic)) {
        ::CloseHandle(file);
        return L"读取 OptionalHeader 失败。";
    }
    ::CloseHandle(file);

    std::wostringstream text;
    text << L"PE 头部摘要\r\n\r\n"
         << L"Machine: 0x" << std::hex << std::uppercase << fileHeader.Machine << L"\r\n"
         << L"Sections: " << std::dec << fileHeader.NumberOfSections << L"\r\n"
         << L"TimeDateStamp: 0x" << std::hex << std::uppercase << fileHeader.TimeDateStamp << L"\r\n"
         << L"Characteristics: 0x" << std::hex << std::uppercase << fileHeader.Characteristics << L"\r\n"
         << L"OptionalHeader.Magic: 0x" << std::hex << std::uppercase << optionalMagic
         << (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? L" (PE32+)" :
             optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? L" (PE32)" : L"") << L"\r\n\r\n"
         << L"KswordARKLight 仅显示轻量 PE 摘要；完整属性页已按要求移除。";
    return text.str();
}

constexpr std::uint64_t kLitePeStaticMaxFileBytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::size_t kLitePeStaticMaxSectionRows = 32;
constexpr std::size_t kLitePeStaticMaxImportModuleRows = 64;
constexpr std::size_t kLitePeStaticMaxDisplayChars = 240;

struct PeStaticSummaryResult {
    bool success = false;
    bool partial = true;
    std::wstring text;
};

// IsLiteralDosOrUncFilePath gates only the bounded deep parser. Other paths
// retain the original header-only reader through the compatibility fallback.
bool IsLiteralDosOrUncFilePath(const std::wstring& path) {
    const auto isAsciiLetter = [](const wchar_t value) {
        return (value >= L'A' && value <= L'Z') || (value >= L'a' && value <= L'z');
    };
    if (path.size() >= 3 && isAsciiLetter(path[0]) && path[1] == L':' &&
        (path[2] == L'\\' || path[2] == L'/')) {
        return true;
    }

    if (path.size() < 5 || path[0] != L'\\' || path[1] != L'\\' ||
        path[2] == L'?' || path[2] == L'.') {
        return false;
    }

    const std::size_t serverEnd = path.find_first_of(L"\\/", 2);
    if (serverEnd == std::wstring::npos || serverEnd == 2) {
        return false;
    }
    const std::size_t shareStart = serverEnd + 1;
    if (shareStart >= path.size()) {
        return false;
    }
    const std::size_t shareEnd = path.find_first_of(L"\\/", shareStart);
    return shareEnd == std::wstring::npos || shareEnd > shareStart;
}

// ReadLitePeSnapshot obtains one bounded byte snapshot before the shared PE
// parser runs. The explicit 16 MiB ceiling matches Lite's existing entropy
// action and prevents the parser from reopening a larger replacement file.
bool ReadLitePeSnapshot(
    const std::wstring& path,
    std::vector<std::uint8_t>& bytesOut,
    std::uint64_t& sizeOut,
    std::wstring& errorOut) {
    bytesOut.clear();
    sizeOut = 0;
    errorOut.clear();

    HANDLE file = ::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        errorOut = L"打开文件失败，错误 " + std::to_wstring(::GetLastError()) + L"。";
        return false;
    }

    LARGE_INTEGER fileSize{};
    if (::GetFileSizeEx(file, &fileSize) == FALSE || fileSize.QuadPart < 0) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(file);
        errorOut = L"获取文件大小失败，错误 " + std::to_wstring(error) + L"。";
        return false;
    }
    if (static_cast<std::uint64_t>(fileSize.QuadPart) > kLitePeStaticMaxFileBytes) {
        ::CloseHandle(file);
        errorOut = L"文件大小为 " + std::to_wstring(fileSize.QuadPart) +
            L" bytes，超过 Lite PE 静态摘要的 16 MiB 上限。";
        return false;
    }

    try {
        bytesOut.resize(static_cast<std::size_t>(fileSize.QuadPart));
    } catch (const std::bad_alloc&) {
        ::CloseHandle(file);
        bytesOut.clear();
        errorOut = L"无法为受限 PE 快照分配内存。";
        return false;
    }

    std::size_t totalRead = 0;
    while (totalRead < bytesOut.size()) {
        const std::size_t remaining = bytesOut.size() - totalRead;
        const DWORD requestSize = static_cast<DWORD>(std::min<std::size_t>(remaining, 1024U * 1024U));
        DWORD read = 0;
        if (::ReadFile(file, bytesOut.data() + totalRead, requestSize, &read, nullptr) == FALSE) {
            const DWORD error = ::GetLastError();
            ::CloseHandle(file);
            bytesOut.clear();
            errorOut = L"读取文件失败，错误 " + std::to_wstring(error) + L"。";
            return false;
        }
        if (read == 0) {
            ::CloseHandle(file);
            bytesOut.clear();
            errorOut = L"文件在读取期间提前结束或发生变化。";
            return false;
        }
        totalRead += read;
    }

    ::CloseHandle(file);
    sizeOut = static_cast<std::uint64_t>(fileSize.QuadPart);
    return true;
}

// SingleLinePreview bounds and normalizes untrusted names and diagnostics from
// the file. The result is safe for one MessageBox row rather than a full report.
std::wstring SingleLinePreview(std::wstring text, const std::size_t maxChars) {
    for (wchar_t& character : text) {
        if (character == L'\r' || character == L'\n' || character == L'\t' ||
            character < L' ' || character == 0x7F) {
            character = L' ';
        }
    }
    if (text.size() > maxChars) {
        text.resize(maxChars);
        text += L"...";
    }
    return text;
}

// BuildPeHeaderFallback keeps the pre-existing PE-header capability whenever
// Lite's bounded deep analysis cannot safely cover the selected file.
PeStaticSummaryResult BuildPeHeaderFallback(const std::wstring& path, const std::wstring& reason) {
    PeStaticSummaryResult result;
    result.success = true;
    result.partial = true;
    result.text = L"PE 静态摘要（Partial）\r\n\r\n"
        L"深度解析未完成：" + SingleLinePreview(reason, kLitePeStaticMaxDisplayChars) +
        L"\r\n\r\n已保留兼容的轻量 PE 头部摘要：\r\n\r\n" + BuildPeHeaderSummary(path);
    return result;
}

std::wstring PeMachineText(const std::uint16_t machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386: return L"x86";
    case IMAGE_FILE_MACHINE_AMD64: return L"x64";
    case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
    case IMAGE_FILE_MACHINE_ARM: return L"ARM";
    case IMAGE_FILE_MACHINE_ARMNT: return L"ARMNT";
    case IMAGE_FILE_MACHINE_IA64: return L"IA64";
    default: return L"Unknown";
    }
}

std::wstring PeSubsystemText(const std::uint16_t subsystem) {
    switch (subsystem) {
    case IMAGE_SUBSYSTEM_NATIVE: return L"Native";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI: return L"Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI: return L"Windows CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI: return L"POSIX CUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION: return L"EFI Application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return L"EFI Boot Service Driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return L"EFI Runtime Driver";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return L"Windows Boot Application";
    default: return L"Unknown";
    }
}

// BuildPeStaticSummary presents only fixed-size, user-mode PE evidence. It
// intentionally omits the parser's full report and individual import functions.
PeStaticSummaryResult BuildPeStaticSummary(const std::wstring& path) {
    PeStaticSummaryResult result;
    if (!IsLiteralDosOrUncFilePath(path)) {
        return BuildPeHeaderFallback(
            path,
            L"深度解析仅支持普通 DOS 盘符或 UNC 路径；当前路径继续使用原有轻量读取器。");
    }

    std::vector<std::uint8_t> fileBytes;
    std::uint64_t fileSize = 0;
    std::wstring readError;
    if (!ReadLitePeSnapshot(path, fileBytes, fileSize, readError)) {
        return BuildPeHeaderFallback(path, readError);
    }

    const ks::file::PeAnalysisResult analysis = ks::file::AnalyzePeBytes(fileBytes);
    if (!analysis.success) {
        const std::wstring diagnostic = analysis.reportText.empty()
            ? L"共享 PE 解析器未返回可用结果。"
            : SingleLinePreview(analysis.reportText, kLitePeStaticMaxDisplayChars);
        return BuildPeHeaderFallback(path, L"深度解析失败：" + diagnostic);
    }

    std::wostringstream text;
    text << L"PE 静态摘要（只读）\r\n\r\n"
         << L"路径: " << SingleLinePreview(path, 512) << L"\r\n"
         << L"快照大小: " << fileSize << L" bytes（上限 16 MiB）\r\n"
         << L"格式: " << (analysis.isPe64 ? L"PE32+" : L"PE32") << L"\r\n"
         << L"Machine: " << HexText(analysis.machine) << L" (" << PeMachineText(analysis.machine) << L")\r\n"
         << L"Subsystem: " << HexText(analysis.subsystem) << L" (" << PeSubsystemText(analysis.subsystem) << L")\r\n"
         << L"ImageBase: " << HexText(analysis.imageBase) << L"\r\n"
         << L"EntryPoint RVA: " << HexText(analysis.entryPointRva) << L"\r\n"
         << L"EntryPoint File Offset: "
         << (analysis.entryPointFileOffsetValid ? HexText(analysis.entryPointFileOffset) : L"<unmapped>") << L"\r\n"
         << L"解析到的区段: " << analysis.sections.size() << L"\r\n"
         << L"解析到的导入模块: " << analysis.importModules.size() << L"\r\n";

    const std::size_t sectionDisplayCount = std::min(analysis.sections.size(), kLitePeStaticMaxSectionRows);
    text << L"\r\n区段（最多显示 " << kLitePeStaticMaxSectionRows << L" 个）\r\n";
    if (sectionDisplayCount == 0) {
        text << L"<none>\r\n";
    } else {
        for (std::size_t index = 0; index < sectionDisplayCount; ++index) {
            const ks::file::PeSectionSummary& section = analysis.sections[index];
            text << L"[" << index << L"] "
                 << SingleLinePreview(Utf8ToWide(section.name), 80)
                 << L" | VA=" << HexText(section.virtualAddress)
                 << L" | VSz=" << HexText(section.virtualSize)
                 << L" | Raw=" << HexText(section.rawOffset) << L"+" << HexText(section.rawSize)
                 << L" | Chars=" << HexText(section.characteristics)
                 << L" | Entropy=" << std::fixed << std::setprecision(2) << section.entropy
                 << L"\r\n";
        }
        if (analysis.sections.size() > sectionDisplayCount) {
            text << L"...仅显示前 " << sectionDisplayCount << L" 个区段。\r\n";
        }
    }

    bool partial = false;
    const std::size_t importDisplayCount = std::min(analysis.importModules.size(), kLitePeStaticMaxImportModuleRows);
    text << L"\r\n导入模块摘要（最多显示 " << kLitePeStaticMaxImportModuleRows
         << L" 个；不显示导入函数）\r\n";
    if (importDisplayCount == 0) {
        text << L"<none>\r\n";
    } else {
        for (std::size_t index = 0; index < importDisplayCount; ++index) {
            const ks::file::PeImportModuleSummary& module = analysis.importModules[index];
            std::wstring moduleName = SingleLinePreview(Utf8ToWide(module.dllName), kLitePeStaticMaxDisplayChars);
            if (moduleName.empty()) {
                moduleName = L"<unnamed module>";
            }
            text << L"[" << module.descriptorIndex << L"] " << moduleName
                 << L" | parsed entries=" << module.imports.size();
            if (!module.diagnosticText.empty()) {
                partial = true;
                text << L" | Partial: "
                     << SingleLinePreview(Utf8ToWide(module.diagnosticText), kLitePeStaticMaxDisplayChars);
            }
            text << L"\r\n";
        }
        if (analysis.importModules.size() > importDisplayCount) {
            text << L"...仅显示前 " << importDisplayCount << L" 个导入模块。\r\n";
        }
    }

    result.success = true;
    result.partial = partial;
    result.text = text.str();
    return result;
}

// CreateEmptyFile creates one new empty text file under the current directory.
// Inputs are a directory path; output is the created full path or empty on
// failure. Existing files are never overwritten.
std::wstring CreateEmptyFile(const std::wstring& directory) {
    if (directory.empty()) {
        return {};
    }
    for (int index = 1; index < 1000; ++index) {
        const std::wstring name = index == 1 ? L"新建文件.txt" : L"新建文件 (" + std::to_wstring(index) + L").txt";
        const std::wstring path = PathNavigator::joinChildPath(directory, name);
        HANDLE file = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            ::CloseHandle(file);
            return path;
        }
        if (::GetLastError() != ERROR_FILE_EXISTS && ::GetLastError() != ERROR_ALREADY_EXISTS) {
            return {};
        }
    }
    return {};
}

// CreateNewDirectory creates a unique "新建文件夹" child. Inputs are a directory;
// output is the created path or empty if all attempts fail.
std::wstring CreateNewDirectory(const std::wstring& directory) {
    if (directory.empty()) {
        return {};
    }
    for (int index = 1; index < 1000; ++index) {
        const std::wstring name = index == 1 ? L"新建文件夹" : L"新建文件夹 (" + std::to_wstring(index) + L")";
        const std::wstring path = PathNavigator::joinChildPath(directory, name);
        if (::CreateDirectoryW(path.c_str(), nullptr)) {
            return path;
        }
        if (::GetLastError() != ERROR_ALREADY_EXISTS) {
            return {};
        }
    }
    return {};
}

} // namespace

FileActionId FileActions::showContextMenu(HWND owner, const FileActionContext& context, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return FileActionId::None;
    }

    // showContextMenu groups the retained FileDock actions so the lightweight
    // Win32 page stays compact. Inputs are the popup owner, current selection
    // state and screen point; processing creates only Win32 HMENU submenus and
    // greys commands that require a selected row; output is the chosen action id.
    const auto appendAction = [&](HMENU target, FileActionId id, const wchar_t* text, bool requiresSelection) {
        UINT flags = MF_STRING;
        if (requiresSelection && !context.hasSelection) {
            flags |= MF_GRAYED;
        }
        ::AppendMenuW(target, flags, static_cast<UINT_PTR>(id), text);
    };

    HMENU openMenu = ::CreatePopupMenu();
    if (openMenu) {
        appendAction(openMenu, FileActionId::OpenRun, L"打开/运行", true);
        appendAction(openMenu, FileActionId::OpenLinkTarget, L"打开链接目标", true);
        appendAction(openMenu, FileActionId::LocateLinkTarget, L"定位链接目标", true);
        appendAction(openMenu, FileActionId::OpenTerminal, L"在终端中打开", false);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(openMenu), L"打开");
    }

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        appendAction(copyMenu, FileActionId::CopyPath, L"复制路径", true);
        appendAction(copyMenu, FileActionId::CopyKernelModeAddress, L"复制内核模式路径", true);
        appendAction(copyMenu, FileActionId::CopyShortFileName, L"复制短文件名", true);
        appendAction(copyMenu, FileActionId::CopyLinkTarget, L"复制链接目标", true);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    HMENU fileMenu = ::CreatePopupMenu();
    if (fileMenu) {
        appendAction(fileMenu, FileActionId::CopyToOppositePanel, L"复制到目标文件夹...", true);
        appendAction(fileMenu, FileActionId::MoveToOppositePanel, L"移动到目标文件夹...", true);
        appendAction(fileMenu, FileActionId::Rename, L"重命名(F2)", true);
        appendAction(fileMenu, FileActionId::DeleteItem, L"删除(Delete)", true);
        appendAction(fileMenu, FileActionId::TakeOwnership, L"取得所有权", true);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"文件操作");
    }

    HMENU kernelMenu = ::CreatePopupMenu();
    if (kernelMenu) {
        appendAction(kernelMenu, FileActionId::DriverDelete, L"驱动删除(R0)", true);
        appendAction(kernelMenu, FileActionId::FileUnlocker, L"文件解锁器(R3/R0)", true);
        appendAction(kernelMenu, FileActionId::MappedProcessScan, L"扫描映射进程(R0)", true);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(kernelMenu), L"R0/占用");
    }

    HMENU newMenu = ::CreatePopupMenu();
    if (newMenu) {
        appendAction(newMenu, FileActionId::NewFile, L"新建文件", false);
        appendAction(newMenu, FileActionId::NewFolder, L"新建文件夹", false);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(newMenu), L"新建");
    }

    HMENU analysisMenu = ::CreatePopupMenu();
    if (analysisMenu) {
        appendAction(analysisMenu, FileActionId::Hash, L"计算哈希值", true);
        appendAction(analysisMenu, FileActionId::Signature, L"检查数字签名", true);
        appendAction(analysisMenu, FileActionId::Entropy, L"计算熵值", true);
        appendAction(analysisMenu, FileActionId::HexView, L"十六进制查看", true);
        appendAction(analysisMenu, FileActionId::PeViewer, L"在 PE 查看器中打开", true);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(analysisMenu), L"分析");
    }

    HMENU viewMenu = ::CreatePopupMenu();
    if (viewMenu) {
        appendAction(viewMenu, FileActionId::SelectColumns, L"选择列...", false);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(viewMenu), L"视图");
    }

    const int chosen = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, owner, nullptr);
    ::DestroyMenu(menu);
    return static_cast<FileActionId>(chosen);
}

// prepareBackground keeps modal confirmations and shell dialogs on the window
// thread. All filesystem, security, Restart Manager and driver work remains in
// execute(), which FileView dispatches to its background action task.
FileActionPreparation FileActions::prepareBackground(FileActionId action, FileActionContext& context) {
    FileActionPreparation preparation{};
    const std::wstring selected = SelectedPath(context);
    switch (action) {
    case FileActionId::DeleteItem:
        if (!selected.empty() &&
            ::MessageBoxW(context.owner, selected.c_str(), L"确认删除选中项？", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            preparation.ready = false;
            preparation.statusText = L"已取消删除。";
        } else {
            context.confirmed = !selected.empty();
        }
        break;
    case FileActionId::CopyToOppositePanel:
    case FileActionId::MoveToOppositePanel: {
        if (selected.empty()) {
            break;
        }
        const bool move = action == FileActionId::MoveToOppositePanel;
        context.targetDirectory = PickTargetFolder(
            context.owner,
            move ? L"选择移动目标文件夹" : L"选择复制目标文件夹");
        if (context.targetDirectory.empty()) {
            preparation.ready = false;
            preparation.statusText = move ? L"已取消移动。" : L"已取消复制。";
        }
        break;
    }
    case FileActionId::Rename:
        if (!selected.empty()) {
            context.renameTarget = PromptRenameTarget(context.owner, selected);
            if (context.renameTarget.empty()) {
                preparation.ready = false;
                preparation.statusText = L"已取消重命名。";
            }
        }
        break;
    case FileActionId::DriverDelete: {
        const std::wstring ntPath = BuildDriverNtPath(selected);
        if (!ntPath.empty() &&
            ::MessageBoxW(context.owner, ntPath.c_str(), L"确认通过R0驱动删除选中项？", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            preparation.ready = false;
            preparation.statusText = L"已取消R0驱动删除。";
        } else {
            context.confirmed = !ntPath.empty();
        }
        break;
    }
    default:
        break;
    }
    return preparation;
}

FileActionResult FileActions::execute(FileActionId action, const FileActionContext& context) {
    FileActionResult result;
    const std::wstring selected = SelectedPath(context);
    switch (action) {
    case FileActionId::OpenRun:
        result.handled = true;
        if (ShellOpenPath(context.owner, selected)) {
            result.statusText = L"已请求打开：" + selected;
        } else {
            result.statusText = L"打开失败：" + selected;
        }
        return result;
    case FileActionId::CopyPath:
        result.handled = true;
        if (context.backgroundExecution) {
            result.clipboardText = selected;
            result.statusText = selected.empty() ? L"没有可复制的路径。" : L"已获取路径。";
            return result;
        }
        result.statusText = copyTextToClipboard(context.owner, selected) ? L"已复制路径。" : L"复制路径失败。";
        return result;
    case FileActionId::CopyShortFileName: {
        result.handled = true;
        const std::wstring shortPath = ShortPathForFile(selected);
        if (context.backgroundExecution) {
            result.clipboardText = shortPath;
            result.statusText = shortPath.empty() ? L"短文件名不可用。" : L"已获取短文件名。";
            return result;
        }
        if (!shortPath.empty() && copyTextToClipboard(context.owner, shortPath)) {
            result.statusText = L"已复制短文件名。";
        } else {
            result.statusText = L"短文件名不可用或复制失败。";
        }
        return result;
    }
    case FileActionId::DeleteItem:
        result.handled = true;
        if (selected.empty()) {
            result.statusText = L"没有选中文件。";
            return result;
        }
        if (!context.backgroundExecution &&
            ::MessageBoxW(context.owner, selected.c_str(), L"确认删除选中项？", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            result.statusText = L"已取消删除。";
            return result;
        }
        if (context.backgroundExecution && !context.confirmed) {
            result.statusText = L"删除未获得用户确认。";
            return result;
        }
        if (context.selectedEntry.kind == FileEntryKind::Directory) {
            if (::RemoveDirectoryW(selected.c_str())) {
                result.refreshRequested = true;
                result.statusText = L"目录已删除。";
            } else {
                result.statusText = L"目录删除失败，错误 " + std::to_wstring(::GetLastError());
            }
        } else if (::DeleteFileW(selected.c_str())) {
            result.refreshRequested = true;
            result.statusText = L"文件已删除。";
        } else {
            result.statusText = L"文件删除失败，错误 " + std::to_wstring(::GetLastError());
        }
        return result;
    case FileActionId::NewFile: {
        result.handled = true;
        const std::wstring path = CreateEmptyFile(context.currentDirectory);
        result.refreshRequested = !path.empty();
        result.statusText = path.empty() ? L"新建文件失败。" : L"已新建文件：" + path;
        return result;
    }
    case FileActionId::NewFolder: {
        result.handled = true;
        const std::wstring path = CreateNewDirectory(context.currentDirectory);
        result.refreshRequested = !path.empty();
        result.statusText = path.empty() ? L"新建文件夹失败。" : L"已新建文件夹：" + path;
        return result;
    }
    case FileActionId::OpenTerminal:
        result.handled = true;
        result.statusText = OpenTerminalAtDirectory(context.owner, context.currentDirectory) ? L"已请求打开终端。" : L"打开终端失败。";
        return result;
    case FileActionId::CopyKernelModeAddress:
        result.handled = true;
        if (context.backgroundExecution) {
            result.clipboardText = BuildDriverNtPath(selected);
            result.statusText = result.clipboardText.empty() ? L"内核模式路径不可用。" : L"已获取内核模式路径。";
            return result;
        }
        result.statusText = copyTextToClipboard(context.owner, BuildDriverNtPath(selected)) ? L"已复制内核模式路径。" : L"复制内核模式路径失败。";
        return result;
    case FileActionId::CopyLinkTarget: {
        result.handled = true;
        const std::wstring target = ResolveLinkTarget(selected);
        if (context.backgroundExecution) {
            result.clipboardText = target;
            result.statusText = target.empty() ? L"链接目标不可用。" : L"已获取链接目标。";
            return result;
        }
        result.statusText = !target.empty() && copyTextToClipboard(context.owner, target) ? L"已复制链接目标。" : L"链接目标不可用或复制失败。";
        return result;
    }
    case FileActionId::OpenLinkTarget: {
        result.handled = true;
        const std::wstring target = ResolveLinkTarget(selected);
        result.statusText = !target.empty() && ShellOpenPath(context.owner, target) ? L"已打开链接目标。" : L"打开链接目标失败。";
        return result;
    }
    case FileActionId::LocateLinkTarget: {
        result.handled = true;
        const std::wstring target = ResolveLinkTarget(selected);
        if (target.empty()) {
            result.statusText = L"链接目标不可用。";
            return result;
        }
        const std::wstring args = L"/select,\"" + target + L"\"";
        const HINSTANCE rc = ::ShellExecuteW(context.owner, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
        result.statusText = reinterpret_cast<INT_PTR>(rc) > 32 ? L"已定位链接目标。" : L"定位链接目标失败。";
        return result;
    }
    case FileActionId::CopyToOppositePanel:
    case FileActionId::MoveToOppositePanel: {
        result.handled = true;
        if (selected.empty()) {
            result.statusText = L"没有选中文件或目录。";
            return result;
        }
        const bool move = action == FileActionId::MoveToOppositePanel;
        const std::wstring targetFolder = context.backgroundExecution
            ? context.targetDirectory
            : PickTargetFolder(context.owner, move ? L"选择移动目标文件夹" : L"选择复制目标文件夹");
        if (targetFolder.empty()) {
            result.statusText = move ? L"已取消移动。" : L"已取消复制。";
            return result;
        }
        std::wstring status;
        const bool ok = CopyOrMovePathToFolder(selected, targetFolder, move, status);
        result.refreshRequested = ok && move;
        result.statusText = status;
        return result;
    }
    case FileActionId::Rename: {
        result.handled = true;
        const std::wstring target = context.backgroundExecution
            ? context.renameTarget
            : PromptRenameTarget(context.owner, selected);
        if (target.empty()) {
            result.statusText = L"已取消重命名。";
            return result;
        }
        if (::MoveFileExW(selected.c_str(), target.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
            result.refreshRequested = true;
            result.statusText = L"已重命名为：" + target;
        } else {
            result.statusText = L"重命名失败，错误 " + std::to_wstring(::GetLastError());
        }
        return result;
    }
    case FileActionId::DriverDelete: {
        result.handled = true;
        if (selected.empty()) {
            result.statusText = L"没有选中文件。";
            return result;
        }
        const std::wstring ntPath = BuildDriverNtPath(selected);
        if (ntPath.empty()) {
            result.statusText = L"驱动删除失败：NT路径转换为空。";
            return result;
        }
        if (!context.backgroundExecution &&
            ::MessageBoxW(context.owner, ntPath.c_str(), L"确认通过R0驱动删除选中项？", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            result.statusText = L"已取消R0驱动删除。";
            return result;
        }
        if (context.backgroundExecution && !context.confirmed) {
            result.statusText = L"R0 驱动删除未获得用户确认。";
            return result;
        }
        const bool isDirectory = context.selectedEntry.kind == FileEntryKind::Directory;
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult io = driverClient.deletePath(ntPath, isDirectory);
        result.refreshRequested = io.ok;
        result.statusText = std::wstring(L"驱动删除(R0)") + (io.ok ? L"成功：" : L"失败：") + ntPath + L" | " + Utf8ToWide(io.message);
        return result;
    }
    case FileActionId::FileUnlocker:
        result.handled = true;
        result.dialogText = QueryFileLockers(selected);
        result.dialogTitle = L"文件解锁器(R3/R0)";
        result.dialogFlags = MB_ICONINFORMATION;
        result.statusText = L"已完成文件占用扫描。";
        if (!context.backgroundExecution) {
            ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
        }
        return result;
    case FileActionId::TakeOwnership:
        result.handled = true;
        result.statusText = TakeOwnershipPath(selected);
        return result;
    case FileActionId::SelectColumns:
        result.handled = true;
        result.statusText = L"已打开列选择菜单。";
        return result;
    case FileActionId::Hash: {
        result.handled = true;
        if (context.selectedEntry.kind != FileEntryKind::File) {
            result.statusText = L"计算哈希值只支持文件。";
            return result;
        }
        std::wstring error;
        const std::wstring hash = ComputeSha256(selected, &error);
        result.statusText = hash.empty() ? L"SHA-256 计算失败：" + error : L"SHA-256: " + hash;
        if (!hash.empty()) {
            result.clipboardText = hash;
            result.dialogTitle = L"文件哈希";
            result.dialogText = result.statusText;
            result.dialogFlags = MB_ICONINFORMATION;
            if (!context.backgroundExecution) {
                copyTextToClipboard(context.owner, hash);
                ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
            }
        }
        return result;
    }
    case FileActionId::Signature:
        result.handled = true;
        if (context.selectedEntry.kind != FileEntryKind::File) {
            result.statusText = L"检查数字签名只支持文件。";
            return result;
        }
        result.statusText = VerifyEmbeddedSignature(selected);
        result.dialogTitle = L"数字签名";
        result.dialogText = result.statusText;
        result.dialogFlags = MB_ICONINFORMATION;
        if (!context.backgroundExecution) {
            ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
        }
        return result;
    case FileActionId::Entropy: {
        result.handled = true;
        if (context.selectedEntry.kind != FileEntryKind::File) {
            result.statusText = L"计算熵值只支持文件。";
            return result;
        }
        std::uint64_t sampled = 0;
        const double entropy = ComputeFileEntropy(selected, 16ull * 1024ull * 1024ull, &sampled);
        if (entropy < 0.0) {
            result.statusText = L"计算熵值失败，错误 " + std::to_wstring(::GetLastError());
        } else {
            wchar_t buffer[160]{};
            ::swprintf_s(buffer, L"Entropy: %.4f bits/byte, sampled=%llu bytes", entropy, static_cast<unsigned long long>(sampled));
            result.statusText = buffer;
            result.dialogTitle = L"文件熵值";
            result.dialogText = result.statusText;
            result.dialogFlags = MB_ICONINFORMATION;
            if (!context.backgroundExecution) {
                ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
            }
        }
        return result;
    }
    case FileActionId::HexView: {
        result.handled = true;
        if (context.selectedEntry.kind != FileEntryKind::File) {
            result.statusText = L"十六进制查看只支持文件。";
            return result;
        }
        const std::wstring preview = HexPreview(selected, 512);
        if (preview.empty()) {
            result.statusText = L"读取十六进制预览失败，错误 " + std::to_wstring(::GetLastError());
            return result;
        }
        result.dialogTitle = L"十六进制预览（前 512 字节）";
        result.dialogText = preview;
        result.dialogFlags = MB_ICONINFORMATION;
        if (!context.backgroundExecution) {
            ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
        }
        result.statusText = L"已显示十六进制预览。";
        return result;
    }
    case FileActionId::PeViewer:
        result.handled = true;
        if (context.selectedEntry.kind != FileEntryKind::File) {
            result.statusText = L"PE 查看只支持文件。";
            return result;
        }
        {
            const PeStaticSummaryResult summary = BuildPeStaticSummary(selected);
            result.statusText = summary.success
                ? (summary.partial ? L"PE 静态摘要已生成（Partial）。" : L"已生成受限 PE 静态摘要。")
                : L"PE 静态摘要不可用（Partial）。";
            result.dialogTitle = L"PE 静态摘要（只读）";
            result.dialogText = summary.text;
            result.dialogFlags = summary.partial ? MB_ICONWARNING : MB_ICONINFORMATION;
        }
        if (!context.backgroundExecution) {
            ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
        }
        return result;
    case FileActionId::MappedProcessScan: {
        result.handled = true;
        if (selected.empty()) {
            result.statusText = L"没有选中文件。";
            return result;
        }
        if (context.selectedEntry.kind != FileEntryKind::File) {
            result.statusText = L"扫描映射进程(R0)只支持文件。";
            return result;
        }
        const std::wstring ntPath = BuildDriverNtPath(selected);
        if (ntPath.empty()) {
            result.statusText = L"扫描映射进程失败：NT路径转换为空。";
            return result;
        }
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::FileSectionMappingsQueryResult query = driverClient.queryFileSectionMappings(
            ntPath,
            KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL,
            KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);
        std::wostringstream summary;
        summary << L"扫描映射进程(R0): " << (query.io.ok ? L"IO OK" : L"IO FAIL")
                << L" | 状态=" << FileSectionStatusText(query.queryStatus)
                << L" | total=" << query.totalCount
                << L" | returned=" << query.returnedCount
                << L" | dataCA=" << HexText(query.dataControlAreaAddress)
                << L" | imageCA=" << HexText(query.imageControlAreaAddress)
                << L" | " << Utf8ToWide(query.io.message);
        if (!query.mappings.empty()) {
            summary << L"\r\n";
            const std::size_t limit = query.mappings.size() < 24 ? query.mappings.size() : 24;
            for (std::size_t i = 0; i < limit; ++i) {
                const ksword::ark::FileSectionMappingEntry& row = query.mappings[i];
                summary << L"#" << (i + 1)
                        << L" PID=" << row.processId
                        << L" Section=" << SectionKindText(row.sectionKind)
                        << L" Map=" << ViewMapTypeText(row.viewMapType)
                        << L" VA=" << HexText(row.startVa) << L"-" << HexText(row.endVa)
                        << L" CA=" << HexText(row.controlAreaAddress)
                        << L"\r\n";
            }
            if (query.mappings.size() > limit) {
                summary << L"... remaining " << (query.mappings.size() - limit) << L" rows omitted from status text.";
            }
        }
        result.statusText = summary.str();
        result.dialogTitle = L"文件映射进程(R0)";
        result.dialogText = result.statusText;
        result.dialogFlags = query.io.ok ? MB_ICONINFORMATION : MB_ICONWARNING;
        if (!context.backgroundExecution && context.owner) {
            ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
        }
        return result;
    }
    default:
        break;
    }
    result.statusText = L"未选择动作。";
    return result;
}

bool FileActions::copyTextToClipboard(HWND owner, const std::wstring& text) {
    if (!::OpenClipboard(owner)) {
        return false;
    }
    ::EmptyClipboard();
    const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory) {
        ::CloseClipboard();
        return false;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    std::memcpy(target, text.c_str(), bytes);
    ::GlobalUnlock(memory);
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    return true;
}

} // namespace Ksword::Features::File
