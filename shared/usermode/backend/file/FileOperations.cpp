#include "FileOperations.h"
#include <objbase.h>
#include <shobjidl.h>
#include <shlobj.h>
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shell32.lib")
#include "PathNavigator.h"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <vector>

namespace ks::r3::file {
bool CopyOrMovePathToFolder(
    const std::wstring& sourcePath,
    const std::wstring& targetFolder,
    bool move,
    std::wstring& statusOut) {
    const auto result = TransferPathToFolder(sourcePath, targetFolder, move);
    statusOut = result.message;
    return result.success;
}
FileOperationResult TransferPathToFolder(const std::wstring& sourcePath, const std::wstring& targetFolder, bool move) {
    FileOperationResult result;
    if (sourcePath.empty() || targetFolder.empty()) {
        result.message = L"源路径或目标文件夹为空。";
        result.errorCode = ERROR_INVALID_PARAMETER;
        return result;
    }

    std::error_code error;
    const std::filesystem::path source(sourcePath);
    const std::filesystem::path target = std::filesystem::path(targetFolder) / source.filename();
    result.target = target.wstring();
    if (move) {
        std::filesystem::rename(source, target, error);
        if (error) {
            std::filesystem::copy(source, target, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, error);
            if (!error) {
                result.copied = true;
                std::filesystem::remove_all(source, error);
            }
        } else {
            result.sourceRemoved = true;
        }
    } else {
        std::filesystem::copy(source, target, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, error);
    }

    if (!error) {
        result.copied = !move || result.copied;
        result.sourceRemoved = move;
    }

    if (error) {
        result.errorCode = static_cast<DWORD>(error.value());
        result.errorCategory = error.category().name();
        const auto message = error.message();
        result.message = std::wstring(move ? L"移动失败: " : L"复制失败: ") + std::wstring(message.begin(), message.end());
        std::error_code probe;
        result.partial = result.copied || std::filesystem::exists(target, probe);
        return result;
    }
    result.success = true;
    result.message = std::wstring(move ? L"已移动到: " : L"已复制到: ") + target.wstring();
    return result;
}
std::wstring CreateEmptyFile(const std::wstring& directory) {
    const auto result = CreateEmptyFileResult(directory);
    return result.success ? result.target : std::wstring{};
}
FileOperationResult CreateEmptyFileResult(const std::wstring& directory) {
    FileOperationResult result;
    if (directory.empty()) {
        result.errorCode = ERROR_INVALID_PARAMETER;
        return result;
    }
    for (int index = 1; index < 1000; ++index) {
        const std::wstring name = index == 1 ? L"新建文件.txt" : L"新建文件 (" + std::to_wstring(index) + L").txt";
        const std::wstring path = PathNavigator::joinChildPath(directory, name);
        HANDLE file = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            ::CloseHandle(file);
            result.target = path;
            result.success = true;
            result.errorCode = ERROR_SUCCESS;
            return result;
        }
        result.errorCode = ::GetLastError();
        if (result.errorCode != ERROR_FILE_EXISTS && result.errorCode != ERROR_ALREADY_EXISTS) {
            return result;
        }
    }
    result.errorCode = ERROR_ALREADY_EXISTS;
    return result;
}
std::wstring CreateNewDirectory(const std::wstring& directory) {
    const auto result = CreateNewDirectoryResult(directory);
    return result.success ? result.target : std::wstring{};
}
FileOperationResult CreateNewDirectoryResult(const std::wstring& directory) {
    FileOperationResult result;
    if (directory.empty()) {
        result.errorCode = ERROR_INVALID_PARAMETER;
        return result;
    }
    for (int index = 1; index < 1000; ++index) {
        const std::wstring name = index == 1 ? L"新建文件夹" : L"新建文件夹 (" + std::to_wstring(index) + L")";
        const std::wstring path = PathNavigator::joinChildPath(directory, name);
        if (::CreateDirectoryW(path.c_str(), nullptr)) {
            result.target = path;
            result.success = true;
            result.errorCode = ERROR_SUCCESS;
            return result;
        }
        result.errorCode = ::GetLastError();
        if (result.errorCode != ERROR_ALREADY_EXISTS) {
            return result;
        }
    }
    result.errorCode = ERROR_ALREADY_EXISTS;
    return result;
}
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
std::wstring ResolveLinkTarget(const std::wstring& path, HRESULT* statusOut) {
    if (statusOut) *statusOut = E_INVALIDARG;
    if (path.size() < 4 || _wcsicmp(path.c_str() + path.size() - 4, L".lnk") != 0) {
        return {};
    }
    const HRESULT initResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    const bool uninitializeCom = initResult == S_OK || initResult == S_FALSE;
    if (FAILED(initResult) && initResult != RPC_E_CHANGED_MODE) {
        if (statusOut) *statusOut = initResult;
        return {};
    }
    IShellLinkW* shellLink = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&shellLink));
    if (FAILED(hr) || shellLink == nullptr) {
        if (statusOut) *statusOut = hr;
        if (uninitializeCom) {
            ::CoUninitialize();
        }
        return {};
    }
    IPersistFile* persistFile = nullptr;
    hr = shellLink->QueryInterface(IID_PPV_ARGS(&persistFile));
    if (FAILED(hr) || persistFile == nullptr) {
        if (statusOut) *statusOut = hr;
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
    if (statusOut) *statusOut = hr;
    if (uninitializeCom) {
        ::CoUninitialize();
    }
    if (FAILED(hr)) {
        return {};
    }
    target.resize(std::wcslen(target.c_str()));
    return target;
}
BOOL RenamePath(const std::wstring& source, const std::wstring& target) { return ::MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING); }
BOOL DeleteFilePath(const std::wstring& path) { return ::DeleteFileW(path.c_str()); }
BOOL DeleteEmptyDirectory(const std::wstring& path) { return ::RemoveDirectoryW(path.c_str()); }

}
