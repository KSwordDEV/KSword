#include "FileActions.h"
#include "../../../shared/usermode/backend/file/PeSnapshot.h"
#include "../../../shared/usermode/backend/file/FileAnalysis.h"
#include "../../../shared/usermode/backend/file/Ownership.h"
#include "../../../shared/usermode/backend/file/FileOperations.h"

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
using ks::r3::file::Utf8ToWide;
using ks::r3::file::HexPreview;
using ks::r3::file::BuildPeHeaderSummary;
using ks::r3::file::IsLiteralDosOrUncFilePath;
using ks::r3::file::ReadLitePeSnapshot;
using ks::r3::file::SingleLinePreview;
using ks::r3::file::BuildPeHeaderFallback;
using ks::r3::file::PeMachineText;
using ks::r3::file::PeSubsystemText;
using ks::r3::file::BuildPeStaticSummary;
using ks::r3::file::PeStaticSummaryResult;

using ks::r3::file::HexText;
using ks::r3::file::BytesToHex;
using ks::r3::file::ComputeSha256;
using ks::r3::file::ComputeFileEntropy;
using ks::r3::file::VerifyEmbeddedSignature;

using ks::r3::file::EnablePrivilege;
using ks::r3::file::TakeOwnershipPath;
using ks::r3::file::QueryFileLockers;

using ks::r3::file::CopyOrMovePathToFolder;
using ks::r3::file::CreateEmptyFile;
using ks::r3::file::CreateNewDirectory;
using ks::r3::file::ShortPathForFile;
using ks::r3::file::ResolveLinkTarget;



// Utf8ToWide converts ArkDriverClient narrow diagnostics to UTF-16 UI text.
// Input is the driver-client message; processing uses strict UTF-8 first and a
// byte-wise fallback; output is safe for status labels and message boxes.


// EnablePrivilege turns on one token privilege for the current process. Input is
// a privilege name such as SE_TAKE_OWNERSHIP_NAME; processing uses
// OpenProcessToken/AdjustTokenPrivileges; output reports whether the privilege
// is now enabled for the attempted operation.


// HexText formats driver diagnostic addresses. Input is a 64-bit value; output
// is a compact uppercase hexadecimal string for result summaries.


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


// ResolveLinkTarget reads a shell link target using IShellLink/IPersistFile.
// Input is a selected .lnk path; output is the resolved path or empty on
// unsupported file types/failures.


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


// TakeOwnershipPath sets the selected file or directory owner to the current
// user. Inputs are a Win32 path and owner HWND only for diagnostics; processing
// enables SeTakeOwnershipPrivilege and calls SetNamedSecurityInfoW; output is a
// concise status message for the File page.


// QueryFileLockers uses Restart Manager to list processes that currently hold
// the selected path. Inputs are a filesystem path; processing starts a temporary
// RM session and registers the file resource; output is a text report. It does
// not kill or unlock processes in the light build.


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


// ComputeSha256 hashes a file using CryptoAPI. Input is file path; output is
// hash text or empty; errorOut receives a compact diagnostic when provided.


// ComputeFileEntropy samples a file and computes byte entropy. Inputs are path
// and max bytes; output is bits-per-byte, or negative on failure.


// HexPreview reads the first bytes of a file and returns a small hex/ascii dump.
// Input is path and byte limit; output is display text or empty on failure.


// VerifyEmbeddedSignature checks Authenticode trust through WinVerifyTrust.
// Inputs are the selected file path; processing asks the OS trust provider
// without UI; output is a compact status line for the retained signature menu.


// BuildPeHeaderSummary preserves Lite's original small PE-header reader. It
// deliberately reads only the DOS/NT/File/Optional header fields, so callers
// can still inspect files which are unsuitable for the bounded deep parser.









// IsLiteralDosOrUncFilePath gates only the bounded deep parser. Other paths
// retain the original header-only reader through the compatibility fallback.


// ReadLitePeSnapshot obtains one bounded byte snapshot before the shared PE
// parser runs. The explicit 16 MiB ceiling matches Lite's existing entropy
// action and prevents the parser from reopening a larger replacement file.


// SingleLinePreview bounds and normalizes untrusted names and diagnostics from
// the file. The result is safe for one MessageBox row rather than a full report.


// BuildPeHeaderFallback keeps the pre-existing PE-header capability whenever
// Lite's bounded deep analysis cannot safely cover the selected file.






// BuildPeStaticSummary presents only fixed-size, user-mode PE evidence. It
// intentionally omits the parser's full report and individual import functions.


// CreateEmptyFile creates one new empty text file under the current directory.
// Inputs are a directory path; output is the created full path or empty on
// failure. Existing files are never overwritten.


// CreateNewDirectory creates a unique "新建文件夹" child. Inputs are a directory;
// output is the created path or empty if all attempts fail.


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
            if (ks::r3::file::DeleteEmptyDirectory(selected)) {
                result.refreshRequested = true;
                result.statusText = L"目录已删除。";
            } else {
                result.statusText = L"目录删除失败，错误 " + std::to_wstring(::GetLastError());
            }
        } else if (ks::r3::file::DeleteFilePath(selected)) {
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
        if (ks::r3::file::RenamePath(selected, target)) {
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
