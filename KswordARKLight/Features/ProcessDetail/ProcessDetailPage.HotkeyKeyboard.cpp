#include "ProcessDetailPage.h"

#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <objbase.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Ksword::Features::ProcessDetail {
namespace {

constexpr std::size_t kHotkeyColumnCount = 9;
constexpr std::size_t kHookColumnCount = 10;
constexpr int kToolbarHeight = 30;
constexpr std::uint16_t kAcceleratorEndFlag = 0x0080U; // RT_ACCELERATOR 最后一项标记。

// HotkeyCandidate 是后台采集的值对象；不持有 HWND、HMODULE 或 COM 接口。
struct HotkeyCandidate final {
    std::wstring objectText;
    std::wstring hotkeyText;
    std::wstring processName;
    std::wstring sourceText;
    std::wstring detailText;
    DWORD processId = 0;
    DWORD threadId = 0;
    std::uint32_t hotkeyId = 0;
    std::uint32_t modifiers = 0;
    std::uint32_t virtualKey = 0;
};

// HookCandidate 是 R0 键盘钩子链的值对象；地址仅供审计展示。
struct HookCandidate final {
    std::wstring objectText;
    std::wstring typeText;
    std::wstring scopeText;
    std::wstring procedureText;
    std::wstring moduleText;
    std::wstring sourceText;
    std::wstring flagsText;
    std::wstring detailText;
    DWORD processId = 0;
    DWORD threadId = 0;
};

// AcceleratorResourceEntry 对应 PE RT_ACCELERATOR 的八字节资源布局。
struct AcceleratorResourceEntry final {
    std::uint16_t flags = 0;
    std::uint16_t key = 0;
    std::uint16_t commandId = 0;
    std::uint16_t padding = 0;
};

static_assert(sizeof(AcceleratorResourceEntry) == 8U);

// WindowContext 保存多种窗口枚举回调的目标 PID、已见 HWND 和结果。
struct WindowContext final {
    DWORD processId = 0;
    std::unordered_set<HWND> seen;
    std::vector<HWND> windows;
};

// AcceleratorContext 由资源枚举回调使用，所有成员均在同步回调期间保持有效。
struct AcceleratorContext final {
    HMODULE module = nullptr;
    DWORD processId = 0;
    const std::wstring* processName = nullptr;
    std::vector<HotkeyCandidate>* rows = nullptr;
    std::unordered_set<std::wstring>* dedupe = nullptr;
};

// HexText 将地址、标志与 ID 格式化为稳定的十六进制文本。
std::wstring HexText(std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << value;
    return stream.str();
}

// Utf8ToWide 转换 ArkDriverClient 返回的 UTF-8 诊断，失败时保留字节内容。
std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int length = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) {
        return { text.begin(), text.end() };
    }
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), length);
    return result;
}

// AppendDiagnostic 组合多个采集来源的诊断，最终显示在对应页面状态栏。
void AppendDiagnostic(std::wstring& target, const std::wstring& text) {
    if (text.empty()) {
        return;
    }
    if (!target.empty()) {
        target += L" | ";
    }
    target += text;
}

// ModifiersFromHotkeyf 将 WM_GETHOTKEY / .lnk 的 HOTKEYF 位转换为 MOD_*。
std::uint32_t ModifiersFromHotkeyf(std::uint32_t value) {
    std::uint32_t result = 0;
    if ((value & HOTKEYF_ALT) != 0U) {
        result |= MOD_ALT;
    }
    if ((value & HOTKEYF_CONTROL) != 0U) {
        result |= MOD_CONTROL;
    }
    if ((value & HOTKEYF_SHIFT) != 0U) {
        result |= MOD_SHIFT;
    }
    return result;
}

// VirtualKeyText 输出虚拟键的易读名称，未知键以 VK 十六进制保留。
std::wstring VirtualKeyText(std::uint32_t virtualKey) {
    if ((virtualKey >= L'A' && virtualKey <= L'Z') ||
        (virtualKey >= L'0' && virtualKey <= L'9')) {
        return std::wstring(1, static_cast<wchar_t>(virtualKey));
    }
    if (virtualKey >= VK_F1 && virtualKey <= VK_F24) {
        return L"F" + std::to_wstring(virtualKey - VK_F1 + 1U);
    }
    const UINT scanCode = ::MapVirtualKeyW(virtualKey, MAPVK_VK_TO_VSC);
    wchar_t name[80]{};
    if (scanCode != 0U && ::GetKeyNameTextW(static_cast<LONG>(scanCode << 16), name, std::size(name)) > 0) {
        return name;
    }
    return L"VK_" + HexText(virtualKey);
}

// FormatHotkey 以 Ctrl+Shift+K 形式展示修饰键和虚拟键组合。
std::wstring FormatHotkey(std::uint32_t modifiers, std::uint32_t virtualKey) {
    std::wstring result;
    const auto append = [&result](const wchar_t* text) {
        if (!result.empty()) {
            result += L"+";
        }
        result += text;
    };
    if ((modifiers & MOD_CONTROL) != 0U) {
        append(L"Ctrl");
    }
    if ((modifiers & MOD_SHIFT) != 0U) {
        append(L"Shift");
    }
    if ((modifiers & MOD_ALT) != 0U) {
        append(L"Alt");
    }
    if ((modifiers & MOD_WIN) != 0U) {
        append(L"Win");
    }
    if (!result.empty()) {
        result += L"+";
    }
    result += VirtualKeyText(virtualKey);
    return result;
}

// KeyboardStatusText 显示 R0 返回的总体枚举状态，PARTIAL 不能按成功隐藏。
std::wstring KeyboardStatusText(std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK: return L"OK";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND: return L"win32k not found";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND: return L"pattern not found";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE: return L"session unavailable";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED: return L"buffer truncated";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED: return L"read failed";
    default: return L"Unknown(" + std::to_wstring(status) + L")";
    }
}

// HookScopeText 把键盘钩子的链范围转换为可读文本。
std::wstring HookScopeText(std::uint32_t scope) {
    switch (scope) {
    case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_THREAD: return L"线程链";
    case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_GLOBAL: return L"全局/桌面链";
    default: return L"未知";
    }
}

// HookTypeText 把协议支持的键盘 Hook 类型转换为 Win32 常量名称。
std::wstring HookTypeText(std::uint32_t type) {
    switch (type) {
    case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD: return L"WH_KEYBOARD";
    case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD_LL: return L"WH_KEYBOARD_LL";
    default: return L"WH_" + std::to_wstring(type);
    }
}

// AddCandidate 基于来源、对象和组合键去重，避免多种公开 API 重复报告同一行。
void AddCandidate(
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    HotkeyCandidate candidate) {
    const std::wstring key = candidate.sourceText + L"\n" + candidate.objectText + L"\n" +
        std::to_wstring(candidate.hotkeyId) + L"\n" + std::to_wstring(candidate.modifiers) + L"\n" +
        std::to_wstring(candidate.virtualKey);
    if (dedupe.insert(key).second) {
        rows.push_back(std::move(candidate));
    }
}

// AddWindow 对回调中的 HWND 重新核验 PID，并递归收集子窗口。
void AddWindow(WindowContext& context, HWND window) {
    DWORD ownerProcessId = 0;
    if (!window || ::GetWindowThreadProcessId(window, &ownerProcessId) == 0U ||
        ownerProcessId != context.processId || !context.seen.insert(window).second) {
        return;
    }
    context.windows.push_back(window);
    ::EnumChildWindows(window, [](HWND child, LPARAM value) -> BOOL {
        auto* childContext = reinterpret_cast<WindowContext*>(value);
        AddWindow(*childContext, child);
        return TRUE;
    }, reinterpret_cast<LPARAM>(&context));
}

// CollectTopLevelWindow 是 EnumWindows 的适配回调。
BOOL CALLBACK CollectTopLevelWindow(HWND window, LPARAM value) {
    auto* context = reinterpret_cast<WindowContext*>(value);
    if (context) {
        AddWindow(*context, window);
    }
    return TRUE;
}

// CollectThreadWindow 是 EnumThreadWindows 的适配回调，用于补齐非顶层窗口。
BOOL CALLBACK CollectThreadWindow(HWND window, LPARAM value) {
    auto* context = reinterpret_cast<WindowContext*>(value);
    if (context) {
        AddWindow(*context, window);
    }
    return TRUE;
}

// CollectProcessWindows 结合全局与线程枚举，收集当前 PID 可见的所有窗口。
std::vector<HWND> CollectProcessWindows(DWORD processId) {
    WindowContext context{};
    context.processId = processId;
    ::EnumWindows(CollectTopLevelWindow, reinterpret_cast<LPARAM>(&context));
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return context.windows;
    }
    THREADENTRY32 thread{};
    thread.dwSize = sizeof(thread);
    if (::Thread32First(snapshot, &thread)) {
        do {
            if (thread.th32OwnerProcessID == processId) {
                ::EnumThreadWindows(thread.th32ThreadID, CollectThreadWindow, reinterpret_cast<LPARAM>(&context));
            }
        } while (::Thread32Next(snapshot, &thread));
    }
    ::CloseHandle(snapshot);
    return context.windows;
}

// WindowTitle 获取一行窗口标题作为热键详情，空标题不会阻止发现记录。
std::wstring WindowTitle(HWND window) {
    const int length = ::GetWindowTextLengthW(window);
    if (length <= 0) {
        return {};
    }
    std::wstring result(static_cast<std::size_t>(length) + 1U, L'\0');
    ::GetWindowTextW(window, result.data(), static_cast<int>(result.size()));
    result.resize(std::wcslen(result.c_str()));
    return result;
}

// MenuMnemonic 解析单个菜单助记符，跳过文字中转义的 &&。
std::optional<wchar_t> MenuMnemonic(const std::wstring& text) {
    for (std::size_t index = 0; index + 1U < text.size(); ++index) {
        if (text[index] != L'&') {
            continue;
        }
        if (text[index + 1U] == L'&') {
            ++index;
            continue;
        }
        return static_cast<wchar_t>(std::towupper(text[index + 1U]));
    }
    return std::nullopt;
}

// CollectMenuHotkeysRecursive 递归扫描当前交互桌面可访问菜单的 Alt 助记符。
void CollectMenuHotkeysRecursive(
    HMENU menu,
    HWND window,
    DWORD processId,
    const std::wstring& processName,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe) {
    const int count = menu ? ::GetMenuItemCount(menu) : 0;
    for (int index = 0; index < count; ++index) {
        MENUITEMINFOW item{};
        item.cbSize = sizeof(item);
        item.fMask = MIIM_ID | MIIM_SUBMENU;
        if (!::GetMenuItemInfoW(menu, static_cast<UINT>(index), TRUE, &item)) {
            continue;
        }
        wchar_t label[512]{};
        ::GetMenuStringW(menu, static_cast<UINT>(index), label, std::size(label), MF_BYPOSITION);
        const std::wstring labelText(label);
        if (const std::optional<wchar_t> mnemonic = MenuMnemonic(labelText)) {
            HotkeyCandidate candidate{};
            candidate.objectText = L"HWND=" + HexText(reinterpret_cast<std::uintptr_t>(window));
            candidate.hotkeyText = L"Alt+" + std::wstring(1, *mnemonic);
            candidate.processName = processName;
            candidate.sourceText = L"菜单快捷键";
            candidate.detailText = labelText;
            candidate.processId = processId;
            candidate.hotkeyId = item.wID;
            candidate.modifiers = MOD_ALT;
            candidate.virtualKey = static_cast<std::uint32_t>(*mnemonic);
            AddCandidate(rows, dedupe, std::move(candidate));
        }
        if (item.hSubMenu) {
            CollectMenuHotkeysRecursive(item.hSubMenu, window, processId, processName, rows, dedupe);
        }
    }
}

// CollectWindowAndMenuHotkeys 扫描 WM_GETHOTKEY 与菜单助记符两个公开 R3 来源。
void CollectWindowAndMenuHotkeys(
    DWORD processId,
    const std::wstring& processName,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe) {
    for (HWND window : CollectProcessWindows(processId)) {
        DWORD_PTR response = 0;
        if (::SendMessageTimeoutW(window, WM_GETHOTKEY, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK, 500, &response) != 0) {
            const WORD hotkey = static_cast<WORD>(response);
            if (hotkey != 0U) {
                HotkeyCandidate candidate{};
                candidate.objectText = L"HWND=" + HexText(reinterpret_cast<std::uintptr_t>(window));
                candidate.modifiers = ModifiersFromHotkeyf(HIBYTE(hotkey));
                candidate.virtualKey = LOBYTE(hotkey);
                candidate.hotkeyText = FormatHotkey(candidate.modifiers, candidate.virtualKey);
                candidate.processId = processId;
                candidate.processName = processName;
                candidate.sourceText = L"窗口热键";
                candidate.detailText = WindowTitle(window);
                AddCandidate(rows, dedupe, std::move(candidate));
            }
        }
        if (HMENU menu = ::GetMenu(window)) {
            CollectMenuHotkeysRecursive(menu, window, processId, processName, rows, dedupe);
        }
    }
}

// ResourceNameText 将整数或字符串 RT_ACCELERATOR 名称转换为表格文本。
std::wstring ResourceNameText(LPWSTR name) {
    if (IS_INTRESOURCE(name)) {
        return L"#" + std::to_wstring(LOWORD(reinterpret_cast<ULONG_PTR>(name)));
    }
    return name ? name : L"?";
}

// EnumerateAcceleratorResource 解码 PE RT_ACCELERATOR；资源条目必须按八字节步进。
BOOL CALLBACK EnumerateAcceleratorResource(HMODULE, LPCWSTR, LPWSTR resourceName, LONG_PTR value) {
    auto* context = reinterpret_cast<AcceleratorContext*>(value);
    if (!context || !context->module || !context->processName || !context->rows || !context->dedupe) {
        return TRUE;
    }
    HRSRC resource = ::FindResourceW(context->module, resourceName, RT_ACCELERATOR);
    HGLOBAL handle = resource ? ::LoadResource(context->module, resource) : nullptr;
    const DWORD bytes = resource ? ::SizeofResource(context->module, resource) : 0;
    const auto* entries = handle ? static_cast<const AcceleratorResourceEntry*>(::LockResource(handle)) : nullptr;
    if (!entries || bytes < sizeof(AcceleratorResourceEntry)) {
        return TRUE;
    }
    const std::wstring resourceNameText = ResourceNameText(resourceName);
    const std::size_t count = bytes / sizeof(AcceleratorResourceEntry);
    for (std::size_t index = 0; index < count; ++index) {
        const AcceleratorResourceEntry& source = entries[index];
        const std::uint16_t flags = source.flags & 0x007FU;
        std::uint32_t modifiers = 0;
        if ((flags & FCONTROL) != 0U) {
            modifiers |= MOD_CONTROL;
        }
        if ((flags & FSHIFT) != 0U) {
            modifiers |= MOD_SHIFT;
        }
        if ((flags & FALT) != 0U) {
            modifiers |= MOD_ALT;
        }
        HotkeyCandidate candidate{};
        candidate.objectText = L"RT_ACCELERATOR " + resourceNameText;
        candidate.hotkeyId = source.commandId;
        candidate.modifiers = modifiers;
        candidate.virtualKey = source.key;
        candidate.hotkeyText = FormatHotkey(modifiers, source.key);
        candidate.processId = context->processId;
        candidate.processName = *context->processName;
        candidate.sourceText = L"PE Accelerator";
        candidate.detailText = L"资源=" + resourceNameText + L" 命令=" + std::to_wstring(source.commandId);
        AddCandidate(*context->rows, *context->dedupe, std::move(candidate));
        if ((source.flags & kAcceleratorEndFlag) != 0U) {
            break;
        }
    }
    return TRUE;
}

// CollectAcceleratorHotkeys 仅把目标映像作为数据文件加载，不运行其入口点。
void CollectAcceleratorHotkeys(
    DWORD processId,
    const std::wstring& processName,
    const std::wstring& imagePath,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    std::wstring& diagnostic) {
    if (imagePath.empty()) {
        AppendDiagnostic(diagnostic, L"未取得映像路径，跳过 PE Accelerator。");
        return;
    }
    HMODULE module = ::LoadLibraryExW(imagePath.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!module) {
        AppendDiagnostic(diagnostic, L"无法读取 PE Accelerator，Win32=" + std::to_wstring(::GetLastError()));
        return;
    }
    AcceleratorContext context{};
    context.module = module;
    context.processId = processId;
    context.processName = &processName;
    context.rows = &rows;
    context.dedupe = &dedupe;
    ::EnumResourceNamesW(module, RT_ACCELERATOR, EnumerateAcceleratorResource, reinterpret_cast<LONG_PTR>(&context));
    ::FreeLibrary(module);
}

// EqualPath 在快捷方式目标与目标进程映像之间进行大小写不敏感的规范化路径比对。
bool EqualPath(const std::wstring& left, const std::wstring& right) {
    if (left.empty() || right.empty()) {
        return false;
    }
    std::error_code error;
    const std::filesystem::path leftPath = std::filesystem::weakly_canonical(left, error);
    error.clear();
    const std::filesystem::path rightPath = std::filesystem::weakly_canonical(right, error);
    const std::wstring normalizedLeft = leftPath.empty() ? left : leftPath.native();
    const std::wstring normalizedRight = rightPath.empty() ? right : rightPath.native();
    return ::CompareStringOrdinal(normalizedLeft.c_str(), -1, normalizedRight.c_str(), -1, TRUE) == CSTR_EQUAL;
}

// ShortcutRoots 返回当前用户与公共桌面/开始菜单范围，避免扫描整个磁盘。
std::vector<std::wstring> ShortcutRoots() {
    constexpr std::array<int, 3> folders{ CSIDL_DESKTOPDIRECTORY, CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS };
    std::vector<std::wstring> roots;
    for (const int folder : folders) {
        wchar_t path[MAX_PATH]{};
        if (SUCCEEDED(::SHGetFolderPathW(nullptr, folder, nullptr, SHGFP_TYPE_CURRENT, path)) && path[0] != L'\0') {
            roots.emplace_back(path);
        }
    }
    return roots;
}

// CollectShortcutHotkeys 匹配桌面与开始菜单中的 .lnk，枚举上限防止异常目录阻塞刷新。
void CollectShortcutHotkeys(
    DWORD processId,
    const std::wstring& processName,
    const std::wstring& imagePath,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    std::wstring& diagnostic) {
    if (imagePath.empty()) {
        return;
    }
    const HRESULT init = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    const bool uninitialize = init == S_OK || init == S_FALSE;
    if (FAILED(init) && init != RPC_E_CHANGED_MODE) {
        AppendDiagnostic(diagnostic, L"快捷方式 COM 初始化失败。");
        return;
    }
    constexpr std::size_t maximumShortcuts = 8000;
    std::size_t examined = 0;
    for (const std::wstring& root : ShortcutRoots()) {
        std::error_code error;
        std::filesystem::recursive_directory_iterator iterator(
            root,
            std::filesystem::directory_options::skip_permission_denied,
            error);
        const std::filesystem::recursive_directory_iterator end;
        for (; !error && iterator != end && examined < maximumShortcuts; iterator.increment(error)) {
            const std::filesystem::directory_entry& file = *iterator;
            if (file.path().extension() != L".lnk" && file.path().extension() != L".LNK") {
                continue;
            }
            ++examined;
            IShellLinkW* link = nullptr;
            IPersistFile* persist = nullptr;
            HRESULT operation = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link));
            if (SUCCEEDED(operation) && link) {
                operation = link->QueryInterface(IID_PPV_ARGS(&persist));
            }
            if (SUCCEEDED(operation) && persist) {
                operation = persist->Load(file.path().c_str(), STGM_READ);
            }
            WORD hotkey = 0;
            wchar_t target[MAX_PATH * 4]{};
            WIN32_FIND_DATAW data{};
            if (SUCCEEDED(operation)) {
                link->GetHotkey(&hotkey);
                operation = link->GetPath(target, std::size(target), &data, SLGP_RAWPATH);
            }
            if (SUCCEEDED(operation) && hotkey != 0U && EqualPath(target, imagePath)) {
                HotkeyCandidate candidate{};
                candidate.objectText = file.path().native();
                candidate.modifiers = ModifiersFromHotkeyf(HIBYTE(hotkey));
                candidate.virtualKey = LOBYTE(hotkey);
                candidate.hotkeyText = FormatHotkey(candidate.modifiers, candidate.virtualKey);
                candidate.processId = processId;
                candidate.processName = processName;
                candidate.sourceText = L"快捷方式热键";
                candidate.detailText = target;
                AddCandidate(rows, dedupe, std::move(candidate));
            }
            if (persist) {
                persist->Release();
            }
            if (link) {
                link->Release();
            }
        }
        if (examined >= maximumShortcuts) {
            AppendDiagnostic(diagnostic, L"快捷方式扫描达到 8000 个文件上限。");
            break;
        }
    }
    if (uninitialize) {
        ::CoUninitialize();
    }
}

// CollectR0Hotkeys 通过 ArkDriverClient 查询当前 PID 的 win32k tagHOTKEY 表。
void CollectR0Hotkeys(
    DWORD processId,
    const std::wstring& processName,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    std::wstring& diagnostic) {
    const ksword::ark::DriverClient client;
    const auto query = client.enumerateKeyboardHotkeys(
        processId,
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS);
    AppendDiagnostic(diagnostic, L"R0 热键=" + KeyboardStatusText(query.status) + L"，返回=" +
        std::to_wstring(query.entries.size()));
    if (!query.io.ok) {
        AppendDiagnostic(diagnostic, Utf8ToWide(query.io.message));
        return;
    }
    for (const auto& source : query.entries) {
        HotkeyCandidate candidate{};
        candidate.objectText = HexText(source.hotkeyObject);
        candidate.hotkeyId = source.hotkeyId;
        candidate.modifiers = source.modifiers;
        candidate.virtualKey = source.virtualKey;
        candidate.hotkeyText = FormatHotkey(source.modifiers, source.virtualKey);
        candidate.processId = source.processId;
        candidate.threadId = source.threadId;
        candidate.processName = processName;
        candidate.sourceText = L"R0 RegisterHotKey";
        candidate.detailText = L"Bucket=" + std::to_wstring(source.bucketIndex) +
            L" Depth=" + std::to_wstring(source.depth) +
            L" Flags=" + HexText(source.entryFlags) + L" | " + source.detail;
        AddCandidate(rows, dedupe, std::move(candidate));
    }
}

// CollectHotkeysForProcess 聚合主程序同样的窗口、菜单、PE 资源、.lnk 与 R0 热键来源。
std::vector<HotkeyCandidate> CollectHotkeysForProcess(
    DWORD processId,
    const std::wstring& processName,
    const std::wstring& imagePath,
    std::wstring& diagnostic) {
    std::vector<HotkeyCandidate> rows;
    std::unordered_set<std::wstring> dedupe;
    CollectWindowAndMenuHotkeys(processId, processName, rows, dedupe);
    CollectAcceleratorHotkeys(processId, processName, imagePath, rows, dedupe, diagnostic);
    CollectShortcutHotkeys(processId, processName, imagePath, rows, dedupe, diagnostic);
    CollectR0Hotkeys(processId, processName, rows, dedupe, diagnostic);
    std::sort(rows.begin(), rows.end(), [](const HotkeyCandidate& left, const HotkeyCandidate& right) {
        if (left.hotkeyText != right.hotkeyText) {
            return left.hotkeyText < right.hotkeyText;
        }
        if (left.sourceText != right.sourceText) {
            return left.sourceText < right.sourceText;
        }
        return left.objectText < right.objectText;
    });
    return rows;
}

// CollectR0KeyboardHooks 查询当前 PID 相关的 WH_KEYBOARD 与 WH_KEYBOARD_LL 链。
std::vector<HookCandidate> CollectR0KeyboardHooks(DWORD processId, std::wstring& diagnostic) {
    std::vector<HookCandidate> rows;
    const ksword::ark::DriverClient client;
    const auto query = client.enumerateKeyboardHooks(
        processId,
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS);
    AppendDiagnostic(diagnostic, L"R0 键盘钩子=" + KeyboardStatusText(query.status) + L"，返回=" +
        std::to_wstring(query.entries.size()));
    if (!query.io.ok) {
        AppendDiagnostic(diagnostic, Utf8ToWide(query.io.message));
        return rows;
    }
    for (const auto& source : query.entries) {
        HookCandidate candidate{};
        candidate.objectText = HexText(source.hookObject);
        candidate.typeText = HookTypeText(source.hookType);
        candidate.scopeText = HookScopeText(source.hookScope);
        candidate.procedureText = HexText(source.procedureAddress) + L" / " + HexText(source.procedureOffset);
        candidate.moduleText = source.moduleBase != 0U
            ? HexText(source.moduleBase)
            : L"ModuleId " + std::to_wstring(source.moduleId);
        candidate.sourceText = source.source == KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_GLOBAL_HOOK_CHAIN
            ? L"R0 全局 Hook 链"
            : L"R0 线程 Hook 链";
        candidate.flagsText = HexText(source.flags);
        candidate.detailText = source.detail;
        candidate.processId = source.processId;
        candidate.threadId = source.threadId;
        rows.push_back(std::move(candidate));
    }
    return rows;
}

// AddButtonTooltip 为本页图标按钮安装原生悬停说明；字面量文本满足延迟读取生命周期。
void AddButtonTooltip(HWND parent, HWND control, const wchar_t* text) {
    if (!parent || !control || !text) {
        return;
    }
    HWND tooltip = ::CreateWindowExW(
        WS_EX_TOPMOST,
        TOOLTIPS_CLASSW,
        nullptr,
        WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (!tooltip) {
        return;
    }
    TOOLINFOW info{};
    info.cbSize = sizeof(info);
    info.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    info.hwnd = parent;
    info.uId = reinterpret_cast<UINT_PTR>(control);
    info.lpszText = const_cast<LPWSTR>(text);
    ::SendMessageW(tooltip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&info));
}

// ResetListColumns 清空 ListView 的旧列组，供键盘内部分栏安全切换。
void ResetListColumns(HWND list) {
    if (!list) {
        return;
    }
    HWND header = ListView_GetHeader(list);
    for (int index = header ? Header_GetItemCount(header) - 1 : -1; index >= 0; --index) {
        ListView_DeleteColumn(list, index);
    }
    ListView_DeleteAllItems(list);
}

} // namespace

// CreateHotkeyTab 创建“进程热键”页，读取操作全部放在刷新任务中执行。
bool ProcessDetailPage::CreateHotkeyTab() {
    const TabIndex tab = TabIndex::Hotkey;
    HWND refresh = AddButton(tab, HotkeyRefresh, L"↻", 6, 6, 34, kToolbarHeight);
    AddButtonTooltip(pages_[static_cast<std::size_t>(tab)].hwnd, refresh, L"刷新当前进程的窗口、菜单、PE 资源、快捷方式和 R0 热键表");
    AddLabel(tab, HotkeyStatus, L"● 尚未刷新进程热键", 48, 8, -6, 24);
    if (!AddList(tab, HotkeyList, 6, 44, -6, -6)) {
        return false;
    }
    RebuildHotkeyList();
    return refresh != nullptr;
}

// CreateKeyboardTab 创建“键盘”页，内部页签在热键表和键盘钩子链之间切换。
bool ProcessDetailPage::CreateKeyboardTab() {
    const TabIndex tab = TabIndex::Keyboard;
    HWND refresh = AddButton(tab, KeyboardRefresh, L"↻", 6, 6, 34, kToolbarHeight);
    AddButtonTooltip(pages_[static_cast<std::size_t>(tab)].hwnd, refresh, L"刷新 R0 热键表以及 WH_KEYBOARD/WH_KEYBOARD_LL 钩子链");
    AddLabel(tab, KeyboardStatus, L"● 尚未刷新键盘证据", 48, 8, -6, 24);
    HWND innerTab = AddControl(tab, 0, WC_TABCONTROLW, L"", WS_TABSTOP | WS_CLIPSIBLINGS,
        KeyboardInnerTab, 6, 42, -6, 26);
    if (innerTab) {
        TCITEMW hotkeys{};
        hotkeys.mask = TCIF_TEXT;
        hotkeys.pszText = const_cast<LPWSTR>(L"热键");
        ::SendMessageW(innerTab, TCM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&hotkeys));
        TCITEMW hooks{};
        hooks.mask = TCIF_TEXT;
        hooks.pszText = const_cast<LPWSTR>(L"键盘钩子");
        ::SendMessageW(innerTab, TCM_INSERTITEMW, 1, reinterpret_cast<LPARAM>(&hooks));
        ::SendMessageW(innerTab, TCM_SETCURSEL, 0, 0);
    }
    if (!innerTab || !AddList(tab, KeyboardList, 6, 74, -6, -6)) {
        return false;
    }
    RebuildKeyboardList();
    return refresh != nullptr;
}

// PopulateHotkeyTab 在未产生快照时恢复空闲提示，避免显示被销毁页面的旧状态。
void ProcessDetailPage::PopulateHotkeyTab() {
    if (!hotkeyLoaded_) {
        SetPageStatus(TabIndex::Hotkey, HotkeyStatus, L"● 尚未刷新进程热键");
    }
}

// PopulateKeyboardTab 在未产生快照时恢复空闲提示，避免显示被销毁页面的旧状态。
void ProcessDetailPage::PopulateKeyboardTab() {
    if (!keyboardLoaded_) {
        SetPageStatus(TabIndex::Keyboard, KeyboardStatus, L"● 尚未刷新键盘证据");
    }
}

// HandleHotkeyCommand 处理进程热键页的刷新按钮命令。
bool ProcessDetailPage::HandleHotkeyCommand(int controlId) {
    if (controlId != HotkeyRefresh) {
        return false;
    }
    RefreshHotkeys();
    return true;
}

// HandleKeyboardCommand 处理键盘页的刷新按钮命令。
bool ProcessDetailPage::HandleKeyboardCommand(int controlId) {
    if (controlId != KeyboardRefresh) {
        return false;
    }
    RefreshKeyboard();
    return true;
}

// RefreshHotkeys 在后台聚合完整进程热键审计；UI 线程只回填最终快照。
void ProcessDetailPage::RefreshHotkeys() {
    if (!hotkeyTask_ || hotkeyTask_->running()) {
        return;
    }
    SetPageStatus(TabIndex::Hotkey, HotkeyStatus, L"● 正在后台扫描进程热键...");
    ::EnableWindow(Control(TabIndex::Hotkey, HotkeyRefresh), FALSE);
    const DWORD processId = processId_;
    const std::wstring processName = snapshot_.basic.processName;
    const std::wstring imagePath = snapshot_.basic.imagePath;
    hotkeyTask_->request(
        [processId, processName, imagePath] {
            ProcessHotkeySnapshot snapshot{};
            const auto begin = std::chrono::steady_clock::now();
            std::wstring diagnostic = L"R3 窗口/菜单/PE Accelerator/.lnk";
            const std::wstring name = processName.empty() ? L"PID " + std::to_wstring(processId) : processName;
            const std::vector<HotkeyCandidate> rows = CollectHotkeysForProcess(processId, name, imagePath, diagnostic);
            snapshot.entries.reserve(rows.size());
            for (const HotkeyCandidate& source : rows) {
                ProcessHotkeyEntry entry{};
                entry.objectText = source.objectText;
                entry.hotkeyText = source.hotkeyText;
                entry.processName = source.processName;
                entry.sourceText = source.sourceText;
                entry.detailText = source.detailText;
                entry.processId = source.processId;
                entry.threadId = source.threadId;
                entry.hotkeyId = source.hotkeyId;
                entry.modifiers = source.modifiers;
                entry.virtualKey = source.virtualKey;
                snapshot.entries.push_back(std::move(entry));
            }
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - begin).count();
            snapshot.statusText = L"● 刷新完成 " + std::to_wstring(elapsed) + L" ms | 热键=" +
                std::to_wstring(snapshot.entries.size()) + L" | " + diagnostic;
            snapshot.completed = true;
            return snapshot;
        },
        [this](std::uint64_t, std::optional<ProcessHotkeySnapshot>&& snapshot, std::exception_ptr error) {
            ::EnableWindow(Control(TabIndex::Hotkey, HotkeyRefresh), TRUE);
            if (error || !snapshot.has_value()) {
                SetPageStatus(TabIndex::Hotkey, HotkeyStatus, L"● 进程热键后台扫描异常结束。");
                return;
            }
            hotkeyEntries_ = std::move(snapshot->entries);
            hotkeyLoaded_ = snapshot->completed;
            SetPageStatus(TabIndex::Hotkey, HotkeyStatus, snapshot->statusText);
            RebuildHotkeyList();
        });
}

// RefreshKeyboard 在后台生成同代次的热键表与键盘钩子链，再一次性提交到 UI。
void ProcessDetailPage::RefreshKeyboard() {
    if (!keyboardTask_ || keyboardTask_->running()) {
        return;
    }
    SetPageStatus(TabIndex::Keyboard, KeyboardStatus, L"● 正在后台扫描键盘热键与钩子...");
    ::EnableWindow(Control(TabIndex::Keyboard, KeyboardRefresh), FALSE);
    const DWORD processId = processId_;
    const std::wstring processName = snapshot_.basic.processName;
    const std::wstring imagePath = snapshot_.basic.imagePath;
    keyboardTask_->request(
        [processId, processName, imagePath] {
            KeyboardSnapshot snapshot{};
            const auto begin = std::chrono::steady_clock::now();
            std::wstring diagnostic = L"R3 窗口/菜单/PE Accelerator/.lnk + R0 win32k";
            const std::wstring name = processName.empty() ? L"PID " + std::to_wstring(processId) : processName;
            const std::vector<HotkeyCandidate> hotkeys = CollectHotkeysForProcess(processId, name, imagePath, diagnostic);
            snapshot.hotkeys.reserve(hotkeys.size());
            for (const HotkeyCandidate& source : hotkeys) {
                ProcessHotkeyEntry entry{};
                entry.objectText = source.objectText;
                entry.hotkeyText = source.hotkeyText;
                entry.processName = source.processName;
                entry.sourceText = source.sourceText;
                entry.detailText = source.detailText;
                entry.processId = source.processId;
                entry.threadId = source.threadId;
                entry.hotkeyId = source.hotkeyId;
                entry.modifiers = source.modifiers;
                entry.virtualKey = source.virtualKey;
                snapshot.hotkeys.push_back(std::move(entry));
            }
            const std::vector<HookCandidate> hooks = CollectR0KeyboardHooks(processId, diagnostic);
            snapshot.hooks.reserve(hooks.size());
            for (const HookCandidate& source : hooks) {
                KeyboardHookEntry entry{};
                entry.objectText = source.objectText;
                entry.typeText = source.typeText;
                entry.scopeText = source.scopeText;
                entry.procedureText = source.procedureText;
                entry.moduleText = source.moduleText;
                entry.sourceText = source.sourceText;
                entry.flagsText = source.flagsText;
                entry.detailText = source.detailText;
                entry.processId = source.processId;
                entry.threadId = source.threadId;
                snapshot.hooks.push_back(std::move(entry));
            }
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - begin).count();
            snapshot.statusText = L"● 刷新完成 " + std::to_wstring(elapsed) + L" ms | 热键=" +
                std::to_wstring(snapshot.hotkeys.size()) + L" | 键盘钩子=" +
                std::to_wstring(snapshot.hooks.size()) + L" | " + diagnostic;
            snapshot.completed = true;
            return snapshot;
        },
        [this](std::uint64_t, std::optional<KeyboardSnapshot>&& snapshot, std::exception_ptr error) {
            ::EnableWindow(Control(TabIndex::Keyboard, KeyboardRefresh), TRUE);
            if (error || !snapshot.has_value()) {
                SetPageStatus(TabIndex::Keyboard, KeyboardStatus, L"● 键盘后台扫描异常结束。");
                return;
            }
            keyboardHotkeyEntries_ = std::move(snapshot->hotkeys);
            keyboardHookEntries_ = std::move(snapshot->hooks);
            keyboardLoaded_ = snapshot->completed;
            SetPageStatus(TabIndex::Keyboard, KeyboardStatus, snapshot->statusText);
            RebuildKeyboardList();
        });
}

// RebuildHotkeyList 按缓存快照生成“进程热键”的完整列组，支持通用复制右键菜单。
void ProcessDetailPage::RebuildHotkeyList() {
    HWND list = Control(TabIndex::Hotkey, HotkeyList);
    if (!list) {
        return;
    }
    ResetListColumns(list);
    const std::array<std::pair<const wchar_t*, int>, kHotkeyColumnCount> columns{{
        { L"对象", 190 }, { L"热键ID", 85 }, { L"热键", 150 }, { L"进程ID", 80 },
        { L"线程ID", 80 }, { L"进程名", 130 }, { L"来源", 145 }, { L"VK/Mod", 130 }, { L"详情", 340 }
    }};
    for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
        AddListColumn(list, index, columns[static_cast<std::size_t>(index)].first, columns[static_cast<std::size_t>(index)].second);
    }
    listColumnCounts_[list] = static_cast<int>(columns.size());
    listContextColumns_[list] = 0;
    for (std::size_t index = 0; index < hotkeyEntries_.size(); ++index) {
        const ProcessHotkeyEntry& entry = hotkeyEntries_[index];
        AddListRow(list, static_cast<int>(index), {
            entry.objectText, entry.hotkeyId == 0U ? L"0" : HexText(entry.hotkeyId), entry.hotkeyText,
            std::to_wstring(entry.processId), entry.threadId == 0U ? L"-" : std::to_wstring(entry.threadId),
            entry.processName, entry.sourceText,
            L"VK=" + HexText(entry.virtualKey) + L" MOD=" + HexText(entry.modifiers), entry.detailText
        }, static_cast<LPARAM>(index + 1U));
    }
}

// RebuildKeyboardList 根据内部 TabControl 的当前视图重建同一个列表，避免双表挤压窗口。
void ProcessDetailPage::RebuildKeyboardList() {
    HWND list = Control(TabIndex::Keyboard, KeyboardList);
    HWND innerTab = Control(TabIndex::Keyboard, KeyboardInnerTab);
    if (!list || !innerTab) {
        return;
    }
    const int selected = static_cast<int>(::SendMessageW(innerTab, TCM_GETCURSEL, 0, 0));
    ResetListColumns(list);
    if (selected == 1) {
        const std::array<std::pair<const wchar_t*, int>, kHookColumnCount> columns{{
            { L"对象", 180 }, { L"类型", 120 }, { L"范围", 100 }, { L"进程ID", 80 }, { L"线程ID", 80 },
            { L"函数/偏移", 180 }, { L"模块", 150 }, { L"来源", 140 }, { L"Flags", 100 }, { L"详情", 320 }
        }};
        for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
            AddListColumn(list, index, columns[static_cast<std::size_t>(index)].first, columns[static_cast<std::size_t>(index)].second);
        }
        listColumnCounts_[list] = static_cast<int>(columns.size());
        for (std::size_t index = 0; index < keyboardHookEntries_.size(); ++index) {
            const KeyboardHookEntry& entry = keyboardHookEntries_[index];
            AddListRow(list, static_cast<int>(index), {
                entry.objectText, entry.typeText, entry.scopeText, std::to_wstring(entry.processId),
                entry.threadId == 0U ? L"-" : std::to_wstring(entry.threadId), entry.procedureText,
                entry.moduleText, entry.sourceText, entry.flagsText, entry.detailText
            }, static_cast<LPARAM>(index + 1U));
        }
    } else {
        const std::array<std::pair<const wchar_t*, int>, kHotkeyColumnCount> columns{{
            { L"对象", 190 }, { L"热键ID", 85 }, { L"热键", 150 }, { L"进程ID", 80 },
            { L"线程ID", 80 }, { L"进程名", 130 }, { L"来源", 145 }, { L"VK/Mod", 130 }, { L"详情", 340 }
        }};
        for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
            AddListColumn(list, index, columns[static_cast<std::size_t>(index)].first, columns[static_cast<std::size_t>(index)].second);
        }
        listColumnCounts_[list] = static_cast<int>(columns.size());
        for (std::size_t index = 0; index < keyboardHotkeyEntries_.size(); ++index) {
            const ProcessHotkeyEntry& entry = keyboardHotkeyEntries_[index];
            AddListRow(list, static_cast<int>(index), {
                entry.objectText, entry.hotkeyId == 0U ? L"0" : HexText(entry.hotkeyId), entry.hotkeyText,
                std::to_wstring(entry.processId), entry.threadId == 0U ? L"-" : std::to_wstring(entry.threadId),
                entry.processName, entry.sourceText,
                L"VK=" + HexText(entry.virtualKey) + L" MOD=" + HexText(entry.modifiers), entry.detailText
            }, static_cast<LPARAM>(index + 1U));
        }
    }
    listContextColumns_[list] = 0;
}

} // namespace Ksword::Features::ProcessDetail
