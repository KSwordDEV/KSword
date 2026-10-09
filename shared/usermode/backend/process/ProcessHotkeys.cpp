#include "ProcessHotkeys.h"
#include <algorithm>
#include <array>
#include <cwchar>
#include <cwctype>
#include <iomanip>
#include <sstream>
#include <filesystem>
#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"Shell32.lib")
namespace ks::r3::process_detail::hotkeys {
std::wstring HexText(std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << value;
    return stream.str();
}
void AppendDiagnostic(std::wstring& target, const std::wstring& text) {
    if (text.empty()) {
        return;
    }
    if (!target.empty()) {
        target += L" | ";
    }
    target += text;
}
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
BOOL CALLBACK CollectTopLevelWindow(HWND window, LPARAM value) {
    auto* context = reinterpret_cast<WindowContext*>(value);
    if (context) {
        AddWindow(*context, window);
    }
    return TRUE;
}
BOOL CALLBACK CollectThreadWindow(HWND window, LPARAM value) {
    auto* context = reinterpret_cast<WindowContext*>(value);
    if (context) {
        AddWindow(*context, window);
    }
    return TRUE;
}
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
std::wstring ResourceNameText(LPWSTR name) {
    if (IS_INTRESOURCE(name)) {
        return L"#" + std::to_wstring(LOWORD(reinterpret_cast<ULONG_PTR>(name)));
    }
    return name ? name : L"?";
}
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
}
