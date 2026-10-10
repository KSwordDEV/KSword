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
namespace {
struct ModuleOwner {HMODULE value;~ModuleOwner(){if(value)::FreeLibrary(value);}};
struct ComOwner {bool owned;~ComOwner(){if(owned)::CoUninitialize();}};
template<class T> struct InterfaceOwner {T*& value;~InterfaceOwner(){if(value)value->Release();}};
void filesystemFailure(ProbeReport* report,const wchar_t* operation,const std::error_code& error) {
    if (report && error) {report->complete = false;report->failures.push_back({operation,L"filesystem",error.value(),true});}
}
}
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
    if (context.report && !context.report->keepGoing()) return;
    DWORD ownerProcessId = 0;
    if (!window || ::GetWindowThreadProcessId(window, &ownerProcessId) == 0U ||
        ownerProcessId != context.processId || !context.seen.insert(window).second) {
        return;
    }
    context.windows.push_back(window);
    ::EnumChildWindows(window, [](HWND child, LPARAM value) -> BOOL {
        auto* childContext = reinterpret_cast<WindowContext*>(value);
        if (childContext->report && !childContext->report->keepGoing()) return FALSE;
        AddWindow(*childContext, child);
        return TRUE;
    }, reinterpret_cast<LPARAM>(&context));
}
BOOL CALLBACK CollectTopLevelWindow(HWND window, LPARAM value) {
    auto* context = reinterpret_cast<WindowContext*>(value);
    if (context) {
        if (context->report && !context->report->keepGoing()) return FALSE;
        AddWindow(*context, window);
    }
    return TRUE;
}
BOOL CALLBACK CollectThreadWindow(HWND window, LPARAM value) {
    auto* context = reinterpret_cast<WindowContext*>(value);
    if (context) {
        if (context->report && !context->report->keepGoing()) return FALSE;
        AddWindow(*context, window);
    }
    return TRUE;
}
std::vector<HWND> CollectProcessWindows(DWORD processId,ProbeReport* report) {
    WindowContext context{};
    context.processId = processId;
    context.report = report;
    ::SetLastError(ERROR_SUCCESS);
    if (!::EnumWindows(CollectTopLevelWindow, reinterpret_cast<LPARAM>(&context)) && report && !report->limited) report->fail(L"EnumWindows",::GetLastError());
    ks::r3::common::UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot.valid()) {
        if (report) report->fail(L"CreateToolhelp32Snapshot",::GetLastError());
        return context.windows;
    }
    THREADENTRY32 thread{};
    thread.dwSize = sizeof(thread);
    if (::Thread32First(snapshot.get(), &thread)) {
        do {
            if (report && !report->keepGoing()) break;
            if (thread.th32OwnerProcessID == processId) {
                ::SetLastError(ERROR_SUCCESS);
                if (!::EnumThreadWindows(thread.th32ThreadID, CollectThreadWindow, reinterpret_cast<LPARAM>(&context)) && report && !report->limited) report->fail(L"EnumThreadWindows",::GetLastError());
            }
        } while (::Thread32Next(snapshot.get(), &thread));
        const DWORD error = ::GetLastError();
        if (report && !report->limited && error != ERROR_NO_MORE_FILES) report->fail(L"Thread32Next",error);
    } else {
        const DWORD error = ::GetLastError();
        if (report && error != ERROR_NO_MORE_FILES) report->fail(L"Thread32First",error);
    }
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
    std::unordered_set<std::wstring>& dedupe,ProbeReport* report,unsigned depth) {
    if (report && (!report->keepGoing() || depth > 64)) {report->complete = false;report->limited = true;return;}
    const int count = menu ? ::GetMenuItemCount(menu) : 0;
    if (count < 0 && report) report->fail(L"GetMenuItemCount",::GetLastError());
    for (int index = 0; index < count; ++index) {
        if (report && !report->keepGoing()) break;
        MENUITEMINFOW item{};
        item.cbSize = sizeof(item);
        item.fMask = MIIM_ID | MIIM_SUBMENU;
        if (!::GetMenuItemInfoW(menu, static_cast<UINT>(index), TRUE, &item)) {
            if (report) report->fail(L"GetMenuItemInfoW",::GetLastError());
            continue;
        }
        wchar_t label[512]{};
        ::GetMenuStringW(menu, static_cast<UINT>(index), label, std::size(label), MF_BYPOSITION);
        const std::wstring labelText(label);
        if (const std::optional<wchar_t> mnemonic = MenuMnemonic(labelText)) {
            HotkeyCandidate candidate{};
            candidate.source = CandidateSource::Menu;candidate.keyKind = KeyKind::Mnemonic;
            candidate.window = reinterpret_cast<std::uintptr_t>(window);candidate.threadId = ::GetWindowThreadProcessId(window,nullptr);
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
            CollectMenuHotkeysRecursive(item.hSubMenu, window, processId, processName, rows, dedupe,report,depth+1);
        }
    }
}
void CollectWindowAndMenuHotkeys(
    DWORD processId,
    const std::wstring& processName,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,ProbeReport* report) {
    for (HWND window : CollectProcessWindows(processId,report)) {
        if (report && !report->keepGoing()) break;
        DWORD owner = 0;const DWORD threadId = ::GetWindowThreadProcessId(window,&owner);
        if (!threadId || owner != processId) {if (report) {report->complete = false;++report->staleWindows;}continue;}
        const auto previousRows = rows.size();
        if (report) ++report->examined;
        DWORD_PTR response = 0;
        ::SetLastError(ERROR_SUCCESS);
        if (::SendMessageTimeoutW(window, WM_GETHOTKEY, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK, 500, &response) != 0) {
            const WORD hotkey = static_cast<WORD>(response);
            if (hotkey != 0U) {
                HotkeyCandidate candidate{};
                candidate.source = CandidateSource::Window;candidate.window = reinterpret_cast<std::uintptr_t>(window);candidate.threadId = threadId;
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
        } else if (report) {
            report->fail(L"SendMessageTimeoutW(WM_GETHOTKEY)",::GetLastError());
        }
        if (HMENU menu = ::GetMenu(window)) {
            CollectMenuHotkeysRecursive(menu, window, processId, processName, rows, dedupe,report);
        }
        DWORD finalOwner = 0;const auto finalThread = ::GetWindowThreadProcessId(window,&finalOwner);
        if (finalOwner != processId || finalThread != threadId) {
            rows.resize(previousRows);if (report) {report->complete = false;++report->staleWindows;}
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
    if (context->report && !context->report->keepGoing()) return FALSE;
    if (context->report) ++context->report->examined;
    HRSRC resource = ::FindResourceW(context->module, resourceName, RT_ACCELERATOR);
    if (!resource) {if (context->report) context->report->fail(L"FindResourceW",::GetLastError());return TRUE;}
    HGLOBAL handle = resource ? ::LoadResource(context->module, resource) : nullptr;
    if (!handle) {if (context->report) context->report->fail(L"LoadResource",::GetLastError());return TRUE;}
    const DWORD bytes = resource ? ::SizeofResource(context->module, resource) : 0;
    const auto* entries = handle ? static_cast<const AcceleratorResourceEntry*>(::LockResource(handle)) : nullptr;
    if (!entries && bytes) {if (context->report) context->report->fail(L"LockResource",::GetLastError());return TRUE;}
    if (!entries || bytes < sizeof(AcceleratorResourceEntry)) {
        if (context->report && bytes) {context->report->malformed = true;context->report->fail(L"RT_ACCELERATOR",ERROR_INVALID_DATA);}
        return TRUE;
    }
    if (bytes % sizeof(AcceleratorResourceEntry) != 0 && context->report) {context->report->malformed = true;context->report->fail(L"RT_ACCELERATOR alignment",ERROR_INVALID_DATA);}
    const std::wstring resourceNameText = ResourceNameText(resourceName);
    const std::size_t count = bytes / sizeof(AcceleratorResourceEntry);
    for (std::size_t index = 0; index < count; ++index) {
        if (context->report && !context->report->keepGoing()) return FALSE;
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
        candidate.source = CandidateSource::Accelerator;candidate.keyKind = (flags & FVIRTKEY) ? KeyKind::VirtualKey : KeyKind::Character;
        candidate.resourceName = resourceNameText;
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
    std::wstring& diagnostic,ProbeReport* report) {
    if (imagePath.empty()) {
        if (report) {report->fatal = true;report->fail(L"ImagePath",ERROR_NOT_FOUND);}
        AppendDiagnostic(diagnostic, L"未取得映像路径，跳过 PE Accelerator。");
        return;
    }
    HMODULE module = ::LoadLibraryExW(imagePath.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!module) {
        const DWORD error = ::GetLastError();if (report) {report->fatal = true;report->fail(L"LoadLibraryExW(resource)",error);}
        AppendDiagnostic(diagnostic, L"无法读取 PE Accelerator，Win32=" + std::to_wstring(error));
        return;
    }
    ModuleOwner moduleOwner{module};
    AcceleratorContext context{};
    context.module = module;
    context.processId = processId;
    context.processName = &processName;
    context.rows = &rows;
    context.dedupe = &dedupe;
    context.report = report;
    ::SetLastError(ERROR_SUCCESS);
    if (!::EnumResourceNamesW(module, RT_ACCELERATOR, EnumerateAcceleratorResource, reinterpret_cast<LONG_PTR>(&context)) && report && !report->limited) {
        const DWORD error = ::GetLastError();
        if (error == ERROR_RESOURCE_TYPE_NOT_FOUND || error == ERROR_RESOURCE_NAME_NOT_FOUND || error == ERROR_RESOURCE_DATA_NOT_FOUND) report->absent = true;
        else report->fail(L"EnumResourceNamesW",error);
    }
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
std::vector<std::wstring> ShortcutRoots(ProbeReport* report) {
    constexpr std::array<int, 3> folders{ CSIDL_DESKTOPDIRECTORY, CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS };
    std::vector<std::wstring> roots;
    for (const int folder : folders) {
        wchar_t path[MAX_PATH]{};
        const HRESULT result = ::SHGetFolderPathW(nullptr, folder, nullptr, SHGFP_TYPE_CURRENT, path);
        if (SUCCEEDED(result) && path[0] != L'\0') {
            roots.emplace_back(path);
        } else if (report) {
            if (FAILED(result)) report->failCom((L"SHGetFolderPathW("+std::to_wstring(folder)+L")").c_str(),result);
            else report->fail(L"SHGetFolderPathW(empty path)",ERROR_NOT_FOUND);
        }
    }
    if (roots.empty() && report) report->fatal = true;
    return roots;
}
void CollectShortcutHotkeys(
    DWORD processId,
    const std::wstring& processName,
    const std::wstring& imagePath,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    std::wstring& diagnostic,ProbeReport* report) {
    if (imagePath.empty()) {
        if (report) {report->fatal = true;report->fail(L"ImagePath",ERROR_NOT_FOUND);}
        return;
    }
    const HRESULT init = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    const bool uninitialize = init == S_OK || init == S_FALSE;
    if (report) {report->comStatusKnown = true;report->comStatus = init;report->comOwned = uninitialize;}
    ComOwner comOwner{uninitialize};
    if (FAILED(init) && init != RPC_E_CHANGED_MODE) {
        if (report) {report->fatal = true;report->failCom(L"CoInitializeEx",init);}
        AppendDiagnostic(diagnostic, L"快捷方式 COM 初始化失败。");
        return;
    }
    constexpr std::size_t maximumShortcuts = 8000;
    std::size_t examined = 0;
    for (const std::wstring& root : ShortcutRoots(report)) {
        std::error_code error;
        std::filesystem::recursive_directory_iterator iterator(
            root,
            std::filesystem::directory_options::skip_permission_denied,
            error);
        const std::filesystem::recursive_directory_iterator end;
        for (; !error && iterator != end && examined < maximumShortcuts; iterator.increment(error)) {
            if (report && !report->keepGoing()) break;
            const std::filesystem::directory_entry& file = *iterator;
            if (file.path().extension() != L".lnk" && file.path().extension() != L".LNK") {
                continue;
            }
            ++examined;
            if (report) ++report->examined;
            IShellLinkW* link = nullptr;
            IPersistFile* persist = nullptr;
            InterfaceOwner<IShellLinkW> linkOwner{link};InterfaceOwner<IPersistFile> persistOwner{persist};
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
                operation = link->GetHotkey(&hotkey);
                if (SUCCEEDED(operation)) operation = link->GetPath(target, std::size(target), &data, SLGP_RAWPATH);
            }
            if (FAILED(operation) && report) report->failCom(L"ShellLink query/load",operation);
            if (SUCCEEDED(operation) && hotkey != 0U && EqualPath(target, imagePath)) {
                HotkeyCandidate candidate{};
                candidate.source = CandidateSource::Shortcut;candidate.shortcutPath = file.path().native();
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
        }
        filesystemFailure(report,L"Shortcut directory traversal",error);
        if (examined >= maximumShortcuts) {
            if (report) {report->complete = false;report->limited = true;}
            AppendDiagnostic(diagnostic, L"快捷方式扫描达到 8000 个文件上限。");
            break;
        }
        if (report && report->limited) break;
    }
}
}
