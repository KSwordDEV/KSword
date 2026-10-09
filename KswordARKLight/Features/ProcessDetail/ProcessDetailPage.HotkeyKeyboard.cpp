#include "../../../shared/usermode/backend/process/ProcessHotkeys.h"
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
#include <cstdlib>
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
using namespace ks::r3::process_detail::hotkeys;

constexpr std::size_t kHotkeyColumnCount = 9;
constexpr std::size_t kHookColumnCount = 10;
constexpr int kToolbarHeight = 30;
 // RT_ACCELERATOR 最后一项标记。

// HotkeyCandidate 是后台采集的值对象；不持有 HWND、HMODULE 或 COM 接口。


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




// WindowContext 保存多种窗口枚举回调的目标 PID、已见 HWND 和结果。


// AcceleratorContext 由资源枚举回调使用，所有成员均在同步回调期间保持有效。


// HexText 将地址、标志与 ID 格式化为稳定的十六进制文本。


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


// ModifiersFromHotkeyf 将 WM_GETHOTKEY / .lnk 的 HOTKEYF 位转换为 MOD_*。


// VirtualKeyText 输出虚拟键的易读名称，未知键以 VK 十六进制保留。


// FormatHotkey 以 Ctrl+Shift+K 形式展示修饰键和虚拟键组合。


// ParseHotkeyText 接受主程序热键编辑框常用的组合键写法。
bool ParseHotkeyText(const std::wstring& text, std::uint32_t& modifiers, std::uint32_t& virtualKey) {
    modifiers = 0;
    virtualKey = 0;
    std::size_t begin = 0;
    while (begin < text.size()) {
        const std::size_t end = text.find(L'+', begin);
        std::wstring part = text.substr(begin, end == std::wstring::npos ? end : end - begin);
        const auto first = part.find_first_not_of(L" \t");
        if (first == std::wstring::npos) return false;
        part = part.substr(first, part.find_last_not_of(L" \t") - first + 1);
        std::transform(part.begin(), part.end(), part.begin(), [](wchar_t ch) { return std::towupper(ch); });
        if (end != std::wstring::npos) {
            std::uint32_t bit = 0;
            if (part == L"CTRL" || part == L"CONTROL") bit = MOD_CONTROL;
            else if (part == L"SHIFT") bit = MOD_SHIFT;
            else if (part == L"ALT") bit = MOD_ALT;
            else if (part == L"WIN" || part == L"WINDOWS") bit = MOD_WIN;
            if (bit == 0 || (modifiers & bit) != 0) return false;
            modifiers |= bit;
            begin = end + 1;
            continue;
        }
        if (part.size() == 1 &&
            ((part[0] >= L'A' && part[0] <= L'Z') || (part[0] >= L'0' && part[0] <= L'9'))) {
            virtualKey = static_cast<std::uint32_t>(part[0]);
        } else if (part.size() >= 2 && part[0] == L'F') {
            wchar_t* tail = nullptr;
            const unsigned long number = std::wcstoul(part.c_str() + 1, &tail, 10);
            if (!tail || *tail != L'\0' || number < 1 || number > 24) return false;
            virtualKey = VK_F1 + static_cast<std::uint32_t>(number) - 1;
        } else {
            constexpr std::pair<const wchar_t*, std::uint32_t> keys[] = {
                {L"ESC", VK_ESCAPE}, {L"ESCAPE", VK_ESCAPE}, {L"TAB", VK_TAB},
                {L"ENTER", VK_RETURN}, {L"RETURN", VK_RETURN}, {L"SPACE", VK_SPACE},
                {L"BACKSPACE", VK_BACK}, {L"DELETE", VK_DELETE}, {L"DEL", VK_DELETE},
                {L"INSERT", VK_INSERT}, {L"HOME", VK_HOME}, {L"END", VK_END},
                {L"PAGEUP", VK_PRIOR}, {L"PAGEDOWN", VK_NEXT}, {L"LEFT", VK_LEFT},
                {L"RIGHT", VK_RIGHT}, {L"UP", VK_UP}, {L"DOWN", VK_DOWN},
                {L"PAUSE", VK_PAUSE}, {L"PRINTSCREEN", VK_SNAPSHOT}
            };
            for (const auto& key : keys) {
                if (part == key.first) { virtualKey = key.second; break; }
            }
            if (virtualKey == 0 && part.rfind(L"VK_0X", 0) == 0) {
                wchar_t* tail = nullptr;
                const unsigned long number = std::wcstoul(part.c_str() + 5, &tail, 16);
                if (tail && *tail == L'\0' && number > 0 && number <= 0xFF) {
                    virtualKey = static_cast<std::uint32_t>(number);
                }
            }
        }
        return virtualKey != 0;
    }
    return false;
}

std::wstring MutationFailureText(const ksword::ark::KeyboardHotkeyMutationResult& result) {
    if (!result.io.ok) return Utf8ToWide(result.io.message);
    switch (result.response.status) {
    case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_INVALID_REQUEST: return L"驱动拒绝了无效请求。";
    case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CONFIRMATION_REQUIRED: return L"驱动要求重新确认。";
    case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSUPPORTED_BUILD: return L"win32k 内部布局未经验证。";
    case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CALLER_CONTEXT_REQUIRED: return L"必须从交互桌面 GUI 线程执行。";
    case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_STALE_SNAPSHOT: return L"对象或链表已变化，请刷新。";
    case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSAFE_TARGET: return L"目标不是可安全修改的普通独立热键。";
    case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CONFLICT: return L"热键组合已被占用。";
    case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED: return L"写后验证失败，已尝试回滚。";
    case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_SAFETY_DENIED: return L"内核安全策略拒绝。";
    default: return L"驱动返回状态 " + std::to_wstring(result.response.status);
    }
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


// AddWindow 对回调中的 HWND 重新核验 PID，并递归收集子窗口。


// CollectTopLevelWindow 是 EnumWindows 的适配回调。


// CollectThreadWindow 是 EnumThreadWindows 的适配回调，用于补齐非顶层窗口。


// CollectProcessWindows 结合全局与线程枚举，收集当前 PID 可见的所有窗口。


// WindowTitle 获取一行窗口标题作为热键详情，空标题不会阻止发现记录。


// MenuMnemonic 解析单个菜单助记符，跳过文字中转义的 &&。


// CollectMenuHotkeysRecursive 递归扫描当前交互桌面可访问菜单的 Alt 助记符。


// CollectWindowAndMenuHotkeys 扫描 WM_GETHOTKEY 与菜单助记符两个公开 R3 来源。


// ResourceNameText 将整数或字符串 RT_ACCELERATOR 名称转换为表格文本。


// EnumerateAcceleratorResource 解码 PE RT_ACCELERATOR；资源条目必须按八字节步进。


// CollectAcceleratorHotkeys 仅把目标映像作为数据文件加载，不运行其入口点。


// EqualPath 在快捷方式目标与目标进程映像之间进行大小写不敏感的规范化路径比对。


// ShortcutRoots 返回当前用户与公共桌面/开始菜单范围，避免扫描整个磁盘。


// CollectShortcutHotkeys 匹配桌面与开始菜单中的 .lnk，枚举上限防止异常目录阻塞刷新。


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
        candidate.hasR0Snapshot =
            (source.entryFlags & KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_MUTABLE) != 0U;
        if (candidate.hasR0Snapshot) {
            auto& row = candidate.r0Snapshot;
            row.source = source.source;
            row.status = source.status;
            row.flags = source.flags;
            row.bucketIndex = source.bucketIndex;
            row.depth = source.depth;
            row.modifiers = source.modifiers;
            row.modifierFlags2 = source.modifierFlags2;
            row.virtualKey = source.virtualKey;
            row.hotkeyId = source.hotkeyId;
            row.processId = source.processId;
            row.threadId = source.threadId;
            row.hotkeyObject = source.hotkeyObject;
            row.nextHotkeyObject = source.nextHotkeyObject;
            row.sessionGlobals = source.sessionGlobals;
            row.threadInfo = source.threadInfo;
            row.windowHandle = source.windowHandle;
            row.destinationHandle = source.destinationHandle;
            row.callbackAddress = source.callbackAddress;
            row.childListFlink = source.childListFlink;
            row.childListBlink = source.childListBlink;
            row.snapshotHash = source.snapshotHash;
            row.objectSize = source.objectSize;
            row.entryFlags = source.entryFlags;
        }
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
    AddEdit(tab, HotkeyInput, L"", false, false, 48, 6, 160, kToolbarHeight);
    AddButton(tab, HotkeyEdit, L"R0 修改", 214, 6, 80, kToolbarHeight);
    AddButton(tab, HotkeyDelete, L"R0 删除", 300, 6, 80, kToolbarHeight);
    AddLabel(tab, HotkeyStatus, L"● 尚未刷新进程热键；输入 Ctrl+Alt+K 等组合后选中 R0 行", 6, 42, -6, 24);
    if (!AddList(tab, HotkeyList, 6, 72, -6, -6)) {
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
    if (controlId == HotkeyRefresh) { RefreshHotkeys(); return true; }
    if (controlId == HotkeyEdit) { MutateSelectedHotkey(false); return true; }
    if (controlId == HotkeyDelete) { MutateSelectedHotkey(true); return true; }
    return false;
}

void ProcessDetailPage::MutateSelectedHotkey(bool remove) {
    const wchar_t* title = remove ? L"R0 删除热键" : L"R0 修改热键";
    if (hotkeyTask_ && hotkeyTask_->running()) return;
    const int selected = SelectedListRow(Control(TabIndex::Hotkey, HotkeyList));
    if (selected < 0 || static_cast<std::size_t>(selected) >= hotkeyEntries_.size()) {
        ::MessageBoxW(hwnd_, L"请先选择一条 R0 热键记录。", title, MB_OK | MB_ICONINFORMATION);
        return;
    }
    const ProcessHotkeyEntry row = hotkeyEntries_[static_cast<std::size_t>(selected)];
    if (row.sourceText != L"R0 RegisterHotKey" || !row.hasR0Snapshot) {
        ::MessageBoxW(hwnd_, L"该项不是具有完整安全快照的普通独立 R0 热键。", title, MB_OK | MB_ICONWARNING);
        return;
    }
    std::uint32_t modifiers = 0;
    std::uint32_t virtualKey = 0;
    if (!remove) {
        if (!ParseHotkeyText(ControlText(TabIndex::Hotkey, HotkeyInput), modifiers, virtualKey)) {
            ::MessageBoxW(hwnd_, L"请输入 Ctrl、Shift、Alt、Win 加字母、数字、F1-F24 或常用功能键。", title, MB_OK | MB_ICONWARNING);
            return;
        }
        modifiers |= row.modifiers & MOD_NOREPEAT;
    }
    const std::wstring message = remove
        ? L"驱动将重新验证完整快照，并在内核 USER 临界区删除普通独立热键。\n\n确认删除 " +
            row.hotkeyText + L"（" + row.objectText + L"）？"
        : L"驱动将重新验证完整快照，仅修改 RegisterHotKey 组合键。\n\n确认将 " +
            row.hotkeyText + L" 修改为 " + FormatHotkey(modifiers, virtualKey) + L"？";
    if (::MessageBoxW(hwnd_, message.c_str(), title, MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) return;
    const auto result = ksword::ark::DriverClient().mutateKeyboardHotkey(
        row.r0Snapshot,
        remove ? KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_DELETE : KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_EDIT,
        modifiers,
        virtualKey);
    const std::uint32_t requiredFlag = remove
        ? KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CHANGED
        : KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_OTHER_BYTES_SAME;
    if (!result.io.ok || result.response.status != KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK ||
        (result.response.responseFlags & requiredFlag) == 0U) {
        const std::wstring failure = L"热键操作失败：" + MutationFailureText(result);
        ::MessageBoxW(hwnd_, failure.c_str(), title, MB_OK | MB_ICONERROR);
        RefreshHotkeys();
        return;
    }
    ::MessageBoxW(hwnd_, remove ? L"热键已删除。" : L"热键已修改。", title, MB_OK | MB_ICONINFORMATION);
    RefreshHotkeys();
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
                entry.hasR0Snapshot = source.hasR0Snapshot;
                entry.r0Snapshot = source.r0Snapshot;
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
                entry.hasR0Snapshot = source.hasR0Snapshot;
                entry.r0Snapshot = source.r0Snapshot;
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
