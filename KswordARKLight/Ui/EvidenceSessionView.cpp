#include "EvidenceSessionView.h"

#include "AsyncTask.h"
#include "Controls.h"
#include "EvidenceSession.h"
#include "ListViewUtil.h"
#include "Theme.h"

#include <commctrl.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Ui {
namespace {

constexpr wchar_t kEvidenceSessionViewClass[] = L"KswordARKLight.EvidenceSessionInspector";
constexpr int kRefreshButtonId = 53901;
constexpr int kCompareButtonId = 53902;
constexpr int kDeleteButtonId = 53903;
constexpr int kClearButtonId = 53904;
constexpr int kEvidenceListId = 53905;
constexpr int kPreviewEditId = 53906;
constexpr int kStatusTextId = 53907;
constexpr UINT kEvidenceComparisonComplete = WM_APP + 794;
constexpr std::size_t kPreviewTextLimit = 64U * 1024U;

HWND g_evidenceSessionInspector = nullptr;

struct EvidenceComparison final {
    std::uint64_t beforeSequence = 0;
    std::uint64_t afterSequence = 0;
    EvidenceDiff diff;
};

struct EvidenceSessionViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND compareButton = nullptr;
    HWND deleteButton = nullptr;
    HWND clearButton = nullptr;
    HWND list = nullptr;
    HWND previewEdit = nullptr;
    HWND statusText = nullptr;
    std::vector<EvidenceItem> items;
    std::unique_ptr<AsyncSnapshotTask<EvidenceComparison>> comparisonTask;
};

int Width(const RECT& rect) {
    return rect.right > rect.left ? rect.right - rect.left : 0;
}

int Height(const RECT& rect) {
    return rect.bottom > rect.top ? rect.bottom - rect.top : 0;
}

EvidenceSessionViewState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<EvidenceSessionViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

std::wstring TimestampText(const std::uint64_t timestamp100ns) {
    FILETIME utc{};
    utc.dwLowDateTime = static_cast<DWORD>(timestamp100ns & 0xFFFFFFFFULL);
    utc.dwHighDateTime = static_cast<DWORD>(timestamp100ns >> 32U);
    FILETIME local{};
    SYSTEMTIME systemTime{};
    if (!::FileTimeToLocalFileTime(&utc, &local) || !::FileTimeToSystemTime(&local, &systemTime)) {
        return L"<时间不可用>";
    }
    wchar_t text[48]{};
    ::swprintf_s(text, L"%04u-%02u-%02u %02u:%02u:%02u",
        systemTime.wYear, systemTime.wMonth, systemTime.wDay,
        systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
    return text;
}

std::vector<std::size_t> SelectedItemIndexes(const EvidenceSessionViewState& state) {
    std::vector<std::size_t> indexes;
    if (!state.list) {
        return indexes;
    }
    for (int row = ListView_GetNextItem(state.list, -1, LVNI_SELECTED);
         row >= 0;
         row = ListView_GetNextItem(state.list, row, LVNI_SELECTED)) {
        LVITEMW item{};
        item.mask = LVIF_PARAM;
        item.iItem = row;
        if (!ListView_GetItem(state.list, &item)) {
            continue;
        }
        const LPARAM modelIndex = item.lParam;
        if (modelIndex >= 0 && static_cast<std::size_t>(modelIndex) < state.items.size()) {
            indexes.push_back(static_cast<std::size_t>(modelIndex));
        }
    }
    return indexes;
}

void SetStatus(EvidenceSessionViewState& state, const std::wstring& text) {
    if (state.statusText) {
        ::SetWindowTextW(state.statusText, text.c_str());
    }
}

void SetPreview(EvidenceSessionViewState& state, const std::wstring& text) {
    if (state.previewEdit) {
        ::SetWindowTextW(state.previewEdit, text.c_str());
    }
}

std::wstring LimitPreviewText(std::wstring text, const wchar_t* label) {
    if (text.size() <= kPreviewTextLimit) {
        return text;
    }
    const std::size_t omitted = text.size() - kPreviewTextLimit;
    text.resize(kPreviewTextLimit);
    text += L"\r\n\r\n[";
    text += label;
    text += L"预览已截断，未显示 ";
    text += std::to_wstring(omitted);
    text += L" 个字符；原始证据与导出内容未被修改。]";
    return text;
}

std::wstring RenderItemPreview(const EvidenceItem& item) {
    std::wstring preview;
    preview += L"序号: " + std::to_wstring(item.sequence) + L"\r\n";
    preview += L"时间: " + TimestampText(item.timestamp100ns) + L"\r\n";
    preview += L"来源: " + item.source + L"\r\n";
    preview += L"格式: " + item.format + L"\r\n";
    preview += L"字符数: " + std::to_wstring(item.text.size()) + L"\r\n\r\n";
    preview += item.text;
    return LimitPreviewText(std::move(preview), L"证据");
}

void UpdatePreviewForSelection(EvidenceSessionViewState& state) {
    const std::vector<std::size_t> selected = SelectedItemIndexes(state);
    if (selected.empty()) {
        SetPreview(state, L"选择一项可预览原始证据；选择两项可比较差异。\r\n\r\n"
            L"检查器只显示证据会话快照，不会触发新的系统或驱动查询。");
        return;
    }
    if (selected.size() == 1U) {
        SetPreview(state, RenderItemPreview(state.items[selected.front()]));
        return;
    }
    SetPreview(state, L"已选择 " + std::to_wstring(selected.size()) +
        L" 项。请选择“比较两项”以在此处显示差异。\r\n"
        L"比较按列表顺序将较早项作为 before、较晚项作为 after。");
}

void RefreshSessionSnapshot(EvidenceSessionViewState& state) {
    state.items = GlobalEvidenceSession().snapshot();
    if (state.list) {
        ScopedListViewRedrawLock redrawLock(state.list);
        ListView_DeleteAllItems(state.list);
        for (std::size_t index = 0; index < state.items.size(); ++index) {
            const EvidenceItem& item = state.items[index];
            InsertListViewTextRow(state.list, {
                std::to_wstring(item.sequence),
                TimestampText(item.timestamp100ns),
                item.source,
                item.format,
                std::to_wstring(item.text.size()),
            }, static_cast<LPARAM>(index));
        }
    }
    SetStatus(state, state.items.empty()
        ? L"证据会话为空；模块复制或导出成功后会留下可检查的文本快照。"
        : L"证据会话: " + std::to_wstring(state.items.size()) + L" 项。单选预览，选择两项比较。");
    UpdatePreviewForSelection(state);
}

void CompareSelectedItems(EvidenceSessionViewState& state) {
    const std::vector<std::size_t> selected = SelectedItemIndexes(state);
    if (selected.size() != 2U) {
        SetStatus(state, L"比较需要恰好选择两项证据。");
        return;
    }
    if (!state.comparisonTask) {
        SetStatus(state, L"比较任务不可用。");
        return;
    }
    const EvidenceItem& before = state.items[selected[0]];
    const EvidenceItem& after = state.items[selected[1]];
    const std::uint64_t beforeSequence = before.sequence;
    const std::uint64_t afterSequence = after.sequence;
    const HWND hwnd = state.hwnd;
    state.comparisonTask->request(
        [beforeSequence, afterSequence, beforeText = before.text, afterText = after.text]() mutable {
            EvidenceComparison result;
            result.beforeSequence = beforeSequence;
            result.afterSequence = afterSequence;
            result.diff = BuildEvidenceDiff(beforeText, afterText);
            return result;
        },
        [hwnd](std::uint64_t, std::optional<EvidenceComparison>&& result, std::exception_ptr error) {
            EvidenceSessionViewState* liveState = StateFromWindow(hwnd);
            if (!liveState) {
                return;
            }
            if (error || !result) {
                SetStatus(*liveState, L"证据比较失败。");
                return;
            }
            const EvidenceComparison& comparison = *result;
            const std::vector<std::size_t> selected = SelectedItemIndexes(*liveState);
            if (selected.size() != 2U ||
                liveState->items[selected[0]].sequence != comparison.beforeSequence ||
                liveState->items[selected[1]].sequence != comparison.afterSequence) {
                SetStatus(*liveState, L"证据比较已完成，但当前选择已变化；结果未覆盖当前预览。");
                return;
            }
            std::wstring preview = L"比较: #" + std::to_wstring(comparison.beforeSequence) + L" -> #" +
                std::to_wstring(comparison.afterSequence) + L"\r\n\r\n" + RenderEvidenceDiff(comparison.diff);
            SetPreview(*liveState, LimitPreviewText(std::move(preview), L"差异"));
            SetStatus(*liveState, L"已比较证据 #" + std::to_wstring(comparison.beforeSequence) + L" 与 #" +
                std::to_wstring(comparison.afterSequence) + L"：+" + std::to_wstring(comparison.diff.added.size()) +
                L" -" + std::to_wstring(comparison.diff.removed.size()) + L" =" +
                std::to_wstring(comparison.diff.unchanged.size()) + L"。");
        });
    SetPreview(state, L"正在后台比较两项证据；检查器仍可继续使用。");
    SetStatus(state, L"正在比较证据 #" + std::to_wstring(beforeSequence) + L" 与 #" +
        std::to_wstring(afterSequence) + L"。");
}

void DeleteSelectedItem(EvidenceSessionViewState& state) {
    const std::vector<std::size_t> selected = SelectedItemIndexes(state);
    if (selected.size() != 1U) {
        SetStatus(state, L"删除需要单选一项证据。");
        return;
    }
    const std::uint64_t sequence = state.items[selected.front()].sequence;
    const HWND hwnd = state.hwnd;
    const std::wstring prompt = L"删除证据 #" + std::to_wstring(sequence) +
        L"？该操作只影响当前 Lite 进程内存中的证据会话。";
    if (::MessageBoxW(hwnd, prompt.c_str(), L"删除证据", MB_YESNO | MB_ICONWARNING) != IDYES || !::IsWindow(hwnd)) {
        return;
    }
    EvidenceSessionViewState* liveState = StateFromWindow(hwnd);
    if (!liveState) {
        return;
    }
    if (!GlobalEvidenceSession().erase(sequence)) {
        SetStatus(*liveState, L"证据会话已变化，无法删除所选项目；请刷新后重试。");
        return;
    }
    RefreshSessionSnapshot(*liveState);
    SetStatus(*liveState, L"已删除证据 #" + std::to_wstring(sequence) + L"。");
}

void ClearSession(EvidenceSessionViewState& state) {
    if (state.items.empty()) {
        SetStatus(state, L"证据会话已经为空。");
        return;
    }
    const HWND hwnd = state.hwnd;
    if (::MessageBoxW(hwnd, L"清空当前 Lite 进程内存中的全部证据会话？\r\n"
            L"已导出的文件不会受影响。", L"清空证据会话", MB_YESNO | MB_ICONWARNING) != IDYES || !::IsWindow(hwnd)) {
        return;
    }
    EvidenceSessionViewState* liveState = StateFromWindow(hwnd);
    if (!liveState) {
        return;
    }
    GlobalEvidenceSession().clear();
    RefreshSessionSnapshot(*liveState);
    SetStatus(*liveState, L"证据会话已清空。");
}

void Layout(EvidenceSessionViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);
    constexpr int pad = 8;
    constexpr int buttonHeight = 26;
    constexpr int statusHeight = 20;
    constexpr int buttonGap = 6;

    int x = pad;
    for (const std::pair<HWND, int>& button : std::vector<std::pair<HWND, int>>{
             { state.refreshButton, 64 }, { state.compareButton, 82 },
             { state.deleteButton, 76 }, { state.clearButton, 76 } }) {
        if (button.first) {
            ::MoveWindow(button.first, x, pad, button.second, buttonHeight, TRUE);
        }
        x += button.second + buttonGap;
    }

    const int listTop = pad + buttonHeight + pad;
    const int availableHeight = (std::max)(0, height - listTop - statusHeight - (pad * 2));
    const int listHeight = (std::max)(100, availableHeight / 2);
    const int previewTop = listTop + listHeight + pad;
    const int previewHeight = (std::max)(80, height - previewTop - statusHeight - pad);
    if (state.list) {
        ::MoveWindow(state.list, pad, listTop, (std::max)(0, width - (pad * 2)), listHeight, TRUE);
    }
    if (state.previewEdit) {
        ::MoveWindow(state.previewEdit, pad, previewTop, (std::max)(0, width - (pad * 2)), previewHeight, TRUE);
    }
    if (state.statusText) {
        ::MoveWindow(state.statusText, pad, (std::max)(0, height - statusHeight - pad),
            (std::max)(0, width - (pad * 2)), statusHeight, TRUE);
    }
}

bool CreateChildControls(EvidenceSessionViewState& state) {
    state.refreshButton = CreateButton(state.hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.compareButton = CreateButton(state.hwnd, kCompareButtonId, L"比较两项", 0, 0, 0, 0);
    state.deleteButton = CreateButton(state.hwnd, kDeleteButtonId, L"删除选中", 0, 0, 0, 0);
    state.clearButton = CreateButton(state.hwnd, kClearButtonId, L"清空会话", 0, 0, 0, 0);
    state.list = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | LVS_REPORT | LVS_SHOWSELALWAYS,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kEvidenceListId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.previewEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL | ES_READONLY | ES_WANTRETURN |
            WS_HSCROLL | WS_VSCROLL,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPreviewEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.statusText = CreateText(state.hwnd, kStatusTextId, L"", 0, 0, 0, 0);
    if (!state.refreshButton || !state.compareButton || !state.deleteButton || !state.clearButton ||
        !state.list || !state.previewEdit || !state.statusText) {
        return false;
    }
    state.comparisonTask = std::make_unique<AsyncSnapshotTask<EvidenceComparison>>(state.hwnd, kEvidenceComparisonComplete);
    ::SendMessageW(state.list, WM_SETFONT, reinterpret_cast<WPARAM>(SystemUIFont()), TRUE);
    ListView_SetExtendedListViewStyleEx(state.list,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    AddListViewColumns(state.list, {
        { 0, 68, LVCFMT_RIGHT, L"序号" },
        { 1, 152, LVCFMT_LEFT, L"采集时间" },
        { 2, 220, LVCFMT_LEFT, L"来源" },
        { 3, 86, LVCFMT_LEFT, L"格式" },
        { 4, 76, LVCFMT_RIGHT, L"字符数" },
    });
    SetWindowFontRecursive(state.hwnd);
    return true;
}

LRESULT CALLBACK EvidenceSessionViewProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    EvidenceSessionViewState* state = StateFromWindow(hwnd);
    switch (message) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<EvidenceSessionViewState>();
        owned->hwnd = hwnd;
        state = owned.release();
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        return TRUE;
    }
    case WM_CREATE:
        if (!state || !CreateChildControls(*state)) {
            return -1;
        }
        g_evidenceSessionInspector = hwnd;
        RefreshSessionSnapshot(*state);
        Layout(*state);
        return 0;
    case WM_GETMINMAXINFO:
        if (auto* info = reinterpret_cast<MINMAXINFO*>(lParam)) {
            info->ptMinTrackSize.x = 560;
            info->ptMinTrackSize.y = 390;
        }
        return 0;
    case WM_SIZE:
        if (state) {
            Layout(*state);
        }
        return 0;
    case WM_COMMAND:
        if (!state || HIWORD(wParam) != BN_CLICKED) {
            break;
        }
        switch (LOWORD(wParam)) {
        case kRefreshButtonId: RefreshSessionSnapshot(*state); return 0;
        case kCompareButtonId: CompareSelectedItems(*state); return 0;
        case kDeleteButtonId: DeleteSelectedItem(*state); return 0;
        case kClearButtonId: ClearSession(*state); return 0;
        default: break;
        }
        break;
    case kEvidenceComparisonComplete:
        if (state && state->comparisonTask && state->comparisonTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        return 0;
    case WM_NOTIFY:
        if (state) {
            const auto* notification = reinterpret_cast<const NMHDR*>(lParam);
            if (notification && notification->hwndFrom == state->list && notification->code == LVN_ITEMCHANGED) {
                UpdatePreviewForSelection(*state);
                return 0;
            }
        }
        break;
    case WM_SETTINGCHANGE:
        RefreshSystemUIFont();
        SetWindowFontRecursive(hwnd);
        ::InvalidateRect(hwnd, nullptr, TRUE);
        return 0;
    case WM_CTLCOLORSTATIC:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), AppTheme().textColor);
        return reinterpret_cast<LRESULT>(AppTheme().windowBrush());
    case WM_CTLCOLOREDIT:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), OPAQUE);
        ::SetBkColor(reinterpret_cast<HDC>(wParam), AppTheme().panelColor);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), AppTheme().textColor);
        return reinterpret_cast<LRESULT>(AppTheme().panelBrush());
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        HDC dc = ::BeginPaint(hwnd, &paint);
        RECT rect{};
        ::GetClientRect(hwnd, &rect);
        ::FillRect(dc, &rect, AppTheme().windowBrush());
        ::EndPaint(hwnd, &paint);
        return 0;
    }
    case WM_CLOSE:
        ::DestroyWindow(hwnd);
        return 0;
    case WM_NCDESTROY:
        if (g_evidenceSessionInspector == hwnd) {
            g_evidenceSessionInspector = nullptr;
        }
        if (state && state->comparisonTask) {
            state->comparisonTask->cancel();
        }
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool EnsureEvidenceSessionViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = EvidenceSessionViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = AppTheme().windowBrush();
    windowClass.lpszClassName = kEvidenceSessionViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

RECT InitialWindowRect(HWND owner) {
    const HMONITOR monitor = ::MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{};
    monitorInfo.cbSize = sizeof(monitorInfo);
    ::GetMonitorInfoW(monitor, &monitorInfo);
    const RECT work = monitorInfo.rcWork;
    const int workWidth = Width(work);
    const int workHeight = Height(work);
    const int width = (std::min)(920, (std::max)(560, workWidth - 80));
    const int height = (std::min)(720, (std::max)(390, workHeight - 80));
    return { work.left + (workWidth - width) / 2, work.top + (workHeight - height) / 2,
        work.left + (workWidth + width) / 2, work.top + (workHeight + height) / 2 };
}

} // namespace

bool ShowEvidenceSessionInspector(HWND owner) {
    if (g_evidenceSessionInspector && ::IsWindow(g_evidenceSessionInspector)) {
        ::ShowWindow(g_evidenceSessionInspector, SW_RESTORE);
        ::BringWindowToTop(g_evidenceSessionInspector);
        ::SetForegroundWindow(g_evidenceSessionInspector);
        if (EvidenceSessionViewState* state = StateFromWindow(g_evidenceSessionInspector)) {
            RefreshSessionSnapshot(*state);
        }
        return true;
    }
    g_evidenceSessionInspector = nullptr;
    if (!EnsureEvidenceSessionViewClass()) {
        return false;
    }
    const RECT rect = InitialWindowRect(owner);
    HWND window = ::CreateWindowExW(0, kEvidenceSessionViewClass, L"KswordARKLight 证据会话",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        rect.left, rect.top, Width(rect), Height(rect), owner, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    if (!window) {
        return false;
    }
    ::ShowWindow(window, SW_SHOWNORMAL);
    ::UpdateWindow(window);
    return true;
}

} // namespace Ksword::Ui
