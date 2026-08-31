#include "PerformanceView.h"

#include "PerformanceSampler.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::HardwareStats {
namespace {

constexpr wchar_t kPerformanceViewClass[] = L"KswordARKLight.HardwareStats.PerformanceView";

constexpr int kRefreshButtonId = 66101;
constexpr int kPauseButtonId = 66102;
constexpr int kIntervalComboId = 66103;
constexpr int kFilterBarId = 66104;
constexpr int kMetricListId = 66105;
constexpr int kLoadingOverlayId = 66106;
constexpr int kExportButtonId = 66107;

constexpr UINT kMenuCopyRow = 66151;
constexpr UINT kMenuCopyVisible = 66152;
constexpr UINT kMenuRefresh = 66153;

constexpr UINT kMsgSampleCompleted = WM_APP + 660;
constexpr UINT_PTR kSampleTimerId = 1;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 4;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct PerformanceViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND pauseButton = nullptr;
    HWND intervalCombo = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    Ksword::Ui::VirtualListView metricList;
    std::shared_ptr<PerformanceSampler> sampler;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<PerformanceSnapshot>> sampleTask;
    std::wstring statusText = L"正在打开性能计数器…";
    std::wstring resolutionText;
    bool paused = false;
    bool everLoaded = false;
    UINT intervalMs = 1000;
};

PerformanceViewState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<PerformanceViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

bool CopyText(HWND owner, const std::wstring& text) {
    if (text.empty() || !::OpenClipboard(owner)) {
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

std::wstring StableKeyFromListItem(const PerformanceViewState& state, int item) {
    const auto& visible = state.metricList.visibleIndexes();
    const auto& rows = state.metricList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t sourceIndex = visible[static_cast<std::size_t>(item)];
    return sourceIndex < rows.size() ? rows[sourceIndex].stableKey : std::wstring{};
}

std::wstring RowsAsText(const PerformanceViewState& state, bool visibleRows) {
    const auto& rows = state.metricList.rows();
    const auto& visible = state.metricList.visibleIndexes();
    const HWND list = state.metricList.hwnd();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!visibleRows &&
            (!list || (ListView_GetItemState(list, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t rowIndex = visible[item];
        if (rowIndex >= rows.size()) {
            continue;
        }
        const auto& cells = rows[rowIndex].cells;
        for (std::size_t column = 0; column < (std::min)(static_cast<std::size_t>(kColumnCount), cells.size()); ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

// ApplyFilter recomputes the visible set on the UI thread.
//
// Every other table in this product filters on a worker because its snapshots
// run to thousands of rows. This one is a fixed handful of counters that is
// rebuilt once per second, and AsyncSnapshotTask starts a thread per request:
// pushing a sixty-row substring scan through it would cost one extra thread
// every tick to save work measured in microseconds.
void ApplyFilter(PerformanceViewState& state,
    const std::wstring& selectedStableKey,
    const std::wstring& topStableKey) {
    HWND list = state.metricList.hwnd();
    if (!list) {
        return;
    }
    const std::wstring query = Ksword::Ui::GetFilterBarText(state.filterBar);
    const bool useRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    state.metricList.setVisibleIndexes(
        Ksword::Ui::VirtualListView::FilterRowIndexes(state.metricList.rows(), query, useRegex));

    const auto& visible = state.metricList.visibleIndexes();
    const auto& rows = state.metricList.rows();
    int selectedItem = -1;
    int topItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t sourceIndex = visible[item];
        if (sourceIndex >= rows.size()) {
            continue;
        }
        if (selectedItem < 0 && !selectedStableKey.empty() && rows[sourceIndex].stableKey == selectedStableKey) {
            selectedItem = static_cast<int>(item);
        }
        if (topItem < 0 && !topStableKey.empty() && rows[sourceIndex].stableKey == topStableKey) {
            topItem = static_cast<int>(item);
        }
    }
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topItem >= 0) {
        // The table is rewritten every tick, so restoring the previous top row is
        // what stops the list from jumping back to the top under the cursor.
        ListView_EnsureVisible(list, topItem, FALSE);
    }
}

void BuildRows(PerformanceViewState& state, const PerformanceSnapshot& snapshot) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(snapshot.metrics.size());
    for (std::size_t index = 0; index < snapshot.metrics.size(); ++index) {
        const PerformanceMetricRow& metric = snapshot.metrics[index];
        Ksword::Ui::VirtualListRow row{};
        // Group plus name identifies a metric across refreshes even though the
        // row order can shift when adapters or cores appear and disappear.
        row.stableKey = metric.group + L"\x1F" + metric.name;
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        row.cells.push_back(metric.group);
        row.cells.push_back(metric.name);
        row.cells.push_back(metric.value);
        row.cells.push_back(metric.source);
        if (!metric.valid) {
            row.textColor = Ksword::Ui::AppTheme().mutedTextColor;
        }
        rows.push_back(std::move(row));
    }
    state.metricList.setRows(std::move(rows));
}

void UpdatePauseButton(PerformanceViewState& state) {
    if (state.pauseButton) {
        ::SetWindowTextW(state.pauseButton, state.paused ? L"继续" : L"暂停");
    }
}

void BeginSample(PerformanceViewState& state) {
    if (!state.sampleTask || !state.sampler) {
        return;
    }
    if (!state.everLoaded) {
        Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在打开性能计数器并等待首个采样周期…");
    }

    const std::shared_ptr<PerformanceSampler> sampler = state.sampler;
    state.sampleTask->request(
        // The sampler is captured by shared_ptr so an in-flight collection keeps
        // it alive even if this page is destroyed before the worker returns.
        [sampler] { return sampler->sample(); },
        [&state](std::uint64_t, std::optional<PerformanceSnapshot>&& snapshot, std::exception_ptr error) {
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"性能采样异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty()
                    ? L"性能计数器不可用。"
                    : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            const HWND list = state.metricList.hwnd();
            const std::wstring selectedStableKey =
                StableKeyFromListItem(state, list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1);
            const std::wstring topStableKey =
                StableKeyFromListItem(state, list ? ListView_GetTopIndex(list) : -1);

            BuildRows(state, *snapshot);
            ApplyFilter(state, selectedStableKey, topStableKey);
            state.everLoaded = true;
            state.resolutionText = snapshot->counterResolutionText;

            SYSTEMTIME now{};
            ::GetLocalTime(&now);
            wchar_t stamp[32] = {};
            swprintf_s(stamp, L"%02u:%02u:%02u",
                static_cast<unsigned>(now.wHour), static_cast<unsigned>(now.wMinute),
                static_cast<unsigned>(now.wSecond));
            state.statusText = L"共 " + std::to_wstring(snapshot->metrics.size()) + L" 项指标，最近采样 " +
                stamp + L"。" + state.resolutionText;
            if (state.paused) {
                state.statusText += L"（已暂停自动刷新）";
            }
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void ShowContextMenu(PerformanceViewState& state, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING, kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"立即刷新");

    const int command = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (static_cast<UINT>(command)) {
    case kMenuCopyRow:
        state.statusText = CopyText(state.hwnd, RowsAsText(state, false)) ? L"已复制选中行。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuCopyVisible:
        state.statusText = CopyText(state.hwnd, RowsAsText(state, true)) ? L"已复制可见行。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuRefresh:
        BeginSample(state);
        break;
    default:
        break;
    }
}

void LayoutView(PerformanceViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);

    int cursorX = kGap;
    const int firstRowY = kGap;
    const auto place = [&cursorX, firstRowY](HWND control, int controlWidth) {
        if (control) {
            ::MoveWindow(control, cursorX, firstRowY, controlWidth, kRowHeight, TRUE);
        }
        cursorX += controlWidth + kGap;
    };
    place(state.refreshButton, 80);
    place(state.exportButton, 78);
    place(state.pauseButton, 64);
    if (state.intervalCombo) {
        // Win32 sizes the drop-down list from the control height rather than
        // from the item count, so the height here is the opened list height.
        ::MoveWindow(state.intervalCombo, cursorX, firstRowY, 120, kRowHeight * 6, TRUE);
    }

    const int secondRowY = firstRowY + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, secondRowY, (std::max)(120, width - kGap * 2), kRowHeight, TRUE);
    }

    const int listTop = kHeaderHeight;
    const int listHeight = (std::max)(0, height - kStatusHeight - listTop - kGap);
    if (HWND list = state.metricList.hwnd()) {
        ::MoveWindow(list, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
}

bool CreateChildControls(PerformanceViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"立即刷新", 0, 0, 0, 0);
    state.exportButton = Ksword::Ui::CreateButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.pauseButton = Ksword::Ui::CreateButton(hwnd, kPauseButtonId, L"暂停", 0, 0, 0, 0);
    state.intervalCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIntervalComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.refreshButton || !state.exportButton || !state.pauseButton || !state.intervalCombo) {
        return false;
    }
    for (const wchar_t* label : { L"每 1 秒", L"每 2 秒", L"每 5 秒" }) {
        ::SendMessageW(state.intervalCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    ::SendMessageW(state.intervalCombo, CB_SETCURSEL, 0, 0);

    state.filterBar = Ksword::Ui::CreateFilterBar(
        hwnd, kFilterBarId, L"筛选分组、指标名称、数值与计数器路径", 0, 0, 0, 0);
    if (!state.filterBar) {
        return false;
    }

    if (!state.metricList.create(hwnd, kMetricListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.metricList.addColumns({
        { 0, 100, LVCFMT_LEFT, L"分组" },
        { 1, 220, LVCFMT_LEFT, L"指标" },
        { 2, 200, LVCFMT_LEFT, L"当前值" },
        { 3, 460, LVCFMT_LEFT, L"计数器路径" },
    });
    if (HWND list = state.metricList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
        ::SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    }

    state.loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK PerformanceViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = StateFromWindow(hwnd);
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<PerformanceViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            state->sampler = MakePerformanceSampler(PerformanceScope::System);
            state->sampleTask =
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<PerformanceSnapshot>>(hwnd, kMsgSampleCompleted);
            LayoutView(*state);
            ::SetTimer(hwnd, kSampleTimerId, state->intervalMs, nullptr);
            BeginSample(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutView(*state);
        }
        return 0;
    case WM_TIMER:
        if (state && wParam == kSampleTimerId) {
            // A hidden tab keeps its timer running, and sampling it would burn a
            // PDH collection and a worker thread every second for a table nobody
            // is looking at.
            if (!state->paused && ::IsWindowVisible(hwnd)) {
                BeginSample(*state);
            }
            return 0;
        }
        break;
    case WM_SHOWWINDOW:
        if (state && wParam != 0 && !state->paused) {
            BeginSample(*state);
        }
        break;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        {
            const int id = LOWORD(wParam);
            const int notification = HIWORD(wParam);
            if (id == kFilterBarId && notification == EN_CHANGE) {
                const HWND list = state->metricList.hwnd();
                const std::wstring selectedStableKey =
                    StableKeyFromListItem(*state, list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1);
                ApplyFilter(*state, selectedStableKey, {});
                return 0;
            }
            if (id == kIntervalComboId && notification == CBN_SELCHANGE) {
                const LRESULT selection = ::SendMessageW(state->intervalCombo, CB_GETCURSEL, 0, 0);
                UINT interval = 1000;
                if (selection == 1) {
                    interval = 2000;
                } else if (selection == 2) {
                    interval = 5000;
                }
                state->intervalMs = interval;
                ::SetTimer(hwnd, kSampleTimerId, interval, nullptr);
                return 0;
            }
            if (notification == BN_CLICKED) {
                switch (id) {
                case kRefreshButtonId:
                    BeginSample(*state);
                    return 0;
                case kExportButtonId: {
                    if (state->metricList.visibleIndexes().empty()) {
                        state->statusText = L"没有可导出的可见结果。";
                    } else {
                        std::wstring error;
                        switch (Ksword::Ui::SaveUtf8TextFileWithDialog(hwnd, L"performance.tsv", L"导出性能监控",
                            L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", ExportPerformanceViewTsv(hwnd), &error)) {
                        case Ksword::Ui::SaveTextFileResult::Saved: state->statusText = L"性能监控可见结果已导出。"; break;
                        case Ksword::Ui::SaveTextFileResult::Cancelled: state->statusText = L"已取消导出性能监控结果。"; break;
                        case Ksword::Ui::SaveTextFileResult::Failed: state->statusText = L"导出性能监控结果失败：" + error; break;
                        }
                    }
                    ::InvalidateRect(hwnd, nullptr, TRUE);
                    return 0;
                }
                case kPauseButtonId:
                    state->paused = !state->paused;
                    UpdatePauseButton(*state);
                    state->statusText = state->paused ? L"已暂停自动刷新。" : L"已恢复自动刷新。";
                    ::InvalidateRect(hwnd, nullptr, TRUE);
                    return 0;
                default:
                    break;
                }
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->metricList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->metricList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    ShowContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        if (state) {
            PAINTSTRUCT paint{};
            HDC dc = ::BeginPaint(hwnd, &paint);
            RECT client{};
            ::GetClientRect(hwnd, &client);
            ::FillRect(dc, &client, Ksword::Ui::AppTheme().windowBrush());
            RECT statusRect{ kGap, client.bottom - kStatusHeight, client.right - kGap, client.bottom };
            Ksword::Ui::DrawTextLine(dc, state->statusText, statusRect,
                Ksword::Ui::AppTheme().mutedTextColor, Ksword::Ui::SystemUIFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    default:
        if (state && msg == kMsgSampleCompleted && state->sampleTask) {
            state->sampleTask->consume(hwnd, wParam, lParam);
            return 0;
        }
        if (msg == WM_NCDESTROY && state) {
            ::KillTimer(hwnd, kSampleTimerId);
            // Cancelling first guarantees no completion callback can run against
            // a half-torn-down state.
            if (state->sampleTask) {
                state->sampleTask->cancel();
            }
            state->metricList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsurePerformanceViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = PerformanceViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kPerformanceViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

PerformanceViewState* VerifiedState(HWND view) {
    if (!view) {
        return nullptr;
    }
    wchar_t className[64] = {};
    if (::GetClassNameW(view, className, ARRAYSIZE(className)) <= 0 ||
        std::wcscmp(className, kPerformanceViewClass) != 0) {
        return nullptr;
    }
    return StateFromWindow(view);
}

} // namespace

HWND CreatePerformanceView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsurePerformanceViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kPerformanceViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

void RefreshPerformanceView(HWND view) {
    if (PerformanceViewState* state = VerifiedState(view)) {
        BeginSample(*state);
    }
}

std::wstring ExportPerformanceViewTsv(HWND view) {
    PerformanceViewState* state = VerifiedState(view);
    if (!state) {
        return {};
    }
    std::wstring text = L"分组\t指标\t当前值\t计数器路径\r\n";
    text += RowsAsText(*state, true);
    return text;
}

} // namespace Ksword::Features::HardwareStats
