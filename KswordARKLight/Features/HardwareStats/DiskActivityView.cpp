#include "DiskActivityView.h"

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

constexpr wchar_t kDiskActivityViewClass[] = L"KswordARKLight.HardwareStats.DiskActivityView";

constexpr int kRefreshButtonId = 66201;
constexpr int kPauseButtonId = 66202;
constexpr int kIntervalComboId = 66203;
constexpr int kFilterBarId = 66204;
constexpr int kDiskListId = 66205;
constexpr int kLoadingOverlayId = 66206;
constexpr int kExportButtonId = 66207;

constexpr UINT kMenuCopyRow = 66251;
constexpr UINT kMenuCopyVisible = 66252;
constexpr UINT kMenuRefresh = 66253;

constexpr UINT kMsgSampleCompleted = WM_APP + 665;
constexpr UINT_PTR kSampleTimerId = 1;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 10;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct DiskActivityViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND pauseButton = nullptr;
    HWND intervalCombo = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    Ksword::Ui::VirtualListView diskList;
    std::shared_ptr<PerformanceSampler> sampler;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<PerformanceSnapshot>> sampleTask;
    std::wstring statusText = L"正在打开 PhysicalDisk 计数器…";
    bool paused = false;
    bool everLoaded = false;
    UINT intervalMs = 1000;
};

DiskActivityViewState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<DiskActivityViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
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

std::wstring StableKeyFromListItem(const DiskActivityViewState& state, int item) {
    const auto& visible = state.diskList.visibleIndexes();
    const auto& rows = state.diskList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t sourceIndex = visible[static_cast<std::size_t>(item)];
    return sourceIndex < rows.size() ? rows[sourceIndex].stableKey : std::wstring{};
}

std::wstring RowsAsText(const DiskActivityViewState& state, bool visibleRows) {
    const auto& rows = state.diskList.rows();
    const auto& visible = state.diskList.visibleIndexes();
    const HWND list = state.diskList.hwnd();
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

// ApplyFilter recomputes the visible set on the UI thread. As on the performance
// tab, the row set is a handful of disks rebuilt once per second, so paying for
// a worker thread per keystroke and per tick would cost more than the scan.
void ApplyFilter(DiskActivityViewState& state,
    const std::wstring& selectedStableKey,
    const std::wstring& topStableKey) {
    HWND list = state.diskList.hwnd();
    if (!list) {
        return;
    }
    const std::wstring query = Ksword::Ui::GetFilterBarText(state.filterBar);
    const bool useRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    state.diskList.setVisibleIndexes(
        Ksword::Ui::VirtualListView::FilterRowIndexes(state.diskList.rows(), query, useRegex));

    const auto& visible = state.diskList.visibleIndexes();
    const auto& rows = state.diskList.rows();
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
        ListView_EnsureVisible(list, topItem, FALSE);
    }
}

void BuildRows(DiskActivityViewState& state, const PerformanceSnapshot& snapshot) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(snapshot.disks.size());
    for (std::size_t index = 0; index < snapshot.disks.size(); ++index) {
        const DiskActivityRow& disk = snapshot.disks[index];
        Ksword::Ui::VirtualListRow row{};
        // The PDH instance name ("0 C:") is the only identity a physical disk has
        // in this object, and it survives across sampling passes.
        row.stableKey = disk.instance;
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        row.cells.push_back(disk.instance);
        row.cells.push_back(FormatByteRate(disk.readBytesPerSecond));
        row.cells.push_back(FormatByteRate(disk.writeBytesPerSecond));
        row.cells.push_back(FormatRate(disk.readsPerSecond));
        row.cells.push_back(FormatRate(disk.writesPerSecond));
        row.cells.push_back(FormatDecimal(disk.currentQueueLength));
        row.cells.push_back(FormatDecimal(disk.averageQueueLength));
        row.cells.push_back(FormatPercent(disk.busyPercent));
        row.cells.push_back(FormatLatency(disk.readLatencySeconds));
        row.cells.push_back(FormatLatency(disk.writeLatencySeconds));
        rows.push_back(std::move(row));
    }
    state.diskList.setRows(std::move(rows));
}

void UpdatePauseButton(DiskActivityViewState& state) {
    if (state.pauseButton) {
        ::SetWindowTextW(state.pauseButton, state.paused ? L"继续" : L"暂停");
    }
}

void BeginSample(DiskActivityViewState& state) {
    if (!state.sampleTask || !state.sampler) {
        return;
    }
    if (!state.everLoaded) {
        Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在打开磁盘计数器并等待首个采样周期…");
    }

    const std::shared_ptr<PerformanceSampler> sampler = state.sampler;
    state.sampleTask->request(
        [sampler] { return sampler->sample(); },
        [&state](std::uint64_t, std::optional<PerformanceSnapshot>&& snapshot, std::exception_ptr error) {
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"磁盘采样异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty()
                    ? L"PhysicalDisk 计数器不可用。"
                    : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            const HWND list = state.diskList.hwnd();
            const std::wstring selectedStableKey =
                StableKeyFromListItem(state, list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1);
            const std::wstring topStableKey =
                StableKeyFromListItem(state, list ? ListView_GetTopIndex(list) : -1);

            BuildRows(state, *snapshot);
            ApplyFilter(state, selectedStableKey, topStableKey);
            state.everLoaded = true;

            SYSTEMTIME now{};
            ::GetLocalTime(&now);
            wchar_t stamp[32] = {};
            swprintf_s(stamp, L"%02u:%02u:%02u",
                static_cast<unsigned>(now.wHour), static_cast<unsigned>(now.wMinute),
                static_cast<unsigned>(now.wSecond));
            state.statusText = L"共 " + std::to_wstring(snapshot->disks.size()) + L" 个磁盘实例（含 _Total 汇总行），最近采样 " +
                stamp + L"。" + snapshot->counterResolutionText;
            if (state.paused) {
                state.statusText += L"（已暂停自动刷新）";
            }
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void ShowContextMenu(DiskActivityViewState& state, POINT screenPoint) {
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

void LayoutView(DiskActivityViewState& state) {
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
        ::MoveWindow(state.intervalCombo, cursorX, firstRowY, 120, kRowHeight * 6, TRUE);
    }

    const int secondRowY = firstRowY + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, secondRowY, (std::max)(120, width - kGap * 2), kRowHeight, TRUE);
    }

    const int listTop = kHeaderHeight;
    const int listHeight = (std::max)(0, height - kStatusHeight - listTop - kGap);
    if (HWND list = state.diskList.hwnd()) {
        ::MoveWindow(list, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
}

bool CreateChildControls(DiskActivityViewState& state) {
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

    state.filterBar = Ksword::Ui::CreateFilterBar(hwnd, kFilterBarId, L"筛选磁盘实例名", 0, 0, 0, 0);
    if (!state.filterBar) {
        return false;
    }

    if (!state.diskList.create(hwnd, kDiskListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.diskList.addColumns({
        { 0, 150, LVCFMT_LEFT, L"物理磁盘" },
        { 1, 120, LVCFMT_RIGHT, L"读取吞吐" },
        { 2, 120, LVCFMT_RIGHT, L"写入吞吐" },
        { 3, 100, LVCFMT_RIGHT, L"读 IOPS" },
        { 4, 100, LVCFMT_RIGHT, L"写 IOPS" },
        { 5, 100, LVCFMT_RIGHT, L"当前队列" },
        { 6, 100, LVCFMT_RIGHT, L"平均队列" },
        { 7, 100, LVCFMT_RIGHT, L"忙碌比例" },
        { 8, 100, LVCFMT_RIGHT, L"读延迟" },
        { 9, 100, LVCFMT_RIGHT, L"写延迟" },
    });
    if (HWND list = state.diskList.hwnd()) {
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

LRESULT CALLBACK DiskActivityViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = StateFromWindow(hwnd);
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<DiskActivityViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            state->sampler = MakePerformanceSampler(PerformanceScope::PhysicalDisk);
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
                const HWND list = state->diskList.hwnd();
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
                    if (state->diskList.visibleIndexes().empty()) {
                        state->statusText = L"没有可导出的可见结果。";
                    } else {
                        std::wstring error;
                        switch (Ksword::Ui::SaveUtf8TextFileWithDialog(hwnd, L"disk_activity.tsv", L"导出磁盘活动",
                            L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", ExportDiskActivityViewTsv(hwnd), &error)) {
                        case Ksword::Ui::SaveTextFileResult::Saved: state->statusText = L"磁盘活动可见结果已导出。"; break;
                        case Ksword::Ui::SaveTextFileResult::Cancelled: state->statusText = L"已取消导出磁盘活动结果。"; break;
                        case Ksword::Ui::SaveTextFileResult::Failed: state->statusText = L"导出磁盘活动结果失败：" + error; break;
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
                if (state->diskList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->diskList.hwnd() && header->code == NM_RCLICK) {
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
            if (state->sampleTask) {
                state->sampleTask->cancel();
            }
            state->diskList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureDiskActivityViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = DiskActivityViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kDiskActivityViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

DiskActivityViewState* VerifiedState(HWND view) {
    if (!view) {
        return nullptr;
    }
    wchar_t className[64] = {};
    if (::GetClassNameW(view, className, ARRAYSIZE(className)) <= 0 ||
        std::wcscmp(className, kDiskActivityViewClass) != 0) {
        return nullptr;
    }
    return StateFromWindow(view);
}

} // namespace

HWND CreateDiskActivityView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureDiskActivityViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kDiskActivityViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

void RefreshDiskActivityView(HWND view) {
    if (DiskActivityViewState* state = VerifiedState(view)) {
        BeginSample(*state);
    }
}

std::wstring ExportDiskActivityViewTsv(HWND view) {
    DiskActivityViewState* state = VerifiedState(view);
    if (!state) {
        return {};
    }
    std::wstring text =
        L"物理磁盘\t读取吞吐\t写入吞吐\t读 IOPS\t写 IOPS\t当前队列\t平均队列\t忙碌比例\t读延迟\t写延迟\r\n";
    text += RowsAsText(*state, true);
    return text;
}

} // namespace Ksword::Features::HardwareStats
