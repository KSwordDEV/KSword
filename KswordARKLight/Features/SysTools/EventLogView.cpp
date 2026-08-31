#include "EventLogView.h"

#include "EventLogReader.h"
#include "../../Core/EntityRef.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::SysTools {
namespace {

constexpr wchar_t kEventLogViewClass[] = L"KswordARKLight.SysTools.EventLogView";

constexpr int kChannelComboId = 67201;
constexpr int kLevelComboId = 67202;
constexpr int kCountComboId = 67203;
constexpr int kRefreshButtonId = 67204;
constexpr int kFilterBarId = 67205;
constexpr int kListId = 67206;
constexpr int kDetailEditId = 67207;
constexpr int kLoadingOverlayId = 67208;

constexpr UINT kMenuCopyRow = 67611;
constexpr UINT kMenuCopyVisible = 67612;
constexpr UINT kMenuCopyMessage = 67613;
constexpr UINT kMenuRefresh = 67614;
constexpr UINT kMenuOpenProcess = 67615;

constexpr UINT kMsgQueryCompleted = WM_APP + 705;
constexpr UINT kMsgFilterCompleted = WM_APP + 706;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kDetailHeight = 140;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 6;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct EventLogFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct EventLogViewState final {
    HWND hwnd = nullptr;
    HWND channelCombo = nullptr;
    HWND levelCombo = nullptr;
    HWND countCombo = nullptr;
    HWND refreshButton = nullptr;
    HWND filterBar = nullptr;
    HWND detailEdit = nullptr;
    HWND loadingOverlay = nullptr;
    Ksword::Ui::VirtualListView list;
    std::vector<EventLogEntry> entries;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在读取系统日志…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<EventLogQueryResult>> queryTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<EventLogFilterResult>> filterTask;
};

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

std::wstring CellText(const EventLogEntry& entry, const int column) {
    switch (column) {
    case 0:
        return entry.timeText;
    case 1:
        return entry.levelText;
    case 2:
        return entry.providerName;
    case 3:
        return std::to_wstring(entry.eventId);
    case 4:
        return entry.processId != 0 ? std::to_wstring(entry.processId) : L"—";
    case 5:
        return entry.message;
    default:
        return {};
    }
}

// LevelRowColor tints the two severities an operator is actually scanning for.
// Information rows keep the default color so the tinted ones still stand out.
COLORREF LevelRowColor(const std::uint8_t level) {
    switch (level) {
    case 1:
    case 2:
        return RGB(176, 32, 32);
    case 3:
        return RGB(158, 104, 0);
    default:
        return CLR_DEFAULT;
    }
}

int SelectedModelIndex(const EventLogViewState& state) {
    const HWND list = state.list.hwnd();
    const int selected = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.list.visibleIndexes();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return -1;
    }
    const std::size_t modelIndex = visible[static_cast<std::size_t>(selected)];
    return modelIndex < state.entries.size() ? static_cast<int>(modelIndex) : -1;
}

const EventLogEntry* SelectedEntry(const EventLogViewState& state) {
    const int index = SelectedModelIndex(state);
    return index >= 0 ? &state.entries[static_cast<std::size_t>(index)] : nullptr;
}

std::wstring DetailTextForEntry(const EventLogEntry& entry) {
    std::wostringstream stream;
    stream << L"时间：" << entry.timeText << L"\r\n"
        << L"级别：" << entry.levelText << L"\r\n"
        << L"来源：" << entry.providerName << L"\r\n"
        << L"事件 ID：" << entry.eventId << L"\r\n"
        << L"记录号：" << entry.recordId << L"\r\n"
        << L"进程 ID：" << (entry.processId != 0 ? std::to_wstring(entry.processId) : std::wstring(L"—")) << L"\r\n"
        << L"计算机：" << entry.computer << L"\r\n\r\n"
        << entry.message;
    return stream.str();
}

void ShowDetail(EventLogViewState& state) {
    if (!state.detailEdit) {
        return;
    }
    const int index = SelectedModelIndex(state);
    if (index < 0) {
        ::SetWindowTextW(state.detailEdit, L"选择一条记录查看完整描述。");
        return;
    }
    const std::wstring text = DetailTextForEntry(state.entries[static_cast<std::size_t>(index)]);
    ::SetWindowTextW(state.detailEdit, text.c_str());
}

// SelectRowAtPoint makes a right-click command apply to the event under the
// pointer, never to a selection that was left by a prior record.
void SelectRowAtPoint(EventLogViewState& state, const POINT screenPoint) {
    const HWND list = state.list.hwnd();
    if (!list) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(list, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int clickedItem = ListView_SubItemHitTest(list, &hit);
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (clickedItem >= 0 && static_cast<std::size_t>(clickedItem) < state.list.visibleIndexes().size()) {
        ListView_SetItemState(list, clickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    ShowDetail(state);
}

void ApplyFilterResult(EventLogViewState& state, EventLogFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.list.hwnd()) {
        return;
    }
    state.list.setVisibleIndexes(std::move(result.visibleIndexes));
    ShowDetail(state);
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void RequestFilter(EventLogViewState& state, std::wstring query) {
    state.filterQuery = std::move(query);
    state.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    const auto rows = state.filterRows;
    const std::uint64_t generation = state.displayGeneration;
    const bool useRegex = state.filterUseRegex;
    if (!state.filterTask || !rows) {
        return;
    }
    state.filterTask->request(
        [rows, generation, useRegex, query = state.filterQuery]() mutable {
            EventLogFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<EventLogFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                return;
            }
            ApplyFilterResult(state, std::move(*result));
        });
}

void BuildRows(EventLogViewState& state) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(state.entries.size());
    for (std::size_t index = 0; index < state.entries.size(); ++index) {
        const EventLogEntry& entry = state.entries[index];
        Ksword::Ui::VirtualListRow row{};
        // The channel record number is unique and monotonic per channel, which
        // is exactly what a stable key needs to survive a refresh.
        row.stableKey = std::to_wstring(entry.recordId);
        row.itemData = static_cast<LPARAM>(index);
        row.textColor = LevelRowColor(entry.level);
        row.cells.reserve(kColumnCount + 1);
        for (int column = 0; column < kColumnCount; ++column) {
            row.cells.push_back(CellText(entry, column));
        }
        row.cells.push_back(entry.computer);
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>(std::move(rows));
    state.list.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

EventLogQueryRequest CurrentRequest(const EventLogViewState& state) {
    EventLogQueryRequest request{};
    const LRESULT channel = state.channelCombo ? ::SendMessageW(state.channelCombo, CB_GETCURSEL, 0, 0) : 0;
    request.channel = channel == 1 ? EventLogChannel::Application : EventLogChannel::System;

    const LRESULT level = state.levelCombo ? ::SendMessageW(state.levelCombo, CB_GETCURSEL, 0, 0) : 0;
    switch (static_cast<int>(level)) {
    case 1: request.level = EventLogLevelFilter::Critical; break;
    case 2: request.level = EventLogLevelFilter::Error; break;
    case 3: request.level = EventLogLevelFilter::Warning; break;
    case 4: request.level = EventLogLevelFilter::Information; break;
    default: request.level = EventLogLevelFilter::All; break;
    }

    const LRESULT count = state.countCombo ? ::SendMessageW(state.countCombo, CB_GETCURSEL, 0, 0) : 0;
    switch (static_cast<int>(count)) {
    case 1: request.maxCount = 500; break;
    case 2: request.maxCount = 1000; break;
    case 3: request.maxCount = 2000; break;
    default: request.maxCount = 200; break;
    }
    return request;
}

void BeginQuery(EventLogViewState& state) {
    if (!state.queryTask) {
        return;
    }
    const EventLogQueryRequest request = CurrentRequest(state);
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    state.statusText = L"正在后台读取事件日志并解析描述…";
    Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在读取事件日志…");
    ::InvalidateRect(state.hwnd, nullptr, TRUE);

    state.queryTask->request(
        [request] { return QueryEventLog(request); },
        [&state](std::uint64_t, std::optional<EventLogQueryResult>&& query, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !query.has_value()) {
                state.statusText = L"事件日志读取异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!query->success) {
                state.entries.clear();
                BuildRows(state);
                state.list.resetVisibleIndexes();
                state.statusText = query->diagnosticText.empty() ? L"事件日志读取失败。" : query->diagnosticText;
                ShowDetail(state);
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            state.entries = std::move(query->entries);
            BuildRows(state);
            std::wostringstream summary;
            summary << query->channelPath << L" 通道读取 " << state.entries.size() << L" 条记录，耗时 "
                << query->elapsedMs << L" ms";
            if (query->unresolvedMessages != 0) {
                summary << L"，其中 " << query->unresolvedMessages << L" 条描述无法解析";
            }
            summary << L"。";
            if (!query->diagnosticText.empty()) {
                summary << query->diagnosticText;
            }
            state.statusText = summary.str();
            RequestFilter(state, state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : std::wstring{});
            ShowDetail(state);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

std::wstring RowsAsText(const EventLogViewState& state, const bool allVisible) {
    const auto& rows = state.list.rows();
    const auto& visible = state.list.visibleIndexes();
    const HWND list = state.list.hwnd();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible &&
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

// OpenSelectedEventProcess intentionally routes only the current numeric PID.
// An event records its provider PID, not a stable process identity, so the
// process page must resolve the current instance before opening details.
void OpenSelectedEventProcess(EventLogViewState& state) {
    const EventLogEntry* entry = SelectedEntry(state);
    if (!entry || entry->processId == 0U) {
        state.statusText = L"当前事件记录没有可导航的 PID。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::ProcessDetails;
    request.entity.kind = Ksword::Core::EntityKind::Process;
    request.entity.id = entry->processId;
    state.statusText = Ksword::Ui::RequestEntityNavigation(state.hwnd, request)
        ? L"已请求打开当前 PID " + std::to_wstring(entry->processId) +
            L" 的进程详细信息；该 PID 来自事件提供程序，目标页会重新解析当前进程实例。"
        : L"无法导航到该事件记录的当前 PID。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void ShowContextMenu(EventLogViewState& state, POINT screenPoint) {
    SelectRowAtPoint(state, screenPoint);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const EventLogEntry* entry = SelectedEntry(state);
    const bool hasSelection = entry != nullptr;
    const bool hasCurrentProcess = entry && entry->processId != 0U;
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyMessage, L"复制完整描述");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (hasCurrentProcess ? MF_ENABLED : MF_GRAYED),
        kMenuOpenProcess, L"查看当前 PID 的进程详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

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
    case kMenuCopyMessage: {
        const int index = SelectedModelIndex(state);
        const std::wstring text = index >= 0
            ? DetailTextForEntry(state.entries[static_cast<std::size_t>(index)])
            : std::wstring{};
        state.statusText = CopyText(state.hwnd, text) ? L"已复制完整描述。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    }
    case kMenuOpenProcess:
        OpenSelectedEventProcess(state);
        break;
    case kMenuRefresh:
        BeginQuery(state);
        break;
    default:
        break;
    }
}

void LayoutView(EventLogViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);

    int cursorX = kGap;
    const int firstRowY = kGap;
    const auto placeCombo = [&cursorX, firstRowY](HWND control, int controlWidth) {
        if (control) {
            // A drop-down list sizes its popup from the control height, not from
            // the item count, so the height passed here is intentionally tall.
            ::MoveWindow(control, cursorX, firstRowY, controlWidth, kRowHeight * 8, TRUE);
        }
        cursorX += controlWidth + kGap;
    };
    placeCombo(state.channelCombo, 120);
    placeCombo(state.levelCombo, 100);
    placeCombo(state.countCombo, 100);
    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, cursorX, firstRowY, 72, kRowHeight, TRUE);
    }

    const int secondRowY = firstRowY + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, secondRowY, (std::max)(120, width - kGap * 2), kRowHeight, TRUE);
    }

    const int listTop = kHeaderHeight;
    const int detailTop = (std::max)(listTop, height - kStatusHeight - kDetailHeight);
    const int listHeight = (std::max)(0, detailTop - listTop - kGap);
    if (HWND list = state.list.hwnd()) {
        ::MoveWindow(list, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
    if (state.detailEdit) {
        ::MoveWindow(state.detailEdit, kGap, detailTop, (std::max)(0, width - kGap * 2),
            (std::max)(0, height - kStatusHeight - detailTop - kGap), TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
}

HWND CreateDropDown(HWND parent, int id) {
    return ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr), nullptr);
}

bool CreateChildControls(EventLogViewState& state) {
    HWND hwnd = state.hwnd;
    state.channelCombo = CreateDropDown(hwnd, kChannelComboId);
    state.levelCombo = CreateDropDown(hwnd, kLevelComboId);
    state.countCombo = CreateDropDown(hwnd, kCountComboId);
    state.refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    if (!state.channelCombo || !state.levelCombo || !state.countCombo || !state.refreshButton) {
        return false;
    }
    for (const wchar_t* label : { L"系统 (System)", L"应用程序 (Application)" }) {
        ::SendMessageW(state.channelCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    for (const wchar_t* label : { L"全部级别", L"关键", L"错误", L"警告", L"信息" }) {
        ::SendMessageW(state.levelCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    for (const wchar_t* label : { L"最近 200 条", L"最近 500 条", L"最近 1000 条", L"最近 2000 条" }) {
        ::SendMessageW(state.countCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    ::SendMessageW(state.channelCombo, CB_SETCURSEL, 0, 0);
    ::SendMessageW(state.levelCombo, CB_SETCURSEL, 0, 0);
    ::SendMessageW(state.countCombo, CB_SETCURSEL, 0, 0);

    state.filterBar = Ksword::Ui::CreateFilterBar(
        hwnd, kFilterBarId, L"筛选时间、级别、来源、事件 ID 与描述", 0, 0, 0, 0);
    if (!state.filterBar) {
        return false;
    }

    if (!state.list.create(hwnd, kListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.list.addColumns({
        { 0, 140, LVCFMT_LEFT, L"时间" },
        { 1, 60, LVCFMT_LEFT, L"级别" },
        { 2, 210, LVCFMT_LEFT, L"来源" },
        { 3, 80, LVCFMT_RIGHT, L"事件 ID" },
        { 4, 70, LVCFMT_RIGHT, L"PID" },
        { 5, 620, LVCFMT_LEFT, L"描述" },
    });
    if (HWND list = state.list.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
        ::SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    }

    state.detailEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"选择一条记录查看完整描述。",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDetailEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.detailEdit) {
        return false;
    }
    ::SendMessageW(state.detailEdit, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    // Event descriptions are long and unstructured, so the pane gets the shared
    // Ctrl+F find bar rather than forcing the reader to scroll them by hand.
    Ksword::Ui::AttachTextFindSupport(state.detailEdit);

    state.loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK EventLogViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<EventLogViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<EventLogViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            state->queryTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<EventLogQueryResult>>(hwnd, kMsgQueryCompleted);
            state->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<EventLogFilterResult>>(hwnd, kMsgFilterCompleted);
            LayoutView(*state);
            BeginQuery(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        {
            const int id = LOWORD(wParam);
            const int notification = HIWORD(wParam);
            if (id == kFilterBarId && notification == EN_CHANGE) {
                RequestFilter(*state, Ksword::Ui::GetFilterBarText(state->filterBar));
                return 0;
            }
            if (notification == CBN_SELCHANGE &&
                (id == kChannelComboId || id == kLevelComboId || id == kCountComboId)) {
                // Channel, level and count all change what the query itself
                // asks for, so each of them has to re-read rather than re-filter.
                BeginQuery(*state);
                return 0;
            }
            if (notification == BN_CLICKED && id == kRefreshButtonId) {
                BeginQuery(*state);
                return 0;
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->list.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->list.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        ShowDetail(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->list.hwnd() && header->code == NM_RCLICK) {
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
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    }
    default:
        if (state) {
            if (msg == kMsgQueryCompleted && state->queryTask) {
                state->queryTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            if (state->queryTask) {
                state->queryTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            state->list.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureEventLogViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = EventLogViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kEventLogViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateEventLogView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureEventLogViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kEventLogViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::SysTools
