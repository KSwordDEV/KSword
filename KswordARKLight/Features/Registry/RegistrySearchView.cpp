#include "RegistrySearchView.h"

#include "RegistryActions.h"
#include "RegistrySearchModel.h"
#include "../../Core/EntityRef.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::Registry {
namespace {

constexpr wchar_t kRegistrySearchViewClass[] = L"KswordARKLight.RegistrySearchView";
constexpr int kSearchHintId = 68200;
constexpr int kPathLabelId = 68201;
constexpr int kPathEditId = 68202;
constexpr int kQueryLabelId = 68203;
constexpr int kQueryEditId = 68204;
constexpr int kSearchButtonId = 68205;
constexpr int kStopButtonId = 68206;
constexpr int kExportButtonId = 68207;
constexpr int kFilterBarId = 68208;
constexpr int kResultListId = 68209;
constexpr int kStatusId = 68210;

constexpr UINT kMenuGoToKey = 68251;
constexpr UINT kMenuCopyCell = 68252;
constexpr UINT kMenuCopyRow = 68253;
constexpr UINT kMenuCopyVisible = 68254;
constexpr UINT kMenuExportVisible = 68255;

constexpr UINT kMsgSearchCompleted = WM_APP + 570;
constexpr UINT kMsgFilterCompleted = WM_APP + 571;

struct RegistrySearchFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct RegistrySearchViewState final {
    HWND hwnd = nullptr;
    HWND hintText = nullptr;
    HWND pathLabel = nullptr;
    HWND pathEdit = nullptr;
    HWND queryLabel = nullptr;
    HWND queryEdit = nullptr;
    HWND searchButton = nullptr;
    HWND stopButton = nullptr;
    HWND exportButton = nullptr;
    HWND filterBar = nullptr;
    HWND statusText = nullptr;
    Ksword::Ui::VirtualListView list;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<RegistrySearchSnapshot>> searchTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<RegistrySearchFilterResult>> filterTask;
    std::shared_ptr<std::atomic_bool> cancelToken;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::vector<RegistrySearchHit> hits;
    std::uint64_t displayGeneration = 0;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::wstring searchStatusText;
    int lastSubItem = 0;
    bool creationSucceeded = false;
};

RegistrySearchViewState* StateFromWindow(HWND hwnd) noexcept {
    return reinterpret_cast<RegistrySearchViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

int Width(const RECT& rect) noexcept {
    return rect.right > rect.left ? rect.right - rect.left : 0;
}

int Height(const RECT& rect) noexcept {
    return rect.bottom > rect.top ? rect.bottom - rect.top : 0;
}

HWND CreateEdit(HWND parent, int id) {
    HWND edit = ::CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        1,
        1,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (edit) {
        ::SendMessageW(edit, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    }
    return edit;
}

std::wstring WindowText(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int length = ::GetWindowTextLengthW(hwnd);
    if (length <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(length) + 1U, L'\0');
    const int copied = ::GetWindowTextW(hwnd, text.data(), length + 1);
    text.resize(copied > 0 ? static_cast<std::size_t>(copied) : 0U);
    return text;
}

const wchar_t* EntryKindText(const RegistrySearchEntryKind kind) {
    return kind == RegistrySearchEntryKind::Key ? L"键" : L"值";
}

std::vector<Ksword::Ui::ListViewColumn> SearchColumns() {
    return {
        { 0, 64, LVCFMT_LEFT, L"类型" },
        { 1, 270, LVCFMT_LEFT, L"键路径" },
        { 2, 150, LVCFMT_LEFT, L"值名称" },
        { 3, 100, LVCFMT_LEFT, L"值类型" },
        { 4, 330, LVCFMT_LEFT, L"数据预览" },
        { 5, 76, LVCFMT_RIGHT, L"字节" },
        { 6, 56, LVCFMT_RIGHT, L"深度" },
        { 7, 76, LVCFMT_LEFT, L"预览" }
    };
}

void RenderStatus(const RegistrySearchViewState& state) {
    if (state.statusText) {
        std::wstring text = state.searchStatusText;
        if (!state.filterQuery.empty()) {
            text += L"；筛选显示 " + std::to_wstring(state.list.visibleIndexes().size()) +
                L" / " + std::to_wstring(state.list.rows().size()) + L" 项。";
        }
        ::SetWindowTextW(state.statusText, text.c_str());
    }
}

void SetStatus(RegistrySearchViewState& state, std::wstring text) {
    state.searchStatusText = std::move(text);
    RenderStatus(state);
}

void SetSearchControlsRunning(RegistrySearchViewState& state, const bool running) {
    if (state.searchButton) {
        ::EnableWindow(state.searchButton, running ? FALSE : TRUE);
    }
    if (state.pathEdit) {
        ::EnableWindow(state.pathEdit, running ? FALSE : TRUE);
    }
    if (state.queryEdit) {
        ::EnableWindow(state.queryEdit, running ? FALSE : TRUE);
    }
    if (state.stopButton) {
        ::EnableWindow(state.stopButton, running ? TRUE : FALSE);
    }
}

std::wstring StableKeyForHit(const RegistrySearchHit& hit, const std::size_t sourceIndex) {
    return std::to_wstring(static_cast<unsigned int>(hit.kind)) + L"|" + hit.keyPath + L"|" +
        hit.valueName + L"|" + std::to_wstring(hit.depth) + L"|" + std::to_wstring(sourceIndex);
}

std::wstring StableKeyFromListItem(const RegistrySearchViewState& state, const int item) {
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t rowIndex = visible[static_cast<std::size_t>(item)];
    return rowIndex < rows.size() ? rows[rowIndex].stableKey : std::wstring{};
}

const RegistrySearchHit* HitForListItem(const RegistrySearchViewState& state, const int item) {
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return nullptr;
    }
    const std::size_t rowIndex = visible[static_cast<std::size_t>(item)];
    if (rowIndex >= rows.size() || rows[rowIndex].itemData < 0) {
        return nullptr;
    }
    const std::size_t sourceIndex = static_cast<std::size_t>(rows[rowIndex].itemData);
    return sourceIndex < state.hits.size() ? &state.hits[sourceIndex] : nullptr;
}

const RegistrySearchHit* SelectedHit(const RegistrySearchViewState& state) {
    return HitForListItem(state, state.list.hwnd()
        ? ListView_GetNextItem(state.list.hwnd(), -1, LVNI_SELECTED)
        : -1);
}

std::vector<std::size_t> VisibleHitIndexes(const RegistrySearchViewState& state) {
    std::vector<std::size_t> indexes;
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    indexes.reserve(visible.size());
    for (const std::size_t rowIndex : visible) {
        if (rowIndex >= rows.size() || rows[rowIndex].itemData < 0) {
            continue;
        }
        const std::size_t hitIndex = static_cast<std::size_t>(rows[rowIndex].itemData);
        if (hitIndex < state.hits.size()) {
            indexes.push_back(hitIndex);
        }
    }
    return indexes;
}

void ApplyFilter(RegistrySearchViewState& state, RegistrySearchFilterResult result) {
    if (!state.list.hwnd() || result.generation != state.displayGeneration ||
        result.query != state.filterQuery || result.useRegex != state.filterUseRegex) {
        return;
    }
    state.list.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    int selectedItem = -1;
    int topItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t rowIndex = visible[item];
        if (rowIndex >= rows.size()) {
            continue;
        }
        if (selectedItem < 0 && rows[rowIndex].stableKey == result.selectedStableKey) {
            selectedItem = static_cast<int>(item);
        }
        if (topItem < 0 && rows[rowIndex].stableKey == result.topStableKey) {
            topItem = static_cast<int>(item);
        }
    }
    ListView_SetItemState(state.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem < 0 && !visible.empty()) {
        selectedItem = 0;
    }
    if (selectedItem >= 0) {
        ListView_SetItemState(state.list.hwnd(), selectedItem,
            LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topItem >= 0) {
        ListView_EnsureVisible(state.list.hwnd(), topItem, FALSE);
    }
    RenderStatus(state);
}

void RequestFilter(RegistrySearchViewState& state, std::wstring selectedStableKey, std::wstring topStableKey) {
    state.filterQuery = state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : std::wstring{};
    state.filterUseRegex = state.filterBar && Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    const auto rows = state.filterRows;
    const std::uint64_t generation = state.displayGeneration;
    if (!state.filterTask || !rows) {
        return;
    }
    state.filterTask->request(
        [rows, generation, query = state.filterQuery, useRegex = state.filterUseRegex,
            selectedStableKey = std::move(selectedStableKey), topStableKey = std::move(topStableKey)]() mutable {
            RegistrySearchFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, result.useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<RegistrySearchFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                SetStatus(state, L"注册表搜索筛选异常结束，已保留当前可见结果。");
                return;
            }
            ApplyFilter(state, std::move(*result));
        });
}

void PopulateHits(RegistrySearchViewState& state) {
    const std::wstring selectedStableKey = StableKeyFromListItem(
        state, ListView_GetNextItem(state.list.hwnd(), -1, LVNI_SELECTED));
    const std::wstring topStableKey = StableKeyFromListItem(state, ListView_GetTopIndex(state.list.hwnd()));
    auto rows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>();
    rows->reserve(state.hits.size());
    for (std::size_t index = 0; index < state.hits.size(); ++index) {
        const RegistrySearchHit& hit = state.hits[index];
        if (!hit.valid) {
            continue;
        }
        Ksword::Ui::VirtualListRow row{};
        row.stableKey = StableKeyForHit(hit, index);
        row.itemData = static_cast<LPARAM>(index);
        row.cells = {
            EntryKindText(hit.kind),
            hit.keyPath,
            hit.valueName.empty() ? std::wstring(L"(默认)") : hit.valueName,
            hit.valueTypeText,
            hit.dataPreview,
            std::to_wstring(hit.dataByteCount),
            std::to_wstring(hit.depth),
            hit.dataPreviewTruncated ? std::wstring(L"已截断") : std::wstring(L"完整")
        };
        rows->push_back(std::move(row));
    }
    state.list.setSharedRows(rows);
    state.filterRows = std::move(rows);
    ++state.displayGeneration;
    RequestFilter(state, selectedStableKey, topStableKey);
}

void BeginSearch(RegistrySearchViewState& state) {
    if (!state.searchTask || state.searchTask->running()) {
        SetStatus(state, L"注册表搜索正在运行或等待停止。");
        return;
    }

    RegistrySearchRequest request{};
    request.startPath = WindowText(state.pathEdit);
    request.query = WindowText(state.queryEdit);
    const RegistrySearchValidation validation = ValidateRegistrySearchRequest(request);
    if (!validation.valid) {
        RegistrySearchSnapshot invalid{};
        invalid.request = validation.request;
        invalid.normalizedQuery = validation.normalizedQuery;
        invalid.stopReason = RegistrySearchStopReason::InvalidRequest;
        invalid.errorText = validation.errorText;
        SetStatus(state, BuildRegistrySearchStatusText(invalid));
        return;
    }

    request = validation.request;
    const auto token = std::make_shared<std::atomic_bool>(false);
    state.cancelToken = token;
    SetSearchControlsRunning(state, true);
    SetStatus(state, L"正在后台搜索当前进程 WinAPI 注册表视图…");
    state.searchTask->request(
        [request = std::move(request), token]() {
            return SearchRegistryWinApi(request, token);
        },
        [&state, token](std::uint64_t, std::optional<RegistrySearchSnapshot>&& snapshot, std::exception_ptr error) {
            if (state.cancelToken != token) {
                return;
            }
            SetSearchControlsRunning(state, false);
            if (error || !snapshot.has_value()) {
                SetStatus(state, L"注册表搜索后台任务异常结束，当前结果未替换。");
                return;
            }
            state.hits = std::move(snapshot->hits);
            PopulateHits(state);
            SetStatus(state, snapshot->statusText.empty()
                ? BuildRegistrySearchStatusText(*snapshot)
                : snapshot->statusText);
        });
}

void StopSearch(RegistrySearchViewState& state) {
    if (!state.cancelToken || !state.searchTask || !state.searchTask->running()) {
        return;
    }
    state.cancelToken->store(true, std::memory_order_relaxed);
    if (state.stopButton) {
        ::EnableWindow(state.stopButton, FALSE);
    }
    SetStatus(state, L"正在请求停止注册表搜索；将保留已扫描的只读结果。");
}

void NavigateToSelectedKey(RegistrySearchViewState& state) {
    const RegistrySearchHit* hit = SelectedHit(state);
    if (!hit || hit->keyPath.empty()) {
        SetStatus(state, L"请选择一个可定位的注册表搜索结果。");
        return;
    }
    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::RegistryBrowser;
    request.entity.kind = Ksword::Core::EntityKind::RegistryKey;
    request.entity.text = hit->keyPath;
    SetStatus(state, Ksword::Ui::RequestEntityNavigation(state.hwnd, request)
        ? L"已转到注册表浏览器；浏览器会重新确认当前路径。"
        : L"无法将该结果转到注册表浏览器。");
}

std::wstring SelectedCellText(const RegistrySearchViewState& state) {
    const int selected = state.list.hwnd()
        ? ListView_GetNextItem(state.list.hwnd(), -1, LVNI_SELECTED)
        : -1;
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return {};
    }
    const std::size_t rowIndex = visible[static_cast<std::size_t>(selected)];
    if (rowIndex >= rows.size() || rows[rowIndex].cells.empty()) {
        return {};
    }
    const int subItem = (std::max)(0, (std::min)(state.lastSubItem, static_cast<int>(rows[rowIndex].cells.size()) - 1));
    return rows[rowIndex].cells[static_cast<std::size_t>(subItem)];
}

void CopySelectedCell(RegistrySearchViewState& state) {
    const std::wstring text = SelectedCellText(state);
    SetStatus(state, !text.empty() && Ksword::Ui::CopyTextToClipboard(state.hwnd, text, L"注册表搜索单元格")
        ? L"已复制搜索单元格。"
        : L"复制搜索单元格失败。");
}

void CopySelectedRow(RegistrySearchViewState& state) {
    const RegistrySearchHit* hit = SelectedHit(state);
    const std::wstring text = hit ? BuildRegistrySearchTsv({ *hit }) : std::wstring{};
    SetStatus(state, !text.empty() && Ksword::Ui::CopyTextToClipboard(state.hwnd, text, L"注册表搜索行")
        ? L"已复制搜索行。"
        : L"复制搜索行失败。");
}

void CopyVisibleRows(RegistrySearchViewState& state) {
    const std::wstring text = BuildVisibleRegistrySearchTsv(state.hits, VisibleHitIndexes(state));
    SetStatus(state, !text.empty() && Ksword::Ui::CopyTextToClipboard(state.hwnd, text, L"注册表搜索可见结果")
        ? L"已复制可见搜索结果。"
        : L"复制可见搜索结果失败。");
}

void ExportVisibleRows(RegistrySearchViewState& state) {
    const std::wstring text = BuildVisibleRegistrySearchTsv(state.hits, VisibleHitIndexes(state));
    if (text.empty()) {
        SetStatus(state, L"当前没有可导出的搜索结果。");
        return;
    }
    std::wstring error;
    switch (Ksword::Ui::SaveUtf8TextFileWithDialog(
        state.hwnd,
        L"ksword-arklight-registry-search.tsv",
        L"导出注册表搜索可见结果",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0",
        L"tsv",
        text,
        &error)) {
    case Ksword::Ui::SaveTextFileResult::Saved:
        SetStatus(state, L"注册表搜索可见结果已导出。");
        break;
    case Ksword::Ui::SaveTextFileResult::Cancelled:
        SetStatus(state, L"已取消导出注册表搜索结果。");
        break;
    case Ksword::Ui::SaveTextFileResult::Failed:
    default:
        SetStatus(state, L"导出注册表搜索结果失败：" + error);
        break;
    }
}

void ShowContextMenu(RegistrySearchViewState& state, POINT screenPoint) {
    const bool hasSelection = SelectedHit(state) != nullptr;
    const bool hasVisibleRows = !VisibleHitIndexes(state).empty();
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kMenuGoToKey, L"转到键");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING | (hasVisibleRows ? 0U : MF_GRAYED), kMenuCopyVisible, L"复制可见结果");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (hasVisibleRows ? 0U : MF_GRAYED), kMenuExportVisible, L"导出可见 TSV");
    const UINT command = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    switch (command) {
    case kMenuGoToKey:
        NavigateToSelectedKey(state);
        break;
    case kMenuCopyCell:
        CopySelectedCell(state);
        break;
    case kMenuCopyRow:
        CopySelectedRow(state);
        break;
    case kMenuCopyVisible:
        CopyVisibleRows(state);
        break;
    case kMenuExportVisible:
        ExportVisibleRows(state);
        break;
    default:
        break;
    }
}

void LayoutChildren(RegistrySearchViewState& state) {
    if (!state.hwnd) {
        return;
    }
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = (std::max)(1, Width(client));
    const int height = (std::max)(1, Height(client));
    constexpr int margin = 8;
    constexpr int hintHeight = 21;
    constexpr int rowTop = margin + hintHeight + 4;
    constexpr int rowHeight = 25;
    constexpr int filterTop = rowTop + rowHeight + 6;
    constexpr int filterHeight = 27;
    constexpr int statusHeight = 22;
    constexpr int gap = 6;
    constexpr int labelWidth = 34;
    constexpr int searchWidth = 54;
    constexpr int stopWidth = 54;
    constexpr int exportWidth = 88;
    const int actionsWidth = searchWidth + stopWidth + exportWidth + gap * 2;
    const int fieldWidth = (std::max)(80, (width - margin * 2 - labelWidth * 2 - actionsWidth - gap * 4) / 2);
    const int pathLeft = margin + labelWidth;
    const int queryLabelLeft = pathLeft + fieldWidth + gap;
    const int queryLeft = queryLabelLeft + labelWidth;
    const int searchLeft = queryLeft + fieldWidth + gap;
    const int listTop = filterTop + filterHeight + 6;
    const int listHeight = (std::max)(1, height - listTop - statusHeight - margin - 4);

    ::MoveWindow(state.hintText, margin, margin, (std::max)(1, width - margin * 2), hintHeight, TRUE);
    ::MoveWindow(state.pathLabel, margin, rowTop, labelWidth, rowHeight, TRUE);
    ::MoveWindow(state.pathEdit, pathLeft, rowTop, fieldWidth, rowHeight, TRUE);
    ::MoveWindow(state.queryLabel, queryLabelLeft, rowTop, labelWidth, rowHeight, TRUE);
    ::MoveWindow(state.queryEdit, queryLeft, rowTop, fieldWidth, rowHeight, TRUE);
    ::MoveWindow(state.searchButton, searchLeft, rowTop, searchWidth, rowHeight, TRUE);
    ::MoveWindow(state.stopButton, searchLeft + searchWidth + gap, rowTop, stopWidth, rowHeight, TRUE);
    ::MoveWindow(state.exportButton, searchLeft + searchWidth + stopWidth + gap * 2, rowTop, exportWidth, rowHeight, TRUE);
    ::MoveWindow(state.filterBar, margin, filterTop, (std::max)(1, width - margin * 2), filterHeight, TRUE);
    ::MoveWindow(state.list.hwnd(), margin, listTop, (std::max)(1, width - margin * 2), listHeight, TRUE);
    ::MoveWindow(state.statusText, margin, listTop + listHeight + 4, (std::max)(1, width - margin * 2), statusHeight, TRUE);
}

bool CreateChildControls(RegistrySearchViewState& state) {
    state.hintText = Ksword::Ui::CreateText(
        state.hwnd, kSearchHintId,
        L"仅搜索当前进程的 WinAPI 注册表视图；不使用驱动，不切换或降级现有 R0 浏览模式。",
        0, 0, 1, 1);
    state.pathLabel = Ksword::Ui::CreateText(state.hwnd, kPathLabelId, L"起点", 0, 0, 1, 1);
    state.pathEdit = CreateEdit(state.hwnd, kPathEditId);
    state.queryLabel = Ksword::Ui::CreateText(state.hwnd, kQueryLabelId, L"关键字", 0, 0, 1, 1);
    state.queryEdit = CreateEdit(state.hwnd, kQueryEditId);
    state.searchButton = Ksword::Ui::CreateButton(state.hwnd, kSearchButtonId, L"搜索", 0, 0, 1, 1);
    state.stopButton = Ksword::Ui::CreateButton(state.hwnd, kStopButtonId, L"停止", 0, 0, 1, 1);
    state.exportButton = Ksword::Ui::CreateButton(state.hwnd, kExportButtonId, L"导出 TSV", 0, 0, 1, 1);
    state.filterBar = Ksword::Ui::CreateFilterBar(state.hwnd, kFilterBarId, L"筛选类型、路径、名称、预览和状态", 0, 0, 1, 1);
    state.statusText = Ksword::Ui::CreateText(state.hwnd, kStatusId, L"", 0, 0, 1, 1);
    if (!state.hintText || !state.pathLabel || !state.pathEdit || !state.queryLabel || !state.queryEdit ||
        !state.searchButton || !state.stopButton || !state.exportButton || !state.filterBar || !state.statusText ||
        !state.list.create(state.hwnd, kResultListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS)) {
        return false;
    }
    if (!state.list.addColumns(SearchColumns())) {
        return false;
    }
    ListView_SetExtendedListViewStyle(
        state.list.hwnd(), LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    ::SetWindowTextW(state.pathEdit, L"HKLM\\SOFTWARE");
    SetSearchControlsRunning(state, false);
    Ksword::Ui::SetWindowFontRecursive(state.hwnd);
    SetStatus(state, L"输入起始路径和关键字后开始有界只读搜索。");
    return true;
}

LRESULT CALLBACK RegistrySearchViewProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    RegistrySearchViewState* state = StateFromWindow(hwnd);
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        state = create ? static_cast<RegistrySearchViewState*>(create->lpCreateParams) : nullptr;
        if (state) {
            state->hwnd = hwnd;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        }
    }

    switch (message) {
    case WM_CREATE:
        if (!state || !CreateChildControls(*state)) {
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return -1;
        }
        state->searchTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<RegistrySearchSnapshot>>(hwnd, kMsgSearchCompleted);
        state->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<RegistrySearchFilterResult>>(hwnd, kMsgFilterCompleted);
        LayoutChildren(*state);
        state->creationSucceeded = true;
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutChildren(*state);
        }
        return 0;
    case kMsgSearchCompleted:
        if (state && state->searchTask && state->searchTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgFilterCompleted:
        if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header && header->hwndFrom == state->list.hwnd()) {
                LRESULT result = 0;
                if (state->list.handleNotify(*header, result)) {
                    return result;
                }
                if (header->code == NM_CLICK || header->code == NM_RCLICK || header->code == NM_DBLCLK) {
                    const auto* activate = reinterpret_cast<const NMITEMACTIVATE*>(lParam);
                    if (activate && activate->iItem >= 0) {
                        state->lastSubItem = activate->iSubItem;
                        ListView_SetItemState(state->list.hwnd(), activate->iItem,
                            LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    }
                }
                if (header->code == NM_DBLCLK) {
                    NavigateToSelectedKey(*state);
                    return 0;
                }
                if (header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    ShowContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
    case WM_COMMAND:
        if (state) {
            const int id = LOWORD(wParam);
            const int code = HIWORD(wParam);
            if (id == kFilterBarId && code == EN_CHANGE) {
                RequestFilter(*state,
                    StableKeyFromListItem(*state, ListView_GetNextItem(state->list.hwnd(), -1, LVNI_SELECTED)),
                    StableKeyFromListItem(*state, ListView_GetTopIndex(state->list.hwnd())));
                return 0;
            }
            if (code == BN_CLICKED && id == kSearchButtonId) {
                BeginSearch(*state);
                return 0;
            }
            if (code == BN_CLICKED && id == kStopButtonId) {
                StopSearch(*state);
                return 0;
            }
            if (code == BN_CLICKED && id == kExportButtonId) {
                ExportVisibleRows(*state);
                return 0;
            }
            if (id == kQueryEditId && code == EN_UPDATE) {
                return 0;
            }
        }
        break;
    case WM_CONTEXTMENU:
        if (state && reinterpret_cast<HWND>(wParam) == state->list.hwnd()) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (point.x == -1 && point.y == -1) {
                RECT rect{};
                ::GetWindowRect(state->list.hwnd(), &rect);
                point = { rect.left + 24, rect.top + 24 };
            }
            ShowContextMenu(*state, point);
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    }
    case WM_NCDESTROY:
        if (state) {
            if (state->cancelToken) {
                state->cancelToken->store(true, std::memory_order_relaxed);
            }
            if (state->searchTask) {
                state->searchTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            state->list.detach();
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            if (state->creationSucceeded) {
                delete state;
            }
        }
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool RegisterRegistrySearchViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = RegistrySearchViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kRegistrySearchViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateRegistrySearchView(HWND parent, const RECT& bounds) {
    if (!parent || !RegisterRegistrySearchViewClass()) {
        return nullptr;
    }
    auto* state = new RegistrySearchViewState();
    HWND page = ::CreateWindowExW(
        0,
        kRegistrySearchViewClass,
        L"Registry Search",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        (std::max)(1, Width(bounds)),
        (std::max)(1, Height(bounds)),
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!page) {
        delete state;
    }
    return page;
}

} // namespace Ksword::Features::Registry
