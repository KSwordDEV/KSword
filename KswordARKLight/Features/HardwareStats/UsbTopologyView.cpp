#include "UsbTopologyView.h"

#include "DeviceTopologyEnumerator.h"
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
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::HardwareStats {
namespace {

constexpr wchar_t kUsbTopologyViewClass[] = L"KswordARKLight.HardwareStats.UsbTopologyView";

constexpr int kRefreshButtonId = 66301;
constexpr int kFilterBarId = 66302;
constexpr int kNodeListId = 66303;
constexpr int kDetailListId = 66304;
constexpr int kLoadingOverlayId = 66305;
constexpr int kExportButtonId = 66306;

constexpr UINT kMenuCopyRow = 66351;
constexpr UINT kMenuCopyVisible = 66352;
constexpr UINT kMenuCopyDetail = 66353;
constexpr UINT kMenuRefresh = 66354;

constexpr UINT kMsgRefreshCompleted = WM_APP + 670;
constexpr UINT kMsgFilterCompleted = WM_APP + 671;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kDetailHeight = 180;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 11;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct UsbFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct UsbTopologyViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND filterBar = nullptr;
    HWND detailList = nullptr;
    HWND loadingOverlay = nullptr;
    Ksword::Ui::VirtualListView nodeList;
    UsbTopologySnapshot snapshot;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在等待 USB 拓扑快照…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<UsbTopologySnapshot>> refreshTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<UsbFilterResult>> filterTask;
};

UsbTopologyViewState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<UsbTopologyViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

void AddColumn(HWND list, int index, const wchar_t* title, int width) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(list, index, &column);
}

void SetDetailText(HWND list, int row, int column, const std::wstring& text) {
    if (column == 0) {
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = row;
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(text.c_str());
        ListView_InsertItem(list, &item);
        return;
    }
    ListView_SetItemText(list, row, column, const_cast<LPWSTR>(text.c_str()));
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

int SelectedNodeIndex(const UsbTopologyViewState& state) {
    const HWND list = state.nodeList.hwnd();
    const int selected = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.nodeList.visibleIndexes();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return -1;
    }
    const std::size_t nodeIndex = visible[static_cast<std::size_t>(selected)];
    return nodeIndex < state.snapshot.nodes.size() ? static_cast<int>(nodeIndex) : -1;
}

const UsbNode* SelectedNode(const UsbTopologyViewState& state) {
    const int index = SelectedNodeIndex(state);
    return index >= 0 ? &state.snapshot.nodes[static_cast<std::size_t>(index)] : nullptr;
}

std::wstring StableKeyFromListItem(const UsbTopologyViewState& state, int item) {
    const auto& visible = state.nodeList.visibleIndexes();
    const auto& rows = state.nodeList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t sourceIndex = visible[static_cast<std::size_t>(item)];
    return sourceIndex < rows.size() ? rows[sourceIndex].stableKey : std::wstring{};
}

std::vector<std::pair<std::wstring, std::wstring>> PropertiesForNode(const UsbNode& node) {
    std::vector<std::pair<std::wstring, std::wstring>> properties;
    properties.emplace_back(L"设备描述", node.description);
    properties.emplace_back(L"节点类型", UsbNodeKindText(node.kind));
    properties.emplace_back(L"层级深度", std::to_wstring(node.depth));
    properties.emplace_back(L"制造商", node.manufacturer);
    properties.emplace_back(L"厂商 ID (VID)", node.vendorId.empty() ? std::wstring(L"—") : L"0x" + node.vendorId);
    properties.emplace_back(L"产品 ID (PID)", node.productId.empty() ? std::wstring(L"—") : L"0x" + node.productId);
    properties.emplace_back(L"版本 (REV)", node.revision.empty() ? std::wstring(L"—") : node.revision);
    properties.emplace_back(L"序列号", node.serialNumber.empty() ? std::wstring(L"设备未上报") : node.serialNumber);
    properties.emplace_back(L"端口", node.portText);
    properties.emplace_back(L"位置信息", node.locationInfo);
    properties.emplace_back(L"设备类", node.deviceClass);
    properties.emplace_back(L"驱动服务", node.service);
    properties.emplace_back(L"驱动键", node.driverKey);
    properties.emplace_back(L"状态", node.statusText);
    properties.emplace_back(L"问题", node.problemText.empty() ? std::wstring(L"无") : node.problemText);
    properties.emplace_back(L"实例 ID", node.instanceId);
    properties.emplace_back(L"父实例 ID", node.parentInstanceId);
    properties.emplace_back(L"硬件 ID", node.hardwareIds);
    return properties;
}

void ShowDetail(UsbTopologyViewState& state) {
    if (!state.detailList) {
        return;
    }
    ListView_DeleteAllItems(state.detailList);
    const UsbNode* node = SelectedNode(state);
    if (!node) {
        SetDetailText(state.detailList, 0, 0, L"选择");
        SetDetailText(state.detailList, 0, 1, L"未选择 USB 节点");
        return;
    }
    const auto properties = PropertiesForNode(*node);
    for (int row = 0; row < static_cast<int>(properties.size()); ++row) {
        SetDetailText(state.detailList, row, 0, properties[static_cast<std::size_t>(row)].first);
        SetDetailText(state.detailList, row, 1, properties[static_cast<std::size_t>(row)].second);
    }
}

std::wstring RowsAsText(const UsbTopologyViewState& state, bool visibleRows) {
    const auto& rows = state.nodeList.rows();
    const auto& visible = state.nodeList.visibleIndexes();
    const HWND list = state.nodeList.hwnd();
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

std::wstring DetailAsText(const UsbTopologyViewState& state) {
    const UsbNode* node = SelectedNode(state);
    if (!node) {
        return {};
    }
    std::wstring text;
    for (const auto& property : PropertiesForNode(*node)) {
        text += property.first + L"\t" + property.second + L"\r\n";
    }
    return text;
}

void ApplyUsbFilter(UsbTopologyViewState& state, UsbFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.nodeList.hwnd()) {
        return;
    }

    state.nodeList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.nodeList.visibleIndexes();
    const auto& rows = state.nodeList.rows();
    int selectedItem = -1;
    int topItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t sourceIndex = visible[item];
        if (sourceIndex >= rows.size()) {
            continue;
        }
        if (selectedItem < 0 && rows[sourceIndex].stableKey == result.selectedStableKey) {
            selectedItem = static_cast<int>(item);
        }
        if (topItem < 0 && rows[sourceIndex].stableKey == result.topStableKey) {
            topItem = static_cast<int>(item);
        }
    }

    HWND list = state.nodeList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    } else if (!visible.empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topItem >= 0) {
        ListView_EnsureVisible(list, topItem, FALSE);
    }
    ShowDetail(state);
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(rows.size()) + L" 项。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void RequestUsbFilter(UsbTopologyViewState& state,
    std::wstring query,
    std::wstring selectedStableKey,
    std::wstring topStableKey) {
    state.filterQuery = std::move(query);
    state.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    const auto rows = state.filterRows;
    const std::uint64_t generation = state.displayGeneration;
    const bool useRegex = state.filterUseRegex;
    if (!state.filterTask || !rows) {
        return;
    }
    state.filterTask->request(
        [rows, generation, useRegex, query = state.filterQuery,
            selectedStableKey = std::move(selectedStableKey), topStableKey = std::move(topStableKey)]() mutable {
            UsbFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<UsbFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"USB 筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            ApplyUsbFilter(state, std::move(*result));
        });
}

void BuildRows(UsbTopologyViewState& state) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(state.snapshot.nodes.size());
    for (const UsbNode& node : state.snapshot.nodes) {
        Ksword::Ui::VirtualListRow row{};
        // The PnP instance ID is unique per devnode and survives replug as long
        // as the device reports a serial number, which makes it the right key for
        // restoring the selection after a refresh.
        row.stableKey = node.instanceId;
        row.itemData = static_cast<LPARAM>(node.index);
        row.cells.reserve(kColumnCount + 3);
        row.cells.push_back(IndentedName(node.description, node.depth));
        row.cells.push_back(UsbNodeKindText(node.kind));
        row.cells.push_back(node.vendorId.empty() ? std::wstring() : L"0x" + node.vendorId);
        row.cells.push_back(node.productId.empty() ? std::wstring() : L"0x" + node.productId);
        row.cells.push_back(node.serialNumber);
        row.cells.push_back(node.portText);
        row.cells.push_back(node.service);
        row.cells.push_back(node.deviceClass);
        row.cells.push_back(node.statusText);
        row.cells.push_back(node.locationInfo);
        row.cells.push_back(node.instanceId);
        // Detail-only text joins the filter input without becoming a column, so a
        // search for a manufacturer or a raw hardware ID still finds the row.
        row.cells.push_back(node.manufacturer);
        row.cells.push_back(node.hardwareIds);
        row.cells.push_back(node.problemText);
        if (!node.problemText.empty()) {
            row.textColor = RGB(176, 32, 32);
        }
        rows.push_back(std::move(row));
    }

    auto filterRows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>(std::move(rows));
    state.nodeList.setSharedRows(filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

void BeginUsbRefresh(UsbTopologyViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool firstLoad = state.nodeList.rows().empty();
    state.statusText = state.refreshTask->running()
        ? L"USB 刷新已排队，等待当前快照完成…"
        : L"正在后台枚举 USB 设备树…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (firstLoad) {
        Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在枚举 USB 设备树…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);

    state.refreshTask->request(
        [] { return EnumerateUsbTopology(); },
        [&state](std::uint64_t, std::optional<UsbTopologySnapshot>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"USB 枚举异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty() ? L"USB 枚举失败。" : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            const HWND list = state.nodeList.hwnd();
            const std::wstring selectedStableKey =
                StableKeyFromListItem(state, list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1);
            const std::wstring topStableKey =
                StableKeyFromListItem(state, list ? ListView_GetTopIndex(list) : -1);

            std::size_t hubs = 0;
            std::size_t controllers = 0;
            std::size_t problems = 0;
            for (const UsbNode& node : snapshot->nodes) {
                if (node.kind == UsbNodeKind::Hub) {
                    ++hubs;
                } else if (node.kind == UsbNodeKind::HostController) {
                    ++controllers;
                }
                if (!node.problemText.empty()) {
                    ++problems;
                }
            }
            const std::size_t total = snapshot->nodes.size();

            state.snapshot = std::move(*snapshot);
            BuildRows(state);
            state.statusText = L"共 " + std::to_wstring(total) + L" 个节点，主控制器 " +
                std::to_wstring(controllers) + L"，集线器 " + std::to_wstring(hubs) +
                L"，异常 " + std::to_wstring(problems) + L"。";
            RequestUsbFilter(state,
                state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : state.filterQuery,
                selectedStableKey,
                topStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void ShowContextMenu(UsbTopologyViewState& state, POINT screenPoint) {
    const UsbNode* node = SelectedNode(state);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (node ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (node ? MF_ENABLED : MF_GRAYED), kMenuCopyDetail, L"复制详情");
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
    case kMenuCopyDetail:
        state.statusText = CopyText(state.hwnd, DetailAsText(state)) ? L"已复制详情。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuRefresh:
        BeginUsbRefresh(state);
        break;
    default:
        break;
    }
}

void LayoutView(UsbTopologyViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);

    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, kGap, kGap, 80, kRowHeight, TRUE);
    }
    if (state.exportButton) {
        ::MoveWindow(state.exportButton, kGap + 80 + kGap, kGap, 78, kRowHeight, TRUE);
    }
    const int secondRowY = kGap + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, secondRowY, (std::max)(120, width - kGap * 2), kRowHeight, TRUE);
    }

    const int listTop = kHeaderHeight;
    const int detailTop = (std::max)(listTop, height - kStatusHeight - kDetailHeight);
    const int listHeight = (std::max)(0, detailTop - listTop - kGap);
    if (HWND list = state.nodeList.hwnd()) {
        ::MoveWindow(list, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
    if (state.detailList) {
        ::MoveWindow(state.detailList, kGap, detailTop, (std::max)(0, width - kGap * 2),
            (std::max)(0, height - kStatusHeight - detailTop - kGap), TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
}

bool CreateChildControls(UsbTopologyViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = Ksword::Ui::CreateButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.filterBar = Ksword::Ui::CreateFilterBar(
        hwnd, kFilterBarId, L"筛选设备描述、VID/PID、序列号、驱动与实例 ID", 0, 0, 0, 0);
    if (!state.refreshButton || !state.exportButton || !state.filterBar) {
        return false;
    }

    if (!state.nodeList.create(hwnd, kNodeListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.nodeList.addColumns({
        { 0, 320, LVCFMT_LEFT, L"设备" },
        { 1, 80, LVCFMT_LEFT, L"类型" },
        { 2, 70, LVCFMT_LEFT, L"VID" },
        { 3, 70, LVCFMT_LEFT, L"PID" },
        { 4, 140, LVCFMT_LEFT, L"序列号" },
        { 5, 70, LVCFMT_LEFT, L"端口" },
        { 6, 110, LVCFMT_LEFT, L"驱动服务" },
        { 7, 110, LVCFMT_LEFT, L"设备类" },
        { 8, 90, LVCFMT_LEFT, L"状态" },
        { 9, 180, LVCFMT_LEFT, L"位置信息" },
        { 10, 300, LVCFMT_LEFT, L"实例 ID" },
    });
    if (HWND list = state.nodeList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
        ::SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    }

    state.detailList = Ksword::Ui::CreateReportListView(hwnd, kDetailListId, 0, 0, 1, 1, LVS_SINGLESEL);
    if (state.detailList) {
        AddColumn(state.detailList, 0, L"属性", 160);
        AddColumn(state.detailList, 1, L"值", 700);
        ListView_SetExtendedListViewStyle(state.detailList,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    }

    state.loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.detailList || !state.loadingOverlay) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK UsbTopologyViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = StateFromWindow(hwnd);
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<UsbTopologyViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            state->refreshTask =
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<UsbTopologySnapshot>>(hwnd, kMsgRefreshCompleted);
            state->filterTask =
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<UsbFilterResult>>(hwnd, kMsgFilterCompleted);
            LayoutView(*state);
            ShowDetail(*state);
            BeginUsbRefresh(*state);
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
                RequestUsbFilter(*state, Ksword::Ui::GetFilterBarText(state->filterBar), {}, {});
                return 0;
            }
            if (id == kRefreshButtonId && notification == BN_CLICKED) {
                BeginUsbRefresh(*state);
                return 0;
            }
            if (id == kExportButtonId && notification == BN_CLICKED) {
                if (state->nodeList.visibleIndexes().empty()) {
                    state->statusText = L"没有可导出的可见结果。";
                } else {
                    std::wstring error;
                    switch (Ksword::Ui::SaveUtf8TextFileWithDialog(hwnd, L"usb_topology.tsv", L"导出 USB 拓扑",
                        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", ExportUsbTopologyViewTsv(hwnd), &error)) {
                    case Ksword::Ui::SaveTextFileResult::Saved: state->statusText = L"USB 拓扑可见结果已导出。"; break;
                    case Ksword::Ui::SaveTextFileResult::Cancelled: state->statusText = L"已取消导出 USB 拓扑结果。"; break;
                    case Ksword::Ui::SaveTextFileResult::Failed: state->statusText = L"导出 USB 拓扑结果失败：" + error; break;
                    }
                }
                ::InvalidateRect(hwnd, nullptr, TRUE);
                return 0;
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->nodeList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->nodeList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        ShowDetail(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->nodeList.hwnd() && header->code == NM_RCLICK) {
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
        if (state) {
            if (msg == kMsgRefreshCompleted && state->refreshTask) {
                state->refreshTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            state->nodeList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureUsbTopologyViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = UsbTopologyViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kUsbTopologyViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

UsbTopologyViewState* VerifiedState(HWND view) {
    if (!view) {
        return nullptr;
    }
    wchar_t className[64] = {};
    if (::GetClassNameW(view, className, ARRAYSIZE(className)) <= 0 ||
        std::wcscmp(className, kUsbTopologyViewClass) != 0) {
        return nullptr;
    }
    return StateFromWindow(view);
}

} // namespace

HWND CreateUsbTopologyView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureUsbTopologyViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kUsbTopologyViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

void RefreshUsbTopologyView(HWND view) {
    if (UsbTopologyViewState* state = VerifiedState(view)) {
        BeginUsbRefresh(*state);
    }
}

std::wstring ExportUsbTopologyViewTsv(HWND view) {
    UsbTopologyViewState* state = VerifiedState(view);
    if (!state) {
        return {};
    }
    std::wstring text = L"设备\t类型\tVID\tPID\t序列号\t端口\t驱动服务\t设备类\t状态\t位置信息\t实例 ID\r\n";
    text += RowsAsText(*state, true);
    return text;
}

} // namespace Ksword::Features::HardwareStats
