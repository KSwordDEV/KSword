#include "NetToolsConnectionView.h"

#include "NetToolsActions.h"
#include "NetToolsEnumerator.h"
#include "NetToolsModel.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Ksword::Features::NetTools {
namespace {

constexpr wchar_t kConnectionViewClass[] = L"KswordARKLight.NetTools.ConnectionView";

constexpr int kRefreshButtonId = 66101;
constexpr int kCloseButtonId = 66102;
constexpr int kProtocolComboId = 66103;
constexpr int kFilterBarId = 66104;
constexpr int kConnectionListId = 66105;
constexpr int kDetailListId = 66106;
constexpr int kLoadingOverlayId = 66107;
constexpr int kExportButtonId = 66108;

constexpr UINT kMenuClose = 66151;
constexpr UINT kMenuCopyRow = 66152;
constexpr UINT kMenuCopyVisible = 66153;
constexpr UINT kMenuCopyDetail = 66154;
constexpr UINT kMenuRefresh = 66155;
constexpr UINT kMenuOpenProcess = 66156;

constexpr UINT kMsgRefreshCompleted = WM_APP + 670;
constexpr UINT kMsgFilterCompleted = WM_APP + 671;
constexpr UINT kMsgActionCompleted = WM_APP + 672;
constexpr UINT kMsgExternalProcessFilter = WM_APP + 673;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kDetailHeight = 168;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 8;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct ConnectionFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct ConnectionActionTaskResult final {
    NetToolsActionResult action;
    bool refreshRequired = false;
};

struct ConnectionViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND closeButton = nullptr;
    HWND protocolCombo = nullptr;
    HWND filterBar = nullptr;
    HWND detailList = nullptr;
    HWND loadingOverlay = nullptr;
    Ksword::Ui::VirtualListView connectionList;
    ConnectionModel model;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在等待连接快照…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    bool actionInProgress = false;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ConnectionEnumerationResult>> refreshTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ConnectionFilterResult>> filterTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ConnectionActionTaskResult>> actionTask;
};

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
    return Ksword::Ui::CopyTextToClipboard(owner, text, L"网络连接");
}

int SelectedModelIndex(const ConnectionViewState& state) {
    const HWND list = state.connectionList.hwnd();
    const int selected = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.connectionList.visibleIndexes();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return -1;
    }
    const std::size_t modelIndex = visible[static_cast<std::size_t>(selected)];
    return modelIndex <= static_cast<std::size_t>(INT_MAX) ? static_cast<int>(modelIndex) : -1;
}

const ConnectionEntry* SelectedEntry(const ConnectionViewState& state) {
    return state.model.entryAt(SelectedModelIndex(state));
}

std::wstring StableKeyFromListItem(const ConnectionViewState& state, int item) {
    const auto& visible = state.connectionList.visibleIndexes();
    const auto& rows = state.connectionList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t sourceIndex = visible[static_cast<std::size_t>(item)];
    return sourceIndex < rows.size() ? rows[sourceIndex].stableKey : std::wstring{};
}

// ConnectionStableKey identifies one endpoint across refreshes. The full tuple
// plus the owner PID is needed: a busy machine reuses local ports within
// seconds, so a shorter key would restore the selection onto a different socket.
std::wstring ConnectionStableKey(const ConnectionEntry& entry) {
    return ConnectionProtocolText(entry.protocol) + L"|" + entry.localAddress + L"|" +
        std::to_wstring(entry.localPort) + L"|" + entry.remoteAddress + L"|" +
        std::to_wstring(entry.remotePort) + L"|" + std::to_wstring(entry.processId);
}

void ShowDetail(ConnectionViewState& state, int modelIndex) {
    if (!state.detailList) {
        return;
    }
    ListView_DeleteAllItems(state.detailList);
    const ConnectionEntry* entry = state.model.entryAt(modelIndex);
    if (!entry) {
        SetDetailText(state.detailList, 0, 0, L"选择");
        SetDetailText(state.detailList, 0, 1, L"未选择连接");
        return;
    }
    const std::vector<NetToolsProperty> properties = state.model.propertiesForEntry(*entry);
    for (int row = 0; row < static_cast<int>(properties.size()); ++row) {
        SetDetailText(state.detailList, row, 0, properties[static_cast<std::size_t>(row)].name);
        SetDetailText(state.detailList, row, 1, properties[static_cast<std::size_t>(row)].value);
    }
}

// UpdateActionButtons keeps the close button tied to what SetTcpEntry could
// actually act on. Offering it on a UDP endpoint or an IPv6 row would only
// produce an error dialog after the click.
void UpdateActionButtons(ConnectionViewState& state) {
    const ConnectionEntry* entry = state.actionInProgress ? nullptr : SelectedEntry(state);
    if (state.closeButton) {
        ::EnableWindow(state.closeButton, entry != nullptr && ConnectionCanClose(*entry));
    }
}

void RefreshSelectionDependentUi(ConnectionViewState& state) {
    ShowDetail(state, SelectedModelIndex(state));
    UpdateActionButtons(state);
}

void ApplyConnectionFilter(ConnectionViewState& state, ConnectionFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.connectionList.hwnd()) {
        return;
    }

    state.connectionList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.connectionList.visibleIndexes();
    const auto& rows = state.connectionList.rows();
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

    HWND list = state.connectionList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    } else if (!visible.empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topItem >= 0) {
        ListView_EnsureVisible(list, topItem, FALSE);
    }
    RefreshSelectionDependentUi(state);
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(rows.size()) + L" 项。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void RequestConnectionFilter(ConnectionViewState& state,
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
            ConnectionFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            constexpr std::wstring_view pidPrefix = L"pid:";
            if (!useRegex && result.query.rfind(pidPrefix, 0) == 0) {
                const std::wstring suffix = L"|" + result.query.substr(pidPrefix.size());
                for (std::size_t index = 0; index < rows->size(); ++index) {
                    if ((*rows)[index].stableKey.ends_with(suffix)) {
                        result.visibleIndexes.push_back(index);
                    }
                }
            } else {
                result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            }
            return result;
        },
        [&state](std::uint64_t, std::optional<ConnectionFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"连接筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            ApplyConnectionFilter(state, std::move(*result));
        });
}

void BuildRows(ConnectionViewState& state) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    const auto& entries = state.model.entries();
    rows.reserve(entries.size());
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const ConnectionEntry& entry = entries[index];
        Ksword::Ui::VirtualListRow row{};
        row.stableKey = ConnectionStableKey(entry);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        for (int column = 0; column < kColumnCount; ++column) {
            row.cells.push_back(state.model.textForColumn(entry, column));
        }
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>(std::move(rows));
    state.connectionList.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

std::wstring SummaryText(const ConnectionViewState& state) {
    std::size_t tcp = 0;
    std::size_t udp = 0;
    std::size_t established = 0;
    std::size_t listening = 0;
    for (const ConnectionEntry& entry : state.model.allEntries()) {
        if (entry.hasState) {
            ++tcp;
            if (ConnectionIsEstablished(entry)) {
                ++established;
            } else if (ConnectionIsListening(entry)) {
                ++listening;
            }
        } else {
            ++udp;
        }
    }
    return L"TCP " + std::to_wstring(tcp) + L" 条（已建立 " + std::to_wstring(established) +
        L"，监听 " + std::to_wstring(listening) + L"），UDP " + std::to_wstring(udp) +
        L" 条，当前显示 " + std::to_wstring(state.model.entries().size()) + L" 条。";
}

void BeginConnectionRefresh(ConnectionViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool firstLoad = state.connectionList.rows().empty();
    state.statusText = state.refreshTask->running() ? L"连接刷新已排队，等待当前快照完成…" : L"正在后台枚举 TCP/UDP 连接…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (firstLoad) {
        Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在加载连接列表…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.refreshTask->request(
        [] { return EnumerateConnections(); },
        [&state](std::uint64_t, std::optional<ConnectionEnumerationResult>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"连接刷新异常结束，请检查访问权限。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty() ? L"连接枚举失败。" : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const std::wstring selectedStableKey =
                StableKeyFromListItem(state, ListView_GetNextItem(state.connectionList.hwnd(), -1, LVNI_SELECTED));
            const std::wstring topStableKey =
                StableKeyFromListItem(state, ListView_GetTopIndex(state.connectionList.hwnd()));
            const std::wstring diagnostic = snapshot->diagnosticText;
            state.model.setEntries(std::move(snapshot->entries));
            BuildRows(state);
            state.statusText = SummaryText(state);
            if (!diagnostic.empty()) {
                state.statusText += L" " + diagnostic;
            }
            RequestConnectionFilter(state,
                state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : state.filterQuery,
                selectedStableKey,
                topStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void ExportVisibleConnections(ConnectionViewState& state) {
    static const std::vector<std::wstring> kColumnTitles = {
        L"协议", L"本地地址", L"本地端口", L"远端地址", L"远端端口", L"状态", L"PID", L"进程名"
    };
    const std::wstring text = Ksword::Ui::BuildVisibleVirtualListTsv(kColumnTitles, state.connectionList);
    if (text.empty()) {
        state.statusText = L"没有可导出的当前可见连接。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (Ksword::Ui::SaveUtf8TextFileWithDialog(
        state.hwnd, L"network_connections.tsv", L"导出连接列表",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", text, &error)) {
    case Ksword::Ui::SaveTextFileResult::Saved:
        state.statusText = L"已导出当前可见连接。";
        break;
    case Ksword::Ui::SaveTextFileResult::Cancelled:
        state.statusText = L"已取消导出连接列表。";
        break;
    case Ksword::Ui::SaveTextFileResult::Failed:
        state.statusText = L"导出连接列表失败：" + error;
        break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// ConfirmClose is the one prompt on this page. Deleting a TCB tears the socket
// down without a FIN: the peer only finds out when its next send fails, whatever
// was in flight is gone, and nothing restores it. The default button is 否 so a
// stray Enter cannot kill a connection.
bool ConfirmClose(HWND owner, const ConnectionEntry& entry) {
    const std::wstring text =
        L"将结束以下 TCP 连接：\n\n" +
        entry.localAddress + L":" + std::to_wstring(entry.localPort) + L" -> " +
        entry.remoteAddress + L":" + std::to_wstring(entry.remotePort) + L"\n" +
        L"所属进程：" + (entry.processName.empty() ? std::wstring(L"（未知）") : entry.processName) +
        L"（PID " + std::to_wstring(entry.processId) + L"）\n\n" +
        L"连接会被直接删除 TCB，不发送 FIN，传输中的数据将丢失且无法恢复。\n\n是否继续？";
    return ::MessageBoxW(owner, text.c_str(), L"结束连接", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
}

void RunCloseConnection(ConnectionViewState& state) {
    const ConnectionEntry* selected = SelectedEntry(state);
    if (!selected) {
        state.statusText = L"未选择连接。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (!ConnectionCanClose(*selected)) {
        state.statusText = L"该连接不支持结束：仅 IPv4 TCP 的已连接状态可以删除 TCB。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (state.actionInProgress || !state.actionTask) {
        state.statusText = L"连接操作正在执行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (!ConfirmClose(state.hwnd, *selected)) {
        state.statusText = L"已取消结束连接。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    const ConnectionEntry entry = *selected;
    state.actionInProgress = true;
    UpdateActionButtons(state);
    state.statusText = L"正在后台结束连接…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.actionTask->request(
        [entry] {
            ConnectionActionTaskResult result{};
            result.action = CloseTcpConnection(entry);
            // The table is stale either way: a successful delete removes the row,
            // and a failure usually means the stack already moved it on.
            result.refreshRequired = true;
            return result;
        },
        [&state](std::uint64_t, std::optional<ConnectionActionTaskResult>&& result, std::exception_ptr error) {
            state.actionInProgress = false;
            if (error || !result.has_value()) {
                state.statusText = L"结束连接异常结束。";
                UpdateActionButtons(state);
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            state.statusText = result->action.message;
            if (result->refreshRequired) {
                BeginConnectionRefresh(state);
                return;
            }
            UpdateActionButtons(state);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

std::wstring RowsAsText(const ConnectionViewState& state, bool visibleRows) {
    const auto& rows = state.connectionList.rows();
    const auto& visible = state.connectionList.visibleIndexes();
    const HWND list = state.connectionList.hwnd();
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

std::wstring DetailAsText(const ConnectionViewState& state) {
    const ConnectionEntry* entry = SelectedEntry(state);
    if (!entry) {
        return {};
    }
    std::wstring text;
    for (const NetToolsProperty& property : state.model.propertiesForEntry(*entry)) {
        text += property.name + L"\t" + property.value + L"\r\n";
    }
    return text;
}

void ShowConnectionContextMenu(ConnectionViewState& state, POINT screenPoint) {
    const ConnectionEntry* entry = SelectedEntry(state);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool canClose = entry != nullptr && ConnectionCanClose(*entry) && !state.actionInProgress;
    ::AppendMenuW(menu, MF_STRING | (canClose ? MF_ENABLED : MF_GRAYED), kMenuClose, L"结束连接");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (entry ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (entry ? MF_ENABLED : MF_GRAYED), kMenuCopyDetail, L"复制详情");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (entry && entry->processId != 0 ? MF_ENABLED : MF_GRAYED),
        kMenuOpenProcess, L"打开所属进程详细信息");
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

    const int command = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (static_cast<UINT>(command)) {
    case kMenuClose:
        RunCloseConnection(state);
        break;
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
    case kMenuOpenProcess:
        if (entry && entry->processId != 0) {
            Ksword::Core::NavigationRequest request{};
            request.target = Ksword::Core::NavigationTarget::ProcessDetails;
            request.entity.kind = Ksword::Core::EntityKind::Process;
            request.entity.id = entry->processId;
            state.statusText = Ksword::Ui::RequestEntityNavigation(state.hwnd, request)
                ? L"已打开所属进程详细信息。"
                : L"无法打开所属进程详细信息。";
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        }
        break;
    case kMenuRefresh:
        BeginConnectionRefresh(state);
        break;
    default:
        break;
    }
}

void LayoutView(ConnectionViewState& state) {
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
    place(state.refreshButton, 64);
    place(state.exportButton, 82);
    place(state.closeButton, 88);
    // The combo needs room for its drop-down list, which Win32 sizes from the
    // control height rather than from the item count.
    if (state.protocolCombo) {
        ::MoveWindow(state.protocolCombo, cursorX, firstRowY, 120, kRowHeight * 6, TRUE);
    }

    const int secondRowY = firstRowY + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, secondRowY, (std::max)(120, width - kGap * 2), kRowHeight, TRUE);
    }

    const int listTop = kHeaderHeight;
    const int detailTop = (std::max)(listTop, height - kStatusHeight - kDetailHeight);
    const int listHeight = (std::max)(0, detailTop - listTop - kGap);
    if (HWND list = state.connectionList.hwnd()) {
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

bool CreateChildControls(ConnectionViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = Ksword::Ui::CreateButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.closeButton = Ksword::Ui::CreateButton(hwnd, kCloseButtonId, L"结束连接", 0, 0, 0, 0);

    state.protocolCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kProtocolComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.protocolCombo) {
        return false;
    }
    for (const wchar_t* label : { L"全部协议", L"仅 TCP", L"仅 UDP" }) {
        ::SendMessageW(state.protocolCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    ::SendMessageW(state.protocolCombo, CB_SETCURSEL, 0, 0);

    state.filterBar = Ksword::Ui::CreateFilterBar(
        hwnd, kFilterBarId, L"筛选地址、端口、状态、PID 与进程名", 0, 0, 0, 0);

    if (!state.connectionList.create(hwnd, kConnectionListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.connectionList.addColumns({
        { 0, 70, LVCFMT_LEFT, L"协议" },
        { 1, 190, LVCFMT_LEFT, L"本地地址" },
        { 2, 80, LVCFMT_RIGHT, L"本地端口" },
        { 3, 190, LVCFMT_LEFT, L"远端地址" },
        { 4, 80, LVCFMT_RIGHT, L"远端端口" },
        { 5, 110, LVCFMT_LEFT, L"状态" },
        { 6, 70, LVCFMT_RIGHT, L"PID" },
        { 7, 170, LVCFMT_LEFT, L"进程名" },
    });
    if (HWND list = state.connectionList.hwnd()) {
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
    if (!state.refreshButton || !state.exportButton || !state.closeButton || !state.filterBar || !state.detailList || !state.loadingOverlay) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK ConnectionViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<ConnectionViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<ConnectionViewState>();
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
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<ConnectionEnumerationResult>>(hwnd, kMsgRefreshCompleted);
            state->filterTask =
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<ConnectionFilterResult>>(hwnd, kMsgFilterCompleted);
            state->actionTask =
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<ConnectionActionTaskResult>>(hwnd, kMsgActionCompleted);
            LayoutView(*state);
            ShowDetail(*state, -1);
            UpdateActionButtons(*state);
            BeginConnectionRefresh(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutView(*state);
        }
        return 0;
    case kMsgExternalProcessFilter:
        if (state && wParam != 0) {
            const std::wstring query = L"pid:" + std::to_wstring(static_cast<DWORD>(wParam));
            Ksword::Ui::SetFilterBarText(state->filterBar, query, false);
            RequestConnectionFilter(*state, query, {}, {});
            return TRUE;
        }
        return FALSE;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        {
            const int id = LOWORD(wParam);
            const int notification = HIWORD(wParam);
            if (id == kFilterBarId && notification == EN_CHANGE) {
                RequestConnectionFilter(*state, Ksword::Ui::GetFilterBarText(state->filterBar), {}, {});
                return 0;
            }
            if (id == kProtocolComboId && notification == CBN_SELCHANGE) {
                const LRESULT selection = ::SendMessageW(state->protocolCombo, CB_GETCURSEL, 0, 0);
                ConnectionProtocolFilter filter = ConnectionProtocolFilter::All;
                if (selection == 1) {
                    filter = ConnectionProtocolFilter::Tcp;
                } else if (selection == 2) {
                    filter = ConnectionProtocolFilter::Udp;
                }
                // Changing the transport filter reorders the model, so the row
                // snapshot and every cached visible index have to be rebuilt.
                const std::wstring selectedStableKey =
                    StableKeyFromListItem(*state, ListView_GetNextItem(state->connectionList.hwnd(), -1, LVNI_SELECTED));
                state->model.setProtocolFilter(filter);
                BuildRows(*state);
                state->statusText = SummaryText(*state);
                RequestConnectionFilter(*state,
                    Ksword::Ui::GetFilterBarText(state->filterBar), selectedStableKey, {});
                return 0;
            }
            if (notification == BN_CLICKED) {
                switch (id) {
                case kRefreshButtonId:
                    BeginConnectionRefresh(*state);
                    return 0;
                case kExportButtonId:
                    ExportVisibleConnections(*state);
                    return 0;
                case kCloseButtonId:
                    RunCloseConnection(*state);
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
                if (state->connectionList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->connectionList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        RefreshSelectionDependentUi(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->connectionList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    ShowConnectionContextMenu(*state, point);
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
            if (msg == kMsgActionCompleted && state->actionTask) {
                state->actionTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            // Cancel before destruction so a completion callback cannot run
            // against a half-torn-down state.
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            if (state->actionTask) {
                state->actionTask->cancel();
            }
            state->connectionList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureConnectionViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = ConnectionViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kConnectionViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateNetToolsConnectionView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureConnectionViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kConnectionViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

bool RequestNetToolsConnectionProcessFilter(HWND page, const DWORD processId) {
    return page && processId != 0 &&
        ::SendMessageW(page, kMsgExternalProcessFilter, static_cast<WPARAM>(processId), 0) != 0;
}

} // namespace Ksword::Features::NetTools
