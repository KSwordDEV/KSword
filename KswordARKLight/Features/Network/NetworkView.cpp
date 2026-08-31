#include "NetworkView.h"

#include "NetworkModel.h"
#include "../NetTools/NetToolsConnectionView.h"
#include "../NetTools/NetToolsDiagnosticView.h"
#include "../NetTools/NetToolsFirewallView.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/TabUtil.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"
#include "../../Ui/WorkspaceHost.h"

#include <algorithm>
#include <commctrl.h>
#include <windowsx.h>

#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::Network {
namespace {

constexpr wchar_t kNetworkViewClass[] = L"KswordARKLight.NetworkFeatureView";
constexpr wchar_t kNetworkAuditPageClass[] = L"KswordARKLight.NetworkAuditPage";

constexpr int kTabControlId = 69005;
constexpr int kAuditRefreshButtonId = 69001;
constexpr int kAuditExportButtonId = 69002;
constexpr int kAuditStatusTextId = 69003;
constexpr int kAuditSummaryTextId = 69004;
constexpr int kAuditListViewId = 69006;
constexpr int kAuditFilterBarId = 69007;
constexpr int kAuditLoadingOverlayId = 69008;

constexpr UINT kMenuCopyCell = 69101;
constexpr UINT kMenuCopyRow = 69102;
constexpr UINT kMenuCopyVisible = 69103;
constexpr UINT kMsgRefreshCompleted = WM_APP + 595;
constexpr UINT kMsgFilterCompleted = WM_APP + 596;

constexpr int kConnectionTabIndex = 0;
constexpr int kDiagnosticTabIndex = 1;
constexpr int kFirewallTabIndex = 2;
constexpr int kFirstAuditTabIndex = 3;
constexpr int kAuditTabCount = 5;

struct NetworkViewState;

struct NetworkFilterResult final {
    int auditIndex = -1;
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct NetworkAuditPageState final {
    NetworkViewState* owner = nullptr;
    int auditIndex = -1;
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND statusText = nullptr;
    HWND summaryText = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    Ksword::Ui::VirtualListView list;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    int contextColumn = 0;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<NetworkFilterResult>> filterTask;
};

struct NetworkViewState final {
    HWND hwnd = nullptr;
    HWND workspace = nullptr;
    HWND connectionView = nullptr;
    HWND diagnosticView = nullptr;
    HWND firewallView = nullptr;
    NetworkAuditModel model;
    std::vector<std::unique_ptr<NetworkAuditPageState>> auditPages;
    bool auditRefreshStarted = false;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<std::vector<NetworkAuditPage>>> refreshTask;
};

NetworkViewState* NetworkStateFromWindow(HWND hwnd) {
    return reinterpret_cast<NetworkViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

NetworkAuditPageState* AuditStateFromWindow(HWND hwnd) {
    return reinterpret_cast<NetworkAuditPageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

int Width(const RECT& rect) {
    return rect.right > rect.left ? rect.right - rect.left : 0;
}

int Height(const RECT& rect) {
    return rect.bottom > rect.top ? rect.bottom - rect.top : 0;
}

NetworkAuditPageState* AuditPageFor(NetworkViewState& state, const int auditIndex) {
    if (auditIndex < 0 || auditIndex >= static_cast<int>(state.auditPages.size())) {
        return nullptr;
    }
    return state.auditPages[static_cast<std::size_t>(auditIndex)].get();
}

void SetStatus(NetworkAuditPageState& page, const std::wstring& text) {
    if (page.statusText) {
        ::SetWindowTextW(page.statusText, text.c_str());
    }
}

void SetSummary(NetworkAuditPageState& page, const std::wstring& text) {
    if (page.summaryText) {
        ::SetWindowTextW(page.summaryText, text.c_str());
    }
}

bool CopyTextToClipboard(HWND owner, const std::wstring& text) {
    return Ksword::Ui::CopyTextToClipboard(owner, text, L"网络审计");
}

std::vector<std::wstring> ColumnTitles(const NetworkAuditPage& page) {
    std::vector<std::wstring> titles;
    titles.reserve(page.columns.size());
    for (const NetworkAuditColumn& column : page.columns) {
        titles.push_back(column.title);
    }
    return titles;
}

std::wstring BuildVisiblePageTsv(const NetworkAuditPageState& page) {
    if (!page.owner) {
        return {};
    }
    const NetworkAuditPage* audit = page.owner->model.pageAt(page.auditIndex);
    return audit ? Ksword::Ui::BuildVisibleVirtualListTsv(ColumnTitles(*audit), page.list) : std::wstring();
}

void ApplyColumns(NetworkAuditPageState& page, const NetworkAuditPage& audit) {
    Ksword::Ui::ClearListViewColumns(page.list.hwnd());
    std::vector<Ksword::Ui::ListViewColumn> columns;
    columns.reserve(audit.columns.size());
    for (std::size_t index = 0; index < audit.columns.size(); ++index) {
        columns.push_back({ static_cast<int>(index), audit.columns[index].width, audit.columns[index].format, audit.columns[index].title });
    }
    page.list.addColumns(columns);
}

void ApplyNetworkFilter(NetworkViewState& state, NetworkFilterResult result) {
    NetworkAuditPageState* page = AuditPageFor(state, result.auditIndex);
    if (!page || result.generation != page->displayGeneration || result.query != page->filterQuery ||
        result.useRegex != page->filterUseRegex) {
        return;
    }
    page->list.setVisibleIndexes(std::move(result.visibleIndexes));
    if (!page->filterQuery.empty()) {
        SetStatus(*page, L"Network 筛选结果 " + std::to_wstring(page->list.rowCount()) + L" 项。");
    }
}

void RequestNetworkFilter(NetworkAuditPageState& page, std::wstring query) {
    if (!page.owner) {
        return;
    }
    page.filterQuery = std::move(query);
    page.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(page.filterBar);
    const auto rows = page.filterRows;
    const int auditIndex = page.auditIndex;
    const std::uint64_t generation = page.displayGeneration;
    const bool useRegex = page.filterUseRegex;
    if (!page.filterTask || !rows) {
        return;
    }
    page.filterTask->request(
        [rows, auditIndex, generation, useRegex, query = page.filterQuery]() mutable {
            NetworkFilterResult result{};
            result.auditIndex = auditIndex;
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&page](std::uint64_t, std::optional<NetworkFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                SetStatus(page, L"Network 筛选任务异常结束，已保留当前可见结果。");
                return;
            }
            if (page.owner) {
                ApplyNetworkFilter(*page.owner, std::move(*result));
            }
        });
}

void RenderAuditPage(NetworkAuditPageState& page) {
    if (!page.owner) {
        return;
    }
    const NetworkAuditPage* audit = page.owner->model.pageAt(page.auditIndex);
    if (!audit) {
        SetSummary(page, L"正在等待后台 Network 审计快照…");
        page.list.setRows({});
        page.filterRows.reset();
        return;
    }
    ApplyColumns(page, *audit);
    auto rows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>();
    rows->reserve(audit->rows.size());
    for (std::size_t index = 0; index < audit->rows.size(); ++index) {
        Ksword::Ui::VirtualListRow row{};
        row.stableKey = std::to_wstring(index);
        row.cells = audit->rows[index].cells;
        for (const std::wstring& cell : row.cells) {
            row.stableKey += L"|" + cell;
        }
        rows->push_back(std::move(row));
    }
    page.list.setRows(*rows);
    page.list.setVisibleIndexes({});
    page.filterRows = std::move(rows);
    ++page.displayGeneration;
    SetSummary(page, audit->summary);
    RequestNetworkFilter(page, page.filterBar ? Ksword::Ui::GetFilterBarText(page.filterBar) : page.filterQuery);
}

void RenderAllAuditPages(NetworkViewState& state) {
    for (const std::unique_ptr<NetworkAuditPageState>& page : state.auditPages) {
        if (page) {
            RenderAuditPage(*page);
        }
    }
}

void SetAuditRefreshEnabled(NetworkViewState& state, const BOOL enabled) {
    for (const std::unique_ptr<NetworkAuditPageState>& page : state.auditPages) {
        if (page && page->refreshButton) {
            ::EnableWindow(page->refreshButton, enabled);
        }
    }
}

void SetAuditLoading(NetworkViewState& state, const bool visible, const wchar_t* text) {
    for (const std::unique_ptr<NetworkAuditPageState>& page : state.auditPages) {
        if (page) {
            Ksword::Ui::SetLoadingOverlay(page->loadingOverlay, visible, text);
        }
    }
}

void SetAuditStatusForAll(NetworkViewState& state, const std::wstring& text) {
    for (const std::unique_ptr<NetworkAuditPageState>& page : state.auditPages) {
        if (page) {
            SetStatus(*page, text);
        }
    }
}

void BeginNetworkRefresh(NetworkViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool firstLoad = state.model.pages().empty();
    SetAuditStatusForAll(state, state.refreshTask->running()
        ? L"Network 刷新已排队，等待当前快照完成…"
        : L"正在后台采集 TCP、UDP、WFP、NDIS、AFD 和 NSI 审计…");
    SetAuditRefreshEnabled(state, FALSE);
    if (firstLoad) {
        SetAuditLoading(state, true, L"正在加载 Network 审计…");
    }
    state.refreshTask->request(
        [] { return BuildNetworkAuditPages(); },
        [&state](std::uint64_t, std::optional<std::vector<NetworkAuditPage>>&& pages, std::exception_ptr error) {
            SetAuditRefreshEnabled(state, TRUE);
            SetAuditLoading(state, false, L"");
            if (error || !pages.has_value()) {
                SetAuditStatusForAll(state, L"Network 后台审计异常结束。请检查驱动状态与访问权限。");
                return;
            }
            state.model.replacePages(std::move(*pages));
            RenderAllAuditPages(state);
            SetAuditStatusForAll(state, L"Network R0 与 R3 审计快照已刷新。");
        });
}

std::wstring SelectedRowsText(const NetworkAuditPageState& page, const bool allVisible) {
    const HWND list = page.list.hwnd();
    const auto& rows = page.list.rows();
    std::wstring text;
    const auto& visible = page.list.visibleIndexes();
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible && (ListView_GetItemState(list, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0) {
            continue;
        }
        const std::size_t source = visible[item];
        if (source < rows.size()) {
            for (std::size_t column = 0; column < rows[source].cells.size(); ++column) {
                if (column != 0) {
                    text.push_back(L'\t');
                }
                text += rows[source].cells[column];
            }
            text += L"\r\n";
        }
    }
    return text;
}

std::wstring SelectedCellText(const NetworkAuditPageState& page) {
    const HWND list = page.list.hwnd();
    const int selected = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
    const auto& visible = page.list.visibleIndexes();
    const auto& rows = page.list.rows();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return {};
    }
    const std::size_t source = visible[static_cast<std::size_t>(selected)];
    if (source >= rows.size() || page.contextColumn < 0 || static_cast<std::size_t>(page.contextColumn) >= rows[source].cells.size()) {
        return {};
    }
    return rows[source].cells[static_cast<std::size_t>(page.contextColumn)];
}

void ShowListContextMenu(NetworkAuditPageState& page, POINT point) {
    POINT client = point;
    ::ScreenToClient(page.list.hwnd(), &client);
    LVHITTESTINFO hit{};
    hit.pt = client;
    const int hitItem = ListView_SubItemHitTest(page.list.hwnd(), &hit);
    if (hitItem >= 0) {
        page.contextColumn = hit.iSubItem;
        ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(page.list.hwnd(), hitItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    const bool hasSelection = ListView_GetNextItem(page.list.hwnd(), -1, LVNI_SELECTED) >= 0;
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kMenuCopyRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING | (!page.list.visibleIndexes().empty() ? 0U : MF_GRAYED), kMenuCopyVisible, L"复制可见结果");
    const UINT command = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, 0, page.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (command == kMenuCopyCell) {
        SetStatus(page, CopyTextToClipboard(page.hwnd, SelectedCellText(page)) ? L"已复制单元格。" : L"复制单元格失败。");
    } else if (command == kMenuCopyRow) {
        SetStatus(page, CopyTextToClipboard(page.hwnd, SelectedRowsText(page, false)) ? L"已复制行。" : L"复制行失败。");
    } else if (command == kMenuCopyVisible) {
        SetStatus(page, CopyTextToClipboard(page.hwnd, SelectedRowsText(page, true)) ? L"已复制可见结果。" : L"复制可见结果失败。");
    }
}

void ExportAuditPage(NetworkAuditPageState& page) {
    const std::wstring text = BuildVisiblePageTsv(page);
    if (text.empty()) {
        SetStatus(page, L"没有可导出的当前可见 Network 审计结果。");
        return;
    }
    std::wstring error;
    const std::wstring fileName = L"network_audit_" + std::to_wstring(page.auditIndex + 1) + L".tsv";
    switch (Ksword::Ui::SaveUtf8TextFileWithDialog(
        page.hwnd, fileName.c_str(), L"导出 Network 审计",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", text, &error)) {
    case Ksword::Ui::SaveTextFileResult::Saved:
        SetStatus(page, L"已导出当前可见 Network 审计结果。");
        break;
    case Ksword::Ui::SaveTextFileResult::Cancelled:
        SetStatus(page, L"已取消导出 Network 审计结果。");
        break;
    case Ksword::Ui::SaveTextFileResult::Failed:
        SetStatus(page, L"导出 Network 审计结果失败：" + error);
        break;
    }
}

void LayoutAuditPage(NetworkAuditPageState& page) {
    RECT client{};
    ::GetClientRect(page.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);
    constexpr int margin = 8;
    constexpr int buttonGap = 6;
    ::MoveWindow(page.refreshButton, margin, margin, 64, 24, TRUE);
    ::MoveWindow(page.exportButton, margin + 64 + buttonGap, margin, 82, 24, TRUE);
    ::MoveWindow(page.statusText, margin + 64 + buttonGap + 82 + 16, margin + 2,
        (std::max)(100, width - 188), 20, TRUE);
    const int summaryTop = margin + 30;
    ::MoveWindow(page.summaryText, margin, summaryTop, (std::max)(100, width - margin * 2), 38, TRUE);
    const int filterTop = summaryTop + 42;
    ::MoveWindow(page.filterBar, margin, filterTop, (std::max)(100, width - margin * 2), 24, TRUE);
    const int listTop = filterTop + 28;
    const int listHeight = (std::max)(1, height - listTop - margin);
    ::MoveWindow(page.list.hwnd(), margin, listTop, (std::max)(1, width - margin * 2), listHeight, TRUE);
    ::MoveWindow(page.loadingOverlay, margin, listTop, (std::max)(1, width - margin * 2), listHeight, TRUE);
}

bool CreateAuditPageControls(NetworkAuditPageState& page) {
    page.refreshButton = Ksword::Ui::CreateButton(page.hwnd, kAuditRefreshButtonId, L"刷新", 0, 0, 0, 0);
    page.exportButton = Ksword::Ui::CreateButton(page.hwnd, kAuditExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    page.statusText = Ksword::Ui::CreateText(page.hwnd, kAuditStatusTextId, L"Network 审计准备就绪。", 0, 0, 0, 0);
    page.summaryText = Ksword::Ui::CreateText(page.hwnd, kAuditSummaryTextId, L"", 0, 0, 0, 0);
    page.filterBar = Ksword::Ui::CreateFilterBar(page.hwnd, kAuditFilterBarId, L"筛选当前页所有列和详情文本", 0, 0, 0, 0);
    if (!page.refreshButton || !page.exportButton || !page.statusText || !page.summaryText || !page.filterBar ||
        !page.list.create(page.hwnd, kAuditListViewId, 0, 0, 1, 1, LVS_SHOWSELALWAYS)) {
        return false;
    }
    ListView_SetExtendedListViewStyle(page.list.hwnd(),
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    page.loadingOverlay = Ksword::Ui::CreateLoadingOverlay(page.hwnd, kAuditLoadingOverlayId, { 0, 0, 1, 1 });
    if (!page.loadingOverlay) {
        return false;
    }
    Ksword::Ui::SetWindowFontRecursive(page.hwnd);
    return true;
}

LRESULT CALLBACK NetworkAuditPageProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    NetworkAuditPageState* page = AuditStateFromWindow(hwnd);
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        page = create ? static_cast<NetworkAuditPageState*>(create->lpCreateParams) : nullptr;
        if (page) {
            page->hwnd = hwnd;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
        }
    }
    switch (message) {
    case WM_CREATE:
        if (!page || !CreateAuditPageControls(*page)) {
            return -1;
        }
        page->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<NetworkFilterResult>>(
            hwnd, kMsgFilterCompleted);
        LayoutAuditPage(*page);
        return 0;
    case WM_SIZE:
        if (page) {
            LayoutAuditPage(*page);
        }
        return 0;
    case WM_COMMAND:
        if (page && LOWORD(wParam) == kAuditFilterBarId && HIWORD(wParam) == EN_CHANGE) {
            RequestNetworkFilter(*page, Ksword::Ui::GetFilterBarText(page->filterBar));
            return 0;
        }
        if (page && HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == kAuditRefreshButtonId) {
            BeginNetworkRefresh(*page->owner);
            return 0;
        }
        if (page && HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == kAuditExportButtonId) {
            ExportAuditPage(*page);
            return 0;
        }
        break;
    case WM_NOTIFY: {
        const auto* header = reinterpret_cast<const NMHDR*>(lParam);
        if (page && header && header->hwndFrom == page->list.hwnd()) {
            LRESULT result = 0;
            if (page->list.handleNotify(*header, result)) {
                return result;
            }
            if (header->code == NM_RCLICK) {
                POINT point{};
                ::GetCursorPos(&point);
                ShowListContextMenu(*page, point);
                return 0;
            }
        }
        break;
    }
    case kMsgFilterCompleted:
        if (page && page->filterTask && page->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_CONTEXTMENU:
        if (page && reinterpret_cast<HWND>(wParam) == page->list.hwnd()) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (point.x == -1 && point.y == -1) {
                RECT rect{};
                ::GetWindowRect(page->list.hwnd(), &rect);
                point = { rect.left + 20, rect.top + 20 };
            }
            ShowListContextMenu(*page, point);
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_NCDESTROY:
        if (page) {
            if (page->filterTask) {
                page->filterTask->cancel();
            }
            page->list.detach();
            page->hwnd = nullptr;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool RegisterNetworkAuditPageClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = NetworkAuditPageProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kNetworkAuditPageClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

void LayoutNetworkChildren(NetworkViewState& state) {
    if (!state.workspace) {
        return;
    }
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    ::MoveWindow(state.workspace, 0, 0, (std::max)(1, Width(client)), (std::max)(1, Height(client)), TRUE);
}

bool CreateNetworkChildren(NetworkViewState& state) {
    if (!RegisterNetworkAuditPageClass()) {
        return false;
    }
    constexpr const wchar_t* kTabTitles[] = {
        L"连接管理", L"网络诊断", L"防火墙规则", L"TCP/UDP R0 cross-view", L"AFD endpoint",
        L"WFP callout/filter/provider", L"NDIS protocol/filter", L"NSI / interfaces / routes"
    };
    state.auditPages.resize(kAuditTabCount);
    std::vector<Ksword::Ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kConnectionTabIndex, kTabTitles[kConnectionTabIndex], L"按需枚举当前 TCP/UDP 连接。",
        [&state](HWND host, const RECT& bounds) {
            state.connectionView = NetTools::CreateNetToolsConnectionView(host, bounds);
            return state.connectionView;
        } });
    tabs.push_back({ kDiagnosticTabIndex, kTabTitles[kDiagnosticTabIndex], L"按需执行网络诊断命令。",
        [&state](HWND host, const RECT& bounds) {
            state.diagnosticView = NetTools::CreateNetToolsDiagnosticView(host, bounds);
            return state.diagnosticView;
        } });
    tabs.push_back({ kFirewallTabIndex, kTabTitles[kFirewallTabIndex], L"按需枚举防火墙规则。",
        [&state](HWND host, const RECT& bounds) {
            state.firewallView = NetTools::CreateNetToolsFirewallView(host, bounds);
            return state.firewallView;
        } });
    for (int auditIndex = 0; auditIndex < kAuditTabCount; ++auditIndex) {
        const int tabId = kFirstAuditTabIndex + auditIndex;
        tabs.push_back({ tabId, kTabTitles[tabId], L"按需创建 R0/R3 网络栈审计页。",
            [&state, auditIndex](HWND host, const RECT& bounds) -> HWND {
                auto page = std::make_unique<NetworkAuditPageState>();
                page->owner = &state;
                page->auditIndex = auditIndex;
                page->hwnd = ::CreateWindowExW(
                    0, kNetworkAuditPageClass, L"",
                    WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                    bounds.left, bounds.top, Width(bounds), Height(bounds), host, nullptr,
                    ::GetModuleHandleW(nullptr), page.get());
                if (!page->hwnd) {
                    return nullptr;
                }
                HWND hwnd = page->hwnd;
                state.auditPages[static_cast<std::size_t>(auditIndex)] = std::move(page);
                RenderAuditPage(*state.auditPages[static_cast<std::size_t>(auditIndex)]);
                return hwnd;
            } });
    }
    Ksword::Ui::WorkspaceOptions options{};
    options.tabControlId = kTabControlId;
    options.initialTabId = kConnectionTabIndex;
    options.margin = 6;
    options.pageActivated = [&state](const int tabId, HWND) {
        if (tabId >= kFirstAuditTabIndex) {
            NetworkAuditPageState* page = AuditPageFor(state, tabId - kFirstAuditTabIndex);
            if (page) {
                RenderAuditPage(*page);
            }
            if (!state.auditRefreshStarted && state.refreshTask) {
                state.auditRefreshStarted = true;
                BeginNetworkRefresh(state);
            }
        }
    };
    state.workspace = Ksword::Ui::CreateWorkspaceHost(
        state.hwnd, { 0, 0, 1, 1 }, std::move(tabs), std::move(options));
    return state.workspace != nullptr;
}

bool RegisterNetworkViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = [](HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) -> LRESULT {
        NetworkViewState* state = NetworkStateFromWindow(hwnd);
        if (message == WM_NCCREATE) {
            const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            state = create ? static_cast<NetworkViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }
        switch (message) {
        case WM_CREATE:
            if (!state || !CreateNetworkChildren(*state)) {
                return -1;
            }
            state->refreshTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<std::vector<NetworkAuditPage>>>(hwnd, kMsgRefreshCompleted);
            LayoutNetworkChildren(*state);
            return 0;
        case WM_SIZE:
            if (state) {
                LayoutNetworkChildren(*state);
            }
            return 0;
        case kMsgRefreshCompleted:
            if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_NCDESTROY:
            if (state) {
                if (state->refreshTask) {
                    state->refreshTask->cancel();
                }
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, message, wParam, lParam);
    };
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kNetworkViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateNetworkFeatureView(HWND parent, const RECT& bounds) {
    if (!parent || !RegisterNetworkViewClass()) {
        return nullptr;
    }
    auto* state = new NetworkViewState();
    HWND hwnd = ::CreateWindowExW(0, kNetworkViewClass, L"Network", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, Width(bounds), Height(bounds), parent, nullptr, ::GetModuleHandleW(nullptr), state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

bool RequestNetworkFeatureViewProcess(HWND view, const DWORD processId) {
    NetworkViewState* state = NetworkStateFromWindow(view);
    if (!state || processId == 0 || !state->workspace ||
        !Ksword::Ui::ActivateWorkspaceHostTab(state->workspace, kConnectionTabIndex, true)) {
        return false;
    }
    state->connectionView = Ksword::Ui::WorkspaceHostPage(state->workspace, kConnectionTabIndex, true);
    return NetTools::RequestNetToolsConnectionProcessFilter(state->connectionView, processId);
}

} // namespace Ksword::Features::Network
