#include "DriverOverviewView.h"

#include "DriverActions.h"
#include "../../Core/EntityRef.h"
#include "../File/PathNavigator.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <cwchar>
#include <memory>
#include <string>
#include <vector>

namespace Ksword::Features::Driver {
namespace {

constexpr wchar_t kDriverOverviewClass[] = L"KswordARKLight.DriverOverviewView";
constexpr int kOverviewListId = 64001;
constexpr int kOverviewFilterId = 64002;
constexpr int kOverviewLoadingOverlayId = 64003;
constexpr UINT kOverviewMenuDetail = 64101;
constexpr UINT kOverviewMenuCopyCell = 64102;
constexpr UINT kOverviewMenuCopyRow = 64103;
constexpr UINT kOverviewMenuCopyName = 64104;
constexpr UINT kOverviewMenuCopyPath = 64105;
constexpr UINT kOverviewMenuCopyVisible = 64106;
constexpr UINT kOverviewMenuOpenDirectory = 64107;
constexpr UINT kMsgOverviewFilterCompleted = WM_APP + 596;
constexpr UINT kMsgOverviewDetailCompleted = WM_APP + 597;
constexpr wchar_t kOverviewDetailClass[] = L"KswordARKLight.DriverOverviewDetailDialog";
constexpr int kOverviewDetailEditId = 64121;
constexpr int kOverviewDetailCopyId = 64122;
constexpr int kOverviewDetailCloseId = 64123;

// DriverOverviewViewState owns the list control and the attached model pointer.
// Inputs arrive through Win32 messages; processing only reads the model and
// renders it into the child list; no ownership of the model is transferred.
struct DriverOverviewViewState {
    HWND hwnd = nullptr;
    HWND filterBar = nullptr;
    HWND listView = nullptr;
    HWND loadingOverlay = nullptr;
    DriverModel* model = nullptr;
    std::vector<DriverOverviewRow> snapshotRows;
    std::vector<DriverOverviewRow> visibleRows;
    Ksword::Ui::VirtualListView virtualList;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t snapshotGeneration = 0;
    std::uint64_t detailRequestId = 0;
    int contextColumn = 0;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<struct OverviewFilterResult>> filterTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<struct OverviewDetailResult>> detailTask;
};

struct OverviewFilterResult {
    std::uint64_t snapshotGeneration = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct OverviewDetailResult {
    std::uint64_t requestId = 0;
    std::wstring text;
};

// DetailDialogState owns one modeless detail window. Input is the generated
// detail text; processing creates an EDIT plus Copy/Close buttons; no driver
// state is modified by this helper.
struct DetailDialogState {
    HWND hwnd = nullptr;
    HWND edit = nullptr;
    HWND copyButton = nullptr;
    HWND closeButton = nullptr;
    HWND owner = nullptr;
    std::wstring title;
    std::wstring text;
};

// StateFromWindow returns the view state previously stored on the HWND. Input
// is the child window; processing reads GWLP_USERDATA; output is null before
// WM_NCCREATE or after WM_NCDESTROY clears the pointer.
DriverOverviewViewState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<DriverOverviewViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// SetChildFont applies the system UI font to one child window. Input is a child
// HWND; processing sends WM_SETFONT; no return value is needed.
void SetChildFont(HWND hwnd) {
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    }
}

// GuessDriverObjectName builds the conventional \Driver\Name fallback from an
// overview row. Input is a kernel module row; processing strips common .sys/.exe
// suffixes and keeps existing object-manager names; output may be empty.
std::wstring GuessDriverObjectName(const DriverOverviewRow& row) {
    std::wstring name = row.driverName;
    if (name.empty()) {
        name = row.pathText;
        const std::size_t slash = name.find_last_of(L"\\/");
        if (slash != std::wstring::npos && slash + 1 < name.size()) {
            name = name.substr(slash + 1);
        }
    }
    if (name.empty()) {
        return {};
    }
    if (name.rfind(L"\\Driver\\", 0) == 0) {
        return name;
    }
    const std::size_t dot = name.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        name.resize(dot);
    }
    return name.empty() ? std::wstring{} : (L"\\Driver\\" + name);
}

// SelectedOverviewRow copies the selected overview model row. Input is the view
// state and output pointer; processing maps the selected list index to the
// current model snapshot; output is true when a row is available.
bool SelectedOverviewRow(const DriverOverviewViewState& state, DriverOverviewRow* rowOut) {
    if (!state.listView || !state.model) {
        return false;
    }
    const int selected = ListView_GetNextItem(state.listView, -1, LVNI_SELECTED);
    if (selected < 0 || selected >= static_cast<int>(state.visibleRows.size())) {
        return false;
    }
    if (rowOut) {
        *rowOut = state.visibleRows[static_cast<std::size_t>(selected)];
    }
    return true;
}

// CopyOverviewText writes selected driver text to the clipboard. Inputs are view
// state and payload; processing delegates clipboard ownership to DriverActions;
// no value is returned because callers retain the non-blocking page state.
void CopyOverviewText(const DriverOverviewViewState& state, const std::wstring& text, const wchar_t* title) {
    (void)title;
    DriverActions::CopyTextToClipboard(state.hwnd, text);
}

// BuildOverviewRowText serializes one overview row. Input is the selected model
// row; output is a TSV-compatible row used by the right-click copy command.
std::wstring BuildOverviewRowText(const DriverOverviewRow& row) {
    return row.driverName + L"\t" +
        row.baseAddressText + L"\t" +
        row.memoryRangeText + L"\t" +
        row.sizeText + L"\t" +
        row.pathText + L"\t" +
        row.signatureText + L"\t" +
        row.statusText + L"\t" +
        row.anomalyText + L"\t" +
        row.capabilityHint;
}

// OverviewCells builds the immutable display cells for a snapshot row. It is
// used by both owner-data rendering and clipboard export, so filtering matches
// exactly the text visible to the user.
std::vector<std::wstring> OverviewCells(const DriverOverviewRow& row) {
    return {
        row.driverName,
        row.baseAddressText,
        row.memoryRangeText,
        row.sizeText,
        row.pathText,
        row.signatureText,
        row.statusText,
        row.anomalyText,
        row.capabilityHint
    };
}

// OverviewStableKey provides selection restoration across a background filter
// or refresh. The path prevents duplicate module display names from colliding.
std::wstring OverviewStableKey(const DriverOverviewRow& row) {
    return row.driverName + L"\n" + row.pathText + L"\n" + row.baseAddressText;
}

std::vector<Ksword::Ui::VirtualListRow> BuildOverviewVirtualRows(const std::vector<DriverOverviewRow>& rows) {
    std::vector<Ksword::Ui::VirtualListRow> displayRows;
    displayRows.reserve(rows.size());
    for (std::size_t index = 0; index < rows.size(); ++index) {
        Ksword::Ui::VirtualListRow display{};
        display.stableKey = OverviewStableKey(rows[index]);
        display.cells = OverviewCells(rows[index]);
        display.itemData = static_cast<LPARAM>(index);
        displayRows.push_back(std::move(display));
    }
    return displayRows;
}

std::wstring StableKeyAt(const DriverOverviewViewState& state, const int visibleIndex) {
    if (visibleIndex < 0 || visibleIndex >= static_cast<int>(state.visibleRows.size())) {
        return {};
    }
    return OverviewStableKey(state.visibleRows[static_cast<std::size_t>(visibleIndex)]);
}

void RestoreListPosition(DriverOverviewViewState& state, const std::wstring& selectedKey, const std::wstring& topKey) {
    int selectedIndex = -1;
    int topIndex = -1;
    for (std::size_t index = 0; index < state.visibleRows.size(); ++index) {
        const std::wstring key = OverviewStableKey(state.visibleRows[index]);
        if (!selectedKey.empty() && key == selectedKey) {
            selectedIndex = static_cast<int>(index);
        }
        if (!topKey.empty() && key == topKey) {
            topIndex = static_cast<int>(index);
        }
    }
    if (selectedIndex >= 0) {
        ListView_SetItemState(state.listView, selectedIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topIndex >= 0) {
        ListView_EnsureVisible(state.listView, topIndex, FALSE);
    }
}

// RegisterDetailDialogClass installs the modeless detail window class. There
// is no input; processing is idempotent; output is true when CreateWindowExW
// can use the class name.
bool RegisterDetailDialogClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        DetailDialogState* state = reinterpret_cast<DetailDialogState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<DetailDialogState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                state->edit = ::CreateWindowExW(
                    WS_EX_CLIENTEDGE,
                    L"EDIT",
                    state->text.c_str(),
                    WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
                    0,
                    0,
                    0,
                    0,
                    hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(kOverviewDetailEditId)),
                    ::GetModuleHandleW(nullptr),
                    nullptr);
                Ksword::Ui::AttachTextFindSupport(state->edit);
                state->copyButton = Ksword::Ui::CreateButton(hwnd, kOverviewDetailCopyId, L"复制详情", 0, 0, 0, 0);
                state->closeButton = Ksword::Ui::CreateButton(hwnd, kOverviewDetailCloseId, L"关闭", 0, 0, 0, 0);
                Ksword::Ui::SetWindowFontRecursive(hwnd);
            }
            return 0;
        case WM_SIZE:
            if (state) {
                RECT rc{};
                ::GetClientRect(hwnd, &rc);
                const int width = rc.right - rc.left;
                const int height = rc.bottom - rc.top;
                const int margin = 8;
                const int buttonHeight = 26;
                ::MoveWindow(state->edit, margin, margin, std::max(80, width - margin * 2), std::max(80, height - buttonHeight - margin * 3), TRUE);
                ::MoveWindow(state->copyButton, margin, std::max(margin, height - buttonHeight - margin), 96, buttonHeight, TRUE);
                ::MoveWindow(state->closeButton, width - 88 - margin, std::max(margin, height - buttonHeight - margin), 88, buttonHeight, TRUE);
            }
            return 0;
        case WM_COMMAND:
            if (state && LOWORD(wParam) == kOverviewDetailCopyId) {
                DriverActions::CopyTextToClipboard(hwnd, state->text);
                return 0;
            }
            if (state && LOWORD(wParam) == kOverviewDetailCloseId) {
                ::DestroyWindow(hwnd);
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
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    wc.lpszClassName = kOverviewDetailClass;
    registered = (::RegisterClassW(&wc) != 0) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

// ShowDetailWindow opens a scrollable, copyable detail popup. Inputs are owner,
// title and body text; processing creates a modeless top-level window; no value
// is returned.
void ShowDetailWindow(HWND owner, const std::wstring& title, const std::wstring& text) {
    if (!RegisterDetailDialogClass()) {
        ::MessageBoxW(owner, text.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
        return;
    }

    auto* state = new DetailDialogState();
    state->owner = owner;
    state->title = title;
    state->text = text;
    HWND hwnd = ::CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        kOverviewDetailClass,
        title.c_str(),
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        860,
        620,
        owner,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
        ::MessageBoxW(owner, text.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
    }
}

// BuildOverviewDetailText formats row-local details and, when possible, R0
// DriverObject details. Input is the selected row; output is a rich text body
// for the detail popup.
std::wstring BuildOverviewDetailText(const DriverOverviewRow& row) {
    std::wstring detail =
        L"DriverName: " + row.driverName + L"\r\n" +
        L"Base: " + row.baseAddressText + L"\r\n" +
        L"MemoryRange: " + row.memoryRangeText + L"\r\n" +
        L"Size: " + row.sizeText + L"\r\n" +
        L"Path: " + row.pathText + L"\r\n" +
        L"Signature: " + row.signatureText + L"\r\n" +
        L"Status: " + row.statusText + L"\r\n" +
        L"Anomaly: " + row.anomalyText + L"\r\n" +
        L"Hint: " + row.capabilityHint + L"\r\n";

    const std::wstring driverObjectName = GuessDriverObjectName(row);
    if (!driverObjectName.empty()) {
        const DriverActionResult r0Detail = DriverActions::BuildDriverObjectDetailText(driverObjectName);
        detail += L"\r\nR0 DriverObject query (" + driverObjectName + L"):\r\n";
        detail += r0Detail.statusText;
    }
    return detail;
}

// ShowOverviewDetail starts the potentially slow R0 DriverObject query away
// from the UI thread. The overlay makes the wait explicit while the list stays
// usable after the result arrives.
void ShowOverviewDetail(DriverOverviewViewState& state) {
    DriverOverviewRow row;
    if (!SelectedOverviewRow(state, &row) || !state.detailTask) {
        return;
    }
    const std::uint64_t requestId = ++state.detailRequestId;
    Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在后台查询 DriverObject 详情…");
    state.detailTask->request(
        [row, requestId] {
            OverviewDetailResult result{};
            result.requestId = requestId;
            result.text = BuildOverviewDetailText(row);
            return result;
        },
        [&state](std::uint64_t, std::optional<OverviewDetailResult>&& result, std::exception_ptr error) {
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !result.has_value() || result->requestId != state.detailRequestId) {
                return;
            }
            ShowDetailWindow(state.hwnd, L"驱动详细信息", result->text);
        });
}

std::wstring DriverDirectoryForOverviewRow(const DriverOverviewRow& row) {
    const std::wstring directory =
        Ksword::Features::File::PathNavigator::parentDirectoryForKnownFilePath(row.pathText);
    // The File browser's ordinary text box expands environment expressions;
    // preserve the snapshot-only boundary by refusing directory names that
    // could be interpreted as an environment-style expression downstream.
    return directory.find(L'%') == std::wstring::npos ? directory : std::wstring{};
}

// OpenOverviewDriverDirectory routes only a strict DOS/UNC parent directory.
// Kernel, device and prefix aliases remain visible in the row but are never
// guessed into a FileBrowser path.
void OpenOverviewDriverDirectory(DriverOverviewViewState& state) {
    DriverOverviewRow row;
    if (!SelectedOverviewRow(state, &row)) {
        return;
    }
    const std::wstring directory = DriverDirectoryForOverviewRow(row);
    if (directory.empty()) {
        return;
    }
    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::FileBrowser;
    request.entity.kind = Ksword::Core::EntityKind::File;
    request.entity.text = directory;
    Ksword::Ui::RequestEntityNavigation(state.hwnd, request);
}

std::wstring BuildOverviewTsv(const DriverOverviewViewState& state);

// ShowOverviewContextMenu displays the overview right-click menu. Inputs are
// the view state and screen coordinate; processing selects the clicked row,
// groups read-only copy/detail actions, and returns no value.
void ShowOverviewContextMenu(DriverOverviewViewState& state, POINT screenPoint) {
    POINT clientPoint = screenPoint;
    ::ScreenToClient(state.listView, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int item = ListView_HitTest(state.listView, &hit);
    state.contextColumn = std::max(0, hit.iSubItem);
    ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (item >= 0 && static_cast<std::size_t>(item) < state.visibleRows.size()) {
        ListView_SetItemState(state.listView, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    DriverOverviewRow selectedRow;
    const bool hasSelection = SelectedOverviewRow(state, &selectedRow);
    const bool hasNavigableDirectory = hasSelection && !DriverDirectoryForOverviewRow(selectedRow).empty();
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kOverviewMenuCopyCell, L"复制单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kOverviewMenuCopyRow, L"复制当前行");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kOverviewMenuCopyName, L"复制驱动名称");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kOverviewMenuCopyPath, L"复制驱动路径");
        ::AppendMenuW(copyMenu, MF_STRING | (!state.visibleRows.empty() ? 0U : MF_GRAYED), kOverviewMenuCopyVisible, L"复制可见结果");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }
    HMENU detailMenu = ::CreatePopupMenu();
    if (detailMenu) {
        ::AppendMenuW(detailMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kOverviewMenuDetail, L"详细信息/R0 DriverObject");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(detailMenu), L"详细信息");
    }
    ::AppendMenuW(menu, MF_STRING | (hasNavigableDirectory ? 0U : MF_GRAYED),
        kOverviewMenuOpenDirectory, L"打开驱动所在目录");

    const UINT command = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (command == kOverviewMenuDetail) {
        ShowOverviewDetail(state);
    } else if (command == kOverviewMenuOpenDirectory) {
        OpenOverviewDriverDirectory(state);
    } else if (command == kOverviewMenuCopyCell ||
        command == kOverviewMenuCopyRow ||
        command == kOverviewMenuCopyName ||
        command == kOverviewMenuCopyPath ||
        command == kOverviewMenuCopyVisible) {
        if (command == kOverviewMenuCopyVisible) {
            CopyOverviewText(state, BuildOverviewTsv(state), L"复制可见驱动结果");
            return;
        }
        DriverOverviewRow row;
        if (!SelectedOverviewRow(state, &row)) {
            return;
        }
        if (command == kOverviewMenuCopyCell) {
            const std::vector<std::wstring> cells = OverviewCells(row);
            const std::size_t column = static_cast<std::size_t>(std::max(0, state.contextColumn));
            CopyOverviewText(state, column < cells.size() ? cells[column] : std::wstring{}, L"复制单元格");
        } else if (command == kOverviewMenuCopyRow) {
            CopyOverviewText(state, BuildOverviewRowText(row), L"复制驱动行");
        } else if (command == kOverviewMenuCopyName) {
            CopyOverviewText(state, row.driverName, L"复制驱动名称");
        } else {
            CopyOverviewText(state, row.pathText, L"复制驱动路径");
        }
    }
}

// OverviewColumns returns the report columns shown by the overview page.
// There is no input; processing returns static descriptors; output is consumed
// by the ListView helper.
std::vector<Ksword::Ui::ListViewColumn> OverviewColumns() {
    return {
        { 0, 190, LVCFMT_LEFT, L"驱动名称" },
        { 1, 145, LVCFMT_LEFT, L"基址" },
        { 2, 260, LVCFMT_LEFT, L"内存区间" },
        { 3, 110, LVCFMT_RIGHT, L"大小" },
        { 4, 420, LVCFMT_LEFT, L"路径" },
        { 5, 160, LVCFMT_LEFT, L"签名/来源" },
        { 6, 180, LVCFMT_LEFT, L"状态" },
        { 7, 320, LVCFMT_LEFT, L"异常标记" },
        { 8, 320, LVCFMT_LEFT, L"能力提示" },
    };
}

std::wstring BuildOverviewTsv(const DriverOverviewViewState& state);

// RequestOverviewFilter filters the immutable preformatted snapshot away from
// the UI thread. A generation check prevents older input or refresh results
// from replacing a newer visible result.
void RequestOverviewFilter(DriverOverviewViewState& state, std::wstring query) {
    if (!state.filterTask || !state.filterRows) {
        return;
    }
    state.filterQuery = std::move(query);
    state.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    const std::uint64_t generation = state.snapshotGeneration;
    const auto rows = state.filterRows;
    const bool useRegex = state.filterUseRegex;
    state.filterTask->request(
        [rows, generation, useRegex, query = state.filterQuery]() mutable {
            OverviewFilterResult result{};
            result.snapshotGeneration = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<OverviewFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value() ||
                result->snapshotGeneration != state.snapshotGeneration ||
                result->query != state.filterQuery ||
                result->useRegex != state.filterUseRegex) {
                return;
            }
            const int selected = ListView_GetNextItem(state.listView, -1, LVNI_SELECTED);
            const std::wstring selectedKey = StableKeyAt(state, selected);
            const std::wstring topKey = StableKeyAt(state, ListView_GetTopIndex(state.listView));
            state.visibleRows.clear();
            state.visibleRows.reserve(result->visibleIndexes.size());
            for (const std::size_t index : result->visibleIndexes) {
                if (index < state.snapshotRows.size()) {
                    state.visibleRows.push_back(state.snapshotRows[index]);
                }
            }
            state.virtualList.setVisibleIndexes(std::move(result->visibleIndexes));
            RestoreListPosition(state, selectedKey, topKey);
        });
}

// PopulateOverviewList installs an immutable virtual-list snapshot. It does
// not enumerate or filter synchronously, so a driver refresh never causes a
// per-row ListView insertion storm on the UI thread.
void PopulateOverviewList(DriverOverviewViewState& state) {
    if (!state.listView || !state.model) {
        return;
    }
    state.snapshotRows = state.model->overviewRows();
    state.filterRows = std::make_shared<const std::vector<Ksword::Ui::VirtualListRow>>(
        BuildOverviewVirtualRows(state.snapshotRows));
    ++state.snapshotGeneration;
    state.virtualList.setRows(*state.filterRows);
    RequestOverviewFilter(state, state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : state.filterQuery);
}

// BuildOverviewTsv converts the rows currently rendered by the virtual list
// into TSV text. Input is the view state; processing serializes its active
// visible indexes so an in-flight filter cannot yield stale export data.
std::wstring BuildOverviewTsv(const DriverOverviewViewState& state) {
    return Ksword::Ui::BuildVisibleVirtualListTsv(
        { L"驱动名称", L"基址", L"内存区间", L"大小", L"路径", L"签名/来源", L"状态", L"异常标记", L"能力提示" },
        state.virtualList);
}

// RegisterDriverOverviewClass installs the child window class once. There is no
// input; processing is idempotent; output is true when CreateWindowExW can use
// the class name.
bool RegisterDriverOverviewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        DriverOverviewViewState* state = StateFromWindow(hwnd);
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<DriverOverviewViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                state->filterBar = Ksword::Ui::CreateFilterBar(hwnd, kOverviewFilterId,
                    L"筛选驱动、路径、签名、状态和异常详情", 0, 0, 0, 0);
                if (state->virtualList.create(hwnd, kOverviewListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
                    state->listView = state->virtualList.hwnd();
                }
                SetChildFont(state->listView);
                state->virtualList.addColumns(OverviewColumns());
                state->loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kOverviewLoadingOverlayId, { 0, 0, 1, 1 });
                state->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<OverviewFilterResult>>(hwnd, kMsgOverviewFilterCompleted);
                state->detailTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<OverviewDetailResult>>(hwnd, kMsgOverviewDetailCompleted);
                PopulateOverviewList(*state);
            }
            return 0;
        case WM_COMMAND:
            if (state && LOWORD(wParam) == kOverviewFilterId && HIWORD(wParam) == EN_CHANGE) {
                RequestOverviewFilter(*state, Ksword::Ui::GetFilterBarText(state->filterBar));
                return 0;
            }
            break;
        case kMsgOverviewFilterCompleted:
            if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgOverviewDetailCompleted:
            if (state && state->detailTask && state->detailTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_NOTIFY:
            if (state) {
                const auto* header = reinterpret_cast<const NMHDR*>(lParam);
                LRESULT virtualResult = 0;
                if (header && state->virtualList.handleNotify(*header, virtualResult)) {
                    return virtualResult;
                }
                if (header && header->hwndFrom == state->listView && header->code == NM_RCLICK) {
                    POINT pt{};
                    ::GetCursorPos(&pt);
                    ShowOverviewContextMenu(*state, pt);
                    return 0;
                }
            }
            break;
        case WM_CONTEXTMENU:
            if (state && reinterpret_cast<HWND>(wParam) == state->listView) {
                POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (pt.x == -1 && pt.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->listView, &rc);
                    pt = { rc.left + 24, rc.top + 24 };
                }
                ShowOverviewContextMenu(*state, pt);
                return 0;
            }
            break;
        case WM_SIZE:
            if (state && state->listView) {
                RECT rc{};
                ::GetClientRect(hwnd, &rc);
                const int width = rc.right - rc.left;
                const int height = rc.bottom - rc.top;
                const int margin = 6;
                const int filterHeight = 28;
                ::MoveWindow(state->filterBar, margin, margin, std::max(80, width - margin * 2), filterHeight, TRUE);
                ::MoveWindow(state->listView, 0, filterHeight + margin * 2, width, std::max(40, height - filterHeight - margin * 2), TRUE);
                ::MoveWindow(state->loadingOverlay, 0, filterHeight + margin * 2, width, std::max(40, height - filterHeight - margin * 2), TRUE);
            }
            return 0;
        case WM_NCDESTROY:
            if (state && state->filterTask) {
                state->filterTask->cancel();
            }
            if (state && state->detailTask) {
                state->detailTask->cancel();
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kDriverOverviewClass;
    if (::RegisterClassW(&wc)) {
        registered = true;
    } else if (::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND CreateDriverOverviewView(HWND parent, const RECT& bounds, DriverModel* model) {
    if (!parent || !RegisterDriverOverviewClass()) {
        return nullptr;
    }

    auto* state = new DriverOverviewViewState();
    state->model = model;
    HWND hwnd = ::CreateWindowExW(
        0,
        kDriverOverviewClass,
        L"",
        WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | WS_VISIBLE,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

void ResizeDriverOverviewView(HWND view, const RECT& bounds) {
    if (view) {
        ::MoveWindow(view,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            TRUE);
    }
}

void RefreshDriverOverviewView(HWND view) {
    DriverOverviewViewState* state = StateFromWindow(view);
    if (state) {
        PopulateOverviewList(*state);
    }
}

std::wstring ExportDriverOverviewViewTsv(HWND view) {
    const DriverOverviewViewState* state = StateFromWindow(view);
    return state ? BuildOverviewTsv(*state) : std::wstring();
}

} // namespace Ksword::Features::Driver
