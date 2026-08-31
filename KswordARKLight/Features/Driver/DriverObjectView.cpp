#include "DriverObjectView.h"

#include "DriverActions.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

namespace Ksword::Features::Driver {
namespace {

constexpr wchar_t kDriverObjectClass[] = L"KswordARKLight.DriverObjectView";
constexpr int kObjectListId = 64011;
constexpr int kObjectFilterId = 64012;
constexpr int kObjectLoadingOverlayId = 64013;
constexpr UINT kObjectMenuDetail = 64201;
constexpr UINT kObjectMenuCopyCell = 64202;
constexpr UINT kObjectMenuCopyRow = 64203;
constexpr UINT kObjectMenuCopyName = 64204;
constexpr UINT kObjectMenuCopyPath = 64205;
constexpr UINT kObjectMenuCopyTarget = 64206;
constexpr UINT kObjectMenuCopyVisible = 64207;
constexpr UINT kMsgObjectFilterCompleted = WM_APP + 598;
constexpr UINT kMsgObjectDetailCompleted = WM_APP + 599;
constexpr wchar_t kObjectDetailClass[] = L"KswordARKLight.DriverObjectDetailDialog";
constexpr int kObjectDetailEditId = 64221;
constexpr int kObjectDetailCopyId = 64222;
constexpr int kObjectDetailCloseId = 64223;

// DriverObjectViewState owns the object report list and model pointer. Inputs
// arrive through Win32 messages; processing renders the current snapshot into
// the child list; no model ownership is transferred here.
struct DriverObjectViewState {
    HWND hwnd = nullptr;
    HWND filterBar = nullptr;
    HWND listView = nullptr;
    HWND loadingOverlay = nullptr;
    DriverModel* model = nullptr;
    std::vector<DriverObjectRow> snapshotRows;
    std::vector<DriverObjectRow> visibleRows;
    Ksword::Ui::VirtualListView virtualList;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t snapshotGeneration = 0;
    std::uint64_t detailRequestId = 0;
    int contextColumn = 0;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<struct ObjectFilterResult>> filterTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<struct ObjectDetailResult>> detailTask;
};

struct ObjectFilterResult {
    std::uint64_t snapshotGeneration = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct ObjectDetailResult {
    std::uint64_t requestId = 0;
    std::wstring text;
};

// DetailDialogState owns the read-only detail popup. Input is generated text;
// processing creates a scrollable EDIT and copy/close controls; no return value
// is needed because the window is modeless.
struct DetailDialogState {
    HWND hwnd = nullptr;
    HWND edit = nullptr;
    HWND copyButton = nullptr;
    HWND closeButton = nullptr;
    std::wstring title;
    std::wstring text;
};

// StateFromWindow returns the view state from the HWND. Input is the child
// window; processing reads GWLP_USERDATA; output is null before creation or
// after WM_NCDESTROY clears the pointer.
DriverObjectViewState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<DriverObjectViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// SetChildFont applies the project UI font to one child window. Input is a
// child HWND; processing sends WM_SETFONT; no value is returned.
void SetChildFont(HWND hwnd) {
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    }
}

// SelectedObjectRow copies the currently selected object row from the attached
// model. Input is view state and optional output pointer; processing maps the
// selected report row to model storage; output is true when a row exists.
bool SelectedObjectRow(const DriverObjectViewState& state, DriverObjectRow* rowOut) {
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

// DriverObjectNameForRow resolves the best DriverObject name for an object-grid
// row. Input may be a native \Driver row, an R0 summary row, or an R0 child
// MajorFunction/DeviceObject row; output is the \Driver\Name string required by
// ArkDriverClient DriverObject IOCTLs.
std::wstring DriverObjectNameForRow(const DriverObjectRow& row) {
    if (!row.fullPathText.empty() &&
        (row.fullPathText.rfind(L"\\Driver\\", 0) == 0 ||
            row.directoryPathText == L"R0 DriverObject" ||
            row.directoryPathText == L"R0 MajorFunction" ||
            row.directoryPathText == L"R0 DeviceObject")) {
        return row.fullPathText;
    }
    if (row.directoryPathText == L"\\Driver" && row.objectTypeText == L"Driver" && !row.objectNameText.empty()) {
        return L"\\Driver\\" + row.objectNameText;
    }
    return {};
}

// CopyObjectText writes selected object text to the clipboard. Inputs are view
// state and payload; processing routes through DriverActions; no value returns.
void CopyObjectText(const DriverObjectViewState& state, const std::wstring& text, const wchar_t* title) {
    (void)title;
    DriverActions::CopyTextToClipboard(state.hwnd, text);
}

// BuildObjectRowText serializes one driver object row. Input is the selected
// model row; output is a TSV-compatible string for the copy-row menu command.
std::wstring BuildObjectRowText(const DriverObjectRow& row) {
    return row.directoryPathText + L"\t" +
        row.objectNameText + L"\t" +
        row.objectTypeText + L"\t" +
        row.fullPathText + L"\t" +
        row.targetPathText + L"\t" +
        row.referenceCountText + L"\t" +
        row.handleCountText + L"\t" +
        row.statusText + L"\t" +
        row.capabilityHint;
}

std::vector<std::wstring> ObjectCells(const DriverObjectRow& row) {
    return {
        row.directoryPathText,
        row.objectNameText,
        row.objectTypeText,
        row.fullPathText,
        row.targetPathText,
        row.referenceCountText,
        row.handleCountText,
        row.statusText,
        row.capabilityHint
    };
}

std::wstring ObjectStableKey(const DriverObjectRow& row) {
    return row.directoryPathText + L"\n" + row.fullPathText + L"\n" + row.objectTypeText;
}

std::vector<Ksword::Ui::VirtualListRow> BuildObjectVirtualRows(const std::vector<DriverObjectRow>& rows) {
    std::vector<Ksword::Ui::VirtualListRow> displayRows;
    displayRows.reserve(rows.size());
    for (std::size_t index = 0; index < rows.size(); ++index) {
        Ksword::Ui::VirtualListRow display{};
        display.stableKey = ObjectStableKey(rows[index]);
        display.cells = ObjectCells(rows[index]);
        display.itemData = static_cast<LPARAM>(index);
        displayRows.push_back(std::move(display));
    }
    return displayRows;
}

std::wstring StableKeyAt(const DriverObjectViewState& state, const int visibleIndex) {
    if (visibleIndex < 0 || visibleIndex >= static_cast<int>(state.visibleRows.size())) {
        return {};
    }
    return ObjectStableKey(state.visibleRows[static_cast<std::size_t>(visibleIndex)]);
}

void RestoreListPosition(DriverObjectViewState& state, const std::wstring& selectedKey, const std::wstring& topKey) {
    int selectedIndex = -1;
    int topIndex = -1;
    for (std::size_t index = 0; index < state.visibleRows.size(); ++index) {
        const std::wstring key = ObjectStableKey(state.visibleRows[index]);
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

// RegisterDetailDialogClass installs the reusable object detail window class.
// There is no input; output is true when the class is available.
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
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(kObjectDetailEditId)),
                    ::GetModuleHandleW(nullptr),
                    nullptr);
                Ksword::Ui::AttachTextFindSupport(state->edit);
                state->copyButton = Ksword::Ui::CreateButton(hwnd, kObjectDetailCopyId, L"复制详情", 0, 0, 0, 0);
                state->closeButton = Ksword::Ui::CreateButton(hwnd, kObjectDetailCloseId, L"关闭", 0, 0, 0, 0);
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
            if (state && LOWORD(wParam) == kObjectDetailCopyId) {
                DriverActions::CopyTextToClipboard(hwnd, state->text);
                return 0;
            }
            if (state && LOWORD(wParam) == kObjectDetailCloseId) {
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
    wc.lpszClassName = kObjectDetailClass;
    registered = (::RegisterClassW(&wc) != 0) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

// ShowDetailWindow creates a scrollable detail popup with copy support. Inputs
// are owner, title, and text body; processing falls back to MessageBox only when
// window creation fails.
void ShowDetailWindow(HWND owner, const std::wstring& title, const std::wstring& text) {
    if (!RegisterDetailDialogClass()) {
        ::MessageBoxW(owner, text.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
        return;
    }

    auto* state = new DetailDialogState();
    state->title = title;
    state->text = text;
    HWND hwnd = ::CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        kObjectDetailClass,
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

// BuildObjectDetailText formats row-local columns and, for DriverObject rows,
// appends R0 DriverObject query output. Input is a selected row; output is a
// detail body suitable for the popup edit control.
std::wstring BuildObjectDetailText(const DriverObjectRow& row) {
    std::wstring detail =
        L"Directory: " + row.directoryPathText + L"\r\n" +
        L"ObjectName: " + row.objectNameText + L"\r\n" +
        L"Type: " + row.objectTypeText + L"\r\n" +
        L"FullPath: " + row.fullPathText + L"\r\n" +
        L"TargetPath: " + row.targetPathText + L"\r\n" +
        L"ReferenceCount: " + row.referenceCountText + L"\r\n" +
        L"HandleCount: " + row.handleCountText + L"\r\n" +
        L"Status: " + row.statusText + L"\r\n" +
        L"Hint: " + row.capabilityHint + L"\r\n";

    const std::wstring driverObjectName = DriverObjectNameForRow(row);
    if (!driverObjectName.empty()) {
        const DriverActionResult r0Detail = DriverActions::BuildDriverObjectDetailText(driverObjectName);
        detail += L"\r\nR0 DriverObject query (" + driverObjectName + L"):\r\n";
        detail += r0Detail.statusText;
    }
    return detail;
}

// ShowObjectDetail runs the optional R0 DriverObject lookup in a worker. This
// keeps object-directory browsing responsive while a large device or dispatch
// list is formatted.
void ShowObjectDetail(DriverObjectViewState& state) {
    DriverObjectRow row;
    if (!SelectedObjectRow(state, &row) || !state.detailTask) {
        return;
    }
    const std::uint64_t requestId = ++state.detailRequestId;
    Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在后台查询对象详情…");
    state.detailTask->request(
        [row, requestId] {
            ObjectDetailResult result{};
            result.requestId = requestId;
            result.text = BuildObjectDetailText(row);
            return result;
        },
        [&state](std::uint64_t, std::optional<ObjectDetailResult>&& result, std::exception_ptr error) {
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !result.has_value() || result->requestId != state.detailRequestId) {
                return;
            }
            ShowDetailWindow(state.hwnd, L"对象详细信息", result->text);
        });
}

std::wstring BuildObjectTsv(const DriverObjectViewState& state);

// ShowObjectContextMenu displays the object-info right-click menu and dispatches
// retained commands. Inputs are view state and screen point; processing selects
// the clicked row before executing grouped copy/detail read-only actions; no value is
// returned.
void ShowObjectContextMenu(DriverObjectViewState& state, POINT screenPoint) {
    POINT clientPoint = screenPoint;
    ::ScreenToClient(state.listView, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int item = ListView_HitTest(state.listView, &hit);
    state.contextColumn = std::max(0, hit.iSubItem);
    if (item >= 0) {
        ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(state.listView, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    DriverObjectRow row;
    const bool hasSelection = SelectedObjectRow(state, &row);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kObjectMenuCopyCell, L"复制单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kObjectMenuCopyRow, L"复制当前行");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kObjectMenuCopyName, L"复制对象名");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kObjectMenuCopyPath, L"复制完整路径");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kObjectMenuCopyTarget, L"复制目标路径");
        ::AppendMenuW(copyMenu, MF_STRING | (!state.visibleRows.empty() ? 0U : MF_GRAYED), kObjectMenuCopyVisible, L"复制可见结果");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }
    HMENU detailMenu = ::CreatePopupMenu();
    if (detailMenu) {
        ::AppendMenuW(detailMenu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kObjectMenuDetail, L"详细信息/R0 DriverObject");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(detailMenu), L"详细信息");
    }

    const UINT command = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (command == kObjectMenuDetail) {
        ShowObjectDetail(state);
    } else if (command == kObjectMenuCopyCell ||
        command == kObjectMenuCopyRow ||
        command == kObjectMenuCopyName ||
        command == kObjectMenuCopyPath ||
        command == kObjectMenuCopyTarget ||
        command == kObjectMenuCopyVisible) {
        if (command == kObjectMenuCopyVisible) {
            CopyObjectText(state, BuildObjectTsv(state), L"复制可见对象结果");
            return;
        }
        if (!SelectedObjectRow(state, &row)) {
            return;
        }
        if (command == kObjectMenuCopyCell) {
            const std::vector<std::wstring> cells = ObjectCells(row);
            const std::size_t column = static_cast<std::size_t>(std::max(0, state.contextColumn));
            CopyObjectText(state, column < cells.size() ? cells[column] : std::wstring{}, L"复制单元格");
        } else if (command == kObjectMenuCopyRow) {
            CopyObjectText(state, BuildObjectRowText(row), L"复制对象行");
        } else if (command == kObjectMenuCopyName) {
            CopyObjectText(state, row.objectNameText, L"复制对象名");
        } else if (command == kObjectMenuCopyPath) {
            CopyObjectText(state, row.fullPathText, L"复制完整路径");
        } else {
            CopyObjectText(state, row.targetPathText, L"复制目标路径");
        }
    }
}

// ObjectColumns returns the report columns shown by the object page. There is
// no input; processing returns static descriptors; output is consumed by the
// ListView helper.
std::vector<Ksword::Ui::ListViewColumn> ObjectColumns() {
    return {
        { 0, 140, LVCFMT_LEFT, L"目录" },
        { 1, 180, LVCFMT_LEFT, L"对象名" },
        { 2, 140, LVCFMT_LEFT, L"类型" },
        { 3, 340, LVCFMT_LEFT, L"完整路径" },
        { 4, 320, LVCFMT_LEFT, L"目标路径" },
        { 5, 120, LVCFMT_RIGHT, L"引用计数" },
        { 6, 120, LVCFMT_RIGHT, L"句柄计数" },
        { 7, 220, LVCFMT_LEFT, L"状态" },
        { 8, 300, LVCFMT_LEFT, L"能力提示" },
    };
}

// RequestObjectFilter filters a retained immutable object snapshot in the
// worker. It never calls the object manager or R0 driver while the user types.
void RequestObjectFilter(DriverObjectViewState& state, std::wstring query) {
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
            ObjectFilterResult result{};
            result.snapshotGeneration = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<ObjectFilterResult>&& result, std::exception_ptr error) {
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

// PopulateObjectList installs a virtual-list snapshot and delegates local
// filtering to RequestObjectFilter. Old rows remain displayed until the next
// complete filter result is installed.
void PopulateObjectList(DriverObjectViewState& state) {
    if (!state.listView || !state.model) {
        return;
    }
    state.snapshotRows = state.model->objectRows();
    state.filterRows = std::make_shared<const std::vector<Ksword::Ui::VirtualListRow>>(
        BuildObjectVirtualRows(state.snapshotRows));
    ++state.snapshotGeneration;
    state.virtualList.setRows(*state.filterRows);
    RequestObjectFilter(state, state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : state.filterQuery);
}

// BuildObjectTsv converts the rows currently rendered by the virtual list into
// TSV text. Input is the view state; processing serializes its active visible
// indexes so an in-flight filter cannot yield stale export data.
std::wstring BuildObjectTsv(const DriverObjectViewState& state) {
    return Ksword::Ui::BuildVisibleVirtualListTsv(
        { L"目录", L"对象名", L"类型", L"完整路径", L"目标路径", L"引用计数", L"句柄计数", L"状态", L"能力提示" },
        state.virtualList);
}

// RegisterDriverObjectClass installs the child window class once. There is no
// input; processing is idempotent; output is true when CreateWindowExW can use
// the class name.
bool RegisterDriverObjectClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        DriverObjectViewState* state = StateFromWindow(hwnd);
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<DriverObjectViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                state->filterBar = Ksword::Ui::CreateFilterBar(hwnd, kObjectFilterId,
                    L"筛选目录、对象、类型、路径、状态和能力详情", 0, 0, 0, 0);
                if (state->virtualList.create(hwnd, kObjectListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
                    state->listView = state->virtualList.hwnd();
                }
                SetChildFont(state->listView);
                state->virtualList.addColumns(ObjectColumns());
                state->loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kObjectLoadingOverlayId, { 0, 0, 1, 1 });
                state->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ObjectFilterResult>>(hwnd, kMsgObjectFilterCompleted);
                state->detailTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ObjectDetailResult>>(hwnd, kMsgObjectDetailCompleted);
                PopulateObjectList(*state);
            }
            return 0;
        case WM_COMMAND:
            if (state && LOWORD(wParam) == kObjectFilterId && HIWORD(wParam) == EN_CHANGE) {
                RequestObjectFilter(*state, Ksword::Ui::GetFilterBarText(state->filterBar));
                return 0;
            }
            break;
        case kMsgObjectFilterCompleted:
            if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgObjectDetailCompleted:
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
                    ShowObjectContextMenu(*state, pt);
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
                ShowObjectContextMenu(*state, pt);
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
    wc.lpszClassName = kDriverObjectClass;
    if (::RegisterClassW(&wc)) {
        registered = true;
    } else if (::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND CreateDriverObjectView(HWND parent, const RECT& bounds, DriverModel* model) {
    if (!parent || !RegisterDriverObjectClass()) {
        return nullptr;
    }

    auto* state = new DriverObjectViewState();
    state->model = model;
    HWND hwnd = ::CreateWindowExW(
        0,
        kDriverObjectClass,
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

void ResizeDriverObjectView(HWND view, const RECT& bounds) {
    if (view) {
        ::MoveWindow(view,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            TRUE);
    }
}

void RefreshDriverObjectView(HWND view) {
    DriverObjectViewState* state = StateFromWindow(view);
    if (state) {
        PopulateObjectList(*state);
    }
}

std::wstring ExportDriverObjectViewTsv(HWND view) {
    const DriverObjectViewState* state = StateFromWindow(view);
    return state ? BuildObjectTsv(*state) : std::wstring();
}

} // namespace Ksword::Features::Driver
