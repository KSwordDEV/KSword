#include "FileHolderView.h"

#include "FileHolderScanner.h"
#include "../../Core/EntityRef.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::SysTools {
namespace {

constexpr wchar_t kFileHolderViewClass[] = L"KswordARKLight.SysTools.FileHolderView";

constexpr int kPathEditId = 67101;
constexpr int kBrowseButtonId = 67102;
constexpr int kScanButtonId = 67103;
constexpr int kSubPathCheckId = 67104;
constexpr int kFilterBarId = 67105;
constexpr int kListId = 67106;
constexpr int kLoadingOverlayId = 67107;

constexpr UINT kMenuCopyRow = 67601;
constexpr UINT kMenuCopyVisible = 67602;
constexpr UINT kMenuOpenLocation = 67603;
constexpr UINT kMenuRescan = 67604;
constexpr UINT kMenuOpenProcessDetails = 67605;

constexpr UINT kMsgScanCompleted = WM_APP + 700;
constexpr UINT kMsgFilterCompleted = WM_APP + 701;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 6;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct FileHolderFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct FileHolderViewState final {
    HWND hwnd = nullptr;
    HWND pathEdit = nullptr;
    HWND browseButton = nullptr;
    HWND scanButton = nullptr;
    HWND subPathCheck = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    Ksword::Ui::VirtualListView list;
    std::vector<FileHolderEntry> entries;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"输入文件或目录路径后点击“扫描占用”。";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    bool scanInProgress = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<FileHolderScanResult>> scanTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<FileHolderFilterResult>> filterTask;
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

std::wstring WindowText(HWND control) {
    if (!control) {
        return {};
    }
    const int length = ::GetWindowTextLengthW(control);
    if (length <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
    const int copied = ::GetWindowTextW(control, text.data(), length + 1);
    text.resize(copied > 0 ? static_cast<std::size_t>(copied) : 0);
    return text;
}

std::wstring FormatHandleValue(const std::uint64_t handleValue) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << handleValue;
    return stream.str();
}

std::wstring CellText(const FileHolderEntry& entry, const int column) {
    switch (column) {
    case 0:
        return entry.processName;
    case 1:
        return std::to_wstring(entry.processId);
    case 2:
        return FormatHandleValue(entry.handleValue);
    case 3:
        return entry.accessText;
    case 4:
        return entry.win32Name;
    case 5:
        return entry.processPath;
    default:
        return {};
    }
}

void ApplyFilterResult(FileHolderViewState& state, FileHolderFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.list.hwnd()) {
        return;
    }
    state.list.setVisibleIndexes(std::move(result.visibleIndexes));
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void RequestFilter(FileHolderViewState& state, std::wstring query) {
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
            FileHolderFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<FileHolderFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                return;
            }
            ApplyFilterResult(state, std::move(*result));
        });
}

void BuildRows(FileHolderViewState& state) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(state.entries.size());
    for (std::size_t index = 0; index < state.entries.size(); ++index) {
        const FileHolderEntry& entry = state.entries[index];
        Ksword::Ui::VirtualListRow row{};
        // PID plus handle value is unique for the lifetime of one snapshot,
        // which is all a stable key has to survive here.
        row.stableKey = std::to_wstring(entry.processId) + L"#" + FormatHandleValue(entry.handleValue);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount + 1);
        for (int column = 0; column < kColumnCount; ++column) {
            row.cells.push_back(CellText(entry, column));
        }
        // The raw NT path is searchable without occupying a column of its own.
        row.cells.push_back(entry.objectName);
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>(std::move(rows));
    state.list.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

void BeginScan(FileHolderViewState& state) {
    if (!state.scanTask) {
        return;
    }
    const std::wstring target = WindowText(state.pathEdit);
    if (target.empty()) {
        state.statusText = L"请先输入要检查的文件或目录路径。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (state.scanInProgress) {
        state.statusText = L"扫描正在进行中，请等待当前遍历结束。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    const bool includeSubPaths =
        state.subPathCheck && ::SendMessageW(state.subPathCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
    state.scanInProgress = true;
    if (state.scanButton) {
        ::EnableWindow(state.scanButton, FALSE);
    }
    state.statusText = L"正在后台枚举全系统句柄，这在繁忙机器上需要数秒…";
    Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在遍历全系统句柄…");
    ::InvalidateRect(state.hwnd, nullptr, TRUE);

    state.scanTask->request(
        [target, includeSubPaths] { return ScanFileHolders(target, includeSubPaths); },
        [&state](std::uint64_t, std::optional<FileHolderScanResult>&& scan, std::exception_ptr error) {
            state.scanInProgress = false;
            if (state.scanButton) {
                ::EnableWindow(state.scanButton, TRUE);
            }
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !scan.has_value()) {
                state.statusText = L"占用扫描异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!scan->success) {
                state.entries.clear();
                BuildRows(state);
                state.list.resetVisibleIndexes();
                state.statusText = scan->diagnosticText.empty() ? L"占用扫描失败。" : scan->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            state.entries = std::move(scan->entries);
            BuildRows(state);
            std::wostringstream summary;
            summary << L"匹配 " << state.entries.size() << L" 个句柄；系统句柄 " << scan->totalHandles
                << L"，其中 File " << scan->fileHandles << L"，已解析 " << scan->inspectedHandles
                << L"，跳过 " << scan->skippedHandles << L"，超时放弃 " << scan->timedOutHandles
                << L"；耗时 " << scan->elapsedMs << L" ms；目标 " << scan->targetNtPath;
            if (!scan->diagnosticText.empty()) {
                summary << L"。" << scan->diagnosticText;
            }
            state.statusText = summary.str();
            RequestFilter(state, state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : std::wstring{});
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void BrowseForTarget(FileHolderViewState& state) {
    wchar_t buffer[MAX_PATH * 4] = {};
    const std::wstring current = WindowText(state.pathEdit);
    if (!current.empty() && current.size() < std::size(buffer)) {
        ::wcscpy_s(buffer, current.c_str());
    }
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = state.hwnd;
    dialog.lpstrFilter = L"所有文件\0*.*\0";
    dialog.lpstrFile = buffer;
    dialog.nMaxFile = static_cast<DWORD>(std::size(buffer));
    dialog.lpstrTitle = L"选择要检查占用的文件";
    // OFN_NODEREFERENCELINKS keeps a shortcut file as itself: the question here
    // is who holds the .lnk, not who holds its target.
    dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_NODEREFERENCELINKS;
    if (::GetOpenFileNameW(&dialog) && state.pathEdit) {
        ::SetWindowTextW(state.pathEdit, buffer);
    }
}

int SelectedModelIndex(const FileHolderViewState& state) {
    const HWND list = state.list.hwnd();
    const int selected = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.list.visibleIndexes();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return -1;
    }
    const std::size_t modelIndex = visible[static_cast<std::size_t>(selected)];
    return modelIndex < state.entries.size() ? static_cast<int>(modelIndex) : -1;
}

std::wstring RowsAsText(const FileHolderViewState& state, const bool allVisible) {
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

// OpenHoldingProcessLocation selects the holding process image in Explorer. It
// is deliberately the only shell action on this page: killing the process from
// here would be a destructive operation dressed up as navigation.
void OpenHoldingProcessLocation(FileHolderViewState& state) {
    const int index = SelectedModelIndex(state);
    if (index < 0) {
        return;
    }
    const std::wstring& path = state.entries[static_cast<std::size_t>(index)].processPath;
    if (path.empty()) {
        state.statusText = L"该进程的映像路径不可读，无法定位。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const std::wstring parameters = L"/select,\"" + path + L"\"";
    ::ShellExecuteW(state.hwnd, L"open", L"explorer.exe", parameters.c_str(), nullptr, SW_SHOWNORMAL);
}

// OpenHoldingProcessDetails routes the selected holder PID to the current
// Process Details view. The holder scan has no creation time, so the target
// view resolves the current process instance for that PID before opening it.
void OpenHoldingProcessDetails(FileHolderViewState& state) {
    const int index = SelectedModelIndex(state);
    if (index < 0) {
        return;
    }
    const FileHolderEntry& entry = state.entries[static_cast<std::size_t>(index)];
    if (entry.processId == 0) {
        state.statusText = L"该占用记录没有有效的进程标识。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::ProcessDetails;
    request.entity.kind = Ksword::Core::EntityKind::Process;
    request.entity.id = entry.processId;
    const bool routed = Ksword::Ui::RequestEntityNavigation(state.hwnd, request);
    state.statusText = routed
        ? L"已请求打开当前 PID " + std::to_wstring(entry.processId) + L" 的进程详细信息；目标页会重新解析该 PID 的进程实例。"
        : L"无法导航到当前 PID 对应的进程实例。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void ShowContextMenu(FileHolderViewState& state, POINT screenPoint) {
    const HWND list = state.list.hwnd();
    int clickedItem = -1;
    if (list) {
        POINT clientPoint = screenPoint;
        ::ScreenToClient(list, &clientPoint);
        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        clickedItem = ListView_HitTest(list, &hit);
    }
    if (clickedItem >= 0 && static_cast<std::size_t>(clickedItem) < state.list.visibleIndexes().size()) {
        ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(list, clickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const int selectedIndex = SelectedModelIndex(state);
    const bool hasSelection = selectedIndex >= 0;
    const bool hasProcess = hasSelection &&
        state.entries[static_cast<std::size_t>(selectedIndex)].processId != 0;
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuOpenLocation, L"定位进程文件");
    ::AppendMenuW(menu, MF_STRING | (hasProcess ? MF_ENABLED : MF_GRAYED), kMenuOpenProcessDetails, L"查看进程详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRescan, L"重新扫描");

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
    case kMenuOpenLocation:
        OpenHoldingProcessLocation(state);
        break;
    case kMenuOpenProcessDetails:
        OpenHoldingProcessDetails(state);
        break;
    case kMenuRescan:
        BeginScan(state);
        break;
    default:
        break;
    }
}

void LayoutView(FileHolderViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);

    const int firstRowY = kGap;
    const int browseWidth = 60;
    const int scanWidth = 90;
    const int editWidth = (std::max)(120, width - kGap * 4 - browseWidth - scanWidth);
    if (state.pathEdit) {
        ::MoveWindow(state.pathEdit, kGap, firstRowY, editWidth, kRowHeight, TRUE);
    }
    if (state.browseButton) {
        ::MoveWindow(state.browseButton, kGap * 2 + editWidth, firstRowY, browseWidth, kRowHeight, TRUE);
    }
    if (state.scanButton) {
        ::MoveWindow(state.scanButton, kGap * 3 + editWidth + browseWidth, firstRowY, scanWidth, kRowHeight, TRUE);
    }

    const int secondRowY = firstRowY + kRowHeight + kGap;
    const int checkWidth = 150;
    if (state.subPathCheck) {
        ::MoveWindow(state.subPathCheck, kGap, secondRowY, checkWidth, kRowHeight, TRUE);
    }
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap * 2 + checkWidth, secondRowY,
            (std::max)(120, width - kGap * 3 - checkWidth), kRowHeight, TRUE);
    }

    const int listTop = kHeaderHeight;
    const int listHeight = (std::max)(0, height - listTop - kStatusHeight - kGap);
    if (HWND list = state.list.hwnd()) {
        ::MoveWindow(list, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
}

bool CreateChildControls(FileHolderViewState& state) {
    HWND hwnd = state.hwnd;
    state.pathEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPathEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.browseButton = Ksword::Ui::CreateButton(hwnd, kBrowseButtonId, L"浏览…", 0, 0, 0, 0);
    state.scanButton = Ksword::Ui::CreateButton(hwnd, kScanButtonId, L"扫描占用", 0, 0, 0, 0);
    state.subPathCheck = ::CreateWindowExW(0, L"BUTTON", L"包含子路径（目录）",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSubPathCheckId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.filterBar = Ksword::Ui::CreateFilterBar(
        hwnd, kFilterBarId, L"筛选进程名、PID、访问权限与路径", 0, 0, 0, 0);
    if (!state.pathEdit || !state.browseButton || !state.scanButton || !state.subPathCheck || !state.filterBar) {
        return false;
    }

    if (!state.list.create(hwnd, kListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.list.addColumns({
        { 0, 180, LVCFMT_LEFT, L"进程" },
        { 1, 70, LVCFMT_RIGHT, L"PID" },
        { 2, 90, LVCFMT_LEFT, L"句柄" },
        { 3, 220, LVCFMT_LEFT, L"访问权限" },
        { 4, 320, LVCFMT_LEFT, L"占用路径" },
        { 5, 320, LVCFMT_LEFT, L"进程映像" },
    });
    if (HWND list = state.list.hwnd()) {
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

LRESULT CALLBACK FileHolderViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<FileHolderViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<FileHolderViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            state->scanTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<FileHolderScanResult>>(hwnd, kMsgScanCompleted);
            state->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<FileHolderFilterResult>>(hwnd, kMsgFilterCompleted);
            LayoutView(*state);
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
            if (notification == BN_CLICKED) {
                switch (id) {
                case kBrowseButtonId:
                    BrowseForTarget(*state);
                    return 0;
                case kScanButtonId:
                    BeginScan(*state);
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
                if (state->list.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->list.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    ShowContextMenu(*state, point);
                    return 0;
                }
                if (header->hwndFrom == state->list.hwnd() && header->code == NM_DBLCLK) {
                    OpenHoldingProcessLocation(*state);
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
            if (msg == kMsgScanCompleted && state->scanTask) {
                state->scanTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            // Cancel before teardown so a completion callback cannot run against
            // a half-destroyed state.
            if (state->scanTask) {
                state->scanTask->cancel();
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

bool EnsureFileHolderViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = FileHolderViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kFileHolderViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateFileHolderView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureFileHolderViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kFileHolderViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::SysTools
