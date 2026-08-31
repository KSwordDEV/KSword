#include "FileView.h"

#include "FileActions.h"
#include "FileSystemEnumerator.h"
#include "PathNavigator.h"

#include "../../Ui/Controls.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Ksword::Features::File {
namespace {

constexpr wchar_t kFileViewClass[] = L"KswordARKLight.FileView";
constexpr int kButtonBackId = 52001;
constexpr int kButtonForwardId = 52002;
constexpr int kButtonUpId = 52003;
constexpr int kButtonRefreshId = 52004;
constexpr int kPathEditId = 52005;
constexpr int kButtonGoId = 52006;
constexpr int kListId = 52007;
constexpr int kStatusId = 52008;
constexpr int kFilterBarId = 52009;
constexpr UINT kColumnMenuBaseId = 52500;
constexpr UINT kMsgDirectoryRefreshCompleted = WM_APP + 540;
constexpr UINT kMsgFilterCompleted = WM_APP + 541;
constexpr UINT kMsgFileActionCompleted = WM_APP + 542;
constexpr UINT kMsgExternalNavigate = WM_APP + 543;

// FileColumnSpec describes one report column. Inputs are static id/title/width
// values; processing uses the same table for initial creation and user column
// visibility toggles; no runtime ownership is stored here.
struct FileColumnSpec {
    int index;
    int defaultWidth;
    const wchar_t* title;
};

// FilePresentationRow is the immutable text snapshot delivered to the virtual
// ListView. FileEntry remains available for actions while formatting happens
// once per completed directory snapshot instead of during every repaint.
struct FilePresentationRow {
    std::vector<std::wstring> cells;
    int imageIndex = -2; // -2 means the visible-row icon has not been requested.
};

struct DirectoryRefreshSnapshot {
    std::wstring directory;
    DirectoryEnumerationResult result;
};

struct FileFilterResult {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
    std::wstring selectedPath;
    std::wstring topPath;
};

// FileActionTaskResult carries a fully materialized backend operation result.
// UI-only effects such as clipboard writes and dialogs are applied only after
// this immutable result returns to the window thread.
struct FileActionTaskResult {
    FileActionResult result;
};

constexpr FileColumnSpec kFileColumns[] = {
    { 0, 260, L"名称" },
    { 1, 90, L"类型" },
    { 2, 110, L"大小" },
    { 3, 150, L"修改时间" },
    { 4, 80, L"标志" },
    { 5, 420, L"完整路径" },
};

// FileViewState owns every child HWND and model object used by one File page.
// Inputs are created during WM_CREATE; processing in FileViewProc updates this
// state in response to navigation, list notifications and menu commands; the
// object is deleted on WM_NCDESTROY and has no independent return behavior.
struct FileViewState {
    HWND hwnd = nullptr;
    HWND backButton = nullptr;
    HWND forwardButton = nullptr;
    HWND upButton = nullptr;
    HWND refreshButton = nullptr;
    HWND pathEdit = nullptr;
    HWND goButton = nullptr;
    HWND filterBar = nullptr;
    HWND list = nullptr;
    HWND status = nullptr;
    HWND loadingOverlay = nullptr;
    HIMAGELIST imageList = nullptr;
    PathNavigator navigator;
    FileSystemEnumerator enumerator;
    std::vector<FileEntry> entries;
    std::vector<FilePresentationRow> presentationRows;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::vector<std::size_t> visibleIndexes;
    std::wstring displayTextScratch;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::wstring enumerationStatusText;
    std::uint64_t displayGeneration = 0;
    bool hideOverlayAfterFilter = false;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<DirectoryRefreshSnapshot>> refreshTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<FileFilterResult>> filterTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<FileActionTaskResult>> actionTask;
    std::unordered_map<std::wstring, int> iconCache;
    bool columnVisible[std::size(kFileColumns)] = { true, true, true, true, true, true };
};

// RegisterFileViewClass registers the native page class once per process. Input
// is the module instance; processing installs a normal Win32 WNDCLASS; output is
// true when the class is available or was already registered.
bool RegisterFileViewClass(HINSTANCE instance);

// FileViewProc dispatches the custom page messages. Inputs are Win32 window
// procedure arguments; processing routes to stateful helpers; output is a Win32
// LRESULT.
LRESULT CALLBACK FileViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

// StateFromWindow returns the per-page state pointer stored in GWLP_USERDATA.
// Input is a page HWND; output may be null before WM_CREATE finishes.
FileViewState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<FileViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// SetStatus writes a short status line for user feedback. Inputs are state and
// text; processing updates the child STATIC; no value is returned.
void SetStatus(FileViewState& state, const std::wstring& text) {
    if (state.status) {
        ::SetWindowTextW(state.status, text.c_str());
    }
}

// CreateFileImageList creates the small-icon image list used by the report
// control. There is no input; processing asks comctl32 for system small-icon
// dimensions; output is owned by FileViewState and destroyed on WM_NCDESTROY.
HIMAGELIST CreateFileImageList() {
    return ImageList_Create(
        ::GetSystemMetrics(SM_CXSMICON),
        ::GetSystemMetrics(SM_CYSMICON),
        ILC_COLOR32 | ILC_MASK,
        32,
        32);
}

// FallbackIconQueryPath chooses a stable synthetic path for generic shell
// icons. Input is a FileEntry kind/name; processing preserves file extensions
// when possible; output is used only with SHGFI_USEFILEATTRIBUTES.
std::wstring FallbackIconQueryPath(const FileEntry& entry) {
    if (entry.kind == FileEntryKind::Directory) {
        return L"folder";
    }
    if (entry.kind == FileEntryKind::Drive) {
        return entry.fullPath.empty() ? L"C:\\" : entry.fullPath;
    }

    const std::size_t dot = entry.name.find_last_of(L'.');
    if (dot != std::wstring::npos && dot + 1 < entry.name.size()) {
        return std::wstring(L"file") + entry.name.substr(dot);
    }
    return L"file";
}

// FileIconCacheKey builds a deterministic cache key for the shell icon. Input
// is one enumerated file row; processing uses the real path for drives,
// directories and reparse points, and extension-based keys for normal files;
// output indexes FileViewState::iconCache.
std::wstring FileIconCacheKey(const FileEntry& entry) {
    std::wstring key = std::to_wstring(static_cast<int>(entry.kind)) + L"|";
    if (entry.kind != FileEntryKind::File || entry.reparsePoint) {
        return key + entry.fullPath;
    }

    const std::size_t dot = entry.name.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        key += entry.name.substr(dot);
    } else {
        key += L"<no-extension>";
    }
    key += L"|" + std::to_wstring(entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT);
    return key;
}

// AddFileIconFromShell resolves one icon through SHGetFileInfoW and copies it
// into the page image list. Inputs are the image list and file row; processing
// first tries the real path, then a generic attributes-based fallback; output is
// the image index or -1 when the shell cannot provide an icon.
int AddFileIconFromShell(HIMAGELIST imageList, const FileEntry& entry) {
    if (!imageList) {
        return -1;
    }

    SHFILEINFOW info{};
    DWORD attributes = entry.attributes;
    if (entry.kind == FileEntryKind::Directory) {
        attributes |= FILE_ATTRIBUTE_DIRECTORY;
    }
    UINT flags = SHGFI_ICON | SHGFI_SMALLICON;
    if (!entry.fullPath.empty() &&
        ::SHGetFileInfoW(entry.fullPath.c_str(), attributes, &info, sizeof(info), flags) &&
        info.hIcon) {
        const int index = ImageList_AddIcon(imageList, info.hIcon);
        ::DestroyIcon(info.hIcon);
        return index;
    }

    const std::wstring fallback = FallbackIconQueryPath(entry);
    flags |= SHGFI_USEFILEATTRIBUTES;
    if (::SHGetFileInfoW(fallback.c_str(), attributes, &info, sizeof(info), flags) && info.hIcon) {
        const int index = ImageList_AddIcon(imageList, info.hIcon);
        ::DestroyIcon(info.hIcon);
        return index;
    }
    return -1;
}

// IconIndexForEntry returns a cached small icon index for one file row. Inputs
// are page state and FileEntry; processing extracts/caches through Shell APIs;
// output is a ListView image index or -1 when no icon is available.
int IconIndexForEntry(FileViewState& state, const FileEntry& entry) {
    const std::wstring key = FileIconCacheKey(entry);
    const auto found = state.iconCache.find(key);
    if (found != state.iconCache.end()) {
        return found->second;
    }

    const int index = AddFileIconFromShell(state.imageList, entry);
    if (index >= 0) {
        state.iconCache.emplace(key, index);
    }
    return index;
}

// CreateChildControls creates the toolbar, path edit, report list and status
// controls. Input is the initialized state; output is true when the core list
// and edit controls are available.
bool CreateChildControls(FileViewState& state) {
    state.backButton = Ksword::Ui::CreateButton(state.hwnd, kButtonBackId, L"后退", 0, 0, 64, 24);
    state.forwardButton = Ksword::Ui::CreateButton(state.hwnd, kButtonForwardId, L"前进", 0, 0, 64, 24);
    state.upButton = Ksword::Ui::CreateButton(state.hwnd, kButtonUpId, L"向上", 0, 0, 64, 24);
    state.refreshButton = Ksword::Ui::CreateButton(state.hwnd, kButtonRefreshId, L"刷新", 0, 0, 64, 24);
    state.goButton = Ksword::Ui::CreateButton(state.hwnd, kButtonGoId, L"转到", 0, 0, 64, 24);
    state.pathEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 200, 24, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPathEditId)), ::GetModuleHandleW(nullptr), nullptr);
    state.filterBar = Ksword::Ui::CreateFilterBar(state.hwnd, kFilterBarId, L"筛选名称、类型、路径和属性", 0, 0, 200, 24);
    state.list = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
        0, 0, 400, 300, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kListId)), ::GetModuleHandleW(nullptr), nullptr);
    state.status = Ksword::Ui::CreateText(state.hwnd, kStatusId, L"", 0, 0, 300, 20);

    if (state.pathEdit) {
        ::SendMessageW(state.pathEdit, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    }
    if (!state.pathEdit || !state.filterBar || !state.list) {
        return false;
    }

    ::SendMessageW(state.list, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    ListView_SetExtendedListViewStyle(state.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
    state.imageList = CreateFileImageList();
    if (state.imageList) {
        ListView_SetImageList(state.list, state.imageList, LVSIL_SMALL);
    }

    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    for (const FileColumnSpec& spec : kFileColumns) {
        column.pszText = const_cast<LPWSTR>(spec.title);
        column.cx = spec.defaultWidth;
        column.iSubItem = spec.index;
        ListView_InsertColumn(state.list, spec.index, &column);
    }

    return true;
}

// LayoutFileView positions all child controls within the page client rect.
// Input is state plus current client size; processing calls MoveWindow; no value
// is returned.
void LayoutFileView(FileViewState& state) {
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int margin = 8;
    const int buttonW = 64;
    const int buttonH = 26;
    const int gap = 6;
    const int statusH = 22;
    int x = margin;
    int y = margin;

    ::MoveWindow(state.backButton, x, y, buttonW, buttonH, TRUE);
    x += buttonW + gap;
    ::MoveWindow(state.forwardButton, x, y, buttonW, buttonH, TRUE);
    x += buttonW + gap;
    ::MoveWindow(state.upButton, x, y, buttonW, buttonH, TRUE);
    x += buttonW + gap;
    ::MoveWindow(state.refreshButton, x, y, buttonW, buttonH, TRUE);
    x += buttonW + gap;

    const int goW = 64;
    const int editW = std::max(120, static_cast<int>(rc.right - x - goW - gap - margin));
    ::MoveWindow(state.pathEdit, x, y, editW, buttonH, TRUE);
    x += editW + gap;
    ::MoveWindow(state.goButton, x, y, goW, buttonH, TRUE);

    const int filterTop = y + buttonH + 5;
    ::MoveWindow(state.filterBar, margin, filterTop, std::max(80, static_cast<int>(rc.right - margin * 2)), buttonH, TRUE);
    const int listTop = filterTop + buttonH + 5;
    const int listH = std::max(80, static_cast<int>(rc.bottom - listTop - statusH - margin));
    ::MoveWindow(state.list, margin, listTop, std::max(80, static_cast<int>(rc.right - margin * 2)), listH, TRUE);
    ::MoveWindow(state.status, margin, listTop + listH + 2, std::max(80, static_cast<int>(rc.right - margin * 2)), statusH, TRUE);
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay,
            margin,
            listTop,
            std::max(80, static_cast<int>(rc.right - margin * 2)),
            listH,
            TRUE);
    }
}

// EntryTypeText converts a model kind into a Chinese display string. Input is a
// FileEntry; output is a static text label for the list view.
const wchar_t* EntryTypeText(const FileEntry& entry) {
    if (entry.kind == FileEntryKind::Drive) {
        return L"驱动器";
    }
    if (entry.kind == FileEntryKind::Directory) {
        return entry.reparsePoint ? L"目录/链接" : L"目录";
    }
    return entry.reparsePoint ? L"文件/链接" : L"文件";
}

// ApplyColumnVisibility adjusts report-column widths without rebuilding rows.
// Input is the FileView state; processing keeps column zero visible and sets
// hidden columns to zero width; no value is returned.
void ApplyColumnVisibility(FileViewState& state) {
    if (!state.list) {
        return;
    }
    for (std::size_t index = 0; index < std::size(kFileColumns); ++index) {
        const FileColumnSpec& spec = kFileColumns[index];
        const bool visible = index == 0 || state.columnVisible[index];
        ListView_SetColumnWidth(state.list, spec.index, visible ? spec.defaultWidth : 0);
    }
}

// ShowColumnMenu displays the retained "选择列" action as a compact Win32
// checkable popup. Inputs are state and screen point; processing toggles one
// column at a time; no value is returned.
void ShowColumnMenu(FileViewState& state, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    for (std::size_t index = 0; index < std::size(kFileColumns); ++index) {
        const UINT flags = MF_STRING |
            (state.columnVisible[index] ? MF_CHECKED : MF_UNCHECKED) |
            (index == 0 ? MF_GRAYED : 0U);
        ::AppendMenuW(menu, flags, kColumnMenuBaseId + static_cast<UINT>(index), kFileColumns[index].title);
    }
    const UINT command = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (command >= kColumnMenuBaseId && command < kColumnMenuBaseId + std::size(kFileColumns)) {
        const std::size_t index = static_cast<std::size_t>(command - kColumnMenuBaseId);
        if (index != 0) {
            state.columnVisible[index] = !state.columnVisible[index];
            ApplyColumnVisibility(state);
            SetStatus(state, L"已更新文件列表列显示。");
        }
    }
}

// VisibleEntryIndex translates an owner-data item to its immutable source index.
// It never asks ListView for an LVITEM because owner-data lists retain no row
// storage for us to read back.
std::size_t VisibleEntryIndex(const FileViewState& state, const int item) {
    if (item < 0 || static_cast<std::size_t>(item) >= state.visibleIndexes.size()) {
        return static_cast<std::size_t>(-1);
    }
    return state.visibleIndexes[static_cast<std::size_t>(item)];
}

std::wstring SelectedEntryPath(const FileViewState& state) {
    const int selected = state.list ? ListView_GetNextItem(state.list, -1, LVNI_SELECTED) : -1;
    const std::size_t entryIndex = VisibleEntryIndex(state, selected);
    return entryIndex < state.entries.size() ? state.entries[entryIndex].fullPath : std::wstring{};
}

std::wstring TopEntryPath(const FileViewState& state) {
    const int topItem = state.list ? ListView_GetTopIndex(state.list) : -1;
    const std::size_t entryIndex = VisibleEntryIndex(state, topItem);
    return entryIndex < state.entries.size() ? state.entries[entryIndex].fullPath : std::wstring{};
}

void RequestFileFilter(FileViewState& state,
    const std::wstring& query,
    std::wstring selectedPath,
    std::wstring topPath);

// BuildPresentationRows materializes every display field once, after the
// directory worker returns. Scrolling then asks only for visible cached text.
void BuildPresentationRows(FileViewState& state, DirectoryEnumerationResult result) {
    state.entries = std::move(result.entries);
    state.enumerationStatusText = result.statusText;
    state.presentationRows.clear();
    state.presentationRows.reserve(state.entries.size());
    auto filterRows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>();
    filterRows->reserve(state.entries.size());

    for (const FileEntry& entry : state.entries) {
        FilePresentationRow row{};
        row.cells = {
            entry.name,
            EntryTypeText(entry),
            FileSystemEnumerator::formatSize(entry.size, entry.kind),
            FileSystemEnumerator::formatLastWriteTime(entry.lastWriteTime),
            FileSystemEnumerator::formatAttributes(entry.attributes),
            entry.fullPath
        };
        Ksword::Ui::VirtualListRow filterRow{};
        filterRow.stableKey = entry.fullPath;
        filterRow.cells = row.cells;
        state.presentationRows.push_back(std::move(row));
        filterRows->push_back(std::move(filterRow));
    }
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

// ApplyFileFilter installs a background-produced visible-index map and restores
// selection/scroll position by full path whenever those entries still exist.
void ApplyFileFilter(FileViewState& state, FileFilterResult result) {
    if (!state.list || result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex) {
        return;
    }
    state.visibleIndexes = std::move(result.visibleIndexes);
    int selectedItem = -1;
    int topItem = -1;
    {
        Ksword::Ui::ScopedListViewRedrawLock redrawLock(state.list);
        ListView_SetItemCountEx(state.list,
            static_cast<int>(std::min<std::size_t>(state.visibleIndexes.size(), static_cast<std::size_t>(INT_MAX))),
            LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
        ListView_SetItemState(state.list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        for (std::size_t item = 0; item < state.visibleIndexes.size(); ++item) {
            const std::size_t entryIndex = state.visibleIndexes[item];
            if (entryIndex >= state.entries.size()) {
                continue;
            }
            const std::wstring& path = state.entries[entryIndex].fullPath;
            if (selectedItem < 0 && !result.selectedPath.empty() && path == result.selectedPath) {
                selectedItem = static_cast<int>(item);
            }
            if (topItem < 0 && !result.topPath.empty() && path == result.topPath) {
                topItem = static_cast<int>(item);
            }
        }
        if (selectedItem >= 0) {
            ListView_SetItemState(state.list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        }
        if (topItem >= 0) {
            ListView_EnsureVisible(state.list, topItem, FALSE);
        } else if (selectedItem >= 0) {
            ListView_EnsureVisible(state.list, selectedItem, FALSE);
        }
    }
    ::InvalidateRect(state.list, nullptr, FALSE);
    const std::wstring filterSuffix = result.query.empty()
        ? L""
        : L"；筛选 " + std::to_wstring(state.visibleIndexes.size()) + L" / " + std::to_wstring(state.entries.size()) + L" 项";
    SetStatus(state, state.enumerationStatusText + filterSuffix);
    if (state.hideOverlayAfterFilter) {
        state.hideOverlayAfterFilter = false;
        Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
    }
}

// RequestFileFilter uses the cached value snapshot only. Input changes are
// debounced by FilterBar and coalesced here, without another filesystem walk.
void RequestFileFilter(FileViewState& state,
    const std::wstring& query,
    std::wstring selectedPath,
    std::wstring topPath) {
    state.filterQuery = query;
    state.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    const std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> rows = state.filterRows;
    const std::uint64_t generation = state.displayGeneration;
    const bool useRegex = state.filterUseRegex;
    if (!state.filterTask || !rows) {
        return;
    }
    state.filterTask->request(
        [rows, generation, useRegex, query, selectedPath = std::move(selectedPath), topPath = std::move(topPath)]() mutable {
            FileFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.selectedPath = std::move(selectedPath);
            result.topPath = std::move(topPath);
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<FileFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                SetStatus(state, L"文件筛选任务异常结束。已保留当前结果。");
                if (state.hideOverlayAfterFilter) {
                    state.hideOverlayAfterFilter = false;
                    Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
                }
                return;
            }
            ApplyFileFilter(state, std::move(*result));
        });
}

// ApplyDirectoryRefresh accepts only the completed worker snapshot and starts
// a cached background filter pass. No FindFirstFile/FindNextFile work runs in
// UI message handlers.
void ApplyDirectoryRefresh(FileViewState& state, DirectoryRefreshSnapshot snapshot) {
    if (snapshot.directory != state.navigator.currentPath()) {
        return;
    }
    const std::wstring selectedPath = SelectedEntryPath(state);
    const std::wstring topPath = TopEntryPath(state);
    BuildPresentationRows(state, std::move(snapshot.result));
    state.visibleIndexes.clear();
    ListView_SetItemCountEx(state.list, 0, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    ApplyColumnVisibility(state);
    ::EnableWindow(state.backButton, state.navigator.canNavigateBack());
    ::EnableWindow(state.forwardButton, state.navigator.canNavigateForward());
    state.hideOverlayAfterFilter = true;
    RequestFileFilter(state,
        state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : state.filterQuery,
        selectedPath,
        topPath);
}

// RefreshCurrentPath schedules directory enumeration and leaves the previous
// immutable table available under a loading overlay until the latest result is
// installed. Repeated navigation and refresh commands are coalesced.
void RefreshCurrentPath(FileViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const std::wstring current = state.navigator.currentPath();
    ::SetWindowTextW(state.pathEdit, current.empty() ? L"此电脑" : current.c_str());
    SetStatus(state, state.refreshTask->running() ? L"目录刷新已排队，等待当前枚举完成…" : L"正在后台枚举目录…");
    ::EnableWindow(state.refreshButton, FALSE);
    Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在后台加载目录…");
    state.refreshTask->request(
        [current]() {
            FileSystemEnumerator enumerator;
            return DirectoryRefreshSnapshot{ current, enumerator.enumerate(current) };
        },
        [&state](std::uint64_t, std::optional<DirectoryRefreshSnapshot>&& snapshot, std::exception_ptr error) {
            ::EnableWindow(state.refreshButton, TRUE);
            if (error || !snapshot.has_value()) {
                Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
                SetStatus(state, L"目录枚举任务异常结束。请检查路径与访问权限。");
                return;
            }
            ApplyDirectoryRefresh(state, std::move(*snapshot));
        });
}

// NavigateTo updates only the lightweight navigator on the UI thread, then
// schedules the potentially slow filesystem snapshot in RefreshCurrentPath.
void NavigateTo(FileViewState& state, const std::wstring& path) {
    state.navigator.navigateTo(path);
    RefreshCurrentPath(state);
}

// TextFromWindow reads a child window's Unicode text. Input is an HWND; output
// is the current text content or empty when the HWND is null.
std::wstring TextFromWindow(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int length = ::GetWindowTextLengthW(hwnd);
    std::wstring text(static_cast<size_t>(length) + 1, L'\0');
    if (length > 0) {
        ::GetWindowTextW(hwnd, text.data(), static_cast<int>(text.size()));
    }
    text.resize(static_cast<size_t>(length));
    return text;
}

// SelectedEntry copies the currently selected list row into an output model.
// Inputs are state and output pointer; output is true when a row is selected.
bool SelectedEntry(const FileViewState& state, FileEntry* entry) {
    const int selected = ListView_GetNextItem(state.list, -1, LVNI_SELECTED);
    const std::size_t entryIndex = VisibleEntryIndex(state, selected);
    if (entryIndex >= state.entries.size()) {
        return false;
    }
    if (entry) {
        *entry = state.entries[entryIndex];
    }
    return true;
}

// ApplyFileActionResult runs only on the window thread. It keeps clipboard and
// modal UI ownership out of the worker while following any refresh/navigation
// request produced by the completed immutable file-action result.
void ApplyFileActionResult(FileViewState& state, FileActionResult result) {
    if (!result.clipboardText.empty() && !FileActions::copyTextToClipboard(state.hwnd, result.clipboardText)) {
        if (!result.statusText.empty()) {
            result.statusText += L"；复制到剪贴板失败。";
        } else {
            result.statusText = L"复制到剪贴板失败。";
        }
    }
    if (!result.statusText.empty()) {
        SetStatus(state, result.statusText);
    }
    if (result.navigateRequested) {
        NavigateTo(state, result.navigatePath);
    } else if (result.refreshRequested) {
        RefreshCurrentPath(state);
    }
    if (!result.dialogText.empty()) {
        ::MessageBoxW(
            state.hwnd,
            result.dialogText.c_str(),
            result.dialogTitle.empty() ? L"文件操作" : result.dialogTitle.c_str(),
            MB_OK | (result.dialogFlags == 0 ? MB_ICONINFORMATION : result.dialogFlags));
    }
}

// BeginFileAction performs UI-only preflight synchronously, then runs every
// shell, filesystem, Restart Manager, security and R0 operation through the
// dedicated action task. A running action rejects duplicate requests while the
// prior directory snapshot remains interactive.
void BeginFileAction(FileViewState& state, const FileActionId action, FileActionContext context) {
    if (action == FileActionId::None) {
        return;
    }
    if (!state.actionTask) {
        SetStatus(state, L"文件操作任务不可用。");
        return;
    }
    if (state.actionTask->running()) {
        SetStatus(state, L"另一个文件操作正在后台执行，请等待完成。");
        return;
    }

    const FileActionPreparation preparation = FileActions::prepareBackground(action, context);
    if (!preparation.ready) {
        SetStatus(state, preparation.statusText.empty() ? L"已取消文件操作。" : preparation.statusText);
        return;
    }

    context.backgroundExecution = true;
    context.owner = nullptr;
    SetStatus(state, L"正在后台执行文件操作…");
    state.actionTask->request(
        [action, context = std::move(context)]() mutable {
            FileActionTaskResult completed{};
            completed.result = FileActions::execute(action, context);
            return completed;
        },
        [&state](std::uint64_t, std::optional<FileActionTaskResult>&& completed, std::exception_ptr error) {
            if (error || !completed.has_value()) {
                SetStatus(state, L"文件后台操作异常结束。请检查访问权限和驱动状态。");
                return;
            }
            ApplyFileActionResult(state, std::move(completed->result));
        });
}

// OpenSelectedEntry either navigates into directories/drives or schedules a
// ShellExecute request for files. It never blocks the file page message loop.
void OpenSelectedEntry(FileViewState& state) {
    FileEntry entry;
    if (!SelectedEntry(state, &entry)) {
        return;
    }
    if (entry.kind == FileEntryKind::Drive || entry.kind == FileEntryKind::Directory) {
        NavigateTo(state, entry.fullPath);
        return;
    }
    FileActionContext context;
    context.owner = state.hwnd;
    context.currentDirectory = state.navigator.currentPath();
    context.selectedEntry = entry;
    context.hasSelection = true;
    BeginFileAction(state, FileActionId::OpenRun, std::move(context));
}

// ShowContextMenu builds a context object, displays the FileActions menu, then
// executes the selected command. Inputs are state and screen coordinate; no
// value is returned.
void ShowContextMenu(FileViewState& state, POINT screenPoint) {
    if (state.actionTask && state.actionTask->running()) {
        SetStatus(state, L"另一个文件操作正在后台执行，请等待完成。");
        return;
    }
    FileActionContext context;
    context.owner = state.hwnd;
    context.currentDirectory = state.navigator.currentPath();
    context.hasSelection = SelectedEntry(state, &context.selectedEntry);
    const FileActionId action = FileActions::showContextMenu(state.hwnd, context, screenPoint);
    if (action == FileActionId::SelectColumns) {
        ShowColumnMenu(state, screenPoint);
        return;
    }
    BeginFileAction(state, action, std::move(context));
}

// HandleCommand processes toolbar button commands. Inputs are state and command
// id; output is true only when the command belongs to FileView.
bool HandleCommand(FileViewState& state, int commandId) {
    switch (commandId) {
    case kButtonBackId:
        if (state.navigator.navigateBack()) {
            RefreshCurrentPath(state);
        }
        return true;
    case kButtonForwardId:
        if (state.navigator.navigateForward()) {
            RefreshCurrentPath(state);
        }
        return true;
    case kButtonUpId:
        state.navigator.navigateUp();
        RefreshCurrentPath(state);
        return true;
    case kButtonRefreshId:
        RefreshCurrentPath(state);
        return true;
    case kButtonGoId:
        NavigateTo(state, TextFromWindow(state.pathEdit));
        return true;
    default:
        return false;
    }
}

// HandleNotify processes list-view notifications. Inputs are state and NMHDR;
// output is true only when the notification was consumed.
bool HandleNotify(FileViewState& state, const NMHDR* hdr) {
    if (!hdr || hdr->hwndFrom != state.list) {
        return false;
    }
    if (hdr->code == LVN_GETDISPINFOW) {
        auto* displayInfo = reinterpret_cast<NMLVDISPINFOW*>(const_cast<NMHDR*>(hdr));
        const std::size_t entryIndex = VisibleEntryIndex(state, displayInfo->item.iItem);
        if (entryIndex >= state.presentationRows.size()) {
            return true;
        }
        FilePresentationRow& row = state.presentationRows[entryIndex];
        if ((displayInfo->item.mask & LVIF_TEXT) != 0) {
            const int column = displayInfo->item.iSubItem;
            state.displayTextScratch = column >= 0 && static_cast<std::size_t>(column) < row.cells.size()
                ? row.cells[static_cast<std::size_t>(column)]
                : std::wstring{};
            displayInfo->item.pszText = state.displayTextScratch.data();
        }
        if ((displayInfo->item.mask & LVIF_PARAM) != 0) {
            displayInfo->item.lParam = static_cast<LPARAM>(entryIndex);
        }
        if ((displayInfo->item.mask & LVIF_IMAGE) != 0) {
            if (row.imageIndex == -2) {
                row.imageIndex = IconIndexForEntry(state, state.entries[entryIndex]);
            }
            if (row.imageIndex >= 0) {
                displayInfo->item.iImage = row.imageIndex;
            }
        }
        return true;
    }
    if (hdr->code == NM_DBLCLK) {
        OpenSelectedEntry(state);
        return true;
    }
    if (hdr->code == NM_RCLICK) {
        POINT pt{};
        ::GetCursorPos(&pt);
        POINT client = pt;
        ::ScreenToClient(state.list, &client);
        LVHITTESTINFO hit{};
        hit.pt = client;
        const int item = ListView_HitTest(state.list, &hit);
        if (item >= 0) {
            ListView_SetItemState(state.list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(state.list, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        }
        ShowContextMenu(state, pt);
        return true;
    }
    return false;
}

bool RegisterFileViewClass(HINSTANCE instance) {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = FileViewProc;
    wc.hInstance = instance;
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    wc.lpszClassName = kFileViewClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
        return true;
    }
    return false;
}

LRESULT CALLBACK FileViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    FileViewState* state = StateFromWindow(hwnd);
    switch (msg) {
    case WM_CREATE: {
        auto ownedState = std::make_unique<FileViewState>();
        ownedState->hwnd = hwnd;
        state = ownedState.get();
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        if (!CreateChildControls(*state)) {
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return -1;
        }
        ownedState.release();
        state->loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, 52010, { 0, 0, 1, 1 });
        state->refreshTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<DirectoryRefreshSnapshot>>(hwnd, kMsgDirectoryRefreshCompleted);
        state->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<FileFilterResult>>(hwnd, kMsgFilterCompleted);
        state->actionTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<FileActionTaskResult>>(hwnd, kMsgFileActionCompleted);
        RefreshCurrentPath(*state);
        return 0;
    }
    case WM_SIZE:
        if (state) {
            LayoutFileView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (state && LOWORD(wParam) == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
            RequestFileFilter(*state,
                Ksword::Ui::GetFilterBarText(state->filterBar),
                SelectedEntryPath(*state),
                TopEntryPath(*state));
            return 0;
        }
        if (state && HandleCommand(*state, LOWORD(wParam))) {
            return 0;
        }
        break;
    case kMsgDirectoryRefreshCompleted:
        if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgFilterCompleted:
        if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgFileActionCompleted:
        if (state && state->actionTask && state->actionTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgExternalNavigate:
        if (state && lParam != 0) {
            const auto* path = reinterpret_cast<const std::wstring*>(lParam);
            if (!path->empty()) {
                NavigateTo(*state, *path);
                return TRUE;
            }
        }
        return FALSE;
    case WM_NOTIFY:
        if (state && HandleNotify(*state, reinterpret_cast<NMHDR*>(lParam))) {
            return 0;
        }
        break;
    case WM_CONTEXTMENU:
        if (state && reinterpret_cast<HWND>(wParam) == state->list) {
            POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (pt.x == -1 && pt.y == -1) {
                RECT rc{};
                ::GetWindowRect(state->list, &rc);
                pt = { rc.left + 20, rc.top + 20 };
            }
            ShowContextMenu(*state, pt);
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
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = ::BeginPaint(hwnd, &ps);
        RECT rc{};
        ::GetClientRect(hwnd, &rc);
        ::FillRect(dc, &rc, Ksword::Ui::AppTheme().windowBrush());
        ::EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_NCDESTROY:
        if (state && state->refreshTask) {
            state->refreshTask->cancel();
        }
        if (state && state->filterTask) {
            state->filterTask->cancel();
        }
        if (state && state->actionTask) {
            state->actionTask->cancel();
        }
        if (state && state->imageList) {
            ImageList_Destroy(state->imageList);
            state->imageList = nullptr;
        }
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        break;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

} // namespace

HWND CreateFileViewPage(HWND parent, const RECT& bounds) {
    HINSTANCE instance = ::GetModuleHandleW(nullptr);
    if (!RegisterFileViewClass(instance)) {
        return nullptr;
    }
    return ::CreateWindowExW(0, kFileViewClass, L"文件", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        instance,
        nullptr);
}

bool RequestFileViewNavigate(HWND page, const std::wstring& path) {
    return page && !path.empty() &&
        ::SendMessageW(page, kMsgExternalNavigate, 0, reinterpret_cast<LPARAM>(&path)) != 0;
}

} // namespace Ksword::Features::File
