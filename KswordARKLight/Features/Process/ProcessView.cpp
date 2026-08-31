#include "ProcessView.h"

#include "ProcessActions.h"
#include "ProcessColumns.h"
#include "ProcessEnumerator.h"
#include "ProcessModel.h"
#include "../AuditCommon/AuditFormatting.h"
#include "../ProcessDetail/ProcessDetailFeature.h"
#include "../../Ui/Controls.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"
#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../../../Ksword5.1/Ksword5.1/ksword/process/process.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Ksword::Features::Process {
namespace {

constexpr wchar_t kProcessViewClass[] = L"KswordARKLight.ProcessView";
constexpr int kRefreshButtonId = 52001;
constexpr int kPresetComboId = 52002;
constexpr int kColumnsButtonId = 52011;
constexpr int kPresetButtonId = 52012;
constexpr int kPauseButtonId = 52003;
constexpr int kPickerButtonId = 52004;
constexpr int kStatusTextId = 52005;
constexpr int kProcessListId = 52006;
constexpr int kRefreshSliderId = 52007;
constexpr int kFilterBarId = 52010;
constexpr UINT kContextMenuBaseId = 53000;
constexpr UINT kColumnMenuBaseId = 54000;
constexpr int kColumnChooserApplyId = 54080;
constexpr int kColumnChooserCancelId = 54081;
constexpr wchar_t kColumnChooserClass[] = L"KswordARKLight.ProcessColumnChooser";
constexpr UINT_PTR kRefreshTimerId = 52008;
constexpr UINT kMsgInitialRefresh = WM_APP + 520;
constexpr UINT kMsgRequestRefresh = WM_APP + 521;
constexpr UINT kMsgRefreshCompleted = WM_APP + 522;
constexpr UINT kMsgFilterCompleted = WM_APP + 523;
constexpr UINT kMsgActionCompleted = WM_APP + 524;
constexpr UINT kMsgOpenDetails = WM_APP + 525;
constexpr int kTreeIndentPixels = 18;
constexpr int kTreeIconGap = 4;
constexpr int kTreeTextGap = 4;

struct NotifyResult {
    bool handled = false;
    LRESULT result = 0;
};

// ProcessStableKey names one snapshot process instance rather than a recyclable PID.
// A zero creation time remains explicit for kernel-only evidence rows.
std::wstring ProcessStableKey(const DWORD processId, const ULONGLONG creationTime100ns) {
    return L"pid:" + std::to_wstring(processId) + L"#" + std::to_wstring(creationTime100ns);
}
// ProcessPresentationRow is the immutable UI snapshot for one process row.
// Keeping display text, identity and icon input together means owner-data
// callbacks never enumerate processes or format every row during a repaint.
struct ProcessPresentationRow {
    ProcessDisplayRow display;
    std::wstring stableKey;
    std::wstring iconPath;
    std::vector<std::wstring> cells;
    DWORD processId = 0;
    ULONGLONG creationTime100ns = 0;
    bool kernelOnly = false;
};

// ProcessFilterResult is produced from a copied presentation snapshot. The UI
// accepts it only when its display generation still matches the current list.
struct ProcessFilterResult {
    std::uint64_t displayGeneration = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
    std::vector<std::wstring> selectedStableKeys;
    std::wstring topStableKey;
};

// ProcessViewActionResult crosses the worker/UI boundary for a context-menu
// operation. The worker owns only immutable process identity and row snapshots;
// the UI owns status, diagnostics and any follow-up refresh.
struct ProcessViewActionResult {
    ProcessActionResult result;
    bool refreshRequired = false;
};

struct ExternalDetailRequest final {
    DWORD processId = 0;
    ULONGLONG expectedCreationTime100ns = 0;
};

enum class ProcessRowVisualState {
    Normal,
    KernelOnly,
    Added,
    Removed
};


// DetailHostState owns one top-level process detail window. Input values are
// supplied at creation time through CREATESTRUCTW; processing hosts the existing
// WS_CHILD ProcessDetailPage and resizes it with the frame; no value is returned
// directly because lifetime is tied to WM_NCDESTROY.
struct DetailHostState {
    DWORD processId = 0;
    ULONGLONG expectedCreationTime100ns = 0;
    HWND child = nullptr;
    int maximumWidth = 0;
};

struct DetailHostCreateParams {
    DWORD processId = 0;
    ULONGLONG expectedCreationTime100ns = 0;
    int maximumWidth = 0;
};

constexpr wchar_t kProcessDetailHostClass[] = L"KswordARKLight.ProcessDetailHost";

bool EnsureDetailChild(HWND hwnd, DetailHostState& state) {
    if (state.child) {
        return true;
    }

    RECT client{};
    ::GetClientRect(hwnd, &client);
    state.child = Ksword::Features::ProcessDetail::CreateProcessDetailPage(
        hwnd,
        state.processId,
        state.expectedCreationTime100ns,
        client);
    if (!state.child) {
        return false;
    }
    ::ShowWindow(state.child, SW_SHOW);
    ::MoveWindow(state.child, 0, 0, client.right - client.left, client.bottom - client.top, TRUE);
    return true;
}

// DetailHostProc is the top-level process-detail host window procedure. Inputs
// are ordinary Win32 messages; processing creates/resizes the child detail page;
// output is the message LRESULT expected by DefWindowProcW callers.
LRESULT CALLBACK DetailHostProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    DetailHostState* state = reinterpret_cast<DetailHostState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        const auto* parameters = create ? static_cast<const DetailHostCreateParams*>(create->lpCreateParams) : nullptr;
        auto* owned = new DetailHostState();
        if (parameters) {
            owned->processId = parameters->processId;
            owned->expectedCreationTime100ns = parameters->expectedCreationTime100ns;
            owned->maximumWidth = parameters->maximumWidth;
        }
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned));
        return TRUE;
    }
    case WM_CREATE:
        state = reinterpret_cast<DetailHostState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        // Delay child-page creation until the first size/show pass. At WM_CREATE
        // the overlapped frame may not yet have its final client rectangle.
        return 0;
    case WM_SIZE:
        if (state && EnsureDetailChild(hwnd, *state)) {
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            ::MoveWindow(state->child, 0, 0, rc.right - rc.left, rc.bottom - rc.top, TRUE);
        }
        return 0;
    case WM_SHOWWINDOW:
        if (state && wParam != FALSE) {
            EnsureDetailChild(hwnd, *state);
        }
        return 0;
    case WM_GETMINMAXINFO:
        if (state && state->maximumWidth > 0) {
            auto* minMax = reinterpret_cast<MINMAXINFO*>(lParam);
            minMax->ptMaxTrackSize.x = state->maximumWidth;
        }
        return 0;
    case WM_NCDESTROY:
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

// RegisterDetailHostClass installs the standalone detail host class once. There
// is no input; processing registers a standard overlapped window; output reports
// whether CreateWindowExW may use the class name.
bool RegisterDetailHostClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = DetailHostProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kProcessDetailHostClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

// OpenProcessDetailWindow creates one top-level detail window for a single PID.
// Inputs are owner and pid; processing reuses the ProcessDetail page exactly as
// used in docks; output reports whether the host window was created and shown.
bool OpenProcessDetailWindow(HWND owner, DWORD processId, ULONGLONG expectedCreationTime100ns) {
    if (processId == 0 || expectedCreationTime100ns == 0U || !RegisterDetailHostClass()) {
        return false;
    }

    const HWND rootOwner = owner ? ::GetAncestor(owner, GA_ROOT) : nullptr;
    RECT available{};
    if (rootOwner) {
        ::GetClientRect(rootOwner, &available);
    }
    int availableWidth = available.right - available.left;
    if (availableWidth <= 0) {
        ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &available, 0);
        availableWidth = available.right - available.left;
    }
    const int maximumWidth = std::max(720, availableWidth * 3 / 4);
    const int initialWidth = std::min(1160, maximumWidth);

    std::wstring processName = LeafName(QueryProcessImagePath(processId));
    if (processName.empty()) {
        processName = L"<unknown>";
    }
    const std::wstring title = L"进程详细信息 - " + processName + L" (PID " + std::to_wstring(processId) + L")";
    const DetailHostCreateParams parameters{ processId, expectedCreationTime100ns, maximumWidth };
    HWND host = ::CreateWindowExW(WS_EX_APPWINDOW,
        kProcessDetailHostClass,
        title.c_str(),
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        initialWidth,
        760,
        rootOwner,
        nullptr,
        ::GetModuleHandleW(nullptr),
        const_cast<DetailHostCreateParams*>(&parameters));
    if (!host) {
        return false;
    }

    ::ShowWindow(host, SW_SHOWNORMAL);
    ::UpdateWindow(host);
    auto* state = reinterpret_cast<DetailHostState*>(::GetWindowLongPtrW(host, GWLP_USERDATA));
    if (!state || !EnsureDetailChild(host, *state)) {
        ::DestroyWindow(host);
        return false;
    }
    return true;
}

// ProcessViewState owns the controls and model for one process-list page.
// Inputs are Win32 messages routed through ProcessViewWndProc. Processing keeps
// the current snapshot, visible mode, icon cache, picker state, and selected
// rows in sync. Return values are produced by WndProc message handling.
struct ProcessViewState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND presetCombo = nullptr;
    HWND columnsButton = nullptr;
    HWND presetButton = nullptr;
    HWND pauseButton = nullptr;
    HWND pickerButton = nullptr;
    HWND refreshSlider = nullptr;
    HWND statusText = nullptr;
    HWND filterBar = nullptr;
    HWND listView = nullptr;
    HIMAGELIST imageList = nullptr;
    ProcessModel model;
    // activeColumns 用途：当前运行期实际展示的逻辑列；关闭页面后不持久化。
    std::vector<ProcessColumnId> activeColumns = DefaultProcessColumns(ProcessViewPreset::Monitor);
    ProcessViewPreset preset = ProcessViewPreset::Monitor;
    bool pickingWindow = false;
    bool refreshPaused = false;
    UINT refreshIntervalSeconds = 2;
    ULONGLONG previousSampleTickMs = 0;
    std::vector<ProcessActionMenuItem> activeMenuItems;
    std::unordered_map<std::wstring, int> iconCache;
    std::unordered_map<std::wstring, ULONGLONG> previousCpuTime100ns;
    std::unordered_map<std::wstring, ProcessSnapshotRow> lastActiveRowsByIdentity;
    std::unordered_map<std::wstring, ProcessRowVisualState> visualStateByIdentity;
    std::vector<ProcessPresentationRow> presentationRows;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::vector<std::size_t> visibleRowIndexes;
    std::wstring displayTextScratch;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    bool hasLastActiveSnapshot = false;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<struct ProcessRefreshSnapshot>> refreshTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ProcessFilterResult>> filterTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ProcessViewActionResult>> actionTask;
};

ULONGLONG ResolveCurrentProcessCreationTime(
    const ProcessViewState& state,
    const DWORD processId,
    const ULONGLONG expectedCreationTime100ns) {
    for (const ProcessSnapshotRow& row : state.model.rows()) {
        if (row.processId != processId) {
            continue;
        }
        if (expectedCreationTime100ns != 0U && row.creationTime100ns != expectedCreationTime100ns) {
            return 0U;
        }
        if (row.creationTime100ns != 0U) {
            return row.creationTime100ns;
        }
    }

    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        return 0U;
    }
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    ULARGE_INTEGER value{};
    if (::GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
        value.LowPart = creation.dwLowDateTime;
        value.HighPart = creation.dwHighDateTime;
    }
    ::CloseHandle(process);
    if (expectedCreationTime100ns != 0U && value.QuadPart != expectedCreationTime100ns) {
        return 0U;
    }
    return value.QuadPart;
}

// KernelProcessSnapshotEntry 用途：保存 ArkDriverClient R0 枚举返回的一行进程证据。
// 调用方式：EnumerateProcessesByR0Driver 填充，ApplyDefaultHiddenProcessAudit 合并到 R3 行。
struct KernelProcessSnapshotEntry {
    std::uint32_t processId = 0;
    std::uint32_t parentProcessId = 0;
    std::uint32_t flags = 0;
    std::uint32_t sessionId = 0;
    std::uint32_t fieldFlags = 0;
    std::uint32_t r0Status = KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE;
    std::uint8_t protection = 0;
    std::uint32_t protectionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
    std::uint64_t objectTableAddress = 0;
    std::uint64_t sectionObjectAddress = 0;
    std::string imageName;
    std::string imagePath;
};

// HiddenProcessAuditResult 用途：汇总默认 R0 查隐藏进程结果，最终追加到状态栏。
// 返回值语义：querySucceeded=false 表示驱动不可用或 IOCTL 失败，但普通 R3 刷新继续执行。
struct HiddenProcessAuditResult {
    bool querySucceeded = false;
    std::size_t kernelEnumeratedCount = 0;
    std::size_t kernelOnlyCount = 0;
    std::wstring detailText;
};

// ProcessRefreshSnapshot is produced entirely on a worker thread. It keeps R3
// enumeration and both R0 evidence queries out of timer and button handlers.
struct ProcessRefreshSnapshot {
    ProcessEnumerationResult enumeration;
    HiddenProcessAuditResult hiddenAudit;
    std::wstring crossViewStatusSuffix;
};

// ActiveColumnSet 用途：将逻辑列集合转换为当前 ListView 的物理列描述。
std::vector<Ksword::Ui::ListViewColumn> ActiveColumnSet(const ProcessViewState& state) {
    std::vector<Ksword::Ui::ListViewColumn> columns;
    columns.reserve(state.activeColumns.size());
    for (std::size_t index = 0; index < state.activeColumns.size(); ++index) {
        const ProcessColumnDescriptor* descriptor = FindProcessColumn(state.activeColumns[index]);
        if (descriptor) columns.push_back({ static_cast<int>(index), descriptor->width, descriptor->format, descriptor->title });
    }
    return columns;
}

// StateFromWindow returns the state pointer stored on the page HWND. Input is a
// window handle; processing reads GWLP_USERDATA; output is null before creation
// finishes or after destruction clears the pointer.
ProcessViewState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<ProcessViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// SetStatus writes a short human-readable status line. Inputs are page state and
// text; processing updates the STATIC control; no value is returned.
void SetStatus(ProcessViewState& state, const std::wstring& text) {
    if (state.statusText) {
        ::SetWindowTextW(state.statusText, text.c_str());
    }
}

// RefreshIntervalMs returns the active refresh period in milliseconds. Input is
// state.refreshIntervalSeconds from the compact slider; processing clamps the
// value to the supported slider range; output is passed to SetTimer.
UINT RefreshIntervalMs(const ProcessViewState& state) {
    const UINT seconds = std::clamp<UINT>(state.refreshIntervalSeconds, 1, 10);
    return seconds * 1000U;
}

// RestartRefreshTimer applies the current slider interval to the page timer.
// Input is the process page state; processing kills the old timer and creates a
// new one on the page HWND; no value is returned.
void RestartRefreshTimer(ProcessViewState& state) {
    if (!state.hwnd) {
        return;
    }
    ::KillTimer(state.hwnd, kRefreshTimerId);
    ::SetTimer(state.hwnd, kRefreshTimerId, RefreshIntervalMs(state), nullptr);
}

// UpdateToolbarTexts keeps compact button labels in sync with runtime state.
// Input is the page state; processing updates only existing HWNDs; no value is
// returned because controls may be absent during partial creation.
void UpdateToolbarTexts(ProcessViewState& state) {
    if (state.presetCombo) {
        const LRESULT count = ::SendMessageW(state.presetCombo, CB_GETCOUNT, 0, 0);
        for (LRESULT index = 0; index < count; ++index) {
            if (static_cast<ProcessViewPreset>(::SendMessageW(state.presetCombo, CB_GETITEMDATA, index, 0)) == state.preset) {
                ::SendMessageW(state.presetCombo, CB_SETCURSEL, index, 0);
                break;
            }
        }
    }
    if (state.pauseButton) {
        ::SetWindowTextW(state.pauseButton, state.refreshPaused ? L"恢复" : L"暂停");
    }
}

// CreateProcessListView creates a multi-select report ListView. Inputs are the
// parent HWND and child id. Processing intentionally avoids the shared helper
// because that helper enables LVS_SINGLESEL; output is the child HWND or null.
HWND CreateProcessListView(HWND parent, int id) {
    HWND hwnd = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
        0,
        0,
        0,
        0,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (!hwnd) {
        return nullptr;
    }

    ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    ListView_SetExtendedListViewStyleEx(hwnd,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    return hwnd;
}

// CreateIconList creates the small-image list used by the process list. There
// are no inputs; processing asks comctl32 for a 16x16 image list; output is the
// HIMAGELIST handle or null. The caller owns and destroys it.
HIMAGELIST CreateIconList() {
    return ImageList_Create(::GetSystemMetrics(SM_CXSMICON),
        ::GetSystemMetrics(SM_CYSMICON),
        ILC_COLOR32 | ILC_MASK,
        64,
        64);
}

// AddIconFromShell extracts a small icon for a path or returns a generic icon.
// Inputs are the image list, an executable path and whether fallback is allowed.
// Processing uses SHGetFileInfoW and copies the icon into the image list. Return
// value is the image index or -1 when no icon could be obtained.
int AddIconFromShell(HIMAGELIST imageList, const std::wstring& path, bool fallback) {
    if (!imageList) {
        return -1;
    }

    SHFILEINFOW info{};
    UINT flags = SHGFI_ICON | SHGFI_SMALLICON;
    const wchar_t* queryPath = path.empty() ? L".exe" : path.c_str();
    if (path.empty() && fallback) {
        flags |= SHGFI_USEFILEATTRIBUTES;
    }

    if (!::SHGetFileInfoW(queryPath,
            fallback ? FILE_ATTRIBUTE_NORMAL : 0,
            &info,
            sizeof(info),
            flags) || !info.hIcon) {
        return -1;
    }

    const int index = ImageList_AddIcon(imageList, info.hIcon);
    ::DestroyIcon(info.hIcon);
    return index;
}

// IconIndexForPath resolves and caches a process icon. Inputs are page state and
// an executable path. Processing extracts an icon with Shell APIs and caches by
// path; output is a ListView image index, falling back to a generic executable.
int IconIndexForPath(ProcessViewState& state, const std::wstring& path) {
    const std::wstring key = path.empty() ? L"<generic-exe>" : path;
    const auto found = state.iconCache.find(key);
    if (found != state.iconCache.end()) {
        return found->second;
    }

    int index = AddIconFromShell(state.imageList, path, path.empty());
    if (index < 0 && !path.empty()) {
        index = IconIndexForPath(state, std::wstring());
    }
    if (index >= 0) {
        state.iconCache.emplace(key, index);
    }
    return index;
}

// LayoutChildren positions the toolbar, status text and ListView. Inputs are the
// page state and client rectangle; processing uses fixed toolbar heights and the
// remaining area for process rows; no value is returned.
void LayoutChildren(ProcessViewState& state, const RECT& rc) {
    const int buttonHeight = 24;
    const int buttonTop = 0;
    int x = 0;

    ::MoveWindow(state.refreshButton, x, buttonTop, 56, buttonHeight, TRUE);
    x += 56;
    ::MoveWindow(state.pauseButton, x, buttonTop, 56, buttonHeight, TRUE);
    x += 56;
    ::MoveWindow(state.presetCombo, x, buttonTop, 92, buttonHeight + 180, TRUE);
    x += 92;
    ::MoveWindow(state.columnsButton, x, buttonTop, 54, buttonHeight, TRUE);
    x += 54;
    ::MoveWindow(state.pickerButton, x, buttonTop, 104, buttonHeight, TRUE);
    x += 104;
    ::MoveWindow(state.refreshSlider, x, buttonTop + 2, 110, buttonHeight - 4, TRUE);
    x += 110;

    const int statusTop = buttonTop + buttonHeight;
    const int width = std::max(100, static_cast<int>(rc.right - rc.left));
    const int height = std::max(100, static_cast<int>(rc.bottom - rc.top));
    if (state.filterBar) {
        ::MoveWindow(state.filterBar,
            x + 8,
            buttonTop,
            std::max(1, width - x - 8),
            buttonHeight,
            TRUE);
    }
    ::MoveWindow(state.statusText, 0, statusTop, width, 20, TRUE);

    const int listTop = statusTop + 20;
    ::MoveWindow(state.listView,
        0,
        listTop,
        std::max(80, width),
        std::max(80, height - listTop),
        TRUE);
}

// PaintBackground clears the page background only. Inputs are HWND and paint DC;
// processing intentionally draws no title text or decorative padding; no value
// is returned.
void PaintBackground(HWND hwnd, HDC dc) {
    RECT rc{};
    ::GetClientRect(hwnd, &rc);
    ::FillRect(dc, &rc, Ksword::Ui::AppTheme().windowBrush());
}

// RebuildColumns replaces the ListView columns for the current mode. Input is
// page state; processing deletes old columns and inserts mode-specific headers;
// no value is returned.
void RebuildColumns(ProcessViewState& state) {
    if (!state.listView) {
        return;
    }

    HWND header = ListView_GetHeader(state.listView);
    const int count = header ? Header_GetItemCount(header) : 0;
    for (int index = count - 1; index >= 0; --index) {
        ListView_DeleteColumn(state.listView, index);
    }

    for (const auto& column : ActiveColumnSet(state)) {
        LVCOLUMNW nativeColumn{};
        nativeColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        nativeColumn.fmt = column.format;
        nativeColumn.cx = column.width;
        nativeColumn.pszText = const_cast<LPWSTR>(column.title.c_str());
        ListView_InsertColumn(state.listView, column.index, &nativeColumn);
    }
}

// Selection and the filtering scheduler are declared here because installing
// a new immutable presentation must save process-instance selection and viewport
// before replacing the owner-data row count.
std::vector<DWORD> SelectedPids(ProcessViewState& state);
std::vector<std::wstring> SelectedStableKeys(ProcessViewState& state);
std::wstring StableKeyFromListItem(const ProcessViewState& state, int item);
void ApplyProcessFilter(ProcessViewState& state,
    ProcessFilterResult result,
    const std::vector<ProcessPresentationRow>* previousPresentationRows = nullptr,
    const std::vector<std::size_t>* previousVisibleRowIndexes = nullptr,
    const std::unordered_map<std::wstring, ProcessRowVisualState>* previousVisualStates = nullptr);
void RequestProcessFilter(ProcessViewState& state,
    const std::wstring& query,
    std::vector<std::wstring> selectedStableKeys,
    std::wstring topStableKey);

// BuildPresentationRows converts the model into immutable owner-data rows once
// per completed snapshot. Formatting is deliberately not performed by
// LVN_GETDISPINFO or custom draw, keeping scrolling independent of table size.
void BuildPresentationRows(ProcessViewState& state,
    std::vector<ProcessPresentationRow>& presentationRows,
    std::vector<Ksword::Ui::VirtualListRow>& filterRows) {
    const auto& sourceRows = state.model.displayRows(ProcessViewMode::UtilizationFriendly);
    presentationRows.clear();
    filterRows.clear();
    presentationRows.reserve(sourceRows.size());
    filterRows.reserve(sourceRows.size());

    for (const ProcessDisplayRow& sourceRow : sourceRows) {
        ProcessPresentationRow row{};
        row.display = sourceRow;
        row.cells.reserve(state.activeColumns.size());
        for (const ProcessColumnId column : state.activeColumns) {
            const ProcessSnapshotRow* process = state.model.rowForDisplayRow(sourceRow);
            row.cells.push_back(sourceRow.groupHeader
                ? (column == ProcessColumnId::Name ? sourceRow.title : L"")
                : (process ? ProcessColumnText(*process, column) : L""));
        }

        if (const ProcessSnapshotRow* process = state.model.rowForDisplayRow(sourceRow)) {
            row.processId = process->processId;
            row.creationTime100ns = process->creationTime100ns;
            row.kernelOnly = process->r0KernelOnly;
            row.iconPath = process->imagePath;
            row.stableKey = ProcessStableKey(process->processId, process->creationTime100ns);
        } else {
            row.stableKey = L"group:" + std::to_wstring(static_cast<int>(sourceRow.group));
        }

        Ksword::Ui::VirtualListRow filterRow{};
        filterRow.stableKey = row.stableKey;
        filterRow.cells = row.cells;
        // 全量列文本仅用于筛选，不会改变当前 ListView 的可见列布局。
        if (const ProcessSnapshotRow* process = state.model.rowForDisplayRow(sourceRow)) {
            for (const ProcessColumnDescriptor& column : ProcessColumnDescriptors()) {
                filterRow.cells.push_back(ProcessColumnText(*process, column.id));
            }
        }
        if (!row.iconPath.empty()) {
            filterRow.cells.push_back(row.iconPath);
        }

        presentationRows.push_back(std::move(row));
        filterRows.push_back(std::move(filterRow));
    }
}

// RebuildRows creates and installs a complete owner-data snapshot in one UI
// transaction. The previous rows stay mapped until the new filter indexes are
// ready, so periodic refreshes never briefly clear the process list.
void RebuildRows(ProcessViewState& state,
    const std::unordered_map<std::wstring, ProcessRowVisualState>* previousVisualStates = nullptr) {
    if (!state.listView) {
        return;
    }

    const std::vector<std::wstring> selectedStableKeys = SelectedStableKeys(state);
    const std::wstring topStableKey = StableKeyFromListItem(state, ListView_GetTopIndex(state.listView));
    std::vector<ProcessPresentationRow> previousPresentationRows = std::move(state.presentationRows);
    const std::vector<std::size_t> previousVisibleRowIndexes = state.visibleRowIndexes;
    auto filterRows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>();
    BuildPresentationRows(state, state.presentationRows, *filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;

    const std::wstring query = state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : state.filterQuery;
    state.filterQuery = query;
    state.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);

    // Process snapshots are intentionally kept compact, so matching this
    // immutable text view on the UI thread is cheap. More importantly, it lets
    // the list swap from one valid mapping directly to the next instead of
    // exposing an empty owner-data table while a worker filters the new rows.
    ProcessFilterResult result{};
    result.displayGeneration = state.displayGeneration;
    result.query = query;
    result.useRegex = state.filterUseRegex;
    result.selectedStableKeys = selectedStableKeys;
    result.topStableKey = topStableKey;
    result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(
        *state.filterRows,
        result.query,
        result.useRegex);
    ApplyProcessFilter(state,
        std::move(result),
        &previousPresentationRows,
        &previousVisibleRowIndexes,
        previousVisualStates);
}

// DisplayIndexFromListItem maps a visible owner-data row to its immutable
// presentation index. It does not call ListView_GetItem because owner-data
// controls do not retain one LVITEM per row.
int DisplayIndexFromListItem(const ProcessViewState& state, int item) {
    if (item < 0 || static_cast<std::size_t>(item) >= state.visibleRowIndexes.size()) {
        return -1;
    }
    const std::size_t displayIndex = state.visibleRowIndexes[static_cast<std::size_t>(item)];
    return displayIndex <= static_cast<std::size_t>(INT_MAX) ? static_cast<int>(displayIndex) : -1;
}

// SelectedDisplayIndexes reads the current multi-selection and translates the
// visible owner-data indexes through the immutable result mapping.
std::vector<int> SelectedDisplayIndexes(ProcessViewState& state) {
    std::vector<int> indexes;
    if (!state.listView) {
        return indexes;
    }

    int item = -1;
    while ((item = ListView_GetNextItem(state.listView, item, LVNI_SELECTED)) != -1) {
        const int displayIndex = DisplayIndexFromListItem(state, item);
        if (displayIndex >= 0) {
            indexes.push_back(displayIndex);
        }
    }
    return indexes;
}

// SelectedPids converts selected immutable presentation rows to process ids.
// Group headers remain selectable for copy operations but never become actions.
std::vector<DWORD> SelectedPids(ProcessViewState& state) {
    std::vector<DWORD> pids;
    for (const int index : SelectedDisplayIndexes(state)) {
        if (index < 0 || static_cast<std::size_t>(index) >= state.presentationRows.size()) {
            continue;
        }
        const DWORD processId = state.presentationRows[static_cast<std::size_t>(index)].processId;
        if (processId != 0) {
            pids.push_back(processId);
        }
    }
    return pids;
}

// SelectedStableKeys retains only real process rows and preserves their snapshot
// identity across an asynchronous filter/rebuild cycle.
std::vector<std::wstring> SelectedStableKeys(ProcessViewState& state) {
    std::vector<std::wstring> stableKeys;
    for (const int index : SelectedDisplayIndexes(state)) {
        if (index < 0 || static_cast<std::size_t>(index) >= state.presentationRows.size()) {
            continue;
        }
        const ProcessPresentationRow& row = state.presentationRows[static_cast<std::size_t>(index)];
        if (row.processId != 0 && !row.stableKey.empty()) {
            stableKeys.push_back(row.stableKey);
        }
    }
    return stableKeys;
}

std::wstring StableKeyFromListItem(const ProcessViewState& state, const int item) {
    const int displayIndex = DisplayIndexFromListItem(state, item);
    if (displayIndex < 0 || static_cast<std::size_t>(displayIndex) >= state.presentationRows.size()) {
        return {};
    }
    return state.presentationRows[static_cast<std::size_t>(displayIndex)].stableKey;
}

// GroupHeaderAtListItem returns the clicked friendly group header from the
// current immutable presentation snapshot.
const ProcessPresentationRow* GroupHeaderAtListItem(ProcessViewState& state, int item) {
    const int displayIndex = DisplayIndexFromListItem(state, item);
    if (displayIndex < 0 || static_cast<std::size_t>(displayIndex) >= state.presentationRows.size()) {
        return nullptr;
    }
    const ProcessPresentationRow& row = state.presentationRows[static_cast<std::size_t>(displayIndex)];
    return row.display.groupHeader ? &row : nullptr;
}

// DisplayRowFromListItem resolves a visible owner-data row without touching the
// model. Custom drawing therefore remains O(visible cells), even for long lists.
const ProcessPresentationRow* DisplayRowFromListItem(ProcessViewState& state, int item) {
    const int displayIndex = DisplayIndexFromListItem(state, item);
    if (displayIndex < 0 || static_cast<std::size_t>(displayIndex) >= state.presentationRows.size()) {
        return nullptr;
    }
    return &state.presentationRows[static_cast<std::size_t>(displayIndex)];
}

// VisualStateForDisplayRow resolves green/gray lifecycle highlighting for a
// visible process row. Inputs are page state and display row; processing maps
// the process instance stable key into the latest refresh-diff table; output is
// Normal for groups and unchanged process rows.
ProcessRowVisualState VisualStateForDisplayRow(ProcessViewState& state, const ProcessPresentationRow& displayRow) {
    if (displayRow.processId == 0) {
        return ProcessRowVisualState::Normal;
    }
    if (displayRow.display.groupHeader) {
        return ProcessRowVisualState::Normal;
    }
    if (displayRow.kernelOnly) {
        return ProcessRowVisualState::KernelOnly;
    }
    const auto source = state.visualStateByIdentity.find(displayRow.stableKey);
    return source != state.visualStateByIdentity.end() ? source->second : ProcessRowVisualState::Normal;
}

// RowBackgroundColor returns the fill color used by custom draw. Inputs are
// selection and lifecycle state; processing gives selected rows system colors,
// new rows light green and deleted rows light gray; output is a COLORREF.
COLORREF RowBackgroundColor(bool selected, ProcessRowVisualState visualState) {
    if (selected) {
        return ::GetSysColor(COLOR_HIGHLIGHT);
    }
    if (visualState == ProcessRowVisualState::KernelOnly) {
        return RGB(255, 226, 226);
    }
    if (visualState == ProcessRowVisualState::Added) {
        return RGB(216, 248, 216);
    }
    if (visualState == ProcessRowVisualState::Removed) {
        return RGB(232, 232, 232);
    }
    return ::GetSysColor(COLOR_WINDOW);
}

// RowTextColor returns the text color used by custom draw. Inputs are selection
// and lifecycle state; processing keeps deleted rows muted while selected rows
// use system highlight text; output is a COLORREF.
COLORREF RowTextColor(bool selected, ProcessRowVisualState visualState) {
    if (selected) {
        return ::GetSysColor(COLOR_HIGHLIGHTTEXT);
    }
    if (visualState == ProcessRowVisualState::KernelOnly) {
        return RGB(150, 0, 0);
    }
    if (visualState == ProcessRowVisualState::Removed) {
        return ::GetSysColor(COLOR_GRAYTEXT);
    }
    return ::GetSysColor(COLOR_WINDOWTEXT);
}

// SubItemBounds returns a bounded rectangle for one report-cell. Inputs are the
// list view, item and subitem; processing avoids the common-control quirk where
// subitem zero can report the whole row by clamping to column zero width; output
// is true when a rectangle was obtained.
bool SubItemBounds(HWND listView, int item, int subItem, RECT& bounds) {
    bounds = {};
    if (subItem == 0) {
        bounds.left = LVIR_BOUNDS;
        if (!ListView_GetSubItemRect(listView, item, 0, LVIR_BOUNDS, &bounds)) {
            return false;
        }
        bounds.right = bounds.left + ListView_GetColumnWidth(listView, 0);
        return true;
    }
    return ListView_GetSubItemRect(listView, item, subItem, LVIR_BOUNDS, &bounds) != FALSE;
}

// TextFormatForColumn maps ListView column alignment into DrawText flags.
// Inputs are the active mode and subitem index; output uses vertical centering,
// ellipsis and the column's left/right alignment.
UINT TextFormatForColumn(const ProcessViewState& state, int subItem) {
    UINT format = DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS;
    const auto columns = ActiveColumnSet(state);
    for (const auto& column : columns) {
        if (column.index == subItem && column.format == LVCFMT_RIGHT) {
            return format | DT_RIGHT;
        }
    }
    return format | DT_LEFT;
}

// DrawDottedTreeGuides paints lightweight dotted indentation guides. Inputs are
// the draw DC, first-column bounds and process depth; processing uses the
// current system text color family with a dotted pen; no value is returned.
void DrawDottedTreeGuides(HDC dc, const RECT& bounds, int depth) {
    if (depth <= 0) {
        return;
    }

    HPEN pen = ::CreatePen(PS_DOT, 1, ::GetSysColor(COLOR_3DSHADOW));
    if (!pen) {
        return;
    }
    HGDIOBJ oldPen = ::SelectObject(dc, pen);
    const int rowMidY = bounds.top + (bounds.bottom - bounds.top) / 2;
    for (int level = 1; level <= depth; ++level) {
        const int x = bounds.left + (level - 1) * kTreeIndentPixels + kTreeIndentPixels / 2;
        ::MoveToEx(dc, x, bounds.top, nullptr);
        ::LineTo(dc, x, bounds.bottom);
    }
    const int branchX = bounds.left + (depth - 1) * kTreeIndentPixels + kTreeIndentPixels / 2;
    const int iconLeft = bounds.left + depth * kTreeIndentPixels;
    ::MoveToEx(dc, branchX, rowMidY, nullptr);
    ::LineTo(dc, iconLeft, rowMidY);
    ::SelectObject(dc, oldPen);
    ::DeleteObject(pen);
}

// DrawProcessSubItem custom-draws every visible process cell. Inputs are the
// page state and NMLVCUSTOMDRAW payload; processing draws a stable background,
// optional tree guides/icon in column zero, and text for all columns so hover
// repaint never erases row text; output reports whether default drawing should
// be skipped.
LRESULT DrawProcessSubItem(ProcessViewState& state, NMLVCUSTOMDRAW* draw) {
    if (!draw) {
        return CDRF_DODEFAULT;
    }

    const int item = static_cast<int>(draw->nmcd.dwItemSpec);
    const int subItem = draw->iSubItem;
    const ProcessPresentationRow* displayRow = DisplayRowFromListItem(state, item);
    if (!displayRow) {
        return CDRF_DODEFAULT;
    }

    RECT cell{};
    if (!SubItemBounds(state.listView, item, subItem, cell)) {
        return CDRF_DODEFAULT;
    }

    HDC dc = draw->nmcd.hdc;
    const bool selected = (ListView_GetItemState(state.listView, item, LVIS_SELECTED) & LVIS_SELECTED) != 0;
    const bool focused = (ListView_GetItemState(state.listView, item, LVIS_FOCUSED) & LVIS_FOCUSED) != 0;
    const ProcessRowVisualState visualState = VisualStateForDisplayRow(state, *displayRow);
    const COLORREF background = RowBackgroundColor(selected, visualState);
    const COLORREF textColor = RowTextColor(selected, visualState);
    HBRUSH brush = ::CreateSolidBrush(background);
    if (brush) {
        ::FillRect(dc, &cell, brush);
        ::DeleteObject(brush);
    }

    ::SetBkMode(dc, TRANSPARENT);
    ::SetTextColor(dc, textColor);
    HFONT font = Ksword::Ui::SystemUIFont();
    HGDIOBJ oldFont = font ? ::SelectObject(dc, font) : nullptr;

    if (subItem == 0 && !displayRow->display.groupHeader) {
        DrawDottedTreeGuides(dc, cell, displayRow->display.depth);
        const int iconSize = ::GetSystemMetrics(SM_CXSMICON);
        const int iconLeft = cell.left + displayRow->display.depth * kTreeIndentPixels;
        const int rowHeight = static_cast<int>(cell.bottom - cell.top);
        const int iconTop = static_cast<int>(cell.top) + std::max(0, (rowHeight - iconSize) / 2);
        const int iconIndex = IconIndexForPath(state, displayRow->iconPath);
        if (state.imageList && iconIndex >= 0) {
            ImageList_Draw(state.imageList, iconIndex, dc, iconLeft, iconTop, ILD_TRANSPARENT);
        }

        RECT textRect = cell;
        textRect.left = iconLeft + iconSize + kTreeIconGap + kTreeTextGap;
        const std::wstring empty;
        const std::wstring& text = displayRow->cells.empty() ? empty : displayRow->cells.front();
        ::DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    } else {
        RECT textRect = cell;
        textRect.left += 4;
        textRect.right -= 4;
        const std::wstring empty;
        const std::wstring& text = subItem >= 0 && static_cast<std::size_t>(subItem) < displayRow->cells.size()
            ? displayRow->cells[static_cast<std::size_t>(subItem)]
            : empty;
        ::DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &textRect, TextFormatForColumn(state, subItem));
    }

    if (focused && subItem == 0) {
        RECT focusRect = cell;
        focusRect.right = cell.left;
        HWND header = ListView_GetHeader(state.listView);
        const int count = header ? Header_GetItemCount(header) : 0;
        for (int column = 0; column < count; ++column) {
            focusRect.right += ListView_GetColumnWidth(state.listView, column);
        }
        ::DrawFocusRect(dc, &focusRect);
    }
    if (oldFont) {
        ::SelectObject(dc, oldFont);
    }
    return CDRF_SKIPDEFAULT;
}

// HandleListCustomDraw owns first-column tree drawing while letting comctl32
// render all other cells normally. Inputs are page state and custom-draw data;
// output is the required custom-draw return code for WM_NOTIFY.
LRESULT HandleListCustomDraw(ProcessViewState& state, NMLVCUSTOMDRAW* draw) {
    if (!draw) {
        return CDRF_DODEFAULT;
    }
    switch (draw->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT:
        return CDRF_NOTIFYSUBITEMDRAW;
    case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
        return DrawProcessSubItem(state, draw);
    default:
        return CDRF_DODEFAULT;
    }
}

// HandleVirtualListDisplayInfo supplies only the text and lParam requested for
// visible owner-data rows. The backing ProcessPresentationRow snapshot owns the
// text for the entire notification, so no temporary process enumeration occurs.
LRESULT HandleVirtualListDisplayInfo(ProcessViewState& state, NMLVDISPINFOW* displayInfo) {
    if (!displayInfo) {
        return 0;
    }

    const int displayIndex = DisplayIndexFromListItem(state, displayInfo->item.iItem);
    if (displayIndex < 0 || static_cast<std::size_t>(displayIndex) >= state.presentationRows.size()) {
        return 0;
    }

    const ProcessPresentationRow& row = state.presentationRows[static_cast<std::size_t>(displayIndex)];
    if ((displayInfo->item.mask & LVIF_TEXT) != 0) {
        const int subItem = displayInfo->item.iSubItem;
        state.displayTextScratch = subItem >= 0 && static_cast<std::size_t>(subItem) < row.cells.size()
            ? row.cells[static_cast<std::size_t>(subItem)]
            : std::wstring{};
        displayInfo->item.pszText = state.displayTextScratch.data();
    }
    if ((displayInfo->item.mask & LVIF_PARAM) != 0) {
        displayInfo->item.lParam = static_cast<LPARAM>(displayIndex);
    }
    return 0;
}

// PresentationRowsEqual reports whether two owner-data rows can retain the same
// painted ListView item. Tree layout attributes participate because custom draw
// uses them even when the column text happens to be unchanged.
bool PresentationRowsEqual(const ProcessPresentationRow& left, const ProcessPresentationRow& right) {
    return left.stableKey == right.stableKey &&
        left.iconPath == right.iconPath &&
        left.cells == right.cells &&
        left.processId == right.processId &&
        left.creationTime100ns == right.creationTime100ns &&
        left.kernelOnly == right.kernelOnly &&
        left.display.groupHeader == right.display.groupHeader &&
        left.display.group == right.display.group &&
        left.display.depth == right.display.depth;
}

// PresentationRowAtVisibleItem maps an owner-data item position through a
// supplied snapshot. It is intentionally independent of ProcessViewState so a
// refresh can compare the old and new snapshots before changing ListView state.
const ProcessPresentationRow* PresentationRowAtVisibleItem(
    const std::vector<ProcessPresentationRow>& presentationRows,
    const std::vector<std::size_t>& visibleRowIndexes,
    std::size_t item) {
    if (item >= visibleRowIndexes.size()) {
        return nullptr;
    }
    const std::size_t displayIndex = visibleRowIndexes[item];
    return displayIndex < presentationRows.size() ? &presentationRows[displayIndex] : nullptr;
}

// AppendRedrawItem accumulates adjacent list positions into the smallest set of
// ListView_RedrawItems calls. Inputs are an item position and mutable ranges;
// processing appends or extends the tail range; no value is returned.
void AppendRedrawItem(std::vector<std::pair<int, int>>& ranges, int item) {
    if (item < 0) {
        return;
    }
    if (!ranges.empty() && item <= ranges.back().second + 1) {
        ranges.back().second = std::max(ranges.back().second, item);
        return;
    }
    ranges.emplace_back(item, item);
}

// ApplyProcessFilter installs a filtered index map while preserving selection
// and the top visible logical row. Refresh callers pass the outgoing snapshot,
// allowing the virtual ListView to repaint only positions whose presentation
// actually changed instead of blanking and invalidating the full table.
void ApplyProcessFilter(ProcessViewState& state,
    ProcessFilterResult result,
    const std::vector<ProcessPresentationRow>* previousPresentationRows,
    const std::vector<std::size_t>* previousVisibleRowIndexes,
    const std::unordered_map<std::wstring, ProcessRowVisualState>* previousVisualStates) {
    if (!state.listView || result.displayGeneration != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex) {
        return;
    }

    const std::vector<ProcessPresentationRow>& oldPresentationRows = previousPresentationRows
        ? *previousPresentationRows
        : state.presentationRows;
    const std::vector<std::size_t>& oldVisibleRowIndexes = previousVisibleRowIndexes
        ? *previousVisibleRowIndexes
        : state.visibleRowIndexes;
    const std::unordered_map<std::wstring, ProcessRowVisualState>* oldVisualStates = previousVisualStates
        ? previousVisualStates
        : &state.visualStateByIdentity;
    const std::size_t newItemCount = std::min<std::size_t>(
        result.visibleIndexes.size(),
        static_cast<std::size_t>(INT_MAX));
    const std::size_t oldItemCount = std::min<std::size_t>(
        oldVisibleRowIndexes.size(),
        static_cast<std::size_t>(INT_MAX));
    const std::size_t comparableItemCount = std::min(oldItemCount, newItemCount);
    std::vector<std::pair<int, int>> redrawRanges;
    redrawRanges.reserve(8);

    auto visualStateFor = [](const ProcessPresentationRow* row,
                              const std::unordered_map<std::wstring, ProcessRowVisualState>* visualStates) {
        if (!row || row->display.groupHeader || row->processId == 0) {
            return ProcessRowVisualState::Normal;
        }
        if (row->kernelOnly) {
            return ProcessRowVisualState::KernelOnly;
        }
        if (!visualStates) {
            return ProcessRowVisualState::Normal;
        }
        const auto found = visualStates->find(row->stableKey);
        return found == visualStates->end() ? ProcessRowVisualState::Normal : found->second;
    };

    for (std::size_t item = 0; item < comparableItemCount; ++item) {
        const ProcessPresentationRow* oldRow = PresentationRowAtVisibleItem(
            oldPresentationRows, oldVisibleRowIndexes, item);
        const ProcessPresentationRow* newRow = PresentationRowAtVisibleItem(
            state.presentationRows, result.visibleIndexes, item);
        if (!oldRow || !newRow || !PresentationRowsEqual(*oldRow, *newRow) ||
            visualStateFor(oldRow, oldVisualStates) != visualStateFor(newRow, &state.visualStateByIdentity)) {
            AppendRedrawItem(redrawRanges, static_cast<int>(item));
        }
    }
    for (std::size_t item = comparableItemCount; item < newItemCount; ++item) {
        AppendRedrawItem(redrawRanges, static_cast<int>(item));
    }

    std::vector<int> selectedItemsBefore;
    for (int item = -1;
         (item = ListView_GetNextItem(state.listView, item, LVNI_SELECTED)) != -1;) {
        selectedItemsBefore.push_back(item);
    }

    state.visibleRowIndexes = std::move(result.visibleIndexes);
    int topItem = -1;
    int firstSelectedItem = -1;
    {
        // Do not use ScopedListViewRedrawLock here: its balanced full
        // invalidation would undo the delta calculation above. The header is
        // unchanged, so only freeze the body while its mapping and selection
        // are switched together.
        Ksword::Ui::ScopedWindowRedrawLock redrawLock(state.listView, false);
        if (oldItemCount != newItemCount) {
            ListView_SetItemCountEx(state.listView,
                static_cast<int>(newItemCount),
                LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
        }
        ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);

        std::unordered_set<std::wstring> selectedSet(
            result.selectedStableKeys.begin(),
            result.selectedStableKeys.end());
        for (std::size_t item = 0; item < newItemCount; ++item) {
            const std::size_t displayIndex = state.visibleRowIndexes[item];
            if (displayIndex >= state.presentationRows.size()) {
                continue;
            }
            const ProcessPresentationRow& row = state.presentationRows[displayIndex];
            if (topItem < 0 && !result.topStableKey.empty() && row.stableKey == result.topStableKey) {
                topItem = static_cast<int>(item);
            }
            if (row.processId != 0 && selectedSet.find(row.stableKey) != selectedSet.end()) {
                const int selectedItem = static_cast<int>(item);
                ListView_SetItemState(state.listView, selectedItem, LVIS_SELECTED, LVIS_SELECTED);
                if (firstSelectedItem < 0) {
                    firstSelectedItem = selectedItem;
                }
            }
        }
        if (firstSelectedItem >= 0) {
            ListView_SetItemState(state.listView, firstSelectedItem, LVIS_FOCUSED, LVIS_FOCUSED);
        }
        if (topItem >= 0) {
            ListView_EnsureVisible(state.listView, topItem, FALSE);
        } else if (firstSelectedItem >= 0) {
            ListView_EnsureVisible(state.listView, firstSelectedItem, FALSE);
        }
    }

    // Selection styling can change independently from row text. Repaint the
    // previous and restored selection positions in addition to data deltas.
    for (const auto& range : redrawRanges) {
        ListView_RedrawItems(state.listView, range.first, range.second);
    }
    for (const int item : selectedItemsBefore) {
        if (item >= 0 && static_cast<std::size_t>(item) < newItemCount) {
            ListView_RedrawItems(state.listView, item, item);
        }
    }
    if (firstSelectedItem >= 0) {
        ListView_RedrawItems(state.listView, firstSelectedItem, firstSelectedItem);
    }
    if (newItemCount == 0 && oldItemCount != 0) {
        ::InvalidateRect(state.listView, nullptr, FALSE);
    }
    if (!result.query.empty()) {
        SetStatus(state,
            L"筛选结果 " + std::to_wstring(state.visibleRowIndexes.size()) +
            L" / " + std::to_wstring(state.presentationRows.size()) + L" 行。");
    }
}

// RequestProcessFilter captures a shared, immutable text snapshot. Repeated
// keystrokes coalesce in AsyncSnapshotTask and its generation check prevents a
// stale background match from overwriting a newer query or process refresh.
void RequestProcessFilter(ProcessViewState& state,
    const std::wstring& query,
    std::vector<std::wstring> selectedStableKeys,
    std::wstring topStableKey) {
    state.filterQuery = query;
    state.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    const std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> rows = state.filterRows;
    const std::uint64_t displayGeneration = state.displayGeneration;
    const bool useRegex = state.filterUseRegex;
    if (!state.filterTask || !rows) {
        ProcessFilterResult result{};
        result.displayGeneration = displayGeneration;
        result.query = query;
        result.useRegex = useRegex;
        result.selectedStableKeys = std::move(selectedStableKeys);
        result.topStableKey = std::move(topStableKey);
        result.visibleIndexes.resize(state.presentationRows.size());
        for (std::size_t index = 0; index < result.visibleIndexes.size(); ++index) {
            result.visibleIndexes[index] = index;
        }
        ApplyProcessFilter(state, std::move(result));
        return;
    }

    state.filterTask->request(
        [rows, displayGeneration, useRegex, query, selectedStableKeys = std::move(selectedStableKeys), topStableKey = std::move(topStableKey)]() mutable {
            ProcessFilterResult result{};
            result.displayGeneration = displayGeneration;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.selectedStableKeys = std::move(selectedStableKeys);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<ProcessFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                SetStatus(state, L"进程筛选任务异常结束。已保留当前可见结果。");
                return;
            }
            ApplyProcessFilter(state, std::move(*result));
        });
}

// SelectedRowsAsText builds tab-separated text for selected visible rows. Inputs
// are page state and whether all columns should be copied. Processing reads the
// current model display rows; output is suitable for the clipboard.
std::wstring SelectedRowsAsText(ProcessViewState& state, bool allColumns) {
    const auto indexes = SelectedDisplayIndexes(state);
    std::wstring text;

    for (int index : indexes) {
        if (index < 0 || static_cast<std::size_t>(index) >= state.presentationRows.size()) {
            continue;
        }
        const ProcessPresentationRow& row = state.presentationRows[static_cast<std::size_t>(index)];
        const int maxColumn = allColumns ? static_cast<int>(row.cells.size()) : std::min<int>(1, static_cast<int>(row.cells.size()));
        for (int column = 0; column < maxColumn; ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += row.cells[static_cast<std::size_t>(column)];
        }
        text += L"\r\n";
    }
    return text;
}

// VisibleRowsAsText exports the current owner-data result mapping, allowing the
// context menu to copy every filtered row without selecting or repainting them.
std::wstring VisibleRowsAsText(const ProcessViewState& state) {
    std::wstring text;
    for (const std::size_t displayIndex : state.visibleRowIndexes) {
        if (displayIndex >= state.presentationRows.size()) {
            continue;
        }
        const ProcessPresentationRow& row = state.presentationRows[displayIndex];
        for (std::size_t column = 0; column < row.cells.size(); ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += row.cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

// VisibleRowsAsTsv exports the current filtered owner-data mapping together
// with precisely the columns that are currently visible. It intentionally
// reuses the immutable presentation snapshot, so saving evidence neither
// re-enumerates target processes nor requires any additional access rights.
std::wstring VisibleRowsAsTsv(const ProcessViewState& state) {
    if (state.visibleRowIndexes.empty()) {
        return {};
    }

    std::vector<std::wstring> headers;
    headers.reserve(state.activeColumns.size());
    for (const ProcessColumnId column : state.activeColumns) {
        const ProcessColumnDescriptor* descriptor = FindProcessColumn(column);
        headers.push_back(descriptor ? descriptor->title : L"");
    }

    std::vector<std::vector<std::wstring>> rows;
    rows.reserve(state.visibleRowIndexes.size());
    for (const std::size_t displayIndex : state.visibleRowIndexes) {
        if (displayIndex < state.presentationRows.size()) {
            rows.push_back(state.presentationRows[displayIndex].cells);
        }
    }
    return Ksword::Features::AuditCommon::BuildTsv(headers, rows);
}

// ExportVisibleResults lets an analyst preserve the exact columns and filtered
// rows currently shown in the process list. SaveUtf8TextFileWithDialog records
// the completed user-selected export in the evidence session.
void ExportVisibleResults(ProcessViewState& state) {
    const std::wstring text = VisibleRowsAsTsv(state);
    if (text.empty()) {
        SetStatus(state, L"没有可导出的可见进程结果。");
        return;
    }

    std::wstring error;
    switch (Ksword::Ui::SaveUtf8TextFileWithDialog(
        state.hwnd,
        L"processes.tsv",
        L"导出可见进程结果",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0",
        L"tsv",
        text,
        &error)) {
    case Ksword::Ui::SaveTextFileResult::Saved:
        SetStatus(state, L"可见进程结果已导出为 TSV，并已记录到证据会话。");
        break;
    case Ksword::Ui::SaveTextFileResult::Cancelled:
        SetStatus(state, L"已取消导出可见进程结果。");
        break;
    case Ksword::Ui::SaveTextFileResult::Failed:
        SetStatus(state, L"导出可见进程结果失败：" + error);
        break;
    }
}

// NarrowToWide converts ArkDriverClient diagnostic strings to the native UI
// encoding. Input is UTF-8/ASCII text from the shared wrapper; output is a
// best-effort wide string suitable for status bars and R0 evidence cells.
std::wstring NarrowToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    int chars = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    UINT codePage = CP_UTF8;
    if (chars <= 0) {
        codePage = CP_ACP;
        chars = ::MultiByteToWideChar(codePage, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    }
    if (chars <= 0) {
        return L"<decode failed>";
    }

    std::wstring wide(static_cast<std::size_t>(chars), L'\0');
    ::MultiByteToWideChar(codePage, 0, text.data(), static_cast<int>(text.size()), wide.data(), chars);
    return wide;
}

// FlagHexText formats raw source/anomaly masks without interpreting unsupported
// future bits. Input is a protocol mask; output is stable uppercase hex.
std::wstring FlagHexText(ULONG value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// ProcessR0StatusText 用途：把 R0 枚举行状态转换成状态栏/表格可读文本。
// 输入 statusValue 为 KSWORD_ARK_PROCESS_R0_STATUS_*；返回中文短语，未知值保留数字。
std::wstring ProcessR0StatusText(const std::uint32_t statusValue) {
    switch (statusValue) {
    case KSWORD_ARK_PROCESS_R0_STATUS_OK:
        return L"OK";
    case KSWORD_ARK_PROCESS_R0_STATUS_PARTIAL:
        return L"Partial";
    case KSWORD_ARK_PROCESS_R0_STATUS_DYNDATA_MISSING:
        return L"DynData missing";
    case KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED:
        return L"Read failed";
    default:
        return L"Unavailable";
    }
}

// EnumerateProcessesByR0Driver 用途：复用 Ksword5.1 的 R0 进程枚举方式查隐藏进程。
// 参数 processListOut 接收 R0 行；detailTextOut 接收 ArkDriverClient 诊断文本；返回 true 表示可对比。
bool EnumerateProcessesByR0Driver(
    std::vector<KernelProcessSnapshotEntry>* const processListOut,
    std::wstring* const detailTextOut) {
    if (processListOut == nullptr) {
        return false;
    }
    processListOut->clear();
    if (detailTextOut != nullptr) {
        detailTextOut->clear();
    }

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::ProcessEnumResult enumResult = driverClient.enumerateProcesses(
        KSWORD_ARK_ENUM_PROCESS_FLAG_SCAN_CID_TABLE);
    if (!enumResult.io.ok) {
        if (detailTextOut != nullptr) {
            *detailTextOut = NarrowToWide(enumResult.io.message);
        }
        return false;
    }

    processListOut->reserve(enumResult.entries.size());
    for (const ksword::ark::ProcessEntry& entry : enumResult.entries) {
        KernelProcessSnapshotEntry processEntry{};
        processEntry.processId = entry.processId;
        processEntry.parentProcessId = entry.parentProcessId;
        processEntry.flags = entry.flags;
        processEntry.sessionId = entry.sessionId;
        processEntry.fieldFlags = entry.fieldFlags;
        processEntry.r0Status = entry.r0Status;
        processEntry.protection = entry.protection;
        processEntry.protectionSource = entry.protectionSource;
        processEntry.objectTableAddress = entry.objectTableAddress;
        processEntry.sectionObjectAddress = entry.sectionObjectAddress;
        processEntry.imageName = entry.imageName;
        processEntry.imagePath = entry.imagePath;
        processListOut->push_back(std::move(processEntry));
    }

    if (detailTextOut != nullptr) {
        *detailTextOut = NarrowToWide(enumResult.io.message);
    }
    return true;
}

// PromptOpenPayloadFile shows a common open-file dialog for R0 injection payloads.
// Inputs are owner/filter/title; processing never changes the current directory;
// output is empty when the user cancels.
std::wstring PromptOpenPayloadFile(HWND owner, const wchar_t* filter, const wchar_t* title) {
    wchar_t path[32768]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = path;
    ofn.nMaxFile = static_cast<DWORD>(std::size(path));
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    return ::GetOpenFileNameW(&ofn) ? std::wstring(path) : std::wstring();
}

// ConfirmR0Injection asks for the explicit UI confirmation expected by the
// shared R0 injection protocol. Inputs are owner/action/pid/path; output is true
// only when the user accepts the high-risk operation.
bool ConfirmR0Injection(HWND owner, const wchar_t* action, DWORD pid, const std::wstring& path) {
    std::wstring message = L"将通过 KswordARK R0 进程注入协议执行操作：";
    message += action ? action : L"注入";
    message += L"\r\n\r\n目标 PID: " + std::to_wstring(pid);
    message += L"\r\nPayload: " + path;
    message += L"\r\n\r\n该操作会在目标进程创建远程线程，可能导致目标崩溃或系统不稳定。是否继续？";
    return ::MessageBoxW(owner, message.c_str(), L"确认 R0 注入", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) == IDYES;
}

// MergeKernelProcessExtension 用途：把 R0 枚举字段合并到 Light 进程行，不覆盖 R3 公开 API 的基础信息。
// 参数 row 是目标 UI 行，kernelProcess 是 R0 行；无返回值，调用方继续决定是否合成隐藏行。
void MergeKernelProcessExtension(
    ProcessSnapshotRow& row,
    const KernelProcessSnapshotEntry& kernelProcess) {
    row.r0EnumFlags = kernelProcess.flags;
    row.r0EnumStatus = kernelProcess.r0Status;
    row.r0EnumImagePath = NarrowToWide(kernelProcess.imagePath);
    if ((kernelProcess.fieldFlags & KSWORD_ARK_PROCESS_FIELD_SESSION_PRESENT) != 0U) {
        row.sessionId = kernelProcess.sessionId;
    }
    if (!row.r0EnumImagePath.empty() && row.imagePath.empty()) {
        row.imagePath = row.r0EnumImagePath;
    }
    // 保护字节由同一 R0 枚举响应提供；字段存在时 0 代表“无保护”，不是读取失败。
    if ((kernelProcess.fieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) != 0U) {
        wchar_t protectionText[32]{};
        ::swprintf_s(protectionText, L"0x%02X", static_cast<unsigned int>(kernelProcess.protection));
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::Protection)] = protectionText;
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::Ppl)] =
            kernelProcess.protection == 0 ? L"无" : std::wstring(L"PPL ") + protectionText;
    } else {
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::Protection)] = L"无（驱动未返回字段）";
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::Ppl)] = L"无（驱动未返回字段）";
    }
    if (kernelProcess.objectTableAddress != 0) {
        wchar_t objectTableText[32]{};
        ::swprintf_s(objectTableText, L"0x%016llX", static_cast<unsigned long long>(kernelProcess.objectTableAddress));
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::HandleTable)] = objectTableText;
    }
    if (kernelProcess.sectionObjectAddress != 0) {
        wchar_t sectionObjectText[32]{};
        ::swprintf_s(sectionObjectText, L"0x%016llX", static_cast<unsigned long long>(kernelProcess.sectionObjectAddress));
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::SectionObject)] = sectionObjectText;
    }
}

// BuildKernelOnlyRow 用途：构造 R0 有、R3 无的合成行，和 Ksword5.1 的隐藏进程文案保持一致。
// 输入 kernelProcess 为 R0 枚举行；返回可直接追加到 ProcessModel 的 ProcessSnapshotRow。
ProcessSnapshotRow BuildKernelOnlyRow(const KernelProcessSnapshotEntry& kernelProcess) {
    ProcessSnapshotRow row{};
    row.processId = static_cast<DWORD>(kernelProcess.processId);
    row.parentProcessId = static_cast<DWORD>(kernelProcess.parentProcessId);
    row.r0KernelOnly = true;
    MergeKernelProcessExtension(row, kernelProcess);

    const std::wstring imageName = NarrowToWide(kernelProcess.imageName);
    row.imageName = imageName.empty() ? L"[R0] Unknown" : (L"[R0] " + imageName);
    const bool cidTableWeakEvidence =
        (kernelProcess.flags &
            (KSWORD_ARK_PROCESS_FLAG_CID_TABLE_REFERENCE_FAILED |
                KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED)) != 0U;
    row.imagePath = cidTableWeakEvidence
        ? L"[CID Table命中：对象引用失败或已退出]"
        : L"[仅内核枚举可见]";
    row.r0AuditSummary = L"KernelOnly(Hidden?)";
    row.r0AuditDetail = cidTableWeakEvidence
        ? L"CID Table命中：保留显示，可尝试R0结束"
        : L"仅内核枚举可见";
    row.r0AuditDetail += L"; flags=" + FlagHexText(kernelProcess.flags);
    row.r0AuditDetail += L"; status=" + ProcessR0StatusText(kernelProcess.r0Status);
    return row;
}

// ApplyDefaultHiddenProcessAudit 用途：默认执行 R0/R3 进程列表差异对比，找出疑似隐藏进程。
// 返回值包含状态栏摘要；驱动不可用时只返回失败摘要，不影响 rows 中的 R3 枚举结果。
HiddenProcessAuditResult ApplyDefaultHiddenProcessAudit(std::vector<ProcessSnapshotRow>& rows) {
    HiddenProcessAuditResult result{};
    std::vector<KernelProcessSnapshotEntry> kernelRows;
    std::wstring queryDetail;
    if (!EnumerateProcessesByR0Driver(&kernelRows, &queryDetail)) {
        result.detailText = L"R0隐藏检查: 待驱动装载/查询失败";
        if (!queryDetail.empty()) {
            result.detailText += L" " + queryDetail;
        }
        return result;
    }

    result.querySucceeded = true;
    result.kernelEnumeratedCount = kernelRows.size();

    std::unordered_map<DWORD, const KernelProcessSnapshotEntry*> kernelByPid;
    kernelByPid.reserve(kernelRows.size() * 2U + 1U);
    for (const KernelProcessSnapshotEntry& kernelProcess : kernelRows) {
        kernelByPid[static_cast<DWORD>(kernelProcess.processId)] = &kernelProcess;
    }

    std::unordered_set<DWORD> userPidSet;
    userPidSet.reserve(rows.size() * 2U + 1U);
    for (ProcessSnapshotRow& row : rows) {
        userPidSet.insert(row.processId);
        const auto found = kernelByPid.find(row.processId);
        if (found != kernelByPid.end()) {
            MergeKernelProcessExtension(row, *found->second);
        }
    }

    for (const KernelProcessSnapshotEntry& kernelProcess : kernelRows) {
        const DWORD processId = static_cast<DWORD>(kernelProcess.processId);
        if (userPidSet.find(processId) != userPidSet.end()) {
            continue;
        }
        rows.push_back(BuildKernelOnlyRow(kernelProcess));
        userPidSet.insert(processId);
        ++result.kernelOnlyCount;
    }

    result.detailText = L"R0隐藏检查: 内核返回 " +
        std::to_wstring(result.kernelEnumeratedCount) +
        L"，疑似隐藏 " +
        std::to_wstring(result.kernelOnlyCount);
    return result;
}

// SourceMaskText renders the process cross-view source matrix. Input is the raw
// sourceMask from R0; processing keeps names aligned with the shared protocol.
std::wstring SourceMaskText(ULONG sourceMask) {
    std::vector<std::wstring> parts;
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0) {
        parts.push_back(L"Public");
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0) {
        parts.push_back(L"ActiveProcessLinks");
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0) {
        parts.push_back(L"CID");
    }
    if (parts.empty()) {
        return L"无来源";
    }

    std::wstring text;
    for (const std::wstring& part : parts) {
        if (!text.empty()) {
            text += L"+";
        }
        text += part;
    }
    return text;
}

// AnomalyMaskText renders known process/thread anomaly bits as evidence labels.
// Input is the raw anomalyFlags mask; output keeps unknown future bits visible.
std::wstring AnomalyMaskText(ULONG anomalyFlags) {
    if (anomalyFlags == 0) {
        return L"未见异常";
    }

    std::vector<std::wstring> parts;
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) != 0) {
        parts.push_back(L"CID-only");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) != 0) {
        parts.push_back(L"Active-only");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) != 0) {
        parts.push_back(L"缺ActiveProcessLinks");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) != 0) {
        parts.push_back(L"缺CID");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH) != 0) {
        parts.push_back(L"PID不一致");
    }

    std::wstring text;
    for (const std::wstring& part : parts) {
        if (!text.empty()) {
            text += L"; ";
        }
        text += part;
    }
    if (text.empty()) {
        text = L"未知异常位 " + FlagHexText(anomalyFlags);
    }
    return text;
}

// ApplyR0ProcessAuditRows annotates R3 process rows with process cross-view
// evidence. Inputs are mutable rows and a status suffix; processing calls only
// ArkDriverClient wrappers and never issues raw DeviceIoControl from the UI.
void ApplyR0ProcessAuditRows(std::vector<ProcessSnapshotRow>& rows, std::wstring& statusSuffix) {
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::ProcessCrossViewResult audit = driverClient.queryProcessCrossView(
        KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
        0,
        0,
        KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES);
    if (!audit.io.ok) {
        statusSuffix = L"；R0审计不可用: " + NarrowToWide(audit.io.message);
        for (ProcessSnapshotRow& row : rows) {
            if (row.r0KernelOnly) {
                row.r0AuditSummary = row.r0AuditSummary.empty() ? L"KernelOnly(Hidden?)" : row.r0AuditSummary;
                if (!row.r0AuditDetail.empty()) {
                    row.r0AuditDetail += L"; CrossView不可用";
                } else {
                    row.r0AuditDetail = audit.unsupported ? L"驱动不支持CrossView" : L"CrossView查询失败";
                }
                continue;
            }
            row.r0AuditSummary = L"不可用";
            row.r0AuditDetail = audit.unsupported ? L"驱动不支持" : L"查询失败";
        }
        return;
    }

    std::unordered_map<DWORD, const ksword::ark::ProcessCrossViewEntry*> auditByPid;
    auditByPid.reserve(audit.entries.size());
    for (const ksword::ark::ProcessCrossViewEntry& entry : audit.entries) {
        auditByPid[static_cast<DWORD>(entry.processId)] = &entry;
    }

    std::size_t matched = 0;
    std::size_t anomalous = 0;
    for (ProcessSnapshotRow& row : rows) {
        const auto found = auditByPid.find(row.processId);
        if (found == auditByPid.end()) {
            if (row.r0KernelOnly) {
                row.r0AuditSummary = row.r0AuditSummary.empty() ? L"KernelOnly(Hidden?)" : row.r0AuditSummary;
                if (!row.r0AuditDetail.empty()) {
                    row.r0AuditDetail += L"; CrossView未返回";
                } else {
                    row.r0AuditDetail = L"仅 R0 枚举返回，CrossView未返回";
                }
                continue;
            }
            row.r0AuditSummary = L"R3-only";
            row.r0AuditDetail = L"R0未返回";
            continue;
        }

        const ksword::ark::ProcessCrossViewEntry& entry = *found->second;
        row.r0ProcessObjectAddress = static_cast<std::uintptr_t>(entry.objectAddress);
        row.r0SourceMask = entry.sourceMask;
        row.r0AnomalyFlags = entry.anomalyFlags;
        row.r0Confidence = entry.confidence;
        row.r0AuditSummary = SourceMaskText(row.r0SourceMask);
        row.r0AuditDetail = AnomalyMaskText(row.r0AnomalyFlags);
        row.r0AuditDetail += L"; conf=" + std::to_wstring(row.r0Confidence);
        if (!entry.detail.empty()) {
            row.r0AuditDetail += L"; " + NarrowToWide(entry.detail);
        }
        ++matched;
        if (row.r0AnomalyFlags != 0) {
            ++anomalous;
        }
    }

    statusSuffix = L"；R0审计匹配 " + std::to_wstring(matched) +
        L"/" + std::to_wstring(rows.size()) +
        L"，异常 " + std::to_wstring(anomalous) +
        L"，返回 " + std::to_wstring(audit.returnedCount) +
        L"/" + std::to_wstring(audit.totalCount);
}

// WriteClipboardText copies Unicode text to the Windows clipboard. Inputs are
// the owner HWND and text. Processing allocates CF_UNICODETEXT global memory and
// transfers ownership to the clipboard. Return value reports success.
bool WriteClipboardText(HWND owner, const std::wstring& text) {
    return Ksword::Ui::CopyTextToClipboard(owner, text, L"进程模块");
}

// DetailDemandForColumns 用途：仅为当前可见深度列请求主程序进程库的额外采集。
std::uint32_t DetailDemandForColumns(const std::vector<ProcessColumnId>& columns) {
    std::uint32_t demand = ks::process::ProcessDetailDemand::None;
    const auto has = [&columns](ProcessColumnId id) { return std::find(columns.begin(), columns.end(), id) != columns.end(); };
    if (has(ProcessColumnId::GpuEngine)) demand |= ks::process::ProcessDetailDemand::GpuEngine;
    if (has(ProcessColumnId::GpuDedicatedMemory) || has(ProcessColumnId::GpuSharedMemory)) demand |= ks::process::ProcessDetailDemand::GpuMemory;
    if (has(ProcessColumnId::PackageName)) demand |= ks::process::ProcessDetailDemand::PackageName;
    if (has(ProcessColumnId::Description)) demand |= ks::process::ProcessDetailDemand::FileDescription;
    if (has(ProcessColumnId::DpiAwareness)) demand |= ks::process::ProcessDetailDemand::DpiAwareness;
    if (has(ProcessColumnId::UacVirtualization)) demand |= ks::process::ProcessDetailDemand::UacVirtualization;
    if (has(ProcessColumnId::DataExecutionPrevention) || has(ProcessColumnId::ControlFlowGuard) || has(ProcessColumnId::HardwareStackProtection)) demand |= ks::process::ProcessDetailDemand::MitigationPolicy;
    if (has(ProcessColumnId::JobObject)) demand |= ks::process::ProcessDetailDemand::JobObject;
    return demand;
}

// ApplyR0KernelColumnDetails 用途：仅在内核列可见时调用 R0 HandleTable 与 SectionObject 查询并回填列表。
void ApplyR0KernelColumnDetails(std::vector<ProcessSnapshotRow>& rows, const std::vector<ProcessColumnId>& columns) {
    const bool needHandleTable = std::find(columns.begin(), columns.end(), ProcessColumnId::HandleTable) != columns.end();
    const bool needSectionObject = std::find(columns.begin(), columns.end(), ProcessColumnId::SectionObject) != columns.end();
    if (!needHandleTable && !needSectionObject) return;

    const ksword::ark::DriverClient driverClient;
    for (ProcessSnapshotRow& row : rows) {
        if (row.processId == 0 || row.r0KernelOnly) continue;
        if (needHandleTable) {
            const ksword::ark::HandleEnumResult handles = driverClient.enumerateProcessHandles(row.processId);
            if (handles.io.ok) {
                row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::HandleTable)] =
                    L"可用：" + std::to_wstring(handles.returnedCount) + L"/" + std::to_wstring(handles.totalCount) + L" 个句柄";
            } else {
                row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::HandleTable)] = L"R0 查询失败";
            }
        }
        if (needSectionObject) {
            const ksword::ark::ProcessSectionQueryResult section = driverClient.queryProcessSection(row.processId);
            if (section.io.ok) {
                wchar_t addressText[32]{};
                ::swprintf_s(addressText, L"0x%016llX", static_cast<unsigned long long>(section.sectionObjectAddress));
                row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::SectionObject)] =
                    section.sectionObjectAddress != 0 ? addressText : L"无 SectionObject";
            } else {
                row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::SectionObject)] = L"R0 查询失败";
            }
        }
    }
}

// ApplyMainProcessDetails 用途：复用 Ksword5.1 已链接的进程库，把真实 R3 深度字段写入 Light 行。
void ApplyMainProcessDetails(std::vector<ProcessSnapshotRow>& rows, const std::vector<ProcessColumnId>& columns) {
    const std::uint32_t demand = DetailDemandForColumns(columns);
    const std::vector<ks::process::ProcessRecord> records = ks::process::EnumerateProcesses(ks::process::ProcessEnumStrategy::Auto, nullptr, demand);
    std::unordered_map<std::uint32_t, const ks::process::ProcessRecord*> byPid;
    for (const ks::process::ProcessRecord& record : records) byPid[record.pid] = &record;
    const auto put = [](ProcessSnapshotRow& row, ProcessColumnId id, const std::wstring& text) { if (!text.empty()) row.detailTexts[static_cast<std::uint8_t>(id)] = text; };
    const bool wantsSignature = std::find(columns.begin(), columns.end(), ProcessColumnId::Signature) != columns.end();
    static std::atomic_size_t signatureCursor{ 0 };
    const std::size_t signatureStart = rows.empty() ? 0 : signatureCursor.fetch_add(24U) % rows.size();
    std::size_t signatureOrdinal = 0;
    for (ProcessSnapshotRow& row : rows) {
        const auto found = byPid.find(row.processId);
        if (found == byPid.end()) continue;
        const ks::process::ProcessRecord& record = *found->second;
        bool verifySignature = false;
        // 静态详情只为需要静态字段的视图采集；签名校验同样在后台完成。
        ks::process::ProcessRecord details{};
        const bool staticNeeded = std::any_of(columns.begin(), columns.end(), [](ProcessColumnId id) {
            return id == ProcessColumnId::Path || id == ProcessColumnId::CommandLine || id == ProcessColumnId::User || id == ProcessColumnId::Signature || id == ProcessColumnId::IsAdmin || id == ProcessColumnId::PplLevel || id == ProcessColumnId::PowerThrottling || id == ProcessColumnId::PackageName || id == ProcessColumnId::Description || id == ProcessColumnId::JobObject || id == ProcessColumnId::UacVirtualization || id == ProcessColumnId::DataExecutionPrevention || id == ProcessColumnId::ControlFlowGuard || id == ProcessColumnId::HardwareStackProtection || id == ProcessColumnId::DpiAwareness;
        });
        if (staticNeeded) {
            // WinVerifyTrust 对受保护或网络路径映像可能长时间阻塞；每轮只验证有限数量，其他行明确标记待验证。
            const std::size_t signatureOffset = rows.empty() ? 0 : (signatureOrdinal++ + rows.size() - signatureStart) % rows.size();
            verifySignature = wantsSignature && signatureOffset < 24U;
            ks::process::QueryProcessStaticDetailByPid(record.pid, details, verifySignature);
            // 这一步实际执行缓解策略、UAC、作业、包名和 DPI 的按需读取，不能只传 demand 给枚举器。
            ks::process::FillProcessOnDemandDetails(details, demand, nullptr);
        }
        const ks::process::ProcessRecord& source = details.staticDetailsReady ? details : record;
        put(row, ProcessColumnId::Path, NarrowToWide(source.imagePath));
        put(row, ProcessColumnId::CommandLine, NarrowToWide(source.commandLine));
        put(row, ProcessColumnId::User, NarrowToWide(source.userName));
        put(row, ProcessColumnId::StartTime, NarrowToWide(record.startTimeText));
        put(row, ProcessColumnId::Signature, wantsSignature && !verifySignature ? L"待验证" : NarrowToWide(source.signatureState));
        put(row, ProcessColumnId::Description, NarrowToWide(source.fileDescription));
        put(row, ProcessColumnId::PackageName, NarrowToWide(source.packageFullName));
        put(row, ProcessColumnId::IsAdmin, source.isAdmin ? L"是" : L"否");
        put(row, ProcessColumnId::PowerThrottling, source.efficiencyModeSupported ? (source.efficiencyModeEnabled ? L"已启用" : L"已禁用") : L"不支持");
        put(row, ProcessColumnId::Status, record.processStateKnown ? (record.processSuspended ? L"已挂起" : L"运行中") : L"未知");
        put(row, ProcessColumnId::GpuEngine, NarrowToWide(record.gpuEngineText));
        put(row, ProcessColumnId::JobObject, source.jobObjectKnown ? (source.inJobObject ? L"是" : L"否") : L"访问受限");
        put(row, ProcessColumnId::UacVirtualization, std::to_wstring(static_cast<unsigned int>(source.uacVirtualizationState)));
        put(row, ProcessColumnId::DataExecutionPrevention, std::to_wstring(static_cast<unsigned int>(source.dataExecutionPreventionState)));
        put(row, ProcessColumnId::ControlFlowGuard, std::to_wstring(static_cast<unsigned int>(source.controlFlowGuardState)));
        put(row, ProcessColumnId::HardwareStackProtection, std::to_wstring(static_cast<unsigned int>(source.hardwareStackProtectionState)));
        put(row, ProcessColumnId::DpiAwareness, std::to_wstring(static_cast<unsigned int>(source.dpiAwarenessLevel)));
        std::uint32_t protectionLevel = 0;
        std::string protectionText;
        if (ks::process::QueryProcessProtectionLevelByPid(record.pid, &protectionLevel, &protectionText, nullptr)) put(row, ProcessColumnId::PplLevel, NarrowToWide(protectionText));
        else put(row, ProcessColumnId::PplLevel, L"访问受限");
        if (record.gpuMemoryKnown) { put(row, ProcessColumnId::GpuDedicatedMemory, FormatByteSize(record.gpuDedicatedMemoryBytes)); put(row, ProcessColumnId::GpuSharedMemory, FormatByteSize(record.gpuSharedMemoryBytes)); }
    }
}

// CollectProcessRefreshSnapshot performs every potentially blocking query for a
// process refresh. It never accesses HWNDs or ProcessViewState and is safe for
// AsyncSnapshotTask's worker thread.
ProcessRefreshSnapshot CollectProcessRefreshSnapshot(const std::vector<ProcessColumnId>& columns) {
    ProcessRefreshSnapshot snapshot{};
    snapshot.enumeration = EnumerateProcessesByNtQuerySystemInformation();
    if (!snapshot.enumeration.success) {
        return snapshot;
    }
    ApplyMainProcessDetails(snapshot.enumeration.rows, columns);
    snapshot.hiddenAudit = ApplyDefaultHiddenProcessAudit(snapshot.enumeration.rows);
    ApplyR0ProcessAuditRows(snapshot.enumeration.rows, snapshot.crossViewStatusSuffix);
    ApplyR0KernelColumnDetails(snapshot.enumeration.rows, columns);
    return snapshot;
}

// ApplyProcessRefresh installs a completed immutable snapshot on the UI thread.
// It records lifecycle differences and commits the owner-data presentation with
// selective ListView invalidation, preserving a stable process-list surface.
void ApplyProcessRefresh(ProcessViewState& state, ProcessRefreshSnapshot snapshot) {
    if (!snapshot.enumeration.success) {
        state.model.setRows({});
        RebuildRows(state);
        SetStatus(state, L"进程枚举失败: " + snapshot.enumeration.diagnosticText);
        return;
    }

    std::vector<ProcessSnapshotRow> rows = std::move(snapshot.enumeration.rows);
    const HiddenProcessAuditResult& hiddenAudit = snapshot.hiddenAudit;
    const ULONGLONG nowMs = ::GetTickCount64();
    const ULONGLONG elapsedMs = state.previousSampleTickMs == 0 ? 0 : nowMs - state.previousSampleTickMs;
    const DWORD processorCount = std::max<DWORD>(1, ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    std::unordered_map<std::wstring, ULONGLONG> newCpuTimes;
    std::unordered_map<std::wstring, ProcessSnapshotRow> activeRowsByIdentity;
    newCpuTimes.reserve(rows.size());
    activeRowsByIdentity.reserve(rows.size());
    const std::unordered_map<std::wstring, ProcessRowVisualState> previousVisualStates =
        std::move(state.visualStateByIdentity);
    state.visualStateByIdentity.clear();
    for (ProcessSnapshotRow& row : rows) {
        const std::wstring identityKey = ProcessStableKey(row.processId, row.creationTime100ns);
        const ULONGLONG total100ns = row.kernelTime100ns + row.userTime100ns;
        // 相邻快照差值只在同一 PID+创建时间实例间计算，避免 PID 回收造成错误增量。
        const auto previousRow = state.lastActiveRowsByIdentity.find(identityKey);
        if (previousRow != state.lastActiveRowsByIdentity.end()) {
            row.workingSetDeltaBytes = static_cast<LONGLONG>(row.workingSetBytes) - static_cast<LONGLONG>(previousRow->second.workingSetBytes);
            row.pageFaultDelta = static_cast<LONGLONG>(row.pageFaultCount) - static_cast<LONGLONG>(previousRow->second.pageFaultCount);
        }
        newCpuTimes[identityKey] = total100ns;
        activeRowsByIdentity[identityKey] = row;
        if (state.hasLastActiveSnapshot &&
            state.lastActiveRowsByIdentity.find(identityKey) == state.lastActiveRowsByIdentity.end()) {
            state.visualStateByIdentity[identityKey] = ProcessRowVisualState::Added;
        }
        row.cpuUsagePercent = 0.0;
        const auto previous = state.previousCpuTime100ns.find(identityKey);
        if (elapsedMs > 0 && previous != state.previousCpuTime100ns.end() && total100ns >= previous->second) {
            const ULONGLONG delta100ns = total100ns - previous->second;
            const double capacity100ns = static_cast<double>(elapsedMs) * 10000.0 * static_cast<double>(processorCount);
            if (capacity100ns > 0.0) {
                row.cpuUsagePercent = std::clamp((static_cast<double>(delta100ns) * 100.0) / capacity100ns, 0.0, 999.9);
            }
        }
    }
    if (state.hasLastActiveSnapshot) {
        for (const auto& oldRow : state.lastActiveRowsByIdentity) {
            if (activeRowsByIdentity.find(oldRow.first) == activeRowsByIdentity.end()) {
                ProcessSnapshotRow removed = oldRow.second;
                removed.cpuUsagePercent = 0.0;
                rows.push_back(removed);
                state.visualStateByIdentity[oldRow.first] = ProcessRowVisualState::Removed;
            }
        }
    }

    const std::size_t activeCount = activeRowsByIdentity.size();
    const std::size_t addedCount = std::count_if(
        state.visualStateByIdentity.begin(),
        state.visualStateByIdentity.end(),
        [](const auto& entry) { return entry.second == ProcessRowVisualState::Added; });
    const std::size_t removedCount = std::count_if(
        state.visualStateByIdentity.begin(),
        state.visualStateByIdentity.end(),
        [](const auto& entry) { return entry.second == ProcessRowVisualState::Removed; });

    state.previousCpuTime100ns = std::move(newCpuTimes);
    state.previousSampleTickMs = nowMs;
    state.lastActiveRowsByIdentity = std::move(activeRowsByIdentity);
    state.hasLastActiveSnapshot = true;

    state.model.setRows(std::move(rows));
    RebuildRows(state, &previousVisualStates);
    SetStatus(state,
        L"已同步 " + std::to_wstring(activeCount) +
        L" 个进程；新增 " + std::to_wstring(addedCount) +
        L"，退出 " + std::to_wstring(removedCount) +
        L" 个进程；刷新 " + std::to_wstring(state.refreshIntervalSeconds) +
        L"s；" + hiddenAudit.detailText + snapshot.crossViewStatusSuffix +
        L"；左 Ctrl 按下时跳过自动刷新。");
}

// BeginProcessRefresh only schedules work and updates lightweight feedback. A
// running request is coalesced by AsyncSnapshotTask so fast timers and manual
// refreshes cannot start concurrent R0/R3 enumeration passes.
void BeginProcessRefresh(ProcessViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    SetStatus(state, state.refreshTask->running() ? L"进程刷新已排队，等待当前快照完成…" : L"正在后台枚举进程与 R0 证据…");
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    const std::vector<ProcessColumnId> requestedColumns = state.activeColumns;
    state.refreshTask->request(
        [requestedColumns]() { return CollectProcessRefreshSnapshot(requestedColumns); },
        [&state](std::uint64_t, std::optional<ProcessRefreshSnapshot>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            if (error || !snapshot.has_value()) {
                SetStatus(state, L"进程刷新任务异常结束。请检查驱动状态和访问权限。");
                return;
            }
            ApplyProcessRefresh(state, std::move(*snapshot));
        });
}

// ApplyPreset 用途：应用内置精简列组；调用后立即重建表头和不可变展示快照。
void ApplyPreset(ProcessViewState& state, ProcessViewPreset preset) {
    state.preset = preset;
    state.activeColumns = DefaultProcessColumns(preset);
    RebuildColumns(state);
    RebuildRows(state);
    UpdateToolbarTexts(state);
    ::PostMessageW(state.hwnd, kMsgRequestRefresh, 0, 0);
    SetStatus(state, std::wstring(L"已切换到") + ProcessViewPresetTitle(preset) + L"列组。");
}

// ToggleColumn 用途：按用户菜单选择显示或隐藏一个逻辑列；名称和 PID 永远保留。
void ToggleColumn(ProcessViewState& state, ProcessColumnId column) {
    const ProcessColumnDescriptor* descriptor = FindProcessColumn(column);
    if (!descriptor || descriptor->locked) return;
    const auto found = std::find(state.activeColumns.begin(), state.activeColumns.end(), column);
    if (found == state.activeColumns.end()) state.activeColumns.push_back(column);
    else state.activeColumns.erase(found);
    state.preset = ProcessViewPreset::Custom;
    RebuildColumns(state);
    RebuildRows(state);
    UpdateToolbarTexts(state);
    ::PostMessageW(state.hwnd, kMsgRequestRefresh, 0, 0);
}

// ColumnChooserState 用途：保存一个临时模态选择列窗口的控件与所属进程页。
struct ColumnChooserState {
    ProcessViewState* owner = nullptr;
    std::vector<HWND> checkBoxes;
};

// ColumnChooserProc 用途：处理选择列模态窗口中的确认、取消和销毁消息。
LRESULT CALLBACK ColumnChooserProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* chooser = reinterpret_cast<ColumnChooserState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        chooser = create ? static_cast<ColumnChooserState*>(create->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(chooser));
    }
    if (!chooser) return ::DefWindowProcW(hwnd, message, wParam, lParam);

    if (message == WM_CREATE) {
        const int columnWidth = 180;
        const int rowHeight = 25;
        for (std::size_t index = 0; index < ProcessColumnDescriptors().size(); ++index) {
            const ProcessColumnDescriptor& descriptor = ProcessColumnDescriptors()[index];
            const int visualColumn = static_cast<int>(index / 20U);
            const int visualRow = static_cast<int>(index % 20U);
            HWND check = ::CreateWindowExW(0, WC_BUTTONW, descriptor.title,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                14 + visualColumn * columnWidth, 42 + visualRow * rowHeight,
                columnWidth - 8, rowHeight, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(100 + index)),
                ::GetModuleHandleW(nullptr), nullptr);
            if (check) {
                const bool visible = std::find(chooser->owner->activeColumns.begin(), chooser->owner->activeColumns.end(), descriptor.id) != chooser->owner->activeColumns.end();
                ::SendMessageW(check, BM_SETCHECK, visible ? BST_CHECKED : BST_UNCHECKED, 0);
                ::EnableWindow(check, !descriptor.locked);
                chooser->checkBoxes.push_back(check);
            }
        }
        Ksword::Ui::CreateButton(hwnd, kColumnChooserApplyId, L"应用", 380, 555, 86, 28);
        Ksword::Ui::CreateButton(hwnd, kColumnChooserCancelId, L"取消", 474, 555, 86, 28);
        Ksword::Ui::CreateText(hwnd, 0, L"选择需要显示的列；名称与 PID 是固定标识列。", 14, 12, 540, 22);
        return 0;
    }
    if (message == WM_COMMAND) {
        const int id = LOWORD(wParam);
        if (id == kColumnChooserApplyId) {
            std::vector<ProcessColumnId> selected;
            for (std::size_t index = 0; index < chooser->checkBoxes.size() && index < ProcessColumnDescriptors().size(); ++index) {
                if (::SendMessageW(chooser->checkBoxes[index], BM_GETCHECK, 0, 0) == BST_CHECKED) selected.push_back(ProcessColumnDescriptors()[index].id);
            }
            chooser->owner->activeColumns = std::move(selected);
            chooser->owner->preset = ProcessViewPreset::Custom;
            RebuildColumns(*chooser->owner);
            RebuildRows(*chooser->owner);
            UpdateToolbarTexts(*chooser->owner);
            ::PostMessageW(chooser->owner->hwnd, kMsgRequestRefresh, 0, 0);
            ::DestroyWindow(hwnd);
            return 0;
        }
        if (id == kColumnChooserCancelId) { ::DestroyWindow(hwnd); return 0; }
    }
    if (message == WM_CLOSE) { ::DestroyWindow(hwnd); return 0; }
    if (message == WM_NCDESTROY) { ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0); return 0; }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

// ShowColumnChooser 用途：创建应用模态复选框窗口；列布局只写回当前 ProcessViewState。
void ShowColumnChooser(ProcessViewState& state) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSW windowClass{};
        windowClass.lpfnWndProc = ColumnChooserProc;
        windowClass.hInstance = ::GetModuleHandleW(nullptr);
        windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
        windowClass.lpszClassName = kColumnChooserClass;
        registered = ::RegisterClassW(&windowClass) != FALSE || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    }
    if (!registered) return;
    ColumnChooserState chooser{ &state, {} };
    HWND dialog = ::CreateWindowExW(WS_EX_DLGMODALFRAME, kColumnChooserClass, L"选择列",
        WS_CAPTION | WS_SYSMENU | WS_POPUP | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 575, 625, state.hwnd, nullptr, ::GetModuleHandleW(nullptr), &chooser);
    if (!dialog) return;
    ::EnableWindow(state.hwnd, FALSE);
    MSG message{};
    while (::IsWindow(dialog) && ::GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!::IsDialogMessageW(dialog, &message)) { ::TranslateMessage(&message); ::DispatchMessageW(&message); }
    }
    ::EnableWindow(state.hwnd, TRUE);
    ::SetForegroundWindow(state.hwnd);
}

// ShowColumnMenu 用途：显示按分组组织的运行期列选择菜单；同一入口供工具栏和表头右键复用。
void ShowColumnMenu(ProcessViewState& state, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) return;
    std::size_t menuIndex = 0;
    for (ProcessColumnGroup group : { ProcessColumnGroup::General, ProcessColumnGroup::Performance, ProcessColumnGroup::Memory, ProcessColumnGroup::Io, ProcessColumnGroup::Security, ProcessColumnGroup::Kernel }) {
        HMENU groupMenu = ::CreatePopupMenu();
        for (const ProcessColumnDescriptor& descriptor : ProcessColumnDescriptors()) {
            if (descriptor.group != group) continue;
            const bool visible = std::find(state.activeColumns.begin(), state.activeColumns.end(), descriptor.id) != state.activeColumns.end();
            const UINT flags = MF_STRING | (visible ? MF_CHECKED : MF_UNCHECKED) | (descriptor.locked ? MF_GRAYED : 0U);
            ::AppendMenuW(groupMenu, flags, kColumnMenuBaseId + static_cast<UINT>(menuIndex), descriptor.title);
            ++menuIndex;
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(groupMenu), ProcessColumnGroupTitle(group));
    }
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kColumnMenuBaseId + 1000, L"恢复当前预设默认列");
    const UINT command = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (command == kColumnMenuBaseId + 1000) { ApplyPreset(state, state.preset == ProcessViewPreset::Custom ? ProcessViewPreset::Monitor : state.preset); return; }
    if (command >= kColumnMenuBaseId && command < kColumnMenuBaseId + ProcessColumnDescriptors().size()) ToggleColumn(state, ProcessColumnDescriptors()[command - kColumnMenuBaseId].id);
}

// ToggleRefreshPaused flips automatic refresh. Input is the page state;
// processing updates the toolbar and status; no value is returned.
void ToggleRefreshPaused(ProcessViewState& state) {
    state.refreshPaused = !state.refreshPaused;
    UpdateToolbarTexts(state);
    SetStatus(state, state.refreshPaused ? L"自动刷新已暂停。" : L"自动刷新已恢复。");
}

// SelectPid highlights all visible rows matching one PID. Inputs are page state
// and PID. Processing clears existing selection then selects/focuses the first
// matching row. Return value reports whether a visible row was found.
bool SelectPid(ProcessViewState& state, DWORD pid) {
    if (!state.listView) {
        return false;
    }

    ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    bool found = false;
    for (int item = 0; item < ListView_GetItemCount(state.listView); ++item) {
        const int displayIndex = DisplayIndexFromListItem(state, item);
        if (displayIndex < 0 || static_cast<std::size_t>(displayIndex) >= state.presentationRows.size()) {
            continue;
        }
        if (state.presentationRows[static_cast<std::size_t>(displayIndex)].processId == pid) {
            ListView_SetItemState(state.listView, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(state.listView, item, FALSE);
            found = true;
        }
    }
    return found;
}

// BeginPicker starts the drag-select interaction. Input is page state; processing
// captures the mouse to the page and changes the cursor prompt. The selected PID
// is resolved later from WindowFromPoint on mouse release; no value is returned.
void BeginPicker(ProcessViewState& state) {
    state.pickingWindow = true;
    ::SetCapture(state.hwnd);
    ::SetCursor(::LoadCursorW(nullptr, IDC_CROSS));
    SetStatus(state, L"拖动到目标窗口后释放鼠标，将根据窗口 HWND 选中对应进程。");
}

// CompletePicker ends drag-select. Input is page state. Processing reads the
// current cursor position, resolves the window PID with GetWindowThreadProcessId,
// selects a matching row, and updates status. No value is returned.
void CompletePicker(ProcessViewState& state) {
    state.pickingWindow = false;
    if (::GetCapture() == state.hwnd) {
        ::ReleaseCapture();
    }

    POINT point{};
    ::GetCursorPos(&point);
    HWND target = ::WindowFromPoint(point);
    DWORD pid = 0;
    if (target) {
        ::GetWindowThreadProcessId(target, &pid);
    }

    if (pid != 0 && SelectPid(state, pid)) {
        SetStatus(state, L"已通过窗口拖选定位 PID " + std::to_wstring(pid) + L"。");
    } else if (pid != 0) {
        SetStatus(state, L"窗口属于 PID " + std::to_wstring(pid) + L"，但当前列表中未找到可见行。请刷新后重试。");
    } else {
        SetStatus(state, L"未能从释放位置解析窗口进程。");
    }
}

// IsReadOnlyProcessAction identifies operations that do not alter the process
// snapshot. It lets action completion refresh after a mutation (including a
// partially successful multi-PID action) without needlessly rebuilding the list
// after Explorer, clipboard or diagnostic-only operations.
bool IsReadOnlyProcessAction(const ProcessActionId actionId) {
    switch (actionId) {
    case ProcessActionId::OpenFolder:
    case ProcessActionId::OpenMemoryOperation:
    case ProcessActionId::ScanHotkeys:
        return true;
    default:
        return false;
    }
}

// BeginProcessAction captures the current selection and model snapshot on the
// UI thread, then executes Win32/R0 work away from it. AsyncSnapshotTask drops
// stale completions and cancels delivery when the page closes, so a slow driver
// request cannot freeze or resurrect a closed dock.
void BeginProcessAction(
    ProcessViewState& state,
    const ProcessActionId actionId,
    std::vector<DWORD> selectedPids,
    std::vector<ProcessSnapshotRow> snapshotRows,
    std::wstring workingText) {
    if (!state.actionTask) {
        SetStatus(state, L"进程操作任务不可用。");
        return;
    }
    if (state.actionTask->running()) {
        SetStatus(state, L"另一个进程操作正在后台执行，请等待完成。");
        return;
    }

    SetStatus(state, std::move(workingText));
    state.actionTask->request(
        [actionId, selectedPids = std::move(selectedPids), snapshotRows = std::move(snapshotRows)]() mutable {
            ProcessViewActionResult completed{};
            completed.result = ExecuteProcessAction(actionId, selectedPids, snapshotRows);
            completed.refreshRequired = !IsReadOnlyProcessAction(actionId);
            return completed;
        },
        [&state](std::uint64_t, std::optional<ProcessViewActionResult>&& completed, std::exception_ptr error) {
            if (error || !completed.has_value()) {
                SetStatus(state, L"后台进程操作异常结束。");
                return;
            }

            SetStatus(state, completed->result.title + L": " + completed->result.detail);
            if (!completed->result.success) {
                ::MessageBoxW(
                    state.hwnd,
                    completed->result.detail.c_str(),
                    completed->result.title.c_str(),
                    MB_OK | MB_ICONINFORMATION);
            }
            if (completed->refreshRequired) {
                BeginProcessRefresh(state);
            }
        });
}

// BeginR0Injection captures the approved payload path and target PID before
// moving file I/O and the driver request to the action worker.
void BeginR0Injection(
    ProcessViewState& state,
    const bool dllMode,
    std::vector<DWORD> selectedPids,
    std::vector<ProcessSnapshotRow> snapshotRows,
    std::wstring payloadPath) {
    if (!state.actionTask) {
        SetStatus(state, L"R0 注入任务不可用。");
        return;
    }
    if (state.actionTask->running()) {
        SetStatus(state, L"另一个进程操作正在后台执行，请等待完成。");
        return;
    }

    SetStatus(state, dllMode ? L"正在后台执行 R0 DLL 注入…" : L"正在后台读取并执行 R0 Shellcode 注入…");
    state.actionTask->request(
        [dllMode, selectedPids = std::move(selectedPids), snapshotRows = std::move(snapshotRows), payloadPath = std::move(payloadPath)]() mutable {
            ProcessViewActionResult completed{};
            completed.result = dllMode
                ? ExecuteR0ProcessDllInjection(selectedPids, snapshotRows, payloadPath)
                : ExecuteR0ProcessShellcodeInjection(selectedPids, snapshotRows, payloadPath);
            completed.refreshRequired = true;
            return completed;
        },
        [&state](std::uint64_t, std::optional<ProcessViewActionResult>&& completed, std::exception_ptr error) {
            if (error || !completed.has_value()) {
                SetStatus(state, L"后台 R0 注入异常结束。");
                return;
            }

            SetStatus(state, completed->result.title + L": " + completed->result.detail);
            if (!completed->result.success) {
                ::MessageBoxW(
                    state.hwnd,
                    completed->result.detail.c_str(),
                    completed->result.title.c_str(),
                    MB_OK | MB_ICONINFORMATION);
            }
            BeginProcessRefresh(state);
        });
}

// ExecuteMenuItem handles one context-menu command. Inputs are page state and an
// action id. UI-local copy and page creation remain immediate; blocking Win32,
// R0 and file operations are queued through BeginProcessAction.
void ExecuteMenuItem(ProcessViewState& state, ProcessActionId actionId) {
    if (actionId == ProcessActionId::CopyCell || actionId == ProcessActionId::CopyRow ||
        actionId == ProcessActionId::CopyVisibleResults || actionId == ProcessActionId::ExportVisibleResults) {
        if (actionId == ProcessActionId::ExportVisibleResults) {
            ExportVisibleResults(state);
            return;
        }
        if (actionId == ProcessActionId::CopyVisibleResults) {
            const bool copied = WriteClipboardText(state.hwnd, VisibleRowsAsText(state));
            SetStatus(state, copied ? L"已复制全部可见进程结果。" : L"复制失败：当前没有可见结果或剪贴板不可用。");
            return;
        }
        const bool allColumns = actionId == ProcessActionId::CopyRow;
        const std::wstring text = SelectedRowsAsText(state, allColumns);
        const bool copied = WriteClipboardText(state.hwnd, text);
        SetStatus(state, copied ? L"已复制选中进程行文本。" : L"复制失败：没有可复制的选中行或剪贴板不可用。");
        return;
    }

    if (actionId == ProcessActionId::OpenDetails) {
        const std::vector<int> selectedIndexes = SelectedDisplayIndexes(state);
        if (selectedIndexes.size() != 1U ||
            selectedIndexes.front() < 0 ||
            static_cast<std::size_t>(selectedIndexes.front()) >= state.presentationRows.size()) {
            SetStatus(state, L"进程详细信息需要单选一个进程。");
            return;
        }
        const ProcessPresentationRow& selectedRow =
            state.presentationRows[static_cast<std::size_t>(selectedIndexes.front())];
        const bool opened = OpenProcessDetailWindow(
            state.hwnd,
            selectedRow.processId,
            selectedRow.creationTime100ns);
        SetStatus(state, opened ? L"已打开进程详细信息窗口。" : L"进程详细信息窗口创建失败。");
        return;
    }

    if (actionId == ProcessActionId::OpenMemoryOperation ||
        actionId == ProcessActionId::OpenImageInFileModule ||
        actionId == ProcessActionId::OpenNetworkForProcess ||
        actionId == ProcessActionId::OpenHandlesForProcess ||
        actionId == ProcessActionId::OpenEtwForProcess ||
        actionId == ProcessActionId::OpenWindowsForProcess) {
        const std::vector<int> selectedIndexes = SelectedDisplayIndexes(state);
        if (selectedIndexes.size() != 1U || selectedIndexes.front() < 0 ||
            static_cast<std::size_t>(selectedIndexes.front()) >= state.presentationRows.size()) {
            SetStatus(state, L"关联调查需要单选一个进程。");
            return;
        }
        const ProcessPresentationRow& selectedRow =
            state.presentationRows[static_cast<std::size_t>(selectedIndexes.front())];
        Ksword::Core::NavigationRequest request{};
        request.entity.kind = Ksword::Core::EntityKind::Process;
        request.entity.id = selectedRow.processId;
        request.entity.creationTime100ns = selectedRow.creationTime100ns;
        switch (actionId) {
        case ProcessActionId::OpenMemoryOperation:
            request.target = Ksword::Core::NavigationTarget::MemoryOperations;
            break;
        case ProcessActionId::OpenImageInFileModule:
            if (selectedRow.iconPath.empty()) {
                SetStatus(state, L"该进程没有可用的映像路径。");
                return;
            }
            request.target = Ksword::Core::NavigationTarget::FileBrowser;
            request.entity.kind = Ksword::Core::EntityKind::File;
            request.entity.text = selectedRow.iconPath;
            break;
        case ProcessActionId::OpenNetworkForProcess:
            request.target = Ksword::Core::NavigationTarget::NetworkConnections;
            break;
        case ProcessActionId::OpenHandlesForProcess:
            request.target = Ksword::Core::NavigationTarget::HandleTable;
            break;
        case ProcessActionId::OpenEtwForProcess:
            request.target = Ksword::Core::NavigationTarget::EtwMonitor;
            break;
        case ProcessActionId::OpenWindowsForProcess:
            request.target = Ksword::Core::NavigationTarget::WindowManager;
            break;
        default:
            return;
        }
        const bool routed = Ksword::Ui::RequestEntityNavigation(state.hwnd, request);
        SetStatus(state, routed ? L"已跳转到关联调查模块。" : L"关联调查模块当前无法接收该实体。");
        return;
    }

    if (actionId == ProcessActionId::R0InjectDll || actionId == ProcessActionId::R0InjectShellcode) {
        const std::vector<DWORD> pids = SelectedPids(state);
        if (pids.size() != 1) {
            SetStatus(state, L"R0 注入需要单选一个进程。");
            return;
        }

        const bool dllMode = actionId == ProcessActionId::R0InjectDll;
        const std::wstring payloadPath = PromptOpenPayloadFile(
            state.hwnd,
            dllMode ? L"DLL 文件 (*.dll)\0*.dll\0所有文件 (*.*)\0*.*\0" : L"Shellcode/二进制文件 (*.*)\0*.*\0",
            dllMode ? L"选择要注入的 DLL" : L"选择要注入的 Shellcode 二进制文件");
        if (payloadPath.empty()) {
            SetStatus(state, L"已取消 R0 注入。");
            return;
        }
        if (!ConfirmR0Injection(state.hwnd, dllMode ? L"DLL 注入" : L"Shellcode 注入", pids.front(), payloadPath)) {
            SetStatus(state, L"用户取消 R0 注入。");
            return;
        }

        BeginR0Injection(state, dllMode, pids, state.model.rows(), payloadPath);
        return;
    }

    BeginProcessAction(
        state,
        actionId,
        SelectedPids(state),
        state.model.rows(),
        L"正在后台执行进程操作…");
}

// ShowContextMenu builds and displays the grouped process context menu. Inputs are
// page state and screen coordinates. Processing folds related operations into
// submenus so the full retained ProcessDock action surface stays usable without
// a long root menu; selected command ids are mapped back to ProcessActionId.
void ShowContextMenu(ProcessViewState& state, POINT screenPoint) {
    const std::vector<DWORD> pids = SelectedPids(state);
    const bool hasVisibleSelection = !SelectedDisplayIndexes(state).empty();
    const bool hasProcessSelection = !pids.empty();
    const bool singleProcess = pids.size() == 1;
    const bool actionRunning = state.actionTask && state.actionTask->running();
    state.activeMenuItems.clear();

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }

    auto appendAction = [&](HMENU parent, ProcessActionId id, const wchar_t* text, bool enabled) {
        state.activeMenuItems.push_back(ProcessActionMenuItem{ id, text });
        const UINT command = kContextMenuBaseId + static_cast<UINT>(state.activeMenuItems.size() - 1);
        const bool immediateAction = id == ProcessActionId::CopyCell ||
            id == ProcessActionId::CopyRow ||
            id == ProcessActionId::CopyVisibleResults ||
            id == ProcessActionId::ExportVisibleResults ||
            id == ProcessActionId::OpenDetails ||
            id == ProcessActionId::OpenMemoryOperation ||
            id == ProcessActionId::OpenImageInFileModule ||
            id == ProcessActionId::OpenNetworkForProcess ||
            id == ProcessActionId::OpenHandlesForProcess ||
            id == ProcessActionId::OpenEtwForProcess ||
            id == ProcessActionId::OpenWindowsForProcess;
        ::AppendMenuW(parent, MF_STRING | (enabled && (!actionRunning || immediateAction) ? 0U : MF_GRAYED), command, text);
    };
    auto appendPopup = [](HMENU parent, HMENU child, const wchar_t* text) {
        ::AppendMenuW(parent, MF_POPUP, reinterpret_cast<UINT_PTR>(child), text);
    };

    HMENU copyMenu = ::CreatePopupMenu();
    appendAction(copyMenu, ProcessActionId::CopyCell, L"复制单元格", hasVisibleSelection);
    appendAction(copyMenu, ProcessActionId::CopyRow, L"复制行", hasVisibleSelection);
    appendAction(copyMenu, ProcessActionId::CopyVisibleResults, L"复制可见结果", !state.visibleRowIndexes.empty());
    appendPopup(menu, copyMenu, L"复制");

    HMENU exportMenu = ::CreatePopupMenu();
    appendAction(exportMenu, ProcessActionId::ExportVisibleResults, L"导出可见结果为 TSV...", !state.visibleRowIndexes.empty());
    appendPopup(menu, exportMenu, L"导出");

    HMENU processMenu = ::CreatePopupMenu();
    appendAction(processMenu, ProcessActionId::OpenDetails, L"进程详细信息", singleProcess);
    appendAction(processMenu, ProcessActionId::TerminateProcessMultiMethod, L"结束进程(组合方法链)", hasProcessSelection);
    appendAction(processMenu, ProcessActionId::TerminateProcessTree, L"结束进程树", hasProcessSelection);
    appendAction(processMenu, ProcessActionId::SuspendProcess, L"挂起进程", hasProcessSelection);
    appendAction(processMenu, ProcessActionId::ResumeProcess, L"恢复进程", hasProcessSelection);
    appendAction(processMenu, ProcessActionId::OpenFolder, L"打开所在目录", singleProcess);
    appendAction(processMenu, ProcessActionId::OpenMemoryOperation, L"跳转到内存操作", singleProcess);
    appendAction(processMenu, ProcessActionId::ScanHotkeys, L"扫描进程热键", singleProcess);

    HMENU efficiencyMenu = ::CreatePopupMenu();
    appendAction(efficiencyMenu, ProcessActionId::EnableEfficiencyMode, L"开启效率模式", hasProcessSelection);
    appendAction(efficiencyMenu, ProcessActionId::DisableEfficiencyMode, L"关闭效率模式", hasProcessSelection);
    appendPopup(processMenu, efficiencyMenu, L"效率模式");

    HMENU criticalMenu = ::CreatePopupMenu();
    appendAction(criticalMenu, ProcessActionId::SetCriticalProcess, L"设为关键进程", hasProcessSelection);
    appendAction(criticalMenu, ProcessActionId::ClearCriticalProcess, L"取消关键进程", hasProcessSelection);
    appendPopup(processMenu, criticalMenu, L"关键进程");

    HMENU priorityMenu = ::CreatePopupMenu();
    appendAction(priorityMenu, ProcessActionId::SetPriorityIdle, L"Idle", hasProcessSelection);
    appendAction(priorityMenu, ProcessActionId::SetPriorityBelowNormal, L"Below Normal", hasProcessSelection);
    appendAction(priorityMenu, ProcessActionId::SetPriorityNormal, L"Normal", hasProcessSelection);
    appendAction(priorityMenu, ProcessActionId::SetPriorityAboveNormal, L"Above Normal", hasProcessSelection);
    appendAction(priorityMenu, ProcessActionId::SetPriorityHigh, L"High", hasProcessSelection);
    appendAction(priorityMenu, ProcessActionId::SetPriorityRealtime, L"Realtime", hasProcessSelection);
    appendPopup(processMenu, priorityMenu, L"优先级");
    appendPopup(menu, processMenu, L"进程");

    HMENU investigationMenu = ::CreatePopupMenu();
    appendAction(investigationMenu, ProcessActionId::OpenImageInFileModule, L"在文件模块定位映像", singleProcess);
    appendAction(investigationMenu, ProcessActionId::OpenNetworkForProcess, L"查看关联网络连接", singleProcess);
    appendAction(investigationMenu, ProcessActionId::OpenHandlesForProcess, L"查看进程句柄", singleProcess);
    appendAction(investigationMenu, ProcessActionId::OpenEtwForProcess, L"筛选 ETW 事件", singleProcess);
    appendAction(investigationMenu, ProcessActionId::OpenWindowsForProcess, L"查看进程窗口", singleProcess);
    appendPopup(menu, investigationMenu, L"关联调查");

    HMENU r0Menu = ::CreatePopupMenu();
    appendAction(r0Menu, ProcessActionId::R0TerminateProcess, L"R0结束进程", hasProcessSelection);
    appendAction(r0Menu, ProcessActionId::R0TerminateProcessTree, L"R0结束进程树", hasProcessSelection);
    appendAction(r0Menu, ProcessActionId::R0SuspendProcess, L"R0挂起进程", hasProcessSelection);
    appendAction(r0Menu, ProcessActionId::RefreshPplProtectionLevel, L"刷新PPL保护级别", hasProcessSelection);

    HMENU pplMenu = ::CreatePopupMenu();
    appendAction(pplMenu, ProcessActionId::R0SetPplNone, L"关闭进程保护 (0x00)", hasProcessSelection);
    appendAction(pplMenu, ProcessActionId::R0SetPplAuthenticode, L"Authenticode (0x11)", hasProcessSelection);
    appendAction(pplMenu, ProcessActionId::R0SetPplCodeGen, L"CodeGen (0x21)", hasProcessSelection);
    appendAction(pplMenu, ProcessActionId::R0SetPplAntimalware, L"Antimalware (0x31)", hasProcessSelection);
    appendAction(pplMenu, ProcessActionId::R0SetPplLsa, L"Lsa (0x41)", hasProcessSelection);
    appendAction(pplMenu, ProcessActionId::R0SetPplWindows, L"Windows (0x51)", hasProcessSelection);
    appendAction(pplMenu, ProcessActionId::R0SetPplWinTcb, L"WinTcb (0x61)", hasProcessSelection);
    appendPopup(r0Menu, pplMenu, L"设置PPL(轻量)");

    // 完整 PP 比同 signer 的 PPL 更强：PPL 进程也拿不到 PP 进程的高权限句柄。
    HMENU ppMenu = ::CreatePopupMenu();
    appendAction(ppMenu, ProcessActionId::R0SetPpAuthenticode, L"Authenticode (0x12)", hasProcessSelection);
    appendAction(ppMenu, ProcessActionId::R0SetPpCodeGen, L"CodeGen (0x22)", hasProcessSelection);
    appendAction(ppMenu, ProcessActionId::R0SetPpAntimalware, L"Antimalware (0x32)", hasProcessSelection);
    appendAction(ppMenu, ProcessActionId::R0SetPpLsa, L"Lsa (0x42)", hasProcessSelection);
    appendAction(ppMenu, ProcessActionId::R0SetPpWindows, L"Windows (0x52)", hasProcessSelection);
    appendAction(ppMenu, ProcessActionId::R0SetPpWinTcb, L"WinTcb (0x62)", hasProcessSelection);
    appendPopup(r0Menu, ppMenu, L"设置PP(完整)");

    HMENU integrityMenu = ::CreatePopupMenu();
    appendAction(integrityMenu, ProcessActionId::R0SetIntegrityUntrusted, L"Untrusted (S-1-16-0)", hasProcessSelection);
    appendAction(integrityMenu, ProcessActionId::R0SetIntegrityLow, L"Low (S-1-16-4096)", hasProcessSelection);
    appendAction(integrityMenu, ProcessActionId::R0SetIntegrityMedium, L"Medium (S-1-16-8192)", hasProcessSelection);
    appendAction(integrityMenu, ProcessActionId::R0SetIntegrityMediumPlus, L"Medium Plus (S-1-16-8448)", hasProcessSelection);
    appendAction(integrityMenu, ProcessActionId::R0SetIntegrityHigh, L"High (S-1-16-12288)", hasProcessSelection);
    appendAction(integrityMenu, ProcessActionId::R0SetIntegritySystem, L"System (S-1-16-16384)", hasProcessSelection);
    appendPopup(r0Menu, integrityMenu, L"设置完整性");

    HMENU hideMenu = ::CreatePopupMenu();
    appendAction(hideMenu, ProcessActionId::R0HideUnlinkOnly, L"只断链", hasProcessSelection);
    appendAction(hideMenu, ProcessActionId::R0HidePatchPidOnly, L"只改PID", hasProcessSelection);
    appendAction(hideMenu, ProcessActionId::R0HideLegacyBoth, L"改PID+断链(旧版高风险)", hasProcessSelection);
    appendAction(hideMenu, ProcessActionId::R0UnhideProcess, L"取消隐藏选中进程", hasProcessSelection);
    appendAction(hideMenu, ProcessActionId::R0ClearHiddenMarks, L"清空全部隐藏标记", true);
    appendPopup(r0Menu, hideMenu, L"进程隐藏");

    HMENU specialMenu = ::CreatePopupMenu();
    appendAction(specialMenu, ProcessActionId::R0EnableBreakOnTermination, L"启用 BreakOnTermination", hasProcessSelection);
    appendAction(specialMenu, ProcessActionId::R0DisableBreakOnTermination, L"关闭 BreakOnTermination", hasProcessSelection);
    appendAction(specialMenu, ProcessActionId::R0DisableApcInsertion, L"禁止APC插入(现有线程)", hasProcessSelection);
    appendAction(specialMenu, ProcessActionId::R0DkomRemoveFromCidTable, L"DKOM从PspCidTable删除", hasProcessSelection);
    appendPopup(r0Menu, specialMenu, L"特殊/DKOM");

    HMENU injectMenu = ::CreatePopupMenu();
    appendAction(injectMenu, ProcessActionId::R0InjectDll, L"DLL 注入...", singleProcess);
    appendAction(injectMenu, ProcessActionId::R0InjectShellcode, L"Shellcode 注入...", singleProcess);
    appendPopup(r0Menu, injectMenu, L"注入(需确认)");
    appendPopup(menu, r0Menu, L"R0");

    if (!hasVisibleSelection && !hasProcessSelection) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_GRAYED, 0, L"未选择进程");
    }

    const UINT command = ::TrackPopupMenu(menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        state.hwnd,
        nullptr);
    ::DestroyMenu(menu);

    if (command >= kContextMenuBaseId) {
        const std::size_t index = static_cast<std::size_t>(command - kContextMenuBaseId);
        if (index < state.activeMenuItems.size()) {
            ExecuteMenuItem(state, state.activeMenuItems[index].id);
        }
    }
}

// CreateChildControls creates toolbar buttons, status text and the ListView.
// Input is state with hwnd set. Processing also attaches the image list and
// inserts initial columns. No value is returned; missing HWNDs are tolerated by
// later null checks.
void CreateChildControls(ProcessViewState& state) {
    state.refreshButton = Ksword::Ui::CreateButton(state.hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.pauseButton = Ksword::Ui::CreateButton(state.hwnd, kPauseButtonId, L"暂停", 0, 0, 0, 0);
    state.presetCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPresetComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (state.presetCombo) {
        ::SendMessageW(state.presetCombo, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
        for (ProcessViewPreset preset : { ProcessViewPreset::Monitor, ProcessViewPreset::Detail, ProcessViewPreset::Memory, ProcessViewPreset::DiskIo, ProcessViewPreset::Gpu, ProcessViewPreset::Security, ProcessViewPreset::Kernel }) {
            const LRESULT item = ::SendMessageW(state.presetCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(ProcessViewPresetTitle(preset)));
            ::SendMessageW(state.presetCombo, CB_SETITEMDATA, item, static_cast<LPARAM>(preset));
        }
        ::SendMessageW(state.presetCombo, CB_SETCURSEL, 0, 0);
    }
    state.columnsButton = Ksword::Ui::CreateButton(state.hwnd, kColumnsButtonId, L"列", 0, 0, 0, 0);
    state.pickerButton = Ksword::Ui::CreateButton(state.hwnd, kPickerButtonId, L"拖动选中进程", 0, 0, 0, 0);
    state.refreshSlider = ::CreateWindowExW(0,
        TRACKBAR_CLASSW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | TBS_AUTOTICKS | TBS_TOOLTIPS,
        0,
        0,
        0,
        0,
        state.hwnd,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kRefreshSliderId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (state.refreshSlider) {
        ::SendMessageW(state.refreshSlider, TBM_SETRANGE, TRUE, MAKELPARAM(1, 10));
        ::SendMessageW(state.refreshSlider, TBM_SETTICFREQ, 1, 0);
        ::SendMessageW(state.refreshSlider, TBM_SETPOS, TRUE, state.refreshIntervalSeconds);
    }
    state.statusText = Ksword::Ui::CreateText(state.hwnd, kStatusTextId, L"准备枚举进程。", 0, 0, 0, 0);
    state.filterBar = Ksword::Ui::CreateFilterBar(state.hwnd, kFilterBarId, L"筛选进程、PID、路径和 R0 证据", 0, 0, 0, 0);
    state.listView = CreateProcessListView(state.hwnd, kProcessListId);
    state.imageList = CreateIconList();
    if (state.listView && state.imageList) {
        ListView_SetImageList(state.listView, state.imageList, LVSIL_SMALL);
    }
    UpdateToolbarTexts(state);
    RebuildColumns(state);
}

// HandleListNotify processes ListView notifications. Inputs are page state and
// NMHDR. Processing supports custom first-column drawing, right-click selection
// correction and context menus; output carries both handled state and LRESULT.
NotifyResult HandleListNotify(ProcessViewState& state, NMHDR* header) {
    if (!header) {
        return {};
    }

    // 表头右键与工具栏“列”按钮共享同一分组列菜单，避免两套显隐状态分叉。
    if (header->hwndFrom == ListView_GetHeader(state.listView)) {
        if (header->code == NM_RCLICK) {
            ShowColumnChooser(state);
            return { true, 0 };
        }
        return {};
    }
    if (header->hwndFrom != state.listView) return {};

    if (header->code == LVN_GETDISPINFOW) {
        return { true, HandleVirtualListDisplayInfo(state, reinterpret_cast<NMLVDISPINFOW*>(header)) };
    }

    if (header->code == NM_CUSTOMDRAW) {
        return { true, HandleListCustomDraw(state, reinterpret_cast<NMLVCUSTOMDRAW*>(header)) };
    }

    if (header->code == NM_RCLICK) {
        POINT screenPoint{};
        ::GetCursorPos(&screenPoint);
        POINT clientPoint = screenPoint;
        ::ScreenToClient(state.listView, &clientPoint);

        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        const int item = ListView_HitTest(state.listView, &hit);
        if (GroupHeaderAtListItem(state, item)) {
            return { true, 0 };
        }
        if (item >= 0 && (ListView_GetItemState(state.listView, item, LVIS_SELECTED) & LVIS_SELECTED) == 0) {
            ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(state.listView, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        }
        ShowContextMenu(state, screenPoint);
        return { true, 0 };
    }

    if (header->code == NM_CLICK || header->code == NM_DBLCLK) {
        const auto* activate = reinterpret_cast<const NMITEMACTIVATE*>(header);
        if (!activate || activate->iItem < 0) {
            return {};
        }
        const ProcessPresentationRow* group = GroupHeaderAtListItem(state, activate->iItem);
        if (group) {
            const ProcessFriendlyGroup groupId = group->display.group;
            state.model.toggleGroupCollapsed(groupId);
            RebuildRows(state);
            SetStatus(state, state.model.isGroupCollapsed(groupId) ? L"已折叠进程分组。" : L"已展开进程分组。");
            return { true, 0 };
        }
    }

    return {};
}

// ProcessViewWndProc dispatches page messages. Inputs are standard Win32 window
// procedure parameters. Processing owns state lifetime, child layout, refresh,
// view switching, drag-picker completion and context menus. Output is an LRESULT
// compatible with DefWindowProcW.
LRESULT CALLBACK ProcessViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_NCCREATE) {
        auto state = std::make_unique<ProcessViewState>();
        state->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state.release()));
    }

    ProcessViewState* state = StateFromWindow(hwnd);
    switch (msg) {
    case WM_CREATE:
        if (state) {
            CreateChildControls(*state);
            state->refreshTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ProcessRefreshSnapshot>>(hwnd, kMsgRefreshCompleted);
            state->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ProcessFilterResult>>(hwnd, kMsgFilterCompleted);
            state->actionTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ProcessViewActionResult>>(hwnd, kMsgActionCompleted);
            SetStatus(*state, L"进程页已创建，等待首次异步刷新。");
            ::PostMessageW(hwnd, kMsgInitialRefresh, 0, 0);
        }
        return 0;
    case kMsgInitialRefresh:
    case kMsgRequestRefresh:
        if (state) {
            BeginProcessRefresh(*state);
            RestartRefreshTimer(*state);
        }
        return 0;
    case kMsgOpenDetails:
        if (state && lParam != 0) {
            const auto* request = reinterpret_cast<const ExternalDetailRequest*>(lParam);
            const ULONGLONG creationTime = ResolveCurrentProcessCreationTime(
                *state, request->processId, request->expectedCreationTime100ns);
            if (creationTime != 0U && OpenProcessDetailWindow(hwnd, request->processId, creationTime)) {
                SetStatus(*state, L"已按稳定进程身份打开详细信息窗口。");
                return TRUE;
            }
            SetStatus(*state, L"无法确认当前 PID 对应的进程实例，已拒绝跨页打开。");
        }
        return FALSE;
    case kMsgRefreshCompleted:
        if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgFilterCompleted:
        if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgActionCompleted:
        if (state && state->actionTask && state->actionTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_SIZE:
        if (state) {
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            LayoutChildren(*state, rc);
        }
        return 0;
    case WM_COMMAND:
        if (state && LOWORD(wParam) == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
            RequestProcessFilter(*state,
                Ksword::Ui::GetFilterBarText(state->filterBar),
                SelectedStableKeys(*state),
                StableKeyFromListItem(*state, ListView_GetTopIndex(state->listView)));
            return 0;
        }
        if (state && HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case kRefreshButtonId:
                BeginProcessRefresh(*state);
                return 0;
            case kColumnsButtonId: {
                ShowColumnChooser(*state);
                return 0;
            }
            case kPauseButtonId:
                ToggleRefreshPaused(*state);
                return 0;
            case kPickerButtonId:
                BeginPicker(*state);
                return 0;
            default:
                break;
            }
        }
        if (state && LOWORD(wParam) == kPresetComboId && HIWORD(wParam) == CBN_SELCHANGE) {
            const LRESULT selected = ::SendMessageW(state->presetCombo, CB_GETCURSEL, 0, 0);
            const LRESULT value = selected >= 0 ? ::SendMessageW(state->presetCombo, CB_GETITEMDATA, selected, 0) : -1;
            if (value >= 0) ApplyPreset(*state, static_cast<ProcessViewPreset>(value));
            return 0;
        }
        break;
    case WM_TIMER:
        if (state && wParam == kRefreshTimerId) {
            if (state->refreshPaused) {
                return 0;
            }
            if ((::GetAsyncKeyState(VK_LCONTROL) & 0x8000) != 0) {
                SetStatus(*state, L"左 Ctrl 按下，跳过本次自动刷新。");
                return 0;
            }
            BeginProcessRefresh(*state);
            return 0;
        }
        break;
    case WM_HSCROLL:
        if (state && reinterpret_cast<HWND>(lParam) == state->refreshSlider) {
            const LRESULT pos = ::SendMessageW(state->refreshSlider, TBM_GETPOS, 0, 0);
            state->refreshIntervalSeconds = static_cast<UINT>(std::clamp<LRESULT>(pos, 1, 10));
            RestartRefreshTimer(*state);
            SetStatus(*state, L"自动刷新频率: " + std::to_wstring(state->refreshIntervalSeconds) + L"s。");
            return 0;
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const NotifyResult notify = HandleListNotify(*state, reinterpret_cast<NMHDR*>(lParam));
            if (notify.handled) {
                return notify.result;
            }
        }
        break;
    case WM_CONTEXTMENU:
        if (state && reinterpret_cast<HWND>(wParam) == state->listView) {
            POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (pt.x != -1 || pt.y != -1) {
                return 0;
            }
            RECT rc{};
            ::GetWindowRect(state->listView, &rc);
            pt.x = rc.left + 24;
            pt.y = rc.top + 24;
            ShowContextMenu(*state, pt);
            return 0;
        }
        break;
    case WM_LBUTTONUP:
        if (state && state->pickingWindow) {
            CompletePicker(*state);
            return 0;
        }
        break;
    case WM_KEYDOWN:
        if (state && state->pickingWindow && wParam == VK_ESCAPE) {
            state->pickingWindow = false;
            if (::GetCapture() == hwnd) {
                ::ReleaseCapture();
            }
            SetStatus(*state, L"拖动选中进程已取消。");
            return 0;
        }
        break;
    case WM_SETCURSOR:
        if (state && state->pickingWindow) {
            ::SetCursor(::LoadCursorW(nullptr, IDC_CROSS));
            return TRUE;
        }
        break;
    case WM_CAPTURECHANGED:
        if (state && state->pickingWindow && reinterpret_cast<HWND>(lParam) != hwnd) {
            state->pickingWindow = false;
            SetStatus(*state, L"拖动选中进程已取消。");
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    }
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = ::BeginPaint(hwnd, &ps);
        PaintBackground(hwnd, dc);
        ::EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_NCDESTROY:
        if (state) {
            ::KillTimer(hwnd, kRefreshTimerId);
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            if (state->actionTask) {
                state->actionTask->cancel();
            }
            if (state->imageList) {
                ImageList_Destroy(state->imageList);
                state->imageList = nullptr;
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    default:
        break;
    }

    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

// RegisterProcessViewClass installs the custom process page class once. There
// are no inputs; processing registers WNDCLASSW and accepts an existing class;
// output is true when CreateWindowExW can use the class name.
bool RegisterProcessViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = ProcessViewWndProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    wc.lpszClassName = kProcessViewClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND CreateProcessView(HWND parent, const RECT& bounds) {
    if (!RegisterProcessViewClass()) {
        return nullptr;
    }

    return ::CreateWindowExW(0,
        kProcessViewClass,
        L"Process List",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
}

void ResizeProcessView(HWND view, const RECT& bounds) {
    if (view) {
        ::MoveWindow(view,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            TRUE);
    }
}

void RequestProcessViewRefresh(HWND view) {
    if (view) {
        // view 用途：已创建的进程页窗口；PostMessage 避免驱动状态回调同步阻塞主窗口。
        ::PostMessageW(view, kMsgRequestRefresh, 0, 0);
    }
}

bool RequestProcessViewOpenDetails(HWND view, DWORD processId, ULONGLONG expectedCreationTime100ns) {
    if (!view || processId == 0) {
        return false;
    }
    const ExternalDetailRequest request{ processId, expectedCreationTime100ns };
    return ::SendMessageW(view, kMsgOpenDetails, 0, reinterpret_cast<LPARAM>(&request)) != 0;
}

} // namespace Ksword::Features::Process
