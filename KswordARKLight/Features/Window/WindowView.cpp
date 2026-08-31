#include "WindowView.h"

#include "WindowActions.h"
#include "WindowEnumerator.h"
#include "WindowModel.h"
#include "Win32kTimerEvidenceModel.h"
#include "../File/PathNavigator.h"
#include "../WindowTools/WindowToolsHierarchyView.h"
#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/Theme.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>
#include <shellapi.h>
#include <windowsx.h>

#include <memory>
#include <string>
#include <cstring>
#include <climits>
#include <cstdint>
#include <sstream>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Ksword::Features::Window {
namespace {
constexpr wchar_t kWindowViewClass[] = L"KswordARKLight.Window.FeatureView";
constexpr int kRefreshButtonId = 62001;
constexpr int kFrontButtonId = 62002;
constexpr int kRestoreButtonId = 62003;
constexpr int kMinimizeButtonId = 62004;
constexpr int kMaximizeButtonId = 62005;
constexpr int kCloseButtonId = 62006;
constexpr int kWindowListId = 62007;
constexpr int kDetailListId = 62008;
constexpr int kSortComboId = 62009;
constexpr int kAuditModeComboId = 62010;
constexpr int kFilterBarId = 62011;
constexpr int kLoadingOverlayId = 62012;
constexpr int kExportButtonId = 62013;
constexpr int kHeaderHeight = 96;
constexpr int kGap = 6;
constexpr int kDetailHeight = 210;
constexpr UINT kWindowMenuRefreshDetail = 62601;
constexpr UINT kWindowMenuCopyDetail = 62602;
constexpr UINT kWindowMenuFront = 62603;
constexpr UINT kWindowMenuRestore = 62604;
constexpr UINT kWindowMenuMinimize = 62605;
constexpr UINT kWindowMenuMaximize = 62606;
constexpr UINT kWindowMenuClose = 62607;
constexpr UINT kWindowMenuCopyCell = 62608;
constexpr UINT kWindowMenuCopyRow = 62609;
constexpr UINT kWindowMenuCopyVisible = 62610;
constexpr UINT kWindowMenuCopyDetailCell = 62611;
constexpr UINT kWindowMenuCopyDetailRow = 62612;
constexpr UINT kWindowMenuCopyDetailVisible = 62613;
constexpr UINT kWindowMenuAllowCapture = 62614;
constexpr UINT kWindowMenuBlockCapture = 62615;
constexpr UINT kWindowMenuExcludeFromCapture = 62616;
constexpr UINT kWindowMenuOpenProcess = 62617;
constexpr UINT kWindowMenuOpenImageDirectory = 62618;
constexpr UINT kWindowMenuExportDetail = 62619;
constexpr UINT kMsgWindowRefreshCompleted = WM_APP + 610;
constexpr UINT kMsgWindowFilterCompleted = WM_APP + 611;
constexpr UINT kMsgWindowDetailCompleted = WM_APP + 612;
constexpr UINT kMsgExternalQuery = WM_APP + 613;

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

// WindowViewMode controls whether this retained page shows the existing R3
// window list or a read-only audit entry matrix. Inputs come from the toolbar
// combo box; processing stays inside this UI module and never calls raw IOCTL.
enum class WindowViewMode {
    WindowList,
    Win32kGuiAudit,
    Win32kMessageHookAudit,
    Win32kTimerAudit,
    GpuDisplayAudit
};

// AuditEntry is one read-only audit row. Inputs are ArkDriverClient wrapper
// results, static source labels and existing R3 observations; processing only
// displays status and evidence mapping; return behavior is normal ListView text.
struct AuditEntry {
    std::wstring category;
    std::wstring source;
    std::wstring item;
    std::wstring status;
    std::wstring detail;
    DWORD relatedProcessId = 0;
};

struct WindowFilterResult {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct WindowRefreshSnapshot {
    WindowViewMode mode = WindowViewMode::WindowList;
    WindowSortMode sortMode = WindowSortMode::StackingOrder;
    WindowEnumerationResult enumeration;
    std::vector<AuditEntry> auditRows;
    std::vector<Ksword::Ui::VirtualListRow> displayRows;
};

struct WindowDetailSnapshot {
    std::uint64_t generation = 0;
    int modelIndex = -1;
    WindowSnapshotRow row;
    WindowDetail detail;
    ksword::ark::Win32kWindowRuntimeDetailResult r0Detail;
};

// Utf8ToWideLossy 把 ArkDriverClient 诊断消息提升为宽字符串。
// 输入：io.message 窄字符串；处理：逐字节提升，足够展示 ASCII/UTF-8 诊断；
// 返回：宽字符串，空输入返回空。
std::wstring Utf8ToWideLossy(const std::string& text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (const char ch : text) {
        wide.push_back(static_cast<unsigned char>(ch));
    }
    return wide;
}

// HexText 把地址/标志格式化为十六进制。
// 输入：64 位值；处理：统一 0x + 大写十六进制；返回：显示字符串。
std::wstring HexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// IoStateText 把 ArkDriverClient IO 状态转换成 UI 状态。
// 输入：ok 与 unsupported；处理：区分正常、旧驱动不支持、设备不可用；
// 返回：表格状态文本。
std::wstring IoStateText(const bool ok, const bool unsupported) {
    if (ok) {
        return L"OK";
    }
    return unsupported ? L"Unsupported" : L"Unavailable";
}

// FixedWideText copies bounded UTF-16 driver arrays into display strings.
// Inputs are a protocol buffer and its element capacity; processing stops at
// the first NUL without reading beyond the fixed packet field; output is empty
// for absent text and otherwise safe for ListView cells.
std::wstring FixedWideText(const wchar_t* text, const std::size_t maxChars) {
    if (text == nullptr || maxChars == 0U) {
        return {};
    }
    std::size_t length = 0U;
    while (length < maxChars && text[length] != L'\0') {
        ++length;
    }
    return std::wstring(text, text + length);
}

// Win32kRuntimeStatusText maps KSWORD_ARK_WIN32K_STATUS_* values to the same
// short explanations used by the full WindowDock. Input is one R0 status code;
// output is display-only text and never drives mutation.
const wchar_t* Win32kRuntimeStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_WIN32K_STATUS_OK: return L"OK";
    case KSWORD_ARK_WIN32K_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING: return L"ProfileMissing";
    case KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND: return L"Win32kNotFound";
    case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED: return L"BufferTruncated";
    case KSWORD_ARK_WIN32K_STATUS_READ_FAILED: return L"ReadFailed";
    case KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED: return L"EnumFailed";
    case KSWORD_ARK_WIN32K_STATUS_UNKNOWN:
    default: return L"Unknown";
    }
}

// Win32kModuleStateText formats a win32k module state packet. Inputs are the
// shared module state and label; processing exposes loaded/profile/base/name
// fields exactly as read from R0; output is one detail-pane row value.
std::wstring Win32kModuleStateText(const wchar_t* label, const KSWORD_ARK_WIN32K_MODULE_STATE& state) {
    std::wostringstream stream;
    stream << label
           << L": loaded=" << state.loaded
           << L"; profile=" << state.profileState
           << L"; base=" << HexText(state.imageBase)
           << L"; size=" << HexText(state.imageSize)
           << L"; name=" << FixedWideText(state.moduleName, KSWORD_ARK_WIN32K_MODULE_NAME_CHARS);
    return stream.str();
}

// Width returns non-negative rectangle width. Input is a RECT; output is pixels
// available for child controls.
int Width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

// Height returns non-negative rectangle height. Input is a RECT; output is pixels
// available for child controls.
int Height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

// WindowViewState owns all HWNDs and the current model for one window page.
// Inputs are Win32 messages; processing is isolated to the Window module and no
// desktop-management data is stored here.
struct WindowViewState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND frontButton = nullptr;
    HWND restoreButton = nullptr;
    HWND minimizeButton = nullptr;
    HWND maximizeButton = nullptr;
    HWND closeButton = nullptr;
    HWND auditModeCombo = nullptr;
    HWND sortCombo = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    HWND windowList = nullptr;
    HWND detailList = nullptr;
    HWND hierarchyReportView = nullptr;
    HIMAGELIST processImageList = nullptr;
    WindowModel model;
    std::vector<AuditEntry> auditRows;
    WindowViewMode viewMode = WindowViewMode::WindowList;
    std::wstring statusText;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t snapshotGeneration = 0;
    int contextColumn = 0;
    Ksword::Ui::VirtualListView virtualList;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<WindowRefreshSnapshot>> refreshTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<WindowFilterResult>> filterTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<WindowDetailSnapshot>> detailTask;
    std::unordered_map<std::wstring, int> processIconCache;
};

std::vector<std::wstring> WindowColumnTitles(const WindowViewState& state) {
    if (state.viewMode == WindowViewMode::WindowList) {
        return { L"进程 / PID", L"HWND", L"Title", L"Class", L"State" };
    }
    return { L"类别", L"数据源", L"入口 / 对象", L"状态", L"说明" };
}

// AppendTsvCell appends one strictly single-line TSV cell. Inputs are the
// current rendered string and an output buffer; tabs/newlines are flattened so
// a copied window title or driver diagnostic cannot add columns or rows.
void AppendTsvCell(std::wstring& output, const std::wstring& cell) {
    for (const wchar_t character : cell) {
        output.push_back(character == L'\t' || character == L'\r' || character == L'\n' ? L' ' : character);
    }
}

// AppendTsvRow writes exactly columnCount cells from one retained display row.
// The Window list keeps additional cells for filtering, but export intentionally
// stops at the currently visible column count so headers and data remain aligned.
void AppendTsvRow(std::wstring& output, const std::vector<std::wstring>& cells, const std::size_t columnCount) {
    for (std::size_t column = 0U; column < columnCount; ++column) {
        if (column != 0U) {
            output.push_back(L'\t');
        }
        if (column < cells.size()) {
            AppendTsvCell(output, cells[column]);
        }
    }
    output += L"\r\n";
}

// BuildVisibleRowsTsv serializes the already-filtered display snapshot. It
// never enumerates HWNDs or queries ArkDriverClient; normal window rows retain
// extra supporting cells for in-page workflows, which are deliberately excluded
// from this five-column visible export.
std::wstring BuildVisibleRowsTsv(const WindowViewState& state) {
    const std::vector<std::wstring> columns = WindowColumnTitles(state);
    const auto& rows = state.virtualList.rows();
    const auto& visibleIndexes = state.virtualList.visibleIndexes();
    if (columns.empty() || visibleIndexes.empty()) {
        return {};
    }

    std::wstring text;
    bool wroteHeader = false;
    for (const std::size_t index : visibleIndexes) {
        if (index >= rows.size()) {
            continue;
        }
        if (!wroteHeader) {
            AppendTsvRow(text, columns, columns.size());
            wroteHeader = true;
        }
        AppendTsvRow(text, rows[index].cells, columns.size());
    }
    return text;
}

void ExportVisibleRows(WindowViewState* state) {
    if (!state) {
        return;
    }
    const std::wstring text = BuildVisibleRowsTsv(*state);
    if (text.empty()) {
        state->statusText = L"没有可导出的可见结果。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (Ksword::Ui::SaveUtf8TextFileWithDialog(state->hwnd, L"window.tsv", L"导出窗口结果",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", text, &error)) {
    case Ksword::Ui::SaveTextFileResult::Saved:
        state->statusText = L"窗口可见结果已导出。";
        break;
    case Ksword::Ui::SaveTextFileResult::Cancelled:
        state->statusText = L"已取消导出窗口结果。";
        break;
    case Ksword::Ui::SaveTextFileResult::Failed:
        state->statusText = L"导出窗口结果失败：" + error;
        break;
    }
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// AddColumn inserts one report-view column. Inputs are list HWND, column index,
// title and width; processing sends LVM_INSERTCOLUMNW; no value is returned.
void AddColumn(HWND list, int index, const wchar_t* title, int width) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(list, index, &column);
}

// SetColumn updates a report-view column title and width. Inputs are list HWND,
// column index, title and width; no value is returned.
void SetColumn(HWND list, int index, const wchar_t* title, int width) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    ListView_SetColumn(list, index, &column);
}

// SetListText inserts or updates a report-view cell. Inputs are list HWND, row,
// column, text and optional lParam for first-column rows; no value is returned.
void SetListText(HWND list, int row, int column, const std::wstring& text, LPARAM data = 0, int imageIndex = -1) {
    if (column == 0) {
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        if (imageIndex >= 0) {
            item.mask |= LVIF_IMAGE;
            item.iImage = imageIndex;
        }
        item.iItem = row;
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(text.c_str());
        item.lParam = data;
        ListView_InsertItem(list, &item);
        return;
    }
    ListView_SetItemText(list, row, column, const_cast<LPWSTR>(text.c_str()));
}

// AddDetailRow appends one property/value row. Inputs are detail list HWND, row,
// property name and value; no value is returned.
void AddDetailRow(HWND list, int row, const std::wstring& name, const std::wstring& value) {
    SetListText(list, row, 0, name);
    SetListText(list, row, 1, value);
}

// ListText returns one ListView cell as UTF-16 text. Inputs are control, row and
// column indexes; processing grows its buffer until the common control reports
// a complete value, so detail exports do not silently truncate long diagnostics
// or titles; output is empty on invalid input or a blank cell.
std::wstring ListText(HWND list, int row, int column) {
    if (!list || row < 0 || column < 0) {
        return {};
    }
    std::vector<wchar_t> buffer(256, L'\0');
    for (;;) {
        LVITEMW item{};
        item.iSubItem = column;
        item.pszText = buffer.data();
        item.cchTextMax = static_cast<int>(buffer.size());
        const LRESULT copiedResult = ::SendMessageW(
            list, LVM_GETITEMTEXTW, static_cast<WPARAM>(row), reinterpret_cast<LPARAM>(&item));
        if (copiedResult < 0 || copiedResult > INT_MAX) {
            return {};
        }
        const int copied = static_cast<int>(copiedResult);
        if (copied < static_cast<int>(buffer.size()) - 1) {
            return std::wstring(buffer.data(), static_cast<std::size_t>(copied));
        }

        // ListView_GetItemText returns cchTextMax - 1 when a buffer might have
        // been filled. Grow and retry even when the cell happened to be exactly
        // that long; only the larger read can prove the value was complete.
        const std::size_t current = buffer.size();
        if (current >= static_cast<std::size_t>(INT_MAX / 2)) {
            // A common-control string cannot be read into a larger cchTextMax
            // value. Returning empty is safer than exporting a partial value.
            return {};
        }
        buffer.assign(current * 2U, L'\0');
    }
}

// BuildRenderedDetailTsv serializes only the property/value strings presently
// shown in the detail ListView. It neither revalidates the HWND nor calls the
// driver, so an export remains evidence for the exact R3/R0 snapshot the user
// can see, including an Unsupported or Partial result.
std::wstring BuildRenderedDetailTsv(HWND detailList) {
    const int rows = detailList ? ListView_GetItemCount(detailList) : 0;
    if (rows <= 0) {
        return {};
    }

    std::wstring text;
    AppendTsvCell(text, L"Property");
    text.push_back(L'\t');
    AppendTsvCell(text, L"Value");
    text += L"\r\n";
    for (int row = 0; row < rows; ++row) {
        AppendTsvCell(text, ListText(detailList, row, 0));
        text.push_back(L'\t');
        AppendTsvCell(text, ListText(detailList, row, 1));
        text += L"\r\n";
    }
    return text;
}

// ExportCurrentDetail persists the already-rendered window/Win32k detail as
// UTF-8 TSV. Inputs are page state and user-selected output path; it performs
// no new R3 inspection, ArkDriverClient request, privilege change, or path
// navigation. SaveUtf8TextFileWithDialog also records the exact text in the
// existing evidence session after a successful write.
void ExportCurrentDetail(WindowViewState* state) {
    if (!state) {
        return;
    }
    const std::wstring text = BuildRenderedDetailTsv(state->detailList);
    if (text.empty()) {
        state->statusText = L"没有可导出的当前窗口/Win32k 详情。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }

    std::wstring error;
    switch (Ksword::Ui::SaveUtf8TextFileWithDialog(state->hwnd, L"window_detail.tsv", L"导出窗口/Win32k 详情",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", text, &error)) {
    case Ksword::Ui::SaveTextFileResult::Saved:
        state->statusText = L"当前窗口/Win32k 详情已导出，并已记录到证据会话。";
        break;
    case Ksword::Ui::SaveTextFileResult::Cancelled:
        state->statusText = L"已取消导出当前窗口/Win32k 详情。";
        break;
    case Ksword::Ui::SaveTextFileResult::Failed:
        state->statusText = L"导出当前窗口/Win32k 详情失败：" + error;
        break;
    }
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// CopyText writes Unicode text to the clipboard. Inputs are owner HWND and text;
// processing transfers CF_UNICODETEXT; output reports success to callers that
// update the status line.
bool CopyText(HWND owner, const std::wstring& text) {
    return Ksword::Ui::CopyTextToClipboard(owner, text, L"窗口模块");
}

// AddIconFromShell extracts one small executable icon. Inputs are an image list
// and process image path; processing falls back to the generic .exe icon for
// inaccessible processes; output is the image-list index or -1 on failure.
int AddIconFromShell(HIMAGELIST imageList, const std::wstring& path) {
    if (imageList == nullptr) {
        return -1;
    }

    SHFILEINFOW info{};
    UINT flags = SHGFI_ICON | SHGFI_SMALLICON;
    const bool fallback = path.empty();
    const wchar_t* queryPath = fallback ? L".exe" : path.c_str();
    if (fallback) {
        flags |= SHGFI_USEFILEATTRIBUTES;
    }
    if (!::SHGetFileInfoW(queryPath,
            fallback ? FILE_ATTRIBUTE_NORMAL : 0,
            &info,
            sizeof(info),
            flags) || info.hIcon == nullptr) {
        return -1;
    }

    const int index = ImageList_AddIcon(imageList, info.hIcon);
    ::DestroyIcon(info.hIcon);
    return index;
}

// ProcessIconIndex resolves and caches the icon for a window row's owning
// process. Inputs are page state and a window row; output is the image-list index
// used by the PID/process column.
int ProcessIconIndex(WindowViewState* state, const WindowSnapshotRow& row) {
    if (!state || state->processImageList == nullptr) {
        return -1;
    }

    const std::wstring key = row.processImagePath.empty() ? L"<generic-exe>" : row.processImagePath;
    const auto found = state->processIconCache.find(key);
    if (found != state->processIconCache.end()) {
        return found->second;
    }

    int index = AddIconFromShell(state->processImageList, row.processImagePath);
    if (index < 0 && !row.processImagePath.empty()) {
        index = AddIconFromShell(state->processImageList, {});
    }
    state->processIconCache[key] = index;
    return index;
}

// SelectedModelIndex returns the currently selected model row. Input is module
// state; output is -1 when no visible list row is selected.
int SelectedModelIndex(WindowViewState* state) {
    if (!state || !state->windowList) {
        return -1;
    }
    const int selected = ListView_GetNextItem(state->windowList, -1, LVNI_SELECTED);
    const auto& visible = state->virtualList.visibleIndexes();
    const auto& rows = state->virtualList.rows();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return -1;
    }
    const std::size_t source = visible[static_cast<std::size_t>(selected)];
    if (source >= rows.size() || rows[source].itemData < 0) {
        return -1;
    }
    return static_cast<int>(rows[source].itemData);
}

// Win32kHookScopeText renders the protocol-level thread/global scope while
// keeping unexpected values explicit for copied audit evidence.
std::wstring Win32kHookScopeText(const std::uint32_t scope) {
    switch (scope) {
    case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_THREAD: return L"Thread";
    case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_GLOBAL: return L"Global";
    case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_UNKNOWN: return L"Unknown";
    default: return L"Scope(" + std::to_wstring(scope) + L")";
    }
}

// Win32kHookTypeText maps the documented WH_* values to their stable names.
std::wstring Win32kHookTypeText(const std::uint32_t hookType) {
    switch (hookType) {
    case 0xFFFFFFFFUL: return L"WH_MSGFILTER(-1)";
    case 0UL: return L"WH_JOURNALRECORD";
    case 1UL: return L"WH_JOURNALPLAYBACK";
    case 2UL: return L"WH_KEYBOARD";
    case 3UL: return L"WH_GETMESSAGE";
    case 4UL: return L"WH_CALLWNDPROC";
    case 5UL: return L"WH_CBT";
    case 6UL: return L"WH_SYSMSGFILTER";
    case 7UL: return L"WH_MOUSE";
    case 8UL: return L"WH_HARDWARE";
    case 9UL: return L"WH_DEBUG";
    case 10UL: return L"WH_SHELL";
    case 11UL: return L"WH_FOREGROUNDIDLE";
    case 12UL: return L"WH_CALLWNDPROCRET";
    case 13UL: return L"WH_KEYBOARD_LL";
    case 14UL: return L"WH_MOUSE_LL";
    default: return L"WH_TYPE(" + std::to_wstring(hookType) + L")";
    }
}

std::wstring Win32kHookSourceText(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SOURCE_THREAD: return L"ThreadHookChain";
    case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SOURCE_GLOBAL: return L"GlobalHookChain";
    default: return L"Source(" + std::to_wstring(source) + L")";
    }
}

std::wstring Win32kHookFlagsText(const std::uint32_t flags) {
    std::vector<const wchar_t*> labels;
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_GLOBAL) != 0U) { labels.push_back(L"Global"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_ANSI) != 0U) { labels.push_back(L"Ansi"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NEED_SKIP) != 0U) { labels.push_back(L"NeedSkip"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_HUNG) != 0U) { labels.push_back(L"Hung"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_FAULTED) != 0U) { labels.push_back(L"Faulted"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NO_DELAY) != 0U) { labels.push_back(L"NoDelay"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_WOW64_DLL) != 0U) { labels.push_back(L"Wow64Dll"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_DESTROYED) != 0U) { labels.push_back(L"Destroyed"); }
    std::wstring text;
    for (const wchar_t* label : labels) {
        if (!text.empty()) {
            text += L"|";
        }
        text += label;
    }
    return text.empty() ? L"-" : text;
}

// SelectedWindow returns the selected HWND after model lookup. Input is module
// state; output is nullptr when no row is selected or the model index is stale.
HWND SelectedWindow(WindowViewState* state) {
    const WindowSnapshotRow* row = state ? state->model.rowAt(SelectedModelIndex(state)) : nullptr;
    return row ? row->hwnd : nullptr;
}

void ShowDetail(WindowViewState* state, int modelIndex);

std::wstring CaptureAffinityText(const DWORD affinity) {
    switch (affinity) {
    case WDA_NONE:
        return L"允许窗口被捕获（WDA_NONE）";
    case WDA_MONITOR:
        return L"阻止屏幕捕获（WDA_MONITOR）";
    case WDA_EXCLUDEFROMCAPTURE:
        return L"从捕获中排除（WDA_EXCLUDEFROMCAPTURE）";
    default:
        return L"未知捕获保护值";
    }
}

bool ConfirmCaptureProtection(HWND owner, const WindowSnapshotRow& row, const DWORD affinity) {
    const std::wstring title = row.title.empty() ? L"(无标题)" : row.title;
    const std::wstring process = row.processName.empty() ? L"(未知进程)" : row.processName;
    const std::wstring text =
        L"将修改其他窗口的捕获保护属性：\n\n"
        L"窗口：" + title + L"\n"
        L"句柄：" + HwndToText(row.hwnd) + L"    类名：" + row.className + L"\n"
        L"进程：" + process + L"（PID " + std::to_wstring(row.processId) + L"）\n\n"
        L"新的属性：" + CaptureAffinityText(affinity) + L"\n\n"
        L"设置为非 WDA_NONE 后，该窗口在屏幕共享、录屏和远程会话中会变成黑块或直接消失，"
        L"而本机屏幕上看不出任何变化。\n\n是否继续？";
    return ::MessageBoxW(owner, text.c_str(), L"设置窗口捕获保护",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
}

void SetCaptureProtection(WindowViewState* state, const DWORD affinity) {
    if (!state || state->viewMode != WindowViewMode::WindowList) {
        return;
    }
    const WindowSnapshotRow* selected = state->model.rowAt(SelectedModelIndex(state));
    if (!selected) {
        state->statusText = L"未选择窗口。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }
    const WindowSnapshotRow row = *selected;
    if (!::IsWindow(row.hwnd)) {
        state->statusText = L"目标窗口已关闭，请刷新后重试。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }
    if (!ConfirmCaptureProtection(state->hwnd, row, affinity)) {
        state->statusText = L"已取消设置窗口捕获保护。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }

    const bool applied = ::SetWindowDisplayAffinity(row.hwnd, affinity) != FALSE;
    const DWORD error = applied ? ERROR_SUCCESS : ::GetLastError();
    if (applied) {
        DWORD current = WDA_NONE;
        state->statusText = ::GetWindowDisplayAffinity(row.hwnd, &current)
            ? L"已设置为 " + CaptureAffinityText(current) + L"。"
            : L"设置调用成功，但回读属性失败。";
    } else {
        state->statusText = L"设置窗口捕获保护失败（错误码 " + std::to_wstring(error) + L"）。";
        if (error == ERROR_ACCESS_DENIED) {
            state->statusText += L" 该 API 主要用于进程保护自身窗口，跨进程设置通常被拒绝。";
        }
    }
    ShowDetail(state, SelectedModelIndex(state));
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// BuildWin32kGuiAuditRows creates the GUI audit entry matrix. Inputs are the
// current R3 window count; processing calls available ArkDriverClient win32k
// wrappers and keeps the R3 window count as cross-view context; output is a
// vector displayed by the audit mode.
std::vector<AuditEntry> BuildWin32kGuiAuditRows(size_t windowCount) {
    std::vector<AuditEntry> rows;
    rows.push_back({ L"Window", L"R3 EnumWindows cross-view", L"Top-level HWND cross-view context", L"Ready",
        L"当前页面已枚举 " + std::to_wstring(windowCount) + L" 个顶层窗口，用于和 ArkDriverClient::queryWin32kWindows 结果对照。" });
    const ksword::ark::DriverClient client;
    const auto profile = client.queryWin32kProfileStatus();
    rows.push_back({ L"Profile", L"ArkDriverClient::queryWin32kProfileStatus", L"win32k/win32kbase/win32kfull", IoStateText(profile.io.ok, profile.unsupported),
        L"cap=" + HexText(profile.capabilityMask) + L"; missing=" + HexText(profile.missingCapabilityMask) + L"; sessions=" + std::to_wstring(profile.entries.size()) + L"; " + Utf8ToWideLossy(profile.io.message) });

    const auto windows = client.queryWin32kWindows();
    rows.push_back({ L"Windows", L"ArkDriverClient::queryWin32kWindows", L"HWND / tagWND cross-view", IoStateText(windows.io.ok, windows.unsupported),
        L"returned=" + std::to_wstring(windows.returnedCount) + L"/" + std::to_wstring(windows.totalCount) + L"; cap=" + HexText(windows.capabilityMask) + L"; " + Utf8ToWideLossy(windows.io.message) });

    const auto guiThreads = client.queryWin32kGuiThreads();
    rows.push_back({ L"GUI Thread", L"ArkDriverClient::queryWin32kGuiThreads", L"tagTHREADINFO / tagQ / focus/capture", IoStateText(guiThreads.io.ok, guiThreads.unsupported),
        L"returned=" + std::to_wstring(guiThreads.returnedCount) + L"/" + std::to_wstring(guiThreads.totalCount) + L"; missing=" + HexText(guiThreads.missingCapabilityMask) + L"; 不采集消息内容。" });

    const auto hotkeys = client.queryWin32kHotkeysPdb();
    rows.push_back({ L"Hotkeys", L"ArkDriverClient::queryWin32kHotkeysPdb", L"Hotkey object chain", IoStateText(hotkeys.io.ok, hotkeys.unsupported),
        L"returned=" + std::to_wstring(hotkeys.returnedCount) + L"/" + std::to_wstring(hotkeys.totalCount) + L"; 不删除热键。" });

    const auto hooks = client.queryWin32kHooksPdb();
    rows.push_back({ L"Hooks", L"ArkDriverClient::queryWin32kHooksPdb", L"WH_* hook chain", IoStateText(hooks.io.ok, hooks.unsupported),
        L"returned=" + std::to_wstring(hooks.returnedCount) + L"/" + std::to_wstring(hooks.totalCount) + L"; chains=" + std::to_wstring(hooks.discoveredChainCount) + L"; " + hooks.detail });

    rows.push_back({ L"Message Hook", L"ArkDriverClient::queryWin32kHooksPdb", L"线程 / 全局消息 Hook 链", IoStateText(hooks.io.ok, hooks.unsupported),
        L"visited=" + std::to_wstring(hooks.visitedNodeCount) + L"; readFail=" + std::to_wstring(hooks.readFailureCount) + L"; corrupt=" + std::to_wstring(hooks.corruptLinkCount) + L"; capability=" + HexText(hooks.capabilityMask) + L"; 仅枚举诊断，不捕获消息 payload。" });

    const auto timers = client.queryWin32kTimers();
    rows.push_back({ L"Timers", L"ArkDriverClient::queryWin32kTimers", L"gTimerHashTable / tagTIMER", IoStateText(timers.io.ok, timers.unsupported),
        L"returned=" + std::to_wstring(timers.returnedCount) + L"/" + std::to_wstring(timers.totalCount) + L"; cap=" + HexText(timers.capabilityMask) + L"; " + Utf8ToWideLossy(timers.io.message) });

    const auto eventHooks = client.queryWin32kEventHooks();
    rows.push_back({ L"Event Hooks", L"ArkDriverClient::queryWin32kEventHooks", L"gpWinEventHooks / tagEVENTHOOK", IoStateText(eventHooks.io.ok, eventHooks.unsupported),
        L"returned=" + std::to_wstring(eventHooks.returnedCount) + L"/" + std::to_wstring(eventHooks.totalCount) + L"; cap=" + HexText(eventHooks.capabilityMask) + L"; " + Utf8ToWideLossy(eventHooks.io.message) });

    rows.push_back({ L"WM_COPYDATA", L"R3 monitor / ETW / snapshot", L"事件摘要边界", L"ReadOnly",
        L"默认不读取 COPYDATASTRUCT payload，不安装全局消息 hook；当前仅记录只读边界说明。" });
    return rows;
}

// BuildWin32kMessageHookAuditRows exposes the structured thread/global hook
// rows added by the current Win32k protocol. It performs one typed, read-only
// client query on the refresh worker and never captures message payloads or
// changes a hook chain.
std::vector<AuditEntry> BuildWin32kMessageHookAuditRows() {
    const ksword::ark::Win32kHooksPdbResult result = ksword::ark::DriverClient().queryWin32kHooksPdb();
    std::vector<AuditEntry> rows;
    rows.reserve(result.entries.size() + 1U);

    const std::wstring summary =
        L"returned=" + std::to_wstring(result.returnedCount) + L"/" + std::to_wstring(result.totalCount) +
        L"; chains=" + std::to_wstring(result.discoveredChainCount) +
        L"; visited=" + std::to_wstring(result.visitedNodeCount) +
        L"; readFail=" + std::to_wstring(result.readFailureCount) +
        L"; corrupt=" + std::to_wstring(result.corruptLinkCount) +
        L"; duplicate=" + std::to_wstring(result.duplicateCount) +
        L"; cap=" + HexText(result.capabilityMask) +
        L"; missing=" + HexText(result.missingCapabilityMask) +
        L"; " + Utf8ToWideLossy(result.io.message) +
        (result.detail.empty() ? L"" : L"; " + result.detail);

    rows.push_back({
        L"Message Hook snapshot",
        L"ArkDriverClient::queryWin32kHooksPdb",
        L"Thread / global message hook chain",
        IoStateText(result.io.ok, result.unsupported),
        summary
    });

    for (const KSWORD_ARK_WIN32K_HOOK_ENTRY& entry : result.entries) {
        const std::wstring item = Win32kHookTypeText(entry.hookType) + L" / " + Win32kHookScopeText(entry.hookScope) +
            L" | PID=" + std::to_wstring(entry.processId) + L" TID=" + std::to_wstring(entry.threadId) +
            L" Session=" + std::to_wstring(entry.sessionId);
        std::wostringstream detail;
        detail << L"source=" << Win32kHookSourceText(entry.source)
               << L"; target=" << entry.targetProcessId << L"/" << entry.targetThreadId << L"/" << entry.targetSessionId
               << L"; hookHandle=" << HexText(entry.hookHandle)
               << L"; hookObject=" << HexText(entry.hookObject)
               << L"; chain=" << HexText(entry.chainHead) << L" -> " << HexText(entry.nextHookObject)
               << L"; procedure=" << HexText(entry.procedureAddress) << L" + " << HexText(entry.procedureOffset)
               << L"; moduleBase=" << HexText(entry.moduleBase)
               << L"; moduleId=" << static_cast<std::int32_t>(entry.moduleId)
               << L"; atom=" << HexText(entry.moduleAtom)
               << L"; threadInfo=" << HexText(entry.threadInfo)
               << L"; targetThreadInfo=" << HexText(entry.targetThreadInfo)
               << L"; desktop=" << HexText(entry.desktopObject)
               << L"; flags=" << Win32kHookFlagsText(entry.flags) << L" (" << HexText(entry.flags) << L")"
               << L"; fieldFlags=" << HexText(entry.fieldFlags)
               << L"; lastStatus=" << HexText(static_cast<std::uint32_t>(entry.lastStatus));
        const std::wstring driverDetail = FixedWideText(entry.detail, KSWORD_ARK_WIN32K_DETAIL_CHARS);
        if (!driverDetail.empty()) {
            detail << L"; " << driverDetail;
        }
        rows.push_back({
            L"Message Hook",
            Win32kHookSourceText(entry.source),
            item,
            Win32kRuntimeStatusText(entry.status),
            detail.str()
        });
    }
    return rows;
}

// BuildWin32kTimerAuditRows exposes the existing typed tagTIMER snapshot as
// immutable display rows. The DriverClient wrapper owns all protocol handling;
// this page only projects the returned snapshot and never alters a timer.
std::vector<AuditEntry> BuildWin32kTimerAuditRows() {
    const ksword::ark::Win32kTimersResult result = ksword::ark::DriverClient().queryWin32kTimers();
    const std::vector<Win32kTimerEvidenceRow> evidenceRows = BuildWin32kTimerEvidenceRows(result);
    std::vector<AuditEntry> rows;
    rows.reserve(evidenceRows.size());
    for (const Win32kTimerEvidenceRow& evidence : evidenceRows) {
        rows.push_back({
            evidence.category,
            evidence.source,
            evidence.item,
            evidence.status,
            evidence.detail,
            static_cast<DWORD>(evidence.relatedProcessId)
        });
    }
    return rows;
}

// BuildGpuDisplayAuditRows creates the GPU/display/watchdog audit entry matrix.
// Inputs are none; processing calls the ArkDriverClient GPU/display watchdog
// audit wrapper and supplements it with R3 configuration context rows;
// output is displayed as read-only audit rows.
std::vector<AuditEntry> BuildGpuDisplayAuditRows() {
    std::vector<AuditEntry> rows;
    const ksword::ark::DriverClient client;
    const auto gpuAudit = client.queryGpuDisplayWatchdogAudit();
    rows.push_back({ L"GPU", L"ArkDriverClient::queryGpuDisplayWatchdogAudit", L"dxgkrnl / dxgmms2 / watchdog", IoStateText(gpuAudit.io.ok, gpuAudit.unsupported),
        L"drivers=" + std::to_wstring(gpuAudit.driverCount) + L"; devices=" + std::to_wstring(gpuAudit.deviceCount) + L"; rows=" + std::to_wstring(gpuAudit.entries.size()) + L"; " + Utf8ToWideLossy(gpuAudit.io.message) });
    rows.push_back({ L"Display", L"R0 DeviceAudit + R3 display APIs", L"Adapter / monitor / display path", gpuAudit.io.ok ? L"OK" : L"Partial",
        L"R0 设备栈已接入；R3 display API 可继续作为 cross-view，不修改显示配置。" });
    rows.push_back({ L"Miniport", L"R0 DeviceAudit", L"Display miniport basic state", gpuAudit.io.ok ? L"OK" : L"Partial",
        L"按 driver/device row 展示 miniport、PCI 设备和显示路径；缺失字段显示 partial。" });
    rows.push_back({ L"TDR", L"Registry/EventLog reader", L"TDR configuration summary", L"ReadOnly",
        L"只读摘要：TdrDelay/TdrDdiDelay/TdrLevel 和事件摘要由用户态安全读取，不修改策略。" });
    rows.push_back({ L"Watchdog", L"ArkDriverClient::queryGpuDisplayWatchdogAudit", L"watchdog.sys integrity / status", IoStateText(gpuAudit.io.ok, gpuAudit.unsupported),
        L"展示 watchdog 模块/驱动对象状态；不关闭 watchdog，不改 TDR 策略。" });
    return rows;
}

std::vector<Ksword::Ui::VirtualListRow> BuildWindowDisplayRows(
    const WindowEnumerationResult& enumeration,
    const WindowSortMode sortMode) {
    WindowModel model;
    model.setRows(enumeration.rows);
    model.setSortMode(sortMode);
    const auto& sourceRows = model.rows();
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(sourceRows.size());
    for (std::size_t index = 0; index < sourceRows.size(); ++index) {
        const WindowSnapshotRow& row = sourceRows[index];
        Ksword::Ui::VirtualListRow display{};
        display.stableKey = HwndToText(row.hwnd);
        display.itemData = static_cast<LPARAM>(index);
        display.cells = {
            model.textForColumn(row, 0),
            model.textForColumn(row, 1),
            model.textForColumn(row, 2),
            model.textForColumn(row, 3),
            model.textForColumn(row, 4),
            row.processImagePath,
            std::to_wstring(row.threadId),
            std::to_wstring(row.style),
            std::to_wstring(row.exStyle),
        };
        rows.push_back(std::move(display));
    }
    return rows;
}

std::vector<Ksword::Ui::VirtualListRow> BuildAuditDisplayRows(const std::vector<AuditEntry>& auditRows) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(auditRows.size());
    for (std::size_t index = 0; index < auditRows.size(); ++index) {
        const AuditEntry& entry = auditRows[index];
        Ksword::Ui::VirtualListRow row{};
        row.stableKey = std::to_wstring(index) + L":" + entry.item;
        row.itemData = static_cast<LPARAM>(index);
        row.cells = { entry.category, entry.source, entry.item, entry.status, entry.detail };
        rows.push_back(std::move(row));
    }
    return rows;
}

// ConfigureWindowColumns restores the existing live-window list headers. Input
// is page state; processing only updates visible ListView columns; no return.
void ConfigureWindowColumns(WindowViewState* state) {
    if (!state || !state->windowList) {
        return;
    }
    SetColumn(state->windowList, 0, L"进程 / PID", 190);
    SetColumn(state->windowList, 1, L"HWND", 120);
    SetColumn(state->windowList, 2, L"Title", 300);
    SetColumn(state->windowList, 3, L"Class", 190);
    SetColumn(state->windowList, 4, L"State", 220);
}

// ConfigureAuditColumns switches the main list to audit-entry headers. Input is
// page state; output is visible column metadata only.
void ConfigureAuditColumns(WindowViewState* state) {
    if (!state || !state->windowList) {
        return;
    }
    SetColumn(state->windowList, 0, L"类别", 150);
    SetColumn(state->windowList, 1, L"数据源", 220);
    SetColumn(state->windowList, 2, L"入口 / 对象", 280);
    SetColumn(state->windowList, 3, L"状态", 120);
    SetColumn(state->windowList, 4, L"说明", 430);
}

// ShowAuditDetail refreshes the detail pane for one audit row. Inputs are state
// and row index; processing is display-only; no value is returned.
void ShowAuditDetail(WindowViewState* state, int rowIndex) {
    if (!state || !state->detailList) {
        return;
    }
    ListView_DeleteAllItems(state->detailList);
    if (rowIndex < 0 || rowIndex >= static_cast<int>(state->auditRows.size())) {
        AddDetailRow(state->detailList, 0, L"Selection", L"No audit entry selected");
        return;
    }
    const AuditEntry& entry = state->auditRows[rowIndex];
    int detailRow = 0;
    AddDetailRow(state->detailList, detailRow++, L"类别", entry.category);
    AddDetailRow(state->detailList, detailRow++, L"数据源", entry.source);
    AddDetailRow(state->detailList, detailRow++, L"入口 / 对象", entry.item);
    AddDetailRow(state->detailList, detailRow++, L"状态", entry.status);
    AddDetailRow(state->detailList, detailRow++, L"说明", entry.detail);
    AddDetailRow(state->detailList, detailRow++, L"安全边界", L"默认只读审计；本页不提供 patch/delete/bypass/remove/unlink 操作。");
}

void RenderWindowDetail(WindowViewState* state, const WindowDetailSnapshot& snapshot);

// ShowDetail schedules live R3 and R0 window inspection outside the UI thread.
// Inputs are a cached model index; stale results are ignored by request epoch.
void ShowDetail(WindowViewState* state, int modelIndex) {
    if (!state || !state->detailList) {
        return;
    }
    if (state->viewMode != WindowViewMode::WindowList) {
        WindowTools::UpdateWindowHierarchyReportView(state->hierarchyReportView, nullptr);
        ShowAuditDetail(state, modelIndex);
        return;
    }
    const WindowSnapshotRow* row = state->model.rowAt(modelIndex);
    if (!row || !state->detailTask) {
        WindowTools::UpdateWindowHierarchyReportView(state->hierarchyReportView, nullptr);
        ListView_DeleteAllItems(state->detailList);
        AddDetailRow(state->detailList, 0, L"Selection", L"No window selected");
        return;
    }
    const WindowSnapshotRow input = *row;
    WindowTools::UpdateWindowHierarchyReportView(state->hierarchyReportView, input.hwnd);
    const std::uint64_t generation = state->snapshotGeneration;
    ListView_DeleteAllItems(state->detailList);
    AddDetailRow(state->detailList, 0, L"状态", L"正在后台查询窗口与 Win32k 详情…");
    state->detailTask->request(
        [input, generation, modelIndex] {
            WindowDetailSnapshot snapshot{};
            snapshot.generation = generation;
            snapshot.modelIndex = modelIndex;
            snapshot.row = input;
            snapshot.detail = QueryWindowDetails(input.hwnd);
            snapshot.r0Detail = ksword::ark::DriverClient().queryWin32kWindowDetail(
                static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(input.hwnd)),
                static_cast<unsigned long>(input.processId),
                static_cast<unsigned long>(input.threadId));
            return snapshot;
        },
        [state](std::uint64_t, std::optional<WindowDetailSnapshot>&& snapshot, std::exception_ptr error) {
            if (!state || error || !snapshot.has_value()) {
                if (state) {
                    state->statusText = L"窗口详情查询异常结束。";
                    ::InvalidateRect(state->hwnd, nullptr, TRUE);
                }
                return;
            }
            if (snapshot->generation != state->snapshotGeneration) {
                return;
            }
            const WindowSnapshotRow* current = state->model.rowAt(snapshot->modelIndex);
            if (!current || current->hwnd != snapshot->row.hwnd) {
                return;
            }
            RenderWindowDetail(state, *snapshot);
        });
}

// RenderWindowDetail installs one completed immutable detail snapshot.
void RenderWindowDetail(WindowViewState* state, const WindowDetailSnapshot& snapshot) {
    if (!state || !state->detailList) {
        return;
    }
    if (state->viewMode != WindowViewMode::WindowList) {
        ShowAuditDetail(state, snapshot.modelIndex);
        return;
    }
    ListView_DeleteAllItems(state->detailList);
    const WindowSnapshotRow* row = &snapshot.row;
    WindowDetail detail = snapshot.detail;
    if (!detail.found) {
        detail = state->model.detailFromRow(*row);
    }
    int detailRow = 0;
    AddDetailRow(state->detailList, detailRow++, L"Window", detail.title);
    for (const WindowProperty& property : detail.properties) {
        AddDetailRow(state->detailList, detailRow++, property.name, property.value);
    }

    // Mirror the full WindowDock single-HWND R0 detail path through
    // ArkDriverClient. Inputs are the currently selected HWND/PID/TID; the
    // wrapper keeps DeviceIoControl syntax centralized and returns one bounded
    // response packet; this block appends read-only detail rows and returns no
    // value to the caller.
    const ksword::ark::Win32kWindowRuntimeDetailResult& r0Detail = snapshot.r0Detail;
    AddDetailRow(state->detailList, detailRow++, L"R0 Win32k Detail",
        IoStateText(r0Detail.io.ok, r0Detail.unsupported) + L" - " + Utf8ToWideLossy(r0Detail.io.message));
    if (r0Detail.io.ok) {
        const KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE& response = r0Detail.response;
        AddDetailRow(state->detailList, detailRow++, L"R0 Status", Win32kRuntimeStatusText(response.status));
        AddDetailRow(state->detailList, detailRow++, L"R0 HWND", HexText(response.hwnd));
        AddDetailRow(state->detailList, detailRow++, L"R0 PID/TID",
            std::to_wstring(response.processId) + L" / " + std::to_wstring(response.threadId));
        AddDetailRow(state->detailList, detailRow++, L"R0 tagWND", HexText(response.tagWnd));
        AddDetailRow(state->detailList, detailRow++, L"R0 threadInfo", HexText(response.threadInfo));
        AddDetailRow(state->detailList, detailRow++, L"R0 queue", HexText(response.queueObject));
        AddDetailRow(state->detailList, detailRow++, L"R0 desktop", HexText(response.desktopObject));
        AddDetailRow(state->detailList, detailRow++, L"R0 capability", HexText(response.capabilityMask));
        AddDetailRow(state->detailList, detailRow++, L"R0 missing capability", HexText(response.missingCapabilityMask));
        AddDetailRow(state->detailList, detailRow++, L"R0 fieldFlags", HexText(response.fieldFlags));
        AddDetailRow(state->detailList, detailRow++, L"R0 lastStatus", HexText(static_cast<std::uint32_t>(response.lastStatus)));
        AddDetailRow(state->detailList, detailRow++, L"R0 Title",
            FixedWideText(response.title, KSWORD_ARK_WIN32K_TITLE_CHARS));
        AddDetailRow(state->detailList, detailRow++, L"R0 Class",
            FixedWideText(response.className, KSWORD_ARK_WIN32K_CLASS_CHARS));
        AddDetailRow(state->detailList, detailRow++, L"R0 Detail",
            FixedWideText(response.detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS));
        AddDetailRow(state->detailList, detailRow++, L"R0 win32k",
            Win32kModuleStateText(L"win32k", response.win32k));
        AddDetailRow(state->detailList, detailRow++, L"R0 win32kbase",
            Win32kModuleStateText(L"win32kbase", response.win32kbase));
        AddDetailRow(state->detailList, detailRow++, L"R0 win32kfull",
            Win32kModuleStateText(L"win32kfull", response.win32kfull));
        AddDetailRow(state->detailList, detailRow++, L"R0 offsets tagWND",
            L"pti=" + HexText(response.fieldOffsets.tagWndThreadInfo) +
            L"; style=" + HexText(response.fieldOffsets.tagWndStyle) +
            L"; rect=" + HexText(response.fieldOffsets.tagWndRect) +
            L"; title=" + HexText(response.fieldOffsets.tagWndTitle) +
            L"; class=" + HexText(response.fieldOffsets.tagWndClass));
        AddDetailRow(state->detailList, detailRow++, L"R0 offsets thread/queue",
            L"queue=" + HexText(response.fieldOffsets.tagThreadInfoQueue) +
            L"; desktop=" + HexText(response.fieldOffsets.tagThreadInfoDesktop) +
            L"; active=" + HexText(response.fieldOffsets.tagQActiveWindow) +
            L"; focus=" + HexText(response.fieldOffsets.tagQFocusWindow) +
            L"; capture=" + HexText(response.fieldOffsets.tagQCaptureWindow));
    }
}

// RequestWindowFilter filters the immutable display snapshot in the worker.
// Inputs are the retained rows and the debounced local query. No enumeration,
// IOCTL, or live HWND query occurs on the UI thread.
void RequestWindowFilter(WindowViewState* state, std::wstring query) {
    if (!state || !state->filterTask || !state->filterRows) {
        return;
    }
    state->filterQuery = std::move(query);
    state->filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state->filterBar);
    const std::uint64_t generation = state->snapshotGeneration;
    const auto rows = state->filterRows;
    const bool useRegex = state->filterUseRegex;
    state->filterTask->request(
        [rows, generation, useRegex, query = state->filterQuery]() mutable {
            WindowFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [state](std::uint64_t, std::optional<WindowFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                if (state) {
                    state->statusText = L"窗口筛选异常结束，已保留当前可见结果。";
                    ::InvalidateRect(state->hwnd, nullptr, TRUE);
                }
                return;
            }
            if (result->generation != state->snapshotGeneration || result->query != state->filterQuery ||
                result->useRegex != state->filterUseRegex) {
                return;
            }
            state->virtualList.setVisibleIndexes(std::move(result->visibleIndexes));
            if (!state->filterQuery.empty()) {
                state->statusText = L"窗口筛选结果：" + std::to_wstring(state->virtualList.rowCount()) + L" 项。";
            }
        });
}

// PopulateList installs a preformatted owner-data snapshot. Input is module
// state; only ListView metadata and immutable rows change on the UI thread.
void PopulateList(WindowViewState* state) {
    if (!state || !state->windowList || !state->filterRows) {
        return;
    }
    if (state->viewMode != WindowViewMode::WindowList) {
        ConfigureAuditColumns(state);
    } else {
        ConfigureWindowColumns(state);
    }
    state->virtualList.setSharedRows(state->filterRows);
    RequestWindowFilter(state, state->filterBar ? Ksword::Ui::GetFilterBarText(state->filterBar) : state->filterQuery);
}

// RefreshWindows performs the R3 EnumWindows and optional R0 audit snapshot on
// the worker. UI state keeps the prior result interactive until replacement.
void RefreshWindows(WindowViewState* state) {
    if (!state || !state->refreshTask) {
        return;
    }
    const WindowViewMode mode = state->viewMode;
    const WindowSortMode sortMode = state->model.sortMode();
    const bool firstLoad = state->virtualList.rows().empty();
    state->statusText = state->refreshTask->running()
        ? L"窗口刷新已排队，等待当前快照完成…"
        : L"正在后台枚举窗口和审计 Win32k 状态…";
    ::EnableWindow(state->refreshButton, FALSE);
    if (firstLoad) {
        Ksword::Ui::SetLoadingOverlay(state->loadingOverlay, true, L"正在加载窗口与 Win32k 审计…");
    }
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
    state->refreshTask->request(
        [mode, sortMode] {
            WindowRefreshSnapshot snapshot{};
            snapshot.mode = mode;
            snapshot.sortMode = sortMode;
            if (mode == WindowViewMode::Win32kGuiAudit) {
                snapshot.enumeration = EnumerateTopLevelWindows();
                snapshot.auditRows = BuildWin32kGuiAuditRows(snapshot.enumeration.rows.size());
                snapshot.displayRows = BuildAuditDisplayRows(snapshot.auditRows);
            } else if (mode == WindowViewMode::Win32kMessageHookAudit) {
                snapshot.auditRows = BuildWin32kMessageHookAuditRows();
                snapshot.displayRows = BuildAuditDisplayRows(snapshot.auditRows);
            } else if (mode == WindowViewMode::Win32kTimerAudit) {
                snapshot.auditRows = BuildWin32kTimerAuditRows();
                snapshot.displayRows = BuildAuditDisplayRows(snapshot.auditRows);
            } else if (mode == WindowViewMode::GpuDisplayAudit) {
                snapshot.auditRows = BuildGpuDisplayAuditRows();
                snapshot.displayRows = BuildAuditDisplayRows(snapshot.auditRows);
            } else {
                snapshot.enumeration = EnumerateTopLevelWindows();
                snapshot.displayRows = BuildWindowDisplayRows(snapshot.enumeration, sortMode);
            }
            return snapshot;
        },
        [state](std::uint64_t, std::optional<WindowRefreshSnapshot>&& snapshot, std::exception_ptr error) {
            if (!state) {
                return;
            }
            ::EnableWindow(state->refreshButton, TRUE);
            Ksword::Ui::SetLoadingOverlay(state->loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state->statusText = L"窗口后台刷新异常结束，请检查驱动状态与访问权限。";
                ::InvalidateRect(state->hwnd, nullptr, TRUE);
                return;
            }
            state->model.setRows(std::move(snapshot->enumeration.rows));
            state->model.setSortMode(snapshot->sortMode);
            state->auditRows = std::move(snapshot->auditRows);
            state->filterRows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>(std::move(snapshot->displayRows));
            ++state->snapshotGeneration;
            if (snapshot->mode == WindowViewMode::WindowList) {
                state->statusText = state->model.rows().empty() ? L"Windows: 0" : L"Windows: " + std::to_wstring(state->model.rows().size());
            } else if (snapshot->mode == WindowViewMode::Win32kGuiAudit) {
                state->statusText = L"Win32K GUI 审计快照已刷新。";
            } else if (snapshot->mode == WindowViewMode::Win32kMessageHookAudit) {
                state->statusText = L"Win32K 消息 Hook 审计快照已刷新：" + std::to_wstring(state->auditRows.size()) + L" 行。";
            } else if (snapshot->mode == WindowViewMode::Win32kTimerAudit) {
                state->statusText = L"Win32K 定时器只读证据快照已刷新：" + std::to_wstring(state->auditRows.size()) +
                    L" 行；首行保留返回计数、完整性和布局来源。";
            } else {
                state->statusText = L"GPU / Display / Watchdog 审计快照已刷新。";
            }
            PopulateList(state);
            WindowTools::UpdateWindowHierarchyReportView(state->hierarchyReportView,
                snapshot->mode == WindowViewMode::WindowList ? SelectedWindow(state) : nullptr);
            ::InvalidateRect(state->hwnd, nullptr, TRUE);
        });
}

// UpdateViewModeFromCombo reads the audit-mode combo and switches between the
// existing window list and read-only audit entry pages. Input is page state;
// processing reuses RefreshWindows for R3 cross-view context; no value is
// returned.
void UpdateViewModeFromCombo(WindowViewState* state) {
    if (!state || !state->auditModeCombo) {
        return;
    }
    const LRESULT selected = ::SendMessageW(state->auditModeCombo, CB_GETCURSEL, 0, 0);
    if (selected == 1) {
        state->viewMode = WindowViewMode::Win32kGuiAudit;
        ::EnableWindow(state->sortCombo, FALSE);
        ::EnableWindow(state->frontButton, FALSE);
        ::EnableWindow(state->restoreButton, FALSE);
        ::EnableWindow(state->minimizeButton, FALSE);
        ::EnableWindow(state->maximizeButton, FALSE);
        ::EnableWindow(state->closeButton, FALSE);
    } else if (selected == 2) {
        state->viewMode = WindowViewMode::Win32kMessageHookAudit;
        ::EnableWindow(state->sortCombo, FALSE);
        ::EnableWindow(state->frontButton, FALSE);
        ::EnableWindow(state->restoreButton, FALSE);
        ::EnableWindow(state->minimizeButton, FALSE);
        ::EnableWindow(state->maximizeButton, FALSE);
        ::EnableWindow(state->closeButton, FALSE);
    } else if (selected == 3) {
        state->viewMode = WindowViewMode::Win32kTimerAudit;
        ::EnableWindow(state->sortCombo, FALSE);
        ::EnableWindow(state->frontButton, FALSE);
        ::EnableWindow(state->restoreButton, FALSE);
        ::EnableWindow(state->minimizeButton, FALSE);
        ::EnableWindow(state->maximizeButton, FALSE);
        ::EnableWindow(state->closeButton, FALSE);
    } else if (selected == 4) {
        state->viewMode = WindowViewMode::GpuDisplayAudit;
        ::EnableWindow(state->sortCombo, FALSE);
        ::EnableWindow(state->frontButton, FALSE);
        ::EnableWindow(state->restoreButton, FALSE);
        ::EnableWindow(state->minimizeButton, FALSE);
        ::EnableWindow(state->maximizeButton, FALSE);
        ::EnableWindow(state->closeButton, FALSE);
    } else {
        state->viewMode = WindowViewMode::WindowList;
        ::EnableWindow(state->sortCombo, TRUE);
        ::EnableWindow(state->frontButton, TRUE);
        ::EnableWindow(state->restoreButton, TRUE);
        ::EnableWindow(state->minimizeButton, TRUE);
        ::EnableWindow(state->maximizeButton, TRUE);
        ::EnableWindow(state->closeButton, TRUE);
    }
    if (state->viewMode != WindowViewMode::WindowList) {
        WindowTools::UpdateWindowHierarchyReportView(state->hierarchyReportView, nullptr);
    }
    RefreshWindows(state);
}

// UpdateSortModeFromCombo reads the toolbar combo-box and rebuilds the list
// without re-enumerating windows. Input is the page state; processing maps combo
// index 0 to stacking order and index 1 to process order; no value is returned.
void UpdateSortModeFromCombo(WindowViewState* state) {
    if (!state || !state->sortCombo) {
        return;
    }
    if (state->viewMode != WindowViewMode::WindowList) {
        return;
    }

    const LRESULT selected = ::SendMessageW(state->sortCombo, CB_GETCURSEL, 0, 0);
    const WindowSortMode mode = selected == 1 ? WindowSortMode::ProcessOrder : WindowSortMode::StackingOrder;
    state->model.setSortMode(mode);
    state->statusText = mode == WindowSortMode::ProcessOrder ? L"Windows: 按进程顺序排序" : L"Windows: 按堆叠顺序排序";
    RefreshWindows(state);
}

// RunAction executes one centralized WindowActions operation against the current
// selection. Inputs are state and action command ID; processing delegates to
// WindowActions.* and refreshes status text; no value is returned.
void RunAction(WindowViewState* state, int commandId) {
    if (!state) {
        return;
    }
    if (state->viewMode != WindowViewMode::WindowList) {
        state->statusText = L"Audit entries are read-only.";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }
    HWND hwnd = SelectedWindow(state);
    WindowActionResult result;
    switch (commandId) {
    case kFrontButtonId:
        result = BringWindowToFront(hwnd);
        break;
    case kRestoreButtonId:
        result = RestoreWindow(hwnd);
        break;
    case kMinimizeButtonId:
        result = MinimizeWindow(hwnd);
        break;
    case kMaximizeButtonId:
        result = MaximizeWindow(hwnd);
        break;
    case kCloseButtonId:
        result = CloseWindowGracefully(hwnd);
        break;
    default:
        result = { false, L"Unknown action." };
        break;
    }
    state->statusText = result.message;
    ShowDetail(state, SelectedModelIndex(state));
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// CopyCurrentDetail serializes the current detail pane as tab-separated text.
// Input is the page state; processing reads the visible detail ListView rows;
// no value is returned because statusText stores the outcome for painting.
void CopyCurrentDetail(WindowViewState* state) {
    if (!state || !state->detailList) {
        return;
    }
    std::wstring text;
    const int rows = ListView_GetItemCount(state->detailList);
    for (int row = 0; row < rows; ++row) {
        text += ListText(state->detailList, row, 0);
        text += L'\t';
        text += ListText(state->detailList, row, 1);
        text += L"\r\n";
    }
    state->statusText = CopyText(state->hwnd, text) ? L"Window detail copied." : L"Copy window detail failed.";
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

void ShowDetailContextMenu(WindowViewState* state, POINT screenPoint) {
    if (!state || !state->detailList) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(state->detailList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int hitRow = ListView_SubItemHitTest(state->detailList, &hit);
    if (hitRow >= 0) {
        ListView_SetItemState(state->detailList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(state->detailList, hitRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    const int selected = ListView_GetNextItem(state->detailList, -1, LVNI_SELECTED);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (selected >= 0 ? 0U : MF_GRAYED), kWindowMenuCopyDetailCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (selected >= 0 ? 0U : MF_GRAYED), kWindowMenuCopyDetailRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING | (ListView_GetItemCount(state->detailList) > 0 ? 0U : MF_GRAYED), kWindowMenuCopyDetailVisible, L"复制可见结果");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (ListView_GetItemCount(state->detailList) > 0 ? 0U : MF_GRAYED),
        kWindowMenuExportDetail, L"导出当前详情为 TSV");
    const UINT command = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state->hwnd, nullptr);
    ::DestroyMenu(menu);
    if (command == kWindowMenuExportDetail) {
        ExportCurrentDetail(state);
        return;
    }
    std::wstring text;
    if (command == kWindowMenuCopyDetailCell && selected >= 0) {
        text = ListText(state->detailList, selected, std::max(0, hit.iSubItem));
    } else if (command == kWindowMenuCopyDetailRow && selected >= 0) {
        text = ListText(state->detailList, selected, 0) + L"\t" + ListText(state->detailList, selected, 1);
    } else if (command == kWindowMenuCopyDetailVisible) {
        for (int row = 0; row < ListView_GetItemCount(state->detailList); ++row) {
            text += ListText(state->detailList, row, 0) + L"\t" + ListText(state->detailList, row, 1) + L"\r\n";
        }
    }
    if (command != 0) {
        state->statusText = CopyText(state->hwnd, text) ? L"已复制结果。" : L"复制结果失败。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
    }
}

std::wstring CopyVirtualRows(const WindowViewState* state, const bool allVisible) {
    if (!state) {
        return {};
    }
    const auto& rows = state->virtualList.rows();
    const auto& visible = state->virtualList.visibleIndexes();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible && (ListView_GetItemState(state->windowList, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0) {
            continue;
        }
        const std::size_t source = visible[item];
        if (source >= rows.size()) {
            continue;
        }
        const auto& cells = rows[source].cells;
        for (std::size_t column = 0; column < cells.size(); ++column) {
            if (column != 0) {
                text.push_back(L'\t');
            }
            for (const wchar_t ch : cells[column]) {
                text.push_back(ch == L'\t' || ch == L'\r' || ch == L'\n' ? L' ' : ch);
            }
        }
        text += L"\r\n";
    }
    return text;
}

std::wstring CopyVirtualCell(const WindowViewState* state) {
    if (!state) {
        return {};
    }
    const int selected = ListView_GetNextItem(state->windowList, -1, LVNI_SELECTED);
    const auto& visible = state->virtualList.visibleIndexes();
    const auto& rows = state->virtualList.rows();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return {};
    }
    const std::size_t source = visible[static_cast<std::size_t>(selected)];
    if (source >= rows.size() || state->contextColumn < 0 || static_cast<std::size_t>(state->contextColumn) >= rows[source].cells.size()) {
        return {};
    }
    return rows[source].cells[static_cast<std::size_t>(state->contextColumn)];
}

// SelectedWindowSnapshot returns the currently selected retained window row
// only in the normal window-list mode. Audit rows never pretend to carry the
// same process-image provenance as an EnumWindows snapshot.
const WindowSnapshotRow* SelectedWindowSnapshot(WindowViewState* state) {
    if (!state || state->viewMode != WindowViewMode::WindowList) {
        return nullptr;
    }
    return state->model.rowAt(SelectedModelIndex(state));
}

// SelectedAuditEntry returns the immutable selected audit snapshot. It never
// treats a kernel object pointer as a live HWND or process handle.
const AuditEntry* SelectedAuditEntry(WindowViewState* state) {
    if (!state || state->viewMode == WindowViewMode::WindowList) {
        return nullptr;
    }
    const int rowIndex = SelectedModelIndex(state);
    if (rowIndex < 0 || rowIndex >= static_cast<int>(state->auditRows.size())) {
        return nullptr;
    }
    return &state->auditRows[static_cast<std::size_t>(rowIndex)];
}

void OpenSelectedWindowProcess(WindowViewState* state) {
    const WindowSnapshotRow* row = SelectedWindowSnapshot(state);
    if (!state || !row || row->processId == 0U) {
        if (state) {
            state->statusText = L"窗口快照没有可导航的 PID。";
            ::InvalidateRect(state->hwnd, nullptr, TRUE);
        }
        return;
    }
    const DWORD processId = row->processId;
    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::ProcessDetails;
    request.entity.kind = Ksword::Core::EntityKind::Process;
    request.entity.id = processId;
    const bool routed = Ksword::Ui::RequestEntityNavigation(state->hwnd, request);
    state->statusText = routed
        ? L"已请求打开当前 PID " + std::to_wstring(processId) + L" 的进程详细信息；窗口快照归属会重新校验。"
        : L"无法导航到该窗口快照的当前进程实例。";
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// OpenSelectedAuditProcess routes only the captured numeric PID from a
// read-only audit record. The destination revalidates the current process, so
// a historical tagTIMER owner is never assumed to still be the same instance.
void OpenSelectedAuditProcess(WindowViewState* state) {
    const AuditEntry* entry = SelectedAuditEntry(state);
    if (!state || !entry || entry->relatedProcessId == 0U) {
        if (state) {
            state->statusText = L"审计快照没有可导航的 PID。";
            ::InvalidateRect(state->hwnd, nullptr, TRUE);
        }
        return;
    }
    const DWORD processId = entry->relatedProcessId;
    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::ProcessDetails;
    request.entity.kind = Ksword::Core::EntityKind::Process;
    request.entity.id = processId;
    const bool routed = Ksword::Ui::RequestEntityNavigation(state->hwnd, request);
    state->statusText = routed
        ? L"已请求打开快照 PID " + std::to_wstring(processId) + L" 的进程详情；历史定时器归属会重新校验。"
        : L"无法导航到该审计快照的当前进程实例。";
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

void OpenSelectedWindowImageDirectory(WindowViewState* state) {
    const WindowSnapshotRow* row = SelectedWindowSnapshot(state);
    if (!state || !row) {
        return;
    }
    const std::wstring directory =
        Ksword::Features::File::PathNavigator::parentDirectoryForKnownFilePath(row->processImagePath);
    if (directory.empty()) {
        state->statusText = L"窗口快照中的映像路径不是可精确导航的 DOS/UNC 文件路径。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }
    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::FileBrowser;
    request.entity.kind = Ksword::Core::EntityKind::File;
    request.entity.text = directory;
    const bool routed = Ksword::Ui::RequestEntityNavigation(state->hwnd, request);
    state->statusText = routed
        ? L"已在文件模块打开窗口映像所在目录。"
        : L"文件模块当前无法接收窗口映像所在目录。";
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// ShowWindowContextMenu exposes the retained Window page actions from the row
// itself. Inputs are page state and screen coordinates; processing selects the
// hit row when needed, groups detail/window actions into submenus, then
// dispatches the chosen menu command; no value is returned.
void ShowWindowContextMenu(WindowViewState* state, POINT screenPoint) {
    if (!state || !state->windowList) {
        return;
    }

    POINT clientPoint = screenPoint;
    ::ScreenToClient(state->windowList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int hitRow = ListView_SubItemHitTest(state->windowList, &hit);
    if (hitRow >= 0 && (ListView_GetItemState(state->windowList, hitRow, LVIS_SELECTED) & LVIS_SELECTED) == 0) {
        ListView_SetItemState(state->windowList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(state->windowList, hitRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ShowDetail(state, SelectedModelIndex(state));
    }
    if (hitRow >= 0) {
        state->contextColumn = hit.iSubItem;
    }

    const bool hasWindow = state->viewMode == WindowViewMode::WindowList && SelectedWindow(state) != nullptr;
    const bool hasRow = ListView_GetNextItem(state->windowList, -1, LVNI_SELECTED) >= 0;
    const bool hasDetailRows = state->detailList && ListView_GetItemCount(state->detailList) > 0;
    const WindowSnapshotRow* investigationRow = SelectedWindowSnapshot(state);
    const AuditEntry* auditInvestigationRow = SelectedAuditEntry(state);
    const bool canOpenProcess = (investigationRow != nullptr && investigationRow->processId != 0U) ||
        (auditInvestigationRow != nullptr && auditInvestigationRow->relatedProcessId != 0U);
    const bool canOpenImageDirectory = investigationRow != nullptr &&
        !Ksword::Features::File::PathNavigator::parentDirectoryForKnownFilePath(investigationRow->processImagePath).empty();
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    HMENU detailMenu = ::CreatePopupMenu();
    if (detailMenu) {
        ::AppendMenuW(detailMenu, MF_STRING | (hasWindow ? 0U : MF_GRAYED), kWindowMenuRefreshDetail, L"刷新详细信息");
        ::AppendMenuW(detailMenu, MF_STRING | (hasRow ? 0U : MF_GRAYED), kWindowMenuCopyDetail, L"复制详细信息");
        ::AppendMenuW(detailMenu, MF_STRING | (hasDetailRows ? 0U : MF_GRAYED), kWindowMenuExportDetail, L"导出当前详情为 TSV");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(detailMenu), L"详细信息");
    }
    HMENU operationMenu = ::CreatePopupMenu();
    if (operationMenu) {
        ::AppendMenuW(operationMenu, MF_STRING | (hasWindow ? 0U : MF_GRAYED), kWindowMenuFront, L"置前");
        ::AppendMenuW(operationMenu, MF_STRING | (hasWindow ? 0U : MF_GRAYED), kWindowMenuRestore, L"恢复");
        ::AppendMenuW(operationMenu, MF_STRING | (hasWindow ? 0U : MF_GRAYED), kWindowMenuMinimize, L"最小化");
        ::AppendMenuW(operationMenu, MF_STRING | (hasWindow ? 0U : MF_GRAYED), kWindowMenuMaximize, L"最大化");
        ::AppendMenuW(operationMenu, MF_STRING | (hasWindow ? 0U : MF_GRAYED), kWindowMenuClose, L"关闭窗口");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(operationMenu), L"窗口操作");
    }
    HMENU captureMenu = ::CreatePopupMenu();
    if (captureMenu) {
        const UINT enabled = hasWindow ? MF_ENABLED : MF_GRAYED;
        ::AppendMenuW(captureMenu, MF_STRING | enabled, kWindowMenuAllowCapture, L"允许窗口捕获");
        ::AppendMenuW(captureMenu, MF_STRING | enabled, kWindowMenuBlockCapture, L"阻止屏幕捕获");
        ::AppendMenuW(captureMenu, MF_STRING | enabled, kWindowMenuExcludeFromCapture, L"从捕获中排除");
        ::AppendMenuW(menu, MF_POPUP | enabled, reinterpret_cast<UINT_PTR>(captureMenu), L"窗口捕获保护");
    }
    HMENU investigationMenu = ::CreatePopupMenu();
    if (investigationMenu) {
        ::AppendMenuW(investigationMenu, MF_STRING | (canOpenProcess ? 0U : MF_GRAYED),
            kWindowMenuOpenProcess, L"打开当前 PID 的进程详情");
        ::AppendMenuW(investigationMenu, MF_STRING | (canOpenImageDirectory ? 0U : MF_GRAYED),
            kWindowMenuOpenImageDirectory, L"打开映像所在目录");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(investigationMenu), L"关联调查");
    }
    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        ::AppendMenuW(copyMenu, MF_STRING | (hasRow ? 0U : MF_GRAYED), kWindowMenuCopyCell, L"复制单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (hasRow ? 0U : MF_GRAYED), kWindowMenuCopyRow, L"复制行");
        ::AppendMenuW(copyMenu, MF_STRING | (!state->virtualList.visibleIndexes().empty() ? 0U : MF_GRAYED), kWindowMenuCopyVisible, L"复制可见结果");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    const UINT command = ::TrackPopupMenu(menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        state->hwnd,
        nullptr);
    ::DestroyMenu(menu);

    switch (command) {
    case kWindowMenuRefreshDetail:
        ShowDetail(state, SelectedModelIndex(state));
        state->statusText = L"Window detail refreshed.";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        break;
    case kWindowMenuCopyDetail:
        CopyCurrentDetail(state);
        break;
    case kWindowMenuExportDetail:
        ExportCurrentDetail(state);
        break;
    case kWindowMenuCopyCell:
        state->statusText = CopyText(state->hwnd, CopyVirtualCell(state)) ? L"已复制单元格。" : L"复制单元格失败。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        break;
    case kWindowMenuCopyRow:
        state->statusText = CopyText(state->hwnd, CopyVirtualRows(state, false)) ? L"已复制行。" : L"复制行失败。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        break;
    case kWindowMenuCopyVisible:
        state->statusText = CopyText(state->hwnd, CopyVirtualRows(state, true)) ? L"已复制可见结果。" : L"复制可见结果失败。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        break;
    case kWindowMenuFront:
        RunAction(state, kFrontButtonId);
        break;
    case kWindowMenuRestore:
        RunAction(state, kRestoreButtonId);
        break;
    case kWindowMenuMinimize:
        RunAction(state, kMinimizeButtonId);
        break;
    case kWindowMenuMaximize:
        RunAction(state, kMaximizeButtonId);
        break;
    case kWindowMenuClose:
        RunAction(state, kCloseButtonId);
        break;
    case kWindowMenuAllowCapture:
        SetCaptureProtection(state, WDA_NONE);
        break;
    case kWindowMenuBlockCapture:
        SetCaptureProtection(state, WDA_MONITOR);
        break;
    case kWindowMenuExcludeFromCapture:
        SetCaptureProtection(state, WDA_EXCLUDEFROMCAPTURE);
        break;
    case kWindowMenuOpenProcess:
        if (state && state->viewMode == WindowViewMode::WindowList) {
            OpenSelectedWindowProcess(state);
        } else {
            OpenSelectedAuditProcess(state);
        }
        break;
    case kWindowMenuOpenImageDirectory:
        OpenSelectedWindowImageDirectory(state);
        break;
    default:
        break;
    }
}

// LayoutView positions toolbar, list, and detail panes. Input is state; no value
// is returned after MoveWindow calls are issued.
void LayoutView(WindowViewState* state) {
    if (!state || !state->hwnd) {
        return;
    }
    RECT rc{};
    ::GetClientRect(state->hwnd, &rc);
    const int width = Width(rc);
    const int height = Height(rc);
    const int leftWidth = (std::max)(1, (width - kGap * 3) * 2 / 3);
    const int hierarchyLeft = kGap * 2 + leftWidth;
    const int hierarchyWidth = (std::max)(1, width - hierarchyLeft - kGap);
    int x = kGap;
    ::MoveWindow(state->auditModeCombo, x, kGap, 180, 160, TRUE); x += 186;
    ::MoveWindow(state->sortCombo, x, kGap, 150, 160, TRUE); x += 156;
    ::MoveWindow(state->refreshButton, x, kGap, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->exportButton, x, kGap, 78, 24, TRUE);

    x = kGap;
    const int actionY = kGap + 28;
    ::MoveWindow(state->frontButton, x, actionY, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->restoreButton, x, actionY, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->minimizeButton, x, actionY, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->maximizeButton, x, actionY, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->closeButton, x, actionY, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->filterBar, kGap, kGap * 3 + 48, leftWidth, 24, TRUE);

    const int detailHeight = height > 480 ? kDetailHeight : height / 3;
    const int listTop = kHeaderHeight + kGap;
    const int listHeight = (std::max)(0, height - listTop - detailHeight - (kGap * 2));
    ::MoveWindow(state->windowList, kGap, listTop, leftWidth, listHeight, TRUE);
    ::MoveWindow(state->detailList, kGap, listTop + listHeight + kGap, leftWidth, detailHeight, TRUE);
    ::MoveWindow(state->loadingOverlay, kGap, listTop, leftWidth, listHeight, TRUE);
    if (state->hierarchyReportView) {
        ::MoveWindow(state->hierarchyReportView, hierarchyLeft, kGap, hierarchyWidth,
            (std::max)(1, height - kGap * 2), TRUE);
    }
}

// CreateChildControls creates all native controls for the Window page. Inputs are
// state and parent HWND; output is true when every required HWND was created.
bool CreateChildControls(WindowViewState* state, HWND hwnd) {
    state->auditModeCombo = ::CreateWindowExW(0,
        L"COMBOBOX",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
        0,
        0,
        180,
        160,
        hwnd,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kAuditModeComboId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    state->sortCombo = ::CreateWindowExW(0,
        L"COMBOBOX",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
        0,
        0,
        150,
        160,
        hwnd,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSortComboId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    state->refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"Refresh", 0, 0, 78, 24);
    state->exportButton = Ksword::Ui::CreateButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 78, 24);
    state->frontButton = Ksword::Ui::CreateButton(hwnd, kFrontButtonId, L"Front", 0, 0, 78, 24);
    state->restoreButton = Ksword::Ui::CreateButton(hwnd, kRestoreButtonId, L"Restore", 0, 0, 78, 24);
    state->minimizeButton = Ksword::Ui::CreateButton(hwnd, kMinimizeButtonId, L"Minimize", 0, 0, 78, 24);
    state->maximizeButton = Ksword::Ui::CreateButton(hwnd, kMaximizeButtonId, L"Maximize", 0, 0, 78, 24);
    state->closeButton = Ksword::Ui::CreateButton(hwnd, kCloseButtonId, L"Close", 0, 0, 78, 24);
    state->filterBar = Ksword::Ui::CreateFilterBar(hwnd, kFilterBarId, L"筛选窗口、HWND、标题、类、状态和审计详情", 0, 0, 0, 0);
    if (!state->virtualList.create(hwnd, kWindowListId, 0, 0, 100, 100, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state->windowList = state->virtualList.hwnd();
    state->detailList = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
        0, 0, 100, 100, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDetailListId)), ::GetModuleHandleW(nullptr), nullptr);
    state->hierarchyReportView = WindowTools::CreateWindowHierarchyReportView(hwnd, { 0, 0, 1, 1 });
    if (!state->auditModeCombo || !state->sortCombo || !state->refreshButton || !state->exportButton || !state->frontButton || !state->restoreButton || !state->minimizeButton || !state->filterBar ||
        !state->maximizeButton || !state->closeButton || !state->windowList || !state->detailList || !state->hierarchyReportView) {
        return false;
    }

    ::SendMessageW(state->auditModeCombo, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    ::SendMessageW(state->auditModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"窗口列表"));
    ::SendMessageW(state->auditModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Win32K GUI 审计"));
    ::SendMessageW(state->auditModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Win32K 消息 Hook 审计"));
    ::SendMessageW(state->auditModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Win32K 定时器审计"));
    ::SendMessageW(state->auditModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"GPU/Display 审计"));
    ::SendMessageW(state->auditModeCombo, CB_SETCURSEL, 0, 0);
    ::SendMessageW(state->sortCombo, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    ::SendMessageW(state->sortCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"按堆叠顺序"));
    ::SendMessageW(state->sortCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"按进程顺序"));
    ::SendMessageW(state->sortCombo, CB_SETCURSEL, 0, 0);
    ::SendMessageW(state->windowList, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    ::SendMessageW(state->detailList, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    ListView_SetExtendedListViewStyle(state->windowList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    ListView_SetExtendedListViewStyle(state->detailList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    state->processImageList = ImageList_Create(::GetSystemMetrics(SM_CXSMICON),
        ::GetSystemMetrics(SM_CYSMICON),
        ILC_COLOR32 | ILC_MASK,
        64,
        64);
    if (state->processImageList != nullptr) {
        ListView_SetImageList(state->windowList, state->processImageList, LVSIL_SMALL);
    }
    state->virtualList.addColumns({
        { 0, 190, LVCFMT_LEFT, L"进程 / PID" },
        { 1, 120, LVCFMT_LEFT, L"HWND" },
        { 2, 300, LVCFMT_LEFT, L"Title" },
        { 3, 190, LVCFMT_LEFT, L"Class" },
        { 4, 220, LVCFMT_LEFT, L"State" },
    });
    AddColumn(state->detailList, 0, L"Property", 170);
    AddColumn(state->detailList, 1, L"Value", 720);
    state->loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    state->refreshTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<WindowRefreshSnapshot>>(hwnd, kMsgWindowRefreshCompleted);
    state->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<WindowFilterResult>>(hwnd, kMsgWindowFilterCompleted);
    state->detailTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<WindowDetailSnapshot>>(hwnd, kMsgWindowDetailCompleted);
    return true;
}

// RegisterWindowViewClass registers the custom Window feature page. There is no
// input beyond process module state; output is true when CreateWindowExW can use
// the class.
bool RegisterWindowViewClass() {
    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        WindowViewState* state = reinterpret_cast<WindowViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        switch (msg) {
        case WM_NCCREATE: {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<WindowViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
            return TRUE;
        }
        case WM_CREATE:
            if (state && CreateChildControls(state, hwnd)) {
                LayoutView(state);
                RefreshWindows(state);
            }
            return 0;
        case WM_SIZE:
            LayoutView(state);
            return 0;
        case WM_COMMAND: {
            const int id = LOWORD(wParam);
            if (id == kRefreshButtonId) {
                RefreshWindows(state);
                return 0;
            }
            if (id == kExportButtonId) {
                ExportVisibleRows(state);
                return 0;
            }
            if (id == kAuditModeComboId && HIWORD(wParam) == CBN_SELCHANGE) {
                UpdateViewModeFromCombo(state);
                return 0;
            }
            if (id == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
                RequestWindowFilter(state, Ksword::Ui::GetFilterBarText(state->filterBar));
                return 0;
            }
            if (id == kSortComboId && HIWORD(wParam) == CBN_SELCHANGE) {
                UpdateSortModeFromCombo(state);
                return 0;
            }
            if (id == kFrontButtonId || id == kRestoreButtonId || id == kMinimizeButtonId ||
                id == kMaximizeButtonId || id == kCloseButtonId) {
                RunAction(state, id);
                return 0;
            }
            break;
        }
        case kMsgWindowRefreshCompleted:
            if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgWindowFilterCompleted:
            if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgWindowDetailCompleted:
            if (state && state->detailTask && state->detailTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgExternalQuery:
            if (state && state->filterBar && lParam != 0) {
                const auto* query = reinterpret_cast<const std::wstring*>(lParam);
                Ksword::Ui::SetFilterBarText(state->filterBar, *query, false);
                RequestWindowFilter(state, *query);
                Ksword::Ui::FocusFilterBar(state->filterBar);
                return 1;
            }
            return 0;
        case WM_NOTIFY: {
            auto* notify = reinterpret_cast<NMHDR*>(lParam);
            if (state && notify && notify->idFrom == kWindowListId) {
                LRESULT result = 0;
                if (state->virtualList.handleNotify(*notify, result)) {
                    return result;
                }
            }
            if (state && notify && notify->idFrom == kWindowListId && notify->code == LVN_ITEMCHANGED) {
                auto* changed = reinterpret_cast<NMLISTVIEW*>(lParam);
                if ((changed->uNewState & LVIS_SELECTED) != 0) {
                    if (state->viewMode == WindowViewMode::WindowList) {
                        ShowDetail(state, SelectedModelIndex(state));
                    } else {
                        ShowAuditDetail(state, SelectedModelIndex(state));
                    }
                }
                return 0;
            }
            if (state && notify && notify->idFrom == kWindowListId && notify->code == NM_RCLICK) {
                POINT point{};
                ::GetCursorPos(&point);
                ShowWindowContextMenu(state, point);
                return 0;
            }
            break;
        }
        case WM_CONTEXTMENU:
            if (state && reinterpret_cast<HWND>(wParam) == state->windowList) {
                POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (point.x == -1 && point.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->windowList, &rc);
                    point = { rc.left + 20, rc.top + 20 };
                }
                ShowWindowContextMenu(state, point);
                return 0;
            }
            if (state && reinterpret_cast<HWND>(wParam) == state->detailList) {
                POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (point.x == -1 && point.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->detailList, &rc);
                    point = { rc.left + 20, rc.top + 20 };
                }
                ShowDetailContextMenu(state, point);
                return 0;
            }
            break;
        case WM_PAINT: {
            PAINTSTRUCT ps{};
            HDC dc = ::BeginPaint(hwnd, &ps);
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            ::FillRect(dc, &rc, Ksword::Ui::AppTheme().panelBrush());
            const int leftWidth = (std::max)(1, (Width(rc) - kGap * 3) * 2 / 3);
            RECT textRc{ 510, 7, kGap + leftWidth, kHeaderHeight };
            const std::wstring title = state ? state->statusText : L"Windows";
            Ksword::Ui::DrawTextLine(dc, title, textRc, Ksword::Ui::AppTheme().mutedTextColor,
                Ksword::Ui::SystemUIFont(), DT_SINGLELINE | DT_LEFT | DT_VCENTER);
            ::EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_DESTROY:
            if (state) {
                if (state->refreshTask) {
                    state->refreshTask->cancel();
                }
                if (state->filterTask) {
                    state->filterTask->cancel();
                }
                if (state->detailTask) {
                    state->detailTask->cancel();
                }
            }
            if (state && state->processImageList != nullptr) {
                ImageList_Destroy(state->processImageList);
                state->processImageList = nullptr;
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
    wc.hbrBackground = Ksword::Ui::AppTheme().panelBrush();
    wc.lpszClassName = kWindowViewClass;
    if (::RegisterClassW(&wc)) {
        return true;
    }
    return ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

} // namespace

HWND CreateWindowFeatureView(HWND parent, const RECT& bounds) {
    if (!parent || !RegisterWindowViewClass()) {
        return nullptr;
    }
    auto* state = new WindowViewState();
    HWND hwnd = ::CreateWindowExW(0, kWindowViewClass, L"Windows",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, Width(bounds), Height(bounds), parent, nullptr, ::GetModuleHandleW(nullptr), state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

bool RequestWindowFeatureViewQuery(HWND page, const std::wstring& query) {
    return page && !query.empty() &&
        ::SendMessageW(page, kMsgExternalQuery, 0, reinterpret_cast<LPARAM>(&query)) != 0;
}

} // namespace Ksword::Features::Window
