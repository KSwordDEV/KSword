#include "HandlePage.h"

#include "HandleClient.h"

#include "../../Core/Common.h"
#include "../../Core/EntityRef.h"

#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/TabUtil.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include "../../../shared/driver/KswordArkHandleIoctl.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cwctype>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace Ksword::Features::Handle {

constexpr wchar_t kHandlePageClass[] = L"KswordARKLight.HandlePage";
constexpr int kPidEditId = 57001;
constexpr int kRefreshButtonId = 57002;
constexpr int kStatusTextId = 57003;
constexpr int kTabId = 57004;
constexpr int kHandleListId = 57005;
constexpr int kDetailListId = 57006;
constexpr int kFilterBarId = 57007;
constexpr int kLoadingOverlayId = 57008;
constexpr int kHandleTabIndex = 0;
constexpr int kDetailTabIndex = 1;
constexpr UINT kHandleMenuCopyCell = 57101;
constexpr UINT kHandleMenuCopyRow = 57102;
constexpr UINT kHandleMenuCopyVisible = 57103;
constexpr UINT kHandleMenuOpenProcessDetails = 57104;
constexpr UINT kHandleMenuExportVisible = 57105;
constexpr UINT kMsgHandleRefreshCompleted = WM_APP + 574;
constexpr UINT kMsgHandleFilterCompleted = WM_APP + 575;
constexpr UINT kMsgHandleDetailCompleted = WM_APP + 576;
constexpr UINT kMsgExternalProcess = WM_APP + 577;

struct HandleFilterResult {
    std::uint64_t snapshotGeneration = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct HandleRefreshSnapshot {
    std::uint32_t processId = 0;
    std::uint64_t processCreationTime100ns = 0;
    bool identityMatched = false;
    HandleEnumView enumeration;
    std::vector<Ksword::Ui::VirtualListRow> rows;
};

struct HandleDetailTaskResult {
    std::uint64_t snapshotGeneration = 0;
    std::uint32_t processId = 0;
    std::uint64_t processCreationTime100ns = 0;
    std::uint64_t handleValue = 0;
    bool identityMatched = false;
    HandleObjectDetailView detail;
};

// HandlePageState stores query snapshots separately from HWND fields so the
// public header remains compact. Inputs are written by Refresh/PopulateDetail;
// output behavior is value ownership for page lifetime.
struct HandlePageState {
    HandleEnumView snapshot;
    std::uint32_t snapshotProcessId = 0;
    std::uint64_t snapshotProcessCreationTime100ns = 0;
    HandleObjectDetailView detail;
    Ksword::Ui::VirtualListView handleList;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::uint64_t snapshotGeneration = 0;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    int contextColumn = 0;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<HandleRefreshSnapshot>> refreshTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<HandleFilterResult>> filterTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<HandleDetailTaskResult>> detailTask;
};

namespace {

// Width returns a non-negative RECT width. Input is any RECT; output is pixels.
int Width(const RECT& rect) {
    return rect.right > rect.left ? rect.right - rect.left : 0;
}

// Height returns a non-negative RECT height. Input is any RECT; output is pixels.
int Height(const RECT& rect) {
    return rect.bottom > rect.top ? rect.bottom - rect.top : 0;
}

// Hex32 formats 32-bit diagnostics. Input is an integer; output is uppercase
// hexadecimal with 0x prefix for table display.
std::wstring Hex32(const std::uint32_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0') << value;
    return stream.str();
}

// Hex64 formats pointer-sized or 64-bit diagnostics. Input is an integer;
// output is uppercase hexadecimal with fixed 16-digit width.
std::wstring Hex64(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(16) << std::setfill(L'0') << value;
    return stream.str();
}

// NtStatusText formats signed NTSTATUS values as unsigned hex. Input is the
// status integer; output keeps success/failure codes readable.
std::wstring NtStatusText(const long status) {
    return Hex32(static_cast<std::uint32_t>(status));
}

// Utf8ToWide converts ArkDriverClient diagnostic strings to UTF-16. Input is a
// narrow string that is normally ASCII; processing uses byte-preserving widening;
// output is safe for Win32 controls.
std::wstring Utf8ToWide(const std::string& text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (const unsigned char ch : text) {
        wide.push_back(static_cast<wchar_t>(ch));
    }
    return wide;
}

// TryReadProcessCreationTime100ns returns the immutable process creation time
// from an already-opened process handle. The caller retains that handle while a
// PID-addressed driver request is in flight, preventing PID reuse.
bool TryReadProcessCreationTime100ns(HANDLE process, std::uint64_t& creationTime100nsOut) {
    creationTime100nsOut = 0;
    if (!process) {
        return false;
    }
    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (!::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
        return false;
    }
    creationTime100nsOut =
        (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U) |
        static_cast<std::uint64_t>(creationTime.dwLowDateTime);
    return creationTime100nsOut != 0U;
}

// BoolText returns a Chinese yes/no label. Input is a boolean; output is a
// stable UI string.
const wchar_t* BoolText(const bool value) {
    return value ? L"是" : L"否";
}

// DecodeStatusText maps handle-table decode status to readable labels. Input is
// KSWORD_ARK_HANDLE_DECODE_STATUS_*; output is a static UI label.
const wchar_t* DecodeStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_HANDLE_DECODE_STATUS_OK: return L"OK";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_DYNDATA_MISSING: return L"DynData缺失";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_LOOKUP_FAILED: return L"进程查找失败";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_EXITING: return L"进程退出中";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_HANDLE_TABLE_MISSING: return L"HandleTable缺失";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_OBJECT_DECODE_FAILED: return L"对象解码失败";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_TYPE_DECODE_FAILED: return L"类型解码失败";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_READ_FAILED: return L"读取失败";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_BUFFER_TOO_SMALL: return L"缓冲区不足";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_HEADER_DYNDATA_MISSING: return L"ObjectHeader偏移缺失";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_HEADER_READ_FAILED: return L"ObjectHeader读取失败";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_ACCESS_DECODE_FAILED: return L"访问掩码解码失败";
    default: return L"Unavailable";
    }
}

// QueryStatusText maps object-query status to readable labels. Input is
// KSWORD_ARK_OBJECT_QUERY_STATUS_*; output is a static UI label.
const wchar_t* QueryStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_OBJECT_QUERY_STATUS_OK: return L"OK";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_DYNDATA_MISSING: return L"DynData缺失";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_PROCESS_LOOKUP_FAILED: return L"进程查找失败";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_HANDLE_REFERENCE_FAILED: return L"句柄引用失败";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_TYPE_QUERY_FAILED: return L"类型查询失败";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_NAME_QUERY_FAILED: return L"名称查询失败";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_NAME_TRUNCATED: return L"名称截断";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_HEADER_DYNDATA_MISSING: return L"ObjectHeader偏移缺失";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_HEADER_QUERY_FAILED: return L"ObjectHeader查询失败";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_ACCESS_DECODE_FAILED: return L"访问掩码解码失败";
    default: return L"Unavailable";
    }
}

// FieldPresent checks one protocol field flag. Inputs are a flag bitmap and one
// KSWORD_ARK_HANDLE_FIELD_* bit; output says whether the field is present.
bool FieldPresent(const std::uint32_t flags, const std::uint32_t bit) {
    return (flags & bit) != 0U;
}

// DetailFieldPresent checks one object-query field flag. Inputs are a flag
// bitmap and one KSWORD_ARK_OBJECT_INFO_FIELD_* bit; output says field presence.
bool DetailFieldPresent(const std::uint32_t flags, const std::uint32_t bit) {
    return (flags & bit) != 0U;
}

// FieldText renders a present/missing marker. Input is a boolean; output is a
// short Chinese status value.
std::wstring FieldText(const bool present) {
    return present ? L"Present" : L"Missing";
}

// AnomalyText derives read-only risk labels from row diagnostics. Input is a
// parsed handle entry; output is a semicolon-separated label list for UI.
std::wstring AnomalyText(const HandleEntryView& entry) {
    std::vector<std::wstring> labels;
    if (entry.decodeStatus != KSWORD_ARK_HANDLE_DECODE_STATUS_OK) {
        labels.push_back(DecodeStatusText(entry.decodeStatus));
    }
    if (entry.objectAddress == 0 && FieldPresent(entry.fieldFlags, KSWORD_ARK_HANDLE_FIELD_OBJECT_PRESENT)) {
        labels.push_back(L"对象地址为空");
    }
    if (labels.empty()) {
        return L"";
    }
    std::wstring text;
    for (const std::wstring& label : labels) {
        if (!text.empty()) {
            text += L"; ";
        }
        text += label;
    }
    return text;
}

std::vector<Ksword::Ui::VirtualListRow> BuildVirtualHandleRows(const HandleEnumView& snapshot) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(snapshot.entries.size());
    for (std::size_t index = 0; index < snapshot.entries.size(); ++index) {
        const HandleEntryView& entry = snapshot.entries[index];
        Ksword::Ui::VirtualListRow row{};
        row.stableKey = std::to_wstring(entry.processId) + L":" + Hex32(entry.handleValue);
        row.itemData = static_cast<LPARAM>(index);
        row.cells = {
            std::to_wstring(entry.processId),
            Hex32(entry.handleValue),
            Hex64(entry.objectAddress),
            L"未公开",
            L"未公开",
            std::to_wstring(entry.objectTypeIndex),
            Hex32(entry.grantedAccess),
            Hex32(entry.attributes),
            L"未公开",
            L"未公开",
            DecodeStatusText(entry.decodeStatus),
            AnomalyText(entry),
        };
        // Detail-only diagnostic fields participate in the local snapshot
        // search without adding hidden columns or issuing another IOCTL.
        row.cells.push_back(Hex64(entry.dynDataCapabilityMask));
        row.cells.push_back(Hex32(entry.epObjectTableOffset));
        row.cells.push_back(Hex32(entry.htHandleContentionEventOffset));
        row.cells.push_back(Hex32(entry.fieldFlags));
        rows.push_back(std::move(row));
    }
    return rows;
}

// ReadPidEdit parses the PID edit box. Input is the edit HWND; processing
// accepts decimal text only; output is zero when parsing fails.
std::uint32_t ReadPidEdit(HWND edit) {
    wchar_t buffer[64]{};
    if (!edit || ::GetWindowTextW(edit, buffer, static_cast<int>(sizeof(buffer) / sizeof(buffer[0]))) <= 0) {
        return 0;
    }
    wchar_t* end = nullptr;
    const unsigned long value = std::wcstoul(buffer, &end, 10);
    while (end && *end != L'\0' && iswspace(*end)) {
        ++end;
    }
    if (!end || *end != L'\0' || value == 0UL || value > 0xFFFFFFFFUL) {
        return 0;
    }
    return static_cast<std::uint32_t>(value);
}

// RegisterHandlePageClass registers the window class once. There is no input;
// processing is idempotent; output reports whether CreateWindowExW may use it.
bool RegisterHandlePageClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = HandlePage::WindowProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    wc.lpszClassName = kHandlePageClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

// AddDetailRow appends one key/value/status row. Inputs are the ListView and
// display cells; processing appends a report row; no value is returned.
void AddDetailRow(HWND list, const std::wstring& name, const std::wstring& value, const std::wstring& status) {
    Ksword::Ui::InsertListViewTextRow(list, { name, value, status });
}

// InsertDetailColumns initializes the detail table columns. Input is the
// ListView HWND; processing inserts name/value/status columns; no return.
void InsertDetailColumns(HWND list) {
    Ksword::Ui::AddListViewColumns(list, {
        { 0, 210, LVCFMT_LEFT, L"字段" },
        { 1, 420, LVCFMT_LEFT, L"值" },
        { 2, 220, LVCFMT_LEFT, L"状态/来源" },
    });
}

bool CopyTextToClipboard(HWND owner, const std::wstring& text) {
    return Ksword::Ui::CopyTextToClipboard(owner, text, L"句柄审计");
}

void AppendTsvRow(std::wstring& output, const std::vector<std::wstring>& cells) {
    for (std::size_t column = 0; column < cells.size(); ++column) {
        if (column != 0) {
            output.push_back(L'\t');
        }
        for (const wchar_t ch : cells[column]) {
            output.push_back(ch == L'\t' || ch == L'\r' || ch == L'\n' ? L' ' : ch);
        }
    }
    output += L"\r\n";
}

std::wstring RowsAsTsv(const HandlePageState& state, const bool allVisible) {
    const HWND list = state.handleList.hwnd();
    const auto& visible = state.handleList.visibleIndexes();
    const auto& rows = state.handleList.rows();
    std::wstring output;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible && (!list || (ListView_GetItemState(list, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t source = visible[item];
        if (source < rows.size()) {
            AppendTsvRow(output, rows[source].cells);
        }
    }
    return output;
}

// VisibleHandleRowsAsTsv serializes exactly the twelve columns shown in the
// current filtered handle table. Input is the immutable rendered snapshot;
// processing never refreshes, resolves objects, or reads hidden diagnostics.
std::wstring VisibleHandleRowsAsTsv(const HandlePageState& state) {
    static const std::vector<std::wstring> kColumnTitles = {
        L"PID", L"Handle", L"Object", L"ObjectHeader", L"ObjectType", L"TypeIdx",
        L"GrantedAccess", L"Attributes", L"PtrCount", L"HandleCount", L"Decode", L"异常句柄标记"
    };
    const auto& visible = state.handleList.visibleIndexes();
    const auto& rows = state.handleList.rows();
    if (visible.empty()) {
        return {};
    }

    std::wstring output;
    AppendTsvRow(output, kColumnTitles);
    for (const std::size_t source : visible) {
        if (source >= rows.size()) {
            return {};
        }
        std::vector<std::wstring> cells(kColumnTitles.size());
        const std::vector<std::wstring>& rowCells = rows[source].cells;
        const std::size_t count = (std::min)(cells.size(), rowCells.size());
        for (std::size_t column = 0; column < count; ++column) {
            cells[column] = rowCells[column];
        }
        AppendTsvRow(output, cells);
    }
    return output;
}

std::wstring SelectedCellText(const HandlePageState& state) {
    const HWND list = state.handleList.hwnd();
    const int selected = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.handleList.visibleIndexes();
    const auto& rows = state.handleList.rows();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return {};
    }
    const std::size_t source = visible[static_cast<std::size_t>(selected)];
    if (source >= rows.size() || state.contextColumn < 0 || static_cast<std::size_t>(state.contextColumn) >= rows[source].cells.size()) {
        return {};
    }
    return rows[source].cells[static_cast<std::size_t>(state.contextColumn)];
}

int SelectedSnapshotIndex(const HandlePageState& state) {
    const HWND list = state.handleList.hwnd();
    const int selected = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.handleList.visibleIndexes();
    const auto& rows = state.handleList.rows();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return -1;
    }
    const std::size_t source = visible[static_cast<std::size_t>(selected)];
    if (source >= rows.size() || rows[source].itemData < 0) {
        return -1;
    }
    return static_cast<int>(rows[source].itemData);
}

// HasAuditedProcessIdentity accepts only the PID/creation-time pair retained
// from the successful HandleTable snapshot preflight. A PID alone is not
// sufficient because it could have been recycled after enumeration.
bool HasAuditedProcessIdentity(const HandlePageState& state) {
    return state.snapshotProcessId != 0U &&
        state.snapshotProcessCreationTime100ns != 0U;
}

std::wstring StableKeyAtVisibleIndex(const HandlePageState& state, const int visibleIndex) {
    const auto& visible = state.handleList.visibleIndexes();
    const auto& rows = state.handleList.rows();
    if (visibleIndex < 0 || static_cast<std::size_t>(visibleIndex) >= visible.size()) {
        return {};
    }
    const std::size_t source = visible[static_cast<std::size_t>(visibleIndex)];
    return source < rows.size() ? rows[source].stableKey : std::wstring{};
}

} // namespace

HWND HandlePage::Create(HWND parent, const RECT& bounds) {
    // Inputs are the dock parent and initial geometry. Processing registers the
    // class and allocates a page instance transferred to WM_NCDESTROY; output is
    // the child HWND or nullptr when registration/window creation fails.
    if (!parent || !RegisterHandlePageClass()) {
        return nullptr;
    }

    auto* page = new HandlePage();
    HWND hwnd = ::CreateWindowExW(
        0,
        kHandlePageClass,
        L"Handle",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        page);
    if (!hwnd) {
        delete page;
    }
    return hwnd;
}

bool HandlePage::SetProcessId(HWND page, const DWORD processId) {
    return page && processId != 0 &&
        ::SendMessageW(page, kMsgExternalProcess, static_cast<WPARAM>(processId), 0) != 0;
}

LRESULT CALLBACK HandlePage::WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    // Input is the raw Win32 message. Processing stores the page pointer during
    // WM_NCCREATE and delegates all later messages; output is an LRESULT for the
    // window manager.
    HandlePage* page = reinterpret_cast<HandlePage*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        page = create ? static_cast<HandlePage*>(create->lpCreateParams) : nullptr;
        if (page) {
            page->hwnd_ = hwnd;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
        }
    }
    if (page) {
        return page->HandleMessage(hwnd, message, wParam, lParam);
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool HandlePage::Initialize(HWND hwnd) {
    // Input is the newly created root HWND. Processing creates all controls once
    // and retains both tab pages for the page lifetime; output is false if a
    // critical control cannot be created.
    hwnd_ = hwnd;
    state_ = new HandlePageState();

    pidEdit_ = ::CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPidEditId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    refreshButton_ = Ksword::Ui::CreateButton(hwnd_, kRefreshButtonId, L"枚举PID句柄", 0, 0, 0, 0);
    statusText_ = Ksword::Ui::CreateText(hwnd_, kStatusTextId, L"输入 PID 后刷新；页面只读展示句柄证据。", 0, 0, 0, 0);
    filterBar_ = Ksword::Ui::CreateFilterBar(hwnd_, kFilterBarId, L"筛选 PID、句柄、对象、访问、状态和详情", 0, 0, 0, 0);
    tab_ = Ksword::Ui::CreateTabControl(hwnd_, kTabId, 0, 0, 0, 0);
    if (!pidEdit_ || !refreshButton_ || !statusText_ || !filterBar_ || !tab_) {
        return false;
    }

    ::SendMessageW(pidEdit_, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    Ksword::Ui::AddTabPage(tab_, kHandleTabIndex, { L"句柄表 cross-view" });
    Ksword::Ui::AddTabPage(tab_, kDetailTabIndex, { L"ObjectHeader / ObjectType" });
    ::SendMessageW(tab_, TCM_SETCURSEL, static_cast<WPARAM>(kHandleTabIndex), 0);
    currentTab_ = kHandleTabIndex;

    if (!state_->handleList.create(tab_, kHandleListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    handleList_ = state_->handleList.hwnd();
    detailList_ = Ksword::Ui::CreateReportListView(tab_, kDetailListId, 0, 0, 0, 0, 0);
    if (!handleList_ || !detailList_) {
        return false;
    }
    state_->handleList.addColumns({
        { 0, 80, LVCFMT_RIGHT, L"PID" },
        { 1, 90, LVCFMT_RIGHT, L"Handle" },
        { 2, 165, LVCFMT_LEFT, L"Object" },
        { 3, 165, LVCFMT_LEFT, L"ObjectHeader" },
        { 4, 165, LVCFMT_LEFT, L"ObjectType" },
        { 5, 70, LVCFMT_RIGHT, L"TypeIdx" },
        { 6, 110, LVCFMT_RIGHT, L"GrantedAccess" },
        { 7, 100, LVCFMT_RIGHT, L"Attributes" },
        { 8, 100, LVCFMT_RIGHT, L"PtrCount" },
        { 9, 100, LVCFMT_RIGHT, L"HandleCount" },
        { 10, 150, LVCFMT_LEFT, L"Decode" },
        { 11, 220, LVCFMT_LEFT, L"异常句柄标记" },
    });
    InsertDetailColumns(detailList_);
    ListView_SetExtendedListViewStyle(handleList_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

    AddDetailRow(detailList_, L"页面边界", L"只读审计", L"不提供关闭句柄/复制句柄/patch 操作");
    AddDetailRow(detailList_, L"输入", L"PID + 选中句柄行", L"R0 重新引用句柄，不信任对象地址作为操作凭据");
    AddDetailRow(detailList_, L"字段范围", L"ObjectHeader/ObjectType/GrantedAccess/Attributes/异常标记", L"来自现有 Handle IOCTL");

    loadingOverlay_ = Ksword::Ui::CreateLoadingOverlay(tab_, kLoadingOverlayId, { 0, 0, 1, 1 });
    state_->refreshTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<HandleRefreshSnapshot>>(hwnd_, kMsgHandleRefreshCompleted);
    state_->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<HandleFilterResult>>(hwnd_, kMsgHandleFilterCompleted);
    state_->detailTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<HandleDetailTaskResult>>(hwnd_, kMsgHandleDetailCompleted);

    Ksword::Ui::SetWindowFontRecursive(hwnd_);
    Layout();
    return true;
}

void HandlePage::Layout() {
    // Input is the current root client area. Processing positions the toolbar,
    // tab control and retained child pages; no value is returned.
    if (!hwnd_) {
        return;
    }
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const int width = std::max(100, Width(rc));
    const int height = std::max(100, Height(rc));
    const int margin = 8;
    const int toolbarHeight = 58;

    ::MoveWindow(pidEdit_, margin, margin, 120, 24, TRUE);
    ::MoveWindow(refreshButton_, margin + 128, margin, 112, 24, TRUE);
    ::MoveWindow(statusText_, margin + 252, margin + 3, std::max(100, width - margin - 252), 20, TRUE);
    ::MoveWindow(filterBar_, margin, margin + 28, std::max(100, width - margin * 2), 24, TRUE);

    const int tabTop = margin + toolbarHeight;
    ::MoveWindow(tab_, margin, tabTop, width - margin * 2, height - tabTop - margin, TRUE);
    RECT display = Ksword::Ui::GetTabDisplayRect(tab_);
    ::MoveWindow(handleList_, display.left, display.top, Width(display), Height(display), TRUE);
    ::MoveWindow(detailList_, display.left, display.top, Width(display), Height(display), TRUE);
    ::MoveWindow(loadingOverlay_, display.left, display.top, Width(display), Height(display), TRUE);
    ::ShowWindow(handleList_, currentTab_ == kHandleTabIndex ? SW_SHOW : SW_HIDE);
    ::ShowWindow(detailList_, currentTab_ == kDetailTabIndex ? SW_SHOW : SW_HIDE);
}

void HandlePage::Refresh() {
    // Input is the PID text box. The driver query runs on the snapshot worker;
    // the UI keeps the previous immutable list visible while it is refreshed.
    if (!state_) {
        return;
    }
    const std::uint32_t processId = ReadPidEdit(pidEdit_);
    if (processId == 0U) {
        SetStatus(L"请输入有效的十进制 PID。");
        return;
    }

    const bool firstLoad = state_->handleList.rows().empty();
    SetStatus(state_->refreshTask->running()
        ? L"句柄刷新已排队，等待当前快照完成…"
        : L"正在后台只读枚举 PID " + std::to_wstring(processId) + L" 的 HandleTable…");
    ::EnableWindow(refreshButton_, FALSE);
    if (firstLoad) {
        Ksword::Ui::SetLoadingOverlay(loadingOverlay_, true, L"正在加载句柄审计…");
    }
    state_->refreshTask->request(
        [processId] {
            HandleRefreshSnapshot snapshot{};
            snapshot.processId = processId;
            Ksword::Core::UniqueHandle process(::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                processId));
            if (!process.valid() ||
                !TryReadProcessCreationTime100ns(process.get(), snapshot.processCreationTime100ns)) {
                return snapshot;
            }
            snapshot.identityMatched = true;
            // Keep the verified process object alive until the PID-addressed
            // driver enumeration returns, so the PID cannot be recycled.
            snapshot.enumeration = HandleAuditClient{}.EnumerateProcessHandles(processId);
            snapshot.rows = BuildVirtualHandleRows(snapshot.enumeration);
            return snapshot;
        },
        [this](std::uint64_t, std::optional<HandleRefreshSnapshot>&& snapshot, std::exception_ptr error) {
            if (!state_) {
                return;
            }
            ::EnableWindow(refreshButton_, TRUE);
            Ksword::Ui::SetLoadingOverlay(loadingOverlay_, false);
            if (error || !snapshot.has_value()) {
                SetStatus(L"句柄后台枚举异常结束，请检查驱动状态与访问权限。");
                return;
            }
            const bool identityMatched = snapshot->identityMatched;
            const std::uint32_t snapshotProcessId = snapshot->processId;
            const std::uint64_t snapshotProcessCreationTime100ns = snapshot->processCreationTime100ns;
            state_->snapshot = std::move(snapshot->enumeration);
            state_->snapshotProcessId = identityMatched ? snapshotProcessId : 0U;
            state_->snapshotProcessCreationTime100ns = identityMatched
                ? snapshotProcessCreationTime100ns
                : 0U;
            state_->filterRows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>(std::move(snapshot->rows));
            ++state_->snapshotGeneration;
            PopulateList();
            const std::wstring message = Utf8ToWide(state_->snapshot.io.message);
            SetStatus(identityMatched && state_->snapshot.io.ok
                ? L"句柄枚举完成：返回 " + std::to_wstring(state_->snapshot.entries.size()) + L" 行；" + message
                : L"句柄枚举失败：" + message);
        });
}

void HandlePage::PopulateList() {
    // Input is the latest immutable handle snapshot. Rendering only installs
    // owner-data rows; local filtering is calculated later on the worker.
    if (!state_ || !handleList_) {
        return;
    }

    const std::wstring selectedStableKey = StableKeyAtVisibleIndex(*state_, ListView_GetNextItem(handleList_, -1, LVNI_SELECTED));
    const std::wstring topStableKey = StableKeyAtVisibleIndex(*state_, ListView_GetTopIndex(handleList_));
    if (!state_->filterRows) {
        return;
    }
    state_->handleList.setRows(*state_->filterRows);
    RequestFilter(filterBar_ ? Ksword::Ui::GetFilterBarText(filterBar_) : state_->filterQuery, selectedStableKey, topStableKey);
}

void HandlePage::RequestFilter(const std::wstring& query, std::wstring selectedStableKey, std::wstring topStableKey) {
    if (!state_ || !state_->filterTask || !state_->filterRows) {
        return;
    }
    state_->filterQuery = query;
    state_->filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(filterBar_);
    const std::uint64_t generation = state_->snapshotGeneration;
    const auto filterRows = state_->filterRows;
    const bool useRegex = state_->filterUseRegex;
    if (selectedStableKey.empty()) {
        selectedStableKey = StableKeyAtVisibleIndex(*state_, ListView_GetNextItem(handleList_, -1, LVNI_SELECTED));
    }
    if (topStableKey.empty()) {
        topStableKey = StableKeyAtVisibleIndex(*state_, ListView_GetTopIndex(handleList_));
    }
    state_->filterTask->request(
        [filterRows, generation, useRegex, query = state_->filterQuery, selectedStableKey = std::move(selectedStableKey), topStableKey = std::move(topStableKey)]() mutable {
            HandleFilterResult result{};
            result.snapshotGeneration = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*filterRows, result.query, useRegex);
            return result;
        },
        [this](std::uint64_t, std::optional<HandleFilterResult>&& result, std::exception_ptr error) {
            if (!state_ || error || !result.has_value()) {
                if (state_) {
                    SetStatus(L"句柄筛选异常结束，已保留当前可见结果。");
                }
                return;
            }
            if (result->snapshotGeneration == state_->snapshotGeneration && result->query == state_->filterQuery &&
                result->useRegex == state_->filterUseRegex) {
                state_->handleList.setVisibleIndexes(std::move(result->visibleIndexes));
                const auto& rows = state_->handleList.rows();
                const auto& visible = state_->handleList.visibleIndexes();
                for (std::size_t item = 0; item < visible.size(); ++item) {
                    const std::size_t source = visible[item];
                    if (!result->selectedStableKey.empty() && source < rows.size() && rows[source].stableKey == result->selectedStableKey) {
                        ListView_SetItemState(handleList_, static_cast<int>(item), LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    }
                    if (!result->topStableKey.empty() && source < rows.size() && rows[source].stableKey == result->topStableKey) {
                        ListView_EnsureVisible(handleList_, static_cast<int>(item), FALSE);
                    }
                }
            }
        });
}

void HandlePage::ShowHandleContextMenu(POINT screenPoint) {
    if (!state_ || !handleList_) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(handleList_, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int item = ListView_SubItemHitTest(handleList_, &hit);
    if (item >= 0) {
        state_->contextColumn = hit.iSubItem;
        ListView_SetItemState(handleList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(handleList_, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    const bool hasSelection = ListView_GetNextItem(handleList_, -1, LVNI_SELECTED) >= 0;
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kHandleMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kHandleMenuCopyRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING | (!state_->handleList.visibleIndexes().empty() ? 0U : MF_GRAYED), kHandleMenuCopyVisible, L"复制可见结果");
    ::AppendMenuW(menu, MF_STRING | (!state_->handleList.visibleIndexes().empty() ? 0U : MF_GRAYED), kHandleMenuExportVisible, L"导出当前可见句柄 TSV");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    const bool hasAuditedProcessIdentity = HasAuditedProcessIdentity(*state_);
    ::AppendMenuW(
        menu,
        MF_STRING | (hasAuditedProcessIdentity ? 0U : MF_GRAYED),
        kHandleMenuOpenProcessDetails,
        L"查看已审计进程详细信息");
    const UINT command = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    if (command == kHandleMenuCopyCell) {
        SetStatus(CopyTextToClipboard(hwnd_, SelectedCellText(*state_)) ? L"已复制单元格。" : L"复制单元格失败。");
    } else if (command == kHandleMenuCopyRow) {
        SetStatus(CopyTextToClipboard(hwnd_, RowsAsTsv(*state_, false)) ? L"已复制行。" : L"复制行失败。");
    } else if (command == kHandleMenuCopyVisible) {
        SetStatus(CopyTextToClipboard(hwnd_, RowsAsTsv(*state_, true)) ? L"已复制可见结果。" : L"复制可见结果失败。");
    } else if (command == kHandleMenuExportVisible) {
        const std::wstring text = VisibleHandleRowsAsTsv(*state_);
        if (text.empty()) {
            SetStatus(L"没有可导出的当前可见句柄快照。");
            return;
        }
        std::wstring error;
        switch (Ksword::Ui::SaveUtf8TextFileWithDialog(
            hwnd_, L"handle_visible_snapshot.tsv", L"导出当前可见句柄快照",
            L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", text, &error)) {
        case Ksword::Ui::SaveTextFileResult::Saved:
            SetStatus(L"当前可见句柄快照已导出为 TSV，并已记录到证据会话。");
            break;
        case Ksword::Ui::SaveTextFileResult::Cancelled:
            SetStatus(L"已取消导出当前可见句柄快照。");
            break;
        case Ksword::Ui::SaveTextFileResult::Failed:
            SetStatus(L"导出当前可见句柄快照失败：" + error);
            break;
        }
    } else if (command == kHandleMenuOpenProcessDetails) {
        // Revalidate after the popup closes so an intervening refresh cannot
        // turn an older PID into a navigation target.
        if (!HasAuditedProcessIdentity(*state_)) {
            SetStatus(L"没有可验证的进程身份，无法安全打开进程详细信息。");
            return;
        }
        Ksword::Core::NavigationRequest request{};
        request.target = Ksword::Core::NavigationTarget::ProcessDetails;
        request.entity.kind = Ksword::Core::EntityKind::Process;
        request.entity.id = state_->snapshotProcessId;
        request.entity.creationTime100ns = state_->snapshotProcessCreationTime100ns;
        const bool routed = Ksword::Ui::RequestEntityNavigation(hwnd_, request);
        SetStatus(routed
            ? L"已请求打开已审计 PID " + std::to_wstring(state_->snapshotProcessId) + L" 的进程详细信息。"
            : L"进程详细信息页未能接收该已审计进程身份。");
    }
}

void HandlePage::ShowDetailContextMenu(POINT screenPoint) {
    if (!detailList_) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(detailList_, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int item = ListView_SubItemHitTest(detailList_, &hit);
    if (item >= 0) {
        ListView_SetItemState(detailList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(detailList_, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    const bool hasSelection = ListView_GetNextItem(detailList_, -1, LVNI_SELECTED) >= 0;
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kHandleMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kHandleMenuCopyRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING, kHandleMenuCopyVisible, L"复制可见结果");
    const UINT command = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    std::wstring text;
    const int selected = ListView_GetNextItem(detailList_, -1, LVNI_SELECTED);
    const int rowCount = ListView_GetItemCount(detailList_);
    if (command == kHandleMenuCopyCell && selected >= 0) {
        wchar_t buffer[4096]{};
        ListView_GetItemText(detailList_, selected, std::max(0, hit.iSubItem), buffer, static_cast<int>(_countof(buffer)));
        text = buffer;
    } else if (command == kHandleMenuCopyRow && selected >= 0) {
        for (int column = 0; column < 3; ++column) {
            wchar_t buffer[4096]{};
            ListView_GetItemText(detailList_, selected, column, buffer, static_cast<int>(_countof(buffer)));
            if (column != 0) {
                text.push_back(L'\t');
            }
            text += buffer;
        }
    } else if (command == kHandleMenuCopyVisible) {
        for (int row = 0; row < rowCount; ++row) {
            for (int column = 0; column < 3; ++column) {
                wchar_t buffer[4096]{};
                ListView_GetItemText(detailList_, row, column, buffer, static_cast<int>(_countof(buffer)));
                if (column != 0) {
                    text.push_back(L'\t');
                }
                text += buffer;
            }
            text += L"\r\n";
        }
    }
    if (command != 0) {
        SetStatus(CopyTextToClipboard(hwnd_, text) ? L"已复制结果。" : L"复制结果失败。");
    }
}

void HandlePage::PopulateDetail(const int rowIndex) {
    // Input is a selected snapshot row. Object inspection runs on a separate
    // worker and is discarded when a newer handle snapshot replaces the row.
    if (!state_ || !detailList_ || rowIndex < 0 ||
        rowIndex >= static_cast<int>(state_->snapshot.entries.size())) {
        return;
    }
    const HandleEntryView entry = state_->snapshot.entries[static_cast<std::size_t>(rowIndex)];
    const std::uint32_t snapshotProcessId = state_->snapshotProcessId;
    const std::uint64_t snapshotProcessCreationTime100ns = state_->snapshotProcessCreationTime100ns;
    if (snapshotProcessId == 0U ||
        snapshotProcessCreationTime100ns == 0U ||
        entry.processId != snapshotProcessId) {
        SetStatus(L"句柄对象详情查询异常结束。");
        return;
    }

    Ksword::Ui::ScopedListViewRedrawLock lock(detailList_);
    ListView_DeleteAllItems(detailList_);
    AddDetailRow(detailList_, L"状态", L"正在后台查询 ObjectHeader/ObjectType…", L"可切换或关闭页面");

    const std::uint64_t snapshotGeneration = state_->snapshotGeneration;
    ::SendMessageW(tab_, TCM_SETCURSEL, static_cast<WPARAM>(kDetailTabIndex), 0);
    currentTab_ = kDetailTabIndex;
    Layout();
    SetStatus(L"正在后台读取句柄 " + Hex32(entry.handleValue) + L" 的对象详情…");
    state_->detailTask->request(
        [entry, snapshotGeneration, snapshotProcessCreationTime100ns] {
            HandleDetailTaskResult result{};
            result.snapshotGeneration = snapshotGeneration;
            result.processId = entry.processId;
            result.processCreationTime100ns = snapshotProcessCreationTime100ns;
            result.handleValue = entry.handleValue;
            Ksword::Core::UniqueHandle process(::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                entry.processId));
            std::uint64_t actualProcessCreationTime100ns = 0;
            if (!process.valid() ||
                !TryReadProcessCreationTime100ns(process.get(), actualProcessCreationTime100ns) ||
                actualProcessCreationTime100ns != snapshotProcessCreationTime100ns) {
                return result;
            }
            result.identityMatched = true;
            // Keep the verified source process alive while the driver resolves
            // the numeric handle value from its HandleTable.
            result.detail = HandleAuditClient{}.QueryHandleObject(entry.processId, entry.handleValue);
            return result;
        },
        [this, entry](std::uint64_t, std::optional<HandleDetailTaskResult>&& result, std::exception_ptr error) {
            if (!state_ || error || !result.has_value() || !result->identityMatched) {
                if (state_) {
                    SetStatus(L"句柄对象详情查询异常结束。");
                }
                return;
            }
            if (result->snapshotGeneration != state_->snapshotGeneration ||
                result->processId != entry.processId ||
                result->processId != state_->snapshotProcessId ||
                result->processCreationTime100ns != state_->snapshotProcessCreationTime100ns ||
                result->handleValue != entry.handleValue) {
                return;
            }
            state_->detail = std::move(result->detail);
            Ksword::Ui::ScopedListViewRedrawLock redrawLock(detailList_);
            ListView_DeleteAllItems(detailList_);
            const HandleObjectDetailView& detail = state_->detail;
            AddDetailRow(detailList_, L"Transport", detail.io.ok ? L"OK" : L"FAIL", Utf8ToWide(detail.io.message));
    AddDetailRow(detailList_, L"PID", std::to_wstring(entry.processId), L"查询输入");
    AddDetailRow(detailList_, L"Handle", Hex32(entry.handleValue), L"查询输入");
    AddDetailRow(detailList_, L"QueryStatus", QueryStatusText(detail.queryStatus), std::to_wstring(detail.queryStatus));
    AddDetailRow(detailList_, L"ObjectName", detail.objectName, L"ArkDriverClient 查询结果");
    AddDetailRow(detailList_, L"TypeName", detail.typeName, FieldText(DetailFieldPresent(detail.fieldFlags, KSWORD_ARK_OBJECT_INFO_FIELD_TYPE_NAME_PRESENT)));
    AddDetailRow(detailList_, L"Object", Hex64(detail.objectAddress), FieldText(DetailFieldPresent(detail.fieldFlags, KSWORD_ARK_OBJECT_INFO_FIELD_OBJECT_PRESENT)));
            AddDetailRow(detailList_, L"ObjectHeader", L"未公开", L"当前 ArkDriverClient 强类型结果未提供该字段");
            AddDetailRow(detailList_, L"ObjectType", L"未公开", L"当前 ArkDriverClient 强类型结果未提供该字段");
    AddDetailRow(detailList_, L"ObjectTypeIndex", std::to_wstring(detail.objectTypeIndex), L"ArkDriverClient 查询结果");
            AddDetailRow(detailList_, L"ObjectHeader 字段", L"未公开", L"等待 ArkDriverClient 强类型接口补齐");
    AddDetailRow(detailList_, L"GrantedAccess(enum)", Hex32(entry.grantedAccess), FieldText(FieldPresent(entry.fieldFlags, KSWORD_ARK_HANDLE_FIELD_GRANTED_ACCESS_PRESENT)));
    AddDetailRow(detailList_, L"ActualGrantedAccess(query)", Hex32(detail.actualGrantedAccess), L"不请求 proxy handle");
    AddDetailRow(detailList_, L"HandleAttributes", Hex32(entry.attributes), FieldText(FieldPresent(entry.fieldFlags, KSWORD_ARK_HANDLE_FIELD_ATTRIBUTES_PRESENT)));
    AddDetailRow(detailList_, L"FieldFlags", Hex32(detail.fieldFlags), L"KSWORD_ARK_OBJECT_INFO_FIELD_*");
    AddDetailRow(detailList_, L"DynDataCapabilityMask", Hex64(detail.dynDataCapabilityMask), L"capability gated");
    AddDetailRow(detailList_, L"OtNameOffset", Hex32(detail.otNameOffset), L"_OBJECT_TYPE.Name");
    AddDetailRow(detailList_, L"OtIndexOffset", Hex32(detail.otIndexOffset), L"_OBJECT_TYPE.Index");
    AddDetailRow(detailList_, L"ObjectReferenceStatus", NtStatusText(detail.objectReferenceStatus), L"ObReferenceObjectByHandle 路径");
    AddDetailRow(detailList_, L"TypeStatus", NtStatusText(detail.typeStatus), L"类型查询");
    AddDetailRow(detailList_, L"NameStatus", NtStatusText(detail.nameStatus), L"名称查询");
    AddDetailRow(detailList_, L"ProxyStatus", std::to_wstring(detail.proxyStatus), L"本页未请求 proxy handle");
    AddDetailRow(detailList_, L"ProxyHandleReturned", BoolText(detail.proxyHandle != 0), Hex64(detail.proxyHandle));
            if (detail.alpcQueried) {
                const auto addAlpcPort = [&](const wchar_t* relation, const ksword::ark::AlpcPortInfo& port) {
                    AddDetailRow(detailList_,
                        std::wstring(L"ALPC ") + relation,
                        port.portName.empty() ? Hex64(port.objectAddress) : port.portName,
                        L"object=" + Hex64(port.objectAddress) +
                            L"; ownerPid=" + std::to_wstring(port.ownerProcessId) +
                            L"; state=" + std::to_wstring(port.state) +
                            L"; flags=" + Hex32(port.flags));
                };
                AddDetailRow(detailList_,
                    L"ALPC Transport",
                    detail.alpc.io.ok ? L"OK" : L"FAIL",
                    Utf8ToWide(detail.alpc.io.message));
                AddDetailRow(detailList_, L"ALPC QueryStatus", std::to_wstring(detail.alpc.queryStatus),
                    L"fieldFlags=" + Hex32(detail.alpc.fieldFlags) +
                        L"; capability=" + Hex64(detail.alpc.dynDataCapabilityMask));
                addAlpcPort(L"Query", detail.alpc.queryPort);
                addAlpcPort(L"Connection", detail.alpc.connectionPort);
                addAlpcPort(L"Server", detail.alpc.serverPort);
                addAlpcPort(L"Client", detail.alpc.clientPort);
            }
            AddDetailRow(detailList_, L"异常句柄标记", AnomalyText(entry), L"只读提示，不做关闭/复制/patch");
            SetStatus(L"已读取句柄 " + Hex32(entry.handleValue) + L" 的 ObjectHeader/ObjectType 详情。");
        });
}

void HandlePage::SetStatus(const std::wstring& text) {
    // Input is a status message. Processing updates only the STATIC text control
    // and returns no value.
    if (statusText_) {
        ::SetWindowTextW(statusText_, text.c_str());
    }
}

LRESULT HandlePage::HandleMessage(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case kMsgExternalProcess:
        if (pidEdit_ && wParam != 0) {
            const std::wstring text = std::to_wstring(static_cast<DWORD>(wParam));
            ::SetWindowTextW(pidEdit_, text.c_str());
            Refresh();
            return TRUE;
        }
        return FALSE;
    case WM_CREATE:
        if (!Initialize(hwnd)) {
            return -1;
        }
        return 0;
    case WM_SIZE:
        Layout();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
            RequestFilter(Ksword::Ui::GetFilterBarText(filterBar_));
            return 0;
        }
        if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == kRefreshButtonId) {
            Refresh();
            return 0;
        }
        if (LOWORD(wParam) == kPidEditId && HIWORD(wParam) == EN_CHANGE) {
            SetStatus(L"PID 已更新，点击“枚举PID句柄”刷新。");
            return 0;
        }
        break;
    case kMsgHandleRefreshCompleted:
        if (state_ && state_->refreshTask && state_->refreshTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgHandleFilterCompleted:
        if (state_ && state_->filterTask && state_->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgHandleDetailCompleted:
        if (state_ && state_->detailTask && state_->detailTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_NOTIFY: {
        const auto* header = reinterpret_cast<const NMHDR*>(lParam);
        if (header && header->hwndFrom == tab_ && header->code == TCN_SELCHANGE) {
            const LRESULT selected = ::SendMessageW(tab_, TCM_GETCURSEL, 0, 0);
            if (selected >= 0) {
                currentTab_ = static_cast<int>(selected);
            }
            Layout();
            return 0;
        }
        if (header && header->hwndFrom == handleList_) {
            LRESULT result = 0;
            if (state_ && state_->handleList.handleNotify(*header, result)) {
                return result;
            }
        }
        if (header && header->hwndFrom == handleList_ &&
            (header->code == NM_DBLCLK || header->code == LVN_ITEMCHANGED)) {
            if (header->code == NM_DBLCLK) {
                PopulateDetail(state_ ? SelectedSnapshotIndex(*state_) : -1);
                return 0;
            }
            const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
            if (changed && (changed->uNewState & LVIS_SELECTED) != 0 &&
                (changed->uOldState & LVIS_SELECTED) == 0) {
                SetStatus(L"已选择句柄；双击行查看 ObjectHeader/ObjectType 详情。");
            }
        }
        break;
    }
    case WM_CONTEXTMENU:
        if (reinterpret_cast<HWND>(wParam) == handleList_) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (point.x == -1 && point.y == -1) {
                RECT rect{};
                ::GetWindowRect(handleList_, &rect);
                point = { rect.left + 16, rect.top + 16 };
            }
            ShowHandleContextMenu(point);
            return 0;
        }
        if (reinterpret_cast<HWND>(wParam) == detailList_) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (point.x == -1 && point.y == -1) {
                RECT rect{};
                ::GetWindowRect(detailList_, &rect);
                point = { rect.left + 16, rect.top + 16 };
            }
            ShowDetailContextMenu(point);
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
        if (state_) {
            if (state_->refreshTask) {
                state_->refreshTask->cancel();
            }
            if (state_->filterTask) {
                state_->filterTask->cancel();
            }
            if (state_->detailTask) {
                state_->detailTask->cancel();
            }
        }
        delete state_;
        state_ = nullptr;
        delete this;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

} // namespace Ksword::Features::Handle
