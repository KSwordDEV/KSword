#include "WindowToolsClipboardView.h"

#include "WindowToolsCommon.h"
#include "../../Core/EntityRef.h"
#include "../../Ui/Controls.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::WindowTools {
namespace {

constexpr wchar_t kClipboardViewClass[] = L"KswordARKLight.WindowTools.ClipboardView";

constexpr int kRefreshButtonId = 67001;
constexpr int kEmptyButtonId = 67002;
constexpr int kFilterBarId = 67003;
constexpr int kFormatListId = 67004;
constexpr int kDetailListId = 67005;
constexpr int kPreviewEditId = 67006;
constexpr int kExportButtonId = 67007;

constexpr UINT kMenuCopyRow = 67601;
constexpr UINT kMenuCopyVisible = 67602;
constexpr UINT kMenuCopyPreview = 67603;
constexpr UINT kMenuRefresh = 67604;
constexpr UINT kMenuOpenOwnerProcess = 67605;
constexpr UINT kMenuOpenClipboardProcess = 67606;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kBottomHeight = 210;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 5;

// kPreviewCharLimit caps how much text the preview pane holds. A clipboard can
// carry an entire document, and a single-line EDIT control degrades badly past a
// few hundred kilobytes; the truncation is reported in the pane so a short
// preview is never mistaken for short clipboard content.
constexpr std::size_t kPreviewCharLimit = 64 * 1024;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

// PredefinedFormat maps a CF_* constant to its SDK spelling. Registered formats
// are resolved at runtime with GetClipboardFormatNameW instead, which is why
// this table only needs the predefined range.
struct PredefinedFormat final {
    UINT format;
    const wchar_t* name;
};

constexpr PredefinedFormat kPredefinedFormats[] = {
    { CF_TEXT,            L"CF_TEXT" },
    { CF_BITMAP,          L"CF_BITMAP" },
    { CF_METAFILEPICT,    L"CF_METAFILEPICT" },
    { CF_SYLK,            L"CF_SYLK" },
    { CF_DIF,             L"CF_DIF" },
    { CF_TIFF,            L"CF_TIFF" },
    { CF_OEMTEXT,         L"CF_OEMTEXT" },
    { CF_DIB,             L"CF_DIB" },
    { CF_PALETTE,         L"CF_PALETTE" },
    { CF_PENDATA,         L"CF_PENDATA" },
    { CF_RIFF,            L"CF_RIFF" },
    { CF_WAVE,            L"CF_WAVE" },
    { CF_UNICODETEXT,     L"CF_UNICODETEXT" },
    { CF_ENHMETAFILE,     L"CF_ENHMETAFILE" },
    { CF_HDROP,           L"CF_HDROP" },
    { CF_LOCALE,          L"CF_LOCALE" },
    { CF_DIBV5,           L"CF_DIBV5" },
    { CF_OWNERDISPLAY,    L"CF_OWNERDISPLAY" },
    { CF_DSPTEXT,         L"CF_DSPTEXT" },
    { CF_DSPBITMAP,       L"CF_DSPBITMAP" },
    { CF_DSPMETAFILEPICT, L"CF_DSPMETAFILEPICT" },
    { CF_DSPENHMETAFILE,  L"CF_DSPENHMETAFILE" },
};

struct ClipboardFormatInfo final {
    UINT format = 0;
    std::wstring name;
    std::wstring category;
    std::wstring sizeText;
    std::wstring note;
    std::wstring preview;
};

struct ClipboardSnapshot final {
    bool opened = false;
    DWORD openError = 0;
    DWORD sequenceNumber = 0;
    int formatCount = 0;
    HWND owner = nullptr;
    HWND openerWindow = nullptr;
    HWND viewerWindow = nullptr;
    DWORD ownerProcessId = 0;
    std::wstring ownerTitle;
    std::wstring ownerClass;
    std::wstring ownerProcess;
    std::vector<ClipboardFormatInfo> formats;
};

struct ClipboardViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND emptyButton = nullptr;
    HWND filterBar = nullptr;
    HWND detailList = nullptr;
    HWND previewEdit = nullptr;
    Ksword::Ui::VirtualListView formatList;
    ClipboardSnapshot snapshot;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"点击刷新读取当前剪贴板内容。";
};

// ScopedClipboard holds the clipboard open for exactly one operation.
//
// OpenClipboard fails outright while another process holds the clipboard, and in
// practice that hold is the last few milliseconds of someone else's copy. A
// short bounded retry converts the common transient failure into a successful
// read; a longer wait would trade a rare real conflict -- which is worth
// reporting -- for a visible UI stall.
class ScopedClipboard final {
public:
    explicit ScopedClipboard(HWND owner) {
        constexpr int kAttempts = 4;
        for (int attempt = 0; attempt < kAttempts; ++attempt) {
            if (::OpenClipboard(owner)) {
                opened_ = true;
                return;
            }
            lastError_ = ::GetLastError();
            if (attempt + 1 < kAttempts) {
                ::Sleep(12);
            }
        }
    }

    ~ScopedClipboard() {
        if (opened_) {
            ::CloseClipboard();
        }
    }

    ScopedClipboard(const ScopedClipboard&) = delete;
    ScopedClipboard& operator=(const ScopedClipboard&) = delete;

    bool opened() const noexcept { return opened_; }
    DWORD lastError() const noexcept { return lastError_; }

private:
    bool opened_ = false;
    DWORD lastError_ = 0;
};

std::wstring PredefinedFormatName(const UINT format) {
    for (const PredefinedFormat& entry : kPredefinedFormats) {
        if (entry.format == format) {
            return entry.name;
        }
    }
    return {};
}

std::wstring FormatCategory(const UINT format) {
    if (format >= CF_PRIVATEFIRST && format <= CF_PRIVATELAST) {
        return L"私有格式";
    }
    if (format >= CF_GDIOBJFIRST && format <= CF_GDIOBJLAST) {
        return L"GDI 对象";
    }
    if (format >= 0xC000) {
        return L"注册格式";
    }
    return L"预定义";
}

// IsHandleBackedFormat reports whether the clipboard handle is a GDI or display
// handle rather than movable memory. GlobalSize on such a handle returns a
// meaningless value, so those rows report the kind of object instead of a size.
bool IsHandleBackedFormat(const UINT format) {
    switch (format) {
    case CF_BITMAP:
    case CF_DSPBITMAP:
    case CF_PALETTE:
    case CF_ENHMETAFILE:
    case CF_DSPENHMETAFILE:
    case CF_OWNERDISPLAY:
        return true;
    default:
        return format >= CF_GDIOBJFIRST && format <= CF_GDIOBJLAST;
    }
}

std::wstring ResolveFormatName(const UINT format) {
    const std::wstring predefined = PredefinedFormatName(format);
    if (!predefined.empty()) {
        return predefined;
    }
    wchar_t buffer[256]{};
    const int copied = ::GetClipboardFormatNameW(format, buffer, static_cast<int>(sizeof(buffer) / sizeof(buffer[0])));
    if (copied > 0) {
        return std::wstring(buffer, buffer + copied);
    }
    return L"(无名称)";
}

std::wstring ByteSizeText(const SIZE_T bytes) {
    std::wstring text = std::to_wstring(static_cast<std::uint64_t>(bytes)) + L" 字节";
    if (bytes >= 1024) {
        text += L"（约 " + std::to_wstring(static_cast<std::uint64_t>(bytes / 1024)) + L" KB）";
    }
    return text;
}

// ReadUnicodePreview copies CF_UNICODETEXT out of the clipboard. The clipboard
// must already be open and stays owned by the system: the returned handle is
// never freed here, and the text is copied before CloseClipboard because the
// handle is invalid the moment the clipboard closes.
std::wstring ReadUnicodePreview(bool& truncated) {
    truncated = false;
    HANDLE handle = ::GetClipboardData(CF_UNICODETEXT);
    if (!handle) {
        return {};
    }
    const auto* source = static_cast<const wchar_t*>(::GlobalLock(handle));
    if (!source) {
        return {};
    }
    const SIZE_T bytes = ::GlobalSize(handle);
    const std::size_t maxChars = bytes / sizeof(wchar_t);
    std::size_t length = 0;
    while (length < maxChars && source[length] != L'\0') {
        ++length;
    }
    if (length > kPreviewCharLimit) {
        length = kPreviewCharLimit;
        truncated = true;
    }
    std::wstring text(source, source + length);
    ::GlobalUnlock(handle);
    return text;
}

// ReadAnsiPreview copies CF_TEXT and widens it with the process ANSI code page.
// CF_TEXT carries no encoding of its own; CF_LOCALE can name one but almost
// nothing sets it, so CP_ACP is the code page the writer effectively used.
std::wstring ReadAnsiPreview(bool& truncated) {
    truncated = false;
    HANDLE handle = ::GetClipboardData(CF_TEXT);
    if (!handle) {
        return {};
    }
    const auto* source = static_cast<const char*>(::GlobalLock(handle));
    if (!source) {
        return {};
    }
    const SIZE_T bytes = ::GlobalSize(handle);
    std::size_t length = 0;
    while (length < bytes && source[length] != '\0') {
        ++length;
    }
    if (length > kPreviewCharLimit) {
        length = kPreviewCharLimit;
        truncated = true;
    }
    std::wstring text;
    if (length > 0) {
        const int required = ::MultiByteToWideChar(CP_ACP, 0, source, static_cast<int>(length), nullptr, 0);
        if (required > 0) {
            text.resize(static_cast<std::size_t>(required));
            ::MultiByteToWideChar(CP_ACP, 0, source, static_cast<int>(length), text.data(), required);
        }
    }
    ::GlobalUnlock(handle);
    return text;
}

// CaptureClipboardSnapshot reads the whole clipboard in one open/close pair.
//
// GetClipboardOwner, GetOpenClipboardWindow and GetClipboardSequenceNumber do
// not need the clipboard open, so they are read first and stay meaningful even
// when the open below fails -- that is exactly the case where the user wants to
// know who is holding it.
ClipboardSnapshot CaptureClipboardSnapshot(HWND owner) {
    ClipboardSnapshot snapshot;
    snapshot.sequenceNumber = ::GetClipboardSequenceNumber();
    snapshot.owner = ::GetClipboardOwner();
    snapshot.openerWindow = ::GetOpenClipboardWindow();
    snapshot.viewerWindow = ::GetClipboardViewer();
    snapshot.formatCount = ::CountClipboardFormats();
    if (snapshot.owner) {
        snapshot.ownerTitle = WindowTitleText(snapshot.owner);
        snapshot.ownerClass = WindowClassText(snapshot.owner);
        ::GetWindowThreadProcessId(snapshot.owner, &snapshot.ownerProcessId);
        snapshot.ownerProcess = ProcessNameFromId(snapshot.ownerProcessId);
    }

    ScopedClipboard clipboard(owner);
    if (!clipboard.opened()) {
        snapshot.openError = clipboard.lastError();
        return snapshot;
    }
    snapshot.opened = true;

    for (UINT format = ::EnumClipboardFormats(0); format != 0; format = ::EnumClipboardFormats(format)) {
        ClipboardFormatInfo info;
        info.format = format;
        info.name = ResolveFormatName(format);
        info.category = FormatCategory(format);

        if (IsHandleBackedFormat(format)) {
            info.sizeText = L"—";
            info.note = L"GDI / 显示句柄，非内存对象，无法用 GlobalSize 度量";
        } else {
            // GetClipboardData is what forces a delayed-rendered format to be
            // produced: the owner receives WM_RENDERFORMAT and renders it
            // synchronously. That is the price of reporting a real size, and it
            // means a hung clipboard owner can stall this read.
            HANDLE handle = ::GetClipboardData(format);
            if (handle) {
                info.sizeText = ByteSizeText(::GlobalSize(handle));
            } else {
                info.sizeText = L"—";
                info.note = L"GetClipboardData 返回空，通常是延迟渲染失败或所有者已退出";
            }
        }

        if (format == CF_UNICODETEXT || format == CF_TEXT) {
            bool truncated = false;
            info.preview = format == CF_UNICODETEXT ? ReadUnicodePreview(truncated) : ReadAnsiPreview(truncated);
            if (truncated) {
                info.preview += L"\r\n\r\n[预览已截断，仅显示前 " + std::to_wstring(kPreviewCharLimit) + L" 个字符]";
            }
            if (info.note.empty()) {
                info.note = L"可在下方预览文本内容";
            }
        }
        if (info.note.empty()) {
            info.note = L"二进制内容，本页不做解码";
        }
        snapshot.formats.push_back(std::move(info));
    }
    return snapshot;
}

// CurrentClipboardOwnerProcessId intentionally reads the owner HWND again at
// click time. The snapshot is useful evidence, but its HWND and PID can both be
// stale by the time the user opens process details.
DWORD CurrentClipboardOwnerProcessId() {
    const HWND owner = ::GetClipboardOwner();
    if (!owner || !::IsWindow(owner)) {
        return 0;
    }
    DWORD processId = 0;
    if (::GetWindowThreadProcessId(owner, &processId) == 0U || processId == 0U) {
        return 0;
    }
    return ::GetClipboardOwner() == owner ? processId : 0U;
}

// CurrentClipboardOpenProcessId follows the same live-read rule for the window
// currently holding OpenClipboard. That window is often the direct explanation
// for an unavailable snapshot, so it must not be confused with the data owner.
DWORD CurrentClipboardOpenProcessId() {
    const HWND opener = ::GetOpenClipboardWindow();
    if (!opener || !::IsWindow(opener)) {
        return 0;
    }
    DWORD processId = 0;
    if (::GetWindowThreadProcessId(opener, &processId) == 0U || processId == 0U) {
        return 0;
    }
    return ::GetOpenClipboardWindow() == opener ? processId : 0U;
}

void SetDetailText(HWND list, const int row, const int column, const std::wstring& text) {
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

void ShowOwnerDetail(ClipboardViewState& state) {
    if (!state.detailList) {
        return;
    }
    ListView_DeleteAllItems(state.detailList);
    const ClipboardSnapshot& snapshot = state.snapshot;

    std::vector<std::pair<std::wstring, std::wstring>> properties;
    properties.emplace_back(L"剪贴板序列号", std::to_wstring(snapshot.sequenceNumber));
    properties.emplace_back(L"格式数量", std::to_wstring(snapshot.formatCount));
    properties.emplace_back(L"占有者窗口", snapshot.owner ? HwndText(snapshot.owner) : L"(无，数据来源进程可能已退出)");
    if (snapshot.owner) {
        properties.emplace_back(L"占有者标题", snapshot.ownerTitle.empty() ? L"(无标题)" : snapshot.ownerTitle);
        properties.emplace_back(L"占有者类名", snapshot.ownerClass);
        properties.emplace_back(L"占有者进程", snapshot.ownerProcess + L"（PID " + std::to_wstring(snapshot.ownerProcessId) + L"）");
    }
    properties.emplace_back(L"当前打开剪贴板的窗口",
        snapshot.openerWindow ? DescribeWindowBrief(snapshot.openerWindow) : L"(无)");
    properties.emplace_back(L"剪贴板查看器链首",
        snapshot.viewerWindow ? DescribeWindowBrief(snapshot.viewerWindow) : L"(无)");
    properties.emplace_back(L"本次读取", snapshot.opened
        ? std::wstring(L"成功")
        : L"失败（OpenClipboard 错误码 " + std::to_wstring(snapshot.openError) + L"）");

    for (int row = 0; row < static_cast<int>(properties.size()); ++row) {
        SetDetailText(state.detailList, row, 0, properties[static_cast<std::size_t>(row)].first);
        SetDetailText(state.detailList, row, 1, properties[static_cast<std::size_t>(row)].second);
    }
}

int SelectedModelIndex(const ClipboardViewState& state) {
    const HWND list = state.formatList.hwnd();
    const int selected = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.formatList.visibleIndexes();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return -1;
    }
    const std::size_t modelIndex = visible[static_cast<std::size_t>(selected)];
    return modelIndex < state.snapshot.formats.size() ? static_cast<int>(modelIndex) : -1;
}

void ShowPreviewForSelection(ClipboardViewState& state) {
    if (!state.previewEdit) {
        return;
    }
    const int index = SelectedModelIndex(state);
    if (index < 0) {
        ::SetWindowTextW(state.previewEdit, L"在上方选择一个剪贴板格式。\r\n仅 CF_UNICODETEXT 与 CF_TEXT 可以显示文本预览。");
        return;
    }
    const ClipboardFormatInfo& info = state.snapshot.formats[static_cast<std::size_t>(index)];
    if (!info.preview.empty()) {
        ::SetWindowTextW(state.previewEdit, info.preview.c_str());
        return;
    }
    const std::wstring text = info.name + L"（" + HexText(info.format, 4) + L"）\r\n" +
        L"类别：" + info.category + L"\r\n" +
        L"数据大小：" + info.sizeText + L"\r\n" +
        L"说明：" + info.note;
    ::SetWindowTextW(state.previewEdit, text.c_str());
}

// SelectRowAtPoint makes row-scoped context commands operate on the row the
// user actually right-clicked, never on a stale selection left by filtering or
// keyboard navigation. A click on empty space deliberately leaves no row
// selected while keeping page-scoped actions available.
void SelectRowAtPoint(ClipboardViewState& state, const POINT screenPoint) {
    const HWND list = state.formatList.hwnd();
    if (!list) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(list, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int clickedItem = ListView_SubItemHitTest(list, &hit);
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    const auto& visible = state.formatList.visibleIndexes();
    if (clickedItem >= 0 && static_cast<std::size_t>(clickedItem) < visible.size()) {
        ListView_SetItemState(list, clickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    ShowPreviewForSelection(state);
}

// ApplyFilter runs on the UI thread on purpose. The row count here is the number
// of formats on the clipboard -- a few dozen at the very most -- so posting the
// work to a background task would cost more than the scan it replaces.
void ApplyFilter(ClipboardViewState& state) {
    if (!state.filterRows || !state.formatList.hwnd()) {
        return;
    }
    const std::wstring query = state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : std::wstring{};
    const bool useRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    state.formatList.setVisibleIndexes(
        Ksword::Ui::VirtualListView::FilterRowIndexes(*state.filterRows, query, useRegex));

    HWND list = state.formatList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (!state.formatList.visibleIndexes().empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    ShowPreviewForSelection(state);
}

void BuildRows(ClipboardViewState& state) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(state.snapshot.formats.size());
    for (std::size_t index = 0; index < state.snapshot.formats.size(); ++index) {
        const ClipboardFormatInfo& info = state.snapshot.formats[index];
        Ksword::Ui::VirtualListRow row{};
        row.stableKey = std::to_wstring(info.format);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        row.cells.push_back(HexText(info.format, 4) + L" (" + std::to_wstring(info.format) + L")");
        row.cells.push_back(info.name);
        row.cells.push_back(info.category);
        row.cells.push_back(info.sizeText);
        row.cells.push_back(info.note);
        rows.push_back(std::move(row));
    }
    auto shared = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>(std::move(rows));
    state.formatList.setRows(*shared);
    state.filterRows = std::move(shared);
}

void RefreshClipboard(ClipboardViewState& state) {
    state.snapshot = CaptureClipboardSnapshot(state.hwnd);
    BuildRows(state);
    ShowOwnerDetail(state);
    ApplyFilter(state);
    if (!state.snapshot.opened) {
        state.statusText = L"无法打开剪贴板（错误码 " + std::to_wstring(state.snapshot.openError) +
            L"）。通常是其他程序正持有剪贴板，请稍后重试。";
    } else {
        state.statusText = L"共 " + std::to_wstring(state.snapshot.formats.size()) + L" 种格式，序列号 " +
            std::to_wstring(state.snapshot.sequenceNumber) + L"。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void ExportVisibleRows(ClipboardViewState& state) {
    const std::wstring text = Ksword::Ui::BuildVisibleVirtualListTsv(
        { L"格式 ID", L"名称", L"类别", L"数据大小", L"说明" }, state.formatList);
    if (text.empty()) {
        state.statusText = L"没有可导出的可见结果。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (Ksword::Ui::SaveUtf8TextFileWithDialog(state.hwnd, L"clipboard_formats.tsv", L"导出剪贴板格式",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", text, &error)) {
    case Ksword::Ui::SaveTextFileResult::Saved: state.statusText = L"剪贴板可见结果已导出。"; break;
    case Ksword::Ui::SaveTextFileResult::Cancelled: state.statusText = L"已取消导出剪贴板结果。"; break;
    case Ksword::Ui::SaveTextFileResult::Failed: state.statusText = L"导出剪贴板结果失败：" + error; break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// OpenCurrentClipboardOwnerProcess routes only the live owner PID. The process
// page resolves that PID again, preserving the page's current-instance contract
// without requiring an additional source-side process handle or privilege.
void OpenCurrentClipboardOwnerProcess(ClipboardViewState& state) {
    const DWORD processId = CurrentClipboardOwnerProcessId();
    if (processId == 0U) {
        state.statusText = L"当前剪贴板没有可读取的占有者进程。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::ProcessDetails;
    request.entity.kind = Ksword::Core::EntityKind::Process;
    request.entity.id = processId;
    state.statusText = Ksword::Ui::RequestEntityNavigation(state.hwnd, request)
        ? L"已请求打开刚读取到的剪贴板占有者 PID " + std::to_wstring(processId) +
            L" 的进程详细信息；目标页会重新确认当前进程实例。"
        : L"无法导航到当前剪贴板占有者的进程实例。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// OpenCurrentClipboardProcess identifies only the window that has the clipboard
// open right now. It does not infer ownership from the last captured snapshot.
void OpenCurrentClipboardProcess(ClipboardViewState& state) {
    const DWORD processId = CurrentClipboardOpenProcessId();
    if (processId == 0U) {
        state.statusText = L"当前没有可读取的剪贴板打开者进程。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::ProcessDetails;
    request.entity.kind = Ksword::Core::EntityKind::Process;
    request.entity.id = processId;
    state.statusText = Ksword::Ui::RequestEntityNavigation(state.hwnd, request)
        ? L"已请求打开刚读取到的剪贴板打开者 PID " + std::to_wstring(processId) +
            L" 的进程详细信息；目标页会重新确认当前进程实例。"
        : L"无法导航到当前剪贴板打开者的进程实例。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// EmptyClipboardWithConfirm is the only destructive action on this page. The
// default button is 否 so a stray Enter cannot wipe the clipboard, and the
// prompt names the two consequences that are not obvious: the data cannot be
// recovered, and this window becomes the new clipboard owner afterwards.
void EmptyClipboardWithConfirm(ClipboardViewState& state) {
    const wchar_t* text =
        L"将清空系统剪贴板中的全部内容。\n\n"
        L"清空后原有数据无法恢复，正在依赖剪贴板的程序会立即失去可粘贴的数据。\n"
        L"操作完成后本窗口会成为剪贴板的新占有者。\n\n"
        L"是否继续？";
    if (::MessageBoxW(state.hwnd, text, L"清空剪贴板", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
        state.statusText = L"已取消清空剪贴板。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    bool emptied = false;
    DWORD error = 0;
    {
        ScopedClipboard clipboard(state.hwnd);
        if (clipboard.opened()) {
            emptied = ::EmptyClipboard() != FALSE;
            error = emptied ? 0 : ::GetLastError();
        } else {
            error = clipboard.lastError();
        }
    }

    RefreshClipboard(state);
    state.statusText = emptied
        ? std::wstring(L"剪贴板已清空。")
        : L"清空剪贴板失败（错误码 " + std::to_wstring(error) + L"）。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

std::wstring PreviewText(const ClipboardViewState& state) {
    const int length = state.previewEdit ? ::GetWindowTextLengthW(state.previewEdit) : 0;
    if (length <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(length), L'\0');
    ::GetWindowTextW(state.previewEdit, text.data(), length + 1);
    return text;
}

void ShowContextMenu(ClipboardViewState& state, const POINT screenPoint) {
    SelectRowAtPoint(state, screenPoint);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool hasSelection = SelectedModelIndex(state) >= 0;
    const bool hasCurrentOwnerProcess = CurrentClipboardOwnerProcessId() != 0U;
    const bool hasCurrentClipboardProcess = CurrentClipboardOpenProcessId() != 0U;
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyPreview, L"复制预览内容");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (hasCurrentOwnerProcess ? MF_ENABLED : MF_GRAYED),
        kMenuOpenOwnerProcess, L"查看当前剪贴板占有者进程的详细信息");
    ::AppendMenuW(menu, MF_STRING | (hasCurrentClipboardProcess ? MF_ENABLED : MF_GRAYED),
        kMenuOpenClipboardProcess, L"查看当前打开剪贴板的进程详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

    const int command = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    std::wstring message;
    switch (static_cast<UINT>(command)) {
    case kMenuCopyRow:
        message = CopyTextToClipboard(state.hwnd, RowsAsTsv(state.formatList, false, kColumnCount))
            ? L"已复制选中行。" : L"复制失败。";
        break;
    case kMenuCopyVisible:
        message = CopyTextToClipboard(state.hwnd, RowsAsTsv(state.formatList, true, kColumnCount))
            ? L"已复制可见行。" : L"复制失败。";
        break;
    case kMenuCopyPreview:
        message = CopyTextToClipboard(state.hwnd, PreviewText(state))
            ? L"已复制预览内容。" : L"复制失败。";
        break;
    case kMenuOpenOwnerProcess:
        OpenCurrentClipboardOwnerProcess(state);
        return;
    case kMenuOpenClipboardProcess:
        OpenCurrentClipboardProcess(state);
        return;
    case kMenuRefresh:
        RefreshClipboard(state);
        return;
    default:
        return;
    }

    // Copying writes to the clipboard this page inspects, so the table on screen
    // is stale the instant the copy succeeds. The refresh runs first and the
    // copy result is written afterwards, otherwise the refresh status would
    // overwrite the message the user actually asked for.
    RefreshClipboard(state);
    state.statusText = std::move(message);
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void LayoutView(ClipboardViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);

    int cursorX = kGap;
    const auto place = [&cursorX](HWND control, const int controlWidth) {
        if (control) {
            ::MoveWindow(control, cursorX, kGap, controlWidth, kRowHeight, TRUE);
        }
        cursorX += controlWidth + kGap;
    };
    place(state.refreshButton, 64);
    place(state.exportButton, 78);
    place(state.emptyButton, 110);

    const int secondRowY = kGap * 2 + kRowHeight;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, secondRowY, (std::max)(120, width - kGap * 2), kRowHeight, TRUE);
    }

    const int listTop = kHeaderHeight;
    const int bottomTop = (std::max)(listTop, height - kStatusHeight - kBottomHeight);
    const int listHeight = (std::max)(0, bottomTop - listTop - kGap);
    if (HWND list = state.formatList.hwnd()) {
        ::MoveWindow(list, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }

    const int bottomHeight = (std::max)(0, height - kStatusHeight - bottomTop - kGap);
    const int detailWidth = (std::max)(120, (width - kGap * 3) / 2);
    if (state.detailList) {
        ::MoveWindow(state.detailList, kGap, bottomTop, detailWidth, bottomHeight, TRUE);
    }
    if (state.previewEdit) {
        const int previewLeft = kGap * 2 + detailWidth;
        ::MoveWindow(state.previewEdit, previewLeft, bottomTop,
            (std::max)(0, width - previewLeft - kGap), bottomHeight, TRUE);
    }
}

bool CreateChildControls(ClipboardViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = Ksword::Ui::CreateButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.emptyButton = Ksword::Ui::CreateButton(hwnd, kEmptyButtonId, L"清空剪贴板", 0, 0, 0, 0);
    state.filterBar = Ksword::Ui::CreateFilterBar(hwnd, kFilterBarId, L"筛选格式 ID、名称、类别与说明", 0, 0, 0, 0);
    if (!state.refreshButton || !state.exportButton || !state.emptyButton || !state.filterBar) {
        return false;
    }

    if (!state.formatList.create(hwnd, kFormatListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.formatList.addColumns({
        { 0, 130, LVCFMT_LEFT, L"格式 ID" },
        { 1, 220, LVCFMT_LEFT, L"名称" },
        { 2, 90,  LVCFMT_LEFT, L"类别" },
        { 3, 150, LVCFMT_LEFT, L"数据大小" },
        { 4, 380, LVCFMT_LEFT, L"说明" },
    });
    if (HWND list = state.formatList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    }

    state.detailList = Ksword::Ui::CreateReportListView(hwnd, kDetailListId, 0, 0, 1, 1, LVS_SINGLESEL);
    if (!state.detailList) {
        return false;
    }
    Ksword::Ui::AddListViewColumns(state.detailList, {
        { 0, 170, LVCFMT_LEFT, L"属性" },
        { 1, 420, LVCFMT_LEFT, L"值" },
    });
    ListView_SetExtendedListViewStyle(state.detailList,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

    state.previewEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 1, 1, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPreviewEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.previewEdit) {
        return false;
    }
    Ksword::Ui::AttachTextFindSupport(state.previewEdit);

    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK ClipboardViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<ClipboardViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<ClipboardViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            LayoutView(*state);
            RefreshClipboard(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (state) {
            const int id = LOWORD(wParam);
            const int notification = HIWORD(wParam);
            if (id == kFilterBarId && notification == EN_CHANGE) {
                ApplyFilter(*state);
                return 0;
            }
            if (notification == BN_CLICKED) {
                if (id == kRefreshButtonId) {
                    RefreshClipboard(*state);
                    return 0;
                }
                if (id == kExportButtonId) {
                    ExportVisibleRows(*state);
                    return 0;
                }
                if (id == kEmptyButtonId) {
                    EmptyClipboardWithConfirm(*state);
                    return 0;
                }
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->formatList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->formatList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        ShowPreviewForSelection(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->formatList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    ShowContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
    case WM_CTLCOLORSTATIC: {
        // A read-only EDIT reports itself through WM_CTLCOLORSTATIC. It gets the
        // panel color rather than the window color so a long preview reads as a
        // content pane instead of dissolving into the page background.
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        if (state && reinterpret_cast<HWND>(lParam) == state->previewEdit) {
            ::SetBkColor(dc, Ksword::Ui::AppTheme().panelColor);
            return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().panelBrush());
        }
        ::SetBkMode(dc, TRANSPARENT);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    }
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
    case WM_NCDESTROY:
        if (state) {
            state->formatList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureClipboardViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = ClipboardViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kClipboardViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateClipboardInspectorView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureClipboardViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kClipboardViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::WindowTools
