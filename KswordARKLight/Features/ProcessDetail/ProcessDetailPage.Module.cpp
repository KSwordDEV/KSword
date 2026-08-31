#include "ProcessDetailPage.h"
#include "../../Core/Common.h"
#include "../../Ui/FilterBar.h"

#include "../../Ui/Controls.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/NumericSortKey.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"

#include <commctrl.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace Ksword::Features::ProcessDetail {
namespace {

constexpr UINT kModuleMenuCopyCell = 64101;
constexpr UINT kModuleMenuCopyRow = 64102;
constexpr UINT kModuleMenuDetail = 64103;
constexpr UINT kModuleMenuOpenFolder = 64104;
constexpr UINT kModuleMenuUnload = 64105;
constexpr UINT kModuleMenuSuspendThread = 64106;
constexpr UINT kModuleMenuResumeThread = 64107;
constexpr UINT kModuleMenuTerminateThread = 64108;

constexpr UINT_PTR kModulePageVisualSubclassId = 0x4D4F4455U; // "MODU"
constexpr UINT_PTR kModuleHeaderSubclassId = 0x4D4F4448U;     // "MODH"
constexpr UINT_PTR kModuleStatusSubclassId = 0x4D4F4453U;     // "MODS"

constexpr wchar_t kModuleDetailClass[] = L"KswordARKLight.ProcessDetail.ModuleDetail";
constexpr int kModuleDetailSummaryId = 65101;
constexpr int kModuleDetailEditId = 65102;
constexpr int kModuleDetailCopyId = 65103;
constexpr int kModuleDetailOpenFolderId = 65104;
constexpr int kModuleDetailCloseId = 65105;

struct ModuleDetailDialogState {
    HWND hwnd = nullptr;
    HWND summary = nullptr;
    HWND edit = nullptr;
    HWND copyButton = nullptr;
    HWND openFolderButton = nullptr;
    HWND closeButton = nullptr;
    std::wstring summaryText;
    std::wstring detailText;
    std::wstring modulePath;
};

// ReadControlText returns one native control's complete UTF-16 text. The
// caller owns the returned value and no HWND lifetime is retained.
std::wstring ReadControlText(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int length = ::GetWindowTextLengthW(hwnd);
    std::wstring text(static_cast<std::size_t>(std::max(0, length)) + 1U, L'\0');
    ::GetWindowTextW(hwnd, text.data(), static_cast<int>(text.size()));
    text.resize(std::wcslen(text.c_str()));
    return text;
}

// ReadListCell is the module-local equivalent of the root list helper. It is
// used by native header sorting and custom draw callbacks that are not class
// members and therefore cannot access private ProcessDetailPage helpers.
std::wstring ReadListCell(HWND list, int row, int column) {
    if (!list || row < 0 || column < 0) {
        return {};
    }
    std::vector<wchar_t> buffer(8192U, L'\0');
    ListView_GetItemText(list, row, column, buffer.data(), static_cast<int>(buffer.size()));
    return buffer.data();
}

// SelectedSnapshotIndex returns the stable snapshot index stored in LVITEM's
// lParam. Sorting changes visual row order but never changes this identity.
std::size_t SelectedSnapshotIndex(HWND list) {
    if (!list) {
        return static_cast<std::size_t>(-1);
    }
    const int row = ListView_GetNextItem(list, -1, LVNI_SELECTED);
    if (row < 0) {
        return static_cast<std::size_t>(-1);
    }
    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = row;
    if (!ListView_GetItem(list, &item) || item.lParam < 0) {
        return static_cast<std::size_t>(-1);
    }
    return static_cast<std::size_t>(item.lParam);
}

std::wstring BaseNameFromPath(const std::wstring& path) {
    const std::size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos || separator + 1U >= path.size()) {
        return path;
    }
    return path.substr(separator + 1U);
}

std::wstring FormatHex(std::uintptr_t value) {
    std::wostringstream text;
    text << L"0x" << std::uppercase << std::hex << value;
    return text.str();
}

std::wstring FormatModuleSize(DWORD bytes) {
    const double kilobytes = static_cast<double>(bytes) / 1024.0;
    std::wostringstream text;
    if (kilobytes < 1024.0) {
        text << std::fixed << std::setprecision(1) << kilobytes << L" KB";
    } else {
        text << std::fixed << std::setprecision(2) << (kilobytes / 1024.0) << L" MB";
    }
    return text.str();
}

std::wstring ModuleSignatureText(bool requested) {
    // The frozen ProcessModuleInfo model has no signature result field. Make
    // that boundary explicit instead of presenting the collector status as a
    // cryptographic trust decision.
    return requested ? L"Unavailable" : L"Pending";
}

std::wstring ModuleRunningState(const ProcessModuleInfo& module) {
    return module.statusText == L"OK" ? L"Loaded" : L"Unknown";
}

std::wstring ModuleThreadText(const ProcessModuleInfo& module) {
    return module.representativeThreadId == 0
        ? L"-"
        : std::to_wstring(module.representativeThreadId);
}

std::wstring LastErrorText(const wchar_t* operation, DWORD error) {
    wchar_t* systemText = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    ::FormatMessageW(
        flags,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&systemText),
        0,
        nullptr);
    std::wstring result = operation ? operation : L"Win32 operation";
    result += L" failed";
    if (systemText) {
        result += L": ";
        result += systemText;
        while (!result.empty() &&
               (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
            result.pop_back();
        }
        ::LocalFree(systemText);
    } else {
        result += L" (" + std::to_wstring(error) + L")";
    }
    return result;
}

bool WriteClipboardText(HWND owner, const std::wstring& text) {
    return Ksword::Ui::CopyTextToClipboard(owner, text, L"进程模块详情");
}

bool OpenFolderAndSelectPath(HWND owner, const std::wstring& path) {
    if (path.empty() || path.front() == L'<') {
        return false;
    }
    const std::wstring parameters = L"/select,\"" + path + L"\"";
    const HINSTANCE result = ::ShellExecuteW(
        owner,
        L"open",
        L"explorer.exe",
        parameters.c_str(),
        nullptr,
        SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(result) > 32;
}

void UpdateSortIndicator(HWND list, int sortColumn, bool descending) {
    HWND header = list ? ListView_GetHeader(list) : nullptr;
    const int count = header ? Header_GetItemCount(header) : 0;
    for (int index = 0; index < count; ++index) {
        HDITEMW item{};
        item.mask = HDI_FORMAT;
        if (!Header_GetItem(header, index, &item)) {
            continue;
        }
        item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (index == sortColumn) {
            item.fmt |= descending ? HDF_SORTDOWN : HDF_SORTUP;
        }
        Header_SetItem(header, index, &item);
    }
}

COLORREF SignatureColor(const std::wstring& text) {
    if (text == L"Pending" || text == L"Unknown" || text == L"Unavailable" || text.empty()) {
        return Ksword::Ui::AppTheme().mutedTextColor;
    }
    if (text.find(L"Trusted") != std::wstring::npos ||
        text.find(L"Valid") != std::wstring::npos ||
        text.find(L"可信") != std::wstring::npos ||
        text.find(L"有效") != std::wstring::npos) {
        return RGB(24, 128, 56);
    }
    return RGB(196, 43, 28);
}

LRESULT CALLBACK ModulePageVisualSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR referenceData) {
    HWND moduleList = reinterpret_cast<HWND>(referenceData);
    if (message == WM_NOTIFY) {
        auto* header = reinterpret_cast<NMHDR*>(lParam);
        if (header && header->hwndFrom == moduleList && header->code == NM_CUSTOMDRAW) {
            auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
            const DWORD stage = draw->nmcd.dwDrawStage;
            if (stage == CDDS_PREPAINT) {
                return CDRF_NOTIFYITEMDRAW;
            }
            if (stage == CDDS_ITEMPREPAINT) {
                return CDRF_NOTIFYSUBITEMDRAW;
            }
            if (stage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
                const bool selected = (draw->nmcd.uItemState & CDIS_SELECTED) != 0;
                if (selected) {
                    draw->clrText = ::GetSysColor(COLOR_HIGHLIGHTTEXT);
                    draw->clrTextBk = ::GetSysColor(COLOR_HIGHLIGHT);
                } else {
                    draw->clrText = Ksword::Ui::AppTheme().textColor;
                    draw->clrTextBk = (draw->nmcd.dwItemSpec % 2U) == 0U
                        ? Ksword::Ui::AppTheme().panelColor
                        : Ksword::Ui::AppTheme().windowColor;
                    if (draw->iSubItem == 2) {
                        draw->clrText = SignatureColor(ReadListCell(
                            moduleList,
                            static_cast<int>(draw->nmcd.dwItemSpec),
                            2));
                    }
                }
                return CDRF_NEWFONT;
            }
        }
    }
    if (message == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, ModulePageVisualSubclassProc, subclassId);
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK ModuleStatusSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR referenceData) {
    (void)referenceData;
    if (message == WM_SETTEXT) {
        const LRESULT result = ::DefSubclassProc(hwnd, message, wParam, lParam);
        ::InvalidateRect(hwnd, nullptr, TRUE);
        return result;
    }
    if (message == WM_ERASEBKGND) {
        return 1;
    }
    if (message == WM_PAINT) {
        PAINTSTRUCT paint{};
        HDC dc = ::BeginPaint(hwnd, &paint);
        RECT client{};
        ::GetClientRect(hwnd, &client);
        ::FillRect(dc, &client, Ksword::Ui::AppTheme().windowBrush());
        ::SetBkMode(dc, TRANSPARENT);
        const std::wstring text = ReadControlText(hwnd);
        COLORREF color = RGB(24, 128, 56);
        if (text.find(L"正在") != std::wstring::npos) {
            color = Ksword::Ui::AppTheme().accentColor;
        } else if (text.find(L"失败") != std::wstring::npos ||
                   text.find(L"模块:0") != std::wstring::npos) {
            color = RGB(196, 43, 28);
        } else if (text.find(L"等待") != std::wstring::npos) {
            color = Ksword::Ui::AppTheme().mutedTextColor;
        }
        ::SetTextColor(dc, color);
        HFONT font = reinterpret_cast<HFONT>(::SendMessageW(hwnd, WM_GETFONT, 0, 0));
        HGDIOBJ oldFont = font ? ::SelectObject(dc, font) : nullptr;
        ::DrawTextW(
            dc,
            text.c_str(),
            static_cast<int>(text.size()),
            &client,
            DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        if (oldFont) {
            ::SelectObject(dc, oldFont);
        }
        ::EndPaint(hwnd, &paint);
        return 0;
    }
    if (message == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, ModuleStatusSubclassProc, subclassId);
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

int SystemIconIndexForPath(const std::wstring& path, HIMAGELIST* imageListOut) {
    SHFILEINFOW info{};
    UINT flags = SHGFI_SYSICONINDEX | SHGFI_SMALLICON;
    DWORD attributes = 0;
    if (path.empty() || path.front() == L'<') {
        flags |= SHGFI_USEFILEATTRIBUTES;
        attributes = FILE_ATTRIBUTE_NORMAL;
    }
    const DWORD_PTR result = ::SHGetFileInfoW(
        path.empty() ? L"module.dll" : path.c_str(),
        attributes,
        &info,
        sizeof(info),
        flags);
    if (imageListOut && result != 0) {
        *imageListOut = reinterpret_cast<HIMAGELIST>(result);
    }
    return result != 0 ? info.iIcon : -1;
}

std::vector<Ksword::Ui::VirtualListRow> BuildModuleVirtualRows(
    const std::vector<ProcessModuleInfo>& modules,
    const bool verifySignatures,
    const int sortColumn,
    const bool sortDescending,
    HIMAGELIST& imageListOut) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(modules.size());
    for (std::size_t index = 0; index < modules.size(); ++index) {
        const ProcessModuleInfo& module = modules[index];
        Ksword::Ui::VirtualListRow row{};
        row.stableKey = module.modulePath + L"\n" + FormatHex(module.baseAddress);
        row.itemData = static_cast<LPARAM>(index);
        row.cells = {
            module.modulePath,
            FormatModuleSize(module.imageSize),
            ModuleSignatureText(verifySignatures),
            L"Unavailable",
            ModuleRunningState(module),
            ModuleThreadText(module)
        };
        HIMAGELIST rowImages = nullptr;
        row.imageIndex = SystemIconIndexForPath(module.modulePath, &rowImages);
        if (!imageListOut && rowImages) {
            imageListOut = rowImages;
        }
        rows.push_back(std::move(row));
    }
    const int column = std::clamp(sortColumn, 0, 5);
    // The size and thread-count columns are numeric, and an ordinal compare
    // ordered them by printed characters: "512.0 KiB" sorted after "4.0 MiB"
    // and 9 threads after 10. CompareCellsNumericAware reads the leading number
    // back out of the cell and only falls back to text order for the path,
    // signature and state columns.
    std::stable_sort(rows.begin(), rows.end(), [column, sortDescending](const auto& left, const auto& right) {
        const std::wstring& leftCell = left.cells[static_cast<std::size_t>(column)];
        const std::wstring& rightCell = right.cells[static_cast<std::size_t>(column)];
        const int comparison = Ksword::Ui::CompareCellsNumericAware(leftCell, rightCell);
        if (comparison == 0) {
            return left.stableKey < right.stableKey;
        }
        return sortDescending ? comparison > 0 : comparison < 0;
    });
    return rows;
}

std::wstring StableKeyAt(const Ksword::Ui::VirtualListView& list, int visibleIndex) {
    if (visibleIndex < 0 || static_cast<std::size_t>(visibleIndex) >= list.visibleIndexes().size()) {
        return {};
    }
    const std::size_t rowIndex = list.visibleIndexes()[static_cast<std::size_t>(visibleIndex)];
    return rowIndex < list.rows().size() ? list.rows()[rowIndex].stableKey : std::wstring{};
}

void RestoreListPosition(
    HWND list,
    const Ksword::Ui::VirtualListView& virtualList,
    const std::wstring& selectedKey,
    const std::wstring& topKey) {
    int selectedIndex = -1;
    int topIndex = -1;
    for (std::size_t index = 0; index < virtualList.visibleIndexes().size(); ++index) {
        const std::size_t rowIndex = virtualList.visibleIndexes()[index];
        if (rowIndex >= virtualList.rows().size()) {
            continue;
        }
        const std::wstring& stableKey = virtualList.rows()[rowIndex].stableKey;
        if (!selectedKey.empty() && stableKey == selectedKey) {
            selectedIndex = static_cast<int>(index);
        }
        if (!topKey.empty() && stableKey == topKey) {
            topIndex = static_cast<int>(index);
        }
    }
    if (selectedIndex >= 0) {
        ListView_SetItemState(list, selectedIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topIndex >= 0) {
        ListView_EnsureVisible(list, topIndex, FALSE);
    }
}

void ApplyDialogFont(HWND hwnd) {
    if (hwnd) {
        ::SendMessageW(
            hwnd,
            WM_SETFONT,
            reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()),
            TRUE);
    }
}

void LayoutModuleDetailDialog(ModuleDetailDialogState& state) {
    if (!state.hwnd) {
        return;
    }
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    constexpr int margin = 10;
    constexpr int spacing = 8;
    constexpr int summaryHeight = 42;
    constexpr int buttonHeight = 28;
    constexpr int copyWidth = 96;
    constexpr int openWidth = 96;
    constexpr int closeWidth = 72;
    const int width = std::max(0L, client.right - client.left);
    const int height = std::max(0L, client.bottom - client.top);
    const int buttonY = std::max(margin, height - margin - buttonHeight);
    int buttonX = std::max(margin, width - margin - closeWidth);
    ::MoveWindow(state.closeButton, buttonX, buttonY, closeWidth, buttonHeight, TRUE);
    buttonX -= spacing + openWidth;
    ::MoveWindow(state.openFolderButton, buttonX, buttonY, openWidth, buttonHeight, TRUE);
    buttonX -= spacing + copyWidth;
    ::MoveWindow(state.copyButton, buttonX, buttonY, copyWidth, buttonHeight, TRUE);
    ::MoveWindow(state.summary, margin, margin, std::max(0, width - margin * 2), summaryHeight, TRUE);
    const int editY = margin + summaryHeight + spacing;
    const int editHeight = std::max(0, buttonY - spacing - editY);
    ::MoveWindow(state.edit, margin, editY, std::max(0, width - margin * 2), editHeight, TRUE);
}

LRESULT CALLBACK ModuleDetailWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<ModuleDetailDialogState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        state = create ? static_cast<ModuleDetailDialogState*>(create->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        if (state) {
            state->hwnd = hwnd;
        }
    }
    switch (message) {
    case WM_CREATE:
        if (!state) {
            return -1;
        }
        state->summary = ::CreateWindowExW(
            0, WC_STATICW, state->summaryText.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            0, 0, 0, 0, hwnd,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModuleDetailSummaryId)),
            ::GetModuleHandleW(nullptr), nullptr);
        state->edit = ::CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_EDITW, state->detailText.c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_LEFT | ES_MULTILINE |
                ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL,
            0, 0, 0, 0, hwnd,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModuleDetailEditId)),
            ::GetModuleHandleW(nullptr), nullptr);
        Ksword::Ui::AttachTextFindSupport(state->edit);
        state->copyButton = ::CreateWindowExW(
            0, WC_BUTTONW, L"复制全部", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModuleDetailCopyId)),
            ::GetModuleHandleW(nullptr), nullptr);
        state->openFolderButton = ::CreateWindowExW(
            0, WC_BUTTONW, L"打开目录", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModuleDetailOpenFolderId)),
            ::GetModuleHandleW(nullptr), nullptr);
        state->closeButton = ::CreateWindowExW(
            0, WC_BUTTONW, L"关闭", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, 0, 0, hwnd,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModuleDetailCloseId)),
            ::GetModuleHandleW(nullptr), nullptr);
        ApplyDialogFont(state->summary);
        ApplyDialogFont(state->edit);
        ApplyDialogFont(state->copyButton);
        ApplyDialogFont(state->openFolderButton);
        ApplyDialogFont(state->closeButton);
        LayoutModuleDetailDialog(*state);
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutModuleDetailDialog(*state);
        }
        return 0;
    case WM_GETMINMAXINFO:
        if (auto* sizeInfo = reinterpret_cast<MINMAXINFO*>(lParam)) {
            sizeInfo->ptMinTrackSize.x = 600;
            sizeInfo->ptMinTrackSize.y = 400;
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        switch (LOWORD(wParam)) {
        case kModuleDetailCopyId:
            WriteClipboardText(hwnd, state->detailText);
            return 0;
        case kModuleDetailOpenFolderId:
            OpenFolderAndSelectPath(hwnd, state->modulePath);
            return 0;
        case kModuleDetailCloseId:
            ::DestroyWindow(hwnd);
            return 0;
        default:
            break;
        }
        break;
    case WM_CLOSE:
        ::DestroyWindow(hwnd);
        return 0;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    case WM_CTLCOLOREDIT:
        ::SetBkColor(reinterpret_cast<HDC>(wParam), Ksword::Ui::AppTheme().panelColor);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().panelBrush());
    case WM_NCDESTROY:
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        if (state) {
            state->hwnd = nullptr;
        }
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool RegisterModuleDetailClass() {
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = ModuleDetailWindowProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kModuleDetailClass;
    if (::RegisterClassW(&windowClass)) {
        return true;
    }
    return ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

void RunModuleDetailDialog(HWND parent, const std::wstring& title, ModuleDetailDialogState& state) {
    if (!RegisterModuleDetailClass()) {
        return;
    }
    HWND owner = parent ? ::GetAncestor(parent, GA_ROOT) : nullptr;
    RECT ownerRect{};
    if (!owner || !::GetWindowRect(owner, &ownerRect)) {
        ownerRect = { 100, 100, 860, 620 };
    }
    RECT windowRect{ 0, 0, 760, 520 };
    constexpr DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME;
    constexpr DWORD exStyle = WS_EX_DLGMODALFRAME;
    ::AdjustWindowRectEx(&windowRect, style, FALSE, exStyle);
    const int width = windowRect.right - windowRect.left;
    const int height = windowRect.bottom - windowRect.top;
    const int x = ownerRect.left + std::max(0L, (ownerRect.right - ownerRect.left - width) / 2);
    const int y = ownerRect.top + std::max(0L, (ownerRect.bottom - ownerRect.top - height) / 2);
    HWND dialog = ::CreateWindowExW(
        exStyle,
        kModuleDetailClass,
        title.c_str(),
        style,
        x,
        y,
        width,
        height,
        owner,
        nullptr,
        ::GetModuleHandleW(nullptr),
        &state);
    if (!dialog) {
        return;
    }
    const bool ownerWasEnabled = !owner || ::IsWindowEnabled(owner) != FALSE;
    if (owner && ownerWasEnabled) {
        ::EnableWindow(owner, FALSE);
    }
    ::ShowWindow(dialog, SW_SHOW);
    ::UpdateWindow(dialog);

    MSG message{};
    bool sawQuit = false;
    int quitCode = 0;
    while (::IsWindow(dialog)) {
        const BOOL result = ::GetMessageW(&message, nullptr, 0, 0);
        if (result <= 0) {
            if (result == 0) {
                sawQuit = true;
                quitCode = static_cast<int>(message.wParam);
            }
            break;
        }
        if (message.message == WM_KEYDOWN && message.wParam == VK_ESCAPE) {
            ::DestroyWindow(dialog);
            continue;
        }
        if (!::IsDialogMessageW(dialog, &message)) {
            ::TranslateMessage(&message);
            ::DispatchMessageW(&message);
        }
    }
    if (owner && ownerWasEnabled) {
        ::EnableWindow(owner, TRUE);
        ::SetActiveWindow(owner);
    }
    if (sawQuit) {
        ::PostQuitMessage(quitCode);
    }
}

} // namespace

bool ProcessDetailPage::CreateModuleTab() {
    HWND refresh = AddButton(TabIndex::Modules, ModuleRefresh, L"刷新模块", 6, 6, 112, 28);
    HWND verify = AddCheck(
        TabIndex::Modules,
        ModuleVerifySignature,
        L"刷新时校验签名",
        126,
        6,
        166,
        28);
    HWND status = AddControl(
        TabIndex::Modules,
        0,
        WC_STATICW,
        L"● 等待首次刷新",
        SS_RIGHT | SS_CENTERIMAGE,
        ModuleStatus,
        304,
        6,
        -6,
        28);
    HWND page = pages_[static_cast<std::size_t>(TabIndex::Modules)].hwnd;
    HWND filter = Ksword::Ui::CreateFilterBar(page, ModuleFilter, L"筛选模块路径、签名和线程", 6, 40, 100, 26);
    if (filter) {
        pages_[static_cast<std::size_t>(TabIndex::Modules)].placements.push_back(Placement{ filter, 6, 40, -6, 26 });
    }
    HWND list = AddVirtualList(TabIndex::Modules, ModuleList, 6, 72, -6, -6, moduleVirtualList_);
    if (!refresh || !verify || !status || !filter || !list) {
        return false;
    }

    ::SendMessageW(verify, BM_SETCHECK, BST_CHECKED, 0);
    AddListColumn(list, 0, L"模块路径", 560);
    AddListColumn(list, 1, L"大小", 110);
    AddListColumn(list, 2, L"数字签名", 260);
    AddListColumn(list, 3, L"入口偏移量", 120);
    AddListColumn(list, 4, L"运行状态", 90);
    AddListColumn(list, 5, L"ThreadID", 180);
    listColumnCounts_[list] = 6;
    if (moduleFilterRows_) {
        moduleVirtualList_.setSharedRows(moduleFilterRows_);
        moduleVirtualList_.setVisibleIndexes(moduleVisibleIndexes_);
    }

    ::SetWindowSubclass(
        pages_[static_cast<std::size_t>(TabIndex::Modules)].hwnd,
        ModulePageVisualSubclassProc,
        kModulePageVisualSubclassId,
        reinterpret_cast<DWORD_PTR>(list));
    ::SetWindowSubclass(status, ModuleStatusSubclassProc, kModuleStatusSubclassId, 0);

    if (HWND header = ListView_GetHeader(list)) {
        ::SetWindowSubclass(
            header,
            ProcessDetailPage::ModuleHeaderSubclassProc,
            kModuleHeaderSubclassId,
            reinterpret_cast<DWORD_PTR>(this));
    }
    UpdateSortIndicator(list, moduleSortColumn_, moduleSortDescending_);
    return true;
}

void ProcessDetailPage::PopulateModuleTab() {
    HWND list = Control(TabIndex::Modules, ModuleList);
    if (!list) {
        return;
    }
    if (moduleFilterRows_) {
        moduleVirtualList_.setSharedRows(moduleFilterRows_);
        moduleVirtualList_.setVisibleIndexes(moduleVisibleIndexes_);
    }
    if (pendingModuleEntries_ || !moduleFilterRows_) {
        SetPageStatus(TabIndex::Modules, ModuleStatus, L"● 正在后台准备模块表...");
    }
}

bool ProcessDetailPage::HandleModuleCommand(int controlId) {
    if (controlId == ModuleVerifySignature) {
        if (HWND verify = Control(TabIndex::Modules, ModuleVerifySignature)) {
            moduleVerifySignatures_ = ::SendMessageW(verify, BM_GETCHECK, 0, 0) == BST_CHECKED;
        }
        RequestModuleFilter(true);
        return true;
    }
    if (controlId == ModuleFilter) {
        RequestModuleFilter(false);
        return true;
    }
    if (controlId != ModuleRefresh) {
        return false;
    }

    SetPageStatus(TabIndex::Modules, ModuleStatus, L"● 正在后台刷新模块列表...");
    RefreshAll();
    return true;
}

void ProcessDetailPage::RequestModuleFilter(bool rebuildRows) {
    if (!moduleFilterTask_) {
        return;
    }
    const HWND filter = Control(TabIndex::Modules, ModuleFilter);
    moduleFilterQuery_ = filter ? Ksword::Ui::GetFilterBarText(filter) : moduleFilterQuery_;
    moduleFilterUseRegex_ = Ksword::Ui::GetFilterBarRegexEnabled(filter);
    const auto existingRows = moduleFilterRows_;
    const auto source = pendingModuleEntries_ ? pendingModuleEntries_ : moduleEntries_;
    // Preserve request ordering when a refresh and typing overlap: the newest
    // query always rebuilds from the pending snapshot, never the old table.
    const bool buildRows = rebuildRows || !existingRows || pendingModuleEntries_;
    if (!source && buildRows) {
        return;
    }
    const std::uint64_t generation = moduleSourceGeneration_;
    const int sortColumn = moduleSortColumn_;
    const bool sortDescending = moduleSortDescending_;
    const bool verifySignatures = moduleVerifySignatures_;
    const bool useRegex = moduleFilterUseRegex_;
    SetPageStatus(TabIndex::Modules, ModuleStatus, L"● 正在后台筛选模块表...");
    moduleFilterTask_->request(
        [source, existingRows, buildRows, generation, sortColumn, sortDescending, verifySignatures, useRegex, query = moduleFilterQuery_]() mutable {
            DetailTableFilterResult result{};
            result.sourceGeneration = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.sortColumn = sortColumn;
            result.sortDescending = sortDescending;
            if (buildRows) {
                HIMAGELIST imageList = nullptr;
                result.rows = std::make_shared<const std::vector<Ksword::Ui::VirtualListRow>>(
                    BuildModuleVirtualRows(*source, verifySignatures, sortColumn, sortDescending, imageList));
                result.imageList = imageList;
            } else {
                result.rows = existingRows;
            }
            if (result.rows) {
                result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*result.rows, result.query, useRegex);
            }
            return result;
        },
        [this](std::uint64_t, std::optional<DetailTableFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value() || result->sourceGeneration != moduleSourceGeneration_ ||
                result->query != moduleFilterQuery_ || result->useRegex != moduleFilterUseRegex_ ||
                result->sortColumn != moduleSortColumn_ ||
                result->sortDescending != moduleSortDescending_ || !result->rows) {
                return;
            }
            const HWND list = moduleVirtualList_.hwnd();
            const std::wstring selectedKey = ::IsWindow(list)
                ? StableKeyAt(moduleVirtualList_, ListView_GetNextItem(list, -1, LVNI_SELECTED))
                : std::wstring{};
            const std::wstring topKey = ::IsWindow(list)
                ? StableKeyAt(moduleVirtualList_, ListView_GetTopIndex(list))
                : std::wstring{};
            const bool replaceRows = result->rows != moduleFilterRows_;
            const std::size_t visibleCount = result->visibleIndexes.size();
            moduleFilterRows_ = result->rows;
            moduleVisibleIndexes_ = result->visibleIndexes;
            if (replaceRows) {
                moduleEntries_ = pendingModuleEntries_ ? pendingModuleEntries_ : moduleEntries_;
                pendingModuleEntries_.reset();
            }
            if (::IsWindow(list)) {
                if (result->imageList) {
                    ListView_SetImageList(list, result->imageList, LVSIL_SMALL);
                }
                if (replaceRows) {
                    moduleVirtualList_.setSharedRows(moduleFilterRows_);
                }
                moduleVirtualList_.setVisibleIndexes(std::move(result->visibleIndexes));
                RestoreListPosition(list, moduleVirtualList_, selectedKey, topKey);
                UpdateSortIndicator(list, moduleSortColumn_, moduleSortDescending_);
            }
            std::wstring status;
            if (!snapshot_.modulesSucceeded) {
                status = L"● 模块刷新失败";
                if (!snapshot_.errorText.empty()) {
                    status += L" | " + snapshot_.errorText;
                }
            } else {
                status = L"● 刷新完成 | 模块:" + std::to_wstring(visibleCount) +
                    L" / " + std::to_wstring(ModuleEntries().size());
                if (ModuleEntries().empty() && !snapshot_.errorText.empty()) {
                    status += L" | " + snapshot_.errorText;
                }
            }
            if (moduleVerifySignatures_) {
                status += L" | 签名校验结果不可用";
            }
            SetPageStatus(TabIndex::Modules, ModuleStatus, status);
        });
}

void ProcessDetailPage::OnModuleSortRequested(const int column) {
    if (column < 0 || column >= 6) {
        return;
    }
    if (moduleSortColumn_ == column) {
        moduleSortDescending_ = !moduleSortDescending_;
    } else {
        moduleSortColumn_ = column;
        moduleSortDescending_ = false;
    }
    UpdateSortIndicator(moduleVirtualList_.hwnd(), moduleSortColumn_, moduleSortDescending_);
    RequestModuleFilter(true);
}

LRESULT CALLBACK ProcessDetailPage::ModuleHeaderSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR referenceData) {
    auto* page = reinterpret_cast<ProcessDetailPage*>(referenceData);
    if (message == WM_LBUTTONUP && page) {
        HDHITTESTINFO hit{};
        hit.pt.x = GET_X_LPARAM(lParam);
        hit.pt.y = GET_Y_LPARAM(lParam);
        const int column = static_cast<int>(::SendMessageW(hwnd, HDM_HITTEST, 0, reinterpret_cast<LPARAM>(&hit)));
        const LRESULT result = ::DefSubclassProc(hwnd, message, wParam, lParam);
        page->OnModuleSortRequested(column);
        return result;
    }
    if (message == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, ModuleHeaderSubclassProc, subclassId);
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

bool ProcessDetailPage::HandleModuleContextMenu(POINT screenPoint) {
    HWND list = Control(TabIndex::Modules, ModuleList);
    if (!list || SelectedListRow(list) < 0) {
        return true;
    }
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return true;
    }
    ::AppendMenuW(menu, MF_STRING, kModuleMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuCopyRow, L"复制行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kModuleMenuDetail, L"查看模块详情");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuOpenFolder, L"打开文件夹");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuUnload, L"卸载");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuSuspendThread, L"挂起Thread");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuResumeThread, L"取消挂起Thread");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuTerminateThread, L"结束Thread");
    const UINT command = ::TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        hwnd_,
        nullptr);
    ::DestroyMenu(menu);

    switch (command) {
    case kModuleMenuCopyCell: CopyListCell(list); break;
    case kModuleMenuCopyRow: CopyListRow(list); break;
    case kModuleMenuDetail: ShowModuleDetailDialog(); break;
    case kModuleMenuOpenFolder: OpenSelectedModuleFolder(); break;
    case kModuleMenuUnload: UnloadSelectedModule(); break;
    case kModuleMenuSuspendThread: SuspendSelectedModuleThread(); break;
    case kModuleMenuResumeThread: ResumeSelectedModuleThread(); break;
    case kModuleMenuTerminateThread: TerminateSelectedModuleThread(); break;
    default: break;
    }
    return true;
}

void ProcessDetailPage::ShowModuleDetailDialog() {
    HWND list = Control(TabIndex::Modules, ModuleList);
    const std::size_t index = SelectedSnapshotIndex(list);
    const auto& modules = ModuleEntries();
    if (index >= modules.size()) {
        SetPageStatus(TabIndex::Modules, ModuleStatus, L"● 查看模块详情失败 | 当前无有效选中项");
        return;
    }
    const ProcessModuleInfo& module = modules[index];
    const std::wstring signature = ModuleSignatureText(moduleVerifySignatures_);
    const std::wstring moduleName = !module.moduleName.empty()
        ? module.moduleName
        : BaseNameFromPath(module.modulePath);
    std::wstring processName = snapshot_.basic.processName.empty()
        ? BaseNameFromPath(snapshot_.basic.imagePath)
        : snapshot_.basic.processName;
    if (processName.empty()) {
        processName = L"Unknown";
    }

    ModuleDetailDialogState dialogState{};
    dialogState.modulePath = module.modulePath;
    dialogState.summaryText = L"模块基址 " + FormatHex(module.baseAddress) +
        L" | 大小 " + FormatModuleSize(module.imageSize) +
        L" | 签名 " + signature;
    std::wostringstream detail;
    detail << L"进程 ID: " << processId_ << L"\r\n"
           << L"进程名: " << processName << L"\r\n"
           << L"模块路径: " << module.modulePath << L"\r\n"
           << L"模块基址: " << FormatHex(module.baseAddress) << L"\r\n"
           << L"模块大小: " << FormatModuleSize(module.imageSize) << L"\r\n"
           << L"入口点 RVA: Unavailable\r\n"
           << L"签名状态: " << signature << L"\r\n"
           << L"签名可信: Unavailable\r\n"
           << L"运行状态: " << ModuleRunningState(module) << L"\r\n"
           << L"代表线程 ID: " << module.representativeThreadId << L"\r\n"
           << L"线程 ID 文本: " << ModuleThreadText(module);
    dialogState.detailText = detail.str();
    RunModuleDetailDialog(hwnd_, L"模块详情 - " + (moduleName.empty() ? L"Unknown" : moduleName), dialogState);
}

void ProcessDetailPage::OpenSelectedModuleFolder() {
    HWND list = Control(TabIndex::Modules, ModuleList);
    const std::size_t index = SelectedSnapshotIndex(list);
    const auto& modules = ModuleEntries();
    if (index >= modules.size()) {
        SetPageStatus(TabIndex::Modules, ModuleStatus, L"● 打开文件夹失败 | 当前无有效选中项");
        return;
    }
    const bool opened = OpenFolderAndSelectPath(hwnd_, modules[index].modulePath);
    SetPageStatus(
        TabIndex::Modules,
        ModuleStatus,
        opened ? L"● 已打开模块所在目录" : L"● 打开模块所在目录失败");
}

void ProcessDetailPage::UnloadSelectedModule() {
    HWND list = Control(TabIndex::Modules, ModuleList);
    const std::size_t index = SelectedSnapshotIndex(list);
    const auto& modules = ModuleEntries();
    if (index >= modules.size()) {
        SetPageStatus(TabIndex::Modules, ModuleStatus, L"● 卸载模块失败 | 当前无有效选中项");
        return;
    }
    const std::uintptr_t moduleBase = modules[index].baseAddress;
    if (moduleBase == 0) {
        SetPageStatus(TabIndex::Modules, ModuleStatus, L"● 卸载模块失败 | 模块基址不可用");
        return;
    }
    const auto moduleSnapshot = moduleEntries_;
    const DWORD targetProcessId = processId_;
    const ULONGLONG expectedProcessCreationTime100ns = expectedCreationTime100ns_;
    ExecuteBackgroundAction(
        TabIndex::Modules,
        ModuleStatus,
        L"● 正在后台卸载模块…",
        [moduleBase, targetProcessId, expectedProcessCreationTime100ns, moduleSnapshot] {
            ProcessDetailActionResult action{};
            HMODULE localKernel32 = ::GetModuleHandleW(L"kernel32.dll");
            FARPROC localFreeLibrary = localKernel32 ? ::GetProcAddress(localKernel32, "FreeLibrary") : nullptr;
            HMODULE localFunctionModule = nullptr;
            if (!localFreeLibrary || !::GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCWSTR>(localFreeLibrary),
                    &localFunctionModule)) {
                action.statusText = L"● 卸载模块失败 | 无法解析 FreeLibrary";
                return action;
            }
            wchar_t localFunctionPath[32768]{};
            const DWORD localFunctionPathLength = ::GetModuleFileNameW(
                localFunctionModule,
                localFunctionPath,
                static_cast<DWORD>(std::size(localFunctionPath)));
            const std::wstring functionModuleName = localFunctionPathLength > 0
                ? BaseNameFromPath(std::wstring(localFunctionPath, localFunctionPathLength))
                : L"kernel32.dll";
            std::uintptr_t remoteFunctionModule = 0;
            if (moduleSnapshot) {
                for (const ProcessModuleInfo& module : *moduleSnapshot) {
                    if (_wcsicmp(BaseNameFromPath(module.modulePath).c_str(), functionModuleName.c_str()) == 0) {
                        remoteFunctionModule = module.baseAddress;
                        break;
                    }
                }
            }
            const std::uintptr_t localFunctionModuleAddress = reinterpret_cast<std::uintptr_t>(localFunctionModule);
            const std::uintptr_t freeLibraryOffset =
                reinterpret_cast<std::uintptr_t>(localFreeLibrary) - localFunctionModuleAddress;
            const std::uintptr_t remoteFreeLibrary = remoteFunctionModule
                ? remoteFunctionModule + freeLibraryOffset
                : reinterpret_cast<std::uintptr_t>(localFreeLibrary);

            Ksword::Core::UniqueHandle verifiedProcess;
            std::wstring identityError;
            if (!ProcessDetailPage::OpenVerifiedProcessActionTarget(
                    targetProcessId,
                    expectedProcessCreationTime100ns,
                    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ,
                    verifiedProcess,
                    identityError)) {
                action.statusText = L"● 卸载模块失败 | " + identityError;
                return action;
            }
            Ksword::Core::UniqueHandle remoteThread(::CreateRemoteThread(
                verifiedProcess.get(),
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteFreeLibrary),
                reinterpret_cast<void*>(moduleBase),
                0,
                nullptr));
            if (!remoteThread.valid()) {
                action.statusText = L"● 卸载模块失败 | " + LastErrorText(L"CreateRemoteThread", ::GetLastError());
                return action;
            }
            const DWORD waitResult = ::WaitForSingleObject(remoteThread.get(), 10000);
            DWORD exitCode = 0;
            const bool completed = waitResult == WAIT_OBJECT_0 &&
                ::GetExitCodeThread(remoteThread.get(), &exitCode) != FALSE && exitCode != 0;
            if (!completed) {
                action.statusText = L"● 卸载模块失败 | FreeLibrary 未成功返回";
                return action;
            }
            action.refreshRequired = true;
            action.statusText = L"● 卸载模块成功";
            return action;
        });
}

void ProcessDetailPage::SuspendSelectedModuleThread() {
    HWND list = Control(TabIndex::Modules, ModuleList);
    const std::size_t index = SelectedSnapshotIndex(list);
    const auto& modules = ModuleEntries();
    if (index >= modules.size() || modules[index].representativeThreadId == 0 ||
        modules[index].representativeThreadCreationTime100ns == 0U) {
        SetPageStatus(TabIndex::Modules, ModuleStatus, L"● 挂起 Thread 失败 | 当前模块行没有可用 ThreadID。");
        return;
    }
    const DWORD threadId = modules[index].representativeThreadId;
    const ULONGLONG expectedThreadCreationTime100ns =
        modules[index].representativeThreadCreationTime100ns;
    const DWORD targetProcessId = processId_;
    const ULONGLONG expectedProcessCreationTime100ns = expectedCreationTime100ns_;
    ExecuteBackgroundAction(
        TabIndex::Modules,
        ModuleStatus,
        L"● 正在后台挂起模块线程…",
        [threadId, expectedThreadCreationTime100ns, targetProcessId, expectedProcessCreationTime100ns] {
            ProcessDetailActionResult action{};
            Ksword::Core::UniqueHandle verifiedProcess;
            Ksword::Core::UniqueHandle verifiedThread;
            std::wstring identityError;
            if (!ProcessDetailPage::OpenVerifiedThreadActionTarget(
                    targetProcessId,
                    expectedProcessCreationTime100ns,
                    threadId,
                    expectedThreadCreationTime100ns,
                    THREAD_SUSPEND_RESUME,
                    verifiedProcess,
                    verifiedThread,
                    identityError)) {
                action.statusText = L"● 挂起 Thread 失败 | " + identityError;
                return action;
            }
            const DWORD previousCount = ::SuspendThread(verifiedThread.get());
            const DWORD error = previousCount == static_cast<DWORD>(-1) ? ::GetLastError() : ERROR_SUCCESS;
            action.refreshRequired = error == ERROR_SUCCESS;
            action.statusText = error == ERROR_SUCCESS
                ? L"● 挂起 Thread 成功"
                : L"● 挂起 Thread 失败 | " + LastErrorText(L"SuspendThread", error);
            return action;
        });
}

void ProcessDetailPage::ResumeSelectedModuleThread() {
    HWND list = Control(TabIndex::Modules, ModuleList);
    const std::size_t index = SelectedSnapshotIndex(list);
    const auto& modules = ModuleEntries();
    if (index >= modules.size() || modules[index].representativeThreadId == 0 ||
        modules[index].representativeThreadCreationTime100ns == 0U) {
        SetPageStatus(TabIndex::Modules, ModuleStatus, L"● 取消挂起 Thread 失败 | 当前模块行没有可用 ThreadID。");
        return;
    }
    const DWORD threadId = modules[index].representativeThreadId;
    const ULONGLONG expectedThreadCreationTime100ns =
        modules[index].representativeThreadCreationTime100ns;
    const DWORD targetProcessId = processId_;
    const ULONGLONG expectedProcessCreationTime100ns = expectedCreationTime100ns_;
    ExecuteBackgroundAction(
        TabIndex::Modules,
        ModuleStatus,
        L"● 正在后台恢复模块线程…",
        [threadId, expectedThreadCreationTime100ns, targetProcessId, expectedProcessCreationTime100ns] {
            ProcessDetailActionResult action{};
            Ksword::Core::UniqueHandle verifiedProcess;
            Ksword::Core::UniqueHandle verifiedThread;
            std::wstring identityError;
            if (!ProcessDetailPage::OpenVerifiedThreadActionTarget(
                    targetProcessId,
                    expectedProcessCreationTime100ns,
                    threadId,
                    expectedThreadCreationTime100ns,
                    THREAD_SUSPEND_RESUME,
                    verifiedProcess,
                    verifiedThread,
                    identityError)) {
                action.statusText = L"● 取消挂起 Thread 失败 | " + identityError;
                return action;
            }
            const DWORD previousCount = ::ResumeThread(verifiedThread.get());
            const DWORD error = previousCount == static_cast<DWORD>(-1) ? ::GetLastError() : ERROR_SUCCESS;
            action.refreshRequired = error == ERROR_SUCCESS;
            action.statusText = error == ERROR_SUCCESS
                ? L"● 取消挂起 Thread 成功"
                : L"● 取消挂起 Thread 失败 | " + LastErrorText(L"ResumeThread", error);
            return action;
        });
}

void ProcessDetailPage::TerminateSelectedModuleThread() {
    HWND list = Control(TabIndex::Modules, ModuleList);
    const std::size_t index = SelectedSnapshotIndex(list);
    const auto& modules = ModuleEntries();
    if (index >= modules.size() || modules[index].representativeThreadId == 0 ||
        modules[index].representativeThreadCreationTime100ns == 0U) {
        SetPageStatus(TabIndex::Modules, ModuleStatus, L"● 结束 Thread 失败 | 当前模块行没有可用 ThreadID。");
        return;
    }
    const DWORD threadId = modules[index].representativeThreadId;
    const ULONGLONG expectedThreadCreationTime100ns =
        modules[index].representativeThreadCreationTime100ns;
    const DWORD targetProcessId = processId_;
    const ULONGLONG expectedProcessCreationTime100ns = expectedCreationTime100ns_;
    ExecuteBackgroundAction(
        TabIndex::Modules,
        ModuleStatus,
        L"● 正在后台结束模块线程…",
        [threadId, expectedThreadCreationTime100ns, targetProcessId, expectedProcessCreationTime100ns] {
            ProcessDetailActionResult action{};
            Ksword::Core::UniqueHandle verifiedProcess;
            Ksword::Core::UniqueHandle verifiedThread;
            std::wstring identityError;
            if (!ProcessDetailPage::OpenVerifiedThreadActionTarget(
                    targetProcessId,
                    expectedProcessCreationTime100ns,
                    threadId,
                    expectedThreadCreationTime100ns,
                    THREAD_TERMINATE,
                    verifiedProcess,
                    verifiedThread,
                    identityError)) {
                action.statusText = L"● 结束 Thread 失败 | " + identityError;
                return action;
            }
            const BOOL terminated = ::TerminateThread(verifiedThread.get(), 0);
            const DWORD error = terminated ? ERROR_SUCCESS : ::GetLastError();
            if (!terminated) {
                action.statusText = L"● 结束 Thread 失败 | " + LastErrorText(L"TerminateThread", error);
                return action;
            }
            action.refreshRequired = true;
            action.statusText = L"● 结束 Thread 成功";
            return action;
        });
}

} // namespace Ksword::Features::ProcessDetail
