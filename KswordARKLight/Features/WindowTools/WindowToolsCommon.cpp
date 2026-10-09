#include "../../../shared/usermode/backend/window/ClipboardCopy.h"
#include "../../../shared/usermode/backend/window/WindowQueries.h"
#include "WindowToolsCommon.h"

#include <commctrl.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>

namespace Ksword::Features::WindowTools {
namespace {
using namespace ks::r3::window_tools;
using namespace ks::r3::window_tools;

// StyleBitName pairs one flag value with the SDK spelling of its macro. The
// value is taken from the macro itself rather than a literal so a decoder can
// never drift from the header it claims to mirror.
struct StyleBitName final {
    DWORD value;
    const wchar_t* name;
};

constexpr StyleBitName kCommonStyleBits[] = {
    { WS_POPUP,        L"WS_POPUP" },
    { WS_CHILD,        L"WS_CHILD" },
    { WS_MINIMIZE,     L"WS_MINIMIZE" },
    { WS_VISIBLE,      L"WS_VISIBLE" },
    { WS_DISABLED,     L"WS_DISABLED" },
    { WS_CLIPSIBLINGS, L"WS_CLIPSIBLINGS" },
    { WS_CLIPCHILDREN, L"WS_CLIPCHILDREN" },
    { WS_MAXIMIZE,     L"WS_MAXIMIZE" },
    { WS_BORDER,       L"WS_BORDER" },
    { WS_DLGFRAME,     L"WS_DLGFRAME" },
    { WS_VSCROLL,      L"WS_VSCROLL" },
    { WS_HSCROLL,      L"WS_HSCROLL" },
    { WS_SYSMENU,      L"WS_SYSMENU" },
    { WS_THICKFRAME,   L"WS_THICKFRAME / WS_SIZEBOX" },
};

constexpr StyleBitName kExStyleBits[] = {
    { WS_EX_DLGMODALFRAME,  L"WS_EX_DLGMODALFRAME" },
    { WS_EX_NOPARENTNOTIFY, L"WS_EX_NOPARENTNOTIFY" },
    { WS_EX_TOPMOST,        L"WS_EX_TOPMOST" },
    { WS_EX_ACCEPTFILES,    L"WS_EX_ACCEPTFILES" },
    { WS_EX_TRANSPARENT,    L"WS_EX_TRANSPARENT" },
    { WS_EX_MDICHILD,       L"WS_EX_MDICHILD" },
    { WS_EX_TOOLWINDOW,     L"WS_EX_TOOLWINDOW" },
    { WS_EX_WINDOWEDGE,     L"WS_EX_WINDOWEDGE" },
    { WS_EX_CLIENTEDGE,     L"WS_EX_CLIENTEDGE" },
    { WS_EX_CONTEXTHELP,    L"WS_EX_CONTEXTHELP" },
    { WS_EX_RIGHT,          L"WS_EX_RIGHT" },
    { WS_EX_RTLREADING,     L"WS_EX_RTLREADING" },
    { WS_EX_LEFTSCROLLBAR,  L"WS_EX_LEFTSCROLLBAR" },
    { WS_EX_CONTROLPARENT,  L"WS_EX_CONTROLPARENT" },
    { WS_EX_STATICEDGE,     L"WS_EX_STATICEDGE" },
    { WS_EX_APPWINDOW,      L"WS_EX_APPWINDOW" },
    { WS_EX_LAYERED,        L"WS_EX_LAYERED" },
    { WS_EX_NOINHERITLAYOUT, L"WS_EX_NOINHERITLAYOUT" },
    { WS_EX_LAYOUTRTL,      L"WS_EX_LAYOUTRTL" },
    { WS_EX_COMPOSITED,     L"WS_EX_COMPOSITED" },
    { WS_EX_NOACTIVATE,     L"WS_EX_NOACTIVATE" },
#ifdef WS_EX_NOREDIRECTIONBITMAP
    { WS_EX_NOREDIRECTIONBITMAP, L"WS_EX_NOREDIRECTIONBITMAP" },
#endif
};

constexpr StyleBitName kClassStyleBits[] = {
    { CS_VREDRAW,          L"CS_VREDRAW" },
    { CS_HREDRAW,          L"CS_HREDRAW" },
    { CS_DBLCLKS,          L"CS_DBLCLKS" },
    { CS_OWNDC,            L"CS_OWNDC" },
    { CS_CLASSDC,          L"CS_CLASSDC" },
    { CS_PARENTDC,         L"CS_PARENTDC" },
    { CS_NOCLOSE,          L"CS_NOCLOSE" },
    { CS_SAVEBITS,         L"CS_SAVEBITS" },
    { CS_BYTEALIGNCLIENT,  L"CS_BYTEALIGNCLIENT" },
    { CS_BYTEALIGNWINDOW,  L"CS_BYTEALIGNWINDOW" },
    { CS_GLOBALCLASS,      L"CS_GLOBALCLASS" },
    { CS_IME,              L"CS_IME" },
    { CS_DROPSHADOW,       L"CS_DROPSHADOW" },
};

// AppendUnknownBits reports whatever the table did not explain. Silently
// dropping leftovers would make an undocumented or newer flag look like it was
// simply not set, which is the opposite of what a diagnostic page is for.
void AppendUnknownBits(std::vector<std::wstring>& names, DWORD remaining) {
    if (remaining != 0) {
        names.push_back(L"未识别位: " + HexText(remaining, 8));
    }
}

// LeafName extracts the file name from a full image path. Inputs are the path
// and the process id it came from; output falls back to a stable placeholder so
// an inaccessible process still occupies its row instead of showing blank.


// ReadWindowInfo converts one HWND into a snapshot row. Input is a live
// top-level HWND; output has hwnd=nullptr when the window vanished mid-pass,
// which EnumWindows makes routine rather than exceptional.




} // namespace





std::wstring PointerText(const std::uint64_t value) {
    return HexText(value, 16);
}



std::wstring RectText(const RECT& rect) {
    std::wostringstream stream;
    stream << L"(" << rect.left << L", " << rect.top << L") - (" << rect.right << L", " << rect.bottom
        << L")  宽 " << (rect.right - rect.left) << L" 高 " << (rect.bottom - rect.top);
    return stream.str();
}









std::wstring DescribeWindowBrief(HWND hwnd) {
    if (!hwnd) {
        return L"(无)";
    }
    if (!::IsWindow(hwnd)) {
        return HwndText(hwnd) + L"  (句柄已失效)";
    }
    std::wstring title = WindowTitleText(hwnd);
    if (title.size() > 48) {
        title = title.substr(0, 48) + L"…";
    }
    std::wstring text = HwndText(hwnd) + L"  [" + WindowClassText(hwnd) + L"]";
    if (!title.empty()) {
        text += L"  \"" + title + L"\"";
    }
    return text;
}

std::vector<std::wstring> DecodeWindowStyleBits(const DWORD style, const bool isChild) {
    std::vector<std::wstring> names;
    DWORD remaining = style;
    for (const StyleBitName& bit : kCommonStyleBits) {
        if ((style & bit.value) == bit.value && bit.value != 0) {
            names.push_back(bit.name);
            remaining &= ~bit.value;
        }
    }

    // WS_CAPTION is WS_BORDER|WS_DLGFRAME rather than a bit of its own, so it is
    // reported as a derived note instead of losing the two real bits above.
    if ((style & WS_CAPTION) == WS_CAPTION) {
        names.push_back(L"WS_CAPTION（= WS_BORDER | WS_DLGFRAME）");
    }

    if ((style & 0x00020000UL) != 0) {
        names.push_back(isChild ? L"WS_GROUP" : L"WS_MINIMIZEBOX");
        remaining &= ~0x00020000UL;
    }
    if ((style & 0x00010000UL) != 0) {
        names.push_back(isChild ? L"WS_TABSTOP" : L"WS_MAXIMIZEBOX");
        remaining &= ~0x00010000UL;
    }

    if (names.empty()) {
        names.push_back(L"WS_OVERLAPPED（无置位，样式值为 0）");
    }

    // The low word belongs to the window class, not to WS_*. Decoding it would
    // require knowing whether this is a BUTTON, an EDIT or a private class, so
    // it is surfaced raw rather than guessed at.
    const DWORD classSpecific = remaining & 0x0000FFFFUL;
    if (classSpecific != 0) {
        names.push_back(L"低 16 位（类相关样式，需按窗口类解释）: " + HexText(classSpecific, 4));
    }
    AppendUnknownBits(names, remaining & 0xFFFF0000UL);
    return names;
}

std::vector<std::wstring> DecodeWindowExStyleBits(const DWORD exStyle) {
    std::vector<std::wstring> names;
    DWORD remaining = exStyle;
    for (const StyleBitName& bit : kExStyleBits) {
        if ((exStyle & bit.value) == bit.value && bit.value != 0) {
            names.push_back(bit.name);
            remaining &= ~bit.value;
        }
    }
    if (names.empty() && remaining == 0) {
        names.push_back(L"WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR（三者均为 0）");
    }
    AppendUnknownBits(names, remaining);
    return names;
}

std::vector<std::wstring> DecodeClassStyleBits(const DWORD classStyle) {
    std::vector<std::wstring> names;
    DWORD remaining = classStyle;
    for (const StyleBitName& bit : kClassStyleBits) {
        if ((classStyle & bit.value) == bit.value && bit.value != 0) {
            names.push_back(bit.name);
            remaining &= ~bit.value;
        }
    }
    if (names.empty() && remaining == 0) {
        names.push_back(L"(无置位)");
    }
    AppendUnknownBits(names, remaining);
    return names;
}



std::wstring RowsAsTsv(const Ksword::Ui::VirtualListView& list, const bool visibleRows, const int columnCount) {
    const auto& rows = list.rows();
    const auto& visible = list.visibleIndexes();
    const HWND hwnd = list.hwnd();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!visibleRows &&
            (!hwnd || (ListView_GetItemState(hwnd, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t rowIndex = visible[item];
        if (rowIndex >= rows.size()) {
            continue;
        }
        const auto& cells = rows[rowIndex].cells;
        const std::size_t limit = (std::min)(static_cast<std::size_t>(columnCount), cells.size());
        for (std::size_t column = 0; column < limit; ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

} // namespace Ksword::Features::WindowTools
