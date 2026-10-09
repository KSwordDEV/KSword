#include "WindowHierarchySupport.h"
#include <algorithm>
#include <cwchar>
#include <sstream>
namespace ks::r3::window_tools {
void AppendUnknownBits(std::vector<std::wstring>& names, DWORD remaining) {
    if (remaining != 0) {
        names.push_back(L"未识别位: " + HexText(remaining, 8));
    }
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
}
