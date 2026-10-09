#include "WindowFormatting.h"
#include <sstream>
#include <iomanip>
namespace ks::r3::window {
std::wstring WindowStateText(const WindowSnapshotRow& row) {
    std::wstring state = row.visible ? L"Visible" : L"Hidden";
    state += row.enabled ? L", Enabled" : L", Disabled";
    if (row.minimized) {
        state += L", Minimized";
    } else if (row.maximized) {
        state += L", Maximized";
    }
    return state;
}
std::wstring HwndToText(HWND hwnd) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << reinterpret_cast<UINT_PTR>(hwnd);
    return stream.str();
}
std::wstring RectToText(const RECT& rect) {
    const LONG width = rect.right - rect.left;
    const LONG height = rect.bottom - rect.top;
    return std::to_wstring(rect.left) + L"," + std::to_wstring(rect.top) + L" " +
        std::to_wstring(width) + L"x" + std::to_wstring(height);
}
}
