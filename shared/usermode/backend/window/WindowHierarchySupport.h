#pragma once
#include "../Common.h"
#include "WindowQueries.h"
namespace ks::r3::window_tools {
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
void AppendUnknownBits(std::vector<std::wstring>& names, DWORD remaining);
std::wstring RectText(const RECT& rect);
std::wstring DescribeWindowBrief(HWND hwnd);
std::vector<std::wstring> DecodeWindowStyleBits(const DWORD style, const bool isChild);
std::vector<std::wstring> DecodeWindowExStyleBits(const DWORD exStyle);
std::vector<std::wstring> DecodeClassStyleBits(const DWORD classStyle);
}
