// Included after runtime_probe_support.h in the owned-process runtime fixture.
namespace apimon_probe {
#define WINDOW_CALL(id, name, ...) Call<decltype(&::name)>(id, L"User32.dll", #name, __VA_ARGS__)
void RunWindowCases() {
    HWND window = CreateWindowExW(WS_EX_LAYERED, L"STATIC", L"API monitor probe", WS_OVERLAPPEDWINDOW,
                                 10, 10, 160, 100, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    RECT rect{}; POINT point{};
    WINDOW_CALL(642, GetWindowRect, window, &rect);
    WINDOW_CALL(643, GetClientRect, window, &rect);
    WINDOW_CALL(642, GetWindowRect, static_cast<HWND>(nullptr), &rect);
    WINDOW_CALL(643, GetClientRect, static_cast<HWND>(nullptr), &rect);
    WINDOW_CALL(644, ClientToScreen, window, &point);
    WINDOW_CALL(645, ScreenToClient, window, &point);
    WINDOW_CALL(646, MoveWindow, window, 10, 10, 160, 100, FALSE);
    WINDOW_CALL(647, SetWindowPos, window, static_cast<HWND>(nullptr), 10, 10, 160, 100, UINT(SWP_NOZORDER | SWP_NOACTIVATE));
    WINDOW_CALL(649, SetWindowTextA, window, "probe");
    WINDOW_CALL(650, SetWindowTextW, window, L"probe");
    WINDOWPLACEMENT placement{}; placement.length = sizeof(placement);
    if (WINDOW_CALL(651, GetWindowPlacement, window, &placement))
        WINDOW_CALL(652, SetWindowPlacement, window, &placement);
    else { WINDOWPLACEMENT bad{}; bad.length = sizeof(bad); WINDOW_CALL(652, SetWindowPlacement, window, &bad); }
    POINT cursor{};
    const BOOL haveCursor = WINDOW_CALL(653, GetCursorPos, &cursor);
    if (haveCursor) WINDOW_CALL(654, SetCursorPos, cursor.x, cursor.y);
    else if (g_allowGlobalStateChanges) WINDOW_CALL(654, SetCursorPos, 0, 0);
    else Skip(654, "cursor_position_unavailable_no_safe_restore");
    HICON icon = LoadIconW(nullptr, MAKEINTRESOURCEW(32512)); ICONINFO iconInfo{};
    WINDOW_CALL(655, GetIconInfo, icon, &iconInfo);
    if (iconInfo.hbmMask) DeleteObject(iconInfo.hbmMask);
    if (iconInfo.hbmColor) DeleteObject(iconInfo.hbmColor);
    WINDOWINFO info{}; info.cbSize = sizeof(info);
    WINDOW_CALL(656, GetWindowInfo, window, &info);
    rect = RECT{0, 0, 100, 80}; WINDOW_CALL(657, AdjustWindowRect, &rect, DWORD(WS_OVERLAPPEDWINDOW), FALSE);
    rect = RECT{0, 0, 100, 80}; WINDOW_CALL(658, AdjustWindowRectEx, &rect, DWORD(WS_OVERLAPPEDWINDOW), FALSE, DWORD(WS_EX_LAYERED));
    WINDOW_CALL(659, InvalidateRect, window, static_cast<const RECT*>(nullptr), FALSE);
    WINDOW_CALL(660, ValidateRect, window, static_cast<const RECT*>(nullptr));
    WINDOW_CALL(661, RedrawWindow, window, static_cast<const RECT*>(nullptr), static_cast<HRGN>(nullptr), UINT(RDW_INVALIDATE));
    WINDOW_CALL(662, UpdateWindow, window);
    HMONITOR monitor = MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorA{}; monitorA.cbSize = sizeof(monitorA);
    MONITORINFO monitorW{}; monitorW.cbSize = sizeof(monitorW);
    WINDOW_CALL(663, GetMonitorInfoA, monitor, &monitorA);
    WINDOW_CALL(664, GetMonitorInfoW, monitor, &monitorW);
    // Unique window-owned registration. Failure can be caused by an already reserved chord.
    if (window) {
        WINDOW_CALL(665, RegisterHotKey, window, 0x6941, UINT(MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT), UINT(VK_F24));
        WINDOW_CALL(666, UnregisterHotKey, window, 0x6941);
    } else { Skip(665, "owned_window_creation_failed"); Skip(666, "owned_window_creation_failed"); }
    // Only the fixture-verified disposable VM permits changing global state.
    // The rectangle cannot distinguish an unconstrained cursor from a screen-sized clip.
    if (g_allowGlobalStateChanges) {
        RECT previousClip{};
        const BOOL havePreviousClip = GetClipCursor(&previousClip);
        WINDOW_CALL(667, ClipCursor, static_cast<const RECT*>(nullptr));
        if (havePreviousClip) ClipCursor(&previousClip);
    } else Skip(667, "global_cursor_clip_changes_not_authorized");
    WINDOW_CALL(668, GetClipCursor, &rect);
    GUITHREADINFO gui{}; gui.cbSize = sizeof(gui);
    WINDOW_CALL(669, GetGUIThreadInfo, GetCurrentThreadId(), &gui);
    CURSORINFO cursorInfo{}; cursorInfo.cbSize = sizeof(cursorInfo);
    WINDOW_CALL(670, GetCursorInfo, &cursorInfo);
    BYTE keys[256]{}; if (WINDOW_CALL(671, GetKeyboardState, keys)) WINDOW_CALL(672, SetKeyboardState, keys);
    else Skip(672, "thread_keyboard_state_unavailable");
    LASTINPUTINFO lastInput{}; lastInput.cbSize = sizeof(lastInput);
    WINDOW_CALL(673, GetLastInputInfo, &lastInput);
    TRACKMOUSEEVENT track{}; track.cbSize = sizeof(track); track.dwFlags = TME_QUERY; track.hwndTrack = window;
    WINDOW_CALL(674, TrackMouseEvent, &track);
    DWORD affinity{}; WINDOW_CALL(675, GetWindowDisplayAffinity, window, &affinity);
    WINDOW_CALL(676, SetWindowDisplayAffinity, window, DWORD(WDA_NONE));
    COLORREF color{}; BYTE alpha{}; DWORD layeredFlags{};
    WINDOW_CALL(678, SetLayeredWindowAttributes, window, COLORREF(0), BYTE(255), DWORD(LWA_ALPHA));
    WINDOW_CALL(677, GetLayeredWindowAttributes, window, &color, &alpha, &layeredFlags);
    WINDOW_CALL(677, GetLayeredWindowAttributes, static_cast<HWND>(nullptr), &color, &alpha, &layeredFlags);
    HDC source = window ? GetDC(window) : nullptr; HDC dc = source ? CreateCompatibleDC(source) : nullptr;
    if (dc) WINDOW_CALL(679, PrintWindow, window, dc, UINT(0));
    else Skip(679, "owned_memory_dc_unavailable");
    if (dc) DeleteDC(dc); if (source) ReleaseDC(window, source);
    POINT physical{}; const BOOL havePhysical = WINDOW_CALL(680, GetPhysicalCursorPos, &physical);
    if (havePhysical) WINDOW_CALL(681, SetPhysicalCursorPos, physical.x, physical.y);
    else if (g_allowGlobalStateChanges) WINDOW_CALL(681, SetPhysicalCursorPos, 0, 0);
    else Skip(681, "physical_cursor_position_unavailable_no_safe_restore");
    point = POINT{0, 0}; WINDOW_CALL(682, LogicalToPhysicalPointForPerMonitorDPI, window, &point);
    WINDOW_CALL(683, PhysicalToLogicalPointForPerMonitorDPI, window, &point);

    HMENU menu = CreateMenu();
    if (menu) {
        WINDOW_CALL(802, AppendMenuA, menu, UINT(MF_STRING), UINT_PTR(101), "first");
        WINDOW_CALL(803, AppendMenuW, menu, UINT(MF_STRING), UINT_PTR(102), L"second");
        WINDOW_CALL(804, InsertMenuA, menu, UINT(0), UINT(MF_BYPOSITION | MF_STRING), UINT_PTR(103), "third");
        WINDOW_CALL(805, InsertMenuW, menu, UINT(0), UINT(MF_BYPOSITION | MF_STRING), UINT_PTR(104), L"fourth");
        WINDOW_CALL(806, ModifyMenuA, menu, UINT(103), UINT(MF_BYCOMMAND | MF_STRING), UINT_PTR(103), "third modified");
        WINDOW_CALL(807, ModifyMenuW, menu, UINT(104), UINT(MF_BYCOMMAND | MF_STRING), UINT_PTR(104), L"fourth modified");
        const BOOL menuAttached = WINDOW_CALL(810, SetMenu, window, menu);
        WINDOW_CALL(811, DrawMenuBar, window);
        MENUITEMINFOA itemA{}; itemA.cbSize = sizeof(itemA); itemA.fMask = MIIM_ID;
        MENUITEMINFOW itemW{}; itemW.cbSize = sizeof(itemW); itemW.fMask = MIIM_ID;
        WINDOW_CALL(812, GetMenuItemInfoA, menu, UINT(0), TRUE, &itemA);
        WINDOW_CALL(813, GetMenuItemInfoW, menu, UINT(0), TRUE, &itemW);
        itemA.fMask = MIIM_STATE; itemA.fState = MFS_ENABLED;
        itemW.fMask = MIIM_STATE; itemW.fState = MFS_ENABLED;
        WINDOW_CALL(814, SetMenuItemInfoA, menu, UINT(0), TRUE, &itemA);
        WINDOW_CALL(815, SetMenuItemInfoW, menu, UINT(0), TRUE, &itemW);
        MENUINFO menuInfo{}; menuInfo.cbSize = sizeof(menuInfo); menuInfo.fMask = MIM_STYLE;
        WINDOW_CALL(816, GetMenuInfo, menu, &menuInfo);
        WINDOW_CALL(817, SetMenuInfo, menu, &menuInfo);
        WINDOW_CALL(818, GetMenuItemRect, window, menu, UINT(0), &rect);
        WINDOW_CALL(819, HiliteMenuItem, window, menu, UINT(0), UINT(MF_BYPOSITION | MF_UNHILITE));
        MENUITEMINFOA insertA{}; insertA.cbSize = sizeof(insertA); insertA.fMask = MIIM_ID; insertA.wID = 105;
        MENUITEMINFOW insertW{}; insertW.cbSize = sizeof(insertW); insertW.fMask = MIIM_ID; insertW.wID = 106;
        WINDOW_CALL(820, InsertMenuItemA, menu, UINT(0), TRUE, &insertA);
        WINDOW_CALL(821, InsertMenuItemW, menu, UINT(0), TRUE, &insertW);
        WINDOW_CALL(822, CheckMenuRadioItem, menu, UINT(0), UINT(1), UINT(0), UINT(MF_BYPOSITION));
        WINDOW_CALL(823, SetMenuDefaultItem, menu, UINT(0), UINT(TRUE));
        WINDOW_CALL(808, RemoveMenu, menu, UINT(0), UINT(MF_BYPOSITION));
        WINDOW_CALL(809, DeleteMenu, menu, UINT(0), UINT(MF_BYPOSITION));
        // A window owns its attached menu. Destroy an independent popup in the
        // probe, and free the main menu only after a successful detach.
        HMENU disposable = CreatePopupMenu();
        if (disposable) WINDOW_CALL(801, DestroyMenu, disposable);
        else Skip(801, "owned_popup_creation_failed");
        if (!menuAttached || SetMenu(window, nullptr)) DestroyMenu(menu);
    } else {
        for (unsigned id = 801; id <= 823; ++id) Skip(id, "owned_menu_creation_failed");
    }
    WINDOW_CALL(648, DestroyWindow, window);
}
#undef WINDOW_CALL
}
