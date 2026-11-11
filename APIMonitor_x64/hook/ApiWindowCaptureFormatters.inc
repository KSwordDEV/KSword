// Named window API formatters. Never dereference caller-owned memory.

void CaptureGetWindowRect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, LPRECT rectangle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" rectangle="); AppendHexText(detailBuffer, ApiReturnBits(rectangle)); }

void CaptureGetClientRect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, LPRECT rectangle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" rectangle="); AppendHexText(detailBuffer, ApiReturnBits(rectangle)); }

void CaptureClientToScreen(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, LPPOINT point, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" point="); AppendHexText(detailBuffer, ApiReturnBits(point)); }

void CaptureScreenToClient(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, LPPOINT point, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" point="); AppendHexText(detailBuffer, ApiReturnBits(point)); }

void CaptureMoveWindow(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, int x, int y, int width, int height, BOOL repaint, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); AppendWideText(detailBuffer, L" width="); AppendHexText(detailBuffer, ApiReturnBits(width)); AppendWideText(detailBuffer, L" height="); AppendHexText(detailBuffer, ApiReturnBits(height)); AppendWideText(detailBuffer, L" repaint="); AppendHexText(detailBuffer, ApiReturnBits(repaint)); }

void CaptureSetWindowPos(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, HWND insertAfter, int x, int y, int width, int height, UINT flags, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" insertAfter="); AppendHexText(detailBuffer, ApiReturnBits(insertAfter)); AppendWideText(detailBuffer, L" x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); AppendWideText(detailBuffer, L" width="); AppendHexText(detailBuffer, ApiReturnBits(width)); AppendWideText(detailBuffer, L" height="); AppendHexText(detailBuffer, ApiReturnBits(height)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); }

void CaptureDestroyWindow(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); }

void CaptureSetWindowTextA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, LPCSTR text, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); }

void CaptureSetWindowTextW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, LPCWSTR text, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); }

void CaptureGetWindowPlacement(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, WINDOWPLACEMENT* placement, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" placement="); AppendHexText(detailBuffer, ApiReturnBits(placement)); }

void CaptureSetWindowPlacement(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, const WINDOWPLACEMENT* placement, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" placement="); AppendHexText(detailBuffer, ApiReturnBits(placement)); }

void CaptureGetCursorPos(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPPOINT point, BOOL resultValue)
{ AppendWideText(detailBuffer, L"point="); AppendHexText(detailBuffer, ApiReturnBits(point)); }

void CaptureSetCursorPos(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], int x, int y, BOOL resultValue)
{ AppendWideText(detailBuffer, L"x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); }

void CaptureGetIconInfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HICON icon, PICONINFO info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"icon="); AppendHexText(detailBuffer, ApiReturnBits(icon)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureGetWindowInfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, PWINDOWINFO info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureAdjustWindowRect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPRECT rectangle, DWORD style, BOOL menu, BOOL resultValue)
{ AppendWideText(detailBuffer, L"rectangle="); AppendHexText(detailBuffer, ApiReturnBits(rectangle)); AppendWideText(detailBuffer, L" style="); AppendHexText(detailBuffer, ApiReturnBits(style)); AppendWideText(detailBuffer, L" menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); }

void CaptureAdjustWindowRectEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPRECT rectangle, DWORD style, BOOL menu, DWORD extendedStyle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"rectangle="); AppendHexText(detailBuffer, ApiReturnBits(rectangle)); AppendWideText(detailBuffer, L" style="); AppendHexText(detailBuffer, ApiReturnBits(style)); AppendWideText(detailBuffer, L" menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" extendedStyle="); AppendHexText(detailBuffer, ApiReturnBits(extendedStyle)); }

void CaptureInvalidateRect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, const RECT* rectangle, BOOL erase, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" rectangle="); AppendHexText(detailBuffer, ApiReturnBits(rectangle)); AppendWideText(detailBuffer, L" erase="); AppendHexText(detailBuffer, ApiReturnBits(erase)); }

void CaptureValidateRect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, const RECT* rectangle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" rectangle="); AppendHexText(detailBuffer, ApiReturnBits(rectangle)); }

void CaptureRedrawWindow(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, const RECT* updateRect, HRGN updateRegion, UINT flags, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" updateRect="); AppendHexText(detailBuffer, ApiReturnBits(updateRect)); AppendWideText(detailBuffer, L" updateRegion="); AppendHexText(detailBuffer, ApiReturnBits(updateRegion)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); }

void CaptureUpdateWindow(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); }

void CaptureGetMonitorInfoA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMONITOR monitor, LPMONITORINFO info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"monitor="); AppendHexText(detailBuffer, ApiReturnBits(monitor)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureGetMonitorInfoW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMONITOR monitor, LPMONITORINFO info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"monitor="); AppendHexText(detailBuffer, ApiReturnBits(monitor)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureRegisterHotKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, int id, UINT modifiers, UINT virtualKey, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" id="); AppendHexText(detailBuffer, ApiReturnBits(id)); AppendWideText(detailBuffer, L" modifiers="); AppendHexText(detailBuffer, ApiReturnBits(modifiers)); AppendWideText(detailBuffer, L" virtualKey="); AppendHexText(detailBuffer, ApiReturnBits(virtualKey)); }

void CaptureUnregisterHotKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, int id, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" id="); AppendHexText(detailBuffer, ApiReturnBits(id)); }

void CaptureClipCursor(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const RECT* rectangle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"rectangle="); AppendHexText(detailBuffer, ApiReturnBits(rectangle)); }

void CaptureGetClipCursor(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPRECT rectangle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"rectangle="); AppendHexText(detailBuffer, ApiReturnBits(rectangle)); }

void CaptureGetGUIThreadInfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD threadId, PGUITHREADINFO info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"threadId="); AppendHexText(detailBuffer, ApiReturnBits(threadId)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureGetCursorInfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PCURSORINFO info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureGetKeyboardState(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PBYTE keyState, BOOL resultValue)
{ AppendWideText(detailBuffer, L"keyState="); AppendHexText(detailBuffer, ApiReturnBits(keyState)); }

void CaptureSetKeyboardState(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPBYTE keyState, BOOL resultValue)
{ AppendWideText(detailBuffer, L"keyState="); AppendHexText(detailBuffer, ApiReturnBits(keyState)); }

void CaptureGetLastInputInfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PLASTINPUTINFO info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureTrackMouseEvent(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPTRACKMOUSEEVENT tracking, BOOL resultValue)
{ AppendWideText(detailBuffer, L"tracking="); AppendHexText(detailBuffer, ApiReturnBits(tracking)); }

void CaptureGetWindowDisplayAffinity(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, DWORD* affinity, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" affinity="); AppendHexText(detailBuffer, ApiReturnBits(affinity)); }

void CaptureSetWindowDisplayAffinity(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, DWORD affinity, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" affinity="); AppendHexText(detailBuffer, ApiReturnBits(affinity)); }

void CaptureGetLayeredWindowAttributes(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, COLORREF* colorKey, BYTE* alpha, DWORD* flags, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" colorKey="); AppendHexText(detailBuffer, ApiReturnBits(colorKey)); AppendWideText(detailBuffer, L" alpha="); AppendHexText(detailBuffer, ApiReturnBits(alpha)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); }

void CaptureSetLayeredWindowAttributes(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, COLORREF colorKey, BYTE alpha, DWORD flags, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" colorKey="); AppendHexText(detailBuffer, ApiReturnBits(colorKey)); AppendWideText(detailBuffer, L" alpha="); AppendHexText(detailBuffer, ApiReturnBits(alpha)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); }

void CapturePrintWindow(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, HDC dc, UINT flags, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); }

void CaptureGetPhysicalCursorPos(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPPOINT point, BOOL resultValue)
{ AppendWideText(detailBuffer, L"point="); AppendHexText(detailBuffer, ApiReturnBits(point)); }

void CaptureSetPhysicalCursorPos(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], int x, int y, BOOL resultValue)
{ AppendWideText(detailBuffer, L"x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); }

void CaptureLogicalToPhysicalPointForPerMonitorDPI(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, LPPOINT point, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" point="); AppendHexText(detailBuffer, ApiReturnBits(point)); }

void CapturePhysicalToLogicalPointForPerMonitorDPI(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, LPPOINT point, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" point="); AppendHexText(detailBuffer, ApiReturnBits(point)); }
