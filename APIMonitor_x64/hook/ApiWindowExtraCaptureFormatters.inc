// Window menu API formatters: arguments only, no caller memory dereference.

void CaptureDestroyMenu(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); }

void CaptureAppendMenuA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT flags, UINT_PTR newItem, LPCSTR text, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" newItem="); AppendHexText(detailBuffer, ApiReturnBits(newItem)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); }

void CaptureAppendMenuW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT flags, UINT_PTR newItem, LPCWSTR text, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" newItem="); AppendHexText(detailBuffer, ApiReturnBits(newItem)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); }

void CaptureInsertMenuA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT position, UINT flags, UINT_PTR newItem, LPCSTR text, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" position="); AppendHexText(detailBuffer, ApiReturnBits(position)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" newItem="); AppendHexText(detailBuffer, ApiReturnBits(newItem)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); }

void CaptureInsertMenuW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT position, UINT flags, UINT_PTR newItem, LPCWSTR text, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" position="); AppendHexText(detailBuffer, ApiReturnBits(position)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" newItem="); AppendHexText(detailBuffer, ApiReturnBits(newItem)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); }

void CaptureModifyMenuA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT position, UINT flags, UINT_PTR newItem, LPCSTR text, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" position="); AppendHexText(detailBuffer, ApiReturnBits(position)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" newItem="); AppendHexText(detailBuffer, ApiReturnBits(newItem)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); }

void CaptureModifyMenuW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT position, UINT flags, UINT_PTR newItem, LPCWSTR text, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" position="); AppendHexText(detailBuffer, ApiReturnBits(position)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" newItem="); AppendHexText(detailBuffer, ApiReturnBits(newItem)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); }

void CaptureRemoveMenu(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT position, UINT flags, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" position="); AppendHexText(detailBuffer, ApiReturnBits(position)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); }

void CaptureDeleteMenu(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT position, UINT flags, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" position="); AppendHexText(detailBuffer, ApiReturnBits(position)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); }

void CaptureSetMenu(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, HMENU menu, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); }

void CaptureDrawMenuBar(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); }

void CaptureGetMenuItemInfoA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT item, BOOL byPosition, LPMENUITEMINFOA info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" item="); AppendHexText(detailBuffer, ApiReturnBits(item)); AppendWideText(detailBuffer, L" byPosition="); AppendHexText(detailBuffer, ApiReturnBits(byPosition)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureGetMenuItemInfoW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT item, BOOL byPosition, LPMENUITEMINFOW info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" item="); AppendHexText(detailBuffer, ApiReturnBits(item)); AppendWideText(detailBuffer, L" byPosition="); AppendHexText(detailBuffer, ApiReturnBits(byPosition)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureSetMenuItemInfoA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT item, BOOL byPosition, LPCMENUITEMINFOA info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" item="); AppendHexText(detailBuffer, ApiReturnBits(item)); AppendWideText(detailBuffer, L" byPosition="); AppendHexText(detailBuffer, ApiReturnBits(byPosition)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureSetMenuItemInfoW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT item, BOOL byPosition, LPCMENUITEMINFOW info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" item="); AppendHexText(detailBuffer, ApiReturnBits(item)); AppendWideText(detailBuffer, L" byPosition="); AppendHexText(detailBuffer, ApiReturnBits(byPosition)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureGetMenuInfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, LPMENUINFO info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureSetMenuInfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, LPCMENUINFO info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureGetMenuItemRect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, HMENU menu, UINT item, LPRECT rectangle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" item="); AppendHexText(detailBuffer, ApiReturnBits(item)); AppendWideText(detailBuffer, L" rectangle="); AppendHexText(detailBuffer, ApiReturnBits(rectangle)); }

void CaptureHiliteMenuItem(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND window, HMENU menu, UINT item, UINT flags, BOOL resultValue)
{ AppendWideText(detailBuffer, L"window="); AppendHexText(detailBuffer, ApiReturnBits(window)); AppendWideText(detailBuffer, L" menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" item="); AppendHexText(detailBuffer, ApiReturnBits(item)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); }

void CaptureInsertMenuItemA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT item, BOOL byPosition, LPCMENUITEMINFOA info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" item="); AppendHexText(detailBuffer, ApiReturnBits(item)); AppendWideText(detailBuffer, L" byPosition="); AppendHexText(detailBuffer, ApiReturnBits(byPosition)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureInsertMenuItemW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT item, BOOL byPosition, LPCMENUITEMINFOW info, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" item="); AppendHexText(detailBuffer, ApiReturnBits(item)); AppendWideText(detailBuffer, L" byPosition="); AppendHexText(detailBuffer, ApiReturnBits(byPosition)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); }

void CaptureCheckMenuRadioItem(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT first, UINT last, UINT check, UINT flags, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" first="); AppendHexText(detailBuffer, ApiReturnBits(first)); AppendWideText(detailBuffer, L" last="); AppendHexText(detailBuffer, ApiReturnBits(last)); AppendWideText(detailBuffer, L" check="); AppendHexText(detailBuffer, ApiReturnBits(check)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); }

void CaptureSetMenuDefaultItem(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMENU menu, UINT item, UINT byPosition, BOOL resultValue)
{ AppendWideText(detailBuffer, L"menu="); AppendHexText(detailBuffer, ApiReturnBits(menu)); AppendWideText(detailBuffer, L" item="); AppendHexText(detailBuffer, ApiReturnBits(item)); AppendWideText(detailBuffer, L" byPosition="); AppendHexText(detailBuffer, ApiReturnBits(byPosition)); }
