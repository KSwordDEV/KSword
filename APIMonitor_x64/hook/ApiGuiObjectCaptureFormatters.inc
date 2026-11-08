// GDI object arguments: scalar values and addresses only; no caller memory is read.

void CaptureCreateBitmap(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], int width, int height, UINT planes, UINT bitsPerPixel, const void* bits, HBITMAP resultValue)
{ AppendWideText(detailBuffer, L"width="); AppendHexText(detailBuffer, ApiReturnBits(width)); AppendWideText(detailBuffer, L" height="); AppendHexText(detailBuffer, ApiReturnBits(height)); AppendWideText(detailBuffer, L" planes="); AppendHexText(detailBuffer, ApiReturnBits(planes)); AppendWideText(detailBuffer, L" bitsPerPixel="); AppendHexText(detailBuffer, ApiReturnBits(bitsPerPixel)); AppendWideText(detailBuffer, L" bits="); AppendHexText(detailBuffer, ApiReturnBits(bits)); }

void CaptureCreateBitmapIndirect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const BITMAP* bitmap, HBITMAP resultValue)
{ AppendWideText(detailBuffer, L"bitmap="); AppendHexText(detailBuffer, ApiReturnBits(bitmap)); }

void CaptureCreateDIBitmap(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, const BITMAPINFOHEADER* header, DWORD init, const void* bits, const BITMAPINFO* info, UINT usage, HBITMAP resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" header="); AppendHexText(detailBuffer, ApiReturnBits(header)); AppendWideText(detailBuffer, L" init="); AppendHexText(detailBuffer, ApiReturnBits(init)); AppendWideText(detailBuffer, L" bits="); AppendHexText(detailBuffer, ApiReturnBits(bits)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); AppendWideText(detailBuffer, L" usage="); AppendHexText(detailBuffer, ApiReturnBits(usage)); }

void CaptureCreateDIBSection(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, const BITMAPINFO* info, UINT usage, void** bits, HANDLE section, DWORD offset, HBITMAP resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" info="); AppendHexText(detailBuffer, ApiReturnBits(info)); AppendWideText(detailBuffer, L" usage="); AppendHexText(detailBuffer, ApiReturnBits(usage)); AppendWideText(detailBuffer, L" bits="); AppendHexText(detailBuffer, ApiReturnBits(bits)); AppendWideText(detailBuffer, L" section="); AppendHexText(detailBuffer, ApiReturnBits(section)); AppendWideText(detailBuffer, L" offset="); AppendHexText(detailBuffer, ApiReturnBits(offset)); }

void CaptureCreateDiscardableBitmap(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int width, int height, HBITMAP resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" width="); AppendHexText(detailBuffer, ApiReturnBits(width)); AppendWideText(detailBuffer, L" height="); AppendHexText(detailBuffer, ApiReturnBits(height)); }

void CaptureCreateBrushIndirect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const LOGBRUSH* brush, HBRUSH resultValue)
{ AppendWideText(detailBuffer, L"brush="); AppendHexText(detailBuffer, ApiReturnBits(brush)); }

void CaptureCreateDIBPatternBrushPt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const void* packedDib, UINT usage, HBRUSH resultValue)
{ AppendWideText(detailBuffer, L"packedDib="); AppendHexText(detailBuffer, ApiReturnBits(packedDib)); AppendWideText(detailBuffer, L" usage="); AppendHexText(detailBuffer, ApiReturnBits(usage)); }

void CaptureCreateHatchBrush(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], int hatch, COLORREF color, HBRUSH resultValue)
{ AppendWideText(detailBuffer, L"hatch="); AppendHexText(detailBuffer, ApiReturnBits(hatch)); AppendWideText(detailBuffer, L" color="); AppendHexText(detailBuffer, ApiReturnBits(color)); }

void CaptureCreatePatternBrush(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HBITMAP bitmap, HBRUSH resultValue)
{ AppendWideText(detailBuffer, L"bitmap="); AppendHexText(detailBuffer, ApiReturnBits(bitmap)); }

void CaptureCreateSolidBrush(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], COLORREF color, HBRUSH resultValue)
{ AppendWideText(detailBuffer, L"color="); AppendHexText(detailBuffer, ApiReturnBits(color)); }

void CaptureCreatePen(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], int style, int width, COLORREF color, HPEN resultValue)
{ AppendWideText(detailBuffer, L"style="); AppendHexText(detailBuffer, ApiReturnBits(style)); AppendWideText(detailBuffer, L" width="); AppendHexText(detailBuffer, ApiReturnBits(width)); AppendWideText(detailBuffer, L" color="); AppendHexText(detailBuffer, ApiReturnBits(color)); }

void CaptureCreatePenIndirect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const LOGPEN* pen, HPEN resultValue)
{ AppendWideText(detailBuffer, L"pen="); AppendHexText(detailBuffer, ApiReturnBits(pen)); }

void CaptureExtCreatePen(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD style, DWORD width, const LOGBRUSH* brush, DWORD styleCount, const DWORD* styleEntries, HPEN resultValue)
{ AppendWideText(detailBuffer, L"style="); AppendHexText(detailBuffer, ApiReturnBits(style)); AppendWideText(detailBuffer, L" width="); AppendHexText(detailBuffer, ApiReturnBits(width)); AppendWideText(detailBuffer, L" brush="); AppendHexText(detailBuffer, ApiReturnBits(brush)); AppendWideText(detailBuffer, L" styleCount="); AppendHexText(detailBuffer, ApiReturnBits(styleCount)); AppendWideText(detailBuffer, L" styleEntries="); AppendHexText(detailBuffer, ApiReturnBits(styleEntries)); }

void CaptureCreateFontIndirectA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const LOGFONTA* font, HFONT resultValue)
{ AppendWideText(detailBuffer, L"font="); AppendHexText(detailBuffer, ApiReturnBits(font)); }

void CaptureCreateFontIndirectW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const LOGFONTW* font, HFONT resultValue)
{ AppendWideText(detailBuffer, L"font="); AppendHexText(detailBuffer, ApiReturnBits(font)); }

void CaptureCreatePalette(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const LOGPALETTE* palette, HPALETTE resultValue)
{ AppendWideText(detailBuffer, L"palette="); AppendHexText(detailBuffer, ApiReturnBits(palette)); }

void CaptureCreateHalftonePalette(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, HPALETTE resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); }

void CaptureGetObjectA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE object, int bufferSize, LPVOID buffer, int resultValue)
{ AppendWideText(detailBuffer, L"object="); AppendHexText(detailBuffer, ApiReturnBits(object)); AppendWideText(detailBuffer, L" bufferSize="); AppendHexText(detailBuffer, ApiReturnBits(bufferSize)); AppendWideText(detailBuffer, L" buffer="); AppendHexText(detailBuffer, ApiReturnBits(buffer)); }

void CaptureGetObjectW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE object, int bufferSize, LPVOID buffer, int resultValue)
{ AppendWideText(detailBuffer, L"object="); AppendHexText(detailBuffer, ApiReturnBits(object)); AppendWideText(detailBuffer, L" bufferSize="); AppendHexText(detailBuffer, ApiReturnBits(bufferSize)); AppendWideText(detailBuffer, L" buffer="); AppendHexText(detailBuffer, ApiReturnBits(buffer)); }

void CaptureGetObjectType(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HGDIOBJ object, DWORD resultValue)
{ AppendWideText(detailBuffer, L"object="); AppendHexText(detailBuffer, ApiReturnBits(object)); }

void CaptureGetStockObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], int index, HGDIOBJ resultValue)
{ AppendWideText(detailBuffer, L"index="); AppendHexText(detailBuffer, ApiReturnBits(index)); }

void CaptureGetCurrentObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, UINT type, HGDIOBJ resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, ApiReturnBits(type)); }

void CaptureResizePalette(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HPALETTE palette, UINT count, BOOL resultValue)
{ AppendWideText(detailBuffer, L"palette="); AppendHexText(detailBuffer, ApiReturnBits(palette)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); }

void CaptureAnimatePalette(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HPALETTE palette, UINT start, UINT count, const PALETTEENTRY* entries, BOOL resultValue)
{ AppendWideText(detailBuffer, L"palette="); AppendHexText(detailBuffer, ApiReturnBits(palette)); AppendWideText(detailBuffer, L" start="); AppendHexText(detailBuffer, ApiReturnBits(start)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); AppendWideText(detailBuffer, L" entries="); AppendHexText(detailBuffer, ApiReturnBits(entries)); }

void CaptureUnrealizeObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HGDIOBJ object, BOOL resultValue)
{ AppendWideText(detailBuffer, L"object="); AppendHexText(detailBuffer, ApiReturnBits(object)); }

void CaptureGetOutlineTextMetricsA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, UINT bufferSize, LPOUTLINETEXTMETRICA metrics, UINT resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" bufferSize="); AppendHexText(detailBuffer, ApiReturnBits(bufferSize)); AppendWideText(detailBuffer, L" metrics="); AppendHexText(detailBuffer, ApiReturnBits(metrics)); }

void CaptureGetOutlineTextMetricsW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, UINT bufferSize, LPOUTLINETEXTMETRICW metrics, UINT resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" bufferSize="); AppendHexText(detailBuffer, ApiReturnBits(bufferSize)); AppendWideText(detailBuffer, L" metrics="); AppendHexText(detailBuffer, ApiReturnBits(metrics)); }

void CaptureGetRasterizerCaps(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPRASTERIZER_STATUS status, UINT size, BOOL resultValue)
{ AppendWideText(detailBuffer, L"status="); AppendHexText(detailBuffer, ApiReturnBits(status)); AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, ApiReturnBits(size)); }

void CaptureGetFontUnicodeRanges(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPGLYPHSET glyphSet, DWORD resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" glyphSet="); AppendHexText(detailBuffer, ApiReturnBits(glyphSet)); }

void CaptureGetCharWidth32A(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, UINT first, UINT last, LPINT widths, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" first="); AppendHexText(detailBuffer, ApiReturnBits(first)); AppendWideText(detailBuffer, L" last="); AppendHexText(detailBuffer, ApiReturnBits(last)); AppendWideText(detailBuffer, L" widths="); AppendHexText(detailBuffer, ApiReturnBits(widths)); }

void CaptureGetCharWidth32W(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, UINT first, UINT last, LPINT widths, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" first="); AppendHexText(detailBuffer, ApiReturnBits(first)); AppendWideText(detailBuffer, L" last="); AppendHexText(detailBuffer, ApiReturnBits(last)); AppendWideText(detailBuffer, L" widths="); AppendHexText(detailBuffer, ApiReturnBits(widths)); }

void CaptureGetCharABCWidthsA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, UINT first, UINT last, LPABC widths, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" first="); AppendHexText(detailBuffer, ApiReturnBits(first)); AppendWideText(detailBuffer, L" last="); AppendHexText(detailBuffer, ApiReturnBits(last)); AppendWideText(detailBuffer, L" widths="); AppendHexText(detailBuffer, ApiReturnBits(widths)); }

void CaptureGetCharABCWidthsW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, UINT first, UINT last, LPABC widths, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" first="); AppendHexText(detailBuffer, ApiReturnBits(first)); AppendWideText(detailBuffer, L" last="); AppendHexText(detailBuffer, ApiReturnBits(last)); AppendWideText(detailBuffer, L" widths="); AppendHexText(detailBuffer, ApiReturnBits(widths)); }
