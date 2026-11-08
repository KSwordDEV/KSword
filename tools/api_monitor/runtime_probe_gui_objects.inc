// Owned in-memory GDI resources only; all selected objects are restored before cleanup.
namespace apimon_probe {
#define GUI_OBJECT_CALL(id, name, ...) Call<decltype(&::name)>(id, L"Gdi32.dll", #name, __VA_ARGS__)
void RunGuiObjectCases() {
    Call<decltype(&::GetCurrentObject)>(921, L"Gdi32.dll", "GetCurrentObject", nullptr, OBJ_BITMAP);
    Call<decltype(&::GetObjectType)>(919, L"Gdi32.dll", "GetObjectType", static_cast<HGDIOBJ>(nullptr));
    HDC dc = CreateCompatibleDC(nullptr);
    unsigned char pixels[128]{};
    HBITMAP bitmap = GUI_OBJECT_CALL(900, CreateBitmap, 8, 8, UINT(1), UINT(1), pixels);
    BITMAP bitmapDesc{}; bitmapDesc.bmWidth = 8; bitmapDesc.bmHeight = 8;
    bitmapDesc.bmWidthBytes = 2; bitmapDesc.bmPlanes = 1; bitmapDesc.bmBitsPixel = 1; bitmapDesc.bmBits = pixels;
    HBITMAP indirect = GUI_OBJECT_CALL(901, CreateBitmapIndirect, &bitmapDesc);
    struct Dib { BITMAPINFOHEADER header; RGBQUAD colors[2]; BYTE pixels[32]; } dib{};
    dib.header.biSize = sizeof(BITMAPINFOHEADER); dib.header.biWidth = 8; dib.header.biHeight = 8;
    dib.header.biPlanes = 1; dib.header.biBitCount = 1; dib.header.biCompression = BI_RGB;
    dib.colors[1] = RGBQUAD{255, 255, 255, 0};
    auto info = reinterpret_cast<const BITMAPINFO*>(&dib);
    HBITMAP dibitmap = GUI_OBJECT_CALL(902, CreateDIBitmap, dc, &dib.header, DWORD(CBM_INIT), pixels, info, UINT(DIB_RGB_COLORS));
    void* dibBits = nullptr;
    HBITMAP section = GUI_OBJECT_CALL(903, CreateDIBSection, dc, info, UINT(DIB_RGB_COLORS), &dibBits, static_cast<HANDLE>(nullptr), DWORD(0));
    HBITMAP discardable = GUI_OBJECT_CALL(904, CreateDiscardableBitmap, dc, 8, 8);
    LOGBRUSH lb{BS_SOLID, RGB(30, 40, 50), 0};
    HBRUSH indirectBrush = GUI_OBJECT_CALL(905, CreateBrushIndirect, &lb);
    HBRUSH dibBrush = GUI_OBJECT_CALL(906, CreateDIBPatternBrushPt, &dib, UINT(DIB_RGB_COLORS));
    HBRUSH hatch = GUI_OBJECT_CALL(907, CreateHatchBrush, HS_CROSS, COLORREF(RGB(30, 40, 50)));
    HBRUSH pattern = GUI_OBJECT_CALL(908, CreatePatternBrush, bitmap);
    HBRUSH solid = GUI_OBJECT_CALL(909, CreateSolidBrush, COLORREF(RGB(30, 40, 50)));
    HPEN pen = GUI_OBJECT_CALL(910, CreatePen, PS_SOLID, 1, COLORREF(RGB(30, 40, 50)));
    LOGPEN lp{PS_SOLID, {1, 0}, RGB(30, 40, 50)};
    HPEN indirectPen = GUI_OBJECT_CALL(911, CreatePenIndirect, &lp);
    HPEN extendedPen = GUI_OBJECT_CALL(912, ExtCreatePen, DWORD(PS_GEOMETRIC | PS_SOLID), DWORD(1), &lb, DWORD(0), static_cast<const DWORD*>(nullptr));
    LOGFONTA fontA{}; fontA.lfHeight = 12; LOGFONTW fontW{}; fontW.lfHeight = 12;
    HFONT a = GUI_OBJECT_CALL(913, CreateFontIndirectA, &fontA);
    HFONT w = GUI_OBJECT_CALL(914, CreateFontIndirectW, &fontW);
    struct Palette { WORD version; WORD count; PALETTEENTRY entries[2]; } paletteSpec{0x300, 2, {{0, 0, 0, PC_RESERVED}, {255, 255, 255, PC_RESERVED}}};
    HPALETTE palette = GUI_OBJECT_CALL(915, CreatePalette, reinterpret_cast<const LOGPALETTE*>(&paletteSpec));
    HPALETTE halftone = GUI_OBJECT_CALL(916, CreateHalftonePalette, dc);
    BITMAP objectA{}, objectW{};
    GUI_OBJECT_CALL(917, GetObjectA, bitmap, int(sizeof(objectA)), &objectA);
    GUI_OBJECT_CALL(918, GetObjectW, bitmap, int(sizeof(objectW)), &objectW);
    GUI_OBJECT_CALL(919, GetObjectType, bitmap);
    GUI_OBJECT_CALL(920, GetStockObject, BLACK_BRUSH);
    GUI_OBJECT_CALL(921, GetCurrentObject, dc, UINT(OBJ_FONT));
    GUI_OBJECT_CALL(922, ResizePalette, palette, UINT(2));
    GUI_OBJECT_CALL(923, AnimatePalette, palette, UINT(0), UINT(2), paletteSpec.entries);
    GUI_OBJECT_CALL(924, UnrealizeObject, palette);
    HGDIOBJ oldFont = w && dc ? SelectObject(dc, w) : nullptr;
    int widths[2]{}; ABC abc[2]{}; RASTERIZER_STATUS raster{};
    GUI_OBJECT_CALL(925, GetOutlineTextMetricsA, dc, UINT(0), static_cast<LPOUTLINETEXTMETRICA>(nullptr));
    GUI_OBJECT_CALL(926, GetOutlineTextMetricsW, dc, UINT(0), static_cast<LPOUTLINETEXTMETRICW>(nullptr));
    GUI_OBJECT_CALL(927, GetRasterizerCaps, &raster, UINT(sizeof(raster)));
    GUI_OBJECT_CALL(928, GetFontUnicodeRanges, dc, static_cast<LPGLYPHSET>(nullptr));
    GUI_OBJECT_CALL(929, GetCharWidth32A, dc, UINT('A'), UINT('B'), widths);
    GUI_OBJECT_CALL(930, GetCharWidth32W, dc, UINT('A'), UINT('B'), widths);
    GUI_OBJECT_CALL(931, GetCharABCWidthsA, dc, UINT('A'), UINT('B'), abc);
    GUI_OBJECT_CALL(932, GetCharABCWidthsW, dc, UINT('A'), UINT('B'), abc);
    if (oldFont && oldFont != HGDI_ERROR) SelectObject(dc, oldFont);
    HGDIOBJ objects[] = {bitmap, indirect, dibitmap, section, discardable, indirectBrush, dibBrush, hatch, pattern, solid, pen, indirectPen, extendedPen, a, w, palette, halftone};
    for (HGDIOBJ object : objects) if (object) DeleteObject(object);
    if (dc) DeleteDC(dc);
}
#undef GUI_OBJECT_CALL
}
