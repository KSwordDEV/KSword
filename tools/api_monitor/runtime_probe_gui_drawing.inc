// Owned memory DC only. Included after runtime_probe_support.h.
namespace apimon_probe {
#define GUI_DRAW_CALL(id, name, ...) Call<decltype(&::name)>(id, L"Gdi32.dll", #name, __VA_ARGS__)
void RunGuiDrawingCases() {
    HDC dc = CreateCompatibleDC(nullptr);
    HBITMAP bitmap = CreateBitmap(32, 32, 1, 32, nullptr);
    HGDIOBJ old = dc && bitmap ? SelectObject(dc, bitmap) : nullptr;
    POINT point{}; POINT points[4]{{1,1},{5,10},{10,5},{15,15}};
    DWORD counts[1]{4}; SIZE size{}; TEXTMETRICA metricsA{}; TEXTMETRICW metricsW{};
    GUI_DRAW_CALL(950, MoveToEx, dc, 2, 2, &point);
    GUI_DRAW_CALL(951, LineTo, dc, 12, 12);
    GUI_DRAW_CALL(951, LineTo, nullptr, 0, 0);
    GUI_DRAW_CALL(952, Polyline, dc, points, 4);
    GUI_DRAW_CALL(953, Polygon, dc, points, 4);
    GUI_DRAW_CALL(954, PolyBezier, dc, points, DWORD(4));
    GUI_DRAW_CALL(955, PolyBezierTo, dc, points, DWORD(3));
    GUI_DRAW_CALL(956, PolylineTo, dc, points, DWORD(4));
    GUI_DRAW_CALL(957, PolyPolyline, dc, points, counts, DWORD(1));
    GUI_DRAW_CALL(958, Rectangle, dc, 1, 1, 20, 20);
    GUI_DRAW_CALL(959, RoundRect, dc, 1, 1, 20, 20, 4, 4);
    GUI_DRAW_CALL(960, Ellipse, dc, 1, 1, 20, 20);
    GUI_DRAW_CALL(961, Arc, dc, 1, 1, 20, 20, 1, 10, 20, 10);
    GUI_DRAW_CALL(962, ArcTo, dc, 1, 1, 20, 20, 1, 10, 20, 10);
    GUI_DRAW_CALL(963, Chord, dc, 1, 1, 20, 20, 1, 10, 20, 10);
    GUI_DRAW_CALL(964, Pie, dc, 1, 1, 20, 20, 1, 10, 20, 10);
    GUI_DRAW_CALL(965, BeginPath, dc);
    BeginPath(dc); MoveToEx(dc, 1, 1, nullptr); LineTo(dc, 10, 10);
    GUI_DRAW_CALL(966, EndPath, dc);
    BeginPath(dc); Rectangle(dc, 1, 1, 16, 16); EndPath(dc);
    GUI_DRAW_CALL(967, FillPath, dc);
    BeginPath(dc); Rectangle(dc, 1, 1, 16, 16); EndPath(dc);
    GUI_DRAW_CALL(968, StrokePath, dc);
    BeginPath(dc); Rectangle(dc, 1, 1, 16, 16); EndPath(dc);
    GUI_DRAW_CALL(969, StrokeAndFillPath, dc);
    BeginPath(dc); MoveToEx(dc, 1, 1, nullptr); LineTo(dc, 10, 10);
    GUI_DRAW_CALL(970, AbortPath, dc);
    BeginPath(dc); MoveToEx(dc, 1, 1, nullptr); LineTo(dc, 10, 10);
    GUI_DRAW_CALL(971, CloseFigure, dc);
    BeginPath(dc); Rectangle(dc, 1, 1, 16, 16); EndPath(dc);
    GUI_DRAW_CALL(972, FlattenPath, dc);
    BeginPath(dc); Rectangle(dc, 1, 1, 16, 16); EndPath(dc);
    GUI_DRAW_CALL(973, WidenPath, dc);
    BeginPath(dc); Rectangle(dc, 1, 1, 16, 16); EndPath(dc);
    GUI_DRAW_CALL(974, SelectClipPath, dc, RGN_COPY);
    GUI_DRAW_CALL(975, GetCurrentPositionEx, dc, &point);
    GUI_DRAW_CALL(976, SetViewportOrgEx, dc, 0, 0, &point);
    GUI_DRAW_CALL(977, OffsetViewportOrgEx, dc, 1, 1, &point);
    GUI_DRAW_CALL(978, SetWindowOrgEx, dc, 0, 0, &point);
    GUI_DRAW_CALL(979, OffsetWindowOrgEx, dc, 1, 1, &point);
    GUI_DRAW_CALL(980, SetViewportExtEx, dc, 32, 32, &size);
    GUI_DRAW_CALL(981, SetWindowExtEx, dc, 32, 32, &size);
    GUI_DRAW_CALL(982, ScaleViewportExtEx, dc, 1, 1, 1, 1, &size);
    GUI_DRAW_CALL(983, ScaleWindowExtEx, dc, 1, 1, 1, 1, &size);
    GUI_DRAW_CALL(984, DPtoLP, dc, &point, 1);
    GUI_DRAW_CALL(985, LPtoDP, dc, &point, 1);
    GUI_DRAW_CALL(986, GetViewportOrgEx, dc, &point);
    GUI_DRAW_CALL(987, GetWindowOrgEx, dc, &point);
    GUI_DRAW_CALL(988, GetViewportExtEx, dc, &size);
    GUI_DRAW_CALL(989, GetWindowExtEx, dc, &size);
    GUI_DRAW_CALL(990, GetTextExtentPoint32A, dc, "abc", 3, &size);
    GUI_DRAW_CALL(991, GetTextExtentPoint32W, dc, L"abc", 3, &size);
    GUI_DRAW_CALL(992, GetTextMetricsA, dc, &metricsA);
    GUI_DRAW_CALL(993, GetTextMetricsW, dc, &metricsW);
    if (dc && old && old != HGDI_ERROR) SelectObject(dc, old);
    if (bitmap) DeleteObject(bitmap);
    if (dc) DeleteDC(dc);
}
#undef GUI_DRAW_CALL
}
