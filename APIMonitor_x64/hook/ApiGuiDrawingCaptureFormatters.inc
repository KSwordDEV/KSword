// GDI drawing and DC formatters; no caller memory is dereferenced.
void CaptureMoveToEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int x, int y, LPPOINT previous, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); AppendWideText(detailBuffer, L" previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); }

void CaptureLineTo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int x, int y, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); }

void CapturePolyline(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, const POINT* points, int count, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" points="); AppendHexText(detailBuffer, ApiReturnBits(points)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); }

void CapturePolygon(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, const POINT* points, int count, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" points="); AppendHexText(detailBuffer, ApiReturnBits(points)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); }

void CapturePolyBezier(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, const POINT* points, DWORD count, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" points="); AppendHexText(detailBuffer, ApiReturnBits(points)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); }

void CapturePolyBezierTo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, const POINT* points, DWORD count, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" points="); AppendHexText(detailBuffer, ApiReturnBits(points)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); }

void CapturePolylineTo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, const POINT* points, DWORD count, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" points="); AppendHexText(detailBuffer, ApiReturnBits(points)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); }

void CapturePolyPolyline(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, const POINT* points, const DWORD* counts, DWORD polylines, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" points="); AppendHexText(detailBuffer, ApiReturnBits(points)); AppendWideText(detailBuffer, L" counts="); AppendHexText(detailBuffer, ApiReturnBits(counts)); AppendWideText(detailBuffer, L" polylines="); AppendHexText(detailBuffer, ApiReturnBits(polylines)); }

void CaptureRectangle(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int left, int top, int right, int bottom, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" left="); AppendHexText(detailBuffer, ApiReturnBits(left)); AppendWideText(detailBuffer, L" top="); AppendHexText(detailBuffer, ApiReturnBits(top)); AppendWideText(detailBuffer, L" right="); AppendHexText(detailBuffer, ApiReturnBits(right)); AppendWideText(detailBuffer, L" bottom="); AppendHexText(detailBuffer, ApiReturnBits(bottom)); }

void CaptureRoundRect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int left, int top, int right, int bottom, int width, int height, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" left="); AppendHexText(detailBuffer, ApiReturnBits(left)); AppendWideText(detailBuffer, L" top="); AppendHexText(detailBuffer, ApiReturnBits(top)); AppendWideText(detailBuffer, L" right="); AppendHexText(detailBuffer, ApiReturnBits(right)); AppendWideText(detailBuffer, L" bottom="); AppendHexText(detailBuffer, ApiReturnBits(bottom)); AppendWideText(detailBuffer, L" width="); AppendHexText(detailBuffer, ApiReturnBits(width)); AppendWideText(detailBuffer, L" height="); AppendHexText(detailBuffer, ApiReturnBits(height)); }

void CaptureEllipse(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int left, int top, int right, int bottom, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" left="); AppendHexText(detailBuffer, ApiReturnBits(left)); AppendWideText(detailBuffer, L" top="); AppendHexText(detailBuffer, ApiReturnBits(top)); AppendWideText(detailBuffer, L" right="); AppendHexText(detailBuffer, ApiReturnBits(right)); AppendWideText(detailBuffer, L" bottom="); AppendHexText(detailBuffer, ApiReturnBits(bottom)); }

void CaptureArc(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int left, int top, int right, int bottom, int startX, int startY, int endX, int endY, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" left="); AppendHexText(detailBuffer, ApiReturnBits(left)); AppendWideText(detailBuffer, L" top="); AppendHexText(detailBuffer, ApiReturnBits(top)); AppendWideText(detailBuffer, L" right="); AppendHexText(detailBuffer, ApiReturnBits(right)); AppendWideText(detailBuffer, L" bottom="); AppendHexText(detailBuffer, ApiReturnBits(bottom)); AppendWideText(detailBuffer, L" startX="); AppendHexText(detailBuffer, ApiReturnBits(startX)); AppendWideText(detailBuffer, L" startY="); AppendHexText(detailBuffer, ApiReturnBits(startY)); AppendWideText(detailBuffer, L" endX="); AppendHexText(detailBuffer, ApiReturnBits(endX)); AppendWideText(detailBuffer, L" endY="); AppendHexText(detailBuffer, ApiReturnBits(endY)); }

void CaptureArcTo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int left, int top, int right, int bottom, int startX, int startY, int endX, int endY, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" left="); AppendHexText(detailBuffer, ApiReturnBits(left)); AppendWideText(detailBuffer, L" top="); AppendHexText(detailBuffer, ApiReturnBits(top)); AppendWideText(detailBuffer, L" right="); AppendHexText(detailBuffer, ApiReturnBits(right)); AppendWideText(detailBuffer, L" bottom="); AppendHexText(detailBuffer, ApiReturnBits(bottom)); AppendWideText(detailBuffer, L" startX="); AppendHexText(detailBuffer, ApiReturnBits(startX)); AppendWideText(detailBuffer, L" startY="); AppendHexText(detailBuffer, ApiReturnBits(startY)); AppendWideText(detailBuffer, L" endX="); AppendHexText(detailBuffer, ApiReturnBits(endX)); AppendWideText(detailBuffer, L" endY="); AppendHexText(detailBuffer, ApiReturnBits(endY)); }

void CaptureChord(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int left, int top, int right, int bottom, int startX, int startY, int endX, int endY, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" left="); AppendHexText(detailBuffer, ApiReturnBits(left)); AppendWideText(detailBuffer, L" top="); AppendHexText(detailBuffer, ApiReturnBits(top)); AppendWideText(detailBuffer, L" right="); AppendHexText(detailBuffer, ApiReturnBits(right)); AppendWideText(detailBuffer, L" bottom="); AppendHexText(detailBuffer, ApiReturnBits(bottom)); AppendWideText(detailBuffer, L" startX="); AppendHexText(detailBuffer, ApiReturnBits(startX)); AppendWideText(detailBuffer, L" startY="); AppendHexText(detailBuffer, ApiReturnBits(startY)); AppendWideText(detailBuffer, L" endX="); AppendHexText(detailBuffer, ApiReturnBits(endX)); AppendWideText(detailBuffer, L" endY="); AppendHexText(detailBuffer, ApiReturnBits(endY)); }

void CapturePie(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int left, int top, int right, int bottom, int startX, int startY, int endX, int endY, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" left="); AppendHexText(detailBuffer, ApiReturnBits(left)); AppendWideText(detailBuffer, L" top="); AppendHexText(detailBuffer, ApiReturnBits(top)); AppendWideText(detailBuffer, L" right="); AppendHexText(detailBuffer, ApiReturnBits(right)); AppendWideText(detailBuffer, L" bottom="); AppendHexText(detailBuffer, ApiReturnBits(bottom)); AppendWideText(detailBuffer, L" startX="); AppendHexText(detailBuffer, ApiReturnBits(startX)); AppendWideText(detailBuffer, L" startY="); AppendHexText(detailBuffer, ApiReturnBits(startY)); AppendWideText(detailBuffer, L" endX="); AppendHexText(detailBuffer, ApiReturnBits(endX)); AppendWideText(detailBuffer, L" endY="); AppendHexText(detailBuffer, ApiReturnBits(endY)); }

void CaptureBeginPath(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); }

void CaptureEndPath(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); }

void CaptureFillPath(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); }

void CaptureStrokePath(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); }

void CaptureStrokeAndFillPath(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); }

void CaptureAbortPath(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); }

void CaptureCloseFigure(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); }

void CaptureFlattenPath(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); }

void CaptureWidenPath(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); }

void CaptureSelectClipPath(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int mode, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" mode="); AppendHexText(detailBuffer, ApiReturnBits(mode)); }

void CaptureGetCurrentPositionEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPPOINT point, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" point="); AppendHexText(detailBuffer, ApiReturnBits(point)); }

void CaptureSetViewportOrgEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int x, int y, LPPOINT previous, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); AppendWideText(detailBuffer, L" previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); }

void CaptureOffsetViewportOrgEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int x, int y, LPPOINT previous, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); AppendWideText(detailBuffer, L" previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); }

void CaptureSetWindowOrgEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int x, int y, LPPOINT previous, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); AppendWideText(detailBuffer, L" previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); }

void CaptureOffsetWindowOrgEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int x, int y, LPPOINT previous, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); AppendWideText(detailBuffer, L" previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); }

void CaptureSetViewportExtEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int x, int y, LPSIZE previous, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); AppendWideText(detailBuffer, L" previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); }

void CaptureSetWindowExtEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int x, int y, LPSIZE previous, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" x="); AppendHexText(detailBuffer, ApiReturnBits(x)); AppendWideText(detailBuffer, L" y="); AppendHexText(detailBuffer, ApiReturnBits(y)); AppendWideText(detailBuffer, L" previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); }

void CaptureScaleViewportExtEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int xNum, int xDenom, int yNum, int yDenom, LPSIZE previous, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" xNum="); AppendHexText(detailBuffer, ApiReturnBits(xNum)); AppendWideText(detailBuffer, L" xDenom="); AppendHexText(detailBuffer, ApiReturnBits(xDenom)); AppendWideText(detailBuffer, L" yNum="); AppendHexText(detailBuffer, ApiReturnBits(yNum)); AppendWideText(detailBuffer, L" yDenom="); AppendHexText(detailBuffer, ApiReturnBits(yDenom)); AppendWideText(detailBuffer, L" previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); }

void CaptureScaleWindowExtEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, int xNum, int xDenom, int yNum, int yDenom, LPSIZE previous, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" xNum="); AppendHexText(detailBuffer, ApiReturnBits(xNum)); AppendWideText(detailBuffer, L" xDenom="); AppendHexText(detailBuffer, ApiReturnBits(xDenom)); AppendWideText(detailBuffer, L" yNum="); AppendHexText(detailBuffer, ApiReturnBits(yNum)); AppendWideText(detailBuffer, L" yDenom="); AppendHexText(detailBuffer, ApiReturnBits(yDenom)); AppendWideText(detailBuffer, L" previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); }

void CaptureDPtoLP(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPPOINT points, int count, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" points="); AppendHexText(detailBuffer, ApiReturnBits(points)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); }

void CaptureLPtoDP(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPPOINT points, int count, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" points="); AppendHexText(detailBuffer, ApiReturnBits(points)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); }

void CaptureGetViewportOrgEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPPOINT point, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" point="); AppendHexText(detailBuffer, ApiReturnBits(point)); }

void CaptureGetWindowOrgEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPPOINT point, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" point="); AppendHexText(detailBuffer, ApiReturnBits(point)); }

void CaptureGetViewportExtEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPSIZE size, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, ApiReturnBits(size)); }

void CaptureGetWindowExtEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPSIZE size, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, ApiReturnBits(size)); }

void CaptureGetTextExtentPoint32A(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPCSTR text, int count, LPSIZE size, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, ApiReturnBits(size)); }

void CaptureGetTextExtentPoint32W(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPCWSTR text, int count, LPSIZE size, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, ApiReturnBits(count)); AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, ApiReturnBits(size)); }

void CaptureGetTextMetricsA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPTEXTMETRICA metrics, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" metrics="); AppendHexText(detailBuffer, ApiReturnBits(metrics)); }

void CaptureGetTextMetricsW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC dc, LPTEXTMETRICW metrics, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, ApiReturnBits(dc)); AppendWideText(detailBuffer, L" metrics="); AppendHexText(detailBuffer, ApiReturnBits(metrics)); }
