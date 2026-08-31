#pragma once

#include "../../Core/Win32Lean.h"

#include <string>

namespace Ksword::Features::File {

// CreateFileViewPage creates the native Win32 file page used by KswordARKLight.
// Inputs are the parent HWND and initial bounds; processing creates a toolbar,
// path box, report list, status line and right-click action surface; output is
// the page HWND, or null if class/window creation fails.
HWND CreateFileViewPage(HWND parent, const RECT& bounds);

// RequestFileViewNavigate synchronously navigates an existing browser page to
// an absolute Win32/UNC/NT path supplied by the shell entity router.
bool RequestFileViewNavigate(HWND page, const std::wstring& path);

} // namespace Ksword::Features::File
