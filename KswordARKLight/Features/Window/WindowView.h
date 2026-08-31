#pragma once

#include "../../Core/Win32Lean.h"

#include <string>

namespace Ksword::Features::Window {

// CreateWindowFeatureView creates the retained non-desktop window-management
// page. Inputs are parent HWND and parent-relative bounds; processing registers
// a Win32 page class, creates list/detail controls, and performs an initial
// EnumWindows snapshot; output is the child page HWND or nullptr on failure.
HWND CreateWindowFeatureView(HWND parent, const RECT& bounds);

bool RequestWindowFeatureViewQuery(HWND page, const std::wstring& query);

} // namespace Ksword::Features::Window
