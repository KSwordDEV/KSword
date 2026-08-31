#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::NetTools {

// CreateNetToolsConnectionView creates the TCP/UDP connection management tab.
// Inputs are the tab-host parent HWND and initial bounds; processing registers
// the window class once and creates the child page; output is the page HWND or
// nullptr on failure.
HWND CreateNetToolsConnectionView(HWND parent, const RECT& bounds);

bool RequestNetToolsConnectionProcessFilter(HWND page, DWORD processId);

} // namespace Ksword::Features::NetTools
