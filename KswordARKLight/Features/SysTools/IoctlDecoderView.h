#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::SysTools {

// CreateIoctlDecoderView creates the native, offline CTL_CODE decoder page.
// Inputs are the workspace parent and bounds; processing creates only Win32
// controls and never queries a driver; output is a child HWND or nullptr.
HWND CreateIoctlDecoderView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::SysTools
