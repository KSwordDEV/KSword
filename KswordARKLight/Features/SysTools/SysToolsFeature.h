#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::SysTools {

// CreateSysToolsFeaturePage is the single entry point of the system-tools
// module. Inputs are the dock parent HWND and the initial bounds; processing
// builds one tab host that owns the five subviews (file-holder scan, event log,
// context-menu cleanup, system time, offline IOCTL decoder); output is the page
// HWND or nullptr.
//
// The five tools are grouped behind one page because none of them justifies a
// top-level dock entry on its own, and all five answer the same kind of
// question: what is the machine currently doing to itself.
HWND CreateSysToolsFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::SysTools
