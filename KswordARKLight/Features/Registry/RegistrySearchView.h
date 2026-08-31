#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Registry {

// CreateRegistrySearchView creates the separate read-only WinAPI registry
// search page.  Inputs are parent and bounds; output is the child HWND.  It
// deliberately has no R0 selector or mutation controls, so it cannot alter the
// existing registry browser's transport or write semantics.
HWND CreateRegistrySearchView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Registry
