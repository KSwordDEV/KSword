#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Memory {

// CreateMemoryFeaturePage is the module-local facade for the memory feature UI.
// Inputs are the dock parent and initial bounds; processing creates the
// driver-only memory read/write view; output is the page HWND or null on failure.
HWND CreateMemoryFeaturePage(HWND parent, const RECT& bounds);

// RequestMemoryFeatureProcess forwards an existing process identity to the
// driver-memory page. It only fills local controls; it never auto-reads or
// auto-writes and remains usable when the driver is unavailable.
bool RequestMemoryFeatureProcess(HWND page, DWORD processId);

} // namespace Ksword::Features::Memory
