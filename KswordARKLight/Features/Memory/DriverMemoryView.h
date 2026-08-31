#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Memory {

// CreateDriverMemoryView creates the Win32 child surface for driver-only memory
// read/write. Inputs are parent window and initial bounds; processing registers
// the page class and creates child controls; output is the page HWND or null on
// failure.
HWND CreateDriverMemoryView(HWND parent, const RECT& bounds);

// RequestDriverMemoryViewProcess selects a process as the next read/write
// target without issuing any driver request. It clears the stale editable
// buffer, restores neutral address/length inputs and focuses the address field
// so the user must explicitly choose the range and start a read.
bool RequestDriverMemoryViewProcess(HWND page, DWORD processId);

} // namespace Ksword::Features::Memory
