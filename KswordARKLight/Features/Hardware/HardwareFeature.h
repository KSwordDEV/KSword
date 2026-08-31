#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Hardware {

// CreateHardwareFeaturePage creates the unified Hardware workspace. It owns
// device/CPU/HWID audit pages plus performance monitoring, disk activity, USB
// topology and system-bus pages; every tab retains its own controls and state.
HWND CreateHardwareFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Hardware
