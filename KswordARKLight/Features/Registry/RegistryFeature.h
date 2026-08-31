#pragma once

#include "../../Core/Win32Lean.h"

#include <string>

namespace Ksword::Features::Registry {

// CreateRegistryFeaturePage is the module-local facade for the registry dock.
// Inputs are parent HWND and initial bounds; output is the root page HWND.
HWND CreateRegistryFeaturePage(HWND parent, const RECT& bounds);

bool RequestRegistryFeatureNavigate(HWND page, const std::wstring& path);

} // namespace Ksword::Features::Registry
