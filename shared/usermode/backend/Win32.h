#pragma once

// Win32Lean.h must be included before any Windows SDK header in this project.
// It defines the lean include mode and disables min/max macros so C++ algorithms
// remain usable. There are no inputs and no runtime behavior.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
