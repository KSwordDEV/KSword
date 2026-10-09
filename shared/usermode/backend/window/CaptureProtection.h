#pragma once
#include "../Common.h"
#include "WindowQueries.h"
namespace ks::r3::window_tools {
std::wstring ApplyDisplayAffinity(HWND window, DWORD affinity);
}
