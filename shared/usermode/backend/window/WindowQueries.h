#pragma once
#include "../Common.h"
#include "WindowToolsTypes.h"
namespace ks::r3::window_tools {
std::wstring LeafName(const std::wstring& path, DWORD processId);
TopLevelWindowInfo ReadWindowInfo(HWND hwnd);
BOOL CALLBACK EnumTopLevelThunk(HWND hwnd, LPARAM lParam);
std::vector<TopLevelWindowInfo> EnumerateTopLevelWindowInfo();
std::wstring HwndText(HWND hwnd);
std::wstring HexText(const std::uint64_t value, const int digits);
std::wstring WindowTitleText(HWND hwnd);
std::wstring WindowClassText(HWND hwnd);
std::wstring ProcessNameFromId(const DWORD processId);
std::wstring DisplayAffinityText(const DWORD affinity, const bool known);
}
