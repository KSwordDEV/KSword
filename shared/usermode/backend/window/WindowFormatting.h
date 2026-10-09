#pragma once
#include "../Common.h"
#include "WindowTypes.h"
namespace ks::r3::window {
std::wstring WindowStateText(const WindowSnapshotRow& row);
std::wstring HwndToText(HWND hwnd);
std::wstring RectToText(const RECT& rect);
}
