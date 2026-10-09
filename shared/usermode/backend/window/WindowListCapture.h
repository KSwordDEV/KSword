#pragma once
#include "../Common.h"
#include "WindowTypes.h"
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x11
#endif
namespace ks::r3::window {
std::wstring CaptureAffinityText(const DWORD affinity);
std::wstring ApplyWindowListCaptureAffinity(HWND window, DWORD affinity);
}
