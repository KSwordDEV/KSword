#pragma once
#include "../Win32.h"
#include <cfgmgr32.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
namespace ks::r3::window_tools {
struct TopLevelWindowInfo final {
    HWND hwnd = nullptr;
    DWORD processId = 0;
    DWORD threadId = 0;
    DWORD style = 0;
    DWORD exStyle = 0;
    DWORD displayAffinity = 0;
    bool displayAffinityKnown = false;
    bool visible = false;
    std::wstring title;
    std::wstring className;
    std::wstring processName;
};
}

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x11
#endif
