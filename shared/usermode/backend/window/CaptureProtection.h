#pragma once
#include "../Common.h"
#include "WindowQueries.h"
namespace ks::r3::window_tools {
struct DisplayAffinityEvidence {
    bool attempted = false,available = false;
    DWORD affinity = WDA_NONE,error = ERROR_SUCCESS;
};
struct DisplayAffinityWriteEvidence {
    bool attempted = false,accepted = false;
    DWORD requested = WDA_NONE,error = ERROR_SUCCESS;
    DisplayAffinityEvidence after;
};
DisplayAffinityEvidence QueryDisplayAffinity(HWND window);
std::wstring ApplyDisplayAffinity(HWND window, DWORD affinity,DisplayAffinityWriteEvidence* evidence = nullptr);
}
