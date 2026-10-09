#pragma once
#include "../Win32.h"
#include <string>
namespace ks::r3::process_detail {
struct ProcessDetailActionResult {
        bool refreshRequired = false;
        bool refreshTokenReport = false;
        bool refreshTokenSwitches = false;
        bool refreshPebReport = false;
        std::wstring statusText;
        std::wstring dialogTitle;
        std::wstring dialogText;
        UINT dialogIcon = 0;
    };
}
