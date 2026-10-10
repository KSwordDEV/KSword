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
        bool requestSucceeded = false, identityMatched = false;
        bool win32ErrorKnown = false;
        DWORD win32Error = ERROR_SUCCESS;
        bool previousSuspendCountKnown = false;
        DWORD previousSuspendCount = 0;
        bool writeAttempted = false, writeSucceeded = false, verified = false;
        bool rollbackAttempted = false, rollbackSucceeded = false;
    };
}
