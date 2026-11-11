#pragma once

#include "CodeIntegrity.h"
#include <functional>
#include <map>
#include <string>

namespace ks::r3::security {
// Only the fixed operations below are emitted; all caller data is UTF-16/base64
// encoded before inclusion in the PowerShell body.
struct ApplicationControlRequest {
    std::wstring operation;
    std::map<std::wstring, std::wstring> values;
};

using ApplicationControlRunner = std::function<CommandResult(const std::wstring&, DWORD)>;

std::wstring BuildApplicationControlScript(const ApplicationControlRequest& request);
CommandResult RunApplicationControl(const ApplicationControlRequest& request, DWORD timeoutMs,
                                    const ApplicationControlRunner& runner = {});
}
