#pragma once
#include "../Common.h"
#include <string>
#include <vector>
#include <array>
#include "CodeIntegrity.h"
#include "Vbs.h"
namespace ks::r3::security {
const std::vector<SecurityProbe>& HyperVProbes();
void AppendHyperVR3(std::vector<MiscAuditRow>& rows);
}
