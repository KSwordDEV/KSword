#pragma once
#include "../Common.h"
#include <string>
#include <vector>
#include <array>
#include "CodeIntegrity.h"
namespace ks::r3::security {
const std::vector<SecurityProbe>& VbsProbes();
void AppendVbsR3(std::vector<MiscAuditRow>& rows);
}
