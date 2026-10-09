#pragma once
#include "../Common.h"
#include <string>
#include <vector>
#include <array>
#include "CodeIntegrity.h"
#include "Vbs.h"
#include "HyperV.h"
namespace ks::r3::security {
void AppendAppLockerR3(std::vector<MiscAuditRow>& rows);
}
