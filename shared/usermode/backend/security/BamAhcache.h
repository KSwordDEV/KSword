#pragma once
#include "../Common.h"
#include <string>
#include <vector>
#include <array>
#include "CodeIntegrity.h"
#include "Vbs.h"
#include "HyperV.h"
#include "AppLocker.h"
namespace ks::r3::security {
void AppendBamAhcacheR3(std::vector<MiscAuditRow>& rows);
}
