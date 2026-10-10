#pragma once
#include "../Common.h"
#include <string>
#include <vector>
#include <array>
#include "CodeIntegrity.h"
#include "Vbs.h"
#include "HyperV.h"
#include "AppLocker.h"
#include "BamAhcache.h"
namespace ks::r3::security {
const std::vector<SecurityProbe>& BugcheckEnvironmentProbes();
void AppendBugcheckEvidenceR3(std::vector<MiscAuditRow>& rows);
}
