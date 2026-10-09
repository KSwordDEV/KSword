#include "BugcheckEvidence.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
void AppendBugcheckEvidenceR3(std::vector<MiscAuditRow>& rows) {



    AddCommandRow(rows, L"Bugcheck / VMware branding", L"VMware environment", L"PowerShell Win32_ComputerSystem", RunPowerShellScalar(
        L"$c=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; 'Manufacturer=' + $c.Manufacturer + '; Model=' + $c.Model"));

}
}
