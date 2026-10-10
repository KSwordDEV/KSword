#include "BugcheckEvidence.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
const std::vector<SecurityProbe>& BugcheckEnvironmentProbes(){static const std::vector<SecurityProbe> probes{
    {L"computer-system",L"CIM Win32_ComputerSystem manufacturer/model environment evidence only",SecurityProbeKind::Command,
        L"$cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop;if($null -eq $cs){[ordered]@{available=$false}|ConvertTo-Json -Compress;exit 5};[ordered]@{available=$true;manufacturer=$cs.Manufacturer;model=$cs.Model;environmentOnly=$true}|ConvertTo-Json -Compress -Depth 8",{},{}}};return probes;}
void AppendBugcheckEvidenceR3(std::vector<MiscAuditRow>& rows) {



    AddCommandRow(rows, L"Bugcheck / VMware branding", L"VMware environment", L"PowerShell Win32_ComputerSystem", RunPowerShellScalar(
        L"$c=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; 'Manufacturer=' + $c.Manufacturer + '; Model=' + $c.Model"));

}
}
