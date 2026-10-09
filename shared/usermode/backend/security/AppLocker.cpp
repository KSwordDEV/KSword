#include "AppLocker.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
void AppendAppLockerR3(std::vector<MiscAuditRow>& rows) {




    AddCommandRow(rows, L"AppLocker / AppID", L"Effective AppLocker policy count", L"PowerShell Get-AppLockerPolicy", RunPowerShellScalar(
        L"try { $p=Get-AppLockerPolicy -Effective -ErrorAction Stop; $xml=[xml]($p.ToXml()); $rules=($xml.AppLockerPolicy.RuleCollection | ForEach-Object { $_.ChildNodes.Count } | Measure-Object -Sum).Sum; 'RuleCollections=' + $xml.AppLockerPolicy.RuleCollection.Count + '; RuleCount=' + $rules } catch { 'Get-AppLockerPolicy failed: ' + $_.Exception.Message; exit 1 }"));
    AddCommandRow(rows, L"AppLocker / AppID", L"AppID service", L"PowerShell Get-Service", RunPowerShellScalar(
        L"Get-Service -Name AppIDSvc -ErrorAction Stop | Select-Object Name,Status,StartType | Format-List | Out-String"));
    AddCommandRow(rows, L"AppLocker / AppID", L"Application Control event logs", L"PowerShell Get-WinEvent", RunPowerShellScalar(
        L"$logs=@('Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-AppLocker/MSI and Script','Microsoft-Windows-CodeIntegrity/Operational'); foreach($l in $logs){ $log=Get-WinEvent -ListLog $l -ErrorAction SilentlyContinue; if($log){ Write-Output ($l + '=enabled:' + $log.IsEnabled + '; records:' + $log.RecordCount) } else { Write-Output ($l + '=Unavailable') } }"));
    AddServiceRow(rows, L"AppLocker / AppID", L"AppID kernel driver", L"AppID");
    AddServiceRow(rows, L"AppLocker / AppID", L"AppLocker minifilter", L"applockerfltr");
    AddServiceRow(rows, L"AppLocker / AppID", L"Microsoft security filter", L"mssecflt");
    AddRegistryRow(rows, L"AppLocker / AppID", L"SRP identifiers policy", L"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers", L"DefaultLevel");


}
}
