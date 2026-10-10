#include "AppLocker.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
const std::vector<SecurityProbe>& AppLockerProbes(){static const std::vector<SecurityProbe> probes{
    {L"effective-policy",L"Get-AppLockerPolicy -Effective rule collection/count summary",SecurityProbeKind::Command,
        L"$policy=Get-AppLockerPolicy -Effective -ErrorAction Stop;if($null -eq $policy){[ordered]@{available=$false}|ConvertTo-Json -Compress;exit 5};try{$xml=[xml]($policy.ToXml())}catch{[ordered]@{available=$false;malformed=$true;error=$_.Exception.Message}|ConvertTo-Json -Compress;exit 4};if($null -eq $xml.AppLockerPolicy){[ordered]@{available=$false;malformed=$true}|ConvertTo-Json -Compress;exit 4};$total=0;$items=@(foreach($collection in @($xml.AppLockerPolicy.RuleCollection)){if($null -eq $collection){continue};$rules=@($collection.ChildNodes|Where-Object {$_.LocalName -in @('FilePathRule','FilePublisherRule','FileHashRule')});$total+=$rules.Count;[ordered]@{type=$collection.GetAttribute('Type');enforcementMode=$collection.GetAttribute('EnforcementMode');ruleCount=[string]$rules.Count}});[ordered]@{available=$true;collectionCount=[string]$items.Count;ruleCount=[string]$total;collections=$items;summaryOnly=$true}|ConvertTo-Json -Compress -Depth 8",{},{}},
    {L"appid-service",L"Get-Service AppIDSvc current status/start configuration",SecurityProbeKind::Command,
        L"$s=Get-Service -Name AppIDSvc -ErrorAction Stop;[ordered]@{available=$true;name=$s.Name;status=$s.Status.ToString();stateId=[int]$s.Status;startType=$s.StartType.ToString();startTypeId=[int]$s.StartType}|ConvertTo-Json -Compress -Depth 8",{},{}},
    {L"event-logs",L"AppLocker EXE/DLL, MSI/Script and CodeIntegrity channel metadata",SecurityProbeKind::Command,
        L"$known=0;$items=@(foreach($name in @('Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-AppLocker/MSI and Script','Microsoft-Windows-CodeIntegrity/Operational')){try{$log=Get-WinEvent -ListLog $name -ErrorAction Stop;if($null -eq $log){[ordered]@{name=$name;available=$false;enabled=$null;recordCount=$null}}else{$known++;[ordered]@{name=$name;available=$true;enabled=$log.IsEnabled;recordCount=$(if($null -eq $log.RecordCount){$null}else{[string]$log.RecordCount})}}}catch{[ordered]@{name=$name;available=$false;enabled=$null;recordCount=$null;errorId=$_.FullyQualifiedErrorId;exceptionHResult=('0x{0:x8}' -f $_.Exception.HResult);error=$_.Exception.Message}}});[ordered]@{available=($known -gt 0);logs=$items}|ConvertTo-Json -Compress -Depth 8;if($known -eq 0){exit 5};if($known -ne 3){exit 6}",{},{}},
    {L"appid",L"SCM AppID driver registration/status",SecurityProbeKind::Service,{},{},L"AppID"},
    {L"applocker-filter",L"SCM AppLocker filter registration/status",SecurityProbeKind::Service,{},{},L"applockerfltr"},
    {L"security-filter",L"SCM mssecflt registration/status",SecurityProbeKind::Service,{},{},L"mssecflt"},
    {L"srp-default-level",L"HKLM64 SRP DefaultLevel configured value",SecurityProbeKind::Registry,{},L"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",L"DefaultLevel"}};return probes;}
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
