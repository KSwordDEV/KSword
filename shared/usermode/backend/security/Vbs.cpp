#include "Vbs.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
void AppendVbsR3(std::vector<MiscAuditRow>& rows) {




    AddCommandRow(rows, L"VBS / HVCI / SKCI", L"DeviceGuard status", L"PowerShell CIM root/Microsoft/Windows/DeviceGuard", RunPowerShellScalar(
        L"$dg=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop; "
        L"'VirtualizationBasedSecurityStatus=' + $dg.VirtualizationBasedSecurityStatus + '; RequiredSecurityProperties=' + (($dg.RequiredSecurityProperties)-join ',') + '; AvailableSecurityProperties=' + (($dg.AvailableSecurityProperties)-join ',') + '; Running=' + (($dg.SecurityServicesRunning)-join ',') + '; Configured=' + (($dg.SecurityServicesConfigured)-join ',')"));
    AddCommandRow(rows, L"VBS / HVCI / SKCI", L"HVCI memory integrity", L"PowerShell registry", RunPowerShellScalar(
        L"$p='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity'; "
        L"if(Test-Path $p){ Get-ItemProperty -LiteralPath $p | Select-Object -Property Enabled,WasEnabledBy,Locked | Format-List | Out-String } else { 'HVCI scenario key missing' }"));
    AddCommandRow(rows, L"VBS / HVCI / SKCI", L"Secure Kernel modules", L"PowerShell Get-ProcessModule/System32", RunPowerShellScalar(
        L"$names=@('securekernel.exe','skci.dll','ci.dll'); foreach($n in $names){ $p=Join-Path $env:windir ('System32\\' + $n); if(Test-Path $p){ Write-Output ($n + '=present') } else { Write-Output ($n + '=missing') } }"));
    AddRegistryRow(rows, L"VBS / HVCI / SKCI", L"DeviceGuard EnableVirtualizationBasedSecurity", L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"EnableVirtualizationBasedSecurity");
    AddRegistryRow(rows, L"VBS / HVCI / SKCI", L"DeviceGuard RequirePlatformSecurityFeatures", L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"RequirePlatformSecurityFeatures");
    AddRegistryRow(rows, L"VBS / HVCI / SKCI", L"LsaCfgFlags", L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LsaCfgFlags");


}
}
