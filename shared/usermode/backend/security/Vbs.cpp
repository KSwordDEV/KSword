#include "Vbs.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
const std::vector<SecurityProbe>& VbsProbes(){static const std::vector<SecurityProbe> probes{
    {L"device-guard",L"CIM root/Microsoft/Windows/DeviceGuard:Win32_DeviceGuard VBS fields",SecurityProbeKind::Command,
        L"$dg=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop;if($null -eq $dg){[ordered]@{available=$false}|ConvertTo-Json -Compress;exit 5};[ordered]@{available=$true;virtualizationBasedSecurityStatus=$dg.VirtualizationBasedSecurityStatus;requiredSecurityProperties=@($dg.RequiredSecurityProperties);availableSecurityProperties=@($dg.AvailableSecurityProperties);securityServicesRunning=@($dg.SecurityServicesRunning);securityServicesConfigured=@($dg.SecurityServicesConfigured)}|ConvertTo-Json -Compress -Depth 8",{},{}},
    {L"system-files",L"System32 disk files only; no active secure-kernel/module claim",SecurityProbeKind::Command,
        L"$partial=$false;$items=@(foreach($name in @('securekernel.exe','skci.dll','ci.dll')){$path=Join-Path $env:windir ('System32\\'+$name);try{[ordered]@{name=$name;path=$path;known=$true;present=[bool](Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop)}}catch{$partial=$true;[ordered]@{name=$name;path=$path;known=$false;present=$null;error=$_.Exception.Message}}});[ordered]@{available=$true;files=$items}|ConvertTo-Json -Compress -Depth 8;if($partial){exit 6}",{},{}},
    {L"hvci-enabled",L"HKLM64 configured HVCI Enabled",SecurityProbeKind::Registry,{},L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",L"Enabled"},
    {L"hvci-was-enabled-by",L"HKLM64 HVCI WasEnabledBy metadata",SecurityProbeKind::Registry,{},L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",L"WasEnabledBy"},
    {L"hvci-locked",L"HKLM64 HVCI Locked metadata",SecurityProbeKind::Registry,{},L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",L"Locked"},
    {L"enable-vbs",L"HKLM64 DeviceGuard configured VBS",SecurityProbeKind::Registry,{},L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",L"EnableVirtualizationBasedSecurity"},
    {L"require-platform",L"HKLM64 configured platform security features",SecurityProbeKind::Registry,{},L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",L"RequirePlatformSecurityFeatures"},
    {L"lsa-flags",L"HKLM64 LsaCfgFlags configuration",SecurityProbeKind::Registry,{},L"SYSTEM\\CurrentControlSet\\Control\\Lsa",L"LsaCfgFlags"}};return probes;}
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
