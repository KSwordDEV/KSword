#include "HyperV.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
const std::vector<SecurityProbe>& HyperVProbes(){static const std::vector<SecurityProbe> probes{
    {L"computer-system",L"CIM Win32_ComputerSystem; generic hypervisor flag, not Hyper-V vendor proof",SecurityProbeKind::Command,
        L"$cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop;if($null -eq $cs){[ordered]@{available=$false}|ConvertTo-Json -Compress;exit 5};[ordered]@{available=$true;hypervisorPresent=$cs.HypervisorPresent;manufacturer=$cs.Manufacturer;model=$cs.Model}|ConvertTo-Json -Compress -Depth 8",{},{}},
    {L"optional-features",L"Get-WindowsOptionalFeature -Online existing four feature registrations",SecurityProbeKind::Command,
        L"$known=0;$items=@(foreach($name in @('Microsoft-Hyper-V-All','Microsoft-Hyper-V-Hypervisor','VirtualMachinePlatform','Microsoft-Windows-Subsystem-Linux')){try{$f=Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop;if($null -eq $f){[ordered]@{name=$name;available=$false;state=$null;stateId=$null}}else{$known++;[ordered]@{name=$name;available=$true;state=$f.State.ToString();stateId=[int]$f.State}}}catch{[ordered]@{name=$name;available=$false;state=$null;stateId=$null;error=$_.Exception.Message;exceptionHResult=('0x{0:x8}' -f $_.Exception.HResult)}}});[ordered]@{available=($known -gt 0);features=$items}|ConvertTo-Json -Compress -Depth 8;if($known -eq 0){exit 5};if($known -ne 4){exit 6}",{},{}},
    {L"pnp-candidates",L"CIM Win32_PnPEntity existing Hyper-V/VMBus/vEthernet/HvSocket name filter",SecurityProbeKind::Command,
        L"$matches=@(Get-CimInstance Win32_PnPEntity -ErrorAction Stop|Where-Object {$_.Name -match 'Hyper-V|VMBus|vmbus|Virtual Switch|vEthernet|HvSocket'});$items=@($matches|Select-Object -First 40|ForEach-Object {[ordered]@{name=$_.Name;pnpClass=$_.PNPClass;status=$_.Status;deviceId=$_.DeviceID}});[ordered]@{available=$true;matchedCount=[string]$matches.Count;returnedCount=[string]$items.Count;truncated=($matches.Count -gt $items.Count);devices=$items}|ConvertTo-Json -Compress -Depth 8;if($matches.Count -gt $items.Count){exit 6}",{},{}},
    {L"vmbus",L"SCM VMBus registration/status",SecurityProbeKind::Service,{},{},L"vmbus"},
    {L"vmsmp",L"SCM virtual-switch driver registration/status",SecurityProbeKind::Service,{},{},L"VMSMP"},
    {L"hvhost",L"SCM Hyper-V host service registration/status",SecurityProbeKind::Service,{},{},L"HvHost"},
    {L"vpci",L"SCM virtual PCI driver registration/status",SecurityProbeKind::Service,{},{},L"vpci"},
    {L"device-guard-hvci",L"HKLM64 DeviceGuard HypervisorEnforcedCodeIntegrity configuration; not BCD launch type",SecurityProbeKind::Registry,{},L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",L"HypervisorEnforcedCodeIntegrity"}};return probes;}
void AppendHyperVR3(std::vector<MiscAuditRow>& rows) {




    AddCommandRow(rows, L"Hyper-V / VMBus / HvSocket", L"ComputerSystem hypervisor", L"PowerShell CIM Win32_ComputerSystem", RunPowerShellScalar(
        L"$cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; 'HypervisorPresent=' + $cs.HypervisorPresent + '; Manufacturer=' + $cs.Manufacturer + '; Model=' + $cs.Model"));
    AddCommandRow(rows, L"Hyper-V / VMBus / HvSocket", L"Hyper-V optional features", L"PowerShell Get-WindowsOptionalFeature", RunPowerShellScalar(
        L"$names=@('Microsoft-Hyper-V-All','Microsoft-Hyper-V-Hypervisor','VirtualMachinePlatform','Microsoft-Windows-Subsystem-Linux'); foreach($n in $names){ $f=Get-WindowsOptionalFeature -Online -FeatureName $n -ErrorAction SilentlyContinue; if($f){ Write-Output ($n + '=' + $f.State) } else { Write-Output ($n + '=Unavailable') } }"));
    AddCommandRow(rows, L"Hyper-V / VMBus / HvSocket", L"Hyper-V network adapters", L"PowerShell CIM Win32_PnPEntity", RunPowerShellScalar(
        L"Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Hyper-V|VMBus|vmbus|Virtual Switch|vEthernet|HvSocket' } | Select-Object -First 40 -Property Name,PNPClass,Status | Format-Table -AutoSize | Out-String"));
    AddServiceRow(rows, L"Hyper-V / VMBus / HvSocket", L"VMBus kernel driver", L"vmbus");
    AddServiceRow(rows, L"Hyper-V / VMBus / HvSocket", L"Hyper-V Virtual Switch Extension Adapter", L"VMSMP");
    AddServiceRow(rows, L"Hyper-V / VMBus / HvSocket", L"Hyper-V socket service", L"HvHost");
    AddServiceRow(rows, L"Hyper-V / VMBus / HvSocket", L"Virtual PCI bus", L"vpci");
    AddRegistryRow(rows, L"Hyper-V / VMBus / HvSocket", L"Hypervisor launch type", L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"HypervisorEnforcedCodeIntegrity");


}
}
