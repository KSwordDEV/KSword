#include "HyperV.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
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
