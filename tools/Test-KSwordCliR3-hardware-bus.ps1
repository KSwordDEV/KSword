$help=Invoke-Cli @('help','hardware','bus','enum')
Assert ($help.Contains('--scope') -and (Invoke-Cli @('hardware','bus','enum','--help')) -eq $help) 'Bus leaf help'
Assert (!(Invoke-Cli @('hardware','bus','help')).Contains('--scope')) 'Bus intermediate help'
foreach($bad in @(
 @('hardware','bus','enum','--scope','pci','--json'),
 @('hardware','bus','enum','--limit','0','--json'),
 @('hardware','bus','enum','--backend','r0','--json'),
 @('hardware','bus','enum','--bad','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Bus argument rejection'}
$common=(Invoke-Cli @('hardware','bus','enum','--json') @(0,6))|ConvertFrom-Json
$all=(Invoke-Cli @('hardware','bus','enum','--scope','all','--json') @(0,6))|ConvertFrom-Json
Assert ($common.data.sources.Count -eq 5 -and $all.data.sources.Count -eq 1 -and $common.data.complete -and $all.data.complete) 'Common/all source scope and completeness'
Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Runtime.InteropServices;
public static class CliBusOracle {
 [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Locate_DevNode(out uint inst,string id,uint flags);
 [DllImport("cfgmgr32.dll")] static extern uint CM_Get_First_Log_Conf(out UIntPtr conf,uint inst,uint flags);
 [DllImport("cfgmgr32.dll")] static extern uint CM_Get_Next_Res_Des(out UIntPtr next,UIntPtr current,uint desired,out uint type,uint flags);
 [DllImport("cfgmgr32.dll")] static extern uint CM_Get_Res_Des_Data_Size(out uint size,UIntPtr current,uint flags);
 [DllImport("cfgmgr32.dll")] static extern uint CM_Free_Res_Des_Handle(UIntPtr descriptor);
 [DllImport("cfgmgr32.dll")] static extern uint CM_Free_Log_Conf_Handle(UIntPtr conf);
 public static string[] Resources(string id){uint inst;if(CM_Locate_DevNode(out inst,id,0)!=0)throw new Exception("bus oracle locate");UIntPtr conf;var first=CM_Get_First_Log_Conf(out conf,inst,2);if(first!=0&&CM_Get_First_Log_Conf(out conf,inst,3)!=0)return new string[0];var current=conf;bool owned=false;var result=new List<string>();try{for(int i=0;i<4096;i++){UIntPtr next;uint type;var step=CM_Get_Next_Res_Des(out next,current,0,out type,0);if(owned){CM_Free_Res_Des_Handle(current);owned=false;}if(step!=0){if(step!=15)throw new Exception("bus resource oracle termination "+step);break;}current=next;owned=true;uint size;if(CM_Get_Res_Des_Data_Size(out size,current,0)!=0)result.Add(type+":unknown");else result.Add(type+":"+size);}}finally{if(owned)CM_Free_Res_Des_Handle(current);CM_Free_Log_Conf_Handle(conf);}return result.ToArray();}
}
'@
$present=@{};Get-PnpDevice -PresentOnly -ErrorAction Stop|ForEach-Object {$present[$_.InstanceId]=$true}
$resourceChecks=0
foreach($device in $common.data.devices){
 Assert ($present.ContainsKey($device.instanceId)) 'Independent present bus device identity'
 Assert ($device.enumerationSource -in @('PCI','ACPI','ACPI_HAL','PCIIDE','ROOT')) 'Only common enumerators requested'
 if($device.resources.available -and !$device.resources.noConfiguration -and $resourceChecks -lt 5){
  $oracle=[CliBusOracle]::Resources($device.instanceId);Assert ($oracle.Count -eq $device.resources.descriptorCount) 'Independent CM descriptor count'
  foreach($r in $device.resources.descriptors){if($null -ne $r.dataSize){Assert ($oracle[$r.ordinal] -eq ($r.type.ToString()+':'+$r.dataSize)) 'Independent resource type and byte length'}}
  $resourceChecks++
 }
 if($device.resources.noConfiguration){Assert ($device.resources.available -and $device.resources.complete -and $device.resources.descriptorCount -eq 0) 'Valid empty resource configurations'}
 foreach($e in $device.properties.PSObject.Properties.Value){if(!$e.available){Assert ($null -eq $e.values -and $null -eq $e.number) 'Unknown bus values are null'}}
 if($device.enumeratorName -eq 'PCI' -and $device.address){
  $address=[Convert]::ToUInt32($device.address.Substring(2),16);Assert ($device.pciDevice -eq ($address -shr 16) -and $device.pciFunction -eq ($address -band 65535)) 'PCI packed-address interpretation'
  if($device.properties.address.available){$prop=Get-PnpDeviceProperty -InstanceId $device.instanceId -KeyName 'DEVPKEY_Device_Address' -ErrorAction Stop;Assert ([uint32]$prop.Data -eq $address) 'Independent native PCI address'}
 }
}
if($InGuest){Assert ($common.data.devices.Count -gt 0 -and $resourceChecks -gt 0) 'Actual guest bus and resource evidence'}
if($common.data.devices.Count){
 $first=$common.data.devices[0];$selected=(Invoke-Cli @('hardware','bus','enum','--instance-id',$first.instanceId,'--json') @(0,6))|ConvertFrom-Json
 Assert ($selected.data.returnedCount -eq 1 -and $selected.data.devices[0].instanceId -eq $first.instanceId) 'Exact bus identity filtering'
 $pci=(Invoke-Cli @('hardware','bus','enum','--enumerator','PCI','--json') @(0,6))|ConvertFrom-Json;foreach($device in $pci.data.devices){Assert ($device.enumeratorName -eq 'PCI') 'Enumerator filter'}
 $limited=(Invoke-Cli @('hardware','bus','enum','--limit','1','--json') 6)|ConvertFrom-Json;Assert ($limited.data.truncated -and $limited.data.returnedCount -eq 1) 'Bus truncation'
}
$missing=(Invoke-Cli @('hardware','bus','enum','--instance-id','ROOT\KswordNoSuchBusFixture','--json') 0)|ConvertFrom-Json
Assert ($missing.data.matchedCount -eq '0') 'Valid bus filter miss'
Assert ((Invoke-Cli @('hardware','bus','enum') @(0,6)).Contains('source: present SetupAPI devnodes')) 'Bus text output'
