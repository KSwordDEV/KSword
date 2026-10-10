$help=Invoke-Cli @('help','hardware','devices','query')
Assert ($help.Contains('--instance-id') -and (Invoke-Cli @('hardware','devices','query','--help')) -eq $help) 'Hardware query leaf help'
Assert (!(Invoke-Cli @('hardware','devices','help')).Contains('--instance-id')) 'Device intermediate help'
Assert (!(Invoke-Cli @('help','hardware')).Contains('--scope')) 'Hardware family help'
foreach($bad in @(
 @('hardware','devices','query','--json'),
 @('hardware','devices','enum','--scope','lost','--json'),
 @('hardware','devices','enum','--limit','0','--json'),
 @('hardware','devices','enum','--backend','r0','--json'),
 @('hardware','devices','query','--instance-id','ROOT\Invalid','--bad','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Hardware parameter rejection'}
$all=(Invoke-Cli @('hardware','devices','enum','--limit','100000','--json') @(0,6))|ConvertFrom-Json
$present=(Invoke-Cli @('hardware','devices','enum','--scope','present','--limit','100000','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.complete -and $present.data.complete -and [uint64]$all.data.enumeratedCount -ge [uint64]$present.data.enumeratedCount) 'All/present scope and completeness'
Assert ((Invoke-Cli @('hardware','devices','enum','--class','KswordNoSuchDeviceClass') @(0)).Contains('matchedCount: 0')) 'Valid empty class filter and text output'
Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Runtime.InteropServices;using System.Text;
public static class CliPnpOracle {
 [StructLayout(LayoutKind.Sequential)] struct Info {public uint size;public Guid cls;public uint inst;public UIntPtr reserved;}
 [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr SetupDiGetClassDevs(IntPtr cls,string enumerator,IntPtr owner,uint flags);
 [DllImport("setupapi.dll",SetLastError=true)] static extern bool SetupDiEnumDeviceInfo(IntPtr set,uint index,ref Info info);
 [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
 [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Get_Device_ID(uint inst,StringBuilder id,uint size,uint flags);
 [DllImport("cfgmgr32.dll")] static extern uint CM_Get_DevNode_Status(out uint status,out uint problem,uint inst,uint flags);
 public static Dictionary<string,string> Query(bool present){var set=SetupDiGetClassDevs(IntPtr.Zero,null,IntPtr.Zero,present?6u:4u);if(set==new IntPtr(-1))throw new Exception("PnP oracle open");var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
 try{for(uint i=0;;i++){var info=new Info();info.size=(uint)Marshal.SizeOf(typeof(Info));if(!SetupDiEnumDeviceInfo(set,i,ref info)){if(Marshal.GetLastWin32Error()!=259)throw new Exception("PnP oracle enum");break;}var id=new StringBuilder(32768);if(CM_Get_Device_ID(info.inst,id,32768,0)!=0)continue;uint status,problem;var cr=CM_Get_DevNode_Status(out status,out problem,info.inst,0);result[id.ToString()]=cr==0?"0x"+status.ToString("X")+":"+problem.ToString():null;}}finally{SetupDiDestroyDeviceInfoList(set);}return result;}
}
'@
foreach($scope in @($all,$present)) {
 $oracle=[CliPnpOracle]::Query($scope.data.scope -eq 'present')
 foreach($device in $scope.data.devices){
  if($device.instanceId){Assert ($oracle.ContainsKey($device.instanceId)) 'Independent PnP identity oracle';if($oracle[$device.instanceId]){Assert (($device.statusFlags+':'+$device.problemCode) -eq $oracle[$device.instanceId]) 'Independent PnP status and problem code'}}
  foreach($prop in $device.properties.PSObject.Properties.Value){if($prop.absent){Assert (!$prop.available -and $null -eq $prop.values) 'Absent is not fabricated empty'};if($prop.available -and $prop.registryType -eq 7){Assert ($null -ne $prop.values) 'Native multi-string arrays'}}
 }
 Assert ($oracle.Count -eq [uint64]$scope.data.enumeratedCount) 'Independent PnP count'
}
$first=$present.data.devices|Where-Object {$_.instanceId}|Select-Object -First 1
if($first){
 $query=(Invoke-Cli @('hardware','devices','query','--instance-id',$first.instanceId,'--json') @(0,6))|ConvertFrom-Json
 Assert ($query.data.found -and $query.data.device.instanceId -eq $first.instanceId -and $query.data.device.classGuid -eq $first.classGuid) 'Live device detail matches enumeration'
 $limited=(Invoke-Cli @('hardware','devices','enum','--limit','1','--json') 6)|ConvertFrom-Json
 Assert ($limited.data.truncated -and $limited.data.returnedCount -eq 1) 'Device truncation'
}
$missing=(Invoke-Cli @('hardware','devices','query','--instance-id','ROOT\Ksword-NoSuch-Pnp-Fixture\0000','--json') 3)|ConvertFrom-Json
Assert (!$missing.data.found -and $null -eq $missing.data.device -and $missing.data.win32Error -ne 0) 'Removed/nonexistent PnP identity failure'
