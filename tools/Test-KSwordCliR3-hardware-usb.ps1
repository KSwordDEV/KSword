$help=Invoke-Cli @('help','hardware','usb','enum')
Assert ($help.Contains('--kind') -and (Invoke-Cli @('hardware','usb','enum','--help')) -eq $help) 'USB leaf help'
Assert (!(Invoke-Cli @('hardware','usb','help')).Contains('--kind')) 'USB intermediate help'
foreach($bad in @(
 @('hardware','usb','enum','--kind','port','--json'),
 @('hardware','usb','enum','--limit','0','--json'),
 @('hardware','usb','enum','--backend','r0','--json'),
 @('hardware','usb','enum','--bad','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'USB parameter rejection'}
$all=(Invoke-Cli @('hardware','usb','enum','--json') @(0,5,6))|ConvertFrom-Json
Assert ($all.data.sources.Count -eq 6) 'Six USB topology source walks'
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using System.Text;
public static class CliUsbOracle {
 [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Locate_DevNode(out uint inst,string id,uint flags);
 [DllImport("cfgmgr32.dll")] static extern uint CM_Get_DevNode_Status(out uint status,out uint problem,uint inst,uint flags);
 [DllImport("cfgmgr32.dll")] static extern uint CM_Get_Parent(out uint parent,uint inst,uint flags);
 [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode)] static extern uint CM_Get_Device_ID(uint inst,StringBuilder id,uint size,uint flags);
 public static string[] Query(string id){uint inst,status,problem,parent;if(CM_Locate_DevNode(out inst,id,0)!=0)throw new Exception("USB oracle locate");var result=new string[3];if(CM_Get_DevNode_Status(out status,out problem,inst,0)==0){result[0]="0x"+status.ToString("X");result[1]=problem.ToString();}if(CM_Get_Parent(out parent,inst,0)==0){var text=new StringBuilder(32768);if(CM_Get_Device_ID(parent,text,32768,0)==0)result[2]=text.ToString();}return result;}
}
'@
$present=@{};Get-PnpDevice -PresentOnly -ErrorAction Stop|ForEach-Object {$present[$_.InstanceId]=$true}
foreach($node in $all.data.nodes){
 Assert ($present.ContainsKey($node.instanceId)) 'Independent present PnP identity oracle'
 $oracle=[CliUsbOracle]::Query($node.instanceId)
 if($oracle[0]){Assert ($node.statusFlags -eq $oracle[0] -and $node.problemCode.ToString() -eq $oracle[1]) 'Independent CM status and problem code'}
 if($oracle[2]){Assert ($node.parentInstanceId -eq $oracle[2]) 'Independent CM parent identity'}
 if($null -ne $node.parentIndex){Assert ($all.data.nodes[$node.parentIndex].instanceId -eq $node.parentInstanceId) 'Snapshot parent index agrees with identity'}
 if($node.kind -eq 'controller'){Assert ($null -eq $node.hubPortCandidate) 'Controller PCI address never a hub-port number'}
 if($node.instanceSerialCandidate){Assert (!$node.instanceSerialCandidate.Contains('&')) 'Serial candidate semantics'}
 foreach($e in $node.properties.PSObject.Properties.Value){if(!$e.available){Assert ($null -eq $e.values -and $null -eq $e.number) 'Unknown USB properties are null'}}
 if($node.properties.hardwareIds.available){
  $property=Get-PnpDeviceProperty -InstanceId $node.instanceId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction Stop
  Assert ((@($property.Data) -join [char]0) -ceq (@($node.properties.hardwareIds.values) -join [char]0)) 'Independent native HardwareIds arrays'
 }
}
if($InGuest){Assert ($all.data.complete -and [uint64]$all.data.enumeratedCount -gt 0) 'Successful actual guest USB topology'}
if($all.data.nodes.Count){
 $first=$all.data.nodes[0];$query=(Invoke-Cli @('hardware','usb','enum','--instance-id',$first.instanceId,'--json') @(0,6))|ConvertFrom-Json
 Assert ($query.data.returnedCount -eq 1 -and $query.data.nodes[0].instanceId -eq $first.instanceId) 'Exact USB instance selection'
 if($all.data.roleClassificationComplete){$controllers=(Invoke-Cli @('hardware','usb','enum','--kind','controller','--json') @(0,6))|ConvertFrom-Json;foreach($node in $controllers.data.nodes){Assert ($node.kind -eq 'controller') 'Controller kind filtering'}}
 if($all.data.nodes.Count -gt 1){$limited=(Invoke-Cli @('hardware','usb','enum','--limit','1','--json') 6)|ConvertFrom-Json;Assert ($limited.data.truncated -and $limited.data.returnedCount -eq 1) 'USB truncation'}
}
$missing=(Invoke-Cli @('hardware','usb','enum','--instance-id','USB\KswordNoSuchUsbFixture','--json') @(0,5,6))|ConvertFrom-Json
Assert ($missing.data.matchedCount -eq '0') 'USB valid filter miss'
Assert ((Invoke-Cli @('hardware','usb','enum') @(0,5,6)).Contains('roleClassificationComplete:')) 'USB text output'
