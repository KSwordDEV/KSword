$help=Invoke-Cli @('help','driver','modules','enum')
Assert ($help.Contains('--source') -and (Invoke-Cli @('driver','modules','enum','--help')) -eq $help) 'Driver leaf help'
Assert (!(Invoke-Cli @('driver','modules','help')).Contains('--source')) 'Driver intermediate help'
Assert (!(Invoke-Cli @('help','driver')).Contains('--signature')) 'Driver family does not expand descendants'
foreach($bad in @(
 @('driver','modules','query','--json'),
 @('driver','modules','query','--name','a','--base','1','--json'),
 @('driver','modules','enum','--source','r0','--json'),
 @('driver','modules','enum','--backend','r0','--json'),
 @('driver','modules','enum','--signature','maybe','--json'),
 @('driver','modules','enum','--limit','0','--json'),
 @('driver','modules','enum','--bad','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Driver parameter validation'}
$nt=(Invoke-Cli @('driver','modules','enum','--source','nt','--json') @(0,3,5,6))|ConvertFrom-Json
Assert ($nt.data.selectedSource -eq 'nt' -and $nt.data.sources.Count -eq 1) 'Explicit NT source'
$psapi=(Invoke-Cli @('driver','modules','enum','--source','psapi','--json') @(0,3,5,6))|ConvertFrom-Json
Assert ($psapi.data.selectedSource -eq 'psapi' -and $psapi.data.sources.Count -eq 1) 'Explicit Psapi source'
foreach($module in $psapi.data.modules){Assert ($null -eq $module.imageSize -and $null -eq $module.endAddressExclusive) 'No fabricated Psapi size'}
Assert ((Invoke-Cli @('driver','modules','enum','--signature','off') @(0,3,5,6)).Contains('selectedSource:')) 'Driver text output'
# Enabling debug privilege must occur inside the same CLI process.
$scoped=(Invoke-Cli @('privilege','run','--enable','SeDebugPrivilege','--json','--','driver','modules','enum','--source','nt','--json') @(0,3,5,6))|ConvertFrom-Json
if($scoped.data.stdout){$visible=$scoped.data.stdout|ConvertFrom-Json}else{$visible=$nt}
function Invoke-VisibleDriver([string[]]$Arguments,[int[]]$Expected) {
 if($scoped.data.executed){$outer=(Invoke-Cli (@('privilege','run','--enable','SeDebugPrivilege','--json','--')+$Arguments) $Expected)|ConvertFrom-Json;return $outer.data.stdout|ConvertFrom-Json}
 return (Invoke-Cli $Arguments $Expected)|ConvertFrom-Json
}
if($InGuest){Assert ($visible.status -eq 'success' -and [uint64]$visible.data.enumeratedCount -gt 0) 'Real NT driver enumeration without KswordARK'}
if($visible.status -in @('success','partial') -and $visible.data.modules.Count -gt 0) {
 $first=$visible.data.modules|Where-Object {$_.name -and $_.baseAddress}|Select-Object -First 1
 if($first){
  $query=Invoke-VisibleDriver @('driver','modules','query','--name',$first.name,'--signature','off','--json') @(0,6)
  $record=$query.data.modules[0]
  Assert ($record.name -eq $first.name -and $record.baseAddress -eq $first.baseAddress -and [uint64]$record.imageSize -gt 0) 'Module name lookup and metadata'
  $query=Invoke-VisibleDriver @('driver','modules','query','--base',$first.baseAddress,'--json') @(0,6)
  $record=$query.data.modules[0]
  Assert ($record.name -eq $first.name -and $record.signature.requested -and !$record.signature.catalogVerification) 'Base lookup and bounded disk trust evidence'
  $inner=Invoke-VisibleDriver @('driver','modules','enum','--limit','1','--json') @(6)
  Assert ($inner.data.truncated -and $inner.data.returnedCount -eq 1) 'Module output truncation'
  $missing=Invoke-VisibleDriver @('driver','modules','query','--name','Ksword-NoSuchDriver-Fixture.sys','--json') @(3)
  Assert ($missing.data.matchedCount -eq '0') 'Visible snapshot establishes missing module'
 }
}
if($InGuest) {
 Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Runtime.InteropServices;using System.Text;
public static class CliDriverOracle {
 [DllImport("psapi.dll",SetLastError=true)] static extern bool EnumDeviceDrivers([Out]IntPtr[] values,int size,out int needed);
 [DllImport("psapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetDeviceDriverBaseName(IntPtr b,StringBuilder name,int size);
 public static Dictionary<string,string> Query(){var values=new IntPtr[8192];int needed;if(!EnumDeviceDrivers(values,values.Length*IntPtr.Size,out needed)||needed>values.Length*IntPtr.Size)throw new Exception("driver oracle");var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
 for(int i=0;i<needed/IntPtr.Size;i++){var name=new StringBuilder(1024);if(GetDeviceDriverBaseName(values[i],name,name.Capacity)==0)throw new Exception("driver name oracle");result[name.ToString()]="0x"+unchecked((ulong)values[i].ToInt64()).ToString("X");}return result;}
}
'@
 $oracle=[CliDriverOracle]::Query()
 foreach($module in $visible.data.modules){Assert ($oracle.ContainsKey($module.name) -and $oracle[$module.name] -eq $module.baseAddress) 'Independent SDK name and base comparison'}
 Assert ($visible.data.sources[0].ntStatus -eq '0x0' -and $oracle.Count -eq [uint64]$visible.data.enumeratedCount) 'Independent loaded-image count'
 Assert ($psapi.status -eq 'partial' -and [uint64]$psapi.data.enumeratedCount -gt 0) 'Real Psapi unavailable-size semantics'
}
