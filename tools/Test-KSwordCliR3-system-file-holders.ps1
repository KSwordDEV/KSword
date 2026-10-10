$help=Invoke-Cli @('help','system','file-holders','query')
Assert ($help.Contains('--path') -and (Invoke-Cli @('system','file-holders','query','--help')) -eq $help) 'File holders leaf help'
Assert (!(Invoke-Cli @('system','file-holders','help')).Contains('--duration-ms')) 'File holders intermediate help'
foreach($bad in @(
 @('system','file-holders','query','--json'),
 @('system','file-holders','query','--path','C:\missing','--recursive','yes','--json'),
 @('system','file-holders','query','--path','C:\missing','--duration-ms','249','--json'),
 @('system','file-holders','query','--path','C:\missing','--max-handles','0','--json'),
 @('system','file-holders','query','--path','C:\missing','--pid','0','--json'),
 @('system','file-holders','query','--path','C:\missing','--creation-time','1','--json'),
 @('system','file-holders','query','--path','C:\missing','--backend','r0','--json'),
 @('system','file-holders','query','--path','C:\missing','--limit','100001','--json'),
 @('system','file-holders','query','--path','C:\missing','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'File holder parameter validation'}
if($InGuest){
 Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;
public static class CliHolderOracle {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(IntPtr file,StringBuilder buffer,uint length,uint flags);
 public static string Path(IntPtr file){var buffer=new StringBuilder(32768);uint count=GetFinalPathNameByHandle(file,buffer,(uint)buffer.Capacity,0);if(count==0||count>=buffer.Capacity)throw new Exception("holder path oracle");var path=buffer.ToString();return path.StartsWith(@"\\?\")?path.Substring(4):path;}
}
'@
 $root=Join-Path $env:TEMP ('KswordHolders-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null
 $file=Join-Path $root 'held.bin';[IO.File]::WriteAllBytes($file,[byte[]]@(1,2,3));$first=$null;$second=$null
 try{
  $first=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  $second=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  $handles=@(('0x'+$first.SafeFileHandle.DangerousGetHandle().ToInt64().ToString('x')),('0x'+$second.SafeFileHandle.DangerousGetHandle().ToInt64().ToString('x')))
  $actualPath=[CliHolderOracle]::Path($first.SafeFileHandle.DangerousGetHandle())
  $creation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
  $guard=@('--pid',$PID.ToString(),'--creation-time',$creation)
  $result=(Invoke-Cli (@('system','file-holders','query','--path',$file)+$guard+@('--json')) @(0,6))|ConvertFrom-Json
  Assert ($result.data.targetIdentityStable -and $result.data.snapshotNtStatus -eq '0x0' -and $result.data.matchedCount -eq '2') "Actual file handles found: $($result.data|ConvertTo-Json -Depth 3 -Compress)"
  foreach($row in $result.data.holders){Assert ($handles -contains $row.handle -and $row.pid -eq $PID -and $row.processCreationTime -eq $creation -and $row.processAlive -and $row.win32Name -eq $actualPath -and $row.objectName.StartsWith('\Device\')) 'Independent owned handle/identity/path evidence including short TEMP names'}
  $recursive=(Invoke-Cli (@('system','file-holders','query','--path',$root,'--recursive','on')+$guard+@('--json')) @(0,6))|ConvertFrom-Json
  Assert ($recursive.data.matchedCount -eq '2') 'Directory subtree boundary includes owned file'
  $truncated=(Invoke-Cli (@('system','file-holders','query','--path',$file,'--limit','1')+$guard+@('--json')) 6)|ConvertFrom-Json
  Assert ($truncated.data.truncated -and $truncated.data.returnedCount -eq '1' -and $truncated.data.matchedCount -eq '2') 'Output limit retains matched count'
  $budget=(Invoke-Cli (@('system','file-holders','query','--path',$file,'--max-handles','1')+$guard+@('--json')) 6)|ConvertFrom-Json
  Assert ($budget.data.limited -and !$budget.data.complete -and $budget.data.examinedHandleCount -eq '1') 'Actual sweep operation budget'
  $wrong=(Invoke-Cli @('system','file-holders','query','--path',$file,'--pid',$PID.ToString(),'--creation-time',([uint64]$creation+1).ToString(),'--json') 3)|ConvertFrom-Json
  Assert (!$wrong.data.targetIdentity.identityMatched) 'Mismatched process creation rejected before scan'
  Assert ((Invoke-Cli (@('system','file-holders','query','--path',$file)+$guard) @(0,6)).Contains('source: SystemExtendedHandleInformation')) 'File holders text output'
  Assert ($first.CanRead -and $second.CanRead) 'Query preserves original handles'
  $first.Dispose();$first=$null;$second.Dispose();$second=$null
  $empty=(Invoke-Cli (@('system','file-holders','query','--path',$file)+$guard+@('--json')) @(0,6))|ConvertFrom-Json
  Assert ($empty.data.matchedCount -eq '0') 'Independent handle release reflected'
 }finally{
  if($first){$first.Dispose()};if($second){$second.Dispose()}
  $absolute=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\';if(!$absolute.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe holder fixture cleanup'}
  Remove-Item -LiteralPath $absolute -Recurse -Force
 }
}
