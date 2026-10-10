$help=Invoke-Cli @('help','kernel','pipes','probe')
Assert ($help.Contains('--confirm') -and (Invoke-Cli @('kernel','pipes','probe','--help')) -eq $help) 'Pipe probe help'
Assert (!(Invoke-Cli @('kernel','pipes','help')).Contains('--directory')) 'Pipe immediate help'
foreach($bad in @(
 @('enum','--directory','invalid'),@('enum','--max-entries','0'),@('enum','--duration-ms','99'),@('enum','--limit','0'),@('enum','--backend','r0'),@('enum','--unknown','1'),
 @('probe'),@('probe','--path','\Device\NamedPipe\Missing'),@('probe','--path','\Device\HarddiskVolume1\Windows\win.ini','--confirm'),@('probe','--path','\Device\NamedPipe\','--confirm')
)){Assert (((Invoke-Cli (@('kernel','pipes')+$bad+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'Pipe validation'}
$all=(Invoke-Cli @('kernel','pipes','enum','--directory','device','--limit','100000','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.sources[0].complete -and $all.data.sources[0].closed -and [uint64]$all.data.enumeratedCount -eq $all.data.pipes.Count) 'Actual directory complete/count/close'
$sdk=@(Get-ChildItem -LiteralPath '\\.\pipe\' -ErrorAction Stop|ForEach-Object {$_.Name})
$common=0;foreach($row in $all.data.pipes){if($sdk -contains $row.name){$common++};Assert ($row.ntPath -eq ('\Device\NamedPipe\'+$row.name) -and $row.win32Path -eq ('\\.\pipe\'+$row.name) -and $row.creationTime -match '^-?\d+$') 'Native paths/raw times'}
Assert ($all.data.pipes.Count -eq 0 -or $common -gt 0) 'Independent Win32 pipe directory snapshot'
$empty=(Invoke-Cli @('kernel','pipes','enum','--directory','device','--filter','KswordMissingPipe54','--json') 0)|ConvertFrom-Json
Assert ($empty.data.returnedCount -eq '0') 'Valid filtered empty pipes'
Assert ((Invoke-Cli @('kernel','pipes','enum','--directory','device','--filter','KswordMissingPipe54')).Contains('source: shared NtOpenFile/NtQueryDirectoryFile')) 'Pipe text'
if($InGuest){
 Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class CliPipeOracle {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool DisconnectNamedPipe(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeInfo(IntPtr handle,out uint flags,out uint output,out uint input,out uint instances);
 public static bool ServerAlive(IntPtr handle){uint flags,output,input,instances;return GetNamedPipeInfo(handle,out flags,out output,out input,out instances)&&(flags&1)!=0&&instances==1;}
}
'@
 $name='KswordPipe-'+[guid]::NewGuid().ToString('N');$server=[IO.Pipes.NamedPipeServerStream]::new($name,[IO.Pipes.PipeDirection]::InOut,1,[IO.Pipes.PipeTransmissionMode]::Byte,[IO.Pipes.PipeOptions]::Asynchronous)
 try{
  $own=(Invoke-Cli @('kernel','pipes','enum','--directory','device','--filter',$name,'--json') 0)|ConvertFrom-Json
  Assert ($own.data.matchedCount -eq '1' -and $own.data.pipes[0].name -eq $name -and @(Get-ChildItem -LiteralPath '\\.\pipe\'|Where-Object {$_.Name -eq $name}).Count -eq 1) 'Independent self-created pipe registration'
  $probe=(Invoke-Cli @('kernel','pipes','probe','--path',('\Device\NamedPipe\'+$name),'--confirm','--json') @(0,6))|ConvertFrom-Json
  Assert ($probe.data.requestSucceeded -and $probe.data.source.closed -and $probe.data.ioNtStatus -eq '0x0') 'Actual read-attributes open/close'
  Assert ([CliPipeOracle]::DisconnectNamedPipe($server.SafePipeHandle.DangerousGetHandle())) 'Reset own server instance after attribute probe connected and closed it'
  Assert ([CliPipeOracle]::ServerAlive($server.SafePipeHandle.DangerousGetHandle())) 'Independent pipe server metadata/lifetime after own instance reset'
 }finally{$server.Dispose()}
 $gone=(Invoke-Cli @('kernel','pipes','probe','--path',('\Device\NamedPipe\'+$name),'--confirm','--json') 3)|ConvertFrom-Json
 Assert (!$gone.data.requestSucceeded -and !$gone.data.source.opened) 'Destroyed pipe cannot be opened'
 $limited=(Invoke-Cli @('kernel','pipes','enum','--directory','device','--max-entries','1','--json') 6)|ConvertFrom-Json
 Assert ($limited.data.limited -and $limited.data.enumeratedCount -eq '1') 'Actual pipe entry cap'
}
