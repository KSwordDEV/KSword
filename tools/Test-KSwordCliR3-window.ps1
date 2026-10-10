$help=Invoke-Cli @('help','window','detail','query')
Assert ($help.Contains('--hwnd') -and (Invoke-Cli @('window','detail','query','--help')) -eq $help) 'Window detail leaf help'
$parent=Invoke-Cli @('window','detail','help')
Assert ($parent.Contains('Default/R0 syntax:') -and $parent.Contains('window detail query') -and !$parent.Contains('Notes:')) 'Existing leaf entry plus direct children without descendant notes'
Assert (!(Invoke-Cli @('window','manage','help')).Contains('--thread-creation-time')) 'Manage hierarchy only direct leaves'
foreach($bad in @(
 @('window','enum','--visible','maybe','--json'),
 @('window','enum','--sort','class','--json'),
 @('window','enum','--limit','0','--json'),
 @('window','enum','--backend','r0','--json'),
 @('window','detail','query','--json'),
 @('window','detail','query','--hwnd','0','--json'),
 @('window','detail','query','--hwnd','1','--creation-time','1','--json'),
 @('window','detail','query','--hwnd','1','--pid','bad','--json'),
 @('window','manage','minimize','--hwnd','1','--json'),
 @('window','enum','--bad','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Window parameter validation'}
$all=(Invoke-Cli @('window','enum','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.complete -and $all.backend -eq 'r3') 'Actual caller-desktop enumeration'
$ordered=(Invoke-Cli @('window','enum','--sort','process','--visible','yes','--json') @(0,6))|ConvertFrom-Json
$last=-1;foreach($row in $ordered.data.windows){Assert ($row.visible -and $row.pid -ge $last) 'Process sort and visible filter';$last=$row.pid}
Assert (((Invoke-Cli @('window','detail','query','--hwnd','0xffffffffffffffff','--json') 3)|ConvertFrom-Json).data.found -eq $false) 'Invalid HWND query'
Assert ((Invoke-Cli @('window','enum','--pid',$PID.ToString()) @(0,6)).Contains('source: EnumWindows')) 'Window text output'
if($InGuest){
 Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Runtime.InteropServices;using System.Text;
public static class CliWindowOracle {
 [StructLayout(LayoutKind.Sequential)] struct Rect {public int left,top,right,bottom;}
 [StructLayout(LayoutKind.Sequential)] struct Info {public uint size;public Rect window,client;public uint style,exStyle,status,borderX,borderY;public ushort atom,version;}
 [DllImport("user32.dll")] static extern bool GetWindowInfo(IntPtr window,ref Info info);
 [DllImport("user32.dll")] static extern bool IsWindow(IntPtr window);
 [DllImport("user32.dll")] static extern bool IsIconic(IntPtr window);
 [DllImport("user32.dll")] static extern bool IsZoomed(IntPtr window);
 [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr window,StringBuilder text,int size);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window,StringBuilder text,int size);
 static IntPtr Handle(string value){return new IntPtr(unchecked((long)Convert.ToUInt64(value.Substring(2),16)));}
 public static bool Exists(string value){return IsWindow(Handle(value));}
 public static Dictionary<string,object> Query(string value){var h=Handle(value);var info=new Info();info.size=(uint)Marshal.SizeOf(typeof(Info));if(!GetWindowInfo(h,ref info))throw new Exception("window oracle info");uint pid;var tid=GetWindowThreadProcessId(h,out pid);var title=new StringBuilder(32768);GetWindowText(h,title,title.Capacity);var cls=new StringBuilder(512);GetClassName(h,cls,cls.Capacity);
 return new Dictionary<string,object>{{"pid",pid},{"tid",tid},{"title",title.ToString()},{"class",cls.ToString()},{"style","0x"+info.style.ToString("X")},{"left",info.window.left},{"clientLeft",info.client.left},{"minimized",IsIconic(h)},{"maximized",IsZoomed(h)},{"visible",IsWindowVisible(h)}};}
}
'@
 $root=Join-Path $env:TEMP ('KswordWindow-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null
 $state=Join-Path $root 'state.json';$fixture=Join-Path (Split-Path -Parent $Cli) 'R3Fixture.exe'
 function Start-WindowTarget([string]$Mode){
  Remove-Item -LiteralPath $state -Force -ErrorAction SilentlyContinue
  $target=Start-Process $fixture -ArgumentList @($Mode,(Quote-CliArgument $state)) -PassThru
  for($i=0;$i -lt 80;$i++){Start-Sleep -Milliseconds 100;try{$data=Get-Content -LiteralPath $state -Raw|ConvertFrom-Json;if($data.pid -eq $target.Id -and ($Mode -ne '--windows-hung' -or $data.hungWindow -ne '0x0')){return @($target,$data)}}catch{}}
  if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose();throw 'Window fixture readiness timeout'
 }
 $pair=Start-WindowTarget '--windows';$target=$pair[0];$data=$pair[1]
 try {
  $guard=@('--hwnd',$data.hwnd,'--pid',$data.pid.ToString(),'--tid',$data.tid.ToString(),'--creation-time',$data.processCreationTime,'--thread-creation-time',$data.threadCreationTime)
  $query=(Invoke-Cli (@('window','detail','query')+$guard+@('--json')) 0)|ConvertFrom-Json
  $row=$query.data.window;$oracle=[CliWindowOracle]::Query($data.hwnd)
  Assert ($row.title -eq $oracle.title -and $row.class -eq $oracle.class -and $row.style -eq $oracle.style -and $row.windowRect.left -eq $oracle.left -and $row.clientRect.left -eq $oracle.clientLeft -and $row.clientRectCoordinates -eq 'screen') 'Independent real caption/class/styles/coordinate oracle'
  Assert ($row.pid -eq $oracle.pid -and $row.tid -eq $oracle.tid -and $row.processCreationTime -eq $data.processCreationTime -and $row.threadCreationTime -eq $data.threadCreationTime) 'Independent fixture process/thread creation identities'
  $alias=(Invoke-Cli (@('window','detail')+$guard+@('--backend','r3','--json')) 0)|ConvertFrom-Json
  Assert ($alias.data.window.hwnd -eq $row.hwnd) 'Explicit R3 selection of existing detail command'
  $filtered=(Invoke-Cli @('window','enum','--pid',$data.pid.ToString(),'--json') 0)|ConvertFrom-Json
  $primary=@($filtered.data.windows|Where-Object {$_.hwnd -eq $data.hwnd})
  Assert ($primary.Count -eq 1) 'Self-owned primary top-level fixture enumeration'
  foreach($owned in $filtered.data.windows){Assert ($owned.pid -eq $data.pid) 'PID filter retains only self-owned application and IME windows'}
  $wrong=@('--hwnd',$data.hwnd,'--pid',$data.pid.ToString(),'--tid',$data.tid.ToString(),'--creation-time',([uint64]$data.processCreationTime+1).ToString(),'--thread-creation-time',$data.threadCreationTime)
  $rejected=(Invoke-Cli (@('window','manage','minimize')+$wrong+@('--json')) 3)|ConvertFrom-Json
  Assert (!$rejected.data.attempted -and ![CliWindowOracle]::Query($data.hwnd).minimized) 'Mismatched process creation refuses write'
  $wrong=@('--hwnd',$data.hwnd,'--pid',$data.pid.ToString(),'--tid',$data.tid.ToString(),'--creation-time',$data.processCreationTime,'--thread-creation-time',([uint64]$data.threadCreationTime+1).ToString())
  Assert (!((Invoke-Cli (@('window','manage','minimize')+$wrong+@('--json')) 3)|ConvertFrom-Json).data.attempted) 'Mismatched thread creation refuses write'
  foreach($verb in @('minimize','restore','maximize','restore')) {
   $result=(Invoke-Cli (@('window','manage',$verb)+$guard+@('--json')) 0)|ConvertFrom-Json
   $oracle=[CliWindowOracle]::Query($data.hwnd)
   $effect=(($verb -eq 'minimize' -and $oracle.minimized) -or ($verb -eq 'maximize' -and $oracle.maximized) -or ($verb -eq 'restore' -and !$oracle.minimized -and !$oracle.maximized))
   Assert ($result.data.verified -and $effect -and $oracle.visible) "Actual $verb display effect independently verified (min=$($oracle.minimized), max=$($oracle.maximized), visible=$($oracle.visible))"
  }
  $already=(Invoke-Cli (@('window','manage','restore')+$guard+@('--json')) 0)|ConvertFrom-Json
  Assert ($already.data.alreadySatisfied -and !$already.data.attempted) 'Already satisfied state skips duplicate request'
  [void](Invoke-Cli (@('window','manage','minimize')+$guard+@('--json')) 0)
  $foreground=(Invoke-Cli (@('window','manage','foreground')+$guard+@('--json')) @(0,3,6))|ConvertFrom-Json
  if($foreground.status -eq 'success'){Assert ($foreground.data.verified -and !$foreground.data.after.minimized -and $foreground.data.foregroundWindow -eq $data.hwnd) 'Actual foreground and restore verified'}else{Assert (!$foreground.data.verified) 'Foreground/UIPI policy limitation is not success'}
  $closed=(Invoke-Cli (@('window','manage','close')+$guard+@('--json')) 0)|ConvertFrom-Json
  Assert ($closed.data.requestAccepted -and $closed.data.verified -and ![CliWindowOracle]::Exists($data.hwnd)) 'Actual graceful close removes self-owned HWND'
  [void]$target.WaitForExit(3000)
  Assert (!((Invoke-Cli (@('window','manage','restore')+$guard+@('--json')) 3)|ConvertFrom-Json).data.attempted) 'Exited process/thread/window target guard'
 }finally{if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()}
 $pair=Start-WindowTarget '--windows-ignore-close';$target=$pair[0];$data=$pair[1]
 try {
  $guard=@('--hwnd',$data.hwnd,'--pid',$data.pid.ToString(),'--tid',$data.tid.ToString(),'--creation-time',$data.processCreationTime,'--thread-creation-time',$data.threadCreationTime)
  $ignored=(Invoke-Cli (@('window','manage','close')+$guard+@('--wait-ms','250','--json')) 6)|ConvertFrom-Json
  $actual=Get-Content -LiteralPath $state -Raw|ConvertFrom-Json
  Assert ($ignored.data.requestAccepted -and !$ignored.data.verified -and [CliWindowOracle]::Exists($data.hwnd) -and $actual.closeMessages -gt 0) 'Posted WM_CLOSE observed by fixture but deliberately ignored stays partial'
 }finally{if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()}
 $pair=Start-WindowTarget '--windows-hung';$target=$pair[0];$data=$pair[1]
 try {
  $guard=@('--hwnd',$data.hungWindow,'--pid',$data.pid.ToString(),'--tid',$data.hungTid.ToString(),'--creation-time',$data.processCreationTime,'--thread-creation-time',$data.hungThreadCreationTime)
  $pending=(Invoke-Cli (@('window','manage','minimize')+$guard+@('--wait-ms','250','--json')) @(0,3,6))|ConvertFrom-Json
  Assert ($pending.data.attempted -and ($pending.status -ne 'success' -or [CliWindowOracle]::Query($data.hungWindow).minimized)) 'Unresponsive GUI target uses bounded asynchronous request and truthful readback'
 }finally{
  if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()
  $absolute=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\';if(!$absolute.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe window cleanup root'}
  Remove-Item -LiteralPath $absolute -Recurse -Force
 }
}
