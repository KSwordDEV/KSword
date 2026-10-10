$help=Invoke-Cli @('help','window','hierarchy','query')
Assert ($help.Contains('--hwnd') -and (Invoke-Cli @('window','hierarchy','query','--help')) -eq $help) 'Hierarchy leaf help'
Assert (!(Invoke-Cli @('window','hierarchy','help')).Contains('--creation-time')) 'Hierarchy intermediate immediate children only'
foreach($bad in @(
 @('window','hierarchy','query','--json'),
 @('window','hierarchy','query','--hwnd','0','--json'),
 @('window','hierarchy','query','--hwnd','1','--pid','bad','--json'),
 @('window','hierarchy','query','--hwnd','1','--creation-time','1','--json'),
 @('window','hierarchy','query','--hwnd','1','--thread-creation-time','0','--tid','1','--json'),
 @('window','hierarchy','query','--hwnd','1','--backend','r0','--json'),
 @('window','hierarchy','query','--hwnd','1','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Hierarchy parameter validation'}
Assert (!((Invoke-Cli @('window','hierarchy','query','--hwnd','0xffffffffffffffff','--json') 3)|ConvertFrom-Json).data.identityMatched) 'Missing HWND'
if($InGuest){
 Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using System.Collections.Generic;
public static class CliHierarchyOracle {
 [StructLayout(LayoutKind.Sequential)] public struct Rect{public int left,top,right,bottom;}
 [StructLayout(LayoutKind.Sequential)] public struct Point{public int x,y;}
 [DllImport("user32.dll")] static extern IntPtr GetParent(IntPtr h);
 [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr h,uint kind);
 [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr h,uint kind);
 [DllImport("user32.dll")] static extern IntPtr GetWindowLongPtrW(IntPtr h,int kind);
 [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h,out Rect rect);
 [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr h,out Rect rect);
 [DllImport("user32.dll")] static extern bool ClientToScreen(IntPtr h,ref Point point);
 [DllImport("user32.dll")] static extern uint GetDpiForWindow(IntPtr h);
 static string Hex(IntPtr v){return "0x"+unchecked((ulong)v.ToInt64()).ToString("x");}
 public static Dictionary<string,object> Query(string value){var h=new IntPtr(unchecked((long)Convert.ToUInt64(value.Substring(2),16)));Rect window,client;Point origin=new Point();if(!GetWindowRect(h,out window)||!GetClientRect(h,out client)||!ClientToScreen(h,ref origin))throw new Exception("geometry oracle");return new Dictionary<string,object>{{"parent",Hex(GetParent(h))},{"ancestorParent",Hex(GetAncestor(h,1))},{"root",Hex(GetAncestor(h,2))},{"rootOwner",Hex(GetAncestor(h,3))},{"owner",Hex(GetWindow(h,4))},{"style","0x"+unchecked((uint)GetWindowLongPtrW(h,-16).ToInt64()).ToString("x")},{"exStyle","0x"+unchecked((uint)GetWindowLongPtrW(h,-20).ToInt64()).ToString("x")},{"windowRect",window},{"clientRect",client},{"clientOriginScreen",origin},{"windowDpi",GetDpiForWindow(h)}};}
}
'@
 $root=Join-Path $env:TEMP ('KswordHierarchy-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null
 $state=Join-Path $root 'state.json';$fixture=Join-Path (Split-Path -Parent $Cli) 'R3Fixture.exe'
 $target=Start-Process $fixture -ArgumentList @('--windows-hierarchy',(Quote-CliArgument $state)) -PassThru
 try{
  $data=$null
  for($i=0;$i -lt 80;$i++){Start-Sleep -Milliseconds 100;try{$candidate=Get-Content -LiteralPath $state -Raw -Encoding UTF8|ConvertFrom-Json;if($candidate.pid -eq $target.Id -and $candidate.childWindow -ne '0x0'){$data=$candidate;break}}catch{}}
  Assert ($null -ne $data) 'Hierarchy fixture readiness'
  foreach($handle in @($data.hwnd,$data.childWindow,$data.ownedWindow)){
   $guard=@('--hwnd',$handle,'--pid',$data.pid.ToString(),'--tid',$data.tid.ToString(),'--creation-time',$data.processCreationTime,'--thread-creation-time',$data.threadCreationTime)
   $result=(Invoke-Cli (@('window','hierarchy','query')+$guard+@('--json')) @(0,6))|ConvertFrom-Json
   $actual=$result.data;$oracle=[CliHierarchyOracle]::Query($handle)
   Assert ($actual.identityMatched -and $actual.parentChainComplete -and $actual.zComplete -and $actual.topLevelZIndexZeroBased -ge 0 -and $actual.remoteProcedureValuesOpaque) 'Actual stable remote hierarchy snapshot'
   foreach($name in @('parent','ancestorParent','root','rootOwner','owner','style','exStyle','windowDpi')){
    $field=@($actual.fields|Where-Object {$_.name -eq $name});Assert ($field.Count -eq 1 -and $field[0].available -and $field[0].value -eq $oracle[$name]) "Independent SDK $name"
   }
   foreach($name in @('windowRect','clientRect')){foreach($axis in @('left','top','right','bottom')){$field=@($actual.fields|Where-Object {$_.name -eq $name})[0];Assert ($field.available -and $field.value.$axis -eq $oracle[$name].$axis) "Independent SDK $name $axis"}}
   $origin=@($actual.fields|Where-Object {$_.name -eq 'clientOriginScreen'})[0];Assert ($origin.value.x -eq $oracle.clientOriginScreen.x -and $origin.value.y -eq $oracle.clientOriginScreen.y) 'Independent client-screen origin'
   if($handle -eq $data.childWindow){Assert ($actual.parentChain[0] -eq $data.hwnd -and $oracle.root -eq $data.hwnd) 'Child chain/root includes fixture parent'}
   if($handle -eq $data.ownedWindow){Assert ($oracle.owner -eq $data.hwnd -and $oracle.rootOwner -eq $data.hwnd -and $oracle.root -eq $handle) 'Owned popup owner differs from root/parent ancestry'}
   $missing=@($actual.fields|Where-Object {!$_.available -and !$_.notApplicable});if($missing.Count){Assert ($result.status -eq 'partial' -and @($missing|Where-Object {$null -ne $_.value}).Count -eq 0) 'Missing fields retain null and partial status'}
  }
  Assert ((Invoke-Cli @('window','hierarchy','query','--hwnd',$data.hwnd) @(0,6)).Contains('parentChain:')) 'Hierarchy text output'
  Assert (!((Invoke-Cli @('window','hierarchy','query','--hwnd',$data.hwnd,'--pid',$data.pid.ToString(),'--creation-time',([uint64]$data.processCreationTime+1).ToString(),'--json') 3)|ConvertFrom-Json).data.identityMatched) 'Wrong creation identity'
  $handle=$data.hwnd;$target.Kill();$target.WaitForExit()
  Assert (!((Invoke-Cli @('window','hierarchy','query','--hwnd',$handle,'--json') 3)|ConvertFrom-Json).data.identityMatched) 'Exited target'
 }finally{
  if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()
  $absolute=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\';if(!$absolute.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe hierarchy fixture cleanup'}
  Remove-Item -LiteralPath $absolute -Recurse -Force
 }
}
