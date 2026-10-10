$help=Invoke-Cli @('help','window','capture','set')
Assert ($help.Contains('--mode') -and (Invoke-Cli @('window','capture','set','--help')) -eq $help) 'Capture leaf help'
Assert (!(Invoke-Cli @('window','capture','help')).Contains('--mode')) 'Capture intermediate help'
foreach($bad in @(
 @('window','capture','query','--json'),
 @('window','capture','query','--hwnd','0','--json'),
 @('window','capture','query','--hwnd','1','--pid','bad','--json'),
 @('window','capture','query','--hwnd','1','--creation-time','1','--json'),
 @('window','capture','query','--hwnd','1','--backend','r0','--json'),
 @('window','capture','set','--mode','invalid','--json'),
 @('window','capture','query','--hwnd','1','--bad','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Capture argument validation'}
Assert (!((Invoke-Cli @('window','capture','query','--hwnd','0xffffffffffffffff','--json') 3)|ConvertFrom-Json).data.identityMatched) 'Invalid capture target'
if($InGuest){
 Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class CliCaptureOracle {
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateWindowEx(uint ex,string cls,string title,uint style,int x,int y,int w,int h,IntPtr parent,IntPtr menu,IntPtr instance,IntPtr data);
 [DllImport("user32.dll")] public static extern bool DestroyWindow(IntPtr window);
 [DllImport("user32.dll")] static extern bool SetLayeredWindowAttributes(IntPtr window,uint color,byte alpha,uint flags);
 [DllImport("user32.dll",SetLastError=true)] public static extern bool SetWindowDisplayAffinity(IntPtr window,uint value);
 [DllImport("user32.dll",SetLastError=true)] public static extern bool GetWindowDisplayAffinity(IntPtr window,out uint value);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
 [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr handle,out long created,out long exited,out long kernel,out long user);
 [DllImport("kernel32.dll")] static extern bool GetThreadTimes(IntPtr handle,out long created,out long exited,out long kernel,out long user);
 public static string[] Create(){var window=CreateWindowEx(0x80080,"STATIC","KSword capture oracle",0xcf0000,-10000,-10000,32,32,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);if(window==IntPtr.Zero||!SetLayeredWindowAttributes(window,0,255,2))throw new Exception("capture fixture create");uint pid;var tid=GetWindowThreadProcessId(window,out pid);long process,thread,e,k,u;GetProcessTimes(GetCurrentProcess(),out process,out e,out k,out u);GetThreadTimes(GetCurrentThread(),out thread,out e,out k,out u);return new[]{"0x"+window.ToInt64().ToString("X"),pid.ToString(),tid.ToString(),process.ToString(),thread.ToString()};}
}
'@
 $data=[CliCaptureOracle]::Create();$hwnd=[IntPtr]::new([Convert]::ToInt64($data[0].Substring(2),16));$guard=@('--hwnd',$data[0],'--pid',$data[1],'--tid',$data[2],'--creation-time',$data[3],'--thread-creation-time',$data[4])
 try{
  foreach($value in @(0,1,17)){
   Assert ([CliCaptureOracle]::SetWindowDisplayAffinity($hwnd,$value)) 'Independent owning-process SDK setup'
   [uint32]$current=0;Assert ([CliCaptureOracle]::GetWindowDisplayAffinity($hwnd,[ref]$current) -and $current -eq $value) 'Independent SDK affinity state'
   $query=(Invoke-Cli (@('window','capture','query')+$guard+@('--json')) 0)|ConvertFrom-Json
   Assert ($query.data.identityMatched -and $query.data.layered -and !$query.data.callerOwnsWindow -and $query.data.affinity.value -eq ('0x'+$value.ToString('x'))) 'Actual cross-process policy query'
  }
  $declined=(Invoke-Cli (@('window','capture','set')+$guard+@('--mode','none','--json')) 5)|ConvertFrom-Json
  Assert (!$declined.data.attempted -and !$declined.data.callerOwnsWindow) 'Standalone CLI refuses unsupported foreign-window write'
  [uint32]$current=0;Assert ([CliCaptureOracle]::GetWindowDisplayAffinity($hwnd,[ref]$current) -and $current -eq 17) 'Foreign-window refusal leaves policy unchanged'
  Assert ((Invoke-Cli (@('window','capture','query')+$guard) 0).Contains('source: GetWindowDisplayAffinity')) 'Capture text output'
 }finally{[void][CliCaptureOracle]::SetWindowDisplayAffinity($hwnd,0);[void][CliCaptureOracle]::DestroyWindow($hwnd)}
 # A native fixture hosts the production adapter inside the owning process.
 # These cases prove same-process support, never remote standalone CLI support.
 $originalCli=$Cli;$Cli=Join-Path (Split-Path -Parent $Cli) 'R3CaptureRunner.exe'
 try{
  foreach($mode in @('none','monitor','exclude')){
   $result=(Invoke-Cli @('window','capture','set','--hwnd','self','--pid','self','--tid','self','--creation-time','self','--thread-creation-time','self','--mode',$mode,'--json') 0)|ConvertFrom-Json
   Assert ($result.data.callerOwnsWindow -and $result.data.accepted -and $result.data.verified -and $result.data.after.mode -eq $mode) 'Same-process production adapter actual SDK set/readback'
  }
 }finally{$Cli=$originalCli}
}
