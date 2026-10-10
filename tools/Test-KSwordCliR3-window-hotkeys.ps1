$help=Invoke-Cli @('help','window','hotkeys','probe')
Assert ($help.Contains('--modifiers') -and (Invoke-Cli @('window','hotkeys','probe','--help')) -eq $help) 'Global hotkey leaf help'
Assert (!(Invoke-Cli @('window','hotkeys','help')).Contains('--modifiers')) 'Global hotkey intermediate help'
foreach($bad in @(
 @('window','hotkeys','probe','--json'),
 @('window','hotkeys','probe','--key','F19','--json'),
 @('window','hotkeys','probe','--key','255','--modifiers','none','--json'),
 @('window','hotkeys','probe','--key','F19','--modifiers','ctrl+ctrl','--json'),
 @('window','hotkeys','probe','--key','F19','--modifiers','shift+','--json'),
 @('window','hotkeys','probe','--key','F19','--modifiers','CTRL','--json'),
 @('window','hotkeys','scan','--limit','0','--json'),
 @('window','hotkeys','scan','--limit','1321','--json'),
 @('window','hotkeys','scan','--backend','r0','--json'),
 @('window','hotkeys','scan','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Global hotkey validation before registration'}
# The host only exercises a documented reservation; no successful registration.
$reserved=(Invoke-Cli @('window','hotkeys','probe','--key','F12','--modifiers','ctrl','--json') 5)|ConvertFrom-Json
Assert ($reserved.data.complete -and $reserved.data.reservedCount -eq '1' -and !$reserved.data.entries[0].attempted -and $null -eq $reserved.data.entries[0].registrationPossible -and $reserved.data.entries[0].classification -eq 'reserved') 'Reserved F12 never registered'
if($InGuest){
 Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using System.Threading;
public static class CliHotkeyOracle {
 [DllImport("user32.dll",SetLastError=true)] static extern bool RegisterHotKey(IntPtr h,int id,uint modifiers,uint key);
 [DllImport("user32.dll",SetLastError=true)] static extern bool UnregisterHotKey(IntPtr h,int id);
 static Thread thread;static ManualResetEventSlim ready,stop;static int error;static bool held,released;
 public static void Start(){ready=new ManualResetEventSlim(false);stop=new ManualResetEventSlim(false);thread=new Thread(()=>{held=RegisterHotKey(IntPtr.Zero,0x3171,7,0x86);error=held?0:Marshal.GetLastWin32Error();ready.Set();stop.Wait();if(held)released=UnregisterHotKey(IntPtr.Zero,0x3171);});thread.Start();if(!ready.Wait(5000)||!held){Stop();throw new Exception("fixture RegisterHotKey error "+error);}}
 public static void Stop(){if(thread!=null){stop.Set();if(!thread.Join(5000))throw new Exception("hotkey fixture thread timeout");thread=null;ready.Dispose();stop.Dispose();if(held&&!released)throw new Exception("fixture UnregisterHotKey failed");}}
 public static bool CanRegister(){bool possible=false;int failure=0;var worker=new Thread(()=>{possible=RegisterHotKey(IntPtr.Zero,0x3172,7,0x86);if(possible){if(!UnregisterHotKey(IntPtr.Zero,0x3172))failure=Marshal.GetLastWin32Error();}else failure=Marshal.GetLastWin32Error();});worker.Start();worker.Join();if(!possible||failure!=0)throw new Exception("Independent hotkey cleanup oracle "+failure);return true;}
}
'@
 $args=@('window','hotkeys','probe','--key','F23','--modifiers','ctrl+alt+shift','--json')
 [CliHotkeyOracle]::Start()
 try{
  $occupied=(Invoke-Cli $args 0)|ConvertFrom-Json;$entry=$occupied.data.entries[0]
  Assert ($entry.attempted -and !$entry.registered -and !$entry.registrationPossible -and $entry.registerWin32Error -eq 1409 -and $entry.classification -eq 'occupied-or-reserved' -and $null -eq $entry.ownerPid) 'Real independently held registration, no invented owner'
 }finally{[CliHotkeyOracle]::Stop()}
 $free=(Invoke-Cli $args 0)|ConvertFrom-Json;$entry=$free.data.entries[0]
 Assert ($entry.registered -and $entry.unregistered -and $entry.registrationPossible -and $free.data.workerExited -and !$free.data.cleanupFailed) 'Real successful registration and same-thread release'
 Assert ([CliHotkeyOracle]::CanRegister()) 'Independent SDK can register after CLI exits'
 $limited=(Invoke-Cli @('window','hotkeys','scan','--limit','2','--json') 6)|ConvertFrom-Json
 Assert ($limited.data.limited -and !$limited.data.complete -and $limited.data.returnedCount -eq '2') 'Scan budget controls actual operations'
 $scan=(Invoke-Cli @('window','hotkeys','scan','--json') @(0,6))|ConvertFrom-Json
 Assert ($scan.data.complete -and $scan.data.returnedCount -eq '1320' -and $scan.data.reservedCount -eq '15' -and !$scan.data.cleanupFailed) 'Actual complete matrix, reserved F12 skipped'
 Assert (@($scan.data.entries|Where-Object {$_.registered -and !$_.unregistered}).Count -eq 0) 'Every successful native registration released'
 Assert ([CliHotkeyOracle]::CanRegister()) 'Independent SDK after complete scan'
 Assert ((Invoke-Cli @('window','hotkeys','probe','--key','F23','--modifiers','shift+ctrl+alt') 0).Contains('classification: available')) 'Global hotkey text and modifier order'
}
