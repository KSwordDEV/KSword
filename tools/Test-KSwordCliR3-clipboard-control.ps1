$help=Invoke-Cli @('help','clipboard','clear')
Assert ($help.Contains('--expect-sequence') -and (Invoke-Cli @('clipboard','clear','--help')) -eq $help) 'Clear leaf help'
Assert (!(Invoke-Cli @('clipboard','help')).Contains('--expect-sequence') -and (Invoke-Cli @('help','window','clipboard','owner','query')).Contains('sampled identifiers')) 'Clipboard hierarchy/alias identity limitations'
foreach($bad in @(@('clear'),@('clear','--confirm','--expect-sequence','0'),@('clear','--confirm','--expect-sequence','4294967296'),@('clear','--confirm','--unknown','1'),@('owner','query','--backend','r0'),@('opener','query','--unknown','1'))){Assert (((Invoke-Cli (@('clipboard')+$bad+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'Clipboard control validation'}
foreach($kind in @('owner','opener')){
 $query=(Invoke-Cli @('clipboard',$kind,'query','--json') @(0,6))|ConvertFrom-Json
 Assert ($query.data.PSObject.Properties['window'] -and $query.data.PSObject.Properties['stable'] -and (!$query.data.windowPresent -or !$query.data.identityKnown -or $query.data.pid -gt 0)) 'Metadata owner/opener nullable identity contract'
}
Assert ((Invoke-Cli @('clipboard','owner','query') @(0,6)).Contains('source: GetClipboardOwner')) 'Clipboard owner text'
if($InGuest){
 Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class CliClipboardControlFixture {
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern IntPtr CreateWindowEx(uint ex,string cls,string title,uint style,int x,int y,int w,int h,IntPtr parent,IntPtr menu,IntPtr instance,IntPtr data);
 [DllImport("user32.dll")] public static extern bool DestroyWindow(IntPtr window);
 [DllImport("user32.dll",SetLastError=true)] public static extern bool OpenClipboard(IntPtr window);
 [DllImport("user32.dll")] public static extern bool CloseClipboard();
 [DllImport("user32.dll")] static extern bool EmptyClipboard();
 [DllImport("user32.dll")] static extern IntPtr SetClipboardData(uint format,IntPtr data);
 [DllImport("user32.dll")] public static extern uint GetClipboardSequenceNumber();
 [DllImport("user32.dll")] public static extern IntPtr GetClipboardOwner();
 [DllImport("user32.dll")] public static extern IntPtr GetOpenClipboardWindow();
 [DllImport("user32.dll")] public static extern int CountClipboardFormats();
 [DllImport("kernel32.dll")] static extern IntPtr GlobalAlloc(uint flags,UIntPtr bytes);
 [DllImport("kernel32.dll")] static extern IntPtr GlobalLock(IntPtr handle);
 [DllImport("kernel32.dll")] static extern bool GlobalUnlock(IntPtr handle);
 public static IntPtr Create(){return CreateWindowEx(0,"STATIC","KSword clipboard clear fixture",0,-10000,-10000,16,16,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);}
 public static void Publish(IntPtr window){if(!OpenClipboard(window))throw new Exception("fixture open");try{if(!EmptyClipboard())throw new Exception("fixture empty");var h=GlobalAlloc(2,new UIntPtr(4));if(h==IntPtr.Zero)throw new Exception("fixture alloc");var pointer=GlobalLock(h);if(pointer==IntPtr.Zero)throw new Exception("fixture lock");Marshal.WriteInt16(pointer,54);Marshal.WriteInt16(pointer,2,0);GlobalUnlock(h);if(SetClipboardData(13,h)==IntPtr.Zero)throw new Exception("fixture publish");}finally{CloseClipboard();}}
}
'@
 $window=[CliClipboardControlFixture]::Create();Assert ($window -ne [IntPtr]::Zero) 'Own publisher window'
 try{
  [CliClipboardControlFixture]::Publish($window);$sequence=[CliClipboardControlFixture]::GetClipboardSequenceNumber()
  $owner=(Invoke-Cli @('clipboard','owner','query','--json') 0)|ConvertFrom-Json
  Assert ($owner.data.pid -eq $PID -and [Convert]::ToUInt64($owner.data.window.Substring(2),16) -eq [uint64]$window.ToInt64() -and [CliClipboardControlFixture]::GetClipboardOwner() -eq $window) 'Independent actual publisher window/PID'
  Assert ([CliClipboardControlFixture]::OpenClipboard($window)) 'Own explicit holder'
  try{$opener=(Invoke-Cli @('window','clipboard','opener','query','--json') 0)|ConvertFrom-Json;Assert ($opener.data.pid -eq $PID -and [CliClipboardControlFixture]::GetOpenClipboardWindow() -eq $window) 'Independent actual holder';$busy=(Invoke-Cli @('clipboard','clear','--confirm','--json') 3)|ConvertFrom-Json;Assert (!$busy.data.attempted -and !$busy.data.opened) 'Held clipboard cannot clear'}finally{[void][CliClipboardControlFixture]::CloseClipboard()}
  $mismatch=(Invoke-Cli @('clipboard','clear','--confirm','--expect-sequence',([uint64]$sequence+1).ToString(),'--json') 3)|ConvertFrom-Json
  Assert (!$mismatch.data.attempted -and !$mismatch.data.sequenceMatched -and [CliClipboardControlFixture]::GetClipboardSequenceNumber() -eq $sequence -and [CliClipboardControlFixture]::CountClipboardFormats() -gt 0) 'Mismatched sequence leaves own formats unchanged'
  $clear=(Invoke-Cli @('window','clipboard','clear','--confirm','--expect-sequence',"$sequence",'--json') 0)|ConvertFrom-Json
  Assert ($clear.data.requestSucceeded -and $clear.data.verified -and $clear.data.afterFormatCount -eq '0' -and $clear.data.closed -and [CliClipboardControlFixture]::CountClipboardFormats() -eq 0) 'Actual clear, independent zero formats and owned close'
  $empty=(Invoke-Cli @('clipboard','clear','--confirm','--json') 0)|ConvertFrom-Json
  Assert ($empty.data.beforeFormatCount -eq '0' -and $empty.data.verified) 'Already-empty clear has real empty evidence'
  Assert ([CliClipboardControlFixture]::OpenClipboard([IntPtr]::Zero)) 'NULL owner can hold clipboard'
  try{$nullHolder=(Invoke-Cli @('clipboard','opener','query','--json') 0)|ConvertFrom-Json;Assert (!$nullHolder.data.windowPresent -and $null -eq $nullHolder.data.pid -and !$nullHolder.data.PSObject.Properties['unlocked']) 'NULL opener does not invent an unlocked state';$nullOpen=(Invoke-Cli @('clipboard','clear','--confirm','--json') @(0,3))|ConvertFrom-Json;if($nullOpen.data.opened){Assert ($nullOpen.data.verified -and [CliClipboardControlFixture]::CountClipboardFormats() -eq 0) 'NULL-HWND open arbitration may permit a second NULL open; actual empty/readback remains required'}else{Assert (!$nullOpen.data.attempted) 'Native NULL-HWND open refusal does not write'}}finally{[void][CliClipboardControlFixture]::CloseClipboard()}
 }finally{[void][CliClipboardControlFixture]::DestroyWindow($window)}
}
