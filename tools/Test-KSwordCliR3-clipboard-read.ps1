$help=Invoke-Cli @('help','clipboard','text','query')
Assert ($help.Contains('--max-units') -and (Invoke-Cli @('clipboard','text','query','--help')) -eq $help) 'Clipboard text leaf help'
Assert (!(Invoke-Cli @('clipboard','text','help')).Contains('--max-units')) 'Clipboard intermediate help'
Assert (!(Invoke-Cli @('help','clipboard')).Contains('--max-units')) 'Clipboard family hierarchy'
Assert ((Invoke-Cli @('help','window','clipboard','text','query')).Contains('window clipboard text query') -and !(Invoke-Cli @('window','clipboard','help')).Contains('--max-units')) 'Canonical window clipboard hierarchy'
foreach($bad in @(
 @('clipboard','formats','enum','--materialize','maybe','--json'),
 @('clipboard','formats','enum','--limit','0','--json'),
 @('clipboard','text','query','--format','html','--json'),
 @('clipboard','text','query','--max-units','0','--json'),
 @('clipboard','text','query','--max-units','65537','--json'),
 @('clipboard','formats','enum','--backend','r0','--json'),
 @('clipboard','formats','enum','--bad','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Clipboard argument validation'}
$metadata=(Invoke-Cli @('clipboard','formats','enum','--json') @(0,3,6))|ConvertFrom-Json
Assert (!$metadata.data.materialize) 'Metadata mode is default'
foreach($format in $metadata.data.formats){Assert (!$format.dataRequested -and $null -eq $format.byteSize) 'Metadata does not materialize content'}
Assert (((Invoke-Cli @('window','clipboard','formats','enum','--json') @(0,3,6))|ConvertFrom-Json).command -eq 'window clipboard formats enum') 'Canonical metadata path routes to R3'
Assert ((Invoke-Cli @('clipboard','formats','enum') @(0,3,6)).Contains('materialize: false')) 'Clipboard text metadata output'
if($InGuest){
 Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Runtime.InteropServices;using System.Text;
public static class CliClipboardFixture {
 static IntPtr window;
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateWindowEx(uint ex,string cls,string title,uint style,int x,int y,int w,int h,IntPtr parent,IntPtr menu,IntPtr instance,IntPtr parameter);
 [DllImport("user32.dll",SetLastError=true)] static extern bool DestroyWindow(IntPtr window);
 [DllImport("user32.dll",SetLastError=true)] static extern bool OpenClipboard(IntPtr window);
 [DllImport("user32.dll",SetLastError=true)] static extern bool CloseClipboard();
 [DllImport("user32.dll",SetLastError=true)] static extern bool EmptyClipboard();
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr SetClipboardData(uint format,IntPtr data);
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr GetClipboardData(uint format);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern uint RegisterClipboardFormat(string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GlobalAlloc(uint flags,UIntPtr size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GlobalLock(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GlobalUnlock(IntPtr handle);
 [DllImport("kernel32.dll")] static extern IntPtr GlobalFree(IntPtr handle);
 [DllImport("kernel32.dll")] static extern UIntPtr GlobalSize(IntPtr handle);
 [DllImport("user32.dll")] static extern uint GetClipboardSequenceNumber();
 static void Open(){if(window==IntPtr.Zero)window=CreateWindowEx(0,"STATIC","KswordClipboardFixture",0,0,0,0,0,new IntPtr(-3),IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);if(window==IntPtr.Zero||!OpenClipboard(window))throw new Exception("clipboard fixture open "+Marshal.GetLastWin32Error());}
 static void Put(uint format,byte[] bytes){var handle=GlobalAlloc(0x42,new UIntPtr((uint)bytes.Length));if(handle==IntPtr.Zero)throw new Exception("clipboard fixture alloc");try{var pointer=GlobalLock(handle);if(pointer==IntPtr.Zero)throw new Exception("clipboard fixture lock");Marshal.Copy(bytes,0,pointer,bytes.Length);GlobalUnlock(handle);if(SetClipboardData(format,handle)==IntPtr.Zero)throw new Exception("clipboard fixture publish");handle=IntPtr.Zero;}finally{if(handle!=IntPtr.Zero)GlobalFree(handle);}}
 public static void Write(string text,uint custom){Open();try{if(!EmptyClipboard())throw new Exception("clipboard fixture empty");Put(13,Encoding.Unicode.GetBytes(text+"\0"));if(custom!=0)Put(custom,new byte[]{1,2,3,4,5});}finally{CloseClipboard();}}
 public static void WriteAnsi(string text){Open();try{if(!EmptyClipboard())throw new Exception("clipboard fixture empty");Put(1,Encoding.ASCII.GetBytes(text+"\0"));}finally{CloseClipboard();}}
 public static void Clear(){Open();try{if(!EmptyClipboard())throw new Exception("clipboard fixture empty");}finally{CloseClipboard();}}
 public static string Read(){Open();try{var handle=GetClipboardData(13);var pointer=GlobalLock(handle);if(pointer==IntPtr.Zero)throw new Exception("clipboard oracle lock");try{return Marshal.PtrToStringUni(pointer);}finally{GlobalUnlock(handle);}}finally{CloseClipboard();}}
 public static ulong Size(uint format){Open();try{return GlobalSize(GetClipboardData(format)).ToUInt64();}finally{CloseClipboard();}}
 public static uint Sequence(){return GetClipboardSequenceNumber();}
 public static void Hold(){Open();}
 public static void Release(){CloseClipboard();}
 public static void Dispose(){if(window!=IntPtr.Zero){DestroyWindow(window);window=IntPtr.Zero;}}
}
'@
 $customName='KswordCliR3-'+[guid]::NewGuid().ToString('N');$custom=[CliClipboardFixture]::RegisterClipboardFormat($customName)
 try {
  $expected='KSword '+[char]0x4e2d+[char]0x6587+"`r`nfixture "+[char]::ConvertFromUtf32(0x1f600)
  [CliClipboardFixture]::Write($expected,$custom)
  $before=[CliClipboardFixture]::Sequence()
  $formats=(Invoke-Cli @('clipboard','formats','enum','--json') 0)|ConvertFrom-Json
  Assert ($formats.data.clipboard.closed -and $formats.data.clipboard.enumComplete -and [CliClipboardFixture]::Sequence() -eq $before) 'Metadata leaves fixture data and sequence unchanged'
  $row=$formats.data.formats|Where-Object {$_.id -eq $custom};Assert ($row.name -eq $customName -and !$row.dataRequested) 'Actual registered format name'
  $text=(Invoke-Cli @('clipboard','text','query','--json') @(0,6))|ConvertFrom-Json
  Assert ($text.data.textAvailable -and $text.data.selectedFormat -eq 13 -and $text.data.text -ceq [CliClipboardFixture]::Read() -and $text.data.text -ceq $expected -and $text.data.unlocked -and $text.data.clipboard.closed) 'Actual Unicode/emoji/line-break text independently read back and released'
  $canonical=(Invoke-Cli @('window','clipboard','text','query','--json') @(0,6))|ConvertFrom-Json
  Assert ($canonical.command -eq 'window clipboard text query' -and $canonical.data.text -ceq $expected) 'Canonical text path and convenience alias agree'
  $sizes=(Invoke-Cli @('clipboard','formats','enum','--materialize','on','--json') @(0,6))|ConvertFrom-Json
  $row=$sizes.data.formats|Where-Object {$_.id -eq $custom};Assert ($row.dataAvailable -and [uint64]$row.byteSize -eq [CliClipboardFixture]::Size($custom)) 'Independent actual HGLOBAL capacity'
  $limited=(Invoke-Cli @('clipboard','formats','enum','--limit','1','--json') 6)|ConvertFrom-Json
  Assert ($limited.data.truncated -and $limited.data.returnedCount -eq 1) 'Format output truncation'
  $preview=(Invoke-Cli @('clipboard','text','query','--max-units','3','--json') 6)|ConvertFrom-Json
  Assert ($preview.data.truncated -and $preview.data.text -ceq $expected.Substring(0,3)) 'Bounded text preview'
  [CliClipboardFixture]::WriteAnsi('Ansi fixture')
  $ansi=(Invoke-Cli @('clipboard','text','query','--format','ansi','--json') @(0,6))|ConvertFrom-Json
  Assert ($ansi.data.selectedFormat -eq 1 -and $ansi.data.text -ceq 'Ansi fixture' -and $ansi.data.previewUnit -eq 'ansi-bytes' -and $ansi.data.ansiCodePage -gt 0) 'Actual ANSI fixture with explicit ACP provenance'
  [CliClipboardFixture]::Write('',0)
  $empty=(Invoke-Cli @('clipboard','text','query','--json') @(0,6))|ConvertFrom-Json
  Assert ($empty.data.empty -and $empty.data.text -ceq '' -and $empty.data.terminated) 'Actual valid empty text distinct from unavailable data'
  [CliClipboardFixture]::Clear()
  $emptyFormats=(Invoke-Cli @('clipboard','formats','enum','--json') 0)|ConvertFrom-Json
  Assert ($emptyFormats.data.enumeratedCount -eq '0') 'Actual valid empty clipboard enumeration'
  Assert (((Invoke-Cli @('clipboard','text','query','--json') 5)|ConvertFrom-Json).status -eq 'unsupported') 'Empty clipboard has no advertised text'
  [CliClipboardFixture]::Hold()
  try {$blocked=(Invoke-Cli @('clipboard','formats','enum','--json') 3)|ConvertFrom-Json;Assert (!$blocked.data.clipboard.opened -and !$blocked.data.clipboard.closeAttempted -and $blocked.data.clipboard.openWin32Error -ne 0) 'Actual clipboard lock contention and no borrowed close'}finally{[CliClipboardFixture]::Release()}
 }finally{[CliClipboardFixture]::Clear();[CliClipboardFixture]::Dispose()}
}
