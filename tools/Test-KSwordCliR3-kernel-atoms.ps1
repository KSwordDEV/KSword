$help=Invoke-Cli @('help','kernel','atoms','enum')
Assert ($help.Contains('--start-id') -and (Invoke-Cli @('kernel','atoms','enum','--help')) -eq $help) 'Atom leaf help'
Assert (!(Invoke-Cli @('kernel','atoms','help')).Contains('--start-id')) 'Atom immediate help'
foreach($bad in @(@('--scope','local'),@('--start-id','49151'),@('--end-id','65536'),@('--start-id','65535','--end-id','49152'),@('--duration-ms','99'),@('--limit','0'),@('--backend','r0'),@('--unknown','1'))){Assert (((Invoke-Cli (@('kernel','atoms','enum','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'Atom parameter validation'}
Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;
public static class CliAtomOracle {
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern uint GlobalGetAtomNameW(ushort id,StringBuilder b,int n);
 [DllImport("user32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern int GetClipboardFormatNameW(uint id,StringBuilder b,int n);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] public static extern ushort GlobalAddAtomW(string name);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern ushort GlobalDeleteAtom(ushort id);
 [DllImport("user32.dll",SetLastError=true,CharSet=CharSet.Unicode)] public static extern uint RegisterClipboardFormatW(string name);
 public static string Name(uint id,bool global){var b=new StringBuilder(512);return (global?(long)GlobalGetAtomNameW((ushort)id,b,512):GetClipboardFormatNameW(id,b,512))>0?b.ToString():null;}
}
'@
$all=(Invoke-Cli @('kernel','atoms','enum','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.completeRange -and $all.data.scannedIdCount -eq '16384') 'Actual complete string-ID range'
foreach($row in @($all.data.atoms|Select-Object -First 32)){
 if($row.global.available){Assert ($row.global.name -eq [CliAtomOracle]::Name($row.id,$true)) 'Independent global atom name'}
 if($row.clipboard.available){Assert ($row.clipboard.name -eq [CliAtomOracle]::Name($row.id,$false)) 'Independent registered clipboard format name'}
}
$empty=(Invoke-Cli @('kernel','atoms','enum','--filter','KswordImpossibleAtom55','--json') @(0,6))|ConvertFrom-Json
Assert ($empty.data.returnedCount -eq '0') 'Filtered empty atom names'
Assert ((Invoke-Cli @('kernel','atoms','enum','--start-id','65535','--end-id','65535') @(0,5,6)).Contains('source: shared GlobalGetAtomNameW')) 'Atom text'
if($InGuest){
 $globalName='KswordAtom-'+[guid]::NewGuid().ToString('N')+[char]0x6d4b+[char]0x8bd5;$id=[CliAtomOracle]::GlobalAddAtomW($globalName);Assert ($id -ge 49152) 'Own global atom created'
 try{
  $own=(Invoke-Cli @('kernel','atoms','enum','--scope','global','--start-id',"$id",'--end-id',"$id",'--json') 0)|ConvertFrom-Json
  Assert ($own.data.returnedCount -eq '1' -and $own.data.atoms[0].global.name -eq $globalName -and $null -eq $own.data.atoms[0].clipboard.available -and [CliAtomOracle]::Name($id,$true) -eq $globalName) 'Real Unicode global atom with out-of-scope clipboard null'
  $clipboardName='KswordFormat-'+[guid]::NewGuid().ToString('N');$format=[CliAtomOracle]::RegisterClipboardFormatW($clipboardName);Assert ($format -ge 49152) 'Own registered clipboard format created'
  $clip=(Invoke-Cli @('kernel','atoms','enum','--scope','clipboard','--start-id',"$format",'--end-id',"$format",'--json') 0)|ConvertFrom-Json
  Assert ($clip.data.atoms[0].clipboard.name -eq $clipboardName -and [CliAtomOracle]::Name($format,$false) -eq $clipboardName -and $null -eq $clip.data.atoms[0].global.available) 'Independent clipboard-format evidence without clipboard data access'
 }finally{Assert ([CliAtomOracle]::GlobalDeleteAtom($id) -eq 0) 'Own atom deleted'}
 Assert ($null -eq [CliAtomOracle]::Name($id,$true)) 'Independent global atom disappearance'
 $gone=(Invoke-Cli @('kernel','atoms','enum','--scope','global','--start-id',"$id",'--end-id',"$id",'--json') 0)|ConvertFrom-Json
 Assert ($gone.data.completeRange -and $gone.data.returnedCount -eq '0') 'Known unallocated atom is valid empty success'
}
