$help=Invoke-Cli @('help','kernel','object-types','enum')
Assert ($help.Contains('--filter') -and (Invoke-Cli @('kernel','object-types','enum','--help')) -eq $help) 'Type matrix leaf help'
Assert (!(Invoke-Cli @('kernel','object-types','help')).Contains('--filter')) 'Type matrix intermediate help'
foreach($bad in @(@('--limit','0'),@('--limit','257'),@('--backend','r0'),@('--unknown','1'))){Assert (((Invoke-Cli (@('kernel','object-types','enum','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'Type matrix validation'}
Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Runtime.InteropServices;
public static class CliObjectTypesOracle {
 [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr h,int c,IntPtr b,uint n,out uint r);
 public static Dictionary<string,int> Query(){var b=Marshal.AllocHGlobal(4*1024*1024);try{uint r;int s=NtQueryObject(IntPtr.Zero,3,b,4*1024*1024,out r);if(s!=0)throw new Exception("oracle types "+s.ToString("X"));int count=Marshal.ReadInt32(b),offset=8;var result=new Dictionary<string,int>();for(int i=0;i<count;i++){if(offset+104>r)throw new Exception("oracle bounds");var row=IntPtr.Add(b,offset);int length=(ushort)Marshal.ReadInt16(row),max=(ushort)Marshal.ReadInt16(row,2);var name=Marshal.ReadIntPtr(row,8);result.Add(Marshal.PtrToStringUni(name,length/2),Marshal.ReadByte(row,90));offset=(offset+104+max+7)&~7;}return result;}finally{Marshal.FreeHGlobal(b);}}
}
'@
$oracle=[CliObjectTypesOracle]::Query()
$all=(Invoke-Cli @('kernel','object-types','enum','--json') 0)|ConvertFrom-Json
Assert ($all.data.complete -and [uint64]$all.data.reportedCount -eq $oracle.Count -and $all.data.parsedCount -eq $all.data.returnedCount) 'Independent native type matrix count/completeness'
foreach($row in $all.data.types){Assert ($oracle.ContainsKey($row.type) -and $oracle[$row.type] -eq $row.typeIndex -and $row.objects -match '^\d+$' -and $row.validAccessMask -match '^0x[0-9a-f]+$') 'Independent native names/index and safe count/access fields'}
$event=(Invoke-Cli @('kernel','object-types','enum','--filter','eVeNt','--json') 0)|ConvertFrom-Json
Assert (@($event.data.types|Where-Object {$_.type -notmatch 'event'}).Count -eq 0 -and [uint64]$event.data.matchedCount -gt 0) 'Case insensitive type name filter'
$empty=(Invoke-Cli @('kernel','object-types','enum','--filter','KswordNoSuchObjectType','--json') 0)|ConvertFrom-Json
Assert ($empty.data.complete -and $empty.data.returnedCount -eq '0') 'Valid filtered empty matrix'
$short=(Invoke-Cli @('kernel','object-types','enum','--limit','1','--json') 6)|ConvertFrom-Json
Assert ($short.data.complete -and $short.data.truncated -and $short.data.returnedCount -eq '1') 'Output budget distinct from native matrix completeness'
Assert ((Invoke-Cli @('kernel','object-types','enum','--filter','Event')).Contains('source: NtQueryObject(ObjectTypesInformation)')) 'Type matrix text'
