$leaf=Invoke-Cli @('help','kernel','nt-query','process','basic','query')
Assert ($leaf.Contains('returned bytes') -and (Invoke-Cli @('kernel','nt-query','process','basic','query','--help')) -eq $leaf) 'Named native query leaf help'
Assert (!(Invoke-Cli @('kernel','nt-query','process','help')).Contains('attempts/limits')) 'Category help only direct presets'
Assert (!(Invoke-Cli @('help','kernel','nt-query')).Contains('debug-port query')) 'Family help does not expand all presets'
foreach($bad in @(@('process','basic','query','--pid','4'),@('process','basic','query','--class','0'),@('query','--backend','r0'),@('query','--unknown','1'),@('exports','enum','--limit','0'),@('exports','enum','--limit','513'))){Assert (((Invoke-Cli (@('kernel','nt-query')+$bad+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'Native fixed preset validation'}
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class CliNtQueryOracle {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr GetModuleHandleW(string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module,string name);
 [DllImport("kernel32.dll",EntryPoint="GetProcAddress")] static extern IntPtr GetOrdinal(IntPtr module,IntPtr ordinal);
 [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h,uint c,IntPtr b,uint n,out uint r);
 public static uint BasicBytes(){var b=Marshal.AllocHGlobal(48);try{uint r;int s=NtQueryInformationProcess(new IntPtr(-1),0,b,48,out r);if(s!=0)throw new Exception("SDK process basic "+s.ToString("X"));return r;}finally{Marshal.FreeHGlobal(b);}}
 public static string Rva(string name,int ordinal){var module=GetModuleHandleW("ntdll.dll");var address=GetProcAddress(module,name);if(address==IntPtr.Zero||GetOrdinal(module,new IntPtr(ordinal))!=address)throw new Exception("SDK export");return "0x"+(address.ToInt64()-module.ToInt64()).ToString("x");}
}
'@
$basic=(Invoke-Cli @('kernel','nt-query','process','basic','query','--json') 0)|ConvertFrom-Json
Assert ($basic.data.queryCount -eq '1' -and $basic.data.queries[0].success -and [uint64]$basic.data.queries[0].returnedBytes -eq [CliNtQueryOracle]::BasicBytes() -and $basic.data.queries[0].ntStatus -eq '0x0') 'Independent native process basic actual length'
$all=(Invoke-Cli @('kernel','nt-query','query','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.queryCount -eq '18' -and $all.data.queries.Count -eq 18 -and $all.data.token.opened -and $all.data.token.closed) 'Existing full preset list and token lifetime'
foreach($row in $all.data.queries){Assert ($row.apiAvailable -and $row.attempted -and [uint64]$row.allocatedBytes -le 16777216 -and [uint64]$row.attemptCount -le 6 -and (!$row.success -or ($row.ntStatus -eq '0x0' -and [uint64]$row.returnedBytes -le [uint64]$row.allocatedBytes))) 'Native status/length/capacity contract'}
$exports=(Invoke-Cli @('kernel','nt-query','exports','enum','--json') 0)|ConvertFrom-Json
Assert ($exports.data.complete -and [uint64]$exports.data.returnedCount -gt 0) 'Loaded ntdll export matrix'
foreach($row in @($exports.data.exports|Where-Object {!$_.forwarded}|Select-Object -First 24)){Assert ($row.rva -eq [CliNtQueryOracle]::Rva($row.name,$row.ordinal)) 'Independent Win32 named/ordinal export RVA'}
$empty=(Invoke-Cli @('kernel','nt-query','exports','enum','--filter','KswordImpossibleExport56','--json') 0)|ConvertFrom-Json
Assert ($empty.data.returnedCount -eq '0') 'Valid filtered empty export list'
$limited=(Invoke-Cli @('kernel','nt-query','exports','enum','--limit','1','--json') 6)|ConvertFrom-Json
Assert ($limited.data.complete -and $limited.data.truncated) 'Export output limit'
Assert ((Invoke-Cli @('kernel','nt-query','thread','basic','query') @(0,6)).Contains('source: shared fixed native query presets')) 'Native preset text'
