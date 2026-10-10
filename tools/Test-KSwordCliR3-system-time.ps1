$help=Invoke-Cli @('help','system','time','query')
Assert ($help.Contains('--max-data-bytes') -and (Invoke-Cli @('system','time','query','--help')) -eq $help) 'Time leaf help'
Assert (!(Invoke-Cli @('system','time','help')).Contains('--max-data-bytes')) 'Time intermediate help'
foreach($bad in @(
 @('system','time','query','--max-data-bytes','0','--json'),
 @('system','time','query','--max-data-bytes','65537','--json'),
 @('system','time','query','--backend','r0','--json'),
 @('system','time','query','--set','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Time read-only parameters'}
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class CliTimeOracle {[DllImport("kernel32.dll")] public static extern ulong GetTickCount64();}
'@
$before=[DateTime]::UtcNow.ToFileTimeUtc();$tickBefore=[CliTimeOracle]::GetTickCount64()
$snapshot=(Invoke-Cli @('system','time','query','--max-data-bytes','65536','--json') @(0,6))|ConvertFrom-Json
$after=[DateTime]::UtcNow.ToFileTimeUtc();$tickAfter=[CliTimeOracle]::GetTickCount64();$data=$snapshot.data
Assert ([uint64]$data.clock.utcFileTime -ge [uint64]$before -and [uint64]$data.clock.utcFileTime -le [uint64]$after -and $data.clock.calendarKnown -and !$data.clock.atomicSnapshot) 'Independent current UTC FILETIME and non-atomic sample'
Assert ([uint64]$data.uptime.tickCountMs -ge $tickBefore -and [uint64]$data.uptime.tickCountMs -le $tickAfter) 'Independent SDK tick counter'
Assert ($data.uptime.estimateAvailable -and !$data.uptime.authoritativeBootTimestamp -and [uint64]$data.uptime.estimatedBootFileTime -eq ([uint64]$data.clock.utcFileTime-[uint64]$data.uptime.tickCountMs*10000)) 'Exact labelled boot estimate arithmetic'
if($data.zone.available){
 $offset=[TimeZoneInfo]::Local.GetUtcOffset([DateTime]::UtcNow).TotalMinutes
 Assert ($data.zone.effectiveBiasMinutes -eq -$offset) 'Independent time-zone offset sign'
 Assert ($data.zone.standardName -eq [TimeZoneInfo]::Local.StandardName -and $data.zone.daylightName -eq [TimeZoneInfo]::Local.DaylightName) 'Independent zone names'
}
$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\W32Time\Parameters')
if($key){try{
 Assert ($data.w32time.opened -and $data.w32time.complete -and [uint64]$data.w32time.valueCount -eq $key.GetValueNames().Count -and $data.w32time.closeWin32Error -eq 0) 'Independent W32Time value count and close'
 foreach($value in $data.w32time.values){
  $kind=$key.GetValueKind($value.name);$raw=$key.GetValue($value.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  if($kind -eq [Microsoft.Win32.RegistryValueKind]::String -or $kind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString){$bytes=[Text.Encoding]::Unicode.GetBytes($raw+[char]0);$hex=($bytes|ForEach-Object {$_.ToString('x2')}) -join '';Assert ($value.dataHex -eq $hex -and !$value.dataTruncated -and !$value.dataMalformed) 'Independent exact unexpanded registry UTF-16 bytes'}
  if($kind -eq [Microsoft.Win32.RegistryValueKind]::DWord){Assert ($value.numericValue -eq $raw) 'Independent W32Time DWORD'}
 }
}finally{$key.Dispose()}}else{Assert (!$data.w32time.opened -and $snapshot.status -eq 'partial') 'Absent W32Time cannot masquerade as full configuration'}
$small=(Invoke-Cli @('system','time','query','--max-data-bytes','1','--json') 6)|ConvertFrom-Json
Assert (@($small.data.w32time.values|Where-Object {$_.dataTruncated}).Count -gt 0 -or !$small.data.w32time.opened) 'Preview truncation/absence is partial'
Assert ((Invoke-Cli @('system','time','query') @(0,6)).Contains('source: Win32 clock/time-zone/tick APIs')) 'Time text output'
