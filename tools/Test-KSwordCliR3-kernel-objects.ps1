$help=Invoke-Cli @('help','kernel','objects','enum')
Assert ($help.Contains('--scope') -and (Invoke-Cli @('kernel','objects','enum','--help')) -eq $help) 'Native objects leaf help'
Assert (!(Invoke-Cli @('kernel','objects','help')).Contains('--scope')) 'Native objects intermediate help'
foreach($bad in @(
 @('kernel','objects','enum','--scope','known-dlls','--json'),
 @('kernel','objects','enum','--kind','process','--json'),
 @('kernel','objects','enum','--max-entries','0','--json'),
 @('kernel','objects','enum','--duration-ms','99','--json'),
 @('kernel','objects','enum','--limit','0','--json'),
 @('kernel','objects','enum','--backend','r0','--json'),
 @('kernel','objects','enum','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Native objects validation'}
. "$PSScriptRoot\KswordCliR3NamespaceOracle.ps1"
foreach($scope in @('device','driver')){
 $root=if($scope -eq 'device'){'\Device'}else{'\Driver'};$status=[CliNamespaceOracle]::OpenStatus($root)
 $result=(Invoke-Cli @('kernel','objects','enum','--scope',$scope,'--limit','100000','--json') @(0,3,6))|ConvertFrom-Json
 if($status -ne 0){Assert ($result.status -eq 'failed' -and !$result.data.sources[0].opened -and $result.data.sources[0].openNtStatus -eq ('0x'+$status.ToString('x'))) 'Independent SDK permission/unavailable root status';continue}
 $oracle=[CliNamespaceOracle]::Enum($root)
 Assert ($result.data.sources[0].complete -and [uint64]$result.data.enumeratedCount -eq $oracle.Count -and $result.data.sources[0].closed) 'Independent Device/Driver object directory count/closure'
 foreach($row in $result.data.objects){Assert ($oracle[$row.name] -eq $row.type -and $row.parentPath -eq $root) 'Independent object names/types';if($row.type -eq 'Device' -or $row.type -eq 'Driver'){Assert (!$row.metadataProbeSupported -and !$row.openAttempted -and $null -eq $row.opened -and $null -eq $row.basic.handleCount) 'Device/Driver unsupported opener/counts not invented'}}
}
$drivers=(Invoke-Cli @('kernel','objects','enum','--scope','driver','--kind','driver','--json') @(0,3,6))|ConvertFrom-Json
Assert (@($drivers.data.objects|Where-Object {$_.type -ne 'Driver'}).Count -eq 0) 'Driver object type filter'
$empty=(Invoke-Cli @('kernel','objects','enum','--scope','driver','--filter','KswordNoSuchDriver47-50','--json') @(0,3,6))|ConvertFrom-Json
Assert ($empty.data.matchedCount -eq '0') 'Valid name-filtered empty object result'
$limited=(Invoke-Cli @('kernel','objects','enum','--scope','driver','--max-entries','1','--json') @(3,6))|ConvertFrom-Json
if($limited.data.sources[0].opened){Assert ($limited.data.limited -and !$limited.data.sources[0].complete) 'Actual object-directory entry budget'}else{Assert ($limited.status -eq 'failed') 'Unreadable selected root cannot exercise scan budget'}
$all=(Invoke-Cli @('kernel','objects','enum','--limit','1','--json') @(3,6))|ConvertFrom-Json
Assert ($all.data.roots.Count -eq 4 -and $all.data.sources.Count -eq 4) 'Shared four roots'
if([uint64]$all.data.matchedCount -gt 1){Assert ($all.data.truncated -and $all.status -eq 'partial') 'Actual display truncation'}
Assert ((Invoke-Cli @('kernel','objects','enum','--scope','driver','--limit','1') @(3,6)).Contains('source: shared Device/Driver/FileSystem')) 'Native object text output'
