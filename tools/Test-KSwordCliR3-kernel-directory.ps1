$help=Invoke-Cli @('help','kernel','directory','enum')
Assert ($help.Contains('--max-depth') -and (Invoke-Cli @('kernel','directory','enum','--help')) -eq $help) 'Recursive directory leaf help'
Assert (!(Invoke-Cli @('kernel','directory','help')).Contains('--max-depth')) 'Recursive directory intermediate help'
foreach($bad in @(
 @('kernel','directory','enum','--root','relative','--json'),
 @('kernel','directory','enum','--max-depth','33','--json'),
 @('kernel','directory','enum','--max-depth','-1','--json'),
 @('kernel','directory','enum','--max-rows','2501','--json'),
 @('kernel','directory','enum','--max-scanned-entries','0','--json'),
 @('kernel','directory','enum','--duration-ms','99','--json'),
 @('kernel','directory','enum','--limit','2501','--json'),
 @('kernel','directory','enum','--backend','r0','--json'),
 @('kernel','directory','enum','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Recursive directory parameter validation'}
. "$PSScriptRoot\KswordCliR3NamespaceOracle.ps1"
$oracle=[CliNamespaceOracle]::Enum('\KnownDlls')
$direct=(Invoke-Cli @('kernel','directory','enum','--root','\KnownDlls','--max-depth','0','--limit','2500','--json') @(0,6))|ConvertFrom-Json
Assert ($direct.data.completeWithinDepth -and $direct.data.scannedDirectoryCount -eq '1' -and [uint64]$direct.data.scannedEntryCount -eq $oracle.Count) 'Independent direct depth-zero view'
foreach($row in $direct.data.entries){Assert ($row.depth -eq 0 -and $oracle[$row.name] -eq $row.type) 'Independent direct child names/types/depth'}
$empty=(Invoke-Cli @('kernel','directory','enum','--root','\KnownDlls','--filter','KswordNoSuchRecursiveItem','--max-depth','0','--json') @(0,6))|ConvertFrom-Json
Assert ($empty.data.completeWithinDepth -and $empty.data.matchedObservedCount -eq '0') 'Complete filtered empty view'
$failed=(Invoke-Cli @('kernel','directory','enum','--root',('\KswordDirectoryMissing-'+[guid]::NewGuid().ToString('N')),'--json') 3)|ConvertFrom-Json
Assert (!$failed.data.sources[0].opened) 'Missing start directory'
Assert ((Invoke-Cli @('kernel','directory','enum','--root','\KnownDlls','--max-depth','0','--limit','1') 6).Contains('source: shared native object-directory breadth-first')) 'Recursive text and display limit'
if($InGuest){
 $root=[CliNamespaceOracle]::Fixture($true)
 try{
  $rootEntries=[CliNamespaceOracle]::Enum($root);$childEntries=[CliNamespaceOracle]::Enum($root+'\ChildDir')
  $result=(Invoke-Cli @('kernel','directory','enum','--root',$root,'--max-depth','1','--json') 0)|ConvertFrom-Json
  Assert ($rootEntries.Count -eq 3 -and $childEntries.Count -eq 1 -and $result.data.scannedDirectoryCount -eq '2' -and $result.data.scannedEntryCount -eq '4' -and $result.data.completeWithinDepth) 'Independent two-directory BFS view'
  $grand=@($result.data.entries|Where-Object {$_.fullPath -eq ($root+'\ChildDir\GrandEvent')})
  Assert ($grand.Count -eq 1 -and $grand[0].depth -eq 1 -and $grand[0].type -eq $childEntries['GrandEvent']) 'Grandchild depth/type, symbolic link not traversed'
  foreach($source in $result.data.sources){Assert ($source.complete -and $source.closed) 'Every traversed directory closed'}
  $shallow=(Invoke-Cli @('kernel','directory','enum','--root',$root,'--max-depth','0','--json') 0)|ConvertFrom-Json
  Assert ($shallow.data.completeWithinDepth -and $shallow.data.scannedEntryCount -eq '3' -and $shallow.data.depthBoundaryDirectoryCount -eq '1') 'Requested depth boundary remains explicit valid scope'
  $filtered=(Invoke-Cli @('kernel','directory','enum','--root',$root,'--max-depth','1','--filter','GrandEvent','--json') 0)|ConvertFrom-Json
  Assert ($filtered.data.returnedCount -eq '1' -and $filtered.data.scannedEntryCount -eq '4') 'Filter does not prune parent traversal'
  $scanned=(Invoke-Cli @('kernel','directory','enum','--root',$root,'--max-scanned-entries','1','--json') 6)|ConvertFrom-Json
  Assert ($scanned.data.limited -and !$scanned.data.completeWithinDepth -and $scanned.data.scannedEntryCount -eq '1') 'Actual traversal entry cap'
  $stored=(Invoke-Cli @('kernel','directory','enum','--root',$root,'--max-rows','1','--json') 6)|ConvertFrom-Json
  Assert ($stored.data.limited -and $stored.data.storedCount -eq '1') 'Backend stored-row cap'
  $truncated=(Invoke-Cli @('kernel','directory','enum','--root',$root,'--limit','1','--json') 6)|ConvertFrom-Json
  Assert ($truncated.data.truncated -and $truncated.data.completeWithinDepth -and $truncated.data.storedCount -eq '4') 'Display limit distinct from complete collection'
 }finally{[CliNamespaceOracle]::Stop()}
}
