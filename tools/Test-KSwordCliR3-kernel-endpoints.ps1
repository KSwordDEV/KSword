$help=Invoke-Cli @('help','kernel','endpoints','enum')
Assert ($help.Contains('--max-depth') -and (Invoke-Cli @('kernel','endpoints','enum','--help')) -eq $help) 'Endpoint leaf help'
Assert (!(Invoke-Cli @('kernel','endpoints','help')).Contains('--max-depth')) 'Endpoint immediate help'
foreach($bad in @(@('--root','relative'),@('--max-depth','33'),@('--max-rows','0'),@('--max-scanned-entries','0'),@('--max-entries','0'),@('--duration-ms','99'),@('--limit','2501'),@('--backend','r0'),@('--unknown','1'))){Assert (((Invoke-Cli (@('kernel','endpoints','enum','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'Endpoint validation'}
. "$PSScriptRoot\KswordCliR3NamespaceOracle.ps1"
$types=@('ALPC Port','Port','WaitCompletionPacket','TpWorkerFactory','Event','Section','Mutant','Semaphore','IoCompletion','Timer','Job','Keyed Event')
$oracle=[CliNamespaceOracle]::Enum('\KnownDlls')
$direct=(Invoke-Cli @('kernel','endpoints','enum','--root','\KnownDlls','--max-depth','0','--limit','2500','--json') @(0,6))|ConvertFrom-Json
Assert ($direct.data.completeWithinDepth -and [uint64]$direct.data.scannedEntryCount -eq $oracle.Count -and [uint64]$direct.data.storedCount -eq @($oracle.Values|Where-Object {$_ -in $types}).Count) 'Independent endpoint type selection'
foreach($row in $direct.data.entries){Assert ($row.type -in $types -and $oracle[$row.name] -eq $row.type -and !$row.openAttempted -and $null -eq $row.basic.handleCount) 'No unsupported communication object opener/count inference'}
$missing=(Invoke-Cli @('kernel','endpoints','enum','--root',('\KswordMissing-'+[guid]::NewGuid().ToString('N')),'--json') 3)|ConvertFrom-Json
Assert (!$missing.data.sources[0].opened) 'Missing endpoint root failure'
Assert ((Invoke-Cli @('kernel','endpoints','enum','--root','\KnownDlls','--max-depth','0') @(0,6)).Contains('source: shared named communication types')) 'Endpoint text'
$empty=(Invoke-Cli @('kernel','endpoints','enum','--root','\KnownDlls','--filter','KswordMissingEndpoint','--json') @(0,6))|ConvertFrom-Json
Assert ($empty.data.matchedObservedCount -eq '0') 'Filtered endpoint empty'
if($InGuest){
 $root=[CliNamespaceOracle]::Fixture($true)
 try{
  $own=(Invoke-Cli @('kernel','endpoints','enum','--root',$root,'--json') 0)|ConvertFrom-Json
  Assert ($own.data.scannedDirectoryCount -eq '2' -and $own.data.scannedEntryCount -eq '4' -and $own.data.storedCount -eq '2') 'Real two-directory communication view'
  Assert (@($own.data.entries|Where-Object {$_.type -ne 'Event'}).Count -eq 0 -and @($own.data.entries|Where-Object {$_.name -eq 'GrandEvent' -and $_.depth -eq 1}).Count -eq 1) 'Directory traversed but not emitted, symlink not followed'
  $filtered=(Invoke-Cli @('kernel','endpoints','enum','--root',$root,'--filter','GrandEvent','--json') 0)|ConvertFrom-Json
  Assert ($filtered.data.returnedCount -eq '1' -and $filtered.data.scannedEntryCount -eq '4') 'Endpoint filter does not prune parents'
  $stored=(Invoke-Cli @('kernel','endpoints','enum','--root',$root,'--max-rows','1','--json') 6)|ConvertFrom-Json
  Assert ($stored.data.limited -and $stored.data.storedCount -eq '1') 'Actual retained endpoint cap'
  $shown=(Invoke-Cli @('kernel','endpoints','enum','--root',$root,'--limit','1','--json') 6)|ConvertFrom-Json
  Assert ($shown.data.truncated -and $shown.data.completeWithinDepth -and $shown.data.storedCount -eq '2') 'Only output truncated'
 }finally{[CliNamespaceOracle]::Stop()}
}
