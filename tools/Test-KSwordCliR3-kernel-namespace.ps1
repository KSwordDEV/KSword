$help=Invoke-Cli @('help','kernel','namespace','enum')
Assert ($help.Contains('--root') -and (Invoke-Cli @('kernel','namespace','enum','--help')) -eq $help) 'Namespace leaf help'
Assert (!(Invoke-Cli @('kernel','namespace','help')).Contains('--duration-ms')) 'Namespace immediate child help'
foreach($bad in @(
 @('kernel','namespace','enum','--root','relative','--json'),
 @('kernel','namespace','enum','--max-entries','0','--json'),
 @('kernel','namespace','enum','--duration-ms','99','--json'),
 @('kernel','namespace','enum','--limit','0','--json'),
 @('kernel','namespace','enum','--backend','r0','--json'),
 @('kernel','namespace','enum','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Namespace parameter validation'}
. "$PSScriptRoot\KswordCliR3NamespaceOracle.ps1"
$oracle=[CliNamespaceOracle]::Enum('\KnownDlls')
$known=(Invoke-Cli @('kernel','namespace','enum','--root','\KnownDlls','--limit','100000','--json') @(0,6))|ConvertFrom-Json
Assert ($known.data.sources[0].complete -and $known.data.sources[0].closed -and [uint64]$known.data.enumeratedCount -eq $oracle.Count) 'Independent native KnownDlls enumeration count and root closure'
foreach($row in $known.data.entries){Assert ($oracle.ContainsKey($row.name) -and $oracle[$row.name] -eq $row.type -and $row.parentPath -eq '\KnownDlls') 'Independent native object name/type'}
$empty=(Invoke-Cli @('kernel','namespace','enum','--root','\KnownDlls','--filter','KswordNoSuchItem-44-47','--json') @(0,6))|ConvertFrom-Json
Assert ($empty.data.matchedCount -eq '0' -and $empty.data.sources[0].complete) 'Complete filtered empty result'
$limited=(Invoke-Cli @('kernel','namespace','enum','--root','\KnownDlls','--max-entries','1','--json') 6)|ConvertFrom-Json
Assert ($limited.data.limited -and !$limited.data.sources[0].complete -and $limited.data.enumeratedCount -eq '1') 'Native entry budget and incomplete evidence'
$failed=(Invoke-Cli @('kernel','namespace','enum','--root',('\KswordMissing-'+[guid]::NewGuid().ToString('N')),'--json') 3)|ConvertFrom-Json
Assert (!$failed.data.sources[0].opened -and $failed.data.sources[0].openNtStatus -ne '0x0') 'Selected missing root preserves NTSTATUS'
Assert ((Invoke-Cli @('kernel','namespace','enum','--root','\KnownDlls','--limit','1') 6).Contains('source: shared NtOpenDirectoryObject')) 'Namespace text and output truncation'
if($InGuest){
 $root=[CliNamespaceOracle]::Fixture()
 try{
  $oracle=[CliNamespaceOracle]::Enum($root);$result=(Invoke-Cli @('kernel','namespace','enum','--root',$root,'--json') 0)|ConvertFrom-Json
  Assert ($result.data.enumeratedCount -eq '3' -and $oracle.Count -eq 3 -and $result.data.sources[0].complete) 'Self-created namespace directory children'
  foreach($row in $result.data.entries){Assert ($oracle[$row.name] -eq $row.type) 'Independent fixture type';if($row.metadataProbeSupported){Assert ($row.opened -and $row.basic.available -and $row.basic.ntStatus -eq '0x0' -and [uint64]$row.basic.handleCount -ge 1 -and $row.closed) 'Real directory/link basic metadata and closure'}else{Assert ($null -eq $row.opened -and $null -eq $row.basic.handleCount -and !$row.openAttempted) 'Other types not falsely claimed opened'}}
  $link=@($result.data.entries|Where-Object {$_.name -eq 'FixtureLink'})[0];Assert ($link.symlinkTarget.available -and $link.symlinkTarget.value -eq '\KnownDlls') 'Independent created symbolic link target'
 }finally{[CliNamespaceOracle]::Stop()}
 $gone=(Invoke-Cli @('kernel','namespace','enum','--root',$root,'--json') 3)|ConvertFrom-Json
 Assert (!$gone.data.sources[0].opened) 'Last fixture references close and namespace root disappears'
 $overview=(Invoke-Cli @('kernel','namespace','enum','--limit','1','--json') 6)|ConvertFrom-Json
 Assert ($overview.data.currentSessionKnown -and $overview.data.requestedRootCount -gt 15 -and $overview.data.openedRootCount -gt 0 -and $overview.data.truncated) 'Shared default roots and current-session discovery'
}
