$help=Invoke-Cli @('help','kernel','base-named-objects','enum')
Assert ($help.Contains('--session-id') -and (Invoke-Cli @('kernel','base-named-objects','enum','--help')) -eq $help) 'Named object leaf help'
Assert (!(Invoke-Cli @('kernel','base-named-objects','help')).Contains('--session-id')) 'Named object immediate help'
foreach($bad in @(
 @('--scope','session'),@('--scope','global','--session-id','0'),@('--scope','invalid'),
 @('--scope','session','--session-id','4294967296'),@('--limit','0'),@('--max-entries','0'),
 @('--duration-ms','99'),@('--backend','r0'),@('--unknown','1')
)){Assert (((Invoke-Cli (@('kernel','base-named-objects','enum','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'Named object validation'}
. "$PSScriptRoot\KswordCliR3NamespaceOracle.ps1"
$sid=[Diagnostics.Process]::GetCurrentProcess().SessionId
foreach($selection in @(@('--scope','global'),@('--scope','session','--session-id',"$sid"))){
 $root=if($selection[1] -eq 'global'){'\BaseNamedObjects'}else{'\Sessions\'+$sid+'\BaseNamedObjects'}
 $status=[CliNamespaceOracle]::OpenStatus($root)
 $result=(Invoke-Cli (@('kernel','base-named-objects','enum','--limit','100000','--json')+$selection) @(0,3,6))|ConvertFrom-Json
 if($status -ne 0){Assert ($result.status -eq 'failed' -and $result.data.sources[0].openNtStatus -eq ('0x'+$status.ToString('x'))) 'Independent session/global directory failure';continue}
 $oracle=[CliNamespaceOracle]::Enum($root)
 Assert ($result.data.sources[0].complete -and [uint64]$result.data.enumeratedCount -eq $result.data.objects.Count -and $result.data.sources[0].closed) 'Named object directory completeness/count/closure'
 $common=0
 foreach($row in $result.data.objects){if($oracle.ContainsKey($row.name)){$common++;Assert ($oracle[$row.name] -eq $row.type -and $row.parentPath -eq $root) 'Independent named object type/name'}}
 Assert ($result.data.objects.Count -eq 0 -or $common -gt 0) 'Independent non-atomic snapshots share real object registrations'
}
$missing=(Invoke-Cli @('kernel','base-named-objects','enum','--scope','session','--session-id','4294967295','--json') 3)|ConvertFrom-Json
Assert (!$missing.data.sources[0].opened -and $missing.data.returnedCount -eq '0') 'Missing session is failed, not valid empty'
$all=(Invoke-Cli @('kernel','base-named-objects','enum','--limit','1','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.currentSessionKnown -and $all.data.roots -contains '\BaseNamedObjects' -and $null -ne $all.data.sessionDiscovery) 'All roots carry session discovery'
Assert ((Invoke-Cli @('kernel','base-named-objects','enum','--scope','global','--limit','1') @(0,3,6)).Contains('source: shared BaseNamedObjects')) 'Named object text'
if($InGuest){
 $root=[CliNamespaceOracle]::Fixture()
 try{
  $name=$root.Substring($root.LastIndexOf('\')+1)
  $own=(Invoke-Cli @('kernel','base-named-objects','enum','--scope','global','--filter',$name,'--json') 0)|ConvertFrom-Json
  Assert ($own.data.matchedCount -eq '1' -and $own.data.objects[0].fullPath -eq $root -and $own.data.objects[0].type -eq 'Directory') 'Real own global registration'
  $budget=(Invoke-Cli @('kernel','base-named-objects','enum','--scope','global','--max-entries','1','--json') 6)|ConvertFrom-Json
  Assert ($budget.data.limited -and !$budget.data.sources[0].complete) 'Actual named object read budget'
 }finally{[CliNamespaceOracle]::Stop()}
 $gone=(Invoke-Cli @('kernel','base-named-objects','enum','--scope','global','--filter',$name,'--json') 0)|ConvertFrom-Json
 Assert ($gone.data.matchedCount -eq '0') 'Registration disappears after owned handles close'
}
