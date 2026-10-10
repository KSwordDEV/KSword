$help=Invoke-Cli @('help','system','event-log','query')
Assert ($help.Contains('--messages') -and (Invoke-Cli @('system','event-log','query','--help')) -eq $help) 'Event log leaf help'
Assert (!(Invoke-Cli @('system','event-log','help')).Contains('--messages')) 'Event log intermediate help'
foreach($bad in @(
 @('system','event-log','query','--channel','security','--json'),
 @('system','event-log','query','--level','verbose','--json'),
 @('system','event-log','query','--messages','yes','--json'),
 @('system','event-log','query','--limit','0','--json'),
 @('system','event-log','query','--limit','5001','--json'),
 @('system','event-log','query','--duration-ms','99','--json'),
 @('system','event-log','query','--backend','r0','--json'),
 @('system','event-log','query','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Event log parameters'}
$actual=(Invoke-Cli @('system','event-log','query','--limit','3','--json') @(0,6))|ConvertFrom-Json
Assert ($actual.data.pageComplete -and $actual.data.closeFailedCount -eq '0' -and $actual.data.returnedCount -eq '3') 'Actual complete newest System page'
foreach($row in $actual.data.events){
 $oracle=Get-WinEvent -LogName System -FilterXPath "*[System[EventRecordID=$($row.recordId)]]" -MaxEvents 1 -ErrorAction Stop
 Assert ($row.providerName -eq $oracle.ProviderName -and $row.eventId -eq $oracle.Id -and [uint64]$row.recordId -eq $oracle.RecordId -and [uint64]$row.timestampFileTime -eq $oracle.TimeCreated.ToUniversalTime().ToFileTimeUtc()) 'Independent Event Log SDK identity/time/descriptor'
 if($row.fields.headerPid.available){Assert ($row.headerPid -eq $oracle.ProcessId) 'Event log recording-context PID'}
 Assert (!$row.messageRequested -and $null -eq $row.message) 'Metadata mode does not fabricate descriptions'
}
Assert ((Invoke-Cli @('system','event-log','query','--limit','1') @(0,6)).Contains('source: Windows Event Log')) 'Event log text output'
if($InGuest){
 $source='KswordCliR3-'+[guid]::NewGuid().ToString('N');$message='KSword event fixture "'+[char]0x4e2d+[char]0x6587+[char]::ConvertFromUtf32(0x1f642)+"`r`nsecond line"
 try{
  [Diagnostics.EventLog]::CreateEventSource($source,'Application')
  [Diagnostics.EventLog]::WriteEntry($source,$message,[Diagnostics.EventLogEntryType]::Information,321)
  $oracle=Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName=$source} -MaxEvents 1 -ErrorAction Stop
  $metadata=(Invoke-Cli @('system','event-log','query','--channel','application','--level','information','--limit','100','--json') @(0,6))|ConvertFrom-Json
  $matches=@($metadata.data.events|Where-Object {$_.providerName -eq $source -and [uint64]$_.recordId -eq $oracle.RecordId})
  Assert ($metadata.data.pageComplete -and $matches.Count -eq 1 -and $matches[0].eventId -eq 321) 'Independent self-created Application event'
  foreach($row in $metadata.data.events){Assert ($row.level -eq 0 -or $row.level -eq 4) 'Information filter exact raw levels'}
  $formatted=(Invoke-Cli @('system','event-log','query','--channel','application','--level','information','--messages','on','--limit','100','--json') @(0,6))|ConvertFrom-Json
  $matches=@($formatted.data.events|Where-Object {$_.providerName -eq $source -and [uint64]$_.recordId -eq $oracle.RecordId})
  Assert ($matches.Count -eq 1 -and $matches[0].messageRequested) 'Owned fixture message request'
  if($matches[0].messageAvailable){Assert ($matches[0].message.Contains($message) -and !$matches[0].messageMalformed) 'Actual uncollapsed Unicode/multiline message'}else{Assert ($formatted.status -eq 'partial' -and $null -eq $matches[0].message) 'Missing message resource is partial and null'}
  Assert ($formatted.data.closeFailedCount -eq '0' -and [uint64]$formatted.data.closeAttemptedCount -ge ([uint64]$formatted.data.returnedCount+2)) 'All query/context/event/publisher handles closed'
 }finally{if([Diagnostics.EventLog]::SourceExists($source)){[Diagnostics.EventLog]::DeleteEventSource($source)}}
}
