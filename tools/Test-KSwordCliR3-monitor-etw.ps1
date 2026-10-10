$help=Invoke-Cli @('help','monitor','etw','capture')
Assert ($help.Contains('--duration-ms') -and (Invoke-Cli @('monitor','etw','capture','--help')) -eq $help) 'ETW leaf help'
Assert (!(Invoke-Cli @('monitor','etw','help')).Contains('--duration-ms')) 'ETW direct child help'
foreach($bad in @(
 @('monitor','etw','capture','--duration-ms','99','--json'),
 @('monitor','etw','capture','--duration-ms','120001','--json'),
 @('monitor','etw','capture','--pid','0','--json'),
 @('monitor','etw','capture','--provider','missing-name','--json'),
 @('monitor','etw','capture','--provider','{wrong}','--json'),
 @('monitor','etw','capture','--level','6','--json'),
 @('monitor','etw','capture','--limit','0','--json'),
 @('monitor','etw','capture','--keywords','0xfffffffffffffffff','--json'),
 @('monitor','etw','capture','--backend','r0','--json'),
 @('monitor','etw','capture','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'ETW parameter validation'}
$presets=(Invoke-Cli @('monitor','etw','providers','enum','--json'))|ConvertFrom-Json
Assert ($presets.data.count -eq '34' -and @($presets.data.providers|Where-Object {$_.name -eq 'Microsoft-Windows-Kernel-Process'}).Count -eq 1) 'Shared preset inventory'
Assert ((Invoke-Cli @('monitor','etw','providers','enum')).Contains('source: shared backend ETW provider presets')) 'ETW preset text output'
if($InGuest){
 $root=Join-Path $env:TEMP ('KswordEtw-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null
 $state=Join-Path $root 'state.json';$fixture=Join-Path (Split-Path -Parent $Cli) 'R3Fixture.exe';$target=Start-Process $fixture -ArgumentList @('--etw',(Quote-CliArgument $state)) -PassThru
 function Assert-EtwStopped($Result){
  Assert ($Result.data.sessionStopped -and $Result.data.consumerJoined -and $Result.data.statisticsKnown -and $Result.data.closeAttempted -and $Result.data.processCompleted) 'Real ETW owned session/consumer cleanup'
  $sessions=(& logman query -ets 2>&1|Out-String);Assert (!$sessions.Contains($Result.data.sessionName)) 'Independent logman proves named session absent'
 }
 try{
  $data=$null;for($i=0;$i -lt 80;$i++){Start-Sleep -Milliseconds 100;try{$candidate=Get-Content -LiteralPath $state -Raw -Encoding UTF8|ConvertFrom-Json;if($candidate.pid -eq $target.Id -and $candidate.registerError -eq 0){$data=$candidate;break}}catch{}}
  Assert ($null -ne $data) 'SDK ETW emitter registered'
  $args=@('monitor','etw','capture','--provider',$data.provider,'--duration-ms','1500','--pid',$data.pid.ToString(),'--level','4','--keywords','1','--json')
  $result=(Invoke-Cli $args 0)|ConvertFrom-Json;Assert-EtwStopped $result
  Assert ([uint64]$result.data.returnedCount -gt 0 -and $result.data.enabledProviderCount -eq '1' -and $result.data.eventsLost -eq '0' -and $result.data.droppedFromBufferCount -eq '0') "Real custom provider emitted/consumed headers: $($result.data|ConvertTo-Json -Depth 4 -Compress)"
  foreach($event in $result.data.events){Assert ($event.headerPid -eq $data.pid -and $event.providerGuid -eq $data.provider -and $event.eventId -eq 31000 -and $event.level -eq 4 -and $event.keyword -eq '0x1' -and [uint64]$event.timestampFileTime -gt 130000000000000000) 'Independent emitter identity/descriptor and FILETIME domain'}
  $limited=(Invoke-Cli @('monitor','etw','capture','--provider',$data.provider,'--duration-ms','1000','--limit','1','--json') 6)|ConvertFrom-Json;Assert-EtwStopped $limited
  Assert ($limited.data.returnedCount -eq '1' -and [uint64]$limited.data.droppedFromBufferCount -gt 0 -and $limited.status -eq 'partial') 'Real bounded latest-row buffer retains drop evidence'
  $empty=(Invoke-Cli @('monitor','etw','capture','--provider',$data.provider,'--duration-ms','300','--pid','4294967295','--json') 0)|ConvertFrom-Json;Assert-EtwStopped $empty
  Assert ($empty.data.returnedCount -eq '0' -and [uint64]$empty.data.filteredCount -gt 0) 'Valid empty result by recording-context filter'
  $default=(Invoke-Cli @('monitor','etw','capture','--duration-ms','300','--limit','100000','--json') @(0,3,5,6))|ConvertFrom-Json
  if($default.data.startSucceeded){Assert ($default.data.sessionStopped -and $default.data.consumerJoined) 'Default provider session cleaned even when evidence partial'}
  if($default.status -eq 'success'){Assert (@($default.data.providers|Where-Object {!$_.enabled}).Count -eq 0) 'No provider failure masquerades as full success'}
  $final=Get-Content -LiteralPath $state -Raw -Encoding UTF8|ConvertFrom-Json;Assert ($final.writeError -eq 0 -and [uint64]$final.writes -gt 0) 'Independent SDK EventWrite successes'
 }finally{
  Set-Content -LiteralPath ($state+'.stop') -Value 'stop';if(!$target.WaitForExit(5000)){$target.Kill();$target.WaitForExit();throw 'ETW emitter stop timeout'}
  $final=Get-Content -LiteralPath $state -Raw -Encoding UTF8|ConvertFrom-Json;$fixtureExit=$target.ExitCode;$target.Dispose();Assert ($final.unregistered -and $final.closeError -eq 0) "Independent SDK provider unregistered: exit=$fixtureExit state=$($final|ConvertTo-Json -Compress)"
  $absolute=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\';if(!$absolute.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe ETW fixture cleanup'}
  Remove-Item -LiteralPath $absolute -Recurse -Force
 }
}
