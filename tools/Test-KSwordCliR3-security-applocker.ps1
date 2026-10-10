$help=Invoke-Cli @('help','security','applocker','policy','query')
Assert ($help.Contains('--timeout-ms') -and (Invoke-Cli @('security','applocker','policy','query','--help')) -eq $help) 'AppLocker leaf help'
Assert (!(Invoke-Cli @('security','applocker','help')).Contains('--timeout-ms')) 'AppLocker immediate help'
foreach($bad in @(@('--duration-ms','499'),@('--timeout-ms','30001'),@('--max-data-bytes','0'),@('--backend','r0'),@('--unknown','1'))){Assert (((Invoke-Cli (@('security','applocker','query','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'AppLocker validation'}
$policy=$null;try{$policy=Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop}catch{}
$result=(Invoke-Cli @('security','applocker','policy','query','--json') @(0,5))|ConvertFrom-Json
if($policy){$xml=[xml]$policy;$count=0;$collections=@($xml.AppLockerPolicy.RuleCollection|Where-Object {$null -ne $_});foreach($collection in $collections){$count+=@($collection.ChildNodes|Where-Object {$_.LocalName -in @('FilePathRule','FilePublisherRule','FileHashRule')}).Count};$p=$result.data.evidence[0].data;Assert ($p.available -and $p.summaryOnly -and [uint64]$p.collectionCount -eq $collections.Count -and [uint64]$p.ruleCount -eq $count) 'Independent effective policy actual rule elements'}else{Assert ($result.status -eq 'unsupported' -and !$result.data.evidence[0].data.available) 'Actual effective policy unavailable'}
$sdk=Get-Service AppIDSvc -ErrorAction Stop
$service=(Invoke-Cli @('security','applocker','service','query','--json') 0)|ConvertFrom-Json
$s=$service.data.evidence[0].data
Assert ($s.name -eq $sdk.Name -and $s.stateId -eq [int]$sdk.Status -and $s.startTypeId -eq [int]$sdk.StartType) 'Independent AppIDSvc status/start configuration'
$logs=(Invoke-Cli @('security','applocker','event-log','query','--json') @(0,5,6))|ConvertFrom-Json
Assert ($logs.data.evidence[0].data.logs.Count -eq 3) 'Existing three channel observations'
foreach($row in $logs.data.evidence[0].data.logs){$log=$null;try{$log=Get-WinEvent -ListLog $row.name -ErrorAction Stop}catch{};if($log){Assert ($row.available -and $row.enabled -eq $log.IsEnabled -and ($null -eq $row.recordCount -or [uint64]$row.recordCount -le [uint64]$log.RecordCount)) 'Independent channel metadata (counts can increase between calls)'}else{Assert (!$row.available -and $null -eq $row.enabled -and $null -eq $row.recordCount) 'Channel unavailable fields stay null'}}
$drivers=(Invoke-Cli @('security','applocker','drivers','query','--json') 0)|ConvertFrom-Json
Assert ($drivers.data.returnedCount -eq '3') 'Existing three driver registrations'
foreach($row in $drivers.data.evidence){$s=$row.data;$sdk=Get-Service -Name $s.name -ErrorAction SilentlyContinue;Assert ($s.scmClosed -and (($sdk -and $s.available -and $s.state -eq [int]$sdk.Status) -or (!$sdk -and $s.absent -and $null -eq $s.state))) 'Independent driver service state/absence'}
$reg=(Invoke-Cli @('security','applocker','registry','query','--json') @(0,6))|ConvertFrom-Json
$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$null
try{$key=$base.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers');$value=if($key){$key.GetValue('DefaultLevel',$null)}else{$null};$v=$reg.data.evidence[0].data;Assert (($null -eq $value -and $v.absent -and $null -eq $v.value) -or ($null -ne $value -and $v.value -eq $value)) 'Independent configured SRP scalar/absence'}finally{if($key){$key.Dispose()};$base.Dispose()}
$all=(Invoke-Cli @('security','applocker','query','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.requestedCount -eq '7' -and $all.data.returnedCount -eq '7' -and !$all.data.limited) 'All existing seven sources'
Assert ((Invoke-Cli @('security','applocker','drivers','query')).Contains('source: shared security read-only probes')) 'AppLocker text'
