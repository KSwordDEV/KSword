$help=Invoke-Cli @('help','security','bam','registry','query')
Assert ($help.Contains('--timeout-ms') -and (Invoke-Cli @('security','bam','registry','query','--help')) -eq $help) 'BAM leaf help'
Assert (!(Invoke-Cli @('security','bam','help')).Contains('--timeout-ms') -and !(Invoke-Cli @('security','ahcache','help')).Contains('--timeout-ms')) 'Both immediate help branches'
foreach($bad in @(@('--duration-ms','499'),@('--timeout-ms','30001'),@('--max-data-bytes','0'),@('--backend','r0'),@('--unknown','1'))){Assert (((Invoke-Cli (@('security','bam','query','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'BAM validation'}
$bam=(Invoke-Cli @('security','bam','registry','query','--json') @(0,5))|ConvertFrom-Json
$d=$bam.data.evidence[0].data;$sdkKnown=$false;$count=$null;$present=$false
try{$present=Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' -ErrorAction Stop;if($present){$count=@(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' -ErrorAction Stop).Count};$sdkKnown=$true}catch{}
if($sdkKnown){Assert ($d.available -and $d.summaryOnly -and $d.present -eq $present -and (($present -and [uint64]$d.userSettingsKeyCount -eq $count) -or (!$present -and $null -eq $d.userSettingsKeyCount))) 'Independent summary-only UserSettings key count/absence'}else{Assert ($bam.status -eq 'unsupported' -and !$d.available) 'Actual BAM summary permission/unavailability'}
$amcache=(Invoke-Cli @('security','ahcache','amcache','query','--json') @(0,5))|ConvertFrom-Json
$d=$amcache.data.evidence[0].data;$path=Join-Path $env:windir 'AppCompat\Programs\Amcache.hve';$file=$null;try{$file=Get-Item -LiteralPath $path -ErrorAction Stop}catch{}
if($file){Assert ($d.available -and $d.summaryOnly -and $d.present -and $d.path -eq $path -and [uint64]$d.lengthBytes -eq $file.Length -and $d.lastWriteUtc -eq $file.LastWriteTimeUtc.ToString('o')) 'Independent Amcache file metadata, no hive read'}else{Assert (($d.available -and $d.summaryOnly -and !$d.present -and $null -eq $d.lengthBytes) -or (!$d.available -and $amcache.status -eq 'unsupported')) 'Unavailable vs missing file stays explicit'}
$keys=(Invoke-Cli @('security','ahcache','registry','query','--json') @(0,6))|ConvertFrom-Json
Assert ($keys.data.evidence[0].data.summaryOnly -and $keys.data.evidence[0].data.keys.Count -eq 2) 'Existing two cache-key presence summaries'
foreach($key in $keys.data.evidence[0].data.keys){if($key.known){Assert ($key.present -eq (Test-Path -LiteralPath $key.path)) 'Independent cache-key presence'}}
foreach($family in @('bam','ahcache')){
 $service=(Invoke-Cli @('security',$family,'service','query','--json') 0)|ConvertFrom-Json
 $data=$service.data.evidence[0].data;$sdk=Get-Service -Name $family -ErrorAction SilentlyContinue
 Assert ($data.name -eq $family -and $data.scmClosed -and (($sdk -and $data.available -and $data.state -eq [int]$sdk.Status) -or (!$sdk -and $data.absent -and $null -eq $data.state))) 'Independent cache driver registration/status'
 $all=(Invoke-Cli @('security',$family,'query','--json') @(0,6))|ConvertFrom-Json
 $expected=if($family -eq 'bam'){'2'}else{'3'};Assert ($all.data.requestedCount -eq $expected -and $all.data.returnedCount -eq $expected) 'Every existing summary source selected'
}
Assert ((Invoke-Cli @('security','bam','service','query')).Contains('source: shared security read-only probes')) 'Cache summary text'
