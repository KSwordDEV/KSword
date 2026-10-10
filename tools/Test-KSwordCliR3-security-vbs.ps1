$help=Invoke-Cli @('help','security','vbs','hvci','query')
Assert ($help.Contains('--timeout-ms') -and (Invoke-Cli @('security','vbs','hvci','query','--help')) -eq $help) 'VBS leaf help'
Assert (!(Invoke-Cli @('security','vbs','help')).Contains('--timeout-ms')) 'VBS immediate help'
foreach($bad in @(@('--duration-ms','499'),@('--timeout-ms','30001'),@('--max-data-bytes','0'),@('--backend','r0'),@('--unknown','1'))){Assert (((Invoke-Cli (@('security','vbs','query','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'VBS validation'}
$files=(Invoke-Cli @('security','vbs','files','enum','--json') @(0,6))|ConvertFrom-Json
Assert ($files.data.evidence[0].data.files.Count -eq 3 -and $files.data.evidence[0].capture.waitCompleted) 'Existing three disk-file observations'
foreach($file in $files.data.evidence[0].data.files){if($file.known){Assert ($file.path -eq (Join-Path $env:windir ('System32\'+$file.name)) -and $file.present -eq (Test-Path -LiteralPath $file.path -PathType Leaf)) 'Independent disk existence, no active-module inference'}}
$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
try{foreach($leaf in @('hvci','registry')){
 $query=(Invoke-Cli @('security','vbs',$leaf,'query','--json') @(0,6))|ConvertFrom-Json
 Assert ($query.data.returnedCount -eq '3') 'Existing three configuration values per group'
 foreach($row in $query.data.evidence){$data=$row.data;$key=$base.OpenSubKey($data.path.Substring(5));try{$value=if($key){$key.GetValue($data.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}else{$null};if($null -eq $value){Assert ($data.absent -and $null -eq $data.value) 'Independent known absence, not default disabled'}else{Assert ($data.available -and $data.value -eq $value -and $data.closed) 'Independent configured value and closure'}}finally{if($key){$key.Dispose()}}}
}}finally{$base.Dispose()}
$dg=$null;try{$dg=Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop}catch{}
$cim=(Invoke-Cli @('security','vbs','device-guard','query','--json') @(0,5,6))|ConvertFrom-Json
if($dg){Assert ($cim.data.evidence[0].data.available -and $cim.data.evidence[0].data.virtualizationBasedSecurityStatus -eq $dg.VirtualizationBasedSecurityStatus -and ($cim.data.evidence[0].data.securityServicesRunning -join ',') -eq ($dg.SecurityServicesRunning -join ',')) 'Independent VBS current reported status/running properties'}else{Assert ($cim.status -eq 'unsupported' -and !$cim.data.evidence[0].data.available) 'Actual CIM unavailable source'}
$all=(Invoke-Cli @('security','vbs','query','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.requestedCount -eq '8' -and $all.data.returnedCount -eq '8' -and !$all.data.limited) 'All eight existing R3 observations'
Assert ((Invoke-Cli @('security','vbs','hvci','query') @(0,6)).Contains('source: shared security read-only probes')) 'VBS text'
