$help=Invoke-Cli @('help','security','ci','device-guard','query')
Assert ($help.Contains('--timeout-ms') -and (Invoke-Cli @('security','ci','device-guard','query','--help')) -eq $help) 'CI leaf help'
Assert ((Invoke-Cli @('help')).Contains('security') -and !(Invoke-Cli @('security','help')).Contains('--timeout-ms')) 'Security top/immediate help'
Assert (!(Invoke-Cli @('security','ci','help')).Contains('--max-data-bytes')) 'CI immediate help'
foreach($bad in @(@('--duration-ms','499'),@('--timeout-ms','499'),@('--max-data-bytes','0'),@('--backend','r0'),@('--unknown','1'))){Assert (((Invoke-Cli (@('security','ci','query','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'CI parameter validation'}
$policy=(Invoke-Cli @('security','ci','policy-files','enum','--json') @(0,6))|ConvertFrom-Json
$capture=$policy.data.evidence[0].capture
Assert ($capture.started -and $capture.waitCompleted -and $capture.exitCodeKnown -and !$capture.outputTruncated -and !$capture.decodeMalformed) 'Real helper execution/decoding/closure evidence'
foreach($row in $policy.data.evidence[0].data.directories){Assert ($row.path.StartsWith($env:windir,[StringComparison]::OrdinalIgnoreCase)) 'Actual Windows paths, not literal env variable';if($row.known){$exists=Test-Path -LiteralPath $row.path;Assert ($row.present -eq $exists) 'Independent policy directory availability';if($exists){Assert ([uint64]$row.fileCount -eq @(Get-ChildItem -LiteralPath $row.path -File).Count) 'Independent CI disk file count'}else{Assert ($null -eq $row.fileCount) 'Missing directory count is null'}}}
$registry=(Invoke-Cli @('security','ci','registry','query','--json') @(0,6))|ConvertFrom-Json
Assert ($registry.data.returnedCount -eq '3') 'All existing CI/cache registry probes'
$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
try{foreach($row in $registry.data.evidence){$v=$row.data;$key=$base.OpenSubKey($v.path.Substring(5));try{$value=if($key){$key.GetValue($v.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}else{$null};if($null -eq $value){Assert ($v.absent -and $null -eq $v.value) 'Independent known registry absence, no disabled inference'}else{Assert ($v.available -and $v.value -eq $value -and $v.closed) 'Independent CI/cache registry scalar/closure'}}finally{if($key){$key.Dispose()}}}}finally{$base.Dispose()}
$service=(Invoke-Cli @('security','ci','service','query','--json') 0)|ConvertFrom-Json
$sdk=Get-Service -Name CI -ErrorAction SilentlyContinue;$s=$service.data.evidence[0].data
Assert ($s.scmClosed -and (($sdk -and $s.available -and $s.state -eq [int]$sdk.Status) -or (!$sdk -and $s.absent -and $null -eq $s.state))) 'Independent CI SCM state/absence and manager closure'
$dg=$null;try{$dg=Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop}catch{}
$cim=(Invoke-Cli @('security','ci','device-guard','query','--json') @(0,5,6))|ConvertFrom-Json
if($dg){$data=$cim.data.evidence[0].data;Assert ($data.available -and $data.codeIntegrityPolicyEnforcementStatus -eq $dg.CodeIntegrityPolicyEnforcementStatus -and $data.usermodeCodeIntegrityPolicyEnforcementStatus -eq $dg.UsermodeCodeIntegrityPolicyEnforcementStatus) 'Independent CIM CI policy fields'}else{Assert ($cim.status -eq 'unsupported' -and !$cim.data.evidence[0].data.available) 'Actual unavailable CIM source with structured error'}
$all=(Invoke-Cli @('security','ci','query','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.requestedCount -eq '6' -and $all.data.returnedCount -eq '6' -and !$all.data.limited) 'Existing six sources, independent limitations retained'
Assert ((Invoke-Cli @('security','ci','registry','query') @(0,6)).Contains('source: shared security read-only probes')) 'CI text output'
if($InGuest){
 $limited=(Invoke-Cli @('security','ci','query','--duration-ms','500','--timeout-ms','500','--json') @(3,6))|ConvertFrom-Json
 Assert ($limited.data.limited -or @($limited.data.evidence|Where-Object {$_.capture.timedOut}).Count -gt 0) 'Actual bounded helper timeout/collection budget'
}
