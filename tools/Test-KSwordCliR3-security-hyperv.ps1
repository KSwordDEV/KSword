$help=Invoke-Cli @('help','security','hyperv','features','enum')
Assert ($help.Contains('--timeout-ms') -and (Invoke-Cli @('security','hyperv','features','enum','--help')) -eq $help) 'Hypervisor leaf help'
Assert (!(Invoke-Cli @('security','hyperv','help')).Contains('--timeout-ms')) 'Hypervisor immediate help'
foreach($bad in @(@('--duration-ms','499'),@('--timeout-ms','30001'),@('--max-data-bytes','0'),@('--backend','r0'),@('--unknown','1'))){Assert (((Invoke-Cli (@('security','hyperv','query','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'Hypervisor validation'}
$sdk=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
$computer=(Invoke-Cli @('security','hyperv','computer-system','query','--json') 0)|ConvertFrom-Json
$data=$computer.data.evidence[0].data
Assert ($data.available -and $data.hypervisorPresent -eq $sdk.HypervisorPresent -and $data.manufacturer -eq $sdk.Manufacturer -and $data.model -eq $sdk.Model) 'Independent generic hypervisor/manufacturer/model, no vendor inference'
$services=(Invoke-Cli @('security','hyperv','services','query','--json') 0)|ConvertFrom-Json
Assert ($services.data.returnedCount -eq '4') 'Existing four service observations'
foreach($row in $services.data.evidence){$s=$row.data;$oracle=Get-Service -Name $s.name -ErrorAction SilentlyContinue;Assert ($s.scmClosed -and (($oracle -and $s.available -and $s.state -eq [int]$oracle.Status) -or (!$oracle -and $s.absent -and $null -eq $s.state))) 'Independent SCM state/known absence'}
$registry=(Invoke-Cli @('security','hyperv','registry','query','--json') @(0,6))|ConvertFrom-Json
$reg=$registry.data.evidence[0].data
$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$null
try{$key=$base.OpenSubKey('SYSTEM\CurrentControlSet\Control\DeviceGuard');$value=if($key){$key.GetValue('HypervisorEnforcedCodeIntegrity',$null)}else{$null};Assert (($null -eq $value -and $reg.absent -and $null -eq $reg.value) -or ($null -ne $value -and $reg.available -and $reg.value -eq $value)) 'Exact DeviceGuard config observation, not BCD launch type'}finally{if($key){$key.Dispose()};$base.Dispose()}
$oracle=@(Get-CimInstance Win32_PnPEntity -ErrorAction Stop|Where-Object {$_.Name -match 'Hyper-V|VMBus|vmbus|Virtual Switch|vEthernet|HvSocket'})
$devices=(Invoke-Cli @('security','hyperv','devices','enum','--json') @(0,6))|ConvertFrom-Json
$d=$devices.data.evidence[0].data
Assert ($d.available -and [uint64]$d.matchedCount -eq $oracle.Count -and $d.devices.Count -le 40) 'Independent existing PnP candidate filter/count'
foreach($row in $d.devices){Assert (@($oracle|Where-Object {$_.DeviceID -eq $row.deviceId -and $_.PNPClass -eq $row.pnpClass -and $_.Status -eq $row.status}).Count -gt 0) 'Independent PnP DeviceID/class/status (display name may be localized by helper runtime)'}
$features=(Invoke-Cli @('security','hyperv','features','enum','--timeout-ms','30000','--duration-ms','60000','--json') @(0,5,6))|ConvertFrom-Json
$f=$features.data.evidence[0].data
Assert ($f.features.Count -eq 4) 'Four optional features with per-item availability'
foreach($row in $f.features){$item=$null;try{$item=Get-WindowsOptionalFeature -Online -FeatureName $row.name -ErrorAction Stop}catch{};if($item){Assert ($row.available -and $row.state -eq $item.State.ToString() -and $row.stateId -eq [int]$item.State) 'Independent optional feature registration/state'}else{Assert (!$row.available -and $null -eq $row.state) 'Unavailable feature/permission is not Disabled'}}
$all=(Invoke-Cli @('security','hyperv','query','--timeout-ms','30000','--duration-ms','60000','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.requestedCount -eq '8' -and $all.data.returnedCount -eq '8' -and !$all.data.limited) 'All eight existing sources'
Assert ((Invoke-Cli @('security','hyperv','services','query')).Contains('source: shared security read-only probes')) 'Hypervisor text'
