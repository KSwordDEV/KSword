$help=Invoke-Cli @('help','security','bugcheck','environment','query')
Assert ($help.Contains('environmentOnly') -and $help.Contains('no crash history') -and (Invoke-Cli @('security','bugcheck','environment','query','--help')) -eq $help) 'Environment leaf exact fields/limitations/help'
Assert (!(Invoke-Cli @('security','bugcheck','help')).Contains('--timeout-ms')) 'Environment intermediate help'
foreach($bad in @(@('--duration-ms','499'),@('--timeout-ms','30001'),@('--max-data-bytes','0'),@('--backend','r0'),@('--unknown','1'))){Assert (((Invoke-Cli (@('security','bugcheck','query','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'Environment validation'}
$sdk=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
foreach($path in @(@('security','bugcheck','query'),@('security','bugcheck','environment','query'))){
 $query=(Invoke-Cli ($path+@('--json')) 0)|ConvertFrom-Json
 $data=$query.data.evidence[0].data
 Assert ($query.data.requestedCount -eq '1' -and $query.data.returnedCount -eq '1' -and $data.environmentOnly -and $data.available -and $data.manufacturer -eq $sdk.Manufacturer -and $data.model -eq $sdk.Model) 'Independent single manufacturer/model source'
 Assert (@($query.diagnostics|Where-Object {$_ -match 'does not query bugcheck history'}).Count -eq 1 -and !$data.PSObject.Properties['crashDetected']) 'No invented crash/dump capability'
}
Assert ((Invoke-Cli @('security','bugcheck','environment','query')).Contains('source: shared security read-only probes')) 'Environment text'
