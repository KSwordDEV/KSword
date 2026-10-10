$help=Invoke-Cli @('help','process','detail','basic','query')
Assert ($help.Contains('--creation-time') -and (Invoke-Cli @('process','detail','basic','query','--help')) -eq $help) 'Basic leaf help'
Assert (!(Invoke-Cli @('process','detail','basic','help')).Contains('--creation-time')) 'Basic group shows direct leaf only'
$parent=Invoke-Cli @('help','process','detail')
Assert ($parent.Contains('process detail basic') -and $parent.Contains('KswordCLI.exe process detail --pid')) 'Legacy detail and basic child coexist'
foreach ($bad in @(
    @('process','detail','basic','query','--json'),
    @('process','detail','basic','query','--pid',$PID.ToString(),'--backend','r0','--json'),
    @('process','detail','basic','query','--pid',$PID.ToString(),'--unknown','1','--json'),
    @('process','detail','basic','query','--pid',$PID.ToString(),'--creation-time','0','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Basic parameter rejection'}
$oracle=Get-Process -Id $PID
$creation=$oracle.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$self=(Invoke-Cli @('process','detail','basic','query','--pid',$PID.ToString(),'--creation-time',$creation,'--json') @(0,6))|ConvertFrom-Json
Assert ($self.data.target.creationTime -eq $creation -and $self.data.availableCount -ge 16 -and $self.data.requestedCount -eq 19) 'Basic identity and availability'
$map=@{}; foreach ($row in $self.data.fields) {$map[$row.name]=$row;if (!$row.available) {Assert ($null -eq $row.value) 'Unavailable basic values are null'}}
$cim=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
Assert ($map['creation-time'].value -eq $creation -and $map['parent-pid'].value -eq $cim.ParentProcessId -and $map['session'].value -eq $oracle.SessionId) 'Independent basic identity fields'
Assert ((Get-Item $map['image-path'].value).FullName -eq (Get-Item $oracle.Path).FullName -and $map['name'].value -eq ([IO.Path]::GetFileName($oracle.Path))) 'Independent image identity'
Assert ($map['user'].value -eq [Security.Principal.WindowsIdentity]::GetCurrent().Name -and $map['command-line'].value -eq $cim.CommandLine) 'Independent token user and raw command line'
$admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Assert ($map['elevated'].value -eq $admin -and $map['priority-class'].value -eq [uint32]$oracle.PriorityClass) 'Independent elevation and priority class'
Assert ($map['peb'].available -and $map['peb'].value -match '^0x[0-9A-Fa-f]+$' -and $map['affinity'].value -eq ('0x{0:X}' -f $oracle.ProcessorAffinity.ToInt64())) 'PEB and independent process affinity'
Assert ($map['working-set'].value -match '^\d+$' -and [uint64]$map['working-set'].value -gt 0 -and $map['io-bytes'].available) 'Typed memory and I/O counters'
$mismatch=(Invoke-Cli @('process','detail','basic','query','--pid',$PID.ToString(),'--creation-time',([uint64]$creation+1).ToString(),'--json') 3)|ConvertFrom-Json
Assert (!$mismatch.data.target.identityMatched) 'Basic identity mismatch'
Assert ((Invoke-Cli @('process','detail','basic','query','--pid',$PID.ToString()) @(0,6)).Contains('availableCount:')) 'Basic text output'
Assert (((Invoke-Cli @('process','detail','basic','query','--pid','0','--json') 3)|ConvertFrom-Json).status -eq 'failed') 'System target cannot be opened'
if ($InGuest) {
    $target=Start-Process "$env:WINDIR\System32\notepad.exe" -PassThru
    try {
        $born=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        $result=(Invoke-Cli @('process','detail','basic','query','--pid',$target.Id.ToString(),'--creation-time',$born,'--json') @(0,6))|ConvertFrom-Json
        Assert ($result.data.availableCount -ge 16 -and $result.data.target.creationTime -eq $born) 'Disposable target basic fields'
        $pidText=$target.Id.ToString();$target.Kill();$target.WaitForExit()
        Assert (((Invoke-Cli @('process','detail','basic','query','--pid',$pidText,'--creation-time',$born,'--json') 3)|ConvertFrom-Json).status -eq 'failed') 'Exited target rejected'
    } finally {if (!$target.HasExited) {$target.Kill();$target.WaitForExit()};$target.Dispose()}
}
