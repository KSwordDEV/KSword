$help=Invoke-Cli @('help','process','detail','fields','query')
Assert ($help.Contains('--creation-time') -and (Invoke-Cli @('process','detail','fields','query','--help')) -eq $help) 'Process fields leaf help'
$parent=Invoke-Cli @('help','process','detail')
Assert ($parent.Contains('KswordCLI.exe process detail --pid') -and $parent.Contains('process detail fields') -and !$parent.Contains('--fields')) 'Existing detail entry and new direct child'
Assert (!(Invoke-Cli @('process','detail','fields','help')).Contains('--fields')) 'Fields group does not list leaf parameters'
$names=(Invoke-Cli @('process','detail','fields','list','--json'))|ConvertFrom-Json
Assert ($names.data.fields.Count -gt 30 -and $names.data.fields -contains 'dep' -and $names.data.fields -contains 'enterprise' -and $names.data.fields -notcontains 'eprocess') 'Discoverable field names'
foreach ($bad in @(
    @('process','detail','fields','query','--json'),
    @('process','detail','fields','query','--pid',$PID.ToString(),'--backend','r0','--json'),
    @('process','detail','fields','query','--pid',$PID.ToString(),'--bad','1','--json'),
    @('process','detail','fields','query','--pid',$PID.ToString(),'--fields','bad','--json'),
    @('process','detail','fields','query','--pid',$PID.ToString(),'--fields','user,user','--json'),
    @('process','detail','fields','query','--pid',$PID.ToString(),'--fields','user,','--json'),
    @('process','detail','fields','query','--pid',$PID.ToString(),'--creation-time','0','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Fields parameter rejection'}
$creation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$query=(Invoke-Cli @('process','detail','fields','query','--pid',$PID.ToString(),'--creation-time',$creation,'--json'))|ConvertFrom-Json
Assert ($query.data.target.identityMatched -and $query.data.target.creationTime -eq $creation -and $query.data.availableCount -eq 4) 'Default fields and retained process identity'
$map=@{};foreach ($f in $query.data.fields) {$map[$f.name]=$f}
$oracle=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
Assert ($map['command-line'].value -eq $oracle.CommandLine.Replace("`r"," ").Replace("`n"," ").Trim() -and $map['user'].value -eq [Security.Principal.WindowsIdentity]::GetCurrent().Name -and $map['architecture'].value -eq 'x64') 'Independent command line user and architecture'
$admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Assert ($map['elevated'].value -eq $admin) 'Independent token elevation'
$all=(Invoke-Cli @('process','detail','fields','query','--pid',$PID.ToString(),'--fields','all','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.requestedCount -eq $names.data.fields.Count -and $all.data.availableCount -gt 0) 'All fields are represented'
foreach ($f in $all.data.fields) {if (!$f.available) {Assert ($null -eq $f.value) 'Unavailable fields are null'} }
$mismatch=(Invoke-Cli @('process','detail','fields','query','--pid',$PID.ToString(),'--creation-time',([uint64]$creation+1).ToString(),'--json') 3)|ConvertFrom-Json
Assert (!$mismatch.data.target.identityMatched -and $mismatch.data.target.creationTime -eq $creation) 'Explicit creation identity mismatch'
Assert ((Invoke-Cli @('process','detail','fields','query','--pid',$PID.ToString(),'--fields','user')).Contains('availableCount: 1')) 'Fields text output'
if ($InGuest) {
    $target=Start-Process -FilePath "$env:WINDIR\System32\notepad.exe" -PassThru
    try {
        $born=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        $row=(Invoke-Cli @('process','detail','fields','query','--pid',$target.Id.ToString(),'--creation-time',$born,'--fields','path,package,dep,cfg,job,dpi','--json') @(0,6))|ConvertFrom-Json
        Assert ($row.data.target.creationTime -eq $born -and $row.data.availableCount -ge 4) 'Owned process on-demand fields'
        $resultMap=@{};foreach ($f in $row.data.fields) {$resultMap[$f.name]=$f}
        Assert ($resultMap['path'].value -eq $target.Path -and $resultMap['package'].available -and $resultMap['package'].value -eq '' -and $resultMap['job'].available) 'Actual path empty package and known job state'
        $gpu=(Invoke-Cli @('process','detail','fields','query','--pid',$target.Id.ToString(),'--fields','gpu,gpu-dedicated-memory,gpu-shared-memory','--json') @(0,5,6))|ConvertFrom-Json
        foreach ($f in $gpu.data.fields) {if (!$f.available) {Assert ($null -eq $f.value) 'Absent GPU is not a measured zero'} }
        $targetText=$target.Id.ToString();$target.Kill();$target.WaitForExit()
        $gone=(Invoke-Cli @('process','detail','fields','query','--pid',$targetText,'--creation-time',$born,'--json') 3)|ConvertFrom-Json
        Assert ($gone.status -eq 'failed') 'Exited process fields fail'
    } finally {if (!$target.HasExited) {$target.Kill();$target.WaitForExit()};$target.Dispose()}
}
