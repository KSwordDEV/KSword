$help=Invoke-Cli @('help','process','enum')
Assert ($help.Contains('--backend r3') -and $help.Contains('Default/R0 syntax:') -and $help.Contains('--flags')) 'Both R3 and compatible R0 help'
Assert ((Invoke-Cli @('process','enum','--help')) -eq $help) 'Process inline help'
foreach ($bad in @(
    @('process','enum','--backend','bad','--json'),
    @('process','enum','--backend','r3','--flags','0','--json'),
    @('process','enum','--backend','r3','--pid','-1','--json'),
    @('process','enum','--backend','r3','--limit','4294967296','--json'),
    @('process','enum','--backend','r3','--unknown','1','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Process enum parameters'}
$self=(Invoke-Cli @('process','enum','--backend','r3','--pid',$PID.ToString(),'--json'))|ConvertFrom-Json
$oracle=Get-Process -Id $PID
Assert ($self.data.complete -and $self.data.processes.Count -eq 1 -and $self.data.processes[0].pid -eq $PID -and $self.data.processes[0].creationTime -eq $oracle.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()) 'Independent process creation identity'
Assert ($self.data.processes[0].path -eq $oracle.Path -and $self.data.processes[0].sessionId -eq $oracle.SessionId -and $self.data.processes[0].basePriority -eq $oracle.BasePriority) 'Independent image path and session'
Assert ($self.data.processes[0].nameSource -eq 'native-snapshot' -and $self.data.processes[0].kernelTime100ns -match '^\d+$' -and $self.data.processes[0].workingSetBytes -match '^\d+$') 'Typed native counters'
$empty=(Invoke-Cli @('process','enum','--backend','r3','--name','KSwordDoesNotExist-984112.exe','--json'))|ConvertFrom-Json
Assert ($empty.data.matchedCount -eq 0 -and $empty.data.processes.Count -eq 0) 'Valid empty process filter'
$idle=(Invoke-Cli @('process','enum','--backend','r3','--pid','0','--json') 6)|ConvertFrom-Json
Assert ($idle.data.processes[0].pid -eq 0 -and $null -eq $idle.data.processes[0].path -and $idle.data.processes[0].pathWin32Error -eq 50) 'Idle path limitation is explicit'
Assert ((Invoke-Cli @('process','enum','--backend','r3','--pid',$PID.ToString())).Contains('source: NtQuerySystemInformation')) 'Process text output'
if ($InGuest) {
    $target=Start-Process -FilePath "$env:WINDIR\System32\notepad.exe" -PassThru
    try {
        $target.Refresh();$creation=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        $row=(Invoke-Cli @('process','enum','--backend','r3','--pid',$target.Id.ToString(),'--json'))|ConvertFrom-Json
        Assert ($row.data.processes[0].name -eq 'notepad.exe' -and $row.data.processes[0].creationTime -eq $creation) 'Owned live process identity'
        $pidText=$target.Id.ToString();$target.Kill();$target.WaitForExit()
        $gone=(Invoke-Cli @('process','enum','--backend','r3','--pid',$pidText,'--json'))|ConvertFrom-Json
        Assert ($gone.data.matchedCount -eq 0) 'Exited owned process is absent'
    } finally {if (!$target.HasExited) {$target.Kill();$target.WaitForExit()};$target.Dispose()}
}
