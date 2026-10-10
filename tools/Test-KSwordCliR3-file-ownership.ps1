foreach ($path in @(@('file','ownership','take'),@('file','locks','query'))) {
    $help=Invoke-Cli (@('help')+$path)
    Assert ($help.Contains('--path') -and (Invoke-Cli ($path+@('--help'))) -eq $help) 'Ownership leaf help'
    Assert (((Invoke-Cli ($path+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'Missing ownership parameters'
}
Assert (!(Invoke-Cli @('help','file','ownership')).Contains('--confirm')) 'Ownership help depth'
foreach ($bad in @(
    @('file','ownership','take','--path','C:\missing','--json'),
    @('file','locks','query','--path','C:\missing','--backend','r0','--json'),
    @('file','locks','query','--path','C:\missing','--unknown','1','--json'),
    @('file','locks','query','--path','C:\missing','--pid','-1','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Ownership parameters'}
if ($InGuest) {
    $root=Join-Path $env:TEMP ('KSwordCliOwnership-'+[Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($root)|Out-Null;$file=Join-Path $root 'fixture.bin';[IO.File]::WriteAllBytes($file,[byte[]]@(1,2,3))
    $locked=$null
    try {
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $taken=(Invoke-Cli @('file','ownership','take','--path',$file,'--confirm','--json'))|ConvertFrom-Json
        $oracle=(Get-Acl -LiteralPath $file).GetOwner([Security.Principal.SecurityIdentifier]).Value
        Assert ($taken.data.verified -and $taken.data.after.sid -eq $identity -and $oracle -eq $identity) 'Independent file owner SID'
        $folder=Invoke-Cli @('file','ownership','take','--path',$root,'--confirm')
        Assert ($folder.Contains('verified: true') -and (Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $identity) 'Directory ownership and text'
        $missing=(Invoke-Cli @('file','ownership','take','--path',(Join-Path $root 'missing'),'--confirm','--json') 3)|ConvertFrom-Json
        Assert ($missing.data.win32Error -eq 2 -and !$missing.data.verified) 'Ownership failure preserves status'
        $empty=(Invoke-Cli @('file','locks','query','--path',$file,'--json'))|ConvertFrom-Json
        Assert ($empty.data.totalCount -eq 0 -and $empty.data.target.present) 'No visible lockers is a valid empty result'
        $locked=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $holders=(Invoke-Cli @('file','locks','query','--path',$file,'--pid',$PID.ToString(),'--json'))|ConvertFrom-Json
        Assert ($holders.data.matchedCount -eq 1 -and $holders.data.processes[0].pid -eq $PID -and $holders.data.target.present) 'Actual current process file lock'
        Assert ($holders.data.processes[0].creationTime -eq (Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()) 'Independent locker creation identity'
        $readOnly=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        # The independent conflicting open must fail while the CLI remains read-only.
        if ($readOnly) {$readOnly.Dispose();throw 'Unexpected exclusive open during lock'}
    } catch [IO.IOException] {
        Assert ($locked -ne $null) 'Only independent conflicting-open failure is expected'
        $text=Invoke-Cli @('file','locks','query','--path',$file,'--limit','1')
        Assert ($text.Contains('Restart Manager')) 'Locker text'
        $locked.Dispose();$locked=$null
        $released=(Invoke-Cli @('file','locks','query','--path',$file,'--json'))|ConvertFrom-Json
        Assert ($released.data.totalCount -eq 0) 'Independent release is reflected'
    } finally {
        if ($locked) {$locked.Dispose()}
        $resolved=[IO.Path]::GetFullPath($root);Assert ($resolved.StartsWith([IO.Path]::GetFullPath($env:TEMP)+'\')) 'Ownership fixture cleanup stays within TEMP'
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
