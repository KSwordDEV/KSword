$help=Invoke-Cli @('help','file','directory','enum')
Assert ($help.Contains('--path') -and $help.Contains('FILETIME')) 'Directory leaf help'
Assert ((Invoke-Cli @('file','directory','enum','--help')) -eq $help) 'Directory inline help'
Assert ((Invoke-Cli @('file','directory','help')).Contains('drives') -and !(Invoke-Cli @('help','file','directory')).Contains('--path')) 'Directory intermediate help'
foreach ($bad in @(
    @('file','directory','enum','--json'),
    @('file','directory','enum','--path','C:\*','--json'),
    @('file','directory','enum','--path','C:\','--kind','bogus','--json'),
    @('file','directory','enum','--path','C:\','--limit','-1','--json'),
    @('file','directory','enum','--path','C:\','--backend','r0','--json'),
    @('file','directory','enum','--path','C:\','--unknown','1','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Directory parameter JSON'}
$drives=(Invoke-Cli @('file','directory','drives','enum','--json'))|ConvertFrom-Json
$oracle=[IO.Directory]::GetLogicalDrives()
Assert ($drives.data.complete -and $drives.data.virtualDriveRoot -and $drives.data.totalCount -eq $oracle.Count) 'Logical drive count'
foreach ($entry in $drives.data.entries) {Assert ($oracle -contains $entry.path -and $entry.kind -eq 'drive' -and $null -eq $entry.sizeBytes) 'Drive identity'}
Assert ((Invoke-Cli @('file','directory','enum','--path',$env:WINDIR,'--limit','1')).Contains('returnedCount: 1')) 'Directory text'
if ($InGuest) {
    $root=Join-Path $env:TEMP ('KSwordCliDirectory-'+[Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($root)|Out-Null
    $denied=$null;$acl=$null;$rule=$null
    try {
        [IO.Directory]::CreateDirectory((Join-Path $root 'empty'))|Out-Null
        $file=Join-Path $root '中文 ☃ data.txt'
        [IO.File]::WriteAllBytes($file,[byte[]]@(0,255,34,92,11))
        [IO.File]::SetAttributes($file,[IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::ReadOnly)
        $result=(Invoke-Cli @('file','directory','enum','--path',($root.Replace('\','/')+'/'),'--json'))|ConvertFrom-Json
        Assert ($result.data.path -eq $root -and $result.data.totalCount -eq 2 -and $result.data.complete) 'Normalized path and immediate children'
        $actual=@($result.data.entries|Where-Object kind -eq 'file')[0];$info=[IO.FileInfo]::new($file)
        Assert ((Get-Item -LiteralPath $actual.path -Force).FullName -eq $info.FullName -and $actual.sizeBytes -eq $info.Length.ToString() -and $actual.lastWriteFileTime -eq $info.LastWriteTimeUtc.ToFileTimeUtc().ToString()) ("Independent file metadata: actual="+($actual|ConvertTo-Json -Compress)+" oracle="+$info.FullName+" size="+$info.Length+" time="+$info.LastWriteTimeUtc.ToFileTimeUtc())
        Assert ($actual.attributeText.Contains('H') -and $actual.attributeText.Contains('R') -and !$actual.reparsePoint) 'File attributes'
        $only=(Invoke-Cli @('file','directory','enum','--path',$root,'--kind','directory','--limit','1','--json'))|ConvertFrom-Json
        Assert ($only.data.totalCount -eq 2 -and $only.data.matchedCount -eq 1 -and $only.data.entries[0].name -eq 'empty') 'Directory kind filter'
        $empty=(Invoke-Cli @('file','directory','enum','--path',(Join-Path $root 'empty'),'--json'))|ConvertFrom-Json
        Assert ($empty.data.complete -and $empty.data.totalCount -eq 0) 'Empty directory success'
        $missing=(Invoke-Cli @('file','directory','enum','--path',(Join-Path $root 'missing'),'--json') 3)|ConvertFrom-Json
        Assert (!$missing.data.complete -and $missing.data.win32Error -eq 3) 'Missing directory status'
        $denied=Join-Path $root 'denied';[IO.Directory]::CreateDirectory($denied)|Out-Null
        $acl=Get-Acl -LiteralPath $denied
        $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.AccessControl.FileSystemRights]::ListDirectory,[Security.AccessControl.AccessControlType]::Deny)
        $acl.AddAccessRule($rule);Set-Acl -LiteralPath $denied -AclObject $acl
        $denial=(Invoke-Cli @('file','directory','enum','--path',$denied,'--json') 3)|ConvertFrom-Json
        Assert ($denial.data.win32Error -eq 5 -and $denial.data.entries.Count -eq 0) 'Denied directory status'
    } finally {
        if ($rule) {$acl.RemoveAccessRuleSpecific($rule);Set-Acl -LiteralPath $denied -AclObject $acl}
        if (Test-Path -LiteralPath $file) {[IO.File]::SetAttributes($file,[IO.FileAttributes]::Normal)}
        $resolved=[IO.Path]::GetFullPath($root);Assert ($resolved.StartsWith([IO.Path]::GetFullPath($env:TEMP)+'\')) 'Fixture cleanup stays within TEMP'
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
