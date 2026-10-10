foreach ($path in @(@('file','create'),@('file','directory','create'),@('file','copy'),@('file','move'),@('file','rename'),@('file','delete'),@('file','directory','delete'),@('file','path','short','query'),@('file','shortcut','query'))) {
    $help=Invoke-Cli (@('help')+$path)
    Assert ($help.Contains('r3') -and (Invoke-Cli ($path+@('--help'))) -eq $help) 'File operation help'
    Assert (((Invoke-Cli ($path+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'Missing file operation parameters'
}
foreach ($bad in @(
    @('file','delete','--path','C:\missing','--json'),
    @('file','create','--directory','C:\','--confirm','--backend','r0','--json'),
    @('file','create','--directory','C:\','--confirm','--typo','1','--json'),
    @('file','shortcut','query','--path','C:\sample.txt','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'File operation parameter rejection'}
Assert (!(Invoke-Cli @('help','file','directory')).Contains('--confirm')) 'Directory group does not expand action options'
if ($InGuest) {
    $root=Join-Path $env:TEMP ('KSwordCliFiles-'+[Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($root)|Out-Null
    $locked=$null
    $vhd=$null
    try {
        $create=(Invoke-Cli @('file','create','--directory',$root,'--confirm','--json'))|ConvertFrom-Json
        $duplicate=(Invoke-Cli @('file','create','--directory',$root,'--confirm','--json'))|ConvertFrom-Json
        Assert ($create.data.verified -and [IO.File]::Exists($create.data.target) -and ([IO.FileInfo]::new($create.data.target)).Length -eq 0) 'Created empty file'
        Assert ($duplicate.data.target -ne $create.data.target -and $duplicate.data.errorCode -eq 0 -and [IO.File]::Exists($duplicate.data.target)) 'Collision-safe creation and cleared error'
        $directory=(Invoke-Cli @('file','directory','create','--directory',$root,'--confirm','--json'))|ConvertFrom-Json
        Assert ($directory.data.verified -and [IO.Directory]::Exists($directory.data.target)) 'Created directory'
        $source=Join-Path $root 'source 中文.bin';$content=[byte[]]@(0,255,34,92,33,44)
        [IO.File]::WriteAllBytes($source,$content)
        $copy=(Invoke-Cli @('file','copy','--path',$source,'--to-directory',$directory.data.target,'--confirm','--json'))|ConvertFrom-Json
        Assert ($copy.data.verified -and [IO.File]::Exists($source) -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($copy.data.target)) -eq [Convert]::ToBase64String($content)) 'Copy exact contents and retain source'
        [IO.File]::WriteAllBytes($source,[byte[]]@(1,2,3))
        $overwrite=(Invoke-Cli @('file','copy','--path',$source,'--to-directory',$directory.data.target,'--confirm','--json'))|ConvertFrom-Json
        Assert (([IO.FileInfo]::new($overwrite.data.target)).Length -eq 3 -and $overwrite.data.verified) 'Copy overwrite behavior'
        $moveFolder=Join-Path $root 'move target';[IO.Directory]::CreateDirectory($moveFolder)|Out-Null
        $move=(Invoke-Cli @('file','move','--path',$source,'--to-directory',$moveFolder,'--confirm','--json'))|ConvertFrom-Json
        Assert ($move.data.verified -and ![IO.File]::Exists($source) -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($move.data.target)) -eq 'AQID') 'Move contents and source removal'
        $renamed=Join-Path $root 'renamed 中文.bin'
        $rename=(Invoke-Cli @('file','rename','--path',$move.data.target,'--target',$renamed,'--confirm','--json'))|ConvertFrom-Json
        Assert ($rename.data.verified -and ![IO.File]::Exists($move.data.target) -and [IO.File]::Exists($renamed)) 'Rename final path evidence'
        $short=(Invoke-Cli @('file','path','short','query','--path',$renamed,'--json'))|ConvertFrom-Json
        Assert ([IO.File]::Exists($short.data.result) -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($short.data.result)) -eq 'AQID') 'Short path addresses same file'
        $lnk=Join-Path $root 'fixture.lnk';$shell=New-Object -ComObject WScript.Shell
        try {$link=$shell.CreateShortcut($lnk);$link.TargetPath=$renamed;$link.Save();$expected=$link.TargetPath}
        finally {if($link){[Runtime.InteropServices.Marshal]::ReleaseComObject($link)|Out-Null};[Runtime.InteropServices.Marshal]::ReleaseComObject($shell)|Out-Null}
        $target=(Invoke-Cli @('file','shortcut','query','--path',$lnk,'--json'))|ConvertFrom-Json
        Assert ($target.data.result -eq $expected -and $target.data.hresult -eq '0x0') 'Independent shortcut target'
        $tree=Join-Path $root 'tree';[IO.Directory]::CreateDirectory((Join-Path $tree 'sub'))|Out-Null
        [IO.File]::WriteAllBytes((Join-Path $tree 'sub\nested.bin'),$content)
        $recursive=(Invoke-Cli @('file','copy','--path',$tree,'--to-directory',$directory.data.target,'--confirm','--json'))|ConvertFrom-Json
        Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $recursive.data.target 'sub\nested.bin'))) -eq [Convert]::ToBase64String($content)) 'Recursive directory copy'
        $nonempty=(Invoke-Cli @('file','directory','delete','--path',$tree,'--confirm','--json') 3)|ConvertFrom-Json
        Assert ($nonempty.data.errorCode -eq 145 -and [IO.Directory]::Exists($tree)) 'Nonempty directory deletion fails'
        $locked=[IO.File]::Open($renamed,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $denied=(Invoke-Cli @('file','delete','--path',$renamed,'--confirm','--json') 3)|ConvertFrom-Json
        Assert ($denied.data.errorCode -eq 32 -and [IO.File]::Exists($renamed)) 'Locked file failure retains source'
        $locked.Dispose();$locked=$null
        $deleted=Invoke-Cli @('file','delete','--path',$renamed,'--confirm')
        Assert ($deleted.Contains('verified: true') -and ![IO.File]::Exists($renamed)) 'Text mutation and independent deletion'
        $alias=(Invoke-Cli @('file','delete-path','--path',$duplicate.data.target,'--confirm','--backend','r3','--json'))|ConvertFrom-Json
        Assert ($alias.data.verified -and ![IO.File]::Exists($duplicate.data.target)) 'Explicit R3 delete-path alias'
        $emptyFolder=Join-Path $root 'to delete';[IO.Directory]::CreateDirectory($emptyFolder)|Out-Null
        $emptyDeleted=(Invoke-Cli @('file','directory','delete','--path',$emptyFolder,'--confirm','--json'))|ConvertFrom-Json
        Assert ($emptyDeleted.data.verified -and ![IO.Directory]::Exists($emptyFolder)) 'Empty directory deletion'
        $missing=(Invoke-Cli @('file','create','--directory',(Join-Path $root 'missing'),'--confirm','--json') 3)|ConvertFrom-Json
        Assert ($missing.data.errorCode -eq 3 -and !$missing.data.requestSucceeded) 'Creation preserves raw failure'
        $sourceMissing=(Invoke-Cli @('file','copy','--path',(Join-Path $root 'missing-file'),'--to-directory',$root,'--confirm','--json') 3)|ConvertFrom-Json
        Assert ($sourceMissing.data.errorCode -ne 0 -and !$sourceMissing.data.verified) 'Copy missing source failure'
        # A disposable VHD supplies a real second volume for fallback and for
        # copy-success/source-delete-failure evidence, without host mutations.
        $letter=@('Z','Y','X','W','V','U','T')|Where-Object {![IO.Directory]::Exists($_+':\')}|Select-Object -First 1
        Assert ($null -ne $letter) 'A free guest drive letter is required'
        $vhd=Join-Path $root 'transfer.vhd';$diskScript=Join-Path $root 'disk-create.txt'
        @("create vdisk file=`"$vhd`" maximum=64 type=expandable","select vdisk file=`"$vhd`"",'attach vdisk','create partition primary','format fs=ntfs quick',"assign letter=$letter")|Set-Content -LiteralPath $diskScript -Encoding ASCII
        & diskpart.exe /s $diskScript | Out-Null
        $volume=$letter+':\';Assert ([IO.Directory]::Exists($volume)) 'Guest disposable VHD mounted'
        $cross=Join-Path $root 'cross-volume';[IO.Directory]::CreateDirectory($cross)|Out-Null;[IO.File]::WriteAllBytes((Join-Path $cross 'data.bin'),$content)
        $transferred=(Invoke-Cli @('file','move','--path',$cross,'--to-directory',$volume,'--confirm','--json'))|ConvertFrom-Json
        Assert ($transferred.data.verified -and $transferred.data.copyCompleted -and $transferred.data.sourceRemoved -and ![IO.Directory]::Exists($cross)) 'Cross-volume fallback completes'
        Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $transferred.data.target 'data.bin'))) -eq [Convert]::ToBase64String($content)) 'Cross-volume exact copied bytes'
        $partialSource=Join-Path $root 'locked-cross-volume';[IO.Directory]::CreateDirectory($partialSource)|Out-Null;$partialFile=Join-Path $partialSource 'data.bin';[IO.File]::WriteAllBytes($partialFile,$content)
        $locked=[IO.File]::Open($partialFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $partial=(Invoke-Cli @('file','move','--path',$partialSource,'--to-directory',$volume,'--confirm','--json') 6)|ConvertFrom-Json
        Assert ($partial.status -eq 'partial' -and $partial.data.partial -and !$partial.data.requestSucceeded -and $partial.data.copyCompleted -and !$partial.data.sourceRemoved) 'Copy completed but source removal failed'
        Assert ($partial.data.errorCode -ne 0 -and [IO.File]::Exists($partialFile) -and [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $partial.data.target 'data.bin'))) -eq [Convert]::ToBase64String($content)) 'Partial move preserves both actual paths and bytes'
    } finally {
        if ($locked) {$locked.Dispose()}
        if ($vhd -and [IO.File]::Exists($vhd)) {
            $detach=Join-Path $root 'disk-detach.txt'
            @("select vdisk file=`"$vhd`"",'detach vdisk')|Set-Content -LiteralPath $detach -Encoding ASCII
            & diskpart.exe /s $detach | Out-Null
        }
        $resolved=[IO.Path]::GetFullPath($root);Assert ($resolved.StartsWith([IO.Path]::GetFullPath($env:TEMP)+'\')) 'File fixture cleanup stays within TEMP'
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
