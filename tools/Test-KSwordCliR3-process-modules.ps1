$paths=@(@('process','module','enum'),@('process','module','unload'),@('process','module','thread','suspend'),@('process','module','thread','resume'),@('process','module','thread','terminate'))
foreach($path in $paths) {
    $help=Invoke-Cli (@('help')+$path)
    Assert ($help.Contains('--pid') -and (Invoke-Cli ($path+@('--help'))) -eq $help) 'Module leaf help'
    Assert (((Invoke-Cli ($path+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'Module missing parameters'
}
Assert (!(Invoke-Cli @('process','module','help')).Contains('--thread-creation-time')) 'Module group lists direct children only'
Assert (!(Invoke-Cli @('help','process','module','thread')).Contains('--thread-creation-time')) 'Module thread hierarchy'
foreach($bad in @(
    @('process','module','enum','--pid',$PID.ToString(),'--backend','r0','--json'),
    @('process','module','enum','--pid',$PID.ToString(),'--bad','1','--json'),
    @('process','module','enum','--pid',$PID.ToString(),'--limit','0','--json'),
    @('process','module','enum','--pid',$PID.ToString(),'--creation-time','0','--json'),
    @('process','module','unload','--pid','0','--base','0','--confirm','--json'),
    @('process','module','thread','suspend','--pid','0','--base','1','--tid','0','--thread-creation-time','1','--confirm','--json'),
    @('process','module','unload','--pid',$PID.ToString(),'--base','1','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Module parameter rejection'}
$oracle=Get-Process -Id $PID;$born=$oracle.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$result=(Invoke-Cli @('process','module','enum','--pid',$PID.ToString(),'--creation-time',$born,'--json') @(0,6))|ConvertFrom-Json
Assert ($result.data.enumeration.complete -and $result.data.returnedCount -gt 0 -and $result.data.target.creationTime -eq $born) 'Actual module snapshot identity'
$oracle.Refresh()
foreach($row in $result.data.modules) {
    if($row.infoEvidence.available -and $row.pathEvidence.available) {
        $actual=@($oracle.Modules|Where-Object {('0x{0:X}' -f $_.BaseAddress.ToInt64()) -eq $row.base})
        if($actual.Count) {Assert ($row.imageSize -eq $actual[0].ModuleMemorySize -and (Get-Item $row.path).FullName -eq (Get-Item $actual[0].FileName).FullName) 'Independent module base size and path'}
    } else {if(!$row.infoEvidence.available){Assert ($null -eq $row.base -and $null -eq $row.imageSize) 'Unknown module metadata is null'};if(!$row.pathEvidence.available){Assert ($null -eq $row.path) 'Unknown module path is null'}}
}
$limited=(Invoke-Cli @('process','module','enum','--pid',$PID.ToString(),'--limit','1','--json') 6)|ConvertFrom-Json
Assert ($limited.data.truncated -and $limited.data.returnedCount -eq 1) 'Limited module enumeration'
Assert (((Invoke-Cli @('process','module','enum','--pid',$PID.ToString(),'--name','KswordImpossibleModule-98392.dll','--json') @(0,6))|ConvertFrom-Json).data.returnedCount -eq 0) 'Valid empty module filter'
Assert (((Invoke-Cli @('process','module','enum','--pid',$PID.ToString(),'--creation-time',([uint64]$born+1).ToString(),'--json') 3)|ConvertFrom-Json).status -eq 'failed') 'Module process identity mismatch'
Assert ((Invoke-Cli @('process','module','enum','--pid',$PID.ToString()) @(0,6)).Contains('modules:')) 'Module text output'
if($InGuest) {
    $root=Join-Path $env:TEMP ('KswordCliModules-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null
    $path=Join-Path $root 'state.json';$directory=Split-Path -Parent $Cli;$dll=Join-Path $directory 'R3ModuleFixture.dll'
    $target=Start-Process (Join-Path $directory 'R3Fixture.exe') -ArgumentList @('--modules',(Quote-CliArgument $path),(Quote-CliArgument $dll)) -PassThru
    try {
        for($i=0;$i -lt 50 -and !(Test-Path -LiteralPath $path);$i++){Start-Sleep -Milliseconds 100}
        function Read-ModuleWorker {for($i=0;$i -lt 20;$i++){try{return (Get-Content -LiteralPath $path -Raw -ErrorAction Stop)|ConvertFrom-Json}catch{Start-Sleep -Milliseconds 20}};throw 'Module fixture state unavailable'}
        $worker=Read-ModuleWorker;$creation=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        $guard=@('--pid',$target.Id.ToString(),'--creation-time',$creation,'--base',$worker.base)
        $modules=(Invoke-Cli (@('process','module','enum')+$guard+@('--json')))|ConvertFrom-Json
        $module=$modules.data.modules[0]
        Assert ($modules.data.returnedCount -eq 1 -and $module.name -eq 'R3ModuleFixture.dll' -and $module.representativeThread.tid -eq $worker.tid -and $module.representativeThread.creationTime -eq $worker.creationTime) 'Native fixture module and associated thread'
        $identity=$guard+@('--module-path',$module.path,'--image-size',$module.imageSize.ToString())
        $bad=(Invoke-Cli (@('process','module','unload')+$guard+@('--module-path','C:\KswordWrong.dll','--confirm','--json')) 3)|ConvertFrom-Json
        Assert ($bad.status -eq 'failed' -and (Read-ModuleWorker).modulePresent) 'Module path mismatch performs no unload'
        $bad=(Invoke-Cli @('process','module','unload','--pid',$target.Id.ToString(),'--creation-time',([uint64]$creation+1).ToString(),'--base',$worker.base,'--confirm','--json') 3)|ConvertFrom-Json
        Assert ($bad.status -eq 'failed' -and (Read-ModuleWorker).modulePresent) 'Process mismatch performs no unload'
        $threadGuard=$identity+@('--tid',$worker.tid.ToString(),'--thread-creation-time',$worker.creationTime)
        $bad=(Invoke-Cli @('process','module','thread','suspend','--pid',$target.Id.ToString(),'--base',$worker.base,'--tid',$worker.tid.ToString(),'--thread-creation-time',([uint64]$worker.creationTime+1).ToString(),'--confirm','--json') 3)|ConvertFrom-Json
        Assert ($bad.status -eq 'failed') 'Module thread mismatch'
        $suspend=(Invoke-Cli (@('process','module','thread','suspend')+$threadGuard+@('--confirm','--json')))|ConvertFrom-Json
        Assert ($suspend.data.threadAction.verified -and $suspend.data.threadAction.observed.after.count -eq 1) 'Module thread suspend readback'
        Start-Sleep -Milliseconds 250;$a=Read-ModuleWorker;Start-Sleep -Milliseconds 500;$b=Read-ModuleWorker;Assert ($a.counter -eq $b.counter) 'Module worker independently stopped'
        $resume=(Invoke-Cli (@('process','module','thread','resume')+$threadGuard+@('--confirm','--json')))|ConvertFrom-Json
        Start-Sleep -Milliseconds 500;$c=Read-ModuleWorker;Assert ($resume.data.threadAction.verified -and [uint64]$c.counter -gt [uint64]$b.counter) 'Module worker independently resumed'
        $terminate=(Invoke-Cli (@('process','module','thread','terminate')+$threadGuard+@('--confirm','--json')))|ConvertFrom-Json
        Start-Sleep -Milliseconds 300;Assert ($terminate.data.threadAction.verified -and $terminate.data.threadAction.observed.exitCode -eq 0 -and (Read-ModuleWorker).exitCode -eq 0) 'Module thread actual exit code zero'
        $remaining=(Invoke-Cli (@('process','module','unload')+$identity+@('--confirm','--json')) 6)|ConvertFrom-Json
        $target.Refresh();Assert ($remaining.data.requestSucceeded -and !$remaining.data.verified -and $remaining.data.observed.basePresent -and @($target.Modules|Where-Object {$_.ModuleName -eq 'R3ModuleFixture.dll'}).Count -eq 1 -and (Read-ModuleWorker).modulePresent) 'FreeLibrary succeeds but remaining reference is partial'
        $unloaded=(Invoke-Cli (@('process','module','unload')+$identity+@('--confirm','--json')))|ConvertFrom-Json
        Start-Sleep -Milliseconds 300;$target.Refresh()
        Assert ($unloaded.data.verified -and !$unloaded.data.observed.basePresent -and @($target.Modules|Where-Object {$_.ModuleName -eq 'R3ModuleFixture.dll'}).Count -eq 0 -and !(Read-ModuleWorker).modulePresent) 'Final reference unloaded with independent module absence'
        Assert (((Invoke-Cli (@('process','module','unload')+$identity+@('--confirm','--json')) 3)|ConvertFrom-Json).status -eq 'failed') 'Absent module cannot be unloaded again'
        $target.Kill();$target.WaitForExit()
        Assert (((Invoke-Cli @('process','module','enum','--pid',$target.Id.ToString(),'--creation-time',$creation,'--json') 3)|ConvertFrom-Json).status -eq 'failed') 'Exited module target rejected'
    } finally {
        if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()
        $absolute=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
        if(!$absolute.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe cleanup root'}
        Remove-Item -LiteralPath $absolute -Recurse -Force
    }
    $x86=Join-Path $env:WINDIR 'SysWOW64\notepad.exe'
    if(Test-Path -LiteralPath $x86) {
        $target=Start-Process $x86 -PassThru
        try {
            $modules=(Invoke-Cli @('process','module','enum','--pid',$target.Id.ToString(),'--name','notepad.exe','--json') @(0,6))|ConvertFrom-Json
            $module=$modules.data.modules[0]
            Assert ($module.base -and $module.path) 'Actual x86 module metadata'
            $unsupported=(Invoke-Cli @('process','module','unload','--pid',$target.Id.ToString(),'--base',$module.base,'--module-path',$module.path,'--confirm','--json') 5)|ConvertFrom-Json
            Assert ($unsupported.status -eq 'unsupported' -and !$unsupported.data.remoteThreadCreated -and !$target.HasExited) 'Cross-bitness unload rejected before remote execution'
        } finally {if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()}
    }
}
