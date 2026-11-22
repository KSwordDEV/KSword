param([ValidateSet('Run','Cleanup')][string]$Phase='Run',[ValidateSet('Structure','Stack')][string]$Suite='Structure',[switch]$IncludeLifecycle,[switch]$SavedStack)

# 仅用于已授权两台 VMware 来宾的 CLI 验收；不改变信任、安全策略或原安装文件。
# CLI 必须同目录携带正式 Release 的三份匹配 VC 依赖；PATH 不能覆盖 System32 中的旧版 DLL。
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false) # Windows PowerShell 的原生管道必须按 CLI 实际 UTF-8 解码，避免中文嵌套 JSON 损坏。
$OutputEncoding=[Console]::OutputEncoding # 只作用于本次独立验收 PowerShell，不写系统代码页或持久用户配置。
$base=switch($env:COMPUTERNAME) {
    'DESKTOP-D2161R7' {'C:\Users\Administrator\Desktop\Ksword-nice'}
    'DESKTOP-O83P0R8' {'C:\Users\User\Desktop\Release'}
    default {throw 'This acceptance runner is restricted to the two owned guests.'}
}
$stage=Join-Path $base ("validation\live-$($Suite.ToLowerInvariant())-20261122") # 两套证据分别落到固定独立目录。
$service="KswordLive${Suite}20261122" # 只创建和删除本次独立测试服务。
if($Phase -eq 'Cleanup') {
    if(Get-CimInstance Win32_SystemDriver -Filter "Name='$service'") {throw 'Test service still exists; refusing file cleanup.'}
    $marker=Join-Path $stage 'acceptance-owned.txt'
    if(!(Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $service) {throw 'Missing ownership marker.'}
    if(@(Get-Process LiveKernelDiagnosticVmTarget -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq (Join-Path $stage 'LiveKernelDiagnosticVmTarget.exe')}).Count) {throw 'Owned fixture still running.'}
    Remove-Item -LiteralPath $stage -Recurse -Force
    [pscustomobject]@{cleaned=$true;stage=$stage;serviceAbsent=$true} | ConvertTo-Json
    exit 0
}

$manifest=Get-Content -LiteralPath (Join-Path $stage 'manifest.json') -Raw | ConvertFrom-Json # 宿主冻结的文件哈希。
$events=New-Object Collections.Generic.List[object] # 保留每个真实 CLI 退出码，不用最终成功覆盖早期失败。
$report=[ordered]@{computer=$env:COMPUTERNAME;startedUtc=[DateTime]::UtcNow.ToString('o');success=$false;events=$events}
$created=$false # 没有成功创建时不触碰任何现有服务。
$fixture=$null # 只通过本次 Start-Process 返回的进程句柄等待退出。
$oldPath=$env:PATH # 仅本 PowerShell 进程临时复用原安装内的 VC 运行库。
$installed=@('Ksword5.1.exe','KswordARK.sys','KswordARKDriver\KswordARK.sys')

function Get-InstalledHashes {
    # 输入为上方冻结的原安装路径列表，输出公有哈希；文件不存在也保留状态。
    @(foreach($relative in $installed) {
        $path=Join-Path $base $relative
        [pscustomobject]@{relative=$relative;exists=(Test-Path -LiteralPath $path);hash=$(if(Test-Path -LiteralPath $path){(Get-FileHash -LiteralPath $path).Hash}else{$null})}
    })
}

function Invoke-Sample([string]$Name,[string[]]$Arguments,[int]$Expected=0) {
    # 输入命令数组和期望退出码；保存完整 JSON/错误流，并把实际退出码写入事件清单。
    $output=Join-Path $stage "$Name.json"
    & (Join-Path $stage 'KswordCLI.exe') @Arguments --json 2> (Join-Path $stage "$Name.stderr.txt") | Set-Content -LiteralPath $output -Encoding UTF8
    $code=$LASTEXITCODE
    $events.Add([pscustomobject]@{name=$Name;exitCode=$code;expectedExitCode=$Expected;arguments=$Arguments;receipt="$Name.json"})
    if($code -ne $Expected) {throw "$Name returned $code; expected $Expected"}
    return (Get-Content -LiteralPath $output -Raw | ConvertFrom-Json)
}

function Assert-RawIdentityRejection([string]$Name,[uint32]$Kind,[uint32]$ProcessId,[uint32]$ThreadId,[uint64]$ProcessTime,[uint64]$ThreadTime) {
    # 按共享头第一版顺序序列化身份包；没有地址、成员偏移或读取范围输入。
    $stream=New-Object IO.MemoryStream
    $writer=New-Object IO.BinaryWriter($stream)
    foreach($value in @([uint32]1,$Kind,$ProcessId,$ThreadId)) {$writer.Write([uint32]$value)}
    $writer.Write($ProcessTime)
    $writer.Write($ThreadTime)
    1..4 | ForEach-Object {$writer.Write([uint32]0)}
    $hex=[BitConverter]::ToString($stream.ToArray()).Replace('-','')
    $writer.Dispose()
    $stream.Dispose()
    $packet=Invoke-Sample $Name @('system','ioctl','call','--code',"$($manifest.sampleIoctlCode)",'--input-hex',$hex,'--output-bytes','9344','--confirm')
    $bytes=New-Object byte[] ($packet.data.outputHex.Length/2)
    for($i=0;$i -lt $bytes.Length;$i++) {$bytes[$i]=[Convert]::ToByte($packet.data.outputHex.Substring(2*$i,2),16)}
    if($bytes.Length -ne 9344 -or [BitConverter]::ToUInt32($bytes,8) -ne 6 -or
       [BitConverter]::ToUInt32($bytes,44) -ne 0 -or [BitConverter]::ToUInt64($bytes,64) -ne 0) {throw "$Name did not return an empty identity-mismatch receipt"}
    if(@($bytes[128..9343] | Where-Object {$_ -ne 0}).Count) {throw "$Name exposed validity bits or object bytes"}
}

try {
    if(!(Test-Path -LiteralPath (Join-Path $stage 'acceptance-owned.txt'))) {throw 'Missing acceptance ownership marker.'}
    $report.originalBefore=Get-InstalledHashes
    $active=@(Get-CimInstance Win32_SystemDriver | Where-Object {$_.State -eq 'Running' -and ($_.Name -match '^Ksword' -or $_.PathName -match 'KswordARK')})
    if($active.Count) {throw 'Another KSword driver is running; no service was stopped.'}
    if(Get-CimInstance Win32_SystemDriver -Filter "Name='$service'") {throw 'Test service already exists.'}
    foreach($file in $manifest.files) {
        $path=Join-Path $stage $file.relative
        if((Get-FileHash -LiteralPath $path).Hash -ne $file.hash) {throw "Staged hash mismatch: $($file.relative)"}
    }
    $signature=Get-AuthenticodeSignature -LiteralPath (Join-Path $stage 'KswordARK.sys')
    $report.signature=[pscustomobject]@{status="$($signature.Status)";thumbprint=$signature.SignerCertificate.Thumbprint}
    if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $manifest.signer) {throw 'The existing guest trust policy did not validate the driver.'}
    $env:PATH="$base;$oldPath"
    & sc.exe create $service type= kernel start= demand binPath= (Join-Path $stage 'KswordARK.sys') | Out-Null
    if($LASTEXITCODE) {throw 'Test service creation failed.'}
    $created=$true
    & sc.exe start $service | Set-Content -LiteralPath (Join-Path $stage 'driver-start.txt') -Encoding UTF8
    if($LASTEXITCODE) {throw "Native driver load failed: $LASTEXITCODE"}
    $ready=Join-Path $stage 'fixture-ready.json'
    $stop=Join-Path $stage 'fixture-stop.txt'
    if((Test-Path -LiteralPath $ready) -or (Test-Path -LiteralPath $stop)) {throw 'Fixture output paths must be new.'}
    $fixtureArguments=@($ready,$stop,'120000') # 默认两个正常执行线程，生命周期验收才增加独占的新建挂起线程。
    if($IncludeLifecycle){$fixtureArguments+='--lifecycle'}
    $fixture=Start-Process -FilePath (Join-Path $stage 'LiveKernelDiagnosticVmTarget.exe') -ArgumentList $fixtureArguments -PassThru -WindowStyle Hidden
    $deadline=[DateTime]::UtcNow.AddSeconds(8)
    while(!(Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline -and !$fixture.HasExited) {Start-Sleep -Milliseconds 30}
    if(!(Test-Path -LiteralPath $ready)) {throw 'The bounded owned target did not publish its identities.'}
    $target=Get-Content -LiteralPath $ready -Raw | ConvertFrom-Json
    if($target.pid -ne $fixture.Id -or $target.wait.cpuDelta100ns -ne 0 -or $target.busy.cpuDelta100ns -le 0) {throw 'Fixture activity or process identity mismatch.'}
    $common=@('--pid',"$($target.pid)",'--creation-time',"$($target.processCreationTime)",'--profiles',(Join-Path $stage 'profiles'))
    $processArguments=@('process','layout','sample')+$common
    [void](Invoke-Sample 'process-before' $processArguments)
    foreach($kind in @('wait','busy')) {
        $thread=$target.$kind
        $arguments=@('process','thread','layout','sample')+$common+@('--tid',"$($thread.tid)",'--thread-creation-time',"$($thread.creationTime)")
        [void](Invoke-Sample "$kind-thread" $arguments)
    }
    [void](Invoke-Sample 'process-after' $processArguments)
    if($Suite -eq 'Stack' -and $SavedStack) {
        $extra=Join-Path $stage 'Invoke-LiveSavedThreadStackVmChecks.ps1' # 当前来源的真实完整等待栈验收，失败保留原始证据。
        . ([ScriptBlock]::Create([IO.File]::ReadAllText($extra,[Text.Encoding]::UTF8))) -Stage $stage -Target $target -Manifest $manifest
    } elseif($Suite -eq 'Stack') {
        $report.stackAcceptanceScope='diagnostic_target_apc_only_not_complete_original_unwind'
        $report.completeLiveKernelUnwindAccepted=$false
        foreach($kind in @('wait','busy')) {
            $thread=$target.$kind
            $arguments=@('process','thread','stack','capture','--pid',"$($target.pid)",'--tid',"$($thread.tid)",
                '--creation-time',"$($target.processCreationTime)",'--thread-creation-time',"$($thread.creationTime)",'--timeout-ms','1000','--method','apc')
            $expected=if($manifest.identity -eq '34404-2952155935-21299200'){6}else{5}
            $captured=Invoke-Sample "$kind-stack" $arguments $expected
            if($captured.data.frameProjection -ne 'shared_gui_cli_verified_capture') {throw 'The production GUI/CLI shared capture path was not used.'}
            if($expected -eq 6 -and (!$captured.data.executedInTarget -or !$captured.data.retirementVerified -or !$captured.data.frameCount)) {throw 'No validated target-context partial stack.'}
            if($expected -eq 6 -and @($captured.data.frames|Where-Object {!$_.module}).Count) {throw 'A live kernel frame lacked stable before/after module annotation.'}
            if($expected -eq 6 -and $kind -eq 'wait' -and !@($captured.data.frames|Where-Object {$_.localPdbMatched -and $_.symbol -eq 'KiDeliverApc'}).Count) {throw 'The shared local PDB resolver did not resolve the actual APC dispatcher frame.'}
            if($expected -eq 5 -and ($captured.data.queued -or $captured.data.frameCount -or $captured.data.availability -ne 'lifetime_unavailable')) {throw 'Unsupported cancellation did not refuse before queueing.'}
        }
        $extra=Join-Path $stage 'Invoke-LiveThreadStackVmChecks.ps1'
        & ([ScriptBlock]::Create([IO.File]::ReadAllText($extra,[Text.Encoding]::UTF8))) -Stage $stage -Target $target -Manifest $manifest
    }
    Assert-RawIdentityRejection 'driver-wrong-process-time' 1 $target.pid 0 ([uint64]$target.processCreationTime+1) 0
    Assert-RawIdentityRejection 'driver-wrong-thread-time' 2 $target.pid $target.wait.tid ([uint64]$target.processCreationTime) ([uint64]$target.wait.creationTime+1)
    $bad=@('process','layout','sample','--pid',"$($target.pid)",'--creation-time',"$([uint64]$target.processCreationTime+1)",'--profiles',(Join-Path $stage 'profiles'))
    $rejected=Invoke-Sample 'cli-wrong-process-time' $bad 3
    if($rejected.data.fields.Count -or $rejected.data.deviceAccessAttempted) {throw 'CLI preflight identity mismatch reached the driver or exposed fields.'}
    if($IncludeLifecycle -and !$SavedStack -and $manifest.identity -eq '34404-2952155935-21299200') {
        $exitCheck=Join-Path $stage 'Invoke-LiveThreadStackExitVmCheck.ps1' # 独立退出目标不破坏仍用于卸载的主夹具。
        & ([ScriptBlock]::Create([IO.File]::ReadAllText($exitCheck,[Text.Encoding]::UTF8))) -Stage $stage -Manifest $manifest
        $unload=Join-Path $stage 'Invoke-LiveThreadStackUnloadVmCheck.ps1' # 最后才停止本轮服务，保留前面全部拒绝用例。
        & ([ScriptBlock]::Create([IO.File]::ReadAllText($unload,[Text.Encoding]::UTF8))) -Stage $stage -Target $target -Service $service
    }
    if($IncludeLifecycle -and $SavedStack) {
        $savedLifecycle=Join-Path $stage 'Invoke-LiveSavedThreadStackLifecycleVmChecks.ps1' # 两个平台均检查新来源退出及普通在途排空。
        & ([ScriptBlock]::Create([IO.File]::ReadAllText($savedLifecycle,[Text.Encoding]::UTF8))) -Stage $stage -Target $target -Manifest $manifest -Service $service # 子作用域隔离生命周期夹具/停止文件，报告和事件容器仍按引用共享。
    }
    [IO.File]::WriteAllText($stop,'stop')
    if(!$fixture.WaitForExit(5000) -or $fixture.ExitCode -ne 0) {throw 'Owned target failed to exit normally.'}
    $exited=Invoke-Sample 'exited-process' $processArguments 3
    if($exited.data.fields.Count) {throw 'Exited target exposed fields.'}
    $report.success=$true
} catch {
    $report.error=$_.Exception.Message
} finally {
    if($fixture -and !$fixture.HasExited) {
        [IO.File]::WriteAllText((Join-Path $stage 'fixture-stop.txt'),'stop')
        if(!$fixture.WaitForExit(5000)) {$report.success=$false;$report.fixtureCleanupError='Owned fixture has not exited; no forced termination performed.'}
    }
    if($fixture -and $fixture.HasExited) {$report.fixtureExitCode=$fixture.ExitCode}
    if($created) {
        if((Get-CimInstance Win32_SystemDriver -Filter "Name='$service'").State -ne 'Stopped') {
            & sc.exe stop $service | Set-Content -LiteralPath (Join-Path $stage 'driver-stop.txt') -Encoding UTF8
            $report.driverStopExit=$LASTEXITCODE
            if($LASTEXITCODE) {$report.success=$false}
        } else {$report.driverStopExit=0} # 在途卸载用例已通过原 SCM 停止时，不把重复 stop 的1062误算清理失败。
        $controller=Get-Service -Name $service # 由原生 cmdlet 返回完整 ServiceController，避免依赖未加载的短类型名。
        try {$controller.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(10))} catch {$report.success=$false;$report.driverDrainError=$_.Exception.Message}
        $controller.Dispose()
        if((Get-CimInstance Win32_SystemDriver -Filter "Name='$service'").State -eq 'Stopped') {
            & sc.exe delete $service | Out-Null
            $report.driverDeleteExit=$LASTEXITCODE
            if($LASTEXITCODE) {$report.success=$false}
        }
    }
    $env:PATH=$oldPath
    $report.originalAfter=Get-InstalledHashes
    if(($report.originalBefore | ConvertTo-Json -Compress) -ne ($report.originalAfter | ConvertTo-Json -Compress)) {$report.success=$false;$report.originalFilesChanged=$true}
    $report.serviceAbsent=!(Get-CimInstance Win32_SystemDriver -Filter "Name='$service'")
    if(!$report.serviceAbsent) {$report.success=$false}
    if($created -and $report.serviceAbsent) {
        try {
            $creation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc()
            $unavailable=Invoke-Sample 'driver-unavailable' @('process','layout','sample','--pid',"$PID",'--creation-time',"$creation",'--profiles',(Join-Path $stage 'profiles')) 2
            if($unavailable.data.fields.Count -or !$unavailable.data.deviceOpenFailed) {throw 'Unavailable driver exposed fields or reported the wrong phase.'}
        } catch {$report.success=$false;$report.unavailableCheckError=$_.Exception.Message}
    }
    $report.endedUtc=[DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stage 'suite.json') -Encoding UTF8
    $evidence=@(Get-ChildItem -LiteralPath $stage -File | Where-Object {$_.Extension -in @('.json','.txt')})
    Compress-Archive -LiteralPath $evidence.FullName -DestinationPath (Join-Path $stage 'evidence.zip')
}
$report | ConvertTo-Json -Depth 8
if(!$report.success) {exit 1}
exit 0 # 最后一个预期失败用例返回 2；显式成功退出，不能把该原生退出码泄漏给宿主包装器。
