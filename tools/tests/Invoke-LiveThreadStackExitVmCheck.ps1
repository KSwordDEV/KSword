param([string]$Stage,[object]$Manifest)

# 独立夹具主动 ExitProcess；原始 CLI 核对固定身份的退休回执，区分未执行退出与退出期间实际执行。
$ErrorActionPreference='Stop'
$ready=Join-Path $Stage 'exit-fixture-ready.json' # 与正常采集目标分离的原始身份文件。
$stop=Join-Path $Stage 'exit-fixture-stop.txt' # 唯一退出触发，不终止来宾其它进程。
$fixture=$null # 保留原进程句柄，退出码不依赖 PID 重开。
$capture=$null # 原始 IOCTL CLI 仍必须使用项目唯一客户端执行。
try {
    $fixture=Start-Process -FilePath (Join-Path $Stage 'LiveKernelDiagnosticVmTarget.exe') `
        -ArgumentList @($ready,$stop,'15000','--exit-with-pending') -PassThru -WindowStyle Hidden
    $deadline=[DateTime]::UtcNow.AddSeconds(6) # 就绪有界等待不改变任何系统策略。
    while(!(Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline -and !$fixture.HasExited){Start-Sleep -Milliseconds 30}
    $target=Get-Content -LiteralPath $ready -Raw|ConvertFrom-Json
    if(!$target.dormant.initiallySuspended -or $target.dormant.cpu100ns){throw 'Exit fixture has no owned never-run thread.'}
    $stream=New-Object IO.MemoryStream # 逐字段编码唯一共享协议，不能加入地址、私有偏移或回调。
    $writer=New-Object IO.BinaryWriter($stream)
    foreach($value in @([uint32]48,[uint32]2,[uint32]$target.pid,[uint32]$target.dormant.tid)){$writer.Write([uint32]$value)}
    $writer.Write([uint64]$target.processCreationTime)
    $writer.Write([uint64]$target.dormant.creationTime)
    foreach($value in @(64,5000,0,0)){$writer.Write([uint32]$value)}
    $hex=[BitConverter]::ToString($stream.ToArray()).Replace('-','')
    $writer.Dispose()
    $stream.Dispose()
    $arguments=@('system','ioctl','call','--code',"$($Manifest.stackIoctlCode)",'--input-hex',$hex,'--output-bytes','680','--confirm','--json')
    $start=New-Object Diagnostics.ProcessStartInfo # 原始进程句柄和同时排空的输出管道。
    $start.FileName=Join-Path $Stage 'KswordCLI.exe'
    $start.Arguments=[string]::Join(' ',$arguments)
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $start.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
    $capture=New-Object Diagnostics.Process
    $capture.StartInfo=$start
    if(!$capture.Start()){throw 'Exit-race CLI creation failed.'}
    $stdout=$capture.StandardOutput.ReadToEndAsync()
    $stderr=$capture.StandardError.ReadToEndAsync()
    if($capture.WaitForExit(700)){throw 'Capture finished before the owned exit trigger; no in-flight exit evidence.'}
    $trigger=[DateTime]::UtcNow.ToFileTimeUtc() # 后续原始入队时间必须早于此独立触发时间。
    [IO.File]::WriteAllText($stop,'exit')
    if(!$capture.WaitForExit(10000) -or !$fixture.WaitForExit(5000)){throw 'Exit-race participants did not retire; no forced termination performed.'}
    $text=$stdout.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $Stage 'dormant-stack-inflight-exit.json'),$text,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $Stage 'dormant-stack-inflight-exit.stderr.txt'),$stderr.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
    $events.Add([pscustomobject]@{name='dormant-stack-inflight-exit';exitCode=$capture.ExitCode;expectedExitCode=0;
        arguments=$arguments;receipt='dormant-stack-inflight-exit.json'})
    $packet=$text|ConvertFrom-Json # CLI 原始命令退出0只代表 IOCTL 传输，业务状态必须另查。
    $wire=New-Object byte[] ($packet.data.outputHex.Length/2)
    for($index=0;$index -lt $wire.Length;$index++){$wire[$index]=[Convert]::ToByte($packet.data.outputHex.Substring(2*$index,2),16)}
    if($capture.ExitCode -ne 0 -or $fixture.ExitCode -ne 0 -or $wire.Length -ne 680){throw 'Exit-race transport or target failed.'}
    $flags=[BitConverter]::ToUInt32($wire,20) # 只有系统实际退出且 APC 已退休才覆盖此用例。
    if(($flags -band 0x203) -ne 0x203 -or
        [BitConverter]::ToUInt32($wire,24) -ne $target.pid -or [BitConverter]::ToUInt32($wire,28) -ne $target.dormant.tid -or
        [BitConverter]::ToUInt64($wire,32) -ne [uint64]$target.processCreationTime -or
        [BitConverter]::ToUInt64($wire,40) -ne [uint64]$target.dormant.creationTime -or
        ![BitConverter]::ToUInt64($wire,112) -or [BitConverter]::ToUInt64($wire,112) -gt $trigger){
        throw 'No retired queued APC receipt tied to the actually exiting owned thread.'
    }
    $status=[BitConverter]::ToUInt32($wire,8) # 正常退出可能先投递内核 APC，也可能先使线程对象终止。
    $count=[BitConverter]::ToUInt32($wire,152)
    $unexecuted=$status -eq [uint32]3221225547 -and ($flags -band 4) -eq 0 -and $count -eq 0
    if($unexecuted) {
        if(@($wire[64..103]+$wire[120..151]+$wire[160..163]+$wire[168..679]|Where-Object {$_}).Count){throw 'Unexecuted exit exposed capture evidence.'}
    } else {
        # 真实 Win11 ExitProcess 会在退出路径投递该普通内核 APC；不能把此结果改写成没有执行的 rundown。
        if($status -ne 0 -or ($flags -band 0x31f) -ne 0x21f -or !$count -or $count -gt 64 -or
            [BitConverter]::ToUInt32($wire,12) -ne 1 -or [BitConverter]::ToUInt32($wire,16) -ne 1 -or
            [BitConverter]::ToUInt32($wire,64) -ne $target.pid -or [BitConverter]::ToUInt32($wire,68) -ne $target.dormant.tid -or
            [BitConverter]::ToUInt64($wire,72) -ne [BitConverter]::ToUInt64($wire,48) -or
            [BitConverter]::ToUInt64($wire,80) -ne [BitConverter]::ToUInt64($wire,56) -or
            [BitConverter]::ToUInt64($wire,120) -lt $trigger -or [BitConverter]::ToUInt32($wire,160) -ne 1){throw 'Exit-path target execution was not independently tied to the trigger and frozen identity.'}
        $systemRange=[Convert]::ToUInt64('FFFF800000000000',16) # 避免 PowerShell 对超大十进制字面量的浮点转换。
        foreach($index in 0..63) {
            $address=[BitConverter]::ToUInt64($wire,168+8*$index)
            if(($index -lt $count -and $address -lt $systemRange) -or ($index -ge $count -and $address)){throw 'Exit-path frame range or tail invalid.'}
        }
    }
    $report.stackInFlightTargetExitCovered=$true
    $report.stackInFlightTargetExitMode=if($unexecuted){'unexecuted_target_exit'}else{'target_apc_executed_during_exit'}
    $report.stackExitUndeliveredRundownCovered=$unexecuted -and ($flags -band 0x100) -eq 0
    $report.stackInFlightTargetExitFrames=$count # 仅作已退出目标的原始诊断证据，不回填 GUI 活目标结果。
    $report.stackInFlightTargetExitTrigger100ns="$trigger"
    $report.stackExitFixtureExitCode=$fixture.ExitCode
} finally {
    if($fixture -and !$fixture.HasExited){[IO.File]::WriteAllText($stop,'exit');[void]$fixture.WaitForExit(18000)}
    if($fixture){$fixture.Dispose()}
    if($capture){$capture.Dispose()} # 不终止尚在运行的原生请求。
}
