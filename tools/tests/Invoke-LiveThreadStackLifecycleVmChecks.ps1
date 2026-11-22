param([string]$Stage,[object]$Target,[object]$Manifest)

# 只对本轮夹具新建且从未运行的线程请求；采集后端本身没有挂起、恢复或强制投递目标。
$ErrorActionPreference='Stop'
if(!$Target.dormant.initiallySuspended -or $Target.dormant.cpu100ns -ne 0){throw 'No owned never-run lifecycle target.'}
$arguments=@('process','thread','stack','capture','--method','apc','--pid',"$($Target.pid)",'--creation-time',"$($Target.processCreationTime)",
    '--tid',"$($Target.dormant.tid)",'--thread-creation-time',"$($Target.dormant.creationTime)") # 全部请求固定同一实例。
if($Manifest.identity -ne '34404-2952155935-21299200') {
    $unavailable=Invoke-Sample 'dormant-stack-unavailable' ($arguments+@('--timeout-ms','100')) 5
    if($unavailable.data.queued -or $unavailable.data.frameCount){throw 'Unavailable backend queued a lifecycle request.'}
    $report.stackLifecycleUnavailable=$true # 不把能力拒绝计为超时或取消覆盖。
    return
}

# 单次现场命中排队超时才允许继续饱和测试，不能拿普通完成后的退休标志代替取消证据。
$timeout=Invoke-Sample 'dormant-stack-timeout' ($arguments+@('--timeout-ms','100')) 3
if($timeout.data.availability -ne 'timeout' -or !$timeout.data.queued -or !$timeout.data.ownApcCancelled -or
    !$timeout.data.retirementVerified -or $timeout.data.executedInTarget -or $timeout.data.frameCount -or
    $timeout.data.captureStartTime100ns){throw 'The owned dormant thread did not produce a cancelled unexecuted APC timeout.'}
$report.stackTimeoutCancellationCovered=$true
$jobs=@() # 并发子进程句柄和异步输出流由本测试唯一持有。
$timedOut=0 # 只有完整取消回执才计入真正占用过队列名额的请求。
$busy=0 # 只有驱动自身的 STATUS_DEVICE_BUSY 且未入队才计入上限拒绝。
try {
    foreach($index in 0..23) {
        $name="dormant-stack-saturation$index" # 独立回执保留每一个真实退出码和原始响应。
        $command=$arguments+@('--timeout-ms','5000','--json') # 24 个进程争用生产上限16，不向驱动添加测试旁门。
        $start=New-Object Diagnostics.ProcessStartInfo
        $start.FileName=Join-Path $Stage 'KswordCLI.exe'
        $start.Arguments=[string]::Join(' ',$command) # 只有固定命令、数字和开关，不包含待转义路径。
        $start.UseShellExecute=$false
        $start.CreateNoWindow=$true
        $start.RedirectStandardOutput=$true
        $start.RedirectStandardError=$true
        $start.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
        $start.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
        $process=New-Object Diagnostics.Process
        $process.StartInfo=$start
        if(!$process.Start()){$process.Dispose();throw 'Lifecycle CLI creation failed.'}
        $jobs+=[pscustomobject]@{name=$name;process=$process;arguments=$command;
            stdout=$process.StandardOutput.ReadToEndAsync();stderr=$process.StandardError.ReadToEndAsync()}
    }
    foreach($job in $jobs) {
        if(!$job.process.WaitForExit(15000)){throw 'Lifecycle capture exceeded its observation budget; no forced termination performed.'}
        $code=$job.process.ExitCode # 读取原始句柄，避免快速退出码在 WinPS 下丢失。
        $text=$job.stdout.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $Stage "$($job.name).json"),$text,[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $Stage "$($job.name).stderr.txt"),$job.stderr.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
        $events.Add([pscustomobject]@{name=$job.name;exitCode=$code;expectedExitCode=3;arguments=$job.arguments;receipt="$($job.name).json"})
        $data=($text|ConvertFrom-Json).data # CLI 共享验证器已核验固定响应，仍独立检查本轮特定事实。
        if($code -ne 3 -or $data.frameCount -or $data.executedInTarget){throw 'Dormant saturation returned execution or an unexpected exit code.'}
        if($data.availability -eq 'timeout' -and $data.queued -and $data.ownApcCancelled -and $data.retirementVerified) {
            $timedOut++
        } elseif($data.availability -eq 'unavailable' -and !$data.queued -and $data.ntStatus -eq '0x80000011') {
            $busy++
        } else {throw 'Saturation did not return either a real cancelled timeout or an unqueued busy refusal.'}
    }
    if(!$timedOut -or !$busy){throw 'The run did not actually reach production saturation.'}
    $report.stackSaturation=[pscustomobject]@{requests=$jobs.Count;cancelledTimeouts=$timedOut;unqueuedBusyRefusals=$busy}
    # 再次成功采集原等待线程证明所有超时和拒绝后仍能复用后端，但不冒充卸载中竞争验证。
    $recovery=@('process','thread','stack','capture','--method','apc','--pid',"$($Target.pid)",'--creation-time',"$($Target.processCreationTime)",
        '--tid',"$($Target.wait.tid)",'--thread-creation-time',"$($Target.wait.creationTime)",'--timeout-ms','1000')
    [void](Invoke-Sample 'wait-stack-after-saturation' $recovery 6)
} finally {
    foreach($job in $jobs){$job.process.Dispose()} # 不杀进程或丢弃被原生驱动持有的在途请求。
}
