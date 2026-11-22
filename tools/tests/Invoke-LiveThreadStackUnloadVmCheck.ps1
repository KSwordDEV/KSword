param([string]$Stage,[object]$Target,[string]$Service)

# 本轮其它用例结束后，针对仍存活的自有挂起线程请求，再通过原 SCM 入口停止唯一测试服务。
# 分别记录停止通知取消与 SCM 等待有界请求排空，不能把后者改名为前者；不强制卸载或杀掉 CLI。
$ErrorActionPreference='Stop'
$arguments=@('process','thread','stack','capture','--method','apc','--pid',"$($Target.pid)",'--creation-time',"$($Target.processCreationTime)",
    '--tid',"$($Target.dormant.tid)",'--thread-creation-time',"$($Target.dormant.creationTime)",'--timeout-ms','5000','--json')
$start=New-Object Diagnostics.ProcessStartInfo # 持有原始进程句柄并并行排空两个管道。
$start.FileName=Join-Path $Stage 'KswordCLI.exe'
$start.Arguments=[string]::Join(' ',$arguments)
$start.UseShellExecute=$false
$start.CreateNoWindow=$true
$start.RedirectStandardOutput=$true
$start.RedirectStandardError=$true
$start.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
$start.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
$process=New-Object Diagnostics.Process
$process.StartInfo=$start
try {
    if(!$process.Start()){throw 'In-flight unload CLI did not start.'}
    $stdout=$process.StandardOutput.ReadToEndAsync() # 不让输出背压延长内核请求生命周期。
    $stderr=$process.StandardError.ReadToEndAsync()
    if($process.WaitForExit(1000)){throw 'Capture ended before the SCM stop attempt; no in-flight claim.'}
    $elapsed=[Diagnostics.Stopwatch]::StartNew() # 单调计时独立限制 SCM 停止及请求退休的观察预算。
    $report.stackUnloadStopAttemptUtc=[DateTime]::UtcNow.ToString('o') # 时间只是辅助，后续必须核验原始响应中的停止状态。
    & sc.exe stop $Service | Set-Content -LiteralPath (Join-Path $Stage 'driver-stop-inflight.txt') -Encoding UTF8
    $stopCode=$LASTEXITCODE # 原生 SCM 拒绝不能被忽略或用强制路径绕过。
    $report.stackUnloadStopExit=$stopCode
    if(!$process.WaitForExit(15000)){throw 'In-flight request did not retire; no forced termination performed.'}
    $code=$process.ExitCode
    $text=$stdout.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $Stage 'dormant-stack-inflight-unload.json'),$text,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $Stage 'dormant-stack-inflight-unload.stderr.txt'),$stderr.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
    $events.Add([pscustomobject]@{name='dormant-stack-inflight-unload';exitCode=$code;expectedExitCode=3;
        arguments=$arguments;receipt='dormant-stack-inflight-unload.json'})
    $data=($text|ConvertFrom-Json).data # 响应只能来自生产共享 GUI/CLI 路径。
    if($stopCode -ne 0){throw 'SCM refused the in-flight unload; no in-flight unload acceptance.'}
    if($code -ne 3 -or !$data.queued -or !$data.ownApcCancelled -or !$data.retirementVerified -or
        $data.ntStatus -notin @('0xc0000056','0x102') -or $data.executedInTarget -or $data.frameCount -or !$data.targetAliveAtReadback) {
        throw 'SCM stop did not safely drain an unexecuted owned APC.'
    }
    $wire=New-Object byte[] ($data.wireResponse.Length/2) # 回执本身必须证明实际入队早于 SCM 停止尝试。
    for($index=0;$index -lt $wire.Length;$index++){$wire[$index]=[Convert]::ToByte($data.wireResponse.Substring(2*$index,2),16)}
    $attempt=[DateTime]::Parse($report.stackUnloadStopAttemptUtc).ToUniversalTime().ToFileTimeUtc()
    if($wire.Length -ne 680 -or [BitConverter]::ToUInt64($wire,112) -gt $attempt){throw 'No wire proof of an APC queued before SCM stop.'}
    $controller=Get-Service -Name $Service # 保留原管理入口，不直接操作驱动对象或底层卸载函数。
    try {$controller.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(10))} finally {$controller.Dispose()}
    if($elapsed.ElapsedMilliseconds -gt 15000){throw 'SCM drain exceeded the bounded acceptance budget.'}
    $report.stackInFlightUnloadDrainCovered=$true # 只声明停止请求与真实在途采集重叠且安全排空。
    $report.stackInFlightUnloadCovered=$data.ntStatus -eq '0xc0000056' # 原来更严格的停止通知取消条件保留独立真假值。
    $report.stackInFlightUnloadMode=if($report.stackInFlightUnloadCovered){'shutdown_notification_cancel'}else{'scm_waited_for_bounded_timeout_drain'}
    $report.stackInFlightUnloadDrainMilliseconds=$elapsed.ElapsedMilliseconds
} finally {
    $process.Dispose() # 只归还观察句柄，不终止任何在途原生进程。
}
