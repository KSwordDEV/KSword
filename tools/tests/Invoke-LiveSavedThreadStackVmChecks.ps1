param([string]$Stage,[object]$Target,[object]$Manifest)

# 只在自有 VM 读取夹具的真实等待线程；不暂停目标，不借助转储、ETW 或请求者栈。
$ErrorActionPreference='Stop'
$common=@('process','thread','stack','capture','--method','saved','--pid',"$($Target.pid)",
    '--creation-time',"$($Target.processCreationTime)",'--tid',"$($Target.wait.tid)",
    '--thread-creation-time',"$($Target.wait.creationTime)",'--timeout-ms','1000')
$captured=Invoke-Sample 'wait-saved-stack' $common 0
if(!$captured.data.complete -or $captured.data.source -ne 'target_saved_context' -or
    $captured.data.frameProjection -ne 'shared_gui_cli_verified_capture' -or
    !$captured.data.frameCount -or $captured.data.queued -or $captured.data.executedInTarget -or
    $captured.data.savedContext.unwindStop -ne 1 -or ([uint32]$captured.data.savedContext.terminalCodeSegment -band 3) -ne 3) {
    throw 'No complete original waiting-thread kernel chain with a verified user machine-frame boundary.'
}
$names=@($captured.data.frames|Where-Object {$_.localPdbMatched}|ForEach-Object {$_.symbol})
if($names -notcontains 'KiSwapContext' -or $names -notcontains 'NtWaitForSingleObject' -or $names -notcontains 'KiSystemServiceCopyEnd') {
    throw 'Exact local PDB annotations did not establish the fixture wait/syscall chain.'
}
if(@($captured.data.frames|Where-Object {$_.module -like '*Ksword*' -or $_.symbol -match 'KswStackApc|KiDeliverApc'}).Count) {
    throw 'The original saved-context chain was contaminated by this driver or an APC dispatcher.'
}
$limited=Invoke-Sample 'wait-saved-stack-limit1' ($common+@('--limit','1')) 6
if($limited.data.complete -or $limited.data.frameCount -ne 1 -or $limited.data.savedContext.unwindStop -ne 2) {
    throw 'Frame-budget truncation was not explicitly partial.'
}

# 直接构造唯一共享身份包，故意错一个创建时间；不能经 CLI 前置拒绝替代驱动身份验证。
$stream=New-Object IO.MemoryStream
$writer=New-Object IO.BinaryWriter($stream)
foreach($value in @([uint32]48,[uint32]1,[uint32]$Target.pid,[uint32]$Target.wait.tid)) {$writer.Write([uint32]$value)}
$writer.Write([uint64]$Target.processCreationTime)
$writer.Write([uint64]$Target.wait.creationTime+1)
foreach($value in @([uint32]64,[uint32]1000,[uint32]0,[uint32]0)) {$writer.Write([uint32]$value)}
$hex=[BitConverter]::ToString($stream.ToArray()).Replace('-','')
$writer.Dispose()
$stream.Dispose()
$raw=Invoke-Sample 'driver-saved-wrong-identity' @('system','ioctl','call','--code',"$($Manifest.snapshotIoctlCode)",
    '--input-hex',$hex,'--output-bytes','792','--confirm')
$bytes=New-Object byte[] ($raw.data.outputHex.Length/2)
for($index=0;$index -lt $bytes.Length;$index++) {$bytes[$index]=[Convert]::ToByte($raw.data.outputHex.Substring($index*2,2),16)}
if($bytes.Length -ne 792 -or [BitConverter]::ToUInt32($bytes,12) -ne 2 -or
    [BitConverter]::ToUInt32($bytes,152) -ne 0 -or @($bytes[168..679]|Where-Object {$_ -ne 0}).Count) {
    throw 'Wrong-instance raw saved-context request exposed frames.'
}

# 四个真实并发请求必须各自取得完整等待链；副本、身份与原始 wire 不能混用。
$jobs=@()
try {
    foreach($index in 0..3) {
        $name="wait-saved-concurrent$index"
        $start=New-Object Diagnostics.ProcessStartInfo
        $start.FileName=Join-Path $Stage 'KswordCLI.exe'
        $start.Arguments=[string]::Join(' ',($common+@('--json')))
        $start.UseShellExecute=$false
        $start.CreateNoWindow=$true
        $start.RedirectStandardOutput=$true
        $start.RedirectStandardError=$true
        $start.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
        $start.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
        $process=New-Object Diagnostics.Process
        $process.StartInfo=$start
        if(!$process.Start()) {$process.Dispose();throw 'Saved-context concurrent CLI creation failed.'}
        $stdout=$process.StandardOutput.ReadToEndAsync()
        $stderr=$process.StandardError.ReadToEndAsync()
        $jobs+=[pscustomobject]@{name=$name;process=$process;stdout=$stdout;stderr=$stderr}
    }
    foreach($job in $jobs) {
        if(!$job.process.WaitForExit(10000)) {throw 'Concurrent saved-context request did not retire; no forced termination performed.'}
        $code=$job.process.ExitCode
        [IO.File]::WriteAllText((Join-Path $Stage "$($job.name).json"),$job.stdout.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $Stage "$($job.name).stderr.txt"),$job.stderr.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
        $events.Add([pscustomobject]@{name=$job.name;exitCode=$code;expectedExitCode=0;arguments=$common;receipt="$($job.name).json"})
        if($code -ne 0) {throw "Concurrent saved-context request returned $code instead of complete success"}
        $packet=Get-Content -LiteralPath (Join-Path $Stage "$($job.name).json") -Raw|ConvertFrom-Json
        if(!$packet.data.complete -or $packet.data.source -ne 'target_saved_context' -or !$packet.data.frameCount) {throw 'Concurrent saved-context request lacked a complete original chain.'}
    }
} finally {
    foreach($job in $jobs) {$job.process.Dispose()}
}
$report.savedStackConcurrencyVerified=4

# 忙线程始终计算且不主动等待；后端只能在其真实调度保存区间取得栈，不挂起或唤醒它。
$busy=@('process','thread','stack','capture','--method','saved','--pid',"$($Target.pid)",
    '--creation-time',"$($Target.processCreationTime)",'--tid',"$($Target.busy.tid)",
    '--thread-creation-time',"$($Target.busy.creationTime)",'--timeout-ms','5000')
$busyCaptured=Invoke-Sample 'busy-saved-stack' $busy 0
if(!$busyCaptured.data.complete -or !$busyCaptured.data.frameCount -or $busyCaptured.data.source -ne 'target_saved_context') {
    throw 'Busy target did not yield an actual complete saved-context chain within its capture budget.'
}
$report.savedBusyFrameCount=$busyCaptured.data.frameCount
$report.savedStackBusyTargetCovered=$true

# 所有结论只来自上方真实退出码和回执；不声称在线程正执行时复制变化中的栈。
$report.stackAcceptanceScope='original_waiting_target_saved_context_to_user_machine_frame'
$report.completeLiveKernelUnwindAccepted=$true
$report.savedWaitFrameCount=$captured.data.frameCount
$report.savedWaitSymbols=$names
$report.savedStackRunningTargetCovered=$false
