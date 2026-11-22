param([string]$Stage,[object]$Target,[object]$Manifest)

# 仅由同目录、已核验哈希的双 VM 主验收器在自有夹具存活期间调用；不改变目标或系统策略。
$ErrorActionPreference='Stop'
$expected=if($Manifest.identity -eq '34404-2952155935-21299200'){6}else{5}
$cli=Join-Path $Stage 'KswordCLI.exe' # 只使用本轮已冻结、同目录依赖完整的 CLI。
$common=@('--pid',"$($Target.pid)",'--creation-time',"$($Target.processCreationTime)",
    '--tid',"$($Target.wait.tid)",'--thread-creation-time',"$($Target.wait.creationTime)")
$stack=@('process','thread','stack','capture','--method','apc')+$common # 旧诊断套件固定旧来源，不因 Auto 首选项变化而误判。

# 直接请求错误包验证内核拒绝；不能只依赖 CLI 的设备访问前参数检查。
foreach($kind in @('version','flags','reserved','process-time','thread-time')) {
    $stream=New-Object IO.MemoryStream
    $writer=New-Object IO.BinaryWriter($stream)
    $writer.Write([uint32]48)
    $writer.Write([uint32]$(if($kind -eq 'version'){1}else{2}))
    $writer.Write([uint32]$Target.pid)
    $writer.Write([uint32]$Target.wait.tid)
    $writer.Write([uint64]$Target.processCreationTime+[uint64]($kind -eq 'process-time'))
    $writer.Write([uint64]$Target.wait.creationTime+[uint64]($kind -eq 'thread-time'))
    $writer.Write([uint32]64)
    $writer.Write([uint32]100)
    $writer.Write([uint32]($kind -eq 'flags'))
    $writer.Write([uint32]($kind -eq 'reserved'))
    $hex=[BitConverter]::ToString($stream.ToArray()).Replace('-','')
    $writer.Dispose()
    $stream.Dispose()
    $packet=Invoke-Sample "stack-raw-$kind" @('system','ioctl','call','--code',"$($Manifest.stackIoctlCode)",
        '--input-hex',$hex,'--output-bytes','680','--confirm')
    $wire=New-Object byte[] ($packet.data.outputHex.Length/2)
    for($index=0;$index -lt $wire.Length;$index++) {$wire[$index]=[Convert]::ToByte($packet.data.outputHex.Substring(2*$index,2),16)}
    if($wire.Length -ne 680) {throw 'Stack refusal did not return the fixed response size.'}
    $status=[BitConverter]::ToUInt32($wire,8)
    $expectedStatus=if($kind -like '*-time'){[uint32]3221226029}else{[uint32]3221225485}
    # requestTime、frameLimit 和 timeout 是诊断回显，不能把它们误判为目标采集证据。
    if($status -ne $expectedStatus -or [BitConverter]::ToUInt32($wire,16) -ne 0 -or
        [BitConverter]::ToUInt32($wire,20) -ne 0 -or @($wire[64..103]+$wire[112..151]+$wire[168..679]|Where-Object {$_ -ne 0}).Count -ne 0 -or
        [BitConverter]::ToUInt32($wire,152) -ne 0 -or [BitConverter]::ToUInt32($wire,160) -ne 0) {throw "Malformed stack request $kind exposed capture evidence or wrong status."}
}

# 帧预算必须实际影响后端；部分帧仍返回 6，不因达到预算而冒充完整栈。
$limited=Invoke-Sample 'wait-stack-limit1' ($stack+@('--limit','1','--timeout-ms','1000')) $expected
if($expected -eq 6 -and $limited.data.frameCount -ne 1) {throw 'One-frame request ignored its actual frame budget.'}
foreach($module in @('ntoskrnl.exe','KswordARK.sys')) {
    # 仅取本次帧链需要的两个模块，避免把整个系统模块清单塞入嵌套命令的有界输出。
    [void](Invoke-Sample ("loaded-module-"+$module) @('privilege','run','--enable','SeDebugPrivilege','--json','--',
        'driver','modules','query','--name',$module,'--signature','off','--source','nt','--json'))
}

# 四个真实并发 CLI 使用相同冻结目标，不以离线状态机或批量顺序调用代替并发执行。
$jobs=@()
try {
    foreach($index in 0..3) {
        $name="wait-stack-concurrent$index"
        $arguments=$stack+@('--timeout-ms','1000','--json')
        $start=New-Object Diagnostics.ProcessStartInfo # 保留真正创建进程的句柄；WinPS 的 Start-Process 重开对象会丢失快速退出码。
        $start.FileName=$cli
        $start.Arguments=[string]::Join(' ',$arguments) # 这些参数只有固定命令、数字身份与开关，不含路径或用户文本。
        $start.UseShellExecute=$false
        $start.CreateNoWindow=$true
        $start.RedirectStandardOutput=$true
        $start.RedirectStandardError=$true
        $start.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
        $start.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
        $process=New-Object Diagnostics.Process
        $process.StartInfo=$start
        if(!$process.Start()) {$process.Dispose();throw 'Concurrent CLI process creation failed.'}
        $stdout=$process.StandardOutput.ReadToEndAsync() # 两个流同时排空，不能让输出管道阻塞内核请求退休。
        $stderr=$process.StandardError.ReadToEndAsync()
        $jobs+=[pscustomobject]@{name=$name;process=$process;arguments=$arguments;stdout=$stdout;stderr=$stderr}
    }
    foreach($job in $jobs) {
        if(!$job.process.WaitForExit(10000)) {throw 'A concurrent CLI did not retire within the observation budget; no forced termination performed.'}
        $code=$job.process.ExitCode
        [IO.File]::WriteAllText((Join-Path $Stage "$($job.name).json"),$job.stdout.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $Stage "$($job.name).stderr.txt"),$job.stderr.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
        $events.Add([pscustomobject]@{name=$job.name;exitCode=$code;expectedExitCode=$expected;arguments=$job.arguments;receipt="$($job.name).json"})
        if($code -ne $expected) {throw "Concurrent stack request returned $code instead of $expected"}
        $packet=Get-Content -LiteralPath (Join-Path $Stage "$($job.name).json") -Raw|ConvertFrom-Json
        if($expected -eq 6 -and (!$packet.data.executedInTarget -or !$packet.data.retirementVerified -or !$packet.data.frameCount)) {throw 'Concurrent stack request lacked target/retirement evidence.'}
        if($expected -eq 5 -and ($packet.data.queued -or $packet.data.frameCount)) {throw 'Unavailable backend queued a concurrent request.'}
    }
} finally {
    foreach($job in $jobs) {$job.process.Dispose()}
}
$report.stackConcurrencyVerified=4
$report.stackRawRefusalCases=5
$report.stackTimeoutCancellationCovered=$false # 没有真实命中未投递队列的超时，不能把正常完成虚报为取消验证。
if($IncludeLifecycle) {
    $lifecycle=Join-Path $Stage 'Invoke-LiveThreadStackLifecycleVmChecks.ps1' # 显式请求才运行额外的真实生命周期用例。
    & ([ScriptBlock]::Create([IO.File]::ReadAllText($lifecycle,[Text.Encoding]::UTF8))) -Stage $Stage -Target $Target -Manifest $Manifest
}
