param([string]$Stage,[object]$Target,[object]$Manifest,[string]$Service)

# 新来源没有目标 APC；本脚本验证退出后拒绝与普通SCM停止，只有wire时序实际重叠才记在途排空。
$ErrorActionPreference='Stop'
function Start-RawSavedCapture([object]$Identity,[string]$Name) {
    $stream=New-Object IO.MemoryStream # 仅序列化唯一身份请求，不提供任何内核地址。
    $writer=New-Object IO.BinaryWriter($stream)
    foreach($value in @([uint32]48,[uint32]1,[uint32]$Identity.pid,[uint32]$Identity.dormant.tid)) {$writer.Write([uint32]$value)}
    $writer.Write([uint64]$Identity.processCreationTime)
    $writer.Write([uint64]$Identity.dormant.creationTime)
    foreach($value in @(64,5000,0,0)) {$writer.Write([uint32]$value)}
    $hex=[BitConverter]::ToString($stream.ToArray()).Replace('-','')
    $writer.Dispose()
    $stream.Dispose()
    $arguments=@('system','ioctl','call','--code',"$($Manifest.snapshotIoctlCode)",'--input-hex',$hex,'--output-bytes','792','--confirm','--json')
    $start=New-Object Diagnostics.ProcessStartInfo # 始终保留原生进程句柄和两个同时排空的流。
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
    if(!$process.Start()) {$process.Dispose();throw 'Raw saved-context CLI did not start.'}
    [pscustomobject]@{name=$Name;process=$process;stdout=$process.StandardOutput.ReadToEndAsync();stderr=$process.StandardError.ReadToEndAsync();arguments=$arguments}
}
function Finish-RawSavedCapture([object]$Job) {
    if(!$Job.process.WaitForExit(12000)) {throw 'Saved-context request did not retire within its bounded observation; no forced termination performed.'}
    $code=$Job.process.ExitCode
    [IO.File]::WriteAllText((Join-Path $Stage "$($Job.name).json"),$Job.stdout.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $Stage "$($Job.name).stderr.txt"),$Job.stderr.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
    $events.Add([pscustomobject]@{name=$Job.name;exitCode=$code;expectedExitCode=0;arguments=$Job.arguments;receipt="$($Job.name).json"})
    if($code -ne 0) {throw 'Raw saved-context transport failed.'}
    $packet=Get-Content -LiteralPath (Join-Path $Stage "$($Job.name).json") -Raw|ConvertFrom-Json
    $bytes=New-Object byte[] ($packet.data.outputHex.Length/2)
    for($index=0;$index -lt $bytes.Length;$index++) {$bytes[$index]=[Convert]::ToByte($packet.data.outputHex.Substring($index*2,2),16)}
    if($bytes.Length -ne 792) {throw 'Raw saved-context response has an invalid size.'}
    $count=[BitConverter]::ToUInt32($bytes,152)
    $source=[BitConverter]::ToUInt32($bytes,16)
    $result=[BitConverter]::ToUInt32($bytes,12)
    $status=[BitConverter]::ToUInt32($bytes,8)
    if($count -gt 64 -or ($count -gt 0 -and ($source -ne 2 -or $status -ne 0 -or $result -notin @(1,5)))) {
        throw 'Raw saved-context frames lack an explicit verified source/result.'
    }
    for($index=$count;$index -lt 64;$index++) {if([BitConverter]::ToUInt64($bytes,168+8*$index)) {throw 'Raw saved-context unused frame tail is nonzero.'}}
    [pscustomobject]@{requestTime=[BitConverter]::ToUInt64($bytes,104);copyEnd=[BitConverter]::ToUInt64($bytes,128);ntStatus=('0x{0:x8}' -f $status);frames=$count;source=$source;result=$result}
}
if(!$Target.dormant.initiallySuspended -or $Target.dormant.cpu100ns) {throw 'No owned never-run lifetime target.'}
$fixture=$null
$capture=$null
$ready=Join-Path $Stage 'saved-exit-ready.json'
$stop=Join-Path $Stage 'saved-exit-stop.txt'
try {
    # 独立自有夹具通过正常停止文件退出；主夹具继续保留用于普通 SCM 排空。
    $fixture=Start-Process -FilePath (Join-Path $Stage 'LiveKernelDiagnosticVmTarget.exe') -ArgumentList @($ready,$stop,'20000','--lifecycle') -PassThru -WindowStyle Hidden
    $deadline=[DateTime]::UtcNow.AddSeconds(6)
    while(!(Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline -and !$fixture.HasExited) {Start-Sleep -Milliseconds 20}
    $identity=Get-Content -LiteralPath $ready -Raw|ConvertFrom-Json
    $capture=Start-RawSavedCapture $identity 'saved-target-exit'
    Start-Sleep -Milliseconds 150
    $exitSignal=[uint64][DateTime]::UtcNow.ToFileTimeUtc()
    [IO.File]::WriteAllText($stop,'stop')
    if(!$fixture.WaitForExit(5000) -or $fixture.ExitCode -ne 0) {throw 'Exit fixture did not terminate normally.'}
    $exited=Finish-RawSavedCapture $capture
    $report.savedStackExit=[pscustomobject]@{requestBeforeExitSignal=($exited.requestTime -lt $exitSignal);fixtureExitCode=$fixture.ExitCode;frames=$exited.frames;ntStatus=$exited.ntStatus;acquisitionOverlappedExit=($exited.copyEnd -gt $exitSignal);afterExitRefused=$false;mode='normal_target_exit_with_independent_saved_context_request'}
    if(!$report.savedStackExit.requestBeforeExitSignal) {throw 'The raw request did not actually start before target exit was signalled.'}
    $capture.process.Dispose()
    $capture=$null
    $capture=Start-RawSavedCapture $identity 'saved-after-target-exit'
    $afterExit=Finish-RawSavedCapture $capture
    if($afterExit.frames -or $afterExit.source -or $afterExit.ntStatus -notin @('0xc000000b','0xc000004b','0xc0000225')) {throw 'An exited frozen thread identity was reused or exposed stale frames.'}
    $report.savedStackExit.afterExitRefused=$true
    $capture.process.Dispose()
    $capture=$null
    # 从未执行用户代码的线程也可能已建立真实的挂起等待栈；必须接受合法帧，不能把它当作必定重试的夹具。
    $capture=Start-RawSavedCapture $Target 'saved-inflight-scm-stop'
    Start-Sleep -Milliseconds 150
    $stopBegin=[uint64][DateTime]::UtcNow.ToFileTimeUtc()
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & sc.exe stop $Service | Set-Content -LiteralPath (Join-Path $Stage 'saved-inflight-stop.txt') -Encoding UTF8
    if($LASTEXITCODE) {throw 'Ordinary SCM stop failed; no forced unload was attempted.'}
    $drained=Finish-RawSavedCapture $capture
    $watch.Stop()
    $overlapped=$drained.requestTime -lt $stopBegin -and $drained.copyEnd -gt $stopBegin
    $controller=Get-Service -Name $Service # 原生停止尚可能正在进入卸载尾声，不重复发送 stop。
    try {$controller.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(10))} finally {$controller.Dispose()}
    $report.savedStackUnload=[pscustomobject]@{mode=$(if($overlapped){'scm_stop_overlapped_saved_context_request'}else{'normal_scm_stop_after_completed_saved_capture'});elapsedMs=$watch.ElapsedMilliseconds;requestBeforeStop=($drained.requestTime -lt $stopBegin);actualCopyAfterStop=($drained.copyEnd -gt $stopBegin);inFlightDrainCovered=$overlapped;frames=$drained.frames;ntStatus=$drained.ntStatus;shutdownCancellationCovered=$false}
} finally {
    if($fixture -and !$fixture.HasExited) {[IO.File]::WriteAllText($stop,'stop');if(!$fixture.WaitForExit(5000)){throw 'Owned exit fixture is still active; not forcibly terminated.'}}
    if($capture) {if(!$capture.process.HasExited){[void]$capture.process.WaitForExit(12000)};$capture.process.Dispose()}
    if($fixture) {$fixture.Dispose()}
}
