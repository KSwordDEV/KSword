$help=Invoke-Cli @('help','process','telemetry','sample')
Assert ($help.Contains('--interval-ms') -and $help.Contains('ETW') -and (Invoke-Cli @('process','telemetry','sample','--help')) -eq $help) 'Telemetry help'
Assert (!(Invoke-Cli @('help','process','telemetry')).Contains('--interval-ms')) 'Telemetry group help'
foreach ($bad in @(
    @('process','telemetry','sample','--json'),
    @('process','telemetry','sample','--pid',$PID.ToString(),'--interval-ms','99','--json'),
    @('process','telemetry','sample','--pid',$PID.ToString(),'--interval-ms','30001','--json'),
    @('process','telemetry','sample','--pid',$PID.ToString(),'--network','bad','--json'),
    @('process','telemetry','sample','--pid',$PID.ToString(),'--backend','r0','--json'),
    @('process','telemetry','sample','--pid',$PID.ToString(),'--bad','1','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Telemetry parameters'}
$creation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$before=(Get-Process -Id $PID).TotalProcessorTime.Ticks
$sample=(Invoke-Cli @('process','telemetry','sample','--pid',$PID.ToString(),'--creation-time',$creation,'--interval-ms','100','--json'))|ConvertFrom-Json
$after=(Get-Process -Id $PID).TotalProcessorTime.Ticks
Assert ($sample.data.cpuKnown -and $sample.data.diskRateKnown -and $sample.data.elapsedMs -ge 100 -and !$sample.data.networkRequested -and $null -eq $sample.data.networkBytesPerSecond) 'Native bounded telemetry and disabled network'
Assert ([uint64]$sample.data.cpuBefore100ns -ge [uint64]$before -and [uint64]$sample.data.cpuAfter100ns -le [uint64]$after) 'Independent CPU cumulative bounds'
$expected=([double]([uint64]$sample.data.cpuAfter100ns-[uint64]$sample.data.cpuBefore100ns))*100/([double]$sample.data.elapsedMs*10000*$sample.data.logicalProcessors)
Assert ([Math]::Abs($expected-$sample.data.cpuPercent) -lt 0.000001) 'CPU rate uses actual elapsed interval and processor count'
$ioRate=([double]([uint64]$sample.data.ioReadBytesAfter-[uint64]$sample.data.ioReadBytesBefore)+[double]([uint64]$sample.data.ioWriteBytesAfter-[uint64]$sample.data.ioWriteBytesBefore))*1000/[double]$sample.data.elapsedMs
Assert ([Math]::Abs($ioRate-$sample.data.diskBytesPerSecond) -lt 0.000001) 'I/O rate follows actual native deltas'
Assert ((Invoke-Cli @('process','telemetry','sample','--pid',$PID.ToString(),'--interval-ms','100')).Contains('cpuKnown: true')) 'Telemetry text'
$mismatch=(Invoke-Cli @('process','telemetry','sample','--pid',$PID.ToString(),'--creation-time',([uint64]$creation+1).ToString(),'--json') 3)|ConvertFrom-Json
Assert (!$mismatch.data.target.identityMatched) 'Telemetry identity mismatch'
if ($InGuest) {
    Add-Type -TypeDefinition @'
using System; using System.IO; using System.Threading;
public static class CliTelemetryLoad {
 static Thread worker; static volatile bool stop; public static long iterations;
 public static void Start(string path) {stop=false;iterations=0;worker=new Thread(()=>{
  var bytes=new byte[4096]; using(var file=new FileStream(path,FileMode.Create,FileAccess.Write,FileShare.ReadWrite)) {
   while(!stop){double x=1;for(int i=1;i<100000;i++)x+=Math.Sqrt(i);file.Write(bytes,0,bytes.Length);file.Flush();iterations++;}
  }});worker.Start();}
 public static void Stop(){stop=true;if(worker!=null)worker.Join();}
}
'@
    $data=Join-Path $env:TEMP ('KSwordCliTelemetry-'+[Guid]::NewGuid().ToString('N')+'.bin')
    try {
        [CliTelemetryLoad]::Start($data)
        $busy=(Invoke-Cli @('process','telemetry','sample','--pid',$PID.ToString(),'--interval-ms','1000','--json'))|ConvertFrom-Json
        Assert ($busy.data.cpuPercent -gt 0 -and $busy.data.diskBytesPerSecond -gt 0 -and [CliTelemetryLoad]::iterations -gt 0) 'Actual CPU and file write workload produces nonzero rates'
    } finally {[CliTelemetryLoad]::Stop();Remove-Item -LiteralPath $data -Force -ErrorAction SilentlyContinue}
    $sessionsBefore=(& logman.exe query -ets 2>&1|Out-String)
    $network=(Invoke-Cli @('process','telemetry','sample','--pid',$PID.ToString(),'--interval-ms','1000','--network','on','--json') @(0,6))|ConvertFrom-Json
    Assert (!$network.data.networkFinalHealth.running) 'Owned network session stopped'
    $sessionsAfter=(& logman.exe query -ets 2>&1|Out-String)
    $cliSessionsBefore=@([regex]::Matches($sessionsBefore,'Ksword\.ProcessNet\.\S+')|ForEach-Object {$_.Value})
    $cliSessionsAfter=@([regex]::Matches($sessionsAfter,'Ksword\.ProcessNet\.\S+')|ForEach-Object {$_.Value})
    Assert (($cliSessionsAfter -join '|') -eq ($cliSessionsBefore -join '|')) 'Independent ETW session enumeration shows no leak'
    if ($network.data.networkRateKnown) {
        Assert ($network.data.networkHealth.running -and !$network.data.networkFinalHealth.dataLossDetected -and $network.data.networkBytesPerSecond -ge 0) 'Available network evidence has healthy running session'
    } else {Assert ($network.status -eq 'partial' -and $null -eq $network.data.networkBytesPerSecond) 'Network limitation cannot pretend measured zero'}
    $target=Start-Process -FilePath "$env:WINDIR\System32\notepad.exe" -PassThru
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Cli;$info.Arguments="process telemetry sample --pid $($target.Id) --interval-ms 3000 --json"
    $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    try {
        $sampling=[Diagnostics.Process]::Start($info);Start-Sleep -Milliseconds 200;$target.Kill();$target.WaitForExit()
        Assert ($sampling.WaitForExit(10000) -and $sampling.ExitCode -eq 3) 'Target exit while sampler waits fails promptly'
        $failed=$sampling.StandardOutput.ReadToEnd()|ConvertFrom-Json;Assert ($failed.status -eq 'failed') 'No stale rates after target exit'
    } finally {if($sampling){if(!$sampling.HasExited){$sampling.Kill()};$sampling.Dispose()};if(!$target.HasExited){$target.Kill()};$target.Dispose()}
}
