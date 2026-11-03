param(
    [Parameter(Mandatory=$true)][string]$Cli,
    [Parameter(Mandatory=$true)][string]$Fixture64,
    [Parameter(Mandatory=$true)][string]$Fixture32,
    [Parameter(Mandatory=$true)][string]$ReportRoot
)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7'){throw 'Wrong guest; no service operation was performed'}
foreach($p in @($Cli,$Fixture64,$Fixture32)){if(!(Test-Path -LiteralPath $p -PathType Leaf)){throw "Missing input: $p"}}
if(Test-Path -LiteralPath $ReportRoot){throw 'Report directory exists'}
New-Item -ItemType Directory -Path $ReportRoot | Out-Null
$driverPath='C:\Users\Administrator\Desktop\Ksword-nice\KswordARK.sys'
$expectedSha='266EB921B5D3238901145898295C25ABC1F5DF52B8BF6D4FA99E1C5DF512F2AE'
$record=[ordered]@{computer=$env:COMPUTERNAME; driverPath=$driverPath; baseline=$null; start=$null; runs=@(); final=$null; errors=@()}
$startedHere=$false
$exitCode=1
function InvokeSc([string[]]$ScArgs){
    # Windows PowerShell may wrap native stderr in ErrorRecord; keep the
    # complete output and numeric exit even when the service refuses to start.
    $previous=$ErrorActionPreference;$ErrorActionPreference='Continue'
    try {$output=@(& sc.exe @ScArgs 2>&1 | ForEach-Object { $_.ToString() });$code=$LASTEXITCODE}
    finally {$ErrorActionPreference=$previous}
    return [ordered]@{exitCode=$code;output=$output}
}
function ServiceSnapshot {
    $d=Get-CimInstance Win32_SystemDriver -Filter "Name='KswordARK'"
    if(!$d){throw 'KswordARK service is missing'}
    $hash=if(Test-Path -LiteralPath $driverPath -PathType Leaf){(Get-FileHash -LiteralPath $driverPath -Algorithm SHA256).Hash}else{$null}
    $query=InvokeSc -ScArgs @('query','KswordARK')
    $device=[KswordR0ReadProbe]::CreateFile('\\.\KswordARKLog',0,3,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
    $deviceError=[Runtime.InteropServices.Marshal]::GetLastWin32Error();$opened=($device -ne [IntPtr](-1))
    if($opened){[void][KswordR0ReadProbe]::CloseHandle($device)}
    return [ordered]@{state=$d.State;startMode=$d.StartMode;imagePath=$d.PathName;sha256=$hash;
        scExit=$query.exitCode;scQuery=$query.output;deviceOpened=$opened;deviceOpenError=$(if($opened){0}else{$deviceError})}
}
function Quote([string]$Value){
    if($Value -notmatch '[\s"]'){return $Value}
    $Value=[regex]::Replace($Value,'(\\*)"','$1$1\"')
    $Value=[regex]::Replace($Value,'(\\+)$','$1$1')
    return '"'+$Value+'"'
}
$source=@'
using System;
using System.Runtime.InteropServices;
public static class KswordR0ReadProbe {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr CreateFile(string path, uint access, uint share, IntPtr sec, uint creation, uint flags, IntPtr template);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
}
'@
Add-Type -TypeDefinition $source
try {
    $record.baseline=ServiceSnapshot
    if($record.baseline.state -ne 'Stopped' -or $record.baseline.startMode -ne 'Manual' -or
        $record.baseline.sha256 -ne $expectedSha -or $record.baseline.imagePath -ne ('\??\'+$driverPath) -or
        $record.baseline.deviceOpened){throw 'Unexpected driver baseline; refused to start'}
    $others=@(Get-Process -Name 'KswordCLI','Ksword5.1','ApiFixture32','ApiFixture64' -ErrorAction SilentlyContinue)
    if($others.Count){throw 'Other KSword controller or test fixture is active; refused to start'}
    $disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    if($disk.FreeSpace -lt 32MB){throw "Insufficient guest space before starting driver: $($disk.FreeSpace)"}
    $record.start=InvokeSc -ScArgs @('start','KswordARK')
    if($record.start.exitCode -ne 0){throw "Driver start failed with sc.exe exit $($record.start.exitCode); no targets were started"}
    $startedHere=$true
    for($i=0;$i -lt 100;$i++){$snapshot=ServiceSnapshot;if($snapshot.state -eq 'Running'){break};Start-Sleep -Milliseconds 100}
    $record.start.after=$snapshot
    if($snapshot.state -ne 'Running' -or !$snapshot.deviceOpened){throw 'Driver was started but service/device not ready'}
    foreach($arch in @('x64','x86')) {
        $fixture=if($arch -eq 'x64'){$Fixture64}else{$Fixture32}
        $root=Join-Path $ReportRoot $arch;New-Item -ItemType Directory -Path $root | Out-Null
        $target=Start-Process -FilePath $fixture -ArgumentList (Quote $root) -WindowStyle Hidden -PassThru
        try {
            for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath (Join-Path $root 'ready'));$i++){Start-Sleep -Milliseconds 50}
            if($target.HasExited -or !(Test-Path -LiteralPath (Join-Path $root 'ready'))){throw "$arch owned fixture failed to start"}
            $identity=Get-CimInstance Win32_Process -Filter "ProcessId=$($target.Id)"
            if(!$identity -or $identity.ExecutablePath -ine $fixture){throw "$arch fixture identity mismatch"}
            $captureArgs=@('monitor','api','capture','--pid',[string]$target.Id,'--duration-ms','2000','--categories','file,registry',
                '--raw','0','--auto-children','0','--r0-inject','1','--limit','20000','--confirm','--json')
            $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Cli
            $info.Arguments=($captureArgs | ForEach-Object {Quote $_}) -join ' ';$info.UseShellExecute=$false;$info.CreateNoWindow=$true
            $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
            $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
            $child=[Diagnostics.Process]::Start($info);$stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
            try {
                if(!$child.WaitForExit(90000)){$child.Kill();$child.WaitForExit();throw "$arch CLI timed out"}
                $raw=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult();$code=$child.ExitCode
            } finally {$child.Dispose()}
            [IO.File]::WriteAllText((Join-Path $root 'capture.json'),$raw,[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText((Join-Path $root 'capture.stderr.txt'),$err,[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText((Join-Path $root 'capture.exit.txt'),[string]$code)
            $current=Get-CimInstance Win32_Process -Filter "ProcessId=$($target.Id)"
            if(!$current -or $current.CreationDate -ne $identity.CreationDate -or $current.ExecutablePath -ine $fixture){throw "$arch fixture changed during capture"}
            if(@(0,6) -notcontains $code){throw "$arch R0 capture failed with exit $code; see capture.json and stderr"}
            $data=($raw | ConvertFrom-Json).data
            $process=@($data.processes | Where-Object {$_.pid -eq $target.Id})
            $business=@($data.events | Where-Object {$_.pid -eq $target.Id -and $_.eventKind -eq 0 -and $_.api -eq 'WriteFile'})
            if($data.injectionBackendRequested -ne 'r0' -or $data.reusedResident -or !$data.cleanupComplete -or !$data.stopWritten -or
                !$data.completedRequestedInterval -or $process.Count -ne 1 -or !$process[0].hooksInstalled -or !$process[0].hooksRemoved -or
                !$process[0].coverageComplete -or $process[0].coverageStale -or $business.Count -eq 0){throw "$arch R0 evidence incomplete; see capture.json"}
            $record.runs+=@([ordered]@{architecture=$arch;pid=$target.Id;creation=$identity.CreationDate.ToString('o');exitCode=$code;
                backend=$data.injectionBackendRequested;reusedResident=$data.reusedResident;writeEvents=$business.Count;
                agentDropped=$process[0].agentDroppedCount;bufferDropped=$data.bufferDroppedCount;cleanupComplete=$data.cleanupComplete})
        } finally {
            [IO.File]::WriteAllText((Join-Path $root 'stop'),'stop')
            if(!$target.WaitForExit(15000)){throw "$arch owned fixture did not exit; driver state must be checked"}
            $target.Refresh();if($target.ExitCode -ne 0){throw "$arch owned fixture exited $($target.ExitCode)"};$target.Dispose()
        }
    }
    $exitCode=0
} catch {
    $record.errors+=@($_ | Out-String)
} finally {
    if($startedHere){
        try {
            $others=@(Get-Process -Name 'KswordCLI','Ksword5.1','ApiFixture32','ApiFixture64' -ErrorAction SilentlyContinue)
            if($others.Count){throw 'KSword controller or owned fixture still active; refusing to stop driver'}
            $record.stop=InvokeSc -ScArgs @('stop','KswordARK')
            for($i=0;$i -lt 100;$i++){$snapshot=ServiceSnapshot;if($snapshot.state -eq 'Stopped'){break};Start-Sleep -Milliseconds 100}
        } catch {$record.errors+=@($_ | Out-String);$exitCode=1}
    }
    try {
        $record.final=ServiceSnapshot
        if($record.baseline -and ($record.final.state -ne 'Stopped' -or $record.final.startMode -ne $record.baseline.startMode -or
            $record.final.sha256 -ne $record.baseline.sha256 -or $record.final.deviceOpened)){
            $record.errors+=@('Final service/device state does not match stopped baseline');$exitCode=1
        }
    } catch {$record.errors+=@($_ | Out-String);$exitCode=1}
    [IO.File]::WriteAllText((Join-Path $ReportRoot 'summary.json'),($record | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
    Write-Output "R0_GUEST_RESULT=$exitCode"
}
exit $exitCode
