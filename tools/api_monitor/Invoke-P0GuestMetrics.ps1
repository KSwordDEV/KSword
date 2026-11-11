param(
    [Parameter(Mandatory=$true)][string]$Cli,
    [Parameter(Mandatory=$true)][string]$Fixture64,
    [Parameter(Mandatory=$true)][string]$Fixture32,
    [Parameter(Mandatory=$true)][string]$ReportRoot
)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7') { throw 'Wrong guest; no process was started.' }
foreach($file in @($Cli,$Fixture64,$Fixture32)) { if(!(Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing $file" } }
if(Test-Path -LiteralPath $ReportRoot) { throw 'Evidence directory already exists.' }
New-Item -ItemType Directory -Path $ReportRoot | Out-Null
function Quote([string]$v) {
    if($v -notmatch '[\s"]') { return $v }
    $v=[regex]::Replace($v,'(\\*)"','$1$1\"'); $v=[regex]::Replace($v,'(\\+)$','$1$1')
    return '"'+$v+'"'
}
$runs=@(); $failures=@()
foreach($arch in @('x64','x86')) {
    $fixture=if($arch -eq 'x64') {$Fixture64} else {$Fixture32}
    $root=Join-Path $ReportRoot $arch; New-Item -ItemType Directory -Path $root | Out-Null
    $target=Start-Process -FilePath $fixture -ArgumentList (Quote $root) -WindowStyle Hidden -PassThru
    try {
        for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath (Join-Path $root 'ready'));$i++){Start-Sleep -Milliseconds 50}
        if($target.HasExited -or !(Test-Path -LiteralPath (Join-Path $root 'ready'))) { throw "$arch fixture not ready" }
        $previousSession=''
        foreach($round in 1..3) {
            $arguments=@('monitor','api','capture','--pid',([string]$target.Id),'--duration-ms','10000',
                '--categories','file','--limit','100000','--confirm','--json')
            $info=[Diagnostics.ProcessStartInfo]::new(); $info.FileName=$Cli
            $info.Arguments=($arguments | ForEach-Object {Quote $_}) -join ' '
            $info.UseShellExecute=$false; $info.CreateNoWindow=$true
            $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
            $info.StandardOutputEncoding=[Text.Encoding]::UTF8; $info.StandardErrorEncoding=[Text.Encoding]::UTF8
            $child=[Diagnostics.Process]::Start($info)
            $stdout=$child.StandardOutput.ReadToEndAsync(); $stderr=$child.StandardError.ReadToEndAsync()
            try {
                Start-Sleep -Seconds 4
                $workClock=[Diagnostics.Stopwatch]::StartNew()
                [IO.File]::WriteAllText((Join-Path $root "start-$round"),'start')
                for($i=0;$i -lt 500 -and !(Test-Path -LiteralPath (Join-Path $root "done-$round"));$i++){Start-Sleep -Milliseconds 10}
                $workClock.Stop()
                $finished=Test-Path -LiteralPath (Join-Path $root "done-$round")
                if(!$child.WaitForExit(90000)) { $child.Kill(); $child.WaitForExit(); throw "$arch controller timed out; cleanup unconfirmed" }
                $output=$stdout.GetAwaiter().GetResult(); $errorText=$stderr.GetAwaiter().GetResult(); $code=$child.ExitCode
            } finally { $child.Dispose() }
            [IO.File]::WriteAllText((Join-Path $root "capture-$round.json"),$output,[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText((Join-Path $root "capture-$round.stderr.txt"),$errorText,[Text.UTF8Encoding]::new($false))
            if(!$finished) { throw "$arch workload did not complete inside capture window" }
            $capture=$output | ConvertFrom-Json; $data=$capture.data
            $observed=@(Import-Csv -LiteralPath (Join-Path $root "observed-$round.csv"))
            $proc=@($data.processes | Where-Object {$_.pid -eq $target.Id})
            if($proc.Count -ne 1) { throw "$arch missing participant" }
            $events=@($data.events | Where-Object { $_.pid -eq $target.Id -and $_.eventKind -eq 0 -and $_.api -eq 'CreateFileW' -and $_.detail -match 'metrics-(present|absent)\.dat' })
            $byThread=@{}; foreach($event in $events) { $key=[string]$event.tid; if(!$byThread.ContainsKey($key)){$byThread[$key]=[Collections.Generic.List[object]]::new()}; $byThread[$key].Add($event) }
            $seen=@{}; $matched=0; $returnMismatch=0; $statusMismatch=0; $durationMissing=0; $durationOutside=0; $shapeMismatch=0
            foreach($item in $observed) {
                $key=[string]$item.tid
                if(!$seen.ContainsKey($key)) { $seen[$key]=0 }
                $index=$seen[$key]; $seen[$key]++
                if(!$byThread.ContainsKey($key) -or $index -ge $byThread[$key].Count) { continue }
                $event=$byThread[$key][$index]; $matched++
                $success=$item.expectedSuccess -eq '1'
                if(($success -and $event.detail -notmatch 'metrics-present\.dat') -or (!$success -and $event.detail -notmatch 'metrics-absent\.dat')) { $shapeMismatch++ }
                if(!$event.returnValueAvailable -or !$event.returnValue -or $event.returnValue -notmatch '^0x[0-9a-fA-F]+$' -or
                    [Convert]::ToUInt64($event.returnValue.Substring(2),16) -ne [uint64]$item.returnValue) { $returnMismatch++ }
                $expectedStatus=if($success) {0} else {[int]$item.lastError}
                if([int]$event.resultCode -ne $expectedStatus) { $statusMismatch++ }
                if(!$event.durationAvailable -or $null -eq $event.duration100ns) { $durationMissing++ }
                elseif([uint64]$event.duration100ns -gt ([uint64]$item.elapsed100ns + 1)) { $durationOutside++ }
            }
            $row=[pscustomobject]@{architecture=$arch;round=$round;expected=$observed.Count;events=$events.Count;matched=$matched;
                targetThreads=$seen.Count;eventThreads=$byThread.Count;returnMismatch=$returnMismatch;statusMismatch=$statusMismatch;
                durationMissing=$durationMissing;durationOutside=$durationOutside;orderMismatch=$shapeMismatch;
                workloadElapsedMs=$workClock.ElapsedMilliseconds;controllerElapsedMs=$data.elapsedMs;controllerExit=$code;
                agentDropped=$proc[0].agentDroppedCount;bufferDropped=$data.bufferDroppedCount;invalidPackets=$data.invalidPacketCount;
                completed=$data.completedRequestedInterval;hooksInstalled=$proc[0].hooksInstalled;hooksRemoved=$proc[0].hooksRemoved;
                cleanupComplete=$data.cleanupComplete;reusedResident=$data.reusedResident;sessionId=$data.sessionId}
            $runs += $row
            Write-Output ($row | ConvertTo-Json -Compress)
            if($code -notin @(0,6) -or !$row.completed -or !$row.hooksInstalled -or !$row.hooksRemoved -or !$row.cleanupComplete -or
                $row.expected -ne 1600 -or $row.events -ne 1600 -or $row.matched -ne 1600 -or $row.targetThreads -ne 4 -or
                $row.returnMismatch -or $row.statusMismatch -or $row.durationMissing -or $row.durationOutside -or $row.orderMismatch -or
                [uint64]$row.agentDropped -or [uint64]$row.bufferDropped -or [uint64]$row.invalidPackets -or
                ($round -gt 1 -and (!$row.reusedResident -or $row.sessionId -eq $previousSession))) { $failures += "$arch round $round" }
            $previousSession=$data.sessionId
        }
    } finally {
        [IO.File]::WriteAllText((Join-Path $root 'stop'),'stop')
        if(!$target.WaitForExit(15000)) { throw "$arch owned fixture did not stop" }
        $target.Refresh(); if($target.ExitCode -ne 0) { throw "$arch fixture exited $($target.ExitCode)" }
        $target.Dispose()
    }
}
$summary=[pscustomobject]@{computer=$env:COMPUTERNAME;runs=$runs;failures=$failures;
    limitations=@('Target QPC wall duration includes hook overhead; event duration measures only the wrapped original API call.',
        'Each CreateFileW result is paired in per-thread call order; count/order mismatches are failures, not inferred loss causes.',
        'This bounded workload is not a guarantee for unbounded event rates or system processes.')}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ReportRoot 'summary.json') -Encoding UTF8
if($failures.Count) { throw ('Metrics comparison failed: '+($failures -join ', ')) }
Write-Output 'P0_GUEST_METRICS_PASS'
