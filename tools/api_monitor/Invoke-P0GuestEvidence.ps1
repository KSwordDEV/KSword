param(
    [Parameter(Mandatory=$true)][string]$Cli,
    [Parameter(Mandatory=$true)][string]$Fixture64,
    [Parameter(Mandatory=$true)][string]$Fixture32,
    [Parameter(Mandatory=$true)][string]$ReportRoot,
    [Parameter(Mandatory=$true)][string]$ExpectedComputerName
)
$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne $ExpectedComputerName) { throw 'Wrong guest computer; no process was started.' }
foreach ($path in @($Cli,$Fixture64,$Fixture32)) { if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing required file: $path" } }
if (Test-Path -LiteralPath $ReportRoot) { throw 'Evidence directory already exists.' }
New-Item -ItemType Directory -Path $ReportRoot | Out-Null
$assertions = 0
function Check([bool]$Value,[string]$Message) {
    if (!$Value) { throw $Message }
    $script:assertions++
    Write-Output "PASS $Message"
}
function Quote([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    $Value=[regex]::Replace($Value,'(\\*)"','$1$1\"')
    $Value=[regex]::Replace($Value,'(\\+)$','$1$1')
    return '"'+$Value+'"'
}
$results = @()
foreach ($arch in @('x64','x86')) {
    $fixture = if ($arch -eq 'x64') { $Fixture64 } else { $Fixture32 }
    $root=Join-Path $ReportRoot $arch
    New-Item -ItemType Directory -Path $root | Out-Null
    $target=Start-Process -FilePath $fixture -ArgumentList (Quote $root) -WindowStyle Hidden -PassThru
    try {
        for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath (Join-Path $root 'ready'));$i++) { Start-Sleep -Milliseconds 50 }
        Check (!$target.HasExited -and (Test-Path -LiteralPath (Join-Path $root 'ready'))) "$arch fixture ready"
        $previousSession=''
        $optionsPath=Join-Path $root 'stack-options.ini'
        [IO.File]::WriteAllText($optionsPath,"[monitor]`r`ncapture_call_stack=1`r`n",[Text.Encoding]::Unicode)
        foreach($run in 1..2) {
            $args=@('monitor','api','capture','--pid',([string]$target.Id),'--duration-ms','2000',
                '--categories','file,registry','--raw','1','--raw-modules','version.dll',
                '--limit','20000','--confirm','--json')
            if ($run -eq 2) { $args += @('--options-file',$optionsPath) }
            $info=[Diagnostics.ProcessStartInfo]::new()
            $info.FileName=$Cli; $info.Arguments=($args | ForEach-Object { Quote $_ }) -join ' '
            $info.UseShellExecute=$false; $info.CreateNoWindow=$true
            $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
            $info.StandardOutputEncoding=[Text.Encoding]::UTF8; $info.StandardErrorEncoding=[Text.Encoding]::UTF8
            $child=[Diagnostics.Process]::Start($info)
            $stdout=$child.StandardOutput.ReadToEndAsync(); $stderr=$child.StandardError.ReadToEndAsync()
            try {
                if (!$child.WaitForExit(90000)) { $child.Kill(); $child.WaitForExit(); throw "$arch controller timed out" }
                $output=$stdout.GetAwaiter().GetResult(); $errorText=$stderr.GetAwaiter().GetResult(); $code=$child.ExitCode
            } finally { $child.Dispose() }
            [IO.File]::WriteAllText((Join-Path $root "capture-$run.json"),$output,[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText((Join-Path $root "capture-$run.stderr.txt"),$errorText,[Text.UTF8Encoding]::new($false))
            Check (@(0,6) -contains $code) "$arch controller returned capture status"
            $capture=$output | ConvertFrom-Json
            $data=$capture.data; $proc=@($data.processes | Where-Object { $_.pid -eq $target.Id })
            Check ($proc.Count -eq 1 -and $proc[0].hooksInstalled -and $proc[0].hooksRemoved -and $data.cleanupComplete -and $data.stopWritten) "$arch hooks installed and removed"
            Check ($proc[0].coverageComplete -and !$proc[0].coverageStale -and $data.completedRequestedInterval) "$arch coverage complete and requested interval captured"
            Check ([uint64]$data.invalidPacketCount -eq 0 -and [uint64]$data.bufferDroppedCount -eq 0 -and [uint64]$proc[0].agentDroppedCount -eq 0) "$arch no reported packet or buffer loss"
            $events=@($data.events | Where-Object { $_.pid -eq $target.Id -and $_.eventKind -eq 0 })
            $raw=@($events | Where-Object { $_.api -eq 'GetFileVersionInfoSizeW' -and $_.detail -match "params=raw abi=$arch" })
            Check ($raw.Count -gt 0) "$arch real raw ABI events captured"
            Check (@($raw | Where-Object { $_.detail -match 'caller=0x[0-9a-fA-F]+' -and $_.detail -match 'stackSlots=\[' }).Count -gt 0) "$arch caller and raw stack slots captured"
            Check (@($events | Where-Object { $_.api -eq 'WriteFile' }).Count -gt 0) "$arch typed WriteFile events captured"
            $stackEvents=@($events | Where-Object { $_.api -eq 'WriteFile' -and $_.callStackAvailable -and @($_.callStack).Count -gt 0 })
            if ($run -eq 1) {
                Check ($stackEvents.Count -eq 0) "$arch call stack disabled by default"
            } else {
                Check ($data.options.capture_call_stack -eq '1') "$arch call stack option imported"
                Check ($stackEvents.Count -gt 0 -and @($stackEvents | Where-Object { @($_.callStack).Count -le 8 -and $_.callStack[0] -match '^0x[0-9a-fA-F]+$' }).Count -gt 0) "$arch strong event carries bounded stack addresses"
            }
            $times=@($events | ForEach-Object {[uint64]$_.timestampFileTime} | Where-Object {$_ -ne 0} | Sort-Object -Unique)
            Check ($times.Count -ge 2) "$arch events span at least two timestamps"
            if ($run -gt 1) { Check ($data.reusedResident -and $data.sessionId -ne $previousSession) "$arch repeat session reuses resident agent with fresh identity" }
            $previousSession=$data.sessionId
            $results += [pscustomobject]@{architecture=$arch; run=$run; eventCount=$events.Count; rawCount=$raw.Count; callStackEvents=$stackEvents.Count;
                firstTimestamp=([string]$times[0]); lastTimestamp=([string]$times[-1]); agentDropped=$proc[0].agentDroppedCount;
                bufferDropped=$data.bufferDroppedCount; controllerExit=$code}
        }
    } finally {
        [IO.File]::WriteAllText((Join-Path $root 'stop'),'stop')
        if (!$target.WaitForExit(15000)) { throw "$arch owned fixture did not stop" }
        $target.Refresh()
        if ($target.ExitCode -ne 0) { throw "$arch owned fixture exited $($target.ExitCode)" }
        $target.Dispose()
    }
}
$summary=[pscustomobject]@{computer=$env:COMPUTERNAME; checks=$script:assertions; runs=$results;
    cliSha256=(Get-FileHash -LiteralPath $Cli -Algorithm SHA256).Hash;
    limits=@('Raw caller return address and raw stack slots are not a captured call stack; strong captured stacks may contain internal frames.',
             'Timestamp variation does not prove rendered timeline geometry or GUI interaction.',
             'This test uses owned fixture processes and does not attach to DWM.')}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ReportRoot 'summary.json') -Encoding UTF8
Write-Output "P0_GUEST_PASS checks=$script:assertions"
