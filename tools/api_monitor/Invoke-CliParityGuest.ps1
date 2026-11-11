param(
    [Parameter(Mandatory=$true)][string]$Cli,
    [Parameter(Mandatory=$true)][string]$Fixture64,
    [Parameter(Mandatory=$true)][string]$Fixture32,
    [Parameter(Mandatory=$true)][string]$ReportRoot,
    [Parameter(Mandatory=$true)][string]$ExpectedComputerName
)
$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne $ExpectedComputerName -or $ExpectedComputerName -ne 'DESKTOP-D2161R7') { throw 'Wrong guest computer' }
foreach ($path in @($Cli,$Fixture64,$Fixture32)) { if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing $path" } }
if (!(Test-Path -LiteralPath (Join-Path (Split-Path -Parent $Cli) 'profiles\api_monitor_definitions.json') -PathType Leaf)) { throw 'Missing published signatures' }
if (Test-Path -LiteralPath $ReportRoot) { throw 'Report path already exists' }
New-Item -ItemType Directory -Path $ReportRoot | Out-Null
$checks=0
function Check([bool]$Value,[string]$Message) { if (!$Value) { throw $Message }; $script:checks++; Write-Output "PASS $Message" }
function Quote([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    $Value=[regex]::Replace($Value,'(\\*)"','$1$1\"')
    $Value=[regex]::Replace($Value,'(\\+)$','$1$1')
    return '"'+$Value+'"'
}
foreach($arch in @('x64','x86')) {
    $fixture=if($arch -eq 'x64') {$Fixture64} else {$Fixture32}
    $root=Join-Path $ReportRoot $arch; New-Item -ItemType Directory -Path $root | Out-Null
    $target=Start-Process -FilePath $fixture -ArgumentList ('"'+$root+'"') -WindowStyle Hidden -PassThru
    try {
        for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath (Join-Path $root 'ready'));$i++){Start-Sleep -Milliseconds 50}
        Check (!$target.HasExited -and (Test-Path -LiteralPath (Join-Path $root 'ready'))) "$arch owned fixture ready"
        $identity=Get-CimInstance Win32_Process -Filter "ProcessId=$($target.Id)"
        if(!$identity -or $identity.ExecutablePath -ine $fixture) { throw "$arch fixture executable identity mismatch" }
        $fixtureModule=(Get-Process -Id $target.Id -ErrorAction Stop).MainModule
        if(!$fixtureModule -or $fixtureModule.FileName -ine $fixture -or $fixtureModule.ModuleMemorySize -le 0) {
            throw "$arch fixture image range unavailable"
        }
        [uint64]$fixtureBase=$fixtureModule.BaseAddress.ToInt64()
        [uint64]$fixtureSize=$fixtureModule.ModuleMemorySize
        $ini=Join-Path $root 'stack.ini'
        [IO.File]::WriteAllText($ini,"[monitor]`r`ncapture_call_stack=1`r`n",[Text.Encoding]::Unicode)
        $filter=Join-Path $root 'winapi-filter.cfg'
        $filterJson='{"version":2,"rules":[{"module":"KernelBase.dll","function":"","pre":true,"post":false,"preAllow":false,"postAllow":false},{"module":"KernelBase.dll","function":"CreateFileW","pre":false,"post":false,"preAllow":true,"postAllow":false}]}'
        [IO.File]::WriteAllText($filter,$filterJson,[Text.UTF8Encoding]::new($false))
        foreach($mode in @('baseline','filtered','cfg_allow','cfg_override','stack')) {
            $args=@('monitor','api','capture','--pid',[string]$target.Id,'--duration-ms','2000',
                '--categories','file,registry','--raw','1','--raw-modules','version.dll','--limit','20000',
                '--options-file',$ini,'--call-stack',$(if($mode -eq 'stack'){'1'}else{'0'}),'--timeline','1','--signatures','1','--confirm','--json')
            if($mode -eq 'filtered') { $args+=@('--pre-exclude-apis','KernelBase.dll!WriteFile','--post-exclude-apis','KernelBase.dll!CreateFileW') }
            if($mode -in @('cfg_allow','cfg_override')) { $args+=@('--filter-file',$filter) }
            if($mode -eq 'cfg_override') { $args+=@('--pre-exclude-apis','KernelBase!CreateFileW') }
            $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Cli
            $info.Arguments=($args | ForEach-Object { Quote $_ }) -join ' '
            $info.UseShellExecute=$false;$info.CreateNoWindow=$true
            $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
            $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
            $child=[Diagnostics.Process]::Start($info)
            $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
            try {
                if(!$child.WaitForExit(90000)) { $child.Kill();$child.WaitForExit();throw "$arch $mode controller timed out" }
                $raw=$stdout.GetAwaiter().GetResult();$errorText=$stderr.GetAwaiter().GetResult();$code=$child.ExitCode
            } finally { $child.Dispose() }
            [IO.File]::WriteAllText((Join-Path $root "$mode.json"),$raw,[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText((Join-Path $root "$mode.stderr.txt"),$errorText,[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText((Join-Path $root "$mode.exit.txt"),[string]$code)
            Check (@(0,6) -contains $code) "$arch $mode capture status: $code"
            $data=($raw | ConvertFrom-Json).data
            $expectedStack=if($mode -eq 'stack'){'1'}else{'0'}
            Check ($data.options.capture_call_stack -eq $expectedStack) "$arch $mode explicit call-stack setting"
            Check ($data.cleanupComplete -and $data.stopWritten -and @($data.processes | Where-Object { $_.pid -eq $target.Id -and $_.hooksRemoved }).Count -eq 1) "$arch $mode hooks removed"
            Check ([uint64]$data.invalidPacketCount -eq 0 -and [uint64]$data.bufferDroppedCount -eq 0) "$arch $mode no reported buffer loss"
            Check (@($data.processes | Where-Object { [uint64]$_.agentDroppedCount -ne 0 -or !$_.coverageComplete -or $_.coverageStale }).Count -eq 0) "$arch $mode no Agent drops and coverage snapshot current"
            $events=@($data.events)
            $calls=@($events | Where-Object { $_.eventKind -eq 0 -and $_.category -ne 6 })
            $writes=@($calls | Where-Object { $_.module -eq 'KernelBase' -and $_.api -ceq 'WriteFile' })
            $creates=@($calls | Where-Object { $_.module -eq 'KernelBase' -and $_.api -ceq 'CreateFileW' })
            if($mode -eq 'stack') {
                Check (@($calls | Where-Object { $_.api -eq 'WriteFile' -and $_.callStackAvailable -and @($_.callStack).Count -ge 1 -and @($_.callStack).Count -le 8 }).Count -gt 0) "$arch explicit stack enabled with bounded frames"
                $fixtureFrames=@($calls | Where-Object { $_.api -eq 'WriteFile' -and $_.callStackAvailable } | ForEach-Object {
                    foreach($frame in $_.callStack) {
                        [uint64]$address=[Convert]::ToUInt64($frame,16)
                        if($address -ge $fixtureBase -and $address-$fixtureBase -lt $fixtureSize) { $frame }
                    }
                })
                Check ($fixtureFrames.Count -gt 0) "$arch call stack includes owned fixture image"
            } else {
                Check (@($calls | Where-Object {$_.callStackAvailable}).Count -eq 0) "$arch $mode stack disabled"
            }
            Check ($null -ne $data.timeline -and [uint64]$data.timeline.eventCount -gt 0 -and @($data.timeline.cells).Count -gt 0) "$arch $mode timeline populated"
            $sum=[uint64]0;foreach($cell in $data.timeline.cells) { $sum += [uint64]$cell.count }
            Check ($sum -eq [uint64]$data.timeline.eventCount) "$arch $mode timeline bucket totals"
            Check (@($events | Where-Object { $_.category -eq 6 -and $_.api -eq 'HooksRemoved' }).Count -gt 0) "$arch $mode control events preserved"
            Check (@($calls | Where-Object { $_.rawAbi -and $_.rawAbi.architecture -eq $arch }).Count -gt 0) "$arch $mode raw ABI words"
            Check (@($calls | Where-Object { $_.declarationCatalogMatchesAgent -eq $true -and $_.declaration }).Count -gt 0) "$arch $mode same-hash declarations"
            if($mode -in @('baseline','stack')) {
                Check ($writes.Count -gt 0 -and $creates.Count -gt 0) "$arch baseline typed calls present"
                Check ([uint64]$data.preFilteredCount -eq 0 -and [uint64]$data.postFilteredRetainedCount -eq 0) "$arch baseline no filtering"
                Check ([uint64]$data.timeline.eventCount -eq $calls.Count) "$arch baseline timeline matches calls"
            } elseif($mode -eq 'filtered') {
                Check ($writes.Count -eq 0 -and [uint64]$data.preFilteredCount -gt 0) "$arch prefilter rejects WriteFile"
                Check ($creates.Count -eq 0 -and [uint64]$data.postFilteredRetainedCount -gt 0) "$arch postfilter hides CreateFileW"
                Check ([uint64]$data.timeline.eventCount -eq $calls.Count + [uint64]$data.postFilteredRetainedCount) "$arch timeline includes postfiltered calls"
            } elseif($mode -eq 'cfg_allow') {
                Check ($writes.Count -eq 0 -and [uint64]$data.preFilteredCount -gt 0) "$arch config prefilter rejects module calls"
                Check ($creates.Count -gt 0) "$arch config allows function exception"
                Check ([uint64]$data.postFilteredRetainedCount -eq 0 -and [uint64]$data.timeline.eventCount -eq $calls.Count) "$arch config timeline matches retained calls"
            } else {
                Check ($writes.Count -eq 0 -and $creates.Count -eq 0 -and [uint64]$data.preFilteredCount -gt 0) "$arch explicit exclusion overrides config allow"
                Check ([uint64]$data.postFilteredRetainedCount -eq 0 -and [uint64]$data.timeline.eventCount -eq $calls.Count) "$arch override timeline matches retained calls"
            }
        }
    } finally {
        [IO.File]::WriteAllText((Join-Path $root 'stop'),'stop')
        if (!$target.WaitForExit(15000)) { throw "$arch owned fixture failed to exit" }
        $target.Refresh();if($target.ExitCode -ne 0){throw "$arch owned fixture exited $($target.ExitCode)"};$target.Dispose()
    }
}
Write-Output "CLI_PARITY_GUEST_PASS checks=$checks"
