param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCliSha256
)

$ErrorActionPreference = 'Stop'
$null = Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WaitingModuleProcessIdentity {
    [StructLayout(LayoutKind.Sequential)] public struct FILETIME { public uint Low; public uint High; }
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetProcessTimes(IntPtr process, out FILETIME creation, out FILETIME exit, out FILETIME kernel, out FILETIME user);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
}
'@
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$release = Join-Path $repo 'Ksword5.1\x64\Release'
$cli = Join-Path $release 'KswordCLI.exe'
$child = Join-Path $release 'ActionAnalyzeWaitingModuleChild.exe'
$dll = Join-Path $release 'ActionAnalyzeWaitingModule.dll'
$work = Join-Path $repo 'tools\action_analyze_validation\waiting_module_event\run'
$logRoot = if ($env:KSWORD_WAITING_MODULE_LOG_DIR) { $env:KSWORD_WAITING_MODULE_LOG_DIR } `
    else { Join-Path $repo '.codex-build-logs\waiting-module-event' }

if (!(Test-Path -LiteralPath $cli) -or !(Test-Path -LiteralPath $child) -or !(Test-Path -LiteralPath $dll)) {
    throw 'The unified Release CLI and both owned fixture artifacts must already exist. This script never builds.'
}
$actualCliSha = (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash
if ($actualCliSha -ne $ExpectedCliSha256.ToUpperInvariant()) {
    throw "CLI hash mismatch: expected $ExpectedCliSha256, actual $actualCliSha"
}
if (Test-Path -LiteralPath $work) { throw "Fixed run directory already exists: $work" }
New-Item -ItemType Directory -Path $work | Out-Null
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$log = Join-Path $logRoot 'waiting-module-event.log'
$receipt = Join-Path $logRoot 'waiting-module-event-receipt.json'
$prefix = 'Local\KSwordWaitingModule-' + [guid]::NewGuid().ToString('N')
$readyName = "$prefix-ready"
$loadName = "$prefix-load"
$completedName = "$prefix-completed"
$releaseName = "$prefix-release"
$resultPath = Join-Path $work 'counter.txt'
$ready = $load = $completed = $release = $null
$target = $controller = $null
$checks = [System.Collections.Generic.List[object]]::new()
$failure = $null
$started = [DateTime]::UtcNow

function Assert-Check([bool]$condition, [string]$name, [object]$evidence = $null) {
    $checks.Add([ordered]@{ name = $name; passed = $condition; evidence = $evidence })
    if (!$condition) { throw "FAIL: $name; evidence=$($evidence | ConvertTo-Json -Compress -Depth 12)" }
}

function Read-Frame([string]$expectedType, [string]$expectedId, [int]$timeoutSeconds = 15) {
    $task = $script:controller.StandardOutput.ReadLineAsync()
    if (!$task.Wait([TimeSpan]::FromSeconds($timeoutSeconds))) { throw "Timed out waiting for $expectedType/$expectedId" }
    $line = $task.Result
    if ($null -eq $line) { throw "CLI stdout closed while waiting for $expectedType/$expectedId" }
    Add-Content -LiteralPath $script:log -Encoding utf8 -Value "RX $line"
    $frame = $line | ConvertFrom-Json -AsHashtable
    Assert-Check ($frame.type -eq $expectedType) "frame type $expectedType" $frame.type
    if ($expectedId) { Assert-Check ($frame.requestId -eq $expectedId) "request id $expectedId" $frame.requestId }
    return $frame
}

function Send-Request([string]$id, [string]$method, [hashtable]$params = @{}, [hashtable]$expected = $null, [string]$type = 'response') {
    $request = [ordered]@{ schemaVersion = 1; requestId = $id; method = $method; session = $script:session; params = $params }
    if ($null -ne $expected) { $request.expected = $expected }
    $line = $request | ConvertTo-Json -Compress -Depth 32
    Add-Content -LiteralPath $script:log -Encoding utf8 -Value "TX $line"
    $script:controller.StandardInput.WriteLine($line)
    $script:controller.StandardInput.Flush()
    return Read-Frame $type $id
}

try {
    $cliInfo = Get-Item -LiteralPath $cli
    $childInfo = Get-Item -LiteralPath $child
    $dllInfo = Get-Item -LiteralPath $dll
    $identity = [ordered]@{
        startedUtc = $started.ToString('o')
        cli = [ordered]@{ path = $cli; sha256 = $actualCliSha; length = $cliInfo.Length; lastWriteUtc = $cliInfo.LastWriteTimeUtc.ToString('o') }
        child = [ordered]@{ path = $child; sha256 = (Get-FileHash $child -Algorithm SHA256).Hash; length = $childInfo.Length }
        dll = [ordered]@{ path = $dll; sha256 = (Get-FileHash $dll -Algorithm SHA256).Hash; length = $dllInfo.Length }
        scope = 'single explicit image site; waitForModule event path only; no GUI, no build, no pauseOnArm'
    }
    Set-Content -LiteralPath $log -Encoding utf8 -Value ($identity | ConvertTo-Json -Depth 8)
    $ready = [System.Threading.EventWaitHandle]::new($false, [System.Threading.EventResetMode]::AutoReset, $readyName)
    $load = [System.Threading.EventWaitHandle]::new($false, [System.Threading.EventResetMode]::AutoReset, $loadName)
    $completed = [System.Threading.EventWaitHandle]::new($false, [System.Threading.EventResetMode]::AutoReset, $completedName)
    $release = [System.Threading.EventWaitHandle]::new($false, [System.Threading.EventResetMode]::AutoReset, $releaseName)

    $env:KSWORD_WAITING_MODULE_EVENTS = $prefix
    $env:KSWORD_WAITING_MODULE_PATH = $dll
    $env:KSWORD_WAITING_MODULE_RESULT = $resultPath
    $target = Start-Process -FilePath $child -PassThru -NoNewWindow
    Assert-Check $ready.WaitOne(10000) 'owned child reached the pre-load wait'
    Assert-Check (!(Test-Path -LiteralPath $resultPath)) 'counter result absent before module load'

    $processHandle = [WaitingModuleProcessIdentity]::OpenProcess(0x1000, $false, [uint32]$target.Id)
    if ($processHandle -eq [IntPtr]::Zero) { throw "OpenProcess identity failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    try {
        $created = New-Object WaitingModuleProcessIdentity+FILETIME
        $exited = New-Object WaitingModuleProcessIdentity+FILETIME
        $kernelTime = New-Object WaitingModuleProcessIdentity+FILETIME
        $userTime = New-Object WaitingModuleProcessIdentity+FILETIME
        if (![WaitingModuleProcessIdentity]::GetProcessTimes($processHandle, [ref]$created, [ref]$exited, [ref]$kernelTime, [ref]$userTime)) {
            throw "GetProcessTimes identity failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        $creation = ([uint64]$created.High -shl 32) -bor [uint64]$created.Low
    }
    finally { [void][WaitingModuleProcessIdentity]::CloseHandle($processHandle) }
    $sitesPath = Join-Path $work 'sites.json'
    $sites = @{ schemaVersion = 1; sites = @(@{ pid = $target.Id; creationFileTime = $creation; module = $dll; exactExport = 'WaitingModuleEntry' }) }
    [System.IO.File]::WriteAllText($sitesPath, ($sites | ConvertTo-Json -Compress -Depth 8), [System.Text.UTF8Encoding]::new($false))
    $controller = [System.Diagnostics.Process]::new()
    $controller.StartInfo.FileName = $cli
    $controller.StartInfo.WorkingDirectory = $release
    $controller.StartInfo.UseShellExecute = $false
    $controller.StartInfo.CreateNoWindow = $true
    $controller.StartInfo.RedirectStandardInput = $true
    $controller.StartInfo.RedirectStandardOutput = $true
    $controller.StartInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    foreach ($arg in @('analyze','execution-group','session','--sites',$sitesPath,'--confirm','--disposition','resume-detach','--input','jsonl','--backend','r3')) {
        [void]$controller.StartInfo.ArgumentList.Add($arg)
    }
    [void]$controller.Start()
    $hello = Read-Frame 'hello' $null
    $script:session = $hello.result.session
    $collectionId = $hello.result.control.collectionId
    Assert-Check (![string]::IsNullOrWhiteSpace($collectionId)) 'CLI created the explicit single-member collection' $collectionId

    $waiting = $false
    $originalOwnerId = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    while ([DateTime]::UtcNow -lt $deadline) {
        $status = Send-Request ("query-{0}" -f [guid]::NewGuid().ToString('N')) 'control.query'
        $member = $status.result.members | Where-Object { $_.site.pid -eq $target.Id } | Select-Object -First 1
        if ($member -and $member.control.breakpoint.waitingForModule) {
            $waiting = $true
            $originalOwnerId = $member.owner.backendInstanceId
            break
        }
        Start-Sleep -Milliseconds 50
    }
    Assert-Check $waiting 'same owner reports waitingForModule before LoadLibrary'
    Assert-Check ($null -eq $member.control.breakpoint.address -or $member.control.breakpoint.address -eq '0') `
        'no breakpoint address is published while waiting' $member.control.breakpoint.address

    Assert-Check $load.Set() 'released the fixture to call LoadLibrary exactly once'
    $armed = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    while ([DateTime]::UtcNow -lt $deadline) {
        $status = Send-Request ("query-{0}" -f [guid]::NewGuid().ToString('N')) 'control.query'
        $member = $status.result.members | Where-Object { $_.site.pid -eq $target.Id } | Select-Object -First 1
        $binding = $member.control.breakpoint
        if ($binding -and !$binding.waitingForModule -and $binding.state -eq 1 -and $binding.moduleBase -ne '0') { $armed = $true; break }
        if ($member.stopToken) { break }
        Start-Sleep -Milliseconds 50
    }
    Assert-Check $armed 'same owner transitions from waiting to armed with event module base' $binding

    $hit = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    while ([DateTime]::UtcNow -lt $deadline) {
        $status = Send-Request ("query-{0}" -f [guid]::NewGuid().ToString('N')) 'control.query'
        $member = $status.result.members | Where-Object { $_.site.pid -eq $target.Id } | Select-Object -First 1
        if ($member.stopToken -and $member.control.breakpointHit) { $hit = $true; break }
        Start-Sleep -Milliseconds 50
    }
    Assert-Check $hit 'DLL export execution reaches the actual bound breakpoint' $member.control.breakpointHit
    Assert-Check ($member.owner.backendInstanceId -eq $originalOwnerId) 'owner identity remains unchanged from the waiting state' $originalOwnerId
    $continued = Send-Request 'continue/1' 'control.continue' @{ scope = 'selected' } `
        @{ collectionId = $collectionId; stops = @($member.stopToken) }
    Assert-Check ($continued.result.operation.outcomes.Count -eq 1 -and $continued.result.operation.outcomes[0].actionAttempted) `
        'one explicit Continue was sent to the original owner' $continued.result.operation.outcomes
    Assert-Check $completed.WaitOne(10000) 'continued export returned and target recorded its counter'
    $counter = [int](Get-Content -LiteralPath $resultPath -Raw).Trim()
    Assert-Check ($counter -eq 1) 'self-owned DLL business counter incremented exactly once' $counter

    $shutdown = Send-Request 'shutdown' 'controller.shutdown'
    Assert-Check ($shutdown.result.clean -and $shutdown.result.state -eq 'closed') 'original owner closed clean after Continue'
    $summary = Read-Frame 'summary' $null
    Assert-Check ($summary.result.exitCode -eq 0 -and $summary.result.control.clean) 'formal CLI shutdown summary is clean with exit 0'
    $controller.StandardInput.Close()
    if (!$controller.WaitForExit(10000)) { throw 'CLI did not exit after clean shutdown' }
    Assert-Check ($controller.ExitCode -eq 0) 'formal CLI exited naturally with code 0' $controller.ExitCode
    Assert-Check $release.Set() 'released target to unload the DLL only after original owner detached'
    if (!$target.WaitForExit(10000)) { throw 'fixture target did not exit after owner detach' }
    Assert-Check ($target.ExitCode -eq 0) 'target naturally exited with code 0 after original owner cleanup' $target.ExitCode
    $failure = $null
}
catch {
    $failure = $_.Exception.Message
    Add-Content -LiteralPath $log -Encoding utf8 -Value "FAILURE=$failure"
}
finally {
    if ($controller -and !$controller.HasExited) {
        try { $controller.StandardInput.Close() } catch {}
        try { if (!$controller.WaitForExit(3000)) { $controller.Kill(); $controller.WaitForExit() } } catch {}
    }
    if ($target -and !$target.HasExited) {
        try { $target.Kill(); $target.WaitForExit() } catch {}
    }
    foreach ($waitHandle in @($release, $completed, $load, $ready)) { if ($waitHandle) { $waitHandle.Dispose() } }
    Remove-Item Env:\KSWORD_WAITING_MODULE_EVENTS, Env:\KSWORD_WAITING_MODULE_PATH, Env:\KSWORD_WAITING_MODULE_RESULT -ErrorAction SilentlyContinue
    $cleanup = [ordered]@{}
    foreach ($path in @($work, $child, $dll)) {
        $cleanup[$path] = [ordered]@{ exists = Test-Path -LiteralPath $path; sha256 = if (Test-Path -LiteralPath $path -PathType Leaf) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } else { $null } }
    }
    $receiptData = [ordered]@{
        startedUtc = $started.ToString('o'); finishedUtc = [DateTime]::UtcNow.ToString('o')
        expectedCliSha256 = $ExpectedCliSha256.ToUpperInvariant(); checks = @($checks)
        result = if ($failure) { 'FAIL_OR_BLOCKED' } else { 'PASS' }; failure = $failure; cleanup = $cleanup
        scope = 'single delayed LoadLibrary event; no pauseOnArm, GUI, build, cancellation or ordinary Pause replay'
    }
    $receiptData | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $receipt -Encoding utf8
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}

if ($failure) { throw $failure }
Write-Output "RESULT=PASS CHECKS=$($checks.Count) RECEIPT=$receipt"
