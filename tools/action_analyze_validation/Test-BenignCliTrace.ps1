param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..'))

$ErrorActionPreference = 'Stop'
# 在正式输出目录运行自有样本，日志只保存文本证据和小型元数据。
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$release = Join-Path $root 'Ksword5.1/x64/Release'
$logs = Join-Path $root '.codex-build-logs'
$cliPath = Join-Path $release 'KswordCLI.exe'
$samplePath = Join-Path $release 'ActionAnalyzeBenignCliTrace.sample'
$tracePath = Join-Path $logs 'action-analyze-benign-provider-trace.json'
$reportPath = Join-Path $logs 'action-analyze-benign-provider-report.json'
if (Test-Path -LiteralPath $samplePath) {
    throw "Sample path is already in use: $samplePath"
}

# 启动指定程序并捕获标准输出。参数列表保持原样传给子进程。
function New-ChildStartInfo([string]$FilePath, [string[]]$Arguments) {
    $settings = [Diagnostics.ProcessStartInfo]::new($FilePath) # 只用于本次子进程。
    $settings.UseShellExecute = $false
    $settings.CreateNoWindow = $true
    $settings.RedirectStandardOutput = $true
    $settings.StandardOutputEncoding = [Text.Encoding]::UTF8
    foreach ($item in $Arguments) { # 不拼接命令行，不经 shell 解释。
        $settings.ArgumentList.Add($item)
    }
    return $settings
}

# 子进程先登记自有 provider，再等待输入。仅在写入、刷新或回读成功后报告相应事件。
$sampleCode = @'
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System.Diagnostics.Tracing;

// 自有测试 provider。事件只描述这一个文件样本的已完成操作。
[EventSource(Name = "KSword-Validation-BenignFileIo", Guid = "D4A71ADA-81B0-4B15-A173-417F33BC8107")]
public sealed class BenignFileIoEvidence : EventSource
{
    // 写入已返回且数据已刷新。iteration 对应本次循环，bytes 是请求写入的长度。
    [Event(1, Level = EventLevel.Informational)]
    public void WriteCompleted(int iteration, int bytes) { WriteEvent(1, iteration, bytes); }

    // 回读已逐字节校验。iteration 关联写入，bytes 是实际返回的长度。
    [Event(2, Level = EventLevel.Informational)]
    public void ReadVerified(int iteration, int bytes) { WriteEvent(2, iteration, bytes); }
}
"@
$source = [BenignFileIoEvidence]::new() # 保持 provider 存活直至全部事件发出。
$path = [Console]::ReadLine() # 调用方指定的固定夹具路径。
$deadline = [datetime]::UtcNow.AddSeconds(9) # provider 无法启用时也会退出。
while (!$source.IsEnabled() -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 25 }
if (!$source.IsEnabled()) { throw 'Sample ETW provider was not enabled' }
$started = [datetime]::UtcNow # 样本与 CLI 报告对照的活动起点。
$payload = [Text.Encoding]::UTF8.GetBytes('KSword owned benign file I/O') # 无外部输入的固定字节。
$stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    for ($iteration = 0; $iteration -lt 6; ++$iteration) { # 每对事件按显式迭代编号匹配。
        $stream.Position = 0
        $stream.Write($payload, 0, $payload.Length)
        $stream.Flush($true)
        $source.WriteCompleted($iteration, $payload.Length)
        $stream.Position = 0
        $actual = [byte[]]::new($payload.Length) # 只读取本轮已写入的字节范围。
        $read = $stream.Read($actual, 0, $actual.Length)
        if ($read -ne $payload.Length -or [Convert]::ToHexString($actual) -ne [Convert]::ToHexString($payload)) {
            throw "Read-back mismatch at iteration $iteration"
        }
        $source.ReadVerified($iteration, $read)
    }
} finally {
    $stream.Dispose()
    $source.Dispose()
}
[Console]::WriteLine(([ordered]@{
    pid = $PID
    startedUtc = $started.ToString('o')
    endedUtc = [datetime]::UtcNow.ToString('o')
    bytesPerOperation = $payload.Length
    samplePath = $path
    payloadSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($payload))
} | ConvertTo-Json -Compress))
'@

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($sampleCode)) # 保留子脚本文本。
$hostPath = (Get-Process -Id $PID).Path # 沿用当前兼容的 PowerShell 可执行文件。
$sampleSettings = New-ChildStartInfo $hostPath @('-NoProfile', '-EncodedCommand', $encoded)
$sampleSettings.RedirectStandardInput = $true
$sample = [Diagnostics.Process]::Start($sampleSettings) # 唯一允许清退的目标样本。
$cli = $null # CLI 尚未开始时清理只需处理样本。
try {
    $sampleCreatedUtc = $sample.StartTime.ToUniversalTime().ToString('o') # 区分同 PID 的其它实例。
    $sampleOutput = $sample.StandardOutput.ReadToEndAsync() # 异步排空输出。
    $sample.StandardInput.WriteLine($samplePath)
    $sample.StandardInput.Close()
    $arguments = @('monitor', 'etw', 'capture', '--provider', '{D4A71ADA-81B0-4B15-A173-417F33BC8107}',
        '--pid', [string]$sample.Id, '--duration-ms', '5500', '--decode', '1', '--limit', '100', '--backend', 'r3', '--json')
    $cli = [Diagnostics.Process]::Start((New-ChildStartInfo $cliPath $arguments))
    $cliOutput = $cli.StandardOutput.ReadToEndAsync() # 保存完整 CLI JSON。
    if (!$cli.WaitForExit(12000) -or !$sample.WaitForExit(12000)) { throw 'CLI or sample deadline exceeded' }

    # 先保存原始日志，使失败时也能复查 Windows 状态和原始行。
    $raw = $cliOutput.GetAwaiter().GetResult()
    Set-Content -LiteralPath $tracePath -Value $raw -Encoding utf8NoBOM
    $trace = $raw | ConvertFrom-Json
    if ($sample.ExitCode -ne 0) { throw "Sample exit=$($sample.ExitCode), raw=$tracePath" }
    $factsText = $sampleOutput.GetAwaiter().GetResult() # 原样保留到 100 ns 精度的时间字符串。
    $facts = $factsText | ConvertFrom-Json
    $data = $trace.data # 用 CLI 收尾回执区分解码缺口和采集丢失。
    $payloadRows = @($data.events | Where-Object { $_.eventId -in 1, 2 })
    $otherRows = @($data.events | Where-Object { $_.eventId -notin 1, 2 })
    $expectedDecodeGap = $cli.ExitCode -eq 6 -and $trace.status -eq 'partial' -and [int]$data.decodePartialCount -gt 0
    if (($cli.ExitCode -ne 0 -and !$expectedDecodeGap) -or !$data.completedRequestedInterval -or $data.cancelled -or
        !$data.sessionStopped -or !$data.consumerJoined -or !$data.statisticsKnown -or $data.callbackFailed -or
        $data.processTraceWin32Error -ne 0 -or $data.closeTraceWin32Error -ne 0 -or
        @($data.stopWin32Errors | Where-Object { $_ -ne 0 }).Count -ne 0 -or
        [int]$data.enabledProviderCount -ne 1 -or [int]$data.eventsLost -ne 0 -or
        [int]$data.logBuffersLost -ne 0 -or [int]$data.realTimeBuffersLost -ne 0 -or
        [int]$data.droppedFromBufferCount -ne 0 -or $payloadRows.Count -ne 12 -or
        @($otherRows | Where-Object { $_.eventId -ne 65534 -or $_.opcode -ne 254 }).Count -ne 0) {
        throw "Capture did not meet acceptance. CLI exit=$($cli.ExitCode), sample exit=$($sample.ExitCode), raw=$tracePath"
    }

    # 对每个事件核对描述符、PID、发生时段、写读顺序、字节数和原始前缀。
    $sampleJson = [Text.Json.JsonDocument]::Parse($factsText) # 读取原始 ISO 时间。
    try {
        $firstTime = $sampleJson.RootElement.GetProperty('startedUtc').GetDateTime().ToFileTimeUtc()
        $lastTime = $sampleJson.RootElement.GetProperty('endedUtc').GetDateTime().ToFileTimeUtc()
    } finally {
        $sampleJson.Dispose()
    }
    $events = @($payloadRows | Sort-Object { [long]$_.timestampFileTime })
    for ($index = 0; $index -lt $events.Count; ++$index) {
        $row = $events[$index] # 已按 ETW 时间排序的单条证据。
        $iteration = [int][math]::Floor($index / 2) # 每轮有写和读各一条。
        $eventId = 1 + $index % 2 # 固定自有 provider 的写入、回读标识。
        $provider = $trace.data.providers[0] # 已由 Windows 成功启用的来源。
        $prefix = ([string]$row.payload.rawPrefixHex) -replace '^0x', ''
        $bytes = [Convert]::FromHexString($prefix)
        if ($row.headerPid -ne $sample.Id -or $row.providerGuid -ne $provider.guid -or
            [long]$row.timestampFileTime -lt $firstTime -or [long]$row.timestampFileTime -gt $lastTime -or
            $row.eventId -ne $eventId -or $row.version -ne 0 -or $row.payload.rawTruncated -or $bytes.Length -ne 8 -or
            [BitConverter]::ToInt32($bytes, 0) -ne $iteration -or
            [BitConverter]::ToInt32($bytes, 4) -ne $facts.bytesPerOperation) {
            throw "Evidence mismatch at row $index"
        }
    }

    # 汇总报告和原始 JSON 分开，保留 CLI 版本、参数及样本身份供复核。
    [ordered]@{
        result = 'verified-sample-payloads'
        scope = 'Owned instrumented file sample, R3 user ETW provider'
        cli = [ordered]@{ exitCode = $cli.ExitCode; status = $trace.status; arguments = $arguments; sha256 = (Get-FileHash -LiteralPath $cliPath).Hash }
        sample = $facts
        sampleCreatedUtc = $sampleCreatedUtc
        sampleExitCode = $sample.ExitCode
        provider = $trace.data.providers[0]
        sessionName = $trace.data.sessionName
        sessionStopped = $trace.data.sessionStopped
        consumerJoined = $trace.data.consumerJoined
        eventsLost = $trace.data.eventsLost
        tdhPartialRows = $data.decodePartialCount
        providerManifestRows = $otherRows.Count
        decoding = 'Fixture schema: two signed little-endian 32-bit integers, iteration and byte count. CLI TDH result is preserved in each event.'
        writeReadPairs = 6
        rawTrace = $tracePath
        events = $events
    } | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $reportPath -Encoding utf8NoBOM
    Write-Output "PASS 6 file write/read pairs, 12 CLI ETW records. Report: $reportPath"
} finally {
    # 仅清退本次启动的样本。核对文件身份与跟踪状态再清理夹具。
    if (!$sample.HasExited) { $sample.Kill() }
    if ($null -ne $cli -and !$cli.HasExited) { $cli.WaitForExit(7000) | Out-Null }
    if (Test-Path -LiteralPath $samplePath -PathType Leaf) {
        $resolved = (Resolve-Path -LiteralPath $samplePath).Path
        $expected = Join-Path (Resolve-Path -LiteralPath $release).Path 'ActionAnalyzeBenignCliTrace.sample'
        $tracked = & git -C $root ls-files -- 'Ksword5.1/x64/Release/ActionAnalyzeBenignCliTrace.sample'
        if ($resolved -eq $expected -and !$tracked) { Remove-Item -LiteralPath $resolved }
    }
}
