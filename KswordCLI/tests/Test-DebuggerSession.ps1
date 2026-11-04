param(
    [Parameter(Mandatory=$true)][string]$CliPath,
    [Parameter(Mandatory=$true)][string]$CanaryPath,
    [ValidateSet('r3','r0')][string]$Backend = 'r3'
)
$ErrorActionPreference = 'Stop'

function Read-LineBounded([System.IO.StreamReader]$Reader) {
    $pending = $Reader.ReadLineAsync()
    if (-not $pending.Wait(15000)) { throw 'Timed out waiting for a debugger response.' }
    if ($null -eq $pending.Result) { throw 'Debugger closed its output unexpectedly.' }
    return $pending.Result
}
function Require-Record($Record, [string]$Operation) {
    if ($Record.record -ne 'debugger' -or $Record.operation -ne $Operation -or -not $Record.ok) {
        throw "Unexpected $Operation response: $($Record | ConvertTo-Json -Compress -Depth 10)"
    }
}
function Request([string]$Line, [string]$Operation) {
    $script:debugger.StandardInput.WriteLine($Line)
    $script:debugger.StandardInput.Flush()
    $record = (Read-LineBounded $script:debugger.StandardOutput) | ConvertFrom-Json
    Require-Record $record $Operation
    return $record
}

$canary = $null
$debugger = $null
try {
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Resolve-Path -LiteralPath $CanaryPath).Path
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $canary = [System.Diagnostics.Process]::Start($start)
    $address = Read-LineBounded $canary.StandardOutput
    $creation = $canary.StartTime.ToUniversalTime().ToFileTimeUtc()

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Resolve-Path -LiteralPath $CliPath).Path
    $start.Arguments = "debugger session --pid $($canary.Id) --creation-time $creation --confirm --backend $Backend --json"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $debugger = [System.Diagnostics.Process]::Start($start)
    $attached = (Read-LineBounded $debugger.StandardOutput) | ConvertFrom-Json
    Require-Record $attached 'attached'
    $event = Request 'wait 10000' 'wait'
    $tid = $event.data.tid
    $threads = Request 'threads' 'threads'
    if (-not ($threads.data | Where-Object { $_.tid -eq $tid })) { throw 'Stopped thread was absent from the thread snapshot.' }
    $context = Request "context $tid" 'context'
    $instruction = $context.data.rip
    $before = Request "read $address 8" 'read'
    if ($before.data.bytes -ne '8877665544332211') { throw "Unexpected initial canary: $($before.data.bytes)" }
    $write = Request "write $address 0102030405060708 confirm" 'write'
    if ([int]$write.data.transferred -ne 8) { throw 'Partial memory write.' }
    $after = Request "read $address 8" 'read'
    if ($after.data.bytes -ne '0102030405060708') { throw "Memory readback mismatch: $($after.data.bytes)" }
    $null = Request "write $address 8877665544332211 confirm" 'write'
    $null = Request "break add $tid 0 $instruction" 'break'
    $armed = Request "context $tid" 'context'
    if ($armed.data.dr0 -ne $instruction) { throw 'Hardware breakpoint readback mismatch.' }
    $null = Request "break remove $tid 0" 'break'
    $restored = Request "context $tid" 'context'
    if ($restored.data.dr0 -ne $context.data.dr0 -or $restored.data.dr7 -ne $context.data.dr7) { throw 'Hardware breakpoint was not restored.' }
    $null = Request 'continue handled' 'continue'
    $null = Request 'detach' 'detach'
    $debugger.StandardInput.Close()
    if (-not $debugger.WaitForExit(15000)) { throw 'Debugger did not exit.' }
    if ($debugger.ExitCode -ne 0) { throw "Debugger exit code $($debugger.ExitCode); stderr: $($debugger.StandardError.ReadToEnd())" }
    if ($canary.HasExited) { throw 'Canary exited while debugger detached.' }
    Write-Output "PASS backend=$Backend attach event threads context read write breakpoint restore continue detach"
}
finally {
    if ($null -ne $debugger -and -not $debugger.HasExited) { $debugger.Kill(); $debugger.WaitForExit() }
    if ($null -ne $canary -and -not $canary.HasExited) { $canary.Kill(); $canary.WaitForExit() }
    if ($null -ne $debugger) { $debugger.Dispose() }
    if ($null -ne $canary) { $canary.Dispose() }
}
