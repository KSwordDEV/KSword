param(
    [Parameter(Mandatory=$true)][string]$Cli,
    [Parameter(Mandatory=$true)][string]$ReportRoot
)
$ErrorActionPreference='Stop'
# Never accept a machine name from the command line: system process injection
# is permitted solely on the explicitly identified Windows 10 test guest.
if ($env:COMPUTERNAME -ne 'DESKTOP-D2161R7') { throw 'Wrong guest; no process was opened.' }
if (!(Test-Path -LiteralPath $Cli -PathType Leaf)) { throw 'CLI not found.' }
if (Test-Path -LiteralPath $ReportRoot) { throw 'Evidence directory already exists.' }
New-Item -ItemType Directory -Path $ReportRoot | Out-Null
$start=[DateTime]::UtcNow
$results=@()
foreach ($item in @(
    @{Name='dwm'; Image=(Join-Path $env:windir 'System32\dwm.exe')},
    @{Name='explorer'; Image=(Join-Path $env:windir 'explorer.exe')}
)) {
    $targets=@(Get-Process -Name $item.Name -ErrorAction Stop | Where-Object { $_.SessionId -eq 1 })
    if($targets.Count -ne 1) { throw "Expected exactly one $($item.Name) in guest session 1." }
    $target=$targets[0]
    $beforeId=$target.Id; $beforeCreation=$target.StartTime.ToUniversalTime().ToFileTimeUtc()
    if(![string]::Equals($target.Path,$item.Image,[StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected image for $($item.Name)." }
    $identity=Get-Process -Id $beforeId -ErrorAction Stop
    if($identity.ProcessName -ne $item.Name -or $identity.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $beforeCreation) {
        throw "Target identity changed before capture: $($item.Name)."
    }
    $arguments=@('privilege','run','--enable','SeDebugPrivilege','--json','--','monitor','api','capture',
        '--pid',([string]$beforeId),'--duration-ms','3000','--categories','file,registry,process,loader',
        '--raw','1','--raw-modules','user32.dll;kernel32.dll;gdi32.dll','--limit','20000',
        '--startup-timeout-ms','60000','--stop-timeout-ms','30000','--confirm','--json')
    $info=[Diagnostics.ProcessStartInfo]::new(); $info.FileName=$Cli
    # This fixed argument set contains no whitespace, quotes, or shell syntax;
    # the executable path is supplied separately to ProcessStartInfo.
    $info.Arguments=$arguments -join ' '; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $info.StandardOutputEncoding=[Text.Encoding]::UTF8; $info.StandardErrorEncoding=[Text.Encoding]::UTF8
    $child=[Diagnostics.Process]::Start($info)
    $stdout=$child.StandardOutput.ReadToEndAsync(); $stderr=$child.StandardError.ReadToEndAsync()
    try {
        if (!$child.WaitForExit(120000)) { $child.Kill(); $child.WaitForExit(); throw "$($item.Name) controller timed out; cleanup is unconfirmed." }
        $output=$stdout.GetAwaiter().GetResult(); $errorText=$stderr.GetAwaiter().GetResult(); $code=$child.ExitCode
    } finally { $child.Dispose() }
    [IO.File]::WriteAllText((Join-Path $ReportRoot ($item.Name+'.json')),$output,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $ReportRoot ($item.Name+'.stderr.txt')),$errorText,[Text.UTF8Encoding]::new($false))
    $outer=$output | ConvertFrom-Json
    if (!$outer.data.executed -or !$outer.data.restored) { throw "$($item.Name) controller privilege execution/restoration not confirmed." }
    $nested=$outer.data.stdout | ConvertFrom-Json
    $observed=@($nested.data.processes | Where-Object { $_.pid -eq $beforeId })
    if ($observed.Count -ne 1 -or [uint64]$observed[0].creationFileTime -ne [uint64]$beforeCreation) { throw "Capture identity mismatch for $($item.Name)." }
    $after=Get-Process -Id $beforeId -ErrorAction Stop
    if ($after.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $beforeCreation) { throw "Target restarted during capture: $($item.Name)." }
    $ok=$observed[0].hooksInstalled -and $observed[0].hooksRemoved -and $nested.data.cleanupComplete -and $nested.data.stopWritten
    $results += [pscustomobject]@{name=$item.Name;pid=$beforeId;creationFileTime=[string]$beforeCreation;
        image=$item.Image;exitCode=$code;hooksInstalled=$observed[0].hooksInstalled;hooksRemoved=$observed[0].hooksRemoved;
        cleanupComplete=$nested.data.cleanupComplete;coverageComplete=$observed[0].coverageComplete;
        coverageStale=$observed[0].coverageStale;agentDropped=$observed[0].agentDroppedCount;
        bufferDropped=$nested.data.bufferDroppedCount;events=@($nested.data.events).Count}
    if (!$ok) { throw "$($item.Name) installation/removal/cleanup incomplete; inspect evidence." }
}
Start-Sleep -Seconds 3
try {
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000,1001;StartTime=$start.ToLocalTime()} -ErrorAction Stop |
        Where-Object { $_.Message -match '(?i)(dwm\.exe|explorer\.exe)' } |
        Select-Object TimeCreated,Id,ProviderName,Message)
} catch {
    if ($_.FullyQualifiedErrorId -notmatch '^NoMatchingEventsFound') { throw }
    $events=@()
}
$summary=[pscustomobject]@{computer=$env:COMPUTERNAME;startedUtc=$start.ToString('o');targets=$results;applicationCrashEvents=$events;
    note='Only hooks were removed. Resident agent code is not forcibly unloaded.'}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ReportRoot 'summary.json') -Encoding UTF8
if($events.Count -gt 0) { throw 'Relevant application crash/WER events found; inspect summary.' }
Write-Output 'P0_GUEST_SYSTEM_PASS hooks removed, identities unchanged, no matching application crash events'
