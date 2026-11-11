[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Cli)
$ErrorActionPreference = 'Stop'
$cliPath = (Resolve-Path -LiteralPath $Cli).Path
$testDir = Join-Path $env:TEMP ('ksword-cli-thread-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$outPath = Join-Path $testDir 'out.json'
$child = $null
function Invoke-Cli([string]$arguments) {
    & cmd.exe /d /c "`"`"$cliPath`" $arguments > `"$outPath`" 2>&1`""
    $code = $LASTEXITCODE
    $text = [IO.File]::ReadAllText($outPath, [Text.Encoding]::UTF8)
    return [pscustomobject]@{ Code = $code; Data = ($text | ConvertFrom-Json); Text = $text }
}
try {
    # The only target is a new child owned by this test, not an existing process.
    $child = Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList '-NoProfile', '-Command', 'Start-Sleep -Seconds 90' -WindowStyle Hidden -PassThru
    $enum = Invoke-Cli "process thread enum --pid $($child.Id) --json"
    if ($enum.Code -notin @(0, 6)) { throw "Thread enumeration failed: $($enum.Text)" }
    $thread = @($enum.Data.data.threads | Where-Object { $_.creationTime }) | Select-Object -First 1
    $processBirth = $enum.Data.data.target.creationTime
    if (-not $thread -or -not $processBirth) { throw 'No queryable owned thread identity was returned.' }
    $r0Identity = Invoke-Cli "thread r0 identity --pid $($child.Id) --tid $($thread.tid) --json"
    if ($r0Identity.Code -ne 0 -or -not $r0Identity.Data.data.identityMatched -or
        $r0Identity.Data.data.processCreationTime -ne $processBirth -or
        $r0Identity.Data.data.threadCreationTime -ne $thread.creationTime) {
        throw "R0 identity did not match the R3 observation: $($r0Identity.Text)"
    }
    Write-Output 'R0_THREAD_IDENTITY_PASS'
    $identity = "--pid $($child.Id) --creation-time $processBirth --tid $($thread.tid) --thread-creation-time $($thread.creationTime) --confirm --json"
    foreach ($action in 'suspend', 'resume', 'terminate') {
        $result = Invoke-Cli "thread r0 $action $identity"
        if ($result.Code -ne 0 -or -not $result.Data.data.verified) {
            throw "R0 thread $action was not confirmed: $($result.Text)"
        }
        Write-Output "R0_THREAD_${action}_PASS"
    }
} finally {
    if ($child -and -not $child.HasExited) { Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue }
    if ($testDir -match [regex]::Escape((Join-Path $env:TEMP 'ksword-cli-thread-')) + '[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $testDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
