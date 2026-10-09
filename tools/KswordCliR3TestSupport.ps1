$records = [System.Collections.Generic.List[object]]::new()
function Quote-CliArgument([string]$Value) {
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}
function Invoke-Cli([string[]]$Arguments, [int[]]$Expected = @(0)) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Cli
    $info.Arguments = ($Arguments | ForEach-Object { Quote-CliArgument $_ }) -join ' '
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.Encoding]::UTF8
    $info.StandardErrorEncoding = [Text.Encoding]::UTF8
    $p = [Diagnostics.Process]::Start($info)
    $outTask = $p.StandardOutput.ReadToEndAsync(); $errTask = $p.StandardError.ReadToEndAsync()
    if (!$p.WaitForExit(45000)) { $p.Kill(); throw 'CLI timeout' }
    $out = $outTask.GetAwaiter().GetResult(); $err = $errTask.GetAwaiter().GetResult()
    $records.Add([pscustomobject]@{arguments=$Arguments;code=$p.ExitCode;stdout=$out;stderr=$err})
    if ($Expected -notcontains $p.ExitCode) { throw "Expected $Expected got $($p.ExitCode): $err $($out.Substring(0,[Math]::Min(1500,$out.Length)))" }
    return $out
}
function Assert([bool]$Condition, [string]$Message) { if (!$Condition) { throw $Message } }
function Save-Report {
    $service = Get-Service KswordARK -ErrorAction SilentlyContinue
    $driverState = if ($service) { $service.Status.ToString() } else { 'Absent' }
    $result = [pscustomobject]@{success=$true;os=[Environment]::OSVersion.VersionString;sha256=(Get-FileHash $Cli).Hash;driver=$driverState;cases=$records}
    if ($ReportPath) { $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ReportPath -Encoding UTF8 }
    Write-Output "R3_PASS feature=$Feature cases=$($records.Count)"
}
