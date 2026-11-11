[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Cli,
    [Parameter(Mandatory = $true)][string]$ProbeSys
)

$ErrorActionPreference = 'Stop'
$cliPath = (Resolve-Path -LiteralPath $Cli).Path
$probePath = (Resolve-Path -LiteralPath $ProbeSys).Path
if ([IO.Path]::GetFileName($probePath) -ine 'KswordCallbackProbe.sys') { throw 'Probe must be named KswordCallbackProbe.sys.' }
if ((Get-Service -Name KswordARK -ErrorAction Stop).Status -ne 'Running') { throw 'KswordARK must already be running; this test does not change its service.' }
$serviceName = 'KswordCallbackProbe-' + [guid]::NewGuid().ToString('N')
$script:activeCli = $null
$created = $false

function Invoke-ProbeCli([string[]]$Arguments) {
    # All call-site arguments are fixed tokens without whitespace; FileName handles a spaced CLI path.
    if (@($Arguments | Where-Object { $_ -match '\s' }).Count) { throw 'Whitespace in CLI argument is unsupported in this fixture.' }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $cliPath
    $info.Arguments = $Arguments -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.Encoding]::UTF8
    $info.StandardErrorEncoding = [Text.Encoding]::UTF8
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Could not start CLI.' }
    $script:activeCli = $process
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(60000)) { throw 'CLI timed out; operation state is unknown. The test service is retained until the process exits.' }
    $result = [pscustomobject]@{ Exit = $process.ExitCode; Stdout = $stdout.Result; Stderr = $stderr.Result; Json = $null }
    $script:activeCli = $null
    $process.Dispose()
    try { $result.Json = $result.Stdout | ConvertFrom-Json } catch { throw "CLI returned invalid JSON (exit $($result.Exit)): $($result.Stderr)" }
    return $result
}

function Read-Inventory {
    $result = Invoke-ProbeCli @('callback','enum','--max-entries','1024','--limit','100000','--json')
    if ($result.Exit -ne 0 -or -not $result.Json.data.queried -or $result.Json.data.displayTruncated -or
        $result.Json.data.lastStatus -ne '0x0' -or $result.Json.data.rows.Count -ne $result.Json.data.totalCount) {
        throw "Callback inventory incomplete (exit $($result.Exit)): $($result.Stderr)"
    }
    return $result.Json.data
}

function To-U64([string]$Value) {
    if (-not $Value.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) { throw 'Expected a hexadecimal address.' }
    return [Convert]::ToUInt64($Value.Substring(2), 16)
}

try {
    $prior = Invoke-ProbeCli @('driver','modules','query','--name','KswordCallbackProbe.sys','--signature','off','--json')
    if ($prior.Exit -ne 3 -or -not $prior.Json.data.complete -or @($prior.Json.data.modules).Count -ne 0) {
        throw 'Cannot prove the probe image was absent before the test; no service was created.'
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Unexpected service-name collision.' }
    & sc.exe create $serviceName type= kernel start= demand binPath= $probePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create probe service ($LASTEXITCODE)." }
    $created = $true
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(10))

    $module = Invoke-ProbeCli @('driver','modules','query','--name','KswordCallbackProbe.sys','--signature','off','--json')
    $modules = @($module.Json.data.modules)
    if ($module.Exit -notin @(0,6) -or $modules.Count -ne 1 -or -not $modules[0].baseAddress -or -not $modules[0].imageSize -or -not $modules[0].path) {
        throw 'Could not uniquely identify the loaded probe module and its range.'
    }
    $modulePath = [string]$modules[0].path
    if ($modulePath.StartsWith('\??\')) { $modulePath = $modulePath.Substring(4) }
    if (-not [IO.Path]::IsPathRooted($modulePath) -or
        -not [string]::Equals([IO.Path]::GetFullPath($modulePath), [IO.Path]::GetFullPath($probePath), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Loaded module path does not match the dedicated probe image; no removal attempted.'
    }
    $base = To-U64 $modules[0].baseAddress
    $size = [Convert]::ToUInt64($modules[0].imageSize)
    if (-not $base -or -not $size) { throw 'Probe image range is invalid.' }
    $before = Read-Inventory
    $rows = @($before.rows | Where-Object {
        if ($_.className -ne 'process' -or $_.moduleBase -ne $modules[0].baseAddress -or -not $_.callback) { return $false }
        $address = To-U64 $_.callback
        return $address -ge $base -and ($address - $base) -lt $size
    })
    if ($rows.Count -ne 1 -or -not $rows[0].identityHash -or $rows[0].identityHash -eq '0x0') {
        throw 'Probe callback was not uniquely identified by its own module range; no removal attempted.'
    }
    $selected = $rows[0]
    $removed = Invoke-ProbeCli @('callback','remove-row','--identity-hash',$selected.identityHash,'--confirm','--json')
    if ($removed.Exit -ne 0 -or $removed.Json.data.ntstatus -ne '0x0' -or $removed.Json.data.revalidationStatus -ne '0x0' -or
        $removed.Json.data.callback -ne $selected.callback -or $removed.Json.data.identityHash -ne $selected.identityHash) {
        throw "Probe callback removal was not confirmed (exit $($removed.Exit)): $($removed.Stderr)"
    }
    $after = Read-Inventory
    if (@($after.rows | Where-Object { $_.className -eq 'process' -and $_.callback -eq $selected.callback -and $_.moduleBase -eq $modules[0].baseAddress }).Count) {
        throw 'The probe callback remains in a complete post-removal inventory.'
    }
    [pscustomobject]@{ Success = $true; Service = $serviceName; Module = $modules[0].name; Callback = $selected.callback;
        IdentityHash = $selected.identityHash; BeforeCount = $before.totalCount; AfterCount = $after.totalCount; RemovalStatus = $removed.Json.data.ntstatus }
} finally {
    if ($created) {
        if ($script:activeCli -and -not $script:activeCli.HasExited) {
            Write-Warning "CLI remains active; probe service $serviceName was retained. Inspect the CLI and callback state before cleanup."
        } else {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -ne 'Stopped') {
                Stop-Service -Name $serviceName
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(10))
            }
            & sc.exe delete $serviceName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not delete stopped probe service $serviceName ($LASTEXITCODE)." }
        }
    }
}
