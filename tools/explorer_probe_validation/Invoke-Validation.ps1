param(
    [Parameter(Mandatory=$true)][int]$ExplorerPid,
    [switch]$BuildOnly,
    [switch]$IncludeControllerDeathProbe
)
$ErrorActionPreference = 'Stop'
$probeRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$probeMsbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
if (!(Test-Path -LiteralPath $probeMsbuild)) { $probeMsbuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe' }
if (!(Test-Path -LiteralPath $probeMsbuild)) { throw '64-bit MSBuild is required.' }
$probeLogs = Join-Path $probeRoot '.codex-build-logs\behavior-planning'
New-Item -ItemType Directory -Path $probeLogs -Force | Out-Null
$probeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$probeBuildLog = Join-Path $probeLogs "explorer-probe-$probeStamp-build.log"
$probeRunLog = Join-Path $probeLogs "explorer-probe-$probeStamp-run.log"
$probeHost = [System.Diagnostics.Process]::GetCurrentProcess()
$probePreviousPriority = $probeHost.PriorityClass
try {
    $probeHost.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
    & $probeMsbuild (Join-Path $PSScriptRoot 'ExplorerProbeValidation.vcxproj') /t:Build `
        /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 `
        /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 /m:1 /v:minimal /nologo 2>&1 |
        Tee-Object -FilePath $probeBuildLog
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $LASTEXITCODE; $probeBuildLog" }
} finally {
    $probeHost.PriorityClass = $probePreviousPriority
}
if ($BuildOnly) { return }
$probeExe = Join-Path $probeRoot 'Ksword5.1\x64\Release\ExplorerProbeValidation.exe'
$probeBefore = Get-Process -Id $ExplorerPid
$probeMetadata = [ordered]@{
    time = (Get-Date).ToString('o')
    explorerPid = $ExplorerPid
    explorerCreated = $probeBefore.StartTime.ToString('o')
    explorerPath = $probeBefore.Path
    os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber)
    exe = $probeExe
    sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $probeExe).Hash
    buildLog = $probeBuildLog
    runLog = $probeRunLog
    scope = 'Authorized local Explorer only; native debug attach; no R0, DWM, DLL load or system-policy changes.'
}
$probeArguments = @('--explorer-pid', $ExplorerPid)
if ($IncludeControllerDeathProbe) { $probeArguments += '--include-controller-death-probe' }
$probeMetadata['includeControllerDeathProbe'] = [bool]$IncludeControllerDeathProbe
& $probeExe @probeArguments 2>&1 | Tee-Object -FilePath $probeRunLog
$probeExit = $LASTEXITCODE
$probeMetadata['exitCode'] = $probeExit
$probeMetadata['explorerAfter'] = (Get-Process -Id $ExplorerPid -ErrorAction SilentlyContinue |
    Select-Object Id,ProcessName,StartTime,Responding,@{Name='threadCount';Expression={$_.Threads.Count}})
$probeMetadata | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 `
    -LiteralPath (Join-Path $probeLogs "explorer-probe-$probeStamp-metadata.json")
if ($probeExit -ne 0) { throw "Validation failed: $probeExit; $probeRunLog" }
