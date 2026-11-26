param([switch]$BuildOnly)
$ErrorActionPreference = 'Stop'
$probeRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$probeMsbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
if (!(Test-Path -LiteralPath $probeMsbuild)) { $probeMsbuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe' }
if (!(Test-Path -LiteralPath $probeMsbuild)) { throw '64-bit MSBuild is required.' }
$probeLogs = Join-Path $probeRoot '.codex-build-logs\behavior-planning'
New-Item -ItemType Directory -Path $probeLogs -Force | Out-Null
$probeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$probeHost = [System.Diagnostics.Process]::GetCurrentProcess()
$probePreviousPriority = $probeHost.PriorityClass
try {
    $probeHost.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
    foreach ($probeProject in @('StartupBootstrap','ApiMonitorStartupValidation')) {
        foreach ($probePlatform in @('x64','Win32')) {
            $probeBuildLog = Join-Path $probeLogs "apimon-startup-$probeStamp-$probeProject-$probePlatform-build.log"
            & $probeMsbuild (Join-Path $PSScriptRoot "$probeProject.vcxproj") /t:Build `
                /p:Configuration=Release "/p:Platform=$probePlatform" /p:PreferredToolArchitecture=x64 `
                /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 /m:1 /v:minimal /nologo 2>&1 |
                Tee-Object -FilePath $probeBuildLog
            if ($LASTEXITCODE -ne 0) { throw "Build failed: $LASTEXITCODE; $probeBuildLog" }
        }
    }
} finally { $probeHost.PriorityClass = $probePreviousPriority }
if ($BuildOnly) { return }
$probeRelease = Join-Path $probeRoot 'Ksword5.1\x64\Release'
$probeArtifacts = Join-Path $PSScriptRoot 'test-artifacts'
$probeRunLog = Join-Path $probeLogs "apimon-startup-$probeStamp-run.log"
$probeMetadata = [ordered]@{
    time = (Get-Date).ToString('o')
    os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber)
    scope = 'Owned x64/x86 children only; R3 injection and distinct early-import IAT test bootstrap; no driver, Explorer, DWM or product edits.'
    artifacts = $probeArtifacts
    binaries = @('ApiMonitorStartupValidation.exe','ApiMonitorStartupTarget_x86.exe',
        'StartupProbeBootstrap_x64.dll','StartupProbeBootstrap_x86.dll','APIMonitor_x64.dll','APIMonitor_x86.dll') |
        ForEach-Object { $probeFile = Get-Item -LiteralPath (Join-Path $probeRelease $_)
            [ordered]@{ path = $probeFile.FullName; size = $probeFile.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $probeFile.FullName).Hash } }
    runLog = $probeRunLog
}
& (Join-Path $probeRelease 'ApiMonitorStartupValidation.exe') $probeRelease $probeArtifacts 2>&1 | Tee-Object -FilePath $probeRunLog
$probeExit = $LASTEXITCODE
$probeMetadata['exitCode'] = $probeExit
$probeMetadata['artifactDirectoryRemoved'] = !(Test-Path -LiteralPath $probeArtifacts)
$probeMetadata['remainingOwnedFixtures'] = @(Get-CimInstance Win32_Process -Filter "Name='ApiMonitorStartupValidation.exe' OR Name='ApiMonitorStartupTarget_x86.exe'" |
    Select-Object ProcessId,CreationDate,ExecutablePath)
$probeMetadata | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 `
    -LiteralPath (Join-Path $probeLogs "apimon-startup-$probeStamp-metadata.json")
if ($probeExit -ne 0) { throw "Validation failed: $probeExit; $probeRunLog" }
if (!$probeMetadata['artifactDirectoryRemoved'] -or $probeMetadata['remainingOwnedFixtures'].Count) {
    throw 'Validation reported residual fixture files or processes; inspect metadata.'
}
