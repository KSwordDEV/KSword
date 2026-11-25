param(
    [string]$MSBuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe'
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$project = Join-Path $PSScriptRoot 'ActionTransportValidation.vcxproj'
$logs = Join-Path $repo '.codex-build-logs\behavior-planning'
$buildLog = Join-Path $logs 'action-analyze-transport-build.log'
$runLog = Join-Path $logs 'action-analyze-transport-run.log'
$metadataPath = Join-Path $logs 'action-analyze-transport-metadata.json'
$exe = Join-Path $repo 'Ksword5.1\x64\Release\ActionTransportValidation.exe'
if (!(Test-Path -LiteralPath $MSBuild)) { throw 'amd64 MSBuild is required.' }
if ($MSBuild -notmatch '[\\/]amd64[\\/]MSBuild\.exe$') { throw 'Use the amd64 MSBuild entry point.' }
[Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'BelowNormal'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$arguments = @($project, '/t:Build', '/p:Configuration=Release', '/p:Platform=x64',
    '/p:PreferredToolArchitecture=x64', '/p:PROCESSOR_ARCHITECTURE=AMD64',
    '/p:PROCESSOR_ARCHITEW6432=AMD64', '/m:1', '/v:minimal', '/nologo')
"BUILD_HOST=$MSBuild`nBUILD_PRIORITY=BelowNormal`nBUILD_ARGUMENTS=$($arguments -join ' ')" |
    Set-Content -LiteralPath $buildLog -Encoding utf8
& $MSBuild @arguments 2>&1 | Tee-Object -FilePath $buildLog -Append
$buildExit = $LASTEXITCODE
"BUILD_EXIT_CODE=$buildExit" | Add-Content -LiteralPath $buildLog -Encoding utf8
if ($buildExit -ne 0) { throw "Build failed; inspect $buildLog" }
if (!(Test-Path -LiteralPath $exe) -or (Get-Item -LiteralPath $exe).Length -eq 0) { throw 'Nonzero fixed Release artifact required.' }
# 夹具自身限制各阶段观察和清理时间；外层 16 秒仅为故障兜底，触发即记失败。
# Kill 只针对下方精确创建的父进程实例。每个已接纳子进程在首次恢复前已加入
# 父端独占、不可继承的 KILL_ON_JOB_CLOSE Job：即使子线程全被挂起，父退出后
# 内核也能清理该子进程。子端 parentAlive/4500ms 检查只补充正常可运行时的退出，
# 不能替代 Job。本脚本未单独注入杀父故障，不能据此宣称该故障路径已实测。
$start = [Diagnostics.ProcessStartInfo]::new($exe)
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = [Diagnostics.Process]::Start($start)
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
$watchdog = !$process.WaitForExit(16000)
if ($watchdog) {
    $process.Kill()
    $process.WaitForExit(2000) | Out-Null
}
$output = $stdout.GetAwaiter().GetResult()
$errors = $stderr.GetAwaiter().GetResult()
$output + $errors | Set-Content -LiteralPath $runLog -Encoding utf8
Write-Output $output
$runExit = $process.ExitCode
$os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
$sourceHashes = @('ActionTransportValidation.cpp', 'ActionTransportValidation.h', 'ActionTransportValidation.vcxproj', 'Invoke-Validation.ps1') | ForEach-Object {
    $path = Join-Path $PSScriptRoot $_
    [ordered]@{ path = [IO.Path]::GetRelativePath($repo, $path); sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
}
$metadata = [ordered]@{
    recordedAt = (Get-Date).ToUniversalTime().ToString('o')
    executable = $exe
    sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    intDir = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'x64\Release'))
    outDir = Split-Path -Parent $exe
    buildHost = $MSBuild
    buildExit = $buildExit
    runExit = $runExit
    watchdogTriggered = $watchdog
    parentKillFaultInjectionTested = $false
    assertionsPassed = ([regex]::Matches($output, '(?m)^ASSERT PASS ')).Count
    assertionsFailed = ([regex]::Matches($output, '(?m)^ASSERT FAIL ')).Count
    result = if ($runExit -eq 0 -and !$watchdog -and $output -match 'RESULT=PASS') { 'PASS' } else { 'FAIL' }
    os = $os
    parentPid = $process.Id
    sessions = @($output -split '\r?\n' | Where-Object { $_ -match '^SESSION ' })
    jobGuards = @($output -split '\r?\n' | Where-Object { $_ -match '^JOB_GUARD ' })
    threadHolds = @($output -split '\r?\n' | Where-Object { $_ -match '^HOLD ' })
    cleanup = @($output -split '\r?\n' | Where-Object { $_ -match '^CLEANUP ' })
    stageTimings = @($output -split '\r?\n' | Where-Object { $_ -match '^STAGE_END ' })
    scope = 'Self-created current-executable children; declared main/business, telemetry writer and (split stages) control reader. Runtime-created threads excluded. Dependency evidence, no throughput or universal-deadlock claim.'
    configurationFilesCreated = 0
    runtimeCopiesCreated = 0
    sources = @($sourceHashes)
}
$metadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metadataPath -Encoding utf8
$process.Dispose()
if ($metadata.result -ne 'PASS') { throw "Native validation failed; inspect $runLog" }
Write-Output "METADATA=$metadataPath"
