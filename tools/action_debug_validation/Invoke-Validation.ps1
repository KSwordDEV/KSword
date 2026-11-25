param([string]$MSBuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe')
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$project = Join-Path $PSScriptRoot 'ActionDebugValidation.vcxproj'
$logs = Join-Path $repo '.codex-build-logs\behavior-planning'
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss-fffffff') + "-$PID"
$prefix = Join-Path $logs "action-analyze-r3-debug-$runId"
$buildLog = "$prefix-build.log"
$runLog = "$prefix-run.log"
$metadataPath = "$prefix-metadata.json"
$exe = Join-Path $repo 'Ksword5.1\x64\Release\ActionDebugValidation.exe'
if (!(Test-Path -LiteralPath $MSBuild) -or $MSBuild -notmatch '[\\/]amd64[\\/]MSBuild\.exe$') {
    throw 'An installed amd64 MSBuild entry point is required.'
}
$hostProcess = [Diagnostics.Process]::GetCurrentProcess()
$previousPriority = $hostProcess.PriorityClass
$hostProcess.PriorityClass = 'BelowNormal'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$common = @('/p:Configuration=Release', '/p:Platform=x64', '/p:PreferredToolArchitecture=x64',
    '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64',
    '/p:VcpkgEnabled=false', '/p:VcpkgApplocalDeps=false', '/nologo')
$buildExit = $null
$runExit = $null
$watchdog = $false
$output = ''
$errors = ''
$process = $null
try {
    # Evaluation only; print and validate the resolved fixed directories before Build.
    $evaluation = & $MSBuild $project @common '-getProperty:IntDir,OutDir,VCToolsInstallDir,PreferredToolArchitecture' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "MSBuild property readback failed: $evaluation" }
    $properties = ($evaluation -join "`n" | ConvertFrom-Json).Properties
    $intDir = [IO.Path]::GetFullPath($properties.IntDir).TrimEnd('\')
    $outDir = [IO.Path]::GetFullPath($properties.OutDir).TrimEnd('\')
    $expectedInt = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'x64\Release')).TrimEnd('\')
    $expectedOut = [IO.Path]::GetFullPath((Split-Path -Parent $exe)).TrimEnd('\')
    $compiler = Join-Path $properties.VCToolsInstallDir 'bin\HostX64\x64\cl.exe'
    if ($intDir -ne $expectedInt -or $outDir -ne $expectedOut -or
        $properties.PreferredToolArchitecture -ne 'x64' -or !(Test-Path -LiteralPath $compiler)) {
        throw 'Resolved directories or HostX64 compiler do not meet the fixture contract.'
    }
    @("BUILD_HOST=$MSBuild", 'BUILD_PRIORITY=BelowNormal', "INTDIR=$intDir", "OUTDIR=$outDir",
        "HOSTX64=$compiler", 'VCPKG_ENABLED=false', 'VCPKG_APPLOCAL=false', 'WARNINGS=/W4 /WX') |
        Tee-Object -FilePath $buildLog
    & $MSBuild $project @common /t:Build /m:1 /v:normal 2>&1 | Tee-Object -FilePath $buildLog -Append
    $buildExit = $LASTEXITCODE
    "BUILD_EXIT_CODE=$buildExit" | Add-Content -LiteralPath $buildLog -Encoding utf8
    if ($buildExit -ne 0) { throw "Build failed; inspect $buildLog" }
    if (!(Test-Path -LiteralPath $exe) -or (Get-Item -LiteralPath $exe).Length -eq 0) {
        throw 'Nonzero fixed Release executable is required.'
    }
    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $watchdog = !$process.WaitForExit(80000)
    if ($watchdog) {
        # Only this exact parent instance. Private noninherited Jobs guard children.
        $process.Kill()
        if (!$process.WaitForExit(3000)) { throw 'Exact fixture parent did not exit after watchdog.' }
    }
    $output = $stdout.GetAwaiter().GetResult()
    $errors = $stderr.GetAwaiter().GetResult()
    $runExit = $process.ExitCode
    ($output + $errors) | Set-Content -LiteralPath $runLog -Encoding utf8
    Write-Output $output
} finally {
    $sourceHashes = @('DebugSession.cpp', 'DebugSession.h', 'DebugScenarios.cpp', 'FixtureCode.h',
        'FixtureCode.asm', 'ActionDebugValidation.vcxproj', 'ActionDebugValidation.vcxproj.filters',
        'Invoke-Validation.ps1', 'README.md') | ForEach-Object {
        $path = Join-Path $PSScriptRoot $_
        if (Test-Path -LiteralPath $path) {
            [ordered]@{ path = [IO.Path]::GetRelativePath($repo, $path); sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
        }
    }
    $os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
    $childPids = @([regex]::Matches($output, '(?m)^SESSION .*? pid=(\d+) ') | ForEach-Object { [int]$_.Groups[1].Value })
    $remaining = @($childPids | ForEach-Object {
        $candidate = Get-Process -Id $_ -ErrorAction SilentlyContinue
        if ($candidate -and $candidate.ProcessName -eq 'ActionDebugValidation') { $_ }
    })
    $passed = $buildExit -eq 0 -and $runExit -eq 0 -and !$watchdog -and
        $output -match '(?m)^RESULT=PASS ' -and $remaining.Count -eq 0
    $metadata = [ordered]@{
        recordedAt = (Get-Date).ToUniversalTime().ToString('o')
        executable = $exe
        executableSha256 = if (Test-Path -LiteralPath $exe) { (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash } else { $null }
        buildHost = $MSBuild; compiler = $compiler; priority = 'BelowNormal'
        intDir = $intDir; outDir = $outDir; buildExit = $buildExit; runExit = $runExit
        watchdogTriggered = $watchdog; parentPid = if ($process) { $process.Id } else { $null }
        assertionsPassed = ([regex]::Matches($output, '(?m)^ASSERT PASS ')).Count
        assertionsFailed = ([regex]::Matches($output, '(?m)^ASSERT FAIL ')).Count
        result = if ($passed) { 'PASS' } else { 'FAIL' }
        os = $os; childPids = $childPids; remainingFixtureChildPids = $remaining
        sessions = @($output -split '\r?\n' | Where-Object { $_ -match '^SESSION ' })
        stops = @($output -split '\r?\n' | Where-Object { $_ -match '^STOP ' })
        jobGuards = @($output -split '\r?\n' | Where-Object { $_ -match '^JOB_GUARD ' })
        cleanup = @($output -split '\r?\n' | Where-Object { $_ -match '^CLEANUP ' })
        controlledAbortTested = $output -match 'CLEANUP scenario=controlled_abort_.*exit=99 forced=1 expectedAbort=1 .*signaled=1 nativeExit=99 retainedProcessHandles=0'
        parentKillFaultInjectionTested = $false
        configurationFilesCreated = 0; runtimeCopiesCreated = 0; sources = @($sourceHashes)
        scope = 'Self-created AMD64 child, real Win32 Debug API, fixed known MASM call/leaf frame only. No driver, product backend, third-party attach, UI, network or security configuration.'
    }
    $metadata | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $metadataPath -Encoding utf8
    if ($process) { $process.Dispose() }
    $hostProcess.PriorityClass = $previousPriority
    Write-Output "METADATA=$metadataPath"
}
if (!$passed) { throw "Native debug validation failed; inspect $metadataPath" }
