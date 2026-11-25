param([string]$MSBuild, [switch]$Ledger)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$project = Join-Path $PSScriptRoot 'ActionAnalyzeSyncStopValidation.vcxproj'
$release = Join-Path $repo 'Ksword5.1\x64\Release'
$logs = Join-Path $repo '.codex-build-logs\behavior-planning'
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss-fffffff') + "-$PID"
$mode = if ($Ledger) { 'ledger' } else { 'baseline' }
$prefix = Join-Path $logs "action-analyze-sb02-$mode-$runId"
$owner = Join-Path $release 'ActionAnalyzeSyncStopValidationX64.exe'
$child = Join-Path $release 'ActionAnalyzeSyncStopValidationX86.exe'

function Read-PeMachine([string]$Path) {
    $file = [IO.BinaryReader]::new([IO.File]::OpenRead($Path))
    try {
        if ($file.ReadUInt16() -ne 0x5a4d) { throw "Missing MZ signature in $Path" }
        $file.BaseStream.Position = 0x3c
        $file.BaseStream.Position = $file.ReadUInt32()
        if ($file.ReadUInt32() -ne 0x4550) { throw "Missing PE signature in $Path" }
        $file.ReadUInt16()
    } finally {
        $file.Dispose()
    }
}

if (!$MSBuild) {
    $MSBuild = @('C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe',
        'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe') |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (!$MSBuild -or $MSBuild -notmatch '[\\/]amd64[\\/]MSBuild\.exe$' -or (Read-PeMachine $MSBuild) -ne 0x8664) {
    throw 'An installed AMD64 MSBuild executable is required.'
}

$hostProcess = [Diagnostics.Process]::GetCurrentProcess()
$savedPriority = $hostProcess.PriorityClass
$run = $null
$output = ''
$runExit = $null
$watchdog = $false
$builds = [Collections.Generic.List[object]]::new()
$artifacts = @()
$passed = $false
$failure = $null
New-Item -ItemType Directory -Path $logs -Force | Out-Null
try {
    $hostProcess.PriorityClass = 'BelowNormal'
    foreach ($platform in @('x64', 'Win32')) {
        $common = @('/p:Configuration=Release', "/p:Platform=$platform", '/p:PreferredToolArchitecture=x64',
            '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64', '/nologo')
        $arch = if ($platform -eq 'x64') { 'x64' } else { 'x86' }
        $target = if ($platform -eq 'x64') { $owner } else { $child }
        $evaluate = "-getProperty:IntDir,OutDir,TargetPath,VCToolsInstallDir,PreferredToolArchitecture,VC_ExecutablePath_$arch"
        $evaluation = & $MSBuild $project @common $evaluate 2>&1
        if ($LASTEXITCODE -ne 0) { throw "MSBuild property readback failed for $platform`n$evaluation" }
        $properties = ($evaluation -join "`n" | ConvertFrom-Json).Properties
        $intDir = [IO.Path]::GetFullPath($properties.IntDir).TrimEnd('\')
        $outDir = [IO.Path]::GetFullPath($properties.OutDir).TrimEnd('\')
        $toolDir = Join-Path $properties.VCToolsInstallDir "bin\HostX64\$arch"
        $compiler = Join-Path $toolDir 'cl.exe'
        $searchPath = $properties."VC_ExecutablePath_$arch"
        if ($intDir -ne (Join-Path $PSScriptRoot "$platform\Release") -or $outDir -ne $release -or
            [IO.Path]::GetFullPath($properties.TargetPath) -ne $target -or $properties.PreferredToolArchitecture -ne 'x64' -or
            ($searchPath.Split(';')[0]).TrimEnd('\') -ne $toolDir.TrimEnd('\') -or (Read-PeMachine $compiler) -ne 0x8664) {
            throw "Directories, target or HostX64 readback failed for $platform`n$evaluation"
        }
        $buildLog = "$prefix-build-$platform.log"
        @("BUILD_HOST=$MSBuild", "BUILD_PRIORITY=$($hostProcess.PriorityClass)", "INTDIR=$intDir", "OUTDIR=$outDir",
            "TARGET=$target", "HOSTX64=$compiler", "VC_EXECUTABLE_PATH=$searchPath", 'WARNINGS=/W4 /WX') |
            Tee-Object -FilePath $buildLog
        & $MSBuild $project @common /t:Build /m:1 /nr:false /v:normal 2>&1 | Tee-Object -FilePath $buildLog -Append
        $exitCode = $LASTEXITCODE
        "BUILD_EXIT_CODE=$exitCode" | Add-Content -LiteralPath $buildLog -Encoding utf8
        $builds.Add([ordered]@{ platform = $platform; exitCode = $exitCode; compiler = $compiler; intDir = $intDir; outDir = $outDir; log = $buildLog })
        if ($exitCode -ne 0) { throw "Build failed for $platform. See $buildLog" }
        $machine = if ($arch -eq 'x64') { 0x8664 } else { 0x014c }
        if ((Read-PeMachine $target) -ne $machine) { throw "Unexpected fixture machine in $target" }
        $pdb = [IO.Path]::ChangeExtension($target, '.pdb')
        $artifacts += [ordered]@{ path = $target; machine = ('0x{0:x4}' -f $machine); sha256 = (Get-FileHash -LiteralPath $target).Hash;
            pdb = $pdb; pdbSha256 = (Get-FileHash -LiteralPath $pdb).Hash }
    }

    $start = [Diagnostics.ProcessStartInfo]::new($owner)
    if ($Ledger) { $start.ArgumentList.Add('--ledger') }
    $start.WorkingDirectory = $release
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $run = [Diagnostics.Process]::Start($start)
    $outTask = $run.StandardOutput.ReadToEndAsync()
    $errTask = $run.StandardError.ReadToEndAsync()
    $watchdog = !$run.WaitForExit(50000)
    if ($watchdog) {
        # 只终止本次 Process 对象。子进程创建时已进入由该 owner 持有的私有 Job。
        if (!$run.HasExited) { $run.Kill() }
        if (!$run.WaitForExit(3000)) { throw 'Exact owner failed to exit after its watchdog.' }
    }
    if (!$outTask.Wait(2000) -or !$errTask.Wait(2000)) { throw 'Owner output did not close within bound.' }
    $output = $outTask.GetAwaiter().GetResult() + $errTask.GetAwaiter().GetResult()
    $runExit = $run.ExitCode
    $output | Set-Content -LiteralPath "$prefix-run.log" -Encoding utf8
    $output -split '\r?\n' | Where-Object { $_ -match '^(OWNER|SESSION|ARCHITECTURE|ROUTE|STOP|FORWARD|CLEANUP|LEDGER|RESULT|UNEXPECTED|FAIL_|WIN32_FAILURE|ASSERT FAIL)' }
} catch {
    $failure = $_
} finally {
    try {
        $childPids = @([regex]::Matches($output, '(?m)^SESSION .*? childPid=(\d+) ') | ForEach-Object { [int]$_.Groups[1].Value })
        $remaining = @($childPids | ForEach-Object {
            Get-Process -Id $_ -ErrorAction SilentlyContinue |
                Where-Object ProcessName -Match '^ActionAnalyzeSyncStopValidationX(64|86)$' | Select-Object -ExpandProperty Id
        })
        $cleanup = @($output -split '\r?\n' | Where-Object { $_ -match '^CLEANUP ' })
        $stops = @($output -split '\r?\n' | Where-Object { $_ -match '^STOP ' })
        $forwards = @($output -split '\r?\n' | Where-Object { $_ -match '^FORWARD ' })
        $ledgerEvidence = @($output -split '\r?\n' | Where-Object { $_ -match '^LEDGER(?:_| )' })
        $ledgerPassed = if ($Ledger) {
            ($ledgerEvidence -match '^LEDGER_SCOPE ').Count -eq 4 -and
            ($ledgerEvidence -match '^LEDGER .*state=held-complete ').Count -eq 4 -and
            ($ledgerEvidence -match '^LEDGER .*state=origin-held ').Count -eq 4 -and
            ($ledgerEvidence -match '^LEDGER_FAILURE ').Count -eq 2 -and
            ($ledgerEvidence -match '^LEDGER_WITHHELD ').Count -eq 4 -and
            ($ledgerEvidence -match '^LEDGER_READBACK ').Count -eq 2 -and
            ($ledgerEvidence -match '^LEDGER_EXIT_RETIRED ').Count -eq 2 -and
            ($ledgerEvidence -match '^LEDGER_RELEASED ').Count -eq 8 -and
            ($ledgerEvidence -match '^LEDGER_NATIVE_CONTINUE ').Count -eq 8 -and
            ($ledgerEvidence -match '^LEDGER_OWNER_FAILURE ').Count -eq 0
        } else { $ledgerEvidence.Count -eq 0 }
        $failedChecks = ([regex]::Matches($output, '(?m)^ASSERT FAIL ')).Count
        $passed = !$failure -and $runExit -eq 0 -and !$watchdog -and $ledgerPassed -and
            $output -match "(?m)^RESULT=PASS sessions=4 assertions=\d+ mode=$mode\r?$" -and
            $childPids.Count -eq 4 -and $remaining.Count -eq 0 -and $cleanup.Count -eq 4 -and $stops.Count -eq 8 -and
            $forwards.Count -eq 8 -and $failedChecks -eq 0 -and $output -notmatch '(?m)^EVENT_FILE_CLOSE_FAILED '
        [ordered]@{
            osVersion = [Environment]::OSVersion.Version.ToString(); result = if ($passed) { 'PASS' } else { 'FAIL' }
            recordedAt = (Get-Date).ToUniversalTime().ToString('o'); msbuild = $MSBuild; buildPriority = 'BelowNormal'; builds = $builds
            validationMode = $mode; ledgerEvidence = $ledgerEvidence
            runExit = $runExit; watchdogTriggered = $watchdog; failure = if ($failure) { $failure.ToString() } else { $null }
            ownerPid = if ($run) { $run.Id } else { $null }; childPids = $childPids; remainingFixtureChildPids = $remaining
            assertionsPassed = ([regex]::Matches($output, '(?m)^ASSERT PASS ')).Count; assertionsFailed = $failedChecks
            cleanup = $cleanup; stops = $stops; forwardedExceptions = $forwards; artifacts = $artifacts
            sources = @(Get-ChildItem -LiteralPath $PSScriptRoot -File | Sort-Object Name | ForEach-Object {
                [ordered]@{ name = $_.Name; sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash }
            })
            ledgerSources = @('StopLedger.h', 'StopLedger.cpp' | ForEach-Object {
                $path = "KswordCLI/ActionAnalyze/Control/$_"
                [ordered]@{ name = $path; sha256 = (Get-FileHash -LiteralPath (Join-Path $repo $path)).Hash }
            })
            configurationFilesCreated = 0; runtimeCopiesCreated = 0
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$prefix-metadata.json" -Encoding utf8
        Write-Output "METADATA=$prefix-metadata.json"
    } finally {
        if ($run) { $run.Dispose() }
        $hostProcess.PriorityClass = $savedPriority
        $hostProcess.Dispose()
    }
}
if ($failure) { throw $failure }
if (!$passed) { throw "SB02 validation failed. See $prefix-metadata.json" }
