param([string]$VcVars64, [ValidateSet('focused', 'full')][string]$Suite = 'focused',
    [string[]]$Scenario = @())

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..'))
$control = Split-Path -Parent $PSScriptRoot
$intDir = Join-Path $PSScriptRoot 'x64\Release\NativeStep'
$outDir = Join-Path $repo 'Ksword5.1\x64\Release'
$exe = Join-Path $outDir 'ActionAnalyzeNativeStepValidation.exe'
$logDir = Join-Path $repo '.codex-build-logs\behavior-planning'
$runId = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fffffff') + "-$PID"
$prefix = Join-Path $logDir "action-analyze-native-step-$runId"

if (!$VcVars64) {
    $VcVars64 = @('C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
        'D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat') | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
}
if (!$VcVars64 -or !(Test-Path -LiteralPath $VcVars64 -PathType Leaf)) { throw 'MSVC vcvars64.bat is required.' }

$hostProcess = [Diagnostics.Process]::GetCurrentProcess()
$priorPriority = $hostProcess.PriorityClass
$buildExit = $null
$runExit = $null
$watchdog = $false
$output = ''
try {
    $hostProcess.PriorityClass = 'BelowNormal'
    $vcSetup = 'call "{0}" >nul && where cl.exe && where ml64.exe' -f $VcVars64
    $toolPaths = @(& $env:ComSpec /d /c $vcSetup)
    $tools = $toolPaths | Where-Object { $_ -match '\\Host[xX]64\\x64\\cl\.exe$' } | Select-Object -First 1
    $masm = $toolPaths | Where-Object { $_ -match '\\Host[xX]64\\x64\\ml64\.exe$' } | Select-Object -First 1
    if (!$tools -or !(Test-Path -LiteralPath $tools -PathType Leaf)) { throw "HostX64 compiler required. Found $toolPaths" }
    if (!$masm -or !(Test-Path -LiteralPath $masm -PathType Leaf)) { throw "HostX64 ml64 required. Found $toolPaths" }
    New-Item -ItemType Directory -Force -Path $intDir, $logDir, $outDir | Out-Null
    @("INTDIR=$intDir", "OUTDIR=$outDir", "HOSTX64=$tools", "MASM=$masm", "PRIORITY=$($hostProcess.PriorityClass)",
        'WARNINGS=/W4 /WX', "EXE=$exe") | Tee-Object -FilePath "$prefix-build.log"

    # Fixed MASM fixture first, then the production owner sources and the test
    # body are compiled and linked directly into the unified Release output.
    $build = ('call "{0}" >nul && "{1}" /nologo /c /Fo"{2}\NativeStepFixture.obj" "{3}\NativeStepFixture.asm" && ' +
        '"{4}" /nologo /std:c++20 /permissive- /EHsc /W4 /WX /O2 /MT /utf-8 /Fo"{2}\\" /Fd"{2}\compile.pdb" ' +
        '/Fe"{5}" "{6}\NativeDebugOwner.cpp" "{6}\NativeStepRuntime.cpp" "{6}\NativeBreakpointImage.cpp" "{6}\NativePrivateExecutionSite.cpp" "{6}\StopLedger.cpp" ' +
        '"{6}\NativeExecutionEvidence.cpp" "{6}\NativeWriteExecutionTransition.cpp" ' +
        '"{6}\..\Project\ProjectStorage.cpp" "{7}\shared\evidence\EvidenceJson.cpp" ' +
        '"{7}\shared\evidence\LosslessValue.cpp" "{7}\shared\usermode\backend\Common.cpp" ' +
        '"{7}\Ksword5.1\Ksword5.1\ksword\file\pe_analyzer.cpp" "{7}\Ksword5.1\Ksword5.1\ksword\string\string.cpp" ' +
        '"{3}\NativeStepTests.cpp" "{2}\NativeStepFixture.obj" /link /PDB:"{2}\link.pdb" Advapi32.lib') -f
        $VcVars64, $masm, $intDir, $PSScriptRoot, $tools, $exe, $control, $repo
    & $env:ComSpec /d /c $build 2>&1 | Tee-Object -FilePath "$prefix-build.log" -Append
    $buildExit = $LASTEXITCODE
    "BUILD_EXIT_CODE=$buildExit" | Tee-Object -FilePath "$prefix-build.log" -Append
    if ($buildExit -ne 0) { throw "Native step validation build failed. $prefix-build.log" }
    if (!(Test-Path -LiteralPath $exe) -or (Get-Item -LiteralPath $exe).Length -eq 0) {
        throw 'Nonzero fixed Release executable is required.'
    }

    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.ArgumentList.Add('--diag-dir')
    $start.ArgumentList.Add($intDir)
    $start.ArgumentList.Add('--suite')
    $start.ArgumentList.Add($Suite)
    foreach ($name in $Scenario) {
        if ($name) {
            $start.ArgumentList.Add('--scenario')
            $start.ArgumentList.Add($name)
        }
    }
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $watchdog = !$process.WaitForExit(240000)
    if ($watchdog) {
        $process.Kill()
        if (!$process.WaitForExit(5000)) { throw 'Exact fixture parent did not exit after watchdog.' }
    }
    $output = $stdout.GetAwaiter().GetResult()
    $errors = $stderr.GetAwaiter().GetResult()
    $executedScenarios = ''
    if ($output -match '(?m)^SCENARIOS=(.*)$') { $executedScenarios = $Matches[1].Trim() }
    $runExit = $process.ExitCode
    ($output + $errors) | Set-Content -LiteralPath "$prefix-run.log" -Encoding utf8
    Write-Output $output
    Write-Output $errors
} finally {
    $leftover = @(Get-Process -Name 'ActionAnalyzeNativeStepValidation' -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.Id):$($_.ProcessName)" })
    $passed = $buildExit -eq 0 -and $runExit -eq 0 -and !$watchdog -and
        $output -match '(?m)^RESULT=PASS checks=\d+ failures=0$' -and $leftover.Count -eq 0
    @("BUILD_EXIT_CODE=$buildExit", "RUN_EXIT_CODE=$runExit", "WATCHDOG=$watchdog",
        "SUITE=$Suite", "SCENARIOS=$executedScenarios",
        "EXE_SHA256=$((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash)",
        "LEFTOVER_FIXTURE_PROCESSES=$($leftover -join ',')", "RESULT=$(if ($passed) { 'PASS' } else { 'FAIL' })",
        "BUILD_LOG=$prefix-build.log", "RUN_LOG=$prefix-run.log") |
        Tee-Object -FilePath "$prefix-metadata.txt"
    $hostProcess.PriorityClass = $priorPriority
    $hostProcess.Dispose()
}
if (!$passed) { throw "Native step validation failed; inspect $prefix-run.log" }
"EVIDENCE=$prefix"
