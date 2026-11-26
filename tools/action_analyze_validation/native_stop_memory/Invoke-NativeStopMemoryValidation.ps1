param([string]$VcVars64)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$intDir = Join-Path $PSScriptRoot 'x64\Release'
$outDir = Join-Path $repo 'Ksword5.1\x64\Release'
$exe = Join-Path $outDir 'ActionAnalyzeNativeStopMemoryValidation.exe'
$logDir = Join-Path $repo '.codex-build-logs\behavior-planning'
$runId = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fffffff') + "-$PID"
$prefix = Join-Path $logDir "action-analyze-native-stop-memory-$runId"
$scratch = Join-Path $intDir 'native-stop-memory-archive-scratch'

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
$errors = ''
try {
    $hostProcess.PriorityClass = 'BelowNormal'
    $vcSetup = 'call "{0}" >nul && where cl.exe && where ml64.exe' -f $VcVars64
    $toolPaths = @(& $env:ComSpec /d /c $vcSetup)
    $tools = $toolPaths | Where-Object { $_ -match '\\Host[xX]64\\x64\\cl\.exe$' } | Select-Object -First 1
    $masm = $toolPaths | Where-Object { $_ -match '\\Host[xX]64\\x64\\ml64\.exe$' } | Select-Object -First 1
    if (!$tools -or !(Test-Path -LiteralPath $tools -PathType Leaf)) { throw "HostX64 compiler required. Found $toolPaths" }
    if (!$masm -or !(Test-Path -LiteralPath $masm -PathType Leaf)) { throw "HostX64 ml64 required. Found $toolPaths" }
    New-Item -ItemType Directory -Force -Path $intDir, $logDir, $outDir | Out-Null
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $scratch | Out-Null
    @("INTDIR=$intDir", "OUTDIR=$outDir", "HOSTX64=$tools", "MASM=$masm", "PRIORITY=$($hostProcess.PriorityClass)",
        'FLAGS=/std:c++20 /permissive- /EHsc /W4 /WX /O2 /MT /utf-8 /DNOMINMAX', "EXE=$exe", "SCRATCH=$scratch") |
        Tee-Object -FilePath "$prefix-build.log"

    $control = Join-Path $repo 'KswordCLI\ActionAnalyze\Control'
    $memory = Join-Path $repo 'KswordCLI\ActionAnalyze\Memory'
    $project = Join-Path $repo 'KswordCLI\ActionAnalyze\Project'
    $rules = Join-Path $repo 'KswordCLI\ActionAnalyze\Rules'
    $shared = Join-Path $repo 'shared'
    $peDir = Join-Path $repo 'Ksword5.1\Ksword5.1\ksword\file'
    $strDir = Join-Path $repo 'Ksword5.1\Ksword5.1\ksword\string'
    $archive = Join-Path $repo 'KswordCLI\ActionAnalyze\Archive'
    $sources = @(
        (Join-Path $PSScriptRoot 'NativeStopMemoryTests.cpp'),
        (Join-Path $control 'OwnedProcessGroup.cpp'),
        (Join-Path $control 'NativeDebugOwner.cpp'),
        (Join-Path $control 'NativePrivateExecutionSite.cpp'),
        (Join-Path $control 'NativeStepRuntime.cpp'),
        (Join-Path $control 'NativeBreakpointImage.cpp'),
        (Join-Path $control 'StopLedger.cpp'),
        (Join-Path $control 'ProcessGroupMemorySnapshot.cpp'),
        (Join-Path $control 'OwnedDataWatchSession.cpp'),
        (Join-Path $control 'OwnedDataWatchSessionArchive.cpp'),
        (Join-Path $control 'CooperativeBreakpointGate.cpp'),
        (Join-Path $control 'NativeExecutionEvidence.cpp'),
        (Join-Path $memory 'SelectedMemorySnapshot.cpp'),
        (Join-Path $memory 'PassiveDirtyMemory.cpp'),
        (Join-Path $project 'ProjectMemorySnapshot.cpp'),
        (Join-Path $project 'ProjectDocument.cpp'),
        (Join-Path $project 'ProjectLock.cpp'),
        (Join-Path $project 'SampleCatalog.cpp'),
        (Join-Path $project 'ProjectRawEvidence.cpp'),
        (Join-Path $project 'ProjectStorage.cpp'),
        (Join-Path $project 'ProjectNativeExecution.cpp'),
        (Join-Path $archive 'RawEvidenceArchive.cpp'),
        (Join-Path $archive 'SegmentBodies.cpp'),
        (Join-Path $archive 'SegmentFormat.cpp'),
        (Join-Path $archive 'SegmentInspection.cpp'),
        (Join-Path $archive 'SegmentReader.cpp'),
        (Join-Path $archive 'SegmentWriter.cpp'),
        (Join-Path $rules 'RuleExpression.cpp'),
        (Join-Path $rules 'FilterAst.cpp'),
        (Join-Path $shared 'evidence\EvidenceJson.cpp'),
        (Join-Path $shared 'evidence\LosslessValue.cpp'),
        (Join-Path $shared 'usermode\backend\Common.cpp'),
        (Join-Path $peDir 'pe_analyzer.cpp'),
        (Join-Path $strDir 'string.cpp')
    )
    foreach ($source in $sources) {
        if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing build source: $source" }
    }
    $sourceArgs = ($sources | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $asmObj = Join-Path $intDir 'NativeStopMemoryFixture.obj'
    $build = ('call "{0}" >nul && "{1}" /nologo /c /Fo"{2}" "{3}" && ' +
        '"{4}" /nologo /std:c++20 /permissive- /EHsc /W4 /WX /O2 /MT /utf-8 /DNOMINMAX ' +
        '/Fo"{5}\\" /Fd"{5}\compile.pdb" /Fe"{6}" {7} "{2}" /link /PDB:"{5}\link.pdb" Advapi32.lib Ole32.lib') -f
        $VcVars64, $masm, $asmObj, (Join-Path $PSScriptRoot 'NativeStopMemoryFixture.asm'),
        $tools, $intDir, $exe, $sourceArgs
    & $env:ComSpec /d /c $build 2>&1 | Tee-Object -FilePath "$prefix-build.log" -Append
    $buildExit = $LASTEXITCODE
    "BUILD_EXIT_CODE=$buildExit" | Tee-Object -FilePath "$prefix-build.log" -Append
    if ($buildExit -ne 0 -or !(Test-Path -LiteralPath $exe) -or (Get-Item -LiteralPath $exe).Length -eq 0) {
        throw "Native stop memory validation build failed. $prefix-build.log"
    }

    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.ArgumentList.Add($scratch)
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $watchdog = !$process.WaitForExit(240000)
    if ($watchdog) {
        $process.Kill()
        if (!$process.WaitForExit(5000)) { throw 'Validation parent did not exit after watchdog.' }
    }
    $output = $stdout.GetAwaiter().GetResult()
    $errors = $stderr.GetAwaiter().GetResult()
    $runExit = $process.ExitCode
    ($output + $errors) | Set-Content -LiteralPath "$prefix-run.log" -Encoding utf8
    Write-Output $output
    Write-Output $errors
} finally {
    $leftover = @(Get-Process -Name 'ActionAnalyzeNativeStopMemoryValidation' -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -ne $PID } | ForEach-Object { "$($_.Id):$($_.ProcessName)" })
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
    $scratchLeft = Test-Path -LiteralPath $scratch
    $passed = $buildExit -eq 0 -and $runExit -eq 0 -and !$watchdog -and
        $output -match 'RESULT=PASS checks=\d+' -and $leftover.Count -eq 0 -and !$scratchLeft
    $exeSha = if (Test-Path -LiteralPath $exe) { (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash } else { 'NONE' }
    @("BUILD_EXIT_CODE=$buildExit", "RUN_EXIT_CODE=$runExit", "WATCHDOG=$watchdog",
        "SCRATCH_CLEANED=$(if (!$scratchLeft) { 'yes' } else { 'no' })", "EXE_SHA256=$exeSha",
        "LEFTOVER_FIXTURE_PROCESSES=$($leftover -join ',')", "RESULT=$(if ($passed) { 'PASS' } else { 'FAIL' })",
        "BUILD_LOG=$prefix-build.log", "RUN_LOG=$prefix-run.log") | Tee-Object -FilePath "$prefix-metadata.txt"
    $hostProcess.PriorityClass = $priorPriority
    $hostProcess.Dispose()
}
if (!$passed) { throw "Native stop memory validation failed; inspect $prefix-run.log" }
"EVIDENCE=$prefix"
