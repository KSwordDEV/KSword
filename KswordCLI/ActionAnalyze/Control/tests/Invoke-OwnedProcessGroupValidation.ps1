param([string]$VcVars64)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..'))
$intDir = Join-Path $PSScriptRoot 'x64\Release\OwnedProcessGroup'
$outDir = Join-Path $repo 'Ksword5.1\x64\Release'
$exe = Join-Path $outDir 'ActionAnalyzeOwnedProcessGroupValidation.exe'
$control = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $repo '.codex-build-logs\behavior-planning'
$runId = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fffffff') + "-$PID"
$prefix = Join-Path $logDir "action-analyze-owned-process-group-$runId"

if (!$VcVars64) {
    $VcVars64 = @('C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
        'D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat') | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
}
if (!$VcVars64 -or !(Test-Path -LiteralPath $VcVars64 -PathType Leaf)) { throw 'MSVC vcvars64.bat is required.' }

$hostProcess = [Diagnostics.Process]::GetCurrentProcess()
$priorPriority = $hostProcess.PriorityClass
try {
    $hostProcess.PriorityClass = 'BelowNormal'
    $vcSetup = 'call "{0}" >nul && where cl.exe' -f $VcVars64
    $toolPaths = @(& $env:ComSpec /d /c $vcSetup)
    $tools = $toolPaths | Where-Object { $_ -match '\\HostX64\\x64\\cl\.exe$' } | Select-Object -First 1
    if (!$tools -or !(Test-Path -LiteralPath $tools -PathType Leaf)) { throw "HostX64 compiler required. Found $toolPaths" }
    New-Item -ItemType Directory -Force -Path $intDir, $logDir, $outDir | Out-Null
    @("INTDIR=$intDir", "OUTDIR=$outDir", "HOSTX64=$tools", "PRIORITY=$($hostProcess.PriorityClass)", "EXE=$exe") |
        Tee-Object -FilePath "$prefix-build.log"

    # 无窗口独立测试：直接编译生产源与测试体到统一 Release，不使用临时工程或运行副本。
    $build = ('call "{0}" >nul && "{1}" /nologo /std:c++20 /permissive- /EHsc /W4 /WX /O2 /MT /utf-8 ' +
        '/Fo"{2}\\" /Fd"{2}\compile.pdb" /Fe"{3}" "{4}\OwnedProcessGroup.cpp" "{4}\NativeDebugOwner.cpp" ' +
        '"{4}\NativeStepRuntime.cpp" "{4}\NativeBreakpointImage.cpp" "{4}\NativePrivateExecutionSite.cpp" "{4}\StopLedger.cpp" ' +
        '"{4}\ProcessGroupMemorySnapshot.cpp" "{4}\..\Memory\SelectedMemorySnapshot.cpp" ' +
        '"{4}\..\Memory\PassiveDirtyMemory.cpp" "{4}\..\Project\ProjectStorage.cpp" "{6}\shared\evidence\EvidenceJson.cpp" ' +
        '"{6}\shared\evidence\LosslessValue.cpp" "{6}\shared\usermode\backend\Common.cpp" ' +
        '"{6}\Ksword5.1\Ksword5.1\ksword\file\pe_analyzer.cpp" "{6}\Ksword5.1\Ksword5.1\ksword\string\string.cpp" ' +
        '"{5}\OwnedProcessGroupTests.cpp" /link /PDB:"{2}\link.pdb"') -f
        $VcVars64, $tools, $intDir, $exe, $control, $PSScriptRoot, $repo
    & $env:ComSpec /d /c $build 2>&1 | Tee-Object -FilePath "$prefix-build.log" -Append
    $buildCode = $LASTEXITCODE
    "BUILD_EXIT_CODE=$buildCode" | Tee-Object -FilePath "$prefix-build.log" -Append
    if ($buildCode -ne 0) { throw "Validation build failed. $prefix-build.log" }

    $output = & $exe 2>&1
    $runCode = $LASTEXITCODE
    @("OS_BUILD=$([Environment]::OSVersion.Version)", "RUN_EXIT_CODE=$runCode", "EXE_SHA256=$((Get-FileHash -LiteralPath $exe).Hash)", $output) |
        Tee-Object -FilePath "$prefix-run.log"
    if ($runCode -ne 0 -or !($output -match '^RESULT=PASS checks=\d+$')) { throw "Validation failed. $prefix-run.log" }
    "EVIDENCE=$prefix"
} finally {
    $hostProcess.PriorityClass = $priorPriority
    $hostProcess.Dispose()
}
