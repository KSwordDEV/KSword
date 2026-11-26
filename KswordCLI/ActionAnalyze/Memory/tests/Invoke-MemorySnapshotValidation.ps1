param([string]$MSBuild)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..'))
$testProject = Join-Path $PSScriptRoot 'ActionAnalyzeMemorySnapshotValidation.vcxproj'
$expectedOut = Join-Path $repo 'Ksword5.1\x64\Release'
$expectedInt = Join-Path $PSScriptRoot 'x64\Release'
$exe = Join-Path $expectedOut 'ActionAnalyzeMemorySnapshotValidation.exe'
$pdb = Join-Path $expectedOut 'ActionAnalyzeMemorySnapshotValidation.pdb'
$scratch = Join-Path $repo 'KswordCLI\x64\Release\ActionAnalyzeMemorySnapshotValidation'
$logDir = Join-Path $repo '.codex-build-logs\memory-snapshot'
$runId = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fffffff') + "-$PID"
$prefix = Join-Path $logDir "memory-snapshot-native-$runId"

if (!$MSBuild) {
    $MSBuild = @('C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe',
        'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe') |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (!$MSBuild -or $MSBuild -notmatch '[\\/]amd64[\\/]MSBuild\.exe$') { throw 'Installed AMD64 MSBuild is required.' }

# 固定输出位置必须空闲且未被 Git 跟踪，避免覆盖正式产物或用户工作。
$tracked = git -C $repo ls-files -- 'KswordCLI/x64/Release/ActionAnalyzeMemorySnapshotValidation' 'Ksword5.1/x64/Release/ActionAnalyzeMemorySnapshotValidation.exe'
if ($LASTEXITCODE -ne 0 -or $tracked) { throw 'Memory snapshot test output paths must be untracked.' }
if (Test-Path -LiteralPath $scratch) { throw "Scratch already exists: $scratch" }

$hostProcess = [Diagnostics.Process]::GetCurrentProcess()
$priorPriority = $hostProcess.PriorityClass
try {
    $hostProcess.PriorityClass = 'BelowNormal'
    $common = @('/nologo', '/p:Configuration=Release', '/p:Platform=x64', '/p:PreferredToolArchitecture=x64',
        '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64')
    $evaluation = & $MSBuild $testProject @common '-getProperty:IntDir,OutDir,TargetPath,VC_ExecutablePath_x64' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Build property readback failed: $evaluation" }
    $properties = ($evaluation -join "`n" | ConvertFrom-Json).Properties
    $intDir = [IO.Path]::GetFullPath($properties.IntDir).TrimEnd('\')
    $outDir = [IO.Path]::GetFullPath($properties.OutDir).TrimEnd('\')
    $tools = ($properties.VC_ExecutablePath_x64.Split(';')[0]).TrimEnd('\')
    if ($intDir -ne $expectedInt -or $outDir -ne $expectedOut -or $properties.TargetPath -ne $exe -or
        $tools -notmatch '\\HostX64\\x64$' -or !(Test-Path -LiteralPath (Join-Path $tools 'cl.exe'))) {
        throw "Build directory or HostX64 mismatch: $evaluation"
    }
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    New-Item -ItemType Directory -Path $scratch -Force | Out-Null
    @("BUILD_HOST=$MSBuild", "BUILD_PRIORITY=$($hostProcess.PriorityClass)", "INTDIR=$intDir", "OUTDIR=$outDir", "HOSTX64=$tools") |
        Tee-Object -FilePath "$prefix-build.log"
    & $MSBuild $testProject @common /t:Build /m:1 /nr:false /v:minimal 2>&1 | Tee-Object -FilePath "$prefix-build.log" -Append
    $buildCode = $LASTEXITCODE
    "BUILD_EXIT_CODE=$buildCode" | Tee-Object -FilePath "$prefix-build.log" -Append
    if ($buildCode -ne 0) { throw "Build failed. $prefix-build.log" }

    $output = & $exe $scratch 2>&1
    $runCode = $LASTEXITCODE
    @("RUN_EXIT_CODE=$runCode", "EXE_SHA256=$((Get-FileHash -LiteralPath $exe).Hash)", $output) |
        Tee-Object -FilePath "$prefix-run.log"
    if ($runCode -ne 0 -or !($output -match '^RESULT=PASS scenarios=\d+ checks=\d+$')) {
        throw "Validation failed. $prefix-run.log"
    }
    Write-Output "EVIDENCE=$prefix"
} finally {
    $hostProcess.PriorityClass = $priorPriority
    $hostProcess.Dispose()
    # 本脚本独占创建这些位置；结束时清除本次测试运行产物，保留文本日志。
    if (Test-Path -LiteralPath $exe -PathType Leaf) { Remove-Item -LiteralPath $exe -Force }
    if (Test-Path -LiteralPath $pdb -PathType Leaf) { Remove-Item -LiteralPath $pdb -Force }
    if ((Test-Path -LiteralPath $scratch) -and
        ([IO.Path]::GetFullPath($scratch).TrimEnd('\') -eq $scratch)) {
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
}
