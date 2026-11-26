[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [string]$ExpectedCliSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = if ($RepositoryRoot) { [IO.Path]::GetFullPath($RepositoryRoot) }
        else { (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path }
$logDir = Join-Path $repo '.codex-build-logs'
$log = Join-Path $logDir 'action-analyze-process-group-cli.log'
$meta = Join-Path $logDir 'action-analyze-process-group-cli.json'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

function Write-Log([string]$text) {
    $text | Tee-Object -FilePath $log -Append
}

# 构建与整批实测在同一个 PowerShell 线程内持有同一个命名互斥。
$mutex = New-Object System.Threading.Mutex($false, 'Local\KSword.ActionAnalyze.CliValidation')
    $acquired = $false
    $abandoned = $false
    $hostProcess = [Diagnostics.Process]::GetCurrentProcess()
    $previousPriority = $hostProcess.PriorityClass
    try {
        "=== PROCESS GROUP CLI VALIDATION $(Get-Date -Format o) ===" | Out-File -FilePath $log -Encoding utf8
        try {
            $acquired = $mutex.WaitOne([TimeSpan]::FromMinutes(90))
        } catch [Threading.AbandonedMutexException] {
            # 上一个持有者异常退出时互斥被遗弃；本线程已经取得所有权，继续本批并记录该事实。
            $acquired = $true
            $abandoned = $true
        }
        if (!$acquired) { throw 'The validation mutex was not acquired.' }
        Write-Log 'MUTEX=Local\KSword.ActionAnalyze.CliValidation ACQUIRED=true'
        Write-Log "MUTEX_ABANDONED_BY_PREVIOUS_OWNER=$abandoned"
    $hostProcess.PriorityClass = 'BelowNormal'
    Write-Log "HOST_PRIORITY=$($hostProcess.PriorityClass)"

    # 构建前用 MSBuild 当前属性读回绝对 IntDir/OutDir 以及 CLToolPath 与 HostX64 工具路径。
    $candidates = @(
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
        'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe'
    )
    $msbuild = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (!$msbuild) { throw '64-bit MSBuild was not found in the approved locations.' }
    Write-Log "MSBUILD=$msbuild"
    $project = Join-Path $repo 'KswordCLI\KswordCLI.vcxproj'
    $solutionDir = (Join-Path $repo 'Ksword5.1') + '\'
    $queryArgs = @('/p:Configuration=Release', '/p:Platform=x64', '/p:PreferredToolArchitecture=x64',
        '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64',
        "/p:SolutionDir=$solutionDir", '/p:BuildProjectReferences=false', '/nologo')
    $query = & $msbuild $project @queryArgs '-getProperty:IntDir,OutDir,CLToolPath,CLToolExe,VCBinDir,VC_ExecutablePath_x64,ProjectDir,PreferredToolArchitecture'
    if ($LASTEXITCODE -ne 0) { throw "MSBuild property query failed: $LASTEXITCODE" }
    $properties = ($query -join "`n" | ConvertFrom-Json).Properties
    $intDir = [IO.Path]::GetFullPath($properties.IntDir, $properties.ProjectDir).TrimEnd('\')
    $outDir = [IO.Path]::GetFullPath($properties.OutDir, $properties.ProjectDir).TrimEnd('\')
    Write-Log "INTDIR=$intDir"
    Write-Log "OUTDIR=$outDir"
    Write-Log "CLTOOLPATH=$($properties.CLToolPath)"
    Write-Log "CLTOOLEXE=$($properties.CLToolExe)"
    Write-Log "VCBINDIR=$($properties.VCBinDir)"
    Write-Log "HOSTX64=$($properties.VC_ExecutablePath_x64)"
    Write-Log "PREFERRED_TOOL_ARCHITECTURE=$($properties.PreferredToolArchitecture)"
    $expectedIntDir = (Join-Path $repo 'KswordCLI\x64\Release').TrimEnd('\')
    $expectedOutDir = (Join-Path $repo 'Ksword5.1\x64\Release').TrimEnd('\')
    if ($intDir -ne $expectedIntDir -or $outDir -ne $expectedOutDir) {
        throw "Unexpected CLI build directories. IntDir=$intDir OutDir=$outDir"
    }
    if ($properties.VC_ExecutablePath_x64 -notmatch '(?i)HostX64[\\/]x64') {
        throw "Unexpected CLI compiler host: $($properties.VC_ExecutablePath_x64)"
    }

    # 正式 CLI 只做一次适用增量构建：使用仓库固定工程与统一 Release，参数与
    # tools/Invoke-KSwordNativeBuildCheck.ps1 的 CLI 分支一致（同一 SolutionDir、HostX64 偏好与固定目录）。
    # 直接调用 MSBuild 是为了在并行会话占用正式产物时识别 LNK1104 并等待重试，而不是重复编译。
    $buildOutput = @()
    $buildCode = 1
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        Write-Log "BUILD_ATTEMPT=$attempt"
        $buildOutput = @(& $msbuild $project @queryArgs /t:Build /m:1 /v:minimal 2>&1)
        $buildCode = $LASTEXITCODE
        $buildOutput | ForEach-Object { Write-Log "BUILD $_" }
        Write-Log "BUILD_EXIT_CODE=$buildCode"
        if ($buildCode -eq 0) { break }
        $detail = ($buildOutput | Out-String)
        if ($detail -notmatch 'LNK1104|cannot open file') {
            throw "The formal CLI build failed with exit code $buildCode."
        }
        Write-Log 'BUILD_RETRY_REASON=the formal artifact was locked by a parallel build'
        Start-Sleep -Seconds 20
    }
    if ($buildCode -ne 0) { throw "The formal CLI build failed after the retries with exit code $buildCode." }
    Write-Log 'BUILD_RESULT=SUCCESS'

    $artifact = Join-Path $repo 'Ksword5.1\x64\Release\KswordCLI.exe'
    $sha = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash
    Write-Log "CLI_SHA256=$sha"
    if ($ExpectedCliSha256 -and $sha -ne $ExpectedCliSha256.ToUpper()) {
        throw "The Release CLI SHA-256 does not match the expected value $ExpectedCliSha256."
    }

    # 整批实测在同一个锁内运行；夹具只使用固定 IntDir 与统一 Release。
    # 实测自身把细节写入同一日志文件，因此这里先收集其标准输出，实测结束后再合并，避免占用冲突。
    $harness = Join-Path $repo 'tools\action_analyze_validation\cli\product_process_group.py'
    $runOutput = & python -B $harness --expected-cli-sha256 $sha 2>&1
    $runCode = $LASTEXITCODE
    $runOutput | ForEach-Object { Write-Log "RUN $_" }
    Write-Log "RUN_EXIT_CODE=$runCode"
    if ($runCode -ne 0) { throw "The process-group CLI validation failed with exit code $runCode." }

    [ordered]@{
        schemaVersion = 1
        mutex = 'Local\KSword.ActionAnalyze.CliValidation'
        hostPriority = 'BelowNormal'
        msbuild = $msbuild
        intDir = $intDir
        outDir = $outDir
        clToolPath = $properties.CLToolPath
        clToolExe = $properties.CLToolExe
        vcBinDir = $properties.VCBinDir
        hostX64 = $properties.VC_ExecutablePath_x64
        buildExitCode = $buildCode
        runExitCode = $runCode
        cliSha256 = $sha
        log = $log
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $meta -Encoding utf8
    Write-Log "META=$meta"
    Write-Log 'RESULT=SUCCESS'
} finally {
    if ($acquired) {
        $mutex.ReleaseMutex()
        try { 'MUTEX_RELEASED=true' | Tee-Object -FilePath $log -Append } catch { }
    }
    $hostProcess.PriorityClass = $previousPriority
    $hostProcess.Dispose()
    $mutex.Dispose()
}
