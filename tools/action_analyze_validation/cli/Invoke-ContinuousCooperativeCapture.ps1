# 持续合作采集验收：全程持有命名互斥，锁内一次正式 CLI 构建 + 全部定向实测。
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$cliScript = Join-Path $PSScriptRoot 'continuous_cooperative_capture.py'
$buildCheck = Join-Path $root 'tools\Invoke-KSwordCliBuildCheck.ps1'
$logDir = Join-Path $root '.codex-build-logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir 'continuous-cooperative-capture.log'
$cli = Join-Path $root 'Ksword5.1\x64\Release\KswordCLI.exe'

function Write-Log([string]$text) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $text
    Write-Host $line
    Add-Content -LiteralPath $log -Value $line -Encoding UTF8
}

# 同一线程宿主创建并持有互斥；finally 中由该线程释放。
$mutex = New-Object System.Threading.Mutex($false, 'Local\KSword.ActionAnalyze.CliValidation')
$owned = $false
$exitCode = 2
try {
    try {
        $owned = $mutex.WaitOne(600000)
    } catch [System.Threading.AbandonedMutexException] {
        $owned = $true
        Write-Log 'MUTEX_ABANDONED_RECOVERED=True'
    }
    if (-not $owned) {
        Write-Log 'MUTEX_BUSY=1 另一验收宿主仍持有 Local\KSword.ActionAnalyze.CliValidation'
        exit 2
    }
    Write-Log ('MUTEX_ACQUIRED=True THREAD={0}' -f [System.Threading.Thread]::CurrentThread.ManagedThreadId)

    # 构建宿主与所有子进程以低于正常优先级启动。
    $hostProcess = [Diagnostics.Process]::GetCurrentProcess()
    $previousPriority = $hostProcess.PriorityClass
    try {
        $hostProcess.PriorityClass = 'BelowNormal'
        Write-Log ('BUILD_HOST_PRIORITY={0}' -f $hostProcess.PriorityClass)

        # 一次必要的正式 Release 增量构建；脚本内部先读回并打印绝对路径 HostX64。
        Write-Log 'BUILD_BEGIN tools/Invoke-KSwordCliBuildCheck.ps1 (Release x64, BuildProjectReferences=false)'
        & $buildCheck 2>&1 | ForEach-Object { Write-Log ('BUILD: ' + $_) }
        if ($LASTEXITCODE -ne 0) {
            throw "CLI 正式 Release 构建失败: EXIT=$LASTEXITCODE"
        }
        if (!(Test-Path -LiteralPath $cli -PathType Leaf)) {
            throw "CLI 产物不存在: $cli"
        }
        $hash = (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash
        Write-Log "BUILD_DONE KswordCLI_SHA256=$hash"

        # 全部实测串行运行在同一互斥内；脚本内部使用私有 console 与真实管道证据。
        Write-Log 'VALIDATION_BEGIN python -B continuous_cooperative_capture.py --case all'
        & python -B $cliScript '--case' 'all' 2>&1 | ForEach-Object { Write-Log ('TEST: ' + $_) }
        $exitCode = $LASTEXITCODE
        Write-Log "VALIDATION_DONE EXIT=$exitCode"
    } finally {
        $hostProcess.PriorityClass = $previousPriority
        Write-Log ('BUILD_HOST_PRIORITY_RESTORED={0}' -f $hostProcess.PriorityClass)
    }
} catch {
    Write-Log ("FATAL: " + $_.Exception.Message)
    $exitCode = 2
} finally {
    if ($owned) {
        $mutex.ReleaseMutex()
        Write-Log ('MUTEX_RELEASED=True THREAD={0}' -f [System.Threading.Thread]::CurrentThread.ManagedThreadId)
    }
    $mutex.Dispose()
}

exit $exitCode
