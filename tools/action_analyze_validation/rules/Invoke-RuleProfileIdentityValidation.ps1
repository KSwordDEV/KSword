<#
.SYNOPSIS
    构建并运行 ActionAnalyze 规则身份夹具（RuleExpressionValidation）。

.DESCRIPTION
    只构建独立无窗口夹具，不构建产品、GUI 或驱动，也不写 shared 验证结果。
    固定中间目录为 tools/action_analyze_validation/rules/x64/Release/RuleExpressionValidation，
    固定输出目录为 Ksword5.1/x64/Release，产物为 ActionAnalyzeRuleExpressionValidation.exe。
    固定位置已被占用时报错退出并报告，绝不删除任何既有产物或其它作者的测试文件。
    成功时只清理本次运行确切创建的夹具中间对象、两份测试 .ksaseg、test-api-presets.json 和夹具 EXE。
    构建宿主使用 BelowNormal 优先级，编译器与链接器必须是 HostX64 工具链。

.PARAMETER RepositoryRoot
    仓库根目录，默认取脚本所在目录的上三级。

.PARAMETER KeepArtifacts
    保留本次创建的夹具文件，便于人工核对。失败时无论如何都保留并报告确切路径。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools/action_analyze_validation/rules/Invoke-RuleProfileIdentityValidation.ps1
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = '',
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
$global:LASTEXITCODE = 0

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $scriptRoot '..\..\..'
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path

# 固定位置：与 README 中的独立夹具命令一致，不允许随机目录。
$intDir = Join-Path $RepositoryRoot 'tools\action_analyze_validation\rules\x64\Release\RuleExpressionValidation'
$outDir = Join-Path $RepositoryRoot 'Ksword5.1\x64\Release'
$exe = Join-Path $outDir 'ActionAnalyzeRuleExpressionValidation.exe'
$profile = Join-Path $outDir 'profiles\action_analyze_api_rules.json'
$logDir = Join-Path $RepositoryRoot '.codex-build-logs'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$stem = "action-analyze-rule-profile-identity-$stamp"
$logPath = Join-Path $logDir "$stem.log"
$receiptPath = Join-Path $logDir "$stem.json"
$batchPath = Join-Path $logDir "$stem.cmd"
$vcvarsLogPath = Join-Path $logDir "$stem.vcvars.log"

# 与 README 相同的十三个源文件。夹具自带 main，不登记到任何产品工程。
$sources = @(
    'KswordCLI/ActionAnalyze/Rules/FilterAst.cpp'
    'KswordCLI/ActionAnalyze/Rules/AnalysisRun.cpp'
    'KswordCLI/ActionAnalyze/Rules/RuleExpression.cpp'
    'KswordCLI/ActionAnalyze/Rules/BehaviorPresets.cpp'
    'KswordCLI/ActionAnalyze/Archive/RawEvidenceArchive.cpp'
    'KswordCLI/ActionAnalyze/Archive/SegmentBodies.cpp'
    'KswordCLI/ActionAnalyze/Archive/SegmentFormat.cpp'
    'KswordCLI/ActionAnalyze/Archive/SegmentReader.cpp'
    'KswordCLI/ActionAnalyze/Archive/SegmentWriter.cpp'
    'Ksword5.1/Ksword5.1/ActionAnalyze/BehaviorRuleDraft.cpp'
    'shared/evidence/EvidenceJson.cpp'
    'shared/evidence/LosslessValue.cpp'
    'tools/action_analyze_validation/rules/RuleExpressionValidation.cpp'
)

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $line
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
}

function Stop-WithFailure {
    param([int]$Code, [string]$Message, [switch]$KeepFiles)
    Write-Log $Message 'ERROR'
    $receipt = [ordered]@{
        task = 'action-analyze-rule-profile-identity'
        startedAt = $script:startedAt
        finishedAt = (Get-Date).ToString('o')
        repositoryRoot = $RepositoryRoot
        intDir = $intDir
        outDir = $outDir
        executable = $exe
        result = 'failed'
        exitCode = $Code
        detail = $Message
        log = $logPath
        cleanup = [ordered]@{ performed = $false; deferredReason = if ($KeepFiles) { 'failure keeps artifacts for inspection' } else { 'failure; see log for the artifacts already created' } }
    }
    Set-Content -LiteralPath $receiptPath -Value ($receipt | ConvertTo-Json -Depth 6) -Encoding UTF8
    Write-Output "RESULT=FAILED EXIT_CODE=$Code"
    exit $Code
}

# 只接受 HostX64 工具链：编译器和链接器都必须位于 Hostx64\x64 目录。
function Test-HostX64 {
    param([string]$Path, [string]$Tool)
    if (-not $Path) { return $false }
    $pattern = '\\Hostx64\\x64\\' + [regex]::Escape($Tool) + '\.exe$'
    return ($Path -match $pattern)
}

# 优先使用 vcvars64，其次使用 VsDevCmd 的 x64 主机参数。
function Find-HostToolchain {
    $roots = @(
        'C:\Program Files\Microsoft Visual Studio\2022'
        'C:\Program Files (x86)\Microsoft Visual Studio\2022'
        'D:\Software\VS'
        'D:\Software\VS2022'
    )
    $candidates = New-Object System.Collections.Generic.List[object]
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
        $install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        foreach ($one in @($install)) {
            if ($one) {
                $candidates.Add([pscustomobject]@{ Kind = 'vcvars64'; Path = (Join-Path $one 'VC\Auxiliary\Build\vcvars64.bat') })
                $candidates.Add([pscustomobject]@{ Kind = 'vsdevcmd'; Path = (Join-Path $one 'Common7\Tools\VsDevCmd.bat') })
            }
        }
    }
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($edition in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
            $candidates.Add([pscustomobject]@{ Kind = 'vcvars64'; Path = (Join-Path $edition.FullName 'VC\Auxiliary\Build\vcvars64.bat') })
            $candidates.Add([pscustomobject]@{ Kind = 'vsdevcmd'; Path = (Join-Path $edition.FullName 'Common7\Tools\VsDevCmd.bat') })
        }
        $candidates.Add([pscustomobject]@{ Kind = 'vcvars64'; Path = (Join-Path $root 'VC\Auxiliary\Build\vcvars64.bat') })
        $candidates.Add([pscustomobject]@{ Kind = 'vsdevcmd'; Path = (Join-Path $root 'Common7\Tools\VsDevCmd.bat') })
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate.Path -PathType Leaf) { return $candidate }
    }
    return $null
}

function Invoke-Batch {
    param([string]$Mode)
    $output = & cmd.exe /d /c "`"$batchPath`" $Mode" 2>&1
    $code = $LASTEXITCODE
    return [pscustomobject]@{ ExitCode = $code; Lines = @($output | ForEach-Object { "$_" }) }
}

# 相对仓库根的路径，用于核对 Git 跟踪状态。
function Get-RepoRelative {
    param([string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($RepositoryRoot, [System.StringComparison]::OrdinalIgnoreCase)) { return $full }
    return $full.Substring($RepositoryRoot.Length).TrimStart([char[]]@('\', '/')).Replace('\', '/')
}

function Test-GitTracked {
    param([string]$Path)
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { return $false }
    $relative = Get-RepoRelative $Path
    # git 对未跟踪文件会在 stderr 报错；PowerShell 5.1 在 Stop 偏好下会将其变成终止错误。
    # 只查询已跟踪列表并按输出判定，不用 --error-unmatch，也不污染脚本级错误偏好。
    $ErrorActionPreference = 'Continue'
    $tracked = @(& git -C $RepositoryRoot ls-files -- $relative 2>$null)
    return ($tracked.Count -gt 0)
}

$script:startedAt = (Get-Date).ToString('o')
if (-not (Test-Path -LiteralPath $logDir -PathType Container)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
Set-Content -LiteralPath $logPath -Value '' -Encoding UTF8

try {
    # 构建宿主优先级：编译、链接等子进程沿用低优先级。
    [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'BelowNormal'
    Write-Log "PriorityClass=BelowNormal"
    Write-Log "RepositoryRoot=$RepositoryRoot"
    Write-Log "IntDir=$intDir"
    Write-Log "OutDir=$outDir"
    Write-Log "Executable=$exe"
    Write-Log "Log=$logPath"

    # 占用检查：固定位置已有内容时报错退出，不删除任何既有产物。
    if (-not (Test-Path -LiteralPath $outDir -PathType Container)) {
        Stop-WithFailure 3 "OutDir 不存在：$outDir。本脚本不构建产品，请先由产品构建部署统一 Release。"
    }
    if (-not (Test-Path -LiteralPath $profile -PathType Leaf)) {
        Stop-WithFailure 3 "产品规则配置缺失：$profile。本脚本不构建产品，请先部署统一 Release 的规则配置。"
    }
    if (Test-Path -LiteralPath $intDir) {
        Stop-WithFailure 3 "固定中间目录已被占用：$intDir。请人工确认后自行处理，脚本不会删除。"
    }
    if (Test-Path -LiteralPath $exe) {
        Stop-WithFailure 3 "固定产物名已被占用：$exe。请人工确认后自行处理，脚本不会删除。"
    }
    $running = @(Get-Process -Name 'ActionAnalyzeRuleExpressionValidation' -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) {
        Stop-WithFailure 3 "已有同名夹具进程在运行（PID $($running.Id -join ',')），脚本不接管也不终止。"
    }

    # 工具链定位。
    $toolchain = Find-HostToolchain
    if (-not $toolchain) {
        Stop-WithFailure 4 '未找到本机 vcvars64 或 VsDevCmd，无法建立 HostX64 工具链环境。'
    }
    if ($toolchain.Kind -eq 'vcvars64') {
        $vcCall = "call `"$($toolchain.Path)`""
    } else {
        $vcCall = "call `"$($toolchain.Path)`" -arch=x64 -host_arch=x64"
    }
    Write-Log "Toolchain=$($toolchain.Kind) $($toolchain.Path)"

    $resolvedSources = @()
    foreach ($source in $sources) {
        $full = Join-Path $RepositoryRoot ($source.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            Stop-WithFailure 5 "缺少源文件：$full"
        }
        $resolvedSources += $full
    }
    $quotedSources = ($resolvedSources | ForEach-Object { '"' + $_ + '"' }) -join ' '

    $defines = '/DNOMINMAX'
    $clCommand = ('cl.exe /nologo /std:c++20 /EHsc /utf-8 /W4 /WX /O2 {0} /Fo"{1}\\" /Fe"{2}" {3} bcrypt.lib' -f $defines, $intDir, $exe, $quotedSources)

    $batch = @"
@echo off
setlocal EnableExtensions
set "MODE=%~1"
$vcCall >"$vcvarsLogPath" 2>&1
if errorlevel 1 (
echo VCVARS_FAILED
exit /b 10
)
rem CL and LINK are reserved compiler/linker option variables; never assign tool paths to them.
set "KSWORD_RULE_CL="
set "KSWORD_RULE_LINK="
for /f "delims=" %%i in ('where cl.exe') do if not defined KSWORD_RULE_CL set "KSWORD_RULE_CL=%%i"
for /f "delims=" %%i in ('where link.exe') do if not defined KSWORD_RULE_LINK set "KSWORD_RULE_LINK=%%i"
echo CL=%KSWORD_RULE_CL%
echo LINK=%KSWORD_RULE_LINK%
if "%MODE%"=="probe" exit /b 0
$clCommand
exit /b %ERRORLEVEL%
"@
    Set-Content -LiteralPath $batchPath -Value $batch -Encoding ASCII

    # 先探测工具链，确认是 HostX64 之后再编译。
    $probe = Invoke-Batch 'probe'
    foreach ($line in $probe.Lines) { Write-Log "probe: $line" }
    if ($probe.ExitCode -ne 0) {
        Stop-WithFailure 5 "工具链探测失败，退出码 $($probe.ExitCode)。详见 $vcvarsLogPath"
    }
    $compiler = ''
    $linker = ''
    foreach ($line in $probe.Lines) {
        if ($line -match '^CL=(.+)$') { $compiler = $Matches[1].Trim() }
        if ($line -match '^LINK=(.+)$') { $linker = $Matches[1].Trim() }
    }
    if (-not (Test-HostX64 $compiler 'cl')) {
        Stop-WithFailure 5 "编译器不是 HostX64：$compiler"
    }
    if (-not (Test-HostX64 $linker 'link')) {
        Stop-WithFailure 5 "链接器不是 HostX64：$linker"
    }
    Write-Log "HostX64=$compiler"
    Write-Log "Linker=$linker"

    # 执行前打印固定位置与 HostX64 工具链。
    Write-Output "IntDir=$intDir"
    Write-Output "OutDir=$outDir"
    Write-Output "HostX64=$compiler"

    [System.IO.Directory]::CreateDirectory($intDir) | Out-Null
    $env:TEMP = $intDir
    $env:TMP = $intDir

    $build = Invoke-Batch 'build'
    foreach ($line in $build.Lines) { Write-Log "build: $line" }
    if ($build.ExitCode -ne 0) {
        Stop-WithFailure 6 "夹具编译失败，退出码 $($build.ExitCode)。中间对象保留在 $intDir" -KeepFiles
    }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        Stop-WithFailure 6 "编译成功但产物缺失：$exe" -KeepFiles
    }
    $exeInfo = Get-Item -LiteralPath $exe
    $exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    Write-Log "ExecutableBytes=$($exeInfo.Length) SHA256=$exeHash"

    $fixtureOutput = & $exe $intDir 2>&1
    $fixtureCode = $LASTEXITCODE
    $fixtureLines = @($fixtureOutput | ForEach-Object { "$_" })
    foreach ($line in $fixtureLines) { Write-Log "fixture: $line" }
    Write-Log "FixtureExitCode=$fixtureCode"

    $summary = ''
    $identityState = 'unknown'
    foreach ($line in $fixtureLines) {
        if ($line -like 'ActionAnalyze rule expression:*') { $summary = $line }
        if ($line -like 'ActionAnalyze preset identity contract:*') { $identityState = $line }
    }
    # sourceSha256 已正式存在：只接受 identity active 且夹具零失败，不保留兼容通行开关。
    if ($identityState -notlike '*active*') {
        Stop-WithFailure 7 "身份契约未生效：$identityState。产品需要提供 ApiPresetDatabase::sourceSha256。" -KeepFiles
    }
    if ($fixtureCode -ne 0) {
        Stop-WithFailure 7 "夹具断言失败，退出码 $fixtureCode。夹具文件保留在 $intDir" -KeepFiles
    }

    # 清理：只删除本次运行确切创建的夹具文件。
    $intDirFull = [System.IO.Path]::GetFullPath($intDir)
    $exeFull = [System.IO.Path]::GetFullPath($exe)
    $objectNames = @($sources | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) + '.obj' })
    $candidates = @()
    foreach ($name in $objectNames) { $candidates += (Join-Path $intDir $name) }
    $candidates += (Join-Path $intDir 'test-api-presets.json')
    $candidates += (Join-Path $intDir 'preset-complete.ksaseg')
    $candidates += (Join-Path $intDir 'preset-no-end.ksaseg')
    $candidates += $exe

    $removed = @()
    $skipped = @()
    $intDirRemoved = $false
    if ($KeepArtifacts) {
        $skipped += 'KeepArtifacts 已指定，保留全部夹具文件'
    } else {
        $running = @(Get-Process -Name 'ActionAnalyzeRuleExpressionValidation' -ErrorAction SilentlyContinue)
        if ($running.Count -gt 0) {
            $skipped += "仍有同名夹具进程运行（PID $($running.Id -join ',')），不删除任何文件"
        } else {
            foreach ($candidate in $candidates) {
                $full = [System.IO.Path]::GetFullPath($candidate)
                $insideIntDir = $full.StartsWith($intDirFull, [System.StringComparison]::OrdinalIgnoreCase)
                if (-not $insideIntDir -and -not $full.Equals($exeFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $skipped += "越界路径，未删除：$full"
                    continue
                }
                if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
                if (Test-GitTracked $full) {
                    $skipped += "Git 已跟踪，未删除：$full"
                    continue
                }
                Remove-Item -LiteralPath $full -Force
                $removed += $full
            }
            if (Test-Path -LiteralPath $intDir -PathType Container) {
                $remaining = @(Get-ChildItem -LiteralPath $intDir -Force)
                if ($remaining.Count -eq 0) {
                    [System.IO.Directory]::Delete($intDir) # 只删除空目录，不递归。
                    $intDirRemoved = $true
                } else {
                    $skipped += "中间目录仍有未识别内容，未删除：$intDir"
                }
            }
        }
    }

    $receipt = [ordered]@{
        task = 'action-analyze-rule-profile-identity'
        startedAt = $script:startedAt
        finishedAt = (Get-Date).ToString('o')
        repositoryRoot = $RepositoryRoot
        intDir = $intDir
        outDir = $outDir
        executable = $exe
        executableSha256 = $exeHash
        hostX64Compiler = $compiler
        hostX64Linker = $linker
        sources = $sources
        buildExitCode = $build.ExitCode
        fixtureExitCode = $fixtureCode
        fixtureSummary = $summary
        identityContract = $identityState
        cleanup = [ordered]@{
            performed = (-not $KeepArtifacts)
            removed = $removed
            skipped = $skipped
            intDirRemoved = $intDirRemoved
        }
        log = $logPath
        receipt = $receiptPath
        result = 'passed'
        exitCode = 0
    }
    Set-Content -LiteralPath $receiptPath -Value ($receipt | ConvertTo-Json -Depth 6) -Encoding UTF8
    Write-Log "FixtureSummary=$summary"
    Write-Log "IdentityContract=$identityState"
    Write-Log "CleanupRemoved=$($removed.Count) CleanupSkipped=$($skipped.Count) IntDirRemoved=$intDirRemoved"
    Write-Output "SUMMARY=$summary"
    Write-Output "RECEIPT=$receiptPath"
    Write-Output "RESULT=PASSED EXIT_CODE=0"
    exit 0
} catch {
    Stop-WithFailure 9 "脚本异常：$($_.Exception.Message)" -KeepFiles
}
