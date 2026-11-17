[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),

    [ValidateSet('Build', 'Rebuild')]
    [string]$Action = 'Build',

    [switch]$VerifyArtifactOnly,
    [switch]$DisableWholeProgramOptimization,
    # Diagnostic build only; the ordinary Release configuration stays probe-free.
    [switch]$EnablePerfTrace,
    [switch]$SkipAutoTestSign,

    [ValidateRange(1, 120)]
    [int]$TimeoutMinutes = 20,

    [ValidateRange(15, 300)]
    [int]$HeartbeatSeconds = 45,

    [ValidateRange(20, 500)]
    [int]$FailureTailLines = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    return '"' + $Value.Replace('"', '\"') + '"'
}

function Classify-BuildFailure {
    param([Parameter(Mandatory = $true)][string]$Text)

    if ($Text -match '(?is)LNK1000.*(?:IMAGE::BuildImage|IncrBuildImage)|IMAGE::BuildImage.*LNK1000') {
        return 'MSVC_LNK1000_IMAGE_BUILD'
    }
    if ($Text -match '(?is)MSB6001.*(?:PATH|Path).*Key') {
        return 'ENV_PATH_CASE_COLLISION'
    }
    if ($Text -match '(?is)LNK1104') {
        return 'OUTPUT_OR_LIBRARY_LOCKED'
    }
    if ($Text -match '(?is)(?:fatal error|error) C\d{4}') {
        return 'CPP_COMPILER_ERROR'
    }
    if ($Text -match '(?is)(?:fatal error|error) LNK\d{4}') {
        return 'MSVC_LINK_ERROR'
    }
    if ($Text -match '(?is)There''s no Qt version assigned|Qt\.props|Qt\.targets') {
        return 'QT_CONFIGURATION_ERROR'
    }
    if ($Text -match '(?is)i18n audit failed|missing source translations') {
        return 'I18N_AUDIT_ERROR'
    }
    return 'UNCLASSIFIED_BUILD_FAILURE'
}

$resolvedRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$agentFile = Join-Path $resolvedRoot 'AGENTS.md'
$projectPath = Join-Path $resolvedRoot 'Ksword5.1\Ksword5.1\Ksword5.1.vcxproj'
$artifactPath = Join-Path $resolvedRoot 'Ksword5.1\x64\Release\Ksword5.1.exe'
$qtDirectory = Join-Path $resolvedRoot '.deps\Qt\6.9.3\msvc2022_64'
if (-not (Test-Path -LiteralPath $qtDirectory)) {
    $qtDirectory = 'D:\Software\Qt\6.9.3\msvc2022_64'
}
$qtMsBuildDirectory = Join-Path $resolvedRoot '.deps\QtVsTools\msbuild'
$primaryMsBuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
$fallbackMsBuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe'

foreach ($requiredPath in @($agentFile, $projectPath, $qtDirectory, $qtMsBuildDirectory)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required KSword build path is missing: $requiredPath"
    }
}

$msbuildPath = if (Test-Path -LiteralPath $primaryMsBuild) {
    $primaryMsBuild
} elseif (Test-Path -LiteralPath $fallbackMsBuild) {
    $fallbackMsBuild
} else {
    throw '64-bit MSBuild was not found in either AGENTS.md-approved location.'
}

$msbuildImage = [System.IO.File]::ReadAllBytes($msbuildPath)
$peOffset = [BitConverter]::ToInt32($msbuildImage, 0x3c)
if ([BitConverter]::ToUInt16($msbuildImage, $peOffset + 4) -ne 0x8664) {
    throw "Refusing to use a non-x64 MSBuild executable: $msbuildPath"
}

$activeBuilds = @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -in @('MSBuild.exe', 'cl.exe', 'link.exe') -and
        $_.CommandLine -match [regex]::Escape($projectPath)
    })
if ($activeBuilds.Count -gt 0) {
    $activeIds = ($activeBuilds.ProcessId | Sort-Object) -join ','
    throw "A KSword build is already active (PID: $activeIds). Do not start a duplicate build."
}

if ($VerifyArtifactOnly) {
    $artifact = Get-Item -LiteralPath $artifactPath -ErrorAction SilentlyContinue
    if (-not $artifact -or $artifact.Length -le 0) {
        Write-Output 'BUILD_RESULT=FAILURE'
        Write-Output 'FAILURE_CLASS=ARTIFACT_MISSING_OR_EMPTY'
        Write-Output "ARTIFACT=$artifactPath"
        exit 2
    }

    $artifactHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash
    Write-Output 'BUILD_RESULT=SUCCESS'
    Write-Output 'MODE=ARTIFACT_ONLY'
    Write-Output 'EXIT_CODE=0'
    Write-Output "ARTIFACT=$artifactPath"
    Write-Output "ARTIFACT_BYTES=$($artifact.Length)"
    Write-Output "ARTIFACT_LAST_WRITE=$($artifact.LastWriteTime.ToString('o'))"
    Write-Output "ARTIFACT_SHA256=$artifactHash"
    exit 0
}

function Write-KSwordSourceIdentity([string]$Boundary) {
    $identityCommit = 'unavailable'
    $identityDirty = 'unavailable'
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $identityHead = & git --no-optional-locks -C $resolvedRoot rev-parse --verify HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and $identityHead -match '^[0-9a-fA-F]{40}$') {
            $identityCommit = $identityHead
            $identityStatus = @(& git --no-optional-locks -C $resolvedRoot status --porcelain --untracked-files=no 2>$null)
            if ($LASTEXITCODE -eq 0) { $identityDirty = if ($identityStatus.Count) { 'true' } else { 'false' } }
        }
    }
    Write-Output "BUILD_SOURCE_COMMIT_$Boundary=$identityCommit"
    Write-Output "BUILD_SOURCE_DIRTY_$Boundary=$identityDirty"
}
Write-KSwordSourceIdentity 'BEGIN'

$logDirectory = Join-Path $resolvedRoot '.codex-build-logs'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$buildStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$rawLogPath = Join-Path $logDirectory "ksword-build-check-$buildStamp.raw.log"
$errorLogPath = Join-Path $logDirectory "ksword-build-check-$buildStamp.err.log"
$temporaryPropsPath = $null
$previousQtDirectory = [Environment]::GetEnvironmentVariable('KSWORD_QT_DIR', 'Process')
$buildStartedAt = Get-Date
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$timedOut = $false
$exitCode = 1
$buildHostProcess = [System.Diagnostics.Process]::GetCurrentProcess()
$previousPriorityClass = $buildHostProcess.PriorityClass

try {
    # Windows children inherit BelowNormal; set it before starting build tools.
    $buildHostProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
    $arguments = @(
        (Quote-ProcessArgument $projectPath),
        "/t:$Action",
        '/p:Configuration=Release',
        '/p:Platform=x64',
        '/p:PreferredToolArchitecture=x64',
        '/p:PROCESSOR_ARCHITECTURE=AMD64',
        '/p:PROCESSOR_ARCHITEW6432=AMD64',
        (Quote-ProcessArgument "/p:QtMsBuild=$qtMsBuildDirectory"),
        '/m:1',
        '/v:minimal'
    )

    if ($SkipAutoTestSign) {
        $arguments += '/p:KswordArkSkipAutoTestSign=true'
    }

    if ($DisableWholeProgramOptimization -or $EnablePerfTrace) {
        $temporaryPropsPath = Join-Path $logDirectory (
            'ksword-build-check-' + [guid]::NewGuid().ToString('N') + '.props')
        $compilerSettings = ''
        $linkSettings = ''
        if ($DisableWholeProgramOptimization) {
            $compilerSettings = '<WholeProgramOptimization>false</WholeProgramOptimization>'
            $linkSettings = '<Link><LinkTimeCodeGeneration>Default</LinkTimeCodeGeneration></Link>'
        }
        if ($EnablePerfTrace) {
            $compilerSettings += @'
<PreprocessorDefinitions Condition="'$(MSBuildProjectName)' == 'Ksword5.1'">KSWORD_PERF_TRACE_ENABLED=1;%(PreprocessorDefinitions)</PreprocessorDefinitions>
'@
        }
        $propsText = @'
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)' == 'Release|x64'">
    <ClCompile>
      __COMPILER_SETTINGS__
    </ClCompile>
    __LINK_SETTINGS__
  </ItemDefinitionGroup>
</Project>
'@
        $propsText = $propsText.Replace('__COMPILER_SETTINGS__', $compilerSettings).Replace('__LINK_SETTINGS__', $linkSettings)
        [System.IO.File]::WriteAllText($temporaryPropsPath, $propsText, [System.Text.UTF8Encoding]::new($false))
        $arguments += Quote-ProcessArgument "/p:ForceImportAfterCppTargets=$temporaryPropsPath"
    }

    [Environment]::SetEnvironmentVariable('KSWORD_QT_DIR', $qtDirectory, 'Process')

    $toolPropertiesJson = & $msbuildPath $projectPath /p:Configuration=Release /p:Platform=x64 `
        /p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 `
        '-getProperty:PreferredToolArchitecture,VC_ExecutablePath_x64' /nologo
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the MSVC host tool configuration.' }
    $toolProperties = ($toolPropertiesJson -join "`n" | ConvertFrom-Json).Properties
    if ($toolProperties.PreferredToolArchitecture -ne 'x64' -or $toolProperties.VC_ExecutablePath_x64 -notmatch 'HostX64') {
        throw 'Refusing a build whose evaluated compiler/linker host is not x64.'
    }

    Write-Output "BUILD_START action=$Action wpo_disabled=$([bool]$DisableWholeProgramOptimization) timeout_minutes=$TimeoutMinutes"
    Write-Output "BUILD_PERF_TRACE_ENABLED=$([bool]$EnablePerfTrace)"
    Write-Output "BUILD_MSBUILD_X64=$msbuildPath"
    Write-Output 'BUILD_TOOL_ARCHITECTURE=x64'
    Write-Output 'BUILD_PRIORITY=BelowNormal'
    Write-Output "BUILD_HOST_TOOLS=$($toolProperties.VC_ExecutablePath_x64)"
    Write-Output "BUILD_LOG=$rawLogPath"

    $process = Start-Process `
        -FilePath $msbuildPath `
        -ArgumentList ($arguments -join ' ') `
        -WorkingDirectory $resolvedRoot `
        -RedirectStandardOutput $rawLogPath `
        -RedirectStandardError $errorLogPath `
        -WindowStyle Hidden `
        -PassThru

    # Windows PowerShell can lose ExitCode if no process handle was retained.
    # Read it while the child is alive; null is never a successful build result.
    $null = $process.Handle

    $timeoutMilliseconds = $TimeoutMinutes * 60 * 1000
    $heartbeatMilliseconds = $HeartbeatSeconds * 1000

    while (-not $process.HasExited) {
        $remainingMilliseconds = $timeoutMilliseconds - [int]$stopwatch.ElapsedMilliseconds
        if ($remainingMilliseconds -le 0) {
            $timedOut = $true
            break
        }

        $waitMilliseconds = [Math]::Min($heartbeatMilliseconds, $remainingMilliseconds)
        if ($process.WaitForExit($waitMilliseconds)) {
            break
        }

        Write-Output "BUILD_WAIT elapsed_seconds=$([int]$stopwatch.Elapsed.TotalSeconds) pid=$($process.Id)"
    }

    if ($timedOut) {
        & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F | Out-Null
        $process.WaitForExit()
        $exitCode = 124
    } else {
        $process.WaitForExit()
        $process.Refresh()
        $exitCode = $process.ExitCode
        if ($null -eq $exitCode) { throw 'MSBuild exit code was unavailable.' }
    }
}
finally {
    $buildHostProcess.PriorityClass = $previousPriorityClass
    $stopwatch.Stop()
    if ($null -eq $previousQtDirectory) {
        [Environment]::SetEnvironmentVariable('KSWORD_QT_DIR', $null, 'Process')
    } else {
        [Environment]::SetEnvironmentVariable('KSWORD_QT_DIR', $previousQtDirectory, 'Process')
    }

    if ($temporaryPropsPath -and (Test-Path -LiteralPath $temporaryPropsPath)) {
        Remove-Item -LiteralPath $temporaryPropsPath -Force
    }
}

Write-KSwordSourceIdentity 'END'

$rawText = if (Test-Path -LiteralPath $rawLogPath) {
    [System.IO.File]::ReadAllText($rawLogPath)
} else {
    ''
}
$errorText = if (Test-Path -LiteralPath $errorLogPath) {
    [System.IO.File]::ReadAllText($errorLogPath)
} else {
    ''
}
$combinedText = $rawText + [Environment]::NewLine + $errorText
$artifact = Get-Item -LiteralPath $artifactPath -ErrorAction SilentlyContinue
$artifactBytes = if ($artifact) { $artifact.Length } else { 0 }
$artifactUpdated = [bool]($artifact -and $artifact.LastWriteTime -ge $buildStartedAt.AddSeconds(-2))
$i18nPassed = $combinedText -match 'i18n audit passed:'
$success = $exitCode -eq 0 -and $artifactBytes -gt 0
if ($Action -eq 'Rebuild') {
    $success = $success -and $artifactUpdated
}

if ($success) {
    $artifactHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash
    Write-Output 'BUILD_RESULT=SUCCESS'
    Write-Output "EXIT_CODE=$exitCode"
    Write-Output "DURATION_SECONDS=$([int]$stopwatch.Elapsed.TotalSeconds)"
    Write-Output "ARTIFACT=$artifactPath"
    Write-Output "ARTIFACT_BYTES=$artifactBytes"
    Write-Output "ARTIFACT_UPDATED=$artifactUpdated"
    Write-Output "ARTIFACT_SHA256=$artifactHash"
    Write-Output "I18N_AUDIT_PASSED=$i18nPassed"
    Write-Output "RAW_LOG=$rawLogPath"
    exit 0
}

$failureClass = if ($timedOut) { 'BUILD_TIMEOUT' } else { Classify-BuildFailure $combinedText }
Write-Output 'BUILD_RESULT=FAILURE'
Write-Output "FAILURE_CLASS=$failureClass"
Write-Output "EXIT_CODE=$exitCode"
Write-Output "DURATION_SECONDS=$([int]$stopwatch.Elapsed.TotalSeconds)"
Write-Output "ARTIFACT_BYTES=$artifactBytes"
Write-Output "I18N_AUDIT_PASSED=$i18nPassed"
Write-Output "RAW_LOG=$rawLogPath"
Write-Output 'BUILD_FAILURE_TAIL_BEGIN'
if (Test-Path -LiteralPath $rawLogPath) {
    Get-Content -LiteralPath $rawLogPath -Tail $FailureTailLines
}
if (Test-Path -LiteralPath $errorLogPath) {
    Get-Content -LiteralPath $errorLogPath -Tail $FailureTailLines
}
Write-Output 'BUILD_FAILURE_TAIL_END'
exit $(if ($exitCode -ne 0) { $exitCode } else { 2 })
