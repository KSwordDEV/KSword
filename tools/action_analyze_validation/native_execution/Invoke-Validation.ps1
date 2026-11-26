param([string]$VcVars64, [string]$MSBuild)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$intDir = Join-Path $PSScriptRoot 'x64\Release'
$outDir = Join-Path $repo 'Ksword5.1\x64\Release'
$exe = Join-Path $outDir 'ActionAnalyzeNativeExecutionValidation.exe'
$project = Join-Path $PSScriptRoot 'NativeExecutionValidation.vcxproj'
$fixtureRoot = Join-Path $intDir 'project-fixture'
$logDir = Join-Path $repo '.codex-build-logs\behavior-planning'
$runId = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fffffff') + "-$PID"
$prefix = Join-Path $logDir "action-analyze-native-execution-$runId"

if (!$VcVars64) {
    $VcVars64 = @('D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat') |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (!$VcVars64 -or !(Test-Path -LiteralPath $VcVars64 -PathType Leaf)) {
    throw 'MSVC vcvars64.bat is required.'
}

if (!$MSBuild) {
    $vsRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $VcVars64)))
    $MSBuild = @((Join-Path $vsRoot 'MSBuild\Current\Bin\amd64\MSBuild.exe'),
        'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe',
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe') |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (!$MSBuild -or !(Test-Path -LiteralPath $MSBuild -PathType Leaf)) {
    throw '64-bit MSBuild.exe is required.'
}

$hostProcess = [Diagnostics.Process]::GetCurrentProcess()
$priorPriority = $hostProcess.PriorityClass
$buildExit = $null
$runExit = $null
$watchdog = $false
$fixtureCleaned = $false
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
    if (Test-Path -LiteralPath $fixtureRoot) {
        $resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
        $resolvedIntDir = [IO.Path]::GetFullPath($intDir)
        if (!$resolvedFixture.StartsWith($resolvedIntDir + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove unexpected fixture path $resolvedFixture"
        }
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
    @("INTDIR=$intDir", "OUTDIR=$outDir", "HOSTX64=$tools", "MASM=$masm", "MSBUILD=$MSBuild",
        "PRIORITY=$($hostProcess.PriorityClass)", 'WARNINGS=/W4 /WX', "EXE=$exe", "FIXTURE=$fixtureRoot") |
        Tee-Object -FilePath "$prefix-build.log"

    $build = ('call "{0}" >nul && "{1}" "{2}" /t:Build /p:Configuration=Release /p:Platform=x64 ' +
        '/p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 ' +
        '/p:VcpkgEnabled=false /m:1 /v:minimal') -f $VcVars64, $MSBuild, $project
    & $env:ComSpec /d /c $build 2>&1 | Tee-Object -FilePath "$prefix-build.log" -Append
    $buildExit = $LASTEXITCODE
    "BUILD_EXIT_CODE=$buildExit" | Tee-Object -FilePath "$prefix-build.log" -Append
    if ($buildExit -ne 0) { throw "Native execution validation build failed. $prefix-build.log" }
    if (!(Test-Path -LiteralPath $exe) -or (Get-Item -LiteralPath $exe).Length -eq 0) {
        throw 'Nonzero fixed Release executable is required.'
    }

    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.ArgumentList.Add('--root')
    $start.ArgumentList.Add($fixtureRoot)
    $start.ArgumentList.Add('--exe')
    $start.ArgumentList.Add($exe)
    $start.ArgumentList.Add('--diag-dir')
    $start.ArgumentList.Add($logDir)
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $watchdog = !$process.WaitForExit(240000)
    if ($watchdog) {
        $process.Kill()
        if (!$process.WaitForExit(5000)) { throw 'Exact validation parent did not exit after watchdog.' }
    }
    $output = $stdout.GetAwaiter().GetResult()
    $errors = $stderr.GetAwaiter().GetResult()
    $runExit = $process.ExitCode
    ($output + $errors) | Set-Content -LiteralPath "$prefix-run.log" -Encoding utf8
    Write-Output $output
    Write-Output $errors
} finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        try {
            Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
            $fixtureCleaned = !(Test-Path -LiteralPath $fixtureRoot)
        } catch {
            $fixtureCleaned = $false
        }
    } else {
        $fixtureCleaned = $true
    }
    $leftover = @(Get-Process -Name 'ActionAnalyzeNativeExecutionValidation' -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.Id):$($_.ProcessName)" })
    $passed = $buildExit -eq 0 -and $runExit -eq 0 -and !$watchdog -and
        $output -match '(?m)^RESULT=PASS checks=\d+ failures=0$' -and $leftover.Count -eq 0 -and $fixtureCleaned
    @("INTDIR=$intDir", "OUTDIR=$outDir", "HOSTX64=$tools", "PRIORITY=$($hostProcess.PriorityClass)",
        "BUILD_EXIT_CODE=$buildExit", "RUN_EXIT_CODE=$runExit", "WATCHDOG=$watchdog",
        "EXE_SHA256=$((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash)",
        "LEFTOVER_FIXTURE_PROCESSES=$($leftover -join ',')", "FIXTURE_CLEANED=$fixtureCleaned",
        "RESULT=$(if ($passed) { 'PASS' } else { 'FAIL' })",
        "BUILD_LOG=$prefix-build.log", "RUN_LOG=$prefix-run.log") |
        Tee-Object -FilePath "$prefix-metadata.txt"
    $hostProcess.PriorityClass = $priorPriority
    $hostProcess.Dispose()
}
if (!$passed) { throw "Native execution validation failed; inspect $prefix-run.log" }
"EVIDENCE=$prefix"
