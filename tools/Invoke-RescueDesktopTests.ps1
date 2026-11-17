[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),
    [switch]$SkipTaskbarProbe,
    [switch]$NativeOnly
)

# 使用已有 Taskbar Release 中间目录；测试仅创建隐藏桌面，不切换用户输入桌面。
$ErrorActionPreference = 'Stop'
$taskRepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$taskOutputDirectory = Join-Path $taskRepositoryRoot 'Taskbar\x64\Release'
$taskVcVars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (!(Test-Path -LiteralPath $taskVcVars)) {
    $taskVcVars = 'D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat'
}
if (!(Test-Path -LiteralPath $taskVcVars)) {
    throw 'Existing Taskbar Release directory and HostX64 toolchain are required.'
}
New-Item -ItemType Directory -Path $taskOutputDirectory -Force | Out-Null
Write-Output "RESCUE_TEST_OUTPUT=$taskOutputDirectory"
$taskPreviousTemp=$env:TEMP
$taskPreviousTmp=$env:TMP

# 独立命名测试对象，不能覆盖 Taskbar 正式对象或更换主程序链接器。
$taskCompile = 'call "' + $taskVcVars + '"'
$taskCompile += ' && cl /nologo /EHsc /W4 /std:c++17 /utf-8 /D_WIN32_WINNT=0x0A00 /c tools\rescue_desktop_tests.cpp /FoTaskbar\x64\Release\RescueDesktopTests.obj'
$taskCompile += ' && cl /nologo /EHsc /W4 /std:c++17 /utf-8 /D_WIN32_WINNT=0x0A00 /c shared\rescue\RescueDesktopWin32.cpp /FoTaskbar\x64\Release\RescueDesktopTestBackend.obj'
$taskCompile += ' && link /nologo /SUBSYSTEM:CONSOLE Taskbar\x64\Release\RescueDesktopTests.obj Taskbar\x64\Release\RescueDesktopTestBackend.obj /OUT:Taskbar\x64\Release\RescueDesktopTests.exe Advapi32.lib User32.lib'
Push-Location -LiteralPath $taskRepositoryRoot
try {
    $env:TEMP=$taskOutputDirectory
    $env:TMP=$taskOutputDirectory
    & $env:ComSpec /d /s /c $taskCompile
    if ($LASTEXITCODE -ne 0) {
        throw "Rescue desktop test compilation failed: $LASTEXITCODE"
    }
    & (Join-Path $taskOutputDirectory 'RescueDesktopTests.exe')
    if ($LASTEXITCODE -ne 0) {
        throw "Rescue desktop tests failed: $LASTEXITCODE"
    }
    if ($NativeOnly) {
        return
    }
    # 实际 KSword 监护入口在 Qt 前处理门闩和令牌；此探测只走提前返回分支。
    $taskActualHost = Join-Path $taskRepositoryRoot 'Ksword5.1\x64\Release\Ksword5.1.exe'
    $taskTaskbar = Join-Path $taskRepositoryRoot 'Ksword5.1\x64\Release\Taskbar.exe'
    $taskProbePaths = @($taskActualHost)
    if (!$SkipTaskbarProbe) {
        $taskProbePaths += $taskTaskbar
    }
    foreach ($taskProbePath in $taskProbePaths) {
        if (!(Test-Path -LiteralPath $taskProbePath)) {
            throw "Elevation gate probe artifact is missing: $taskProbePath"
        }
    }
    & (Join-Path $taskOutputDirectory 'RescueDesktopTests.exe') --session-guard-probe $taskActualHost
    if ($LASTEXITCODE -ne 0) {
        throw "Rescue session guard probe failed: $LASTEXITCODE"
    }
    & (Join-Path $taskOutputDirectory 'RescueDesktopTests.exe') --client-path-rejection-probe $taskActualHost
    if ($LASTEXITCODE -ne 0) {
        throw "Rescue client path rejection probe failed: $LASTEXITCODE"
    }
    & (Join-Path $taskOutputDirectory 'RescueDesktopTests.exe') --client-init-rejection-probe $taskActualHost
    if ($LASTEXITCODE -ne 0) {
        throw "Rescue client initialization rejection probe failed: $LASTEXITCODE"
    }
    if (!$SkipTaskbarProbe) {
        & (Join-Path $taskOutputDirectory 'RescueDesktopTests.exe') --taskbar-single-instance-probe $taskTaskbar
        if ($LASTEXITCODE -ne 0) {
            throw "Taskbar single-instance probe failed: $LASTEXITCODE"
        }
    }
    & (Join-Path $taskOutputDirectory 'RescueDesktopTests.exe') --elevation-gate-probe $taskActualHost
    if ($LASTEXITCODE -ne 0) {
        throw "Rescue elevation gate probe failed: $LASTEXITCODE"
    }
}
finally {
    $env:TEMP=$taskPreviousTemp
    $env:TMP=$taskPreviousTmp
    Pop-Location
}
