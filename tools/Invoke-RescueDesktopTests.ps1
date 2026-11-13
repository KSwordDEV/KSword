[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

# 使用已有 Taskbar Release 中间目录；测试仅创建隐藏桌面，不切换用户输入桌面。
$ErrorActionPreference = 'Stop'
$taskRepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$taskOutputDirectory = Join-Path $taskRepositoryRoot 'Taskbar\x64\Release'
$taskVcVars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (!(Test-Path -LiteralPath $taskVcVars)) {
    $taskVcVars = 'D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat'
}
if (!(Test-Path -LiteralPath $taskOutputDirectory) -or !(Test-Path -LiteralPath $taskVcVars)) {
    throw 'Existing Taskbar Release directory and HostX64 toolchain are required.'
}

# 独立命名测试对象，不能覆盖 Taskbar 正式对象或更换主程序链接器。
$taskCompile = 'call "' + $taskVcVars + '"'
$taskCompile += ' && cl /nologo /EHsc /W4 /std:c++17 /utf-8 /D_WIN32_WINNT=0x0A00 /c tools\rescue_desktop_tests.cpp /FoTaskbar\x64\Release\RescueDesktopTests.obj'
$taskCompile += ' && cl /nologo /EHsc /W4 /std:c++17 /utf-8 /D_WIN32_WINNT=0x0A00 /c shared\rescue\RescueDesktopWin32.cpp /FoTaskbar\x64\Release\RescueDesktopTestBackend.obj'
$taskCompile += ' && link /nologo /SUBSYSTEM:CONSOLE Taskbar\x64\Release\RescueDesktopTests.obj Taskbar\x64\Release\RescueDesktopTestBackend.obj /OUT:Taskbar\x64\Release\RescueDesktopTests.exe Advapi32.lib User32.lib'
Push-Location -LiteralPath $taskRepositoryRoot
try {
    & $env:ComSpec /d /s /c $taskCompile
    if ($LASTEXITCODE -ne 0) {
        throw "Rescue desktop test compilation failed: $LASTEXITCODE"
    }
    & (Join-Path $taskOutputDirectory 'RescueDesktopTests.exe')
    if ($LASTEXITCODE -ne 0) {
        throw "Rescue desktop tests failed: $LASTEXITCODE"
    }
    # 用实际 Taskbar 检查未提升的内部入口；已经提升的测试宿主跳过，不自动显示 UAC。
    $taskActualHost = Join-Path $taskRepositoryRoot 'Ksword5.1\x64\Release\Taskbar.exe'
    $taskActualClient = Join-Path $taskRepositoryRoot 'Ksword5.1\x64\Release\Ksword5.1.exe'
    foreach ($taskProbePath in @($taskActualHost, $taskActualClient)) {
        if (!(Test-Path -LiteralPath $taskProbePath)) {
            throw "Elevation gate probe artifact is missing: $taskProbePath"
        }
    }
    & (Join-Path $taskOutputDirectory 'RescueDesktopTests.exe') --session-guard-probe $taskActualHost $taskActualClient
    if ($LASTEXITCODE -ne 0) {
        throw "Rescue session guard probe failed: $LASTEXITCODE"
    }
    & (Join-Path $taskOutputDirectory 'RescueDesktopTests.exe') --elevation-gate-probe $taskActualHost $taskActualClient
    if ($LASTEXITCODE -ne 0) {
        throw "Rescue elevation gate probe failed: $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
