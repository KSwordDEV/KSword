[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'), [switch]$CheckUiCompilation)
$ErrorActionPreference = 'Stop'
$taskRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$taskQt = Join-Path $taskRoot '.deps\Qt\6.9.3\msvc2022_64'
$taskVcVars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (!(Test-Path -LiteralPath $taskVcVars)) { $taskVcVars = 'D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat' }
if (!(Test-Path -LiteralPath $taskVcVars) -or !(Test-Path -LiteralPath $taskQt)) { throw 'HostX64 MSVC and repository Qt are required.' }
$taskOutput = Join-Path $taskRoot 'Taskbar\x64\Release'
New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
Write-Output "RUNTIME_CONTROL_OUTPUT=$taskOutput"
$taskPreviousTemp=$env:TEMP
$taskPreviousTmp=$env:TMP
$taskCompile = 'call "' + $taskVcVars + '" && cl /nologo /EHsc /std:c++17 /Zc:__cplusplus /permissive- /utf-8 /MD /W4 /I"' + $taskQt + '\include" /I"' + $taskQt + '\include\QtCore" /I"' + $taskQt + '\include\QtGui"'
$taskCompilerPrefix = $taskCompile
$taskCompile += ' /I"' + $taskQt + '\include\QtWidgets" tools\runtime_controls_tests.cpp Ksword5.1\Ksword5.1\Framework\BackgroundTaskRegistry.cpp Ksword5.1\Ksword5.1\UI\ShortcutRegistry.cpp Ksword5.1\Ksword5.1\UI\MemoryWorkbench\WorkbenchActions.cpp Taskbar\SosHotkeyLauncher.cpp'
$taskCompile += ' /Fo"' + $taskOutput.Replace('\', '/') + '/" /Fe"' + $taskOutput + '\runtime_controls_tests.exe" /link /LIBPATH:"' + $taskQt + '\lib" Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib User32.lib'
Push-Location -LiteralPath $taskRoot
try {
    $env:TEMP=$taskOutput
    $env:TMP=$taskOutput
    & $env:ComSpec /d /s /c $taskCompile
    if ($LASTEXITCODE -ne 0) { throw "Runtime control compilation failed: $LASTEXITCODE" }
    $taskOldPath = $env:PATH
    try {
        $env:PATH = (Join-Path $taskQt 'bin') + ';' + $taskOldPath
        & (Join-Path $taskOutput 'runtime_controls_tests.exe')
        if ($LASTEXITCODE -ne 0) { throw "Runtime control tests failed: $LASTEXITCODE" }
    } finally { $env:PATH = $taskOldPath }
    if ($CheckUiCompilation) {
        $taskUiCompile = $taskCompilerPrefix + ' /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DZYDIS_STATIC_BUILD /I"' + $taskRoot + '\Ksword5.1\Ksword5.1" /I"' + $taskRoot + '\third_party\zydis" /I"' + $taskRoot + '\third_party\zstd" /I"' + $taskQt + '\include\QtWidgets" /I"' + $taskQt + '\include\QtNetwork" /I"' + $taskQt + '\include\QtSvg" /c Ksword5.1\Ksword5.1\UI\BackgroundTaskPage.cpp Ksword5.1\Ksword5.1\UI\ShortcutManagerDialog.cpp /Fo"' + $taskOutput.Replace('\', '/') + '/"'
        & $env:ComSpec /d /s /c $taskUiCompile
        if ($LASTEXITCODE -ne 0) { throw "Runtime control UI source compilation failed: $LASTEXITCODE" }
        Write-Output 'RUNTIME_CONTROL_UI_SOURCES=COMPILED'
    }
} finally {
    $env:TEMP=$taskPreviousTemp
    $env:TMP=$taskPreviousTmp
    Pop-Location
}
