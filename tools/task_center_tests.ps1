# 编译并运行真实任务核心和两个生产视图；只用合成任务，不访问服务、驱动或剪贴板。
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$taskRepo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$taskOutput = Join-Path $taskRepo 'output'
if (!(Test-Path -LiteralPath $taskOutput)) { throw 'Existing output directory is required.' }
$taskQt = Join-Path $taskRepo '.deps\Qt\6.9.3\msvc2022_64'
if (!(Test-Path -LiteralPath $taskQt)) { $taskQt = 'D:\Software\Qt\6.9.3\msvc2022_64' }
$taskVc = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$taskSdk = 'C:\Program Files (x86)\Windows Kits\10'
$taskSdkVersion = '10.0.26100.0'
$taskCompiler = Join-Path $taskVc 'bin\Hostx64\x64\cl.exe'
$taskLinker = Join-Path $taskVc 'bin\Hostx64\x64\link.exe'
if (!(Test-Path -LiteralPath $taskCompiler)) { throw 'Validated HostX64 compiler is required.' }

# 每个源直接编译为专属对象，不复用主程序的 obj/tlog，避免并行任务改变验收输入。
$taskSources = @(
    'tools\task_center_tests.cpp',
    'Ksword5.1\Ksword5.1\Framework\Progress.cpp',
    'Ksword5.1\Ksword5.1\Framework\ProgressDockWidget.cpp',
    'Ksword5.1\Ksword5.1\Framework\NotificationCardManager.cpp',
    'Ksword5.1\Ksword5.1\Framework\TaskSnapshotFeed.cpp',
    'Ksword5.1\Ksword5.1\Internationalization\LanguageManager.cpp',
    'Ksword5.1\Ksword5.1\ksword\log\log.cpp'
)
$taskIncludes = @('/I' + (Join-Path $taskRepo 'Ksword5.1\Ksword5.1'))
$taskIncludes += '/external:I' + (Join-Path $taskVc 'include')
$taskIncludes += '/external:I' + (Join-Path $taskVc 'atlmfc\include')
foreach ($taskModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg', 'QtTest')) {
    $taskIncludes += '/external:I' + (Join-Path $taskQt ('include\' + $taskModule))
}
foreach ($taskPart in @('ucrt', 'shared', 'um')) {
    $taskIncludes += '/external:I' + (Join-Path $taskSdk ('Include\' + $taskSdkVersion + '\' + $taskPart))
}
$taskObjects = @()
foreach ($taskRelative in $taskSources) {
    $taskSource = Join-Path $taskRepo $taskRelative
    $taskObject = Join-Path $taskOutput ('task_center_' + $taskRelative.Replace('\', '_') + '.obj')
    Write-Output ('TASK_COMPILE=' + [IO.Path]::GetFileName($taskSource))
    & $taskCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W3 /O2 /Gy /bigobj /external:W0 `
        /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /DQT_WIDGETS_LIB /DQT_GUI_LIB /DQT_CORE_LIB @taskIncludes `
        /c $taskSource ('/Fo' + $taskObject)
    if ($LASTEXITCODE -ne 0) { throw "Task center source compilation failed: $taskRelative" }
    $taskObjects += $taskObject
}

# Qt 与 Windows 依赖仅链接实际 UI 组件需要的库，不启动主程序 main 或后台枚举器。
$taskLibraries = @('/LIBPATH:' + (Join-Path $taskQt 'lib'))
$taskLibraries += '/LIBPATH:' + (Join-Path $taskVc 'lib\x64')
foreach ($taskPart in @('ucrt', 'um')) {
    $taskLibraries += '/LIBPATH:' + (Join-Path $taskSdk ('Lib\' + $taskSdkVersion + '\' + $taskPart + '\x64'))
}
$taskExe = Join-Path $taskOutput 'task_center_tests.exe'
& $taskLinker /NOLOGO /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:REF ('/OUT:' + $taskExe) @taskObjects @taskLibraries `
    Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Svg.lib Qt6Test.lib user32.lib advapi32.lib ole32.lib shell32.lib gdi32.lib dwmapi.lib
if ($LASTEXITCODE -ne 0) { throw 'Task center production fixture link failed.' }

# 仅本子进程的 offscreen 环境，不写用户系统配置，测试也不点击通知复制按钮。
$taskOldPath = $env:PATH
$taskOldPlatform = $env:QT_QPA_PLATFORM
$taskOldPlugins = $env:QT_PLUGIN_PATH
try {
    $env:PATH = (Join-Path $taskQt 'bin') + ';' + $taskOldPath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $taskQt 'plugins'
    & $taskExe
    if ($LASTEXITCODE -ne 0) { throw 'Task center production regression failed.' }
}
finally {
    $env:PATH = $taskOldPath
    $env:QT_QPA_PLATFORM = $taskOldPlatform
    $env:QT_PLUGIN_PATH = $taskOldPlugins
}
