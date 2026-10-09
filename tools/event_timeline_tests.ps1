# 编译并运行真实时间轴模型和两个生产轨道配置；只用合成任务，不访问服务、驱动或剪贴板。
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$SkipRuntime,
    [switch]$SkipConsumerCompile,
    [string]$RuntimeProbe = ''
)
$ErrorActionPreference = 'Stop'
$timelineRepo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$timelineOutput = Join-Path $timelineRepo 'output'
if (!(Test-Path -LiteralPath $timelineOutput)) { throw 'Existing output directory is required.' }
$timelineQt = Join-Path $timelineRepo '.deps\Qt\6.9.3\msvc2022_64'
if (!(Test-Path -LiteralPath $timelineQt)) { $timelineQt = 'D:\Software\Qt\6.9.3\msvc2022_64' }
$timelineVc = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$timelineSdk = 'C:\Program Files (x86)\Windows Kits\10'
$timelineSdkVersion = '10.0.26100.0'
$timelineCompiler = Join-Path $timelineVc 'bin\Hostx64\x64\cl.exe'
$timelineLinker = Join-Path $timelineVc 'bin\Hostx64\x64\link.exe'
if (!(Test-Path -LiteralPath $timelineCompiler)) { throw 'Validated HostX64 compiler is required.' }

# 每个源直接编译为专属对象，不复用主程序的 obj/tlog，避免并行任务改变验收输入。
$timelineSources = @(
    'tools\event_timeline_tests.cpp',
    'Ksword5.1\Ksword5.1\MonitorDock\EventTimelineModel.cpp',
    'Ksword5.1\Ksword5.1\MonitorDock\ProcessTraceTimelineWidget.cpp',
    'Ksword5.1\Ksword5.1\MonitorDock\ProcessTraceTimelineWidget.Render.cpp',
    'Ksword5.1\Ksword5.1\Internationalization\LanguageManager.cpp'
)
$timelineIncludes = @('/I' + (Join-Path $timelineRepo 'Ksword5.1\Ksword5.1'))
$timelineIncludes += '/external:I' + (Join-Path $timelineVc 'include')
$timelineIncludes += '/external:I' + (Join-Path $timelineVc 'atlmfc\include')
foreach ($timelineModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg', 'QtNetwork', 'QtTest')) {
    $timelineIncludes += '/external:I' + (Join-Path $timelineQt ('include\' + $timelineModule))
}
foreach ($timelinePart in @('ucrt', 'shared', 'um')) {
    $timelineIncludes += '/external:I' + (Join-Path $timelineSdk ('Include\' + $timelineSdkVersion + '\' + $timelinePart))
}
$timelineObjects = @()
foreach ($timelineRelative in $timelineSources) {
    $timelineSource = Join-Path $timelineRepo $timelineRelative
    $timelineObject = Join-Path $timelineOutput ('event_timeline_' + $timelineRelative.Replace('\', '_') + '.obj')
    Write-Output ('TIMELINE_COMPILE=' + [IO.Path]::GetFileName($timelineSource))
    & $timelineCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W3 /O2 /Gy /bigobj /external:W0 `
        /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /DQT_WIDGETS_LIB /DQT_GUI_LIB /DQT_CORE_LIB @timelineIncludes `
        /c $timelineSource ('/Fo' + $timelineObject)
    if ($LASTEXITCODE -ne 0) { throw "Event timeline source compilation failed: $timelineRelative" }
    $timelineObjects += $timelineObject
}

# Qt 与 Windows 依赖仅链接实际 UI 组件需要的库，不启动主程序 main 或后台枚举器。
$timelineLibraries = @('/LIBPATH:' + (Join-Path $timelineQt 'lib'))
$timelineLibraries += '/LIBPATH:' + (Join-Path $timelineVc 'lib\x64')
foreach ($timelinePart in @('ucrt', 'um')) {
    $timelineLibraries += '/LIBPATH:' + (Join-Path $timelineSdk ('Lib\' + $timelineSdkVersion + '\' + $timelinePart + '\x64'))
}
$timelineExe = Join-Path $timelineOutput 'event_timeline_tests.exe'
& $timelineLinker /NOLOGO /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:REF ('/OUT:' + $timelineExe) @timelineObjects @timelineLibraries `
    Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Svg.lib Qt6Test.lib user32.lib advapi32.lib ole32.lib shell32.lib gdi32.lib dwmapi.lib
if ($LASTEXITCODE -ne 0) { throw 'Event timeline production fixture link failed.' }

# 另外直接编译定向/全局ETW与网络的真实接入源；不启动其业务构造器。
$timelineIncludes += '/external:I' + (Join-Path $timelineRepo 'third_party\zydis')
$timelineIncludes += '/external:I' + (Join-Path $timelineRepo 'third_party\zstd')
$timelineConsumers = @(
    'MonitorDock\ProcessTraceMonitorWidget.Ui.cpp',
    'MonitorDock\ProcessTraceMonitorWidget.Actions.cpp',
    'MonitorDock\MonitorDock.cpp',
    'NetworkDock\NetworkDock.UiBuild.cpp',
    'NetworkDock\NetworkDock.MonitorPipeline.cpp'
)
foreach ($timelineRelative in $(if ($SkipConsumerCompile) { @() } else { $timelineConsumers })) {
    $timelineSource = Join-Path $timelineRepo ('Ksword5.1\Ksword5.1\' + $timelineRelative)
    $timelineObject = Join-Path $timelineOutput ('event_timeline_consumer_' + $timelineRelative.Replace('\', '_') + '.obj')
    Write-Output ('TIMELINE_CONSUMER_COMPILE=' + [IO.Path]::GetFileName($timelineSource))
    & $timelineCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W3 /O2 /Gy /bigobj /external:W0 `
        /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /DQT_WIDGETS_LIB /DQT_GUI_LIB /DQT_CORE_LIB /DQT_NETWORK_LIB @timelineIncludes `
        /c $timelineSource ('/Fo' + $timelineObject)
    if ($LASTEXITCODE -ne 0) { throw "Event timeline consumer compilation failed: $timelineRelative" }
}
if ($SkipRuntime) {
    Write-Output 'TIMELINE_RUNTIME_SKIPPED=EXPLICIT'
    return
}

# 仅本子进程的 offscreen 环境，不写用户系统配置，测试也不点击通知复制按钮。
$timelineOldPath = $env:PATH
$timelineOldPlatform = $env:QT_QPA_PLATFORM
$timelineOldPlugins = $env:QT_PLUGIN_PATH
try {
    $env:PATH = (Join-Path $timelineQt 'bin') + ';' + $timelineOldPath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $timelineQt 'plugins'
    if ($RuntimeProbe) { & $timelineExe $RuntimeProbe } else { & $timelineExe }
    if ($LASTEXITCODE -ne 0) { throw 'Event timeline production regression failed.' }
}
finally {
    $env:PATH = $timelineOldPath
    $env:QT_QPA_PLATFORM = $timelineOldPlatform
    $env:QT_PLUGIN_PATH = $timelineOldPlugins
}
