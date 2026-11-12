# 编译真实详情投影、字段源与共享分栏；输入仓库/Qt/编译器路径，失败以非零退出码报告。
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$QtRoot = $env:KSWORD_QT_DIR,
    [string]$VcRoot = 'D:/Software/VS/VC/Tools/MSVC/14.44.35207',
    [switch]$BuildOnly
)
$ErrorActionPreference = 'Stop'
$cardRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path # 所有生产文件的仓库根。
$cardOutput = Join-Path $cardRoot '.codex-build-logs/detail-card-resize' # 夹具自己的对象与证据不进入源码差异。
if (!$QtRoot) {
    $QtRoot = Join-Path $cardRoot '.deps/Qt/6.9.3/msvc2022_64'
    if (!(Test-Path -LiteralPath $QtRoot)) { $QtRoot = 'D:/Software/Qt/6.9.3/msvc2022_64' }
}
$cardApp = Join-Path $cardRoot 'Ksword5.1/Ksword5.1' # 主程序头文件与源码根。
$cardCompiler = Join-Path $VcRoot 'bin/Hostx64/x64/cl.exe' # 只使用64位宿主编译器。
$cardLinker = Join-Path $VcRoot 'bin/Hostx64/x64/link.exe' # 与编译器配套的64位链接器。
$cardSdk = 'C:/Program Files (x86)/Windows Kits/10' # Windows SDK 根目录。
$cardSdkVersion = '10.0.26100.0' # 与现有构建环境一致的SDK版本。
New-Item -ItemType Directory -Path $cardOutput -Force | Out-Null

# 所有被测布局直接编译生产文件；不复制或模拟投影与分栏的几何算法。
$cardSources = @(
    'tools/detail_card_resize_tests.cpp',
    'tools/detail_card_resize_adapters.cpp',
    'UI/DetailFieldProjection.cpp', 'UI/DetailPresentation.cpp', 'UI/ParameterWorkspace.cpp',
    'UI/StructuredFieldView.cpp', 'UI/FieldDocument.cpp', 'UI/FieldTreeModel.cpp',
    'UI/ThemeBinding.cpp', 'UI/PrimaryPageStyle.cpp', 'UI/MainSurfaceStyle.cpp',
    'UI/FlatButtonTheme.cpp', 'UI/ThemeControlGlyphs.cpp', 'UI/ThemeStatusRole.cpp',
    'UI/ThemeAccentIcon.cpp',
    'UI/PageControlStyle.cpp', 'UI/PageTabFocusStyle.cpp', 'UI/PageTabMotion.cpp',
    'UI/TabHierarchyTransition.cpp', 'UI/SmoothScrollSupport.cpp',
    'UI/FlowLayout.cpp', 'Internationalization/LanguageManager.cpp'
)
$cardIncludes = @(('/I' + $cardRoot), ('/I' + $cardApp), ('/external:I' + (Join-Path $VcRoot 'include'))) # 编译器与项目头搜索路径。
foreach ($cardModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg', 'QtConcurrent', 'QtOpenGLWidgets', 'QtOpenGL')) {
    $cardIncludes += '/external:I' + (Join-Path $QtRoot ('include/' + $cardModule))
}
foreach ($cardPart in @('ucrt', 'shared', 'um')) {
    $cardIncludes += '/external:I' + (Join-Path $cardSdk ('Include/' + $cardSdkVersion + '/' + $cardPart))
}

# Q_OBJECT元信息也从真实头文件生成，确保搜索信号与异步文档通知保持原行为。
foreach ($cardHeader in @('StructuredFieldView')) {
    $cardMoc = Join-Path $cardOutput ('moc_' + $cardHeader + '.cpp') # 当前头文件的元对象翻译单元。
    & (Join-Path $QtRoot 'bin/moc.exe') (Join-Path $cardApp ('UI/' + $cardHeader + '.h')) -o $cardMoc
    if ($LASTEXITCODE -ne 0) { throw "moc failed: $cardHeader" }
    $cardSources += $cardMoc
}
$cardObjects = @() # 本次链接使用的独立对象，不借用主程序增量缓存。
foreach ($cardSource in $cardSources) {
    $cardSourcePath = $cardSource # 规范化后的输入源码绝对路径。
    if (![IO.Path]::IsPathRooted($cardSourcePath)) {
        if ($cardSourcePath.StartsWith('tools/')) { $cardSourcePath = Join-Path $cardRoot $cardSourcePath }
        else { $cardSourcePath = Join-Path $cardApp $cardSourcePath }
    }
    $cardObject = Join-Path $cardOutput ([IO.Path]::GetFileNameWithoutExtension($cardSourcePath) + '.obj') # 每个源码独占对象。
    & $cardCompiler /nologo /std:c++20 /Zc:__cplusplus /Zc:inline /permissive- /utf-8 /EHsc /MD /W3 /external:W0 /O1 /Gy /Gw /bigobj `
        /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE `
        @cardIncludes /c $cardSourcePath ('/Fo' + $cardObject)
    if ($LASTEXITCODE -ne 0) { throw "Production compilation failed: $cardSource" }
    $cardObjects += $cardObject
}

# 只链接普通用户态Qt组件；夹具不加载驱动、不枚举进程，也不写系统剪贴板。
$cardExe = Join-Path $cardOutput 'detail_card_resize_tests.exe' # 生成的可运行回归程序。
$cardLibs = @(('/LIBPATH:' + (Join-Path $VcRoot 'lib/x64')), ('/LIBPATH:' + (Join-Path $QtRoot 'lib'))) # 编译器与Qt导入库。
foreach ($cardPart in @('ucrt', 'um')) {
    $cardLibs += '/LIBPATH:' + (Join-Path $cardSdk ('Lib/' + $cardSdkVersion + '/' + $cardPart + '/x64'))
}
& $cardLinker /nologo /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:REF ('/OUT:' + $cardExe) `
    @cardObjects @cardLibs Qt6Widgets.lib Qt6Gui.lib Qt6Core.lib Qt6Svg.lib Qt6Concurrent.lib Qt6OpenGLWidgets.lib Qt6OpenGL.lib user32.lib advapi32.lib dwmapi.lib
if ($LASTEXITCODE -ne 0) { throw 'Detail card regression link failed.' }
if ($BuildOnly) { exit 0 }
$cardOldPath = $env:PATH # 执行结束恢复调用者的运行库搜索路径。
$cardOldPlatform = $env:QT_QPA_PLATFORM # 执行结束恢复原窗口平台选择。
$cardOldPlugins = $env:QT_PLUGIN_PATH # 执行结束恢复原Qt插件路径。
try {
    $env:PATH = (Join-Path $QtRoot 'bin') + ';' + $cardOldPath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $QtRoot 'plugins'
    & $cardExe $cardOutput 2>&1 | Tee-Object -FilePath (Join-Path $cardOutput 'resize.log')
    if ($LASTEXITCODE -ne 0) { throw 'Detail card resize regression failed.' }
}
finally {
    $env:PATH = $cardOldPath
    $env:QT_QPA_PLATFORM = $cardOldPlatform
    $env:QT_PLUGIN_PATH = $cardOldPlugins
}
