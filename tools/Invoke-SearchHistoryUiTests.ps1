# 在既有构建日志目录验证真实搜索/CMD UI，不启动生产程序或执行命令。
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$testRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$testOutput = Join-Path $testRepository '.codex-build-logs'
if (!(Test-Path -LiteralPath $testOutput)) { throw 'The existing build log directory is required.' }
$testQt = Join-Path $testRepository '.deps\Qt\6.9.3\msvc2022_64'
if (!(Test-Path -LiteralPath $testQt)) { $testQt = 'D:\Software\Qt\6.9.3\msvc2022_64' }
$testVcRoot = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$testSdkRoot = 'C:\Program Files (x86)\Windows Kits\10'
$testSdkVersion = '10.0.26100.0'
$testCompiler = Join-Path $testVcRoot 'bin\Hostx64\x64\cl.exe'
$testExe = Join-Path $testOutput 'history_search_ui_tests.exe'

# fixtureSources 直接编译当前生产实现；不把这些独立测试登记为主程序源文件。
$fixtureSources = @(
    'tools\history_search_ui_tests.cpp',
    'Ksword5.1\Ksword5.1\Framework\CustomTitleBar.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeBinding.cpp',
    'Ksword5.1\Ksword5.1\UI\GlobalUiSearch.cpp',
    'Ksword5.1\Ksword5.1\UI\TableSearchSupport.cpp',
    'Ksword5.1\Ksword5.1\UI\CommandExecutionPopup.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeControlGlyphs.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeItemForeground.cpp',
    'Ksword5.1\Ksword5.1\Internationalization\LanguageManager.cpp'
) | ForEach-Object { Join-Path $testRepository $_ }
$fixtureHeaders = @(
    'Ksword5.1\Ksword5.1\Framework\CustomTitleBar.h',
    'Ksword5.1\Ksword5.1\UI\GlobalUiSearch.h',
    'Ksword5.1\Ksword5.1\UI\CommandExecutionPopup.h'
) | ForEach-Object { Join-Path $testRepository $_ }
foreach ($testRequired in @($testCompiler, (Join-Path $testQt 'bin\moc.exe')) + $fixtureSources + $fixtureHeaders) {
    if (!(Test-Path -LiteralPath $testRequired)) { throw "Missing fixture input: $testRequired" }
}

# moc 只写现有日志目录；与生产工程生成的 moc/object 隔离，避免覆盖增量产物。
foreach ($fixtureHeader in $fixtureHeaders) {
    $fixtureStem = [IO.Path]::GetFileNameWithoutExtension($fixtureHeader)
    $fixtureMoc = Join-Path $testOutput ('history_moc_' + $fixtureStem + '.cpp')
    & (Join-Path $testQt 'bin\moc.exe') $fixtureHeader -o $fixtureMoc
    if ($LASTEXITCODE -ne 0) { throw "Fixture moc failed: $fixtureStem" }
    $fixtureSources += $fixtureMoc
}

# 所有 include/lib 使用标准 HostX64 工具链和仓库 Qt；中文源码保留 UTF-8。
$includeArgs = @('/I' + (Join-Path $testVcRoot 'include'))
foreach ($testModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg', 'QtNetwork')) {
    $includeArgs += '/external:I' + (Join-Path $testQt ('include\' + $testModule))
}
foreach ($testPart in @('ucrt', 'shared', 'um')) {
    $includeArgs += '/external:I' + (Join-Path $testSdkRoot ('Include\' + $testSdkVersion + '\' + $testPart))
}
$libArgs = @('/LIBPATH:' + (Join-Path $testQt 'lib'))
$libArgs += '/LIBPATH:' + (Join-Path $testVcRoot 'lib\x64')
$libArgs += '/LIBPATH:' + (Join-Path $testRepository 'Ksword5.1\Ksword5.1\lib')
foreach ($testPart in @('ucrt', 'um')) {
    $libArgs += '/LIBPATH:' + (Join-Path $testSdkRoot ('Lib\' + $testSdkVersion + '\' + $testPart + '\x64'))
}
# 标题栏既有 C4702 只在夹具忽略；各 object 使用独立前缀，避免与其它离屏回归同名源冲突。
$fixtureObjects = @()
foreach ($fixtureSource in $fixtureSources) {
    $fixtureObject = Join-Path $testOutput ('search-history-' + [IO.Path]::GetFileNameWithoutExtension($fixtureSource) + '.obj')
    & $testCompiler /nologo /c /std:c++latest /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /wd4702 /O2 /external:W0 `
        /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE @includeArgs $fixtureSource ('/Fo' + $fixtureObject)
    if ($LASTEXITCODE -ne 0) { throw "Search fixture compilation failed: $fixtureSource" }
    $fixtureObjects += $fixtureObject
}
& $testCompiler /nologo @fixtureObjects ('/Fe' + $testExe) `
    /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO @libArgs Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Svg.lib `
    qtadvanceddocking.lib user32.lib advapi32.lib
if ($LASTEXITCODE -ne 0) { throw 'Search history fixture compilation or link failed.' }

# fixture 没有生产资源包，glyph 不生成真实用户缓存；执行请求只接入测试记录槽。
$oldFixturePath = $env:PATH
$oldFixturePlatform = $env:QT_QPA_PLATFORM
$oldFixturePluginPath = $env:QT_PLUGIN_PATH
try {
    $env:PATH = (Join-Path $testQt 'bin') + ';' + (Join-Path $testRepository 'Ksword5.1\Ksword5.1\lib') + ';' + $oldFixturePath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $testQt 'plugins'
    & $testExe
    if ($LASTEXITCODE -ne 0) { throw 'Search history behavioral regression failed.' }
}
finally {
    $env:PATH = $oldFixturePath
    $env:QT_QPA_PLATFORM = $oldFixturePlatform
    $env:QT_PLUGIN_PATH = $oldFixturePluginPath
}
