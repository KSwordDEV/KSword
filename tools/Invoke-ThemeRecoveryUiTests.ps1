# 在既有构建日志目录执行离屏主题回归，不启动生产程序或访问驱动。
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
$testExe = Join-Path $testOutput 'theme_recovery_ui_tests.exe'

# fixtureSources 是独立测试的完整编译清单；生产新模块仍须同步登记主工程。
$fixtureSources = @(
    'tools\theme_recovery_ui_tests.cpp',
    'tools\theme_recovery_dock_tests.cpp',
    'tools\theme_recovery_chart_tests.cpp',
    'Ksword5.1\Ksword5.1\UI\SvgThemeIconManager.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeControlGlyphs.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeAccentIcon.cpp',
    'Ksword5.1\Ksword5.1\UI\DockThemeIcons.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeColorRemap.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeBinding.cpp',
    'Ksword5.1\Ksword5.1\UI\PerformanceChartTheme.cpp',
    'shared\ui\KsPainterChart.cpp'
) | ForEach-Object { Join-Path $testRepository $_ }
foreach ($testRequired in @($testCompiler, (Join-Path $testQt 'bin\rcc.exe')) + $fixtureSources) {
    if (!(Test-Path -LiteralPath $testRequired)) { throw "Required fixture input is missing: $testRequired" }
}

# 仅打包控件测试资源；不修改当前包含并行工作台改动的生产 qrc。
$testResourceRoot = Join-Path $testRepository 'Ksword5.1\Ksword5.1\Resource\Icon\system'
$testQrc = Join-Path $testOutput 'theme-recovery-fixture.qrc'
$testBundle = Join-Path $testOutput 'theme-recovery-fixture.rcc'
$testResourceXml = '<RCC><qresource prefix="/Icon">'
foreach ($testName in @('ks_control_check_white.svg', 'ks_control_down_white.svg', 'ks_control_up_white.svg')) {
    $testResourceFile = [Security.SecurityElement]::Escape((Join-Path $testResourceRoot $testName))
    $testResourceXml += '<file alias="' + $testName + '">' + $testResourceFile + '</file>'
}
$testResourceXml += '</qresource></RCC>'
[IO.File]::WriteAllText($testQrc, $testResourceXml, [Text.UTF8Encoding]::new($false))
& (Join-Path $testQt 'bin\rcc.exe') -binary $testQrc -o $testBundle
if ($LASTEXITCODE -ne 0) { throw 'Fixture resource compilation failed.' }

# includeArgs/libArgs 使用 HostX64 标准 MSVC 与仓库 Qt，不复制或替换生产二进制。
$includeArgs = @('/I' + (Join-Path $testVcRoot 'include'))
foreach ($testModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg')) {
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
& $testCompiler /nologo /std:c++17 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /O2 /external:W0 `
    /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE @includeArgs @fixtureSources `
    ('/Fo' + $testOutput + '\') ('/Fe' + $testExe) `
    /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO @libArgs Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Svg.lib qtadvanceddocking.lib user32.lib
if ($LASTEXITCODE -ne 0) { throw 'Theme recovery fixture compilation or link failed.' }

# 只运行 offscreen fixture；缓存测试仅写显式指定的仓库构建日志目录。
$oldFixturePath = $env:PATH
$oldFixturePlatform = $env:QT_QPA_PLATFORM
$oldFixturePluginPath = $env:QT_PLUGIN_PATH
try {
    $env:PATH = (Join-Path $testQt 'bin') + ';' + (Join-Path $testRepository 'Ksword5.1\Ksword5.1\lib') + ';' + $oldFixturePath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $testQt 'plugins'
    & $testExe $testRepository $testBundle
    if ($LASTEXITCODE -ne 0) { throw 'Theme recovery behavioral regression failed.' }
}
finally {
    $env:PATH = $oldFixturePath
    $env:QT_QPA_PLATFORM = $oldFixturePlatform
    $env:QT_PLUGIN_PATH = $oldFixturePluginPath
}
