# 编译实际主题绑定、旧补偿器及两个生产控件；产物只写已有 output，GUI 使用 offscreen。
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$themeRepo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$themeOutput = Join-Path $themeRepo 'output'
if (!(Test-Path -LiteralPath $themeOutput)) { throw 'Existing output directory is required.' }
$themeQt = Join-Path $themeRepo '.deps\Qt\6.9.3\msvc2022_64'
if (!(Test-Path -LiteralPath $themeQt)) { $themeQt = 'D:\Software\Qt\6.9.3\msvc2022_64' }
$themeVc = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$themeSdk = 'C:\Program Files (x86)\Windows Kits\10'
$themeSdkVersion = '10.0.26100.0'
$themeCompiler = Join-Path $themeVc 'bin\Hostx64\x64\cl.exe'
$themeLinker = Join-Path $themeVc 'bin\Hostx64\x64\link.exe'
$themeMoc = Join-Path $themeQt 'bin\moc.exe'
foreach ($themeRequired in @($themeCompiler, $themeLinker, $themeMoc)) {
    if (!(Test-Path -LiteralPath $themeRequired)) { throw "Required tool is unavailable: $themeRequired" }
}

# 所有对象与 moc 使用专属文件名；不复用生产缓存，也不覆盖其他并行夹具产物。
$themeSources = @(
    'tools\theme_binding_tests.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeBinding.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeColorRemap.cpp',
    'Ksword5.1\Ksword5.1\UI\CommandExecutionPopup.cpp',
    'Ksword5.1\Ksword5.1\Framework\CustomTitleBar.cpp',
    'Ksword5.1\Ksword5.1\Internationalization\LanguageManager.cpp',
    'Ksword5.1\Ksword5.1\ksword\log\log.cpp'
)
$themeIncludes = @('/I' + (Join-Path $themeRepo 'Ksword5.1\Ksword5.1'))
$themeIncludes += '/external:I' + (Join-Path $themeVc 'include')
$themeIncludes += '/external:I' + (Join-Path $themeVc 'atlmfc\include')
foreach ($themeModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg', 'QtTest')) {
    $themeIncludes += '/external:I' + (Join-Path $themeQt ('include\' + $themeModule))
}
foreach ($themePart in @('ucrt', 'shared', 'um')) {
    $themeIncludes += '/external:I' + (Join-Path $themeSdk ('Include\' + $themeSdkVersion + '\' + $themePart))
}
foreach ($themeHeader in @('Framework\CustomTitleBar.h', 'UI\CommandExecutionPopup.h')) {
    $themeGenerated = Join-Path $themeOutput ('theme_binding_moc_' + $themeHeader.Replace('\', '_') + '.cpp')
    & $themeMoc (Join-Path $themeRepo ('Ksword5.1\Ksword5.1\' + $themeHeader)) -o $themeGenerated
    if ($LASTEXITCODE -ne 0) { throw "Production moc failed: $themeHeader" }
    $themeSources += $themeGenerated
}
$themeObjects = @()
foreach ($themeRelative in $themeSources) {
    $themeSource = if ([IO.Path]::IsPathRooted($themeRelative)) { $themeRelative } else { Join-Path $themeRepo $themeRelative }
    $themeObject = Join-Path $themeOutput ('theme_binding_' + [IO.Path]::GetFileName($themeSource) + '.obj')
    Write-Output ('THEME_COMPILE=' + [IO.Path]::GetFileName($themeSource))
    & $themeCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W3 /WX /O2 /Gy /bigobj /external:W0 `
        /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /DQT_WIDGETS_LIB /DQT_GUI_LIB /DQT_CORE_LIB @themeIncludes `
        /c $themeSource ('/Fo' + $themeObject)
    if ($LASTEXITCODE -ne 0) { throw "Theme binding source compilation failed: $themeSource" }
    $themeObjects += $themeObject
}

# 链接实际组件需要的 Qt/Windows 库，入口仍仅是私有夹具 QApplication。
$themeLibraries = @('/LIBPATH:' + (Join-Path $themeQt 'lib'))
$themeLibraries += '/LIBPATH:' + (Join-Path $themeVc 'lib\x64')
foreach ($themePart in @('ucrt', 'um')) {
    $themeLibraries += '/LIBPATH:' + (Join-Path $themeSdk ('Lib\' + $themeSdkVersion + '\' + $themePart + '\x64'))
}
$themeExe = Join-Path $themeOutput 'theme_binding_tests.exe'
& $themeLinker /NOLOGO /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:REF ('/OUT:' + $themeExe) @themeObjects @themeLibraries `
    Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Svg.lib Qt6Test.lib user32.lib advapi32.lib ole32.lib shell32.lib gdi32.lib dwmapi.lib
if ($LASTEXITCODE -ne 0) { throw 'Theme binding production fixture link failed.' }

# 环境仅在此脚本进程生效，退出恢复；测试不点击命令执行按钮或读写剪贴板。
$themeOldPath = $env:PATH
$themeOldPlatform = $env:QT_QPA_PLATFORM
$themeOldPlugins = $env:QT_PLUGIN_PATH
try {
    $env:PATH = (Join-Path $themeQt 'bin') + ';' + $themeOldPath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $themeQt 'plugins'
    & $themeExe
    if ($LASTEXITCODE -ne 0) { throw 'Theme binding production regression failed.' }
}
finally {
    $env:PATH = $themeOldPath
    $env:QT_QPA_PLATFORM = $themeOldPlatform
    $env:QT_PLUGIN_PATH = $themeOldPlugins
}
