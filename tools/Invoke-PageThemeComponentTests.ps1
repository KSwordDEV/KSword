[CmdletBinding()]
param([switch]$Offscreen)

$ErrorActionPreference = 'Stop'
# 在已有 output 目录编译真实生产视图，独立于主程序构建缓存。
$testRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$testQt = Join-Path $testRoot '.deps/Qt/6.9.3/msvc2022_64'
$testVcRoot = 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207'
$testSdkRoot = 'C:/Program Files (x86)/Windows Kits/10'
$testCompiler = Join-Path $testVcRoot 'bin/Hostx64/x64/cl.exe'
$testIncludeArgs = @('/I' + (Join-Path $testVcRoot 'include'))
foreach ($testModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtOpenGL', 'QtOpenGLWidgets', 'QtSvg')) {
    $testIncludeArgs += '/external:I' + (Join-Path $testQt ('include/' + $testModule))
}
foreach ($testPart in @('ucrt', 'shared', 'um')) {
    $testIncludeArgs += '/external:I' + (Join-Path $testSdkRoot ('Include/10.0.26100.0/' + $testPart))
}
$testLibArgs = @('/LIBPATH:' + (Join-Path $testQt 'lib'))
$testLibArgs += '/LIBPATH:' + (Join-Path $testVcRoot 'lib/x64')
foreach ($testPart in @('ucrt', 'um')) {
    $testLibArgs += '/LIBPATH:' + (Join-Path $testSdkRoot ('Lib/10.0.26100.0/' + $testPart + '/x64'))
}
Push-Location $testRoot
try {
    & $testCompiler /nologo /std:c++17 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /O2 /external:W0 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE /DNOMINMAX @testIncludeArgs tools/page_theme_component_tests.cpp Ksword5.1/Ksword5.1/UI/FlatButtonTheme.cpp Ksword5.1/Ksword5.1/UI/FloatingScrollbars.cpp Ksword5.1/Ksword5.1/UI/ThemeBinding.cpp Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.cpp Ksword5.1/Ksword5.1/UI/ThemeAccentIcon.cpp Ksword5.1/Ksword5.1/UI/SvgThemeIconManager.cpp /Fooutput/ /Feoutput/page_theme_component_tests.exe /link /INCREMENTAL:NO @testLibArgs Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6OpenGL.lib Qt6OpenGLWidgets.lib Qt6Svg.lib
    if ($LASTEXITCODE -ne 0) { throw 'Page theme fixture compilation failed.' }
    # DLL 和平台插件只影响此次测试；所有显示窗口都使用 DontShowOnScreen。
    $testOldPath = $env:PATH
    $testOldPluginPath = $env:QT_PLUGIN_PATH
    $testOldPlatform = $env:QT_QPA_PLATFORM
    $testOldGpu = $env:KSWORD_PROCESS_LIST_GPU
    $testOldProfile = $env:KSWORD_PROCESS_LIST_PROFILE
    try {
        $env:PATH = (Join-Path $testQt 'bin') + ';' + $testOldPath
        $env:QT_PLUGIN_PATH = Join-Path $testQt 'plugins'
        $env:QT_QPA_PLATFORM = if ($Offscreen) { 'offscreen' } else { 'windows' }
        & output/page_theme_component_tests.exe
        if ($LASTEXITCODE -ne 0) { throw 'Page theme component regression failed.' }
    }
    finally {
        $env:PATH = $testOldPath
        $env:QT_PLUGIN_PATH = $testOldPluginPath
        $env:QT_QPA_PLATFORM = $testOldPlatform
        $env:KSWORD_PROCESS_LIST_GPU = $testOldGpu
        $env:KSWORD_PROCESS_LIST_PROFILE = $testOldProfile
    }
}
finally { Pop-Location }
