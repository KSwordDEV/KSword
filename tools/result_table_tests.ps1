# 串行编译实际生产结果表组件，所有专属产物写入既有 output/ 目录。
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$resultRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$resultOutput = Join-Path $resultRepository 'output'
if (!(Test-Path -LiteralPath $resultOutput)) { throw 'Existing output directory is required.' }
$resultQt = Join-Path $resultRepository '.deps/Qt/6.9.3/msvc2022_64'
$resultVc = 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207'
$resultSdk = 'C:/Program Files (x86)/Windows Kits/10'
$resultSdkVersion = '10.0.26100.0'
$resultCompiler = Join-Path $resultVc 'bin/Hostx64/x64/cl.exe'
$resultLinker = Join-Path $resultVc 'bin/Hostx64/x64/link.exe'
foreach ($resultRequired in @($resultCompiler, $resultLinker, (Join-Path $resultQt 'lib/Qt6Widgets.lib'))) {
    if (!(Test-Path -LiteralPath $resultRequired)) { throw "Missing HostX64 fixture dependency: $resultRequired" }
}
$resultIncludes = @(('/I' + $resultRepository), ('/external:I' + (Join-Path $resultVc 'include')))
foreach ($resultModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg')) {
    $resultIncludes += '/external:I' + (Join-Path $resultQt ('include/' + $resultModule))
}
foreach ($resultPart in @('ucrt', 'shared', 'um')) {
    $resultIncludes += '/external:I' + (Join-Path $resultSdk ('Include/' + $resultSdkVersion + '/' + $resultPart))
}
$resultApp = 'Ksword5.1/Ksword5.1'
$resultSources = @(
    'tools/result_table_tests.cpp', "$resultApp/UI/UiCommitCoordinator.cpp", "$resultApp/UI/ResultTableHost.cpp",
    "$resultApp/UI/TablePresentation.cpp", "$resultApp/UI/GlobalUiBaseStyle.cpp", "$resultApp/UI/FlatButtonTheme.cpp", "$resultApp/UI/ThemeBinding.cpp", "$resultApp/UI/ThemeControlGlyphs.cpp", "$resultApp/UI/ThemeStatusRole.cpp",
    "$resultApp/UI/TableInteractionSupport.cpp", "$resultApp/UI/TableFreezeSupport.cpp", "$resultApp/UI/TableHeaderSortingSupport.cpp",
    "$resultApp/UI/TableSearchSupport.cpp", "$resultApp/UI/TableSnapshotCompare.cpp", "$resultApp/Internationalization/LanguageManager.cpp"
)
$resultObjects = @()
foreach ($resultSource in $resultSources) {
    $resultObject = Join-Path $resultOutput ('result_table_' + [IO.Path]::GetFileNameWithoutExtension($resultSource) + '.obj')
    Write-Output ('RESULT_TABLE_COMPILE=' + $resultSource)
    # 专属组件和回归按 /W4 /WX；Qt/SDK 头使用 external:W0，保持生产标准库边界。
    & $resultCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /external:W0 /O1 /Gy /bigobj `
        /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE `
        @resultIncludes /c (Join-Path $resultRepository $resultSource) ('/Fo' + $resultObject)
    if ($LASTEXITCODE -ne 0) { throw "Result table production compilation failed: $resultSource" }
    $resultObjects += $resultObject
}
$resultExe = Join-Path $resultOutput 'result_table_tests.exe'
$resultLibs = @(('/LIBPATH:' + (Join-Path $resultVc 'lib/x64')), ('/LIBPATH:' + (Join-Path $resultQt 'lib')))
foreach ($resultPart in @('ucrt', 'um')) {
    $resultLibs += '/LIBPATH:' + (Join-Path $resultSdk ('Lib/' + $resultSdkVersion + '/' + $resultPart + '/x64'))
}
& $resultLinker /nologo /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:REF ('/OUT:' + $resultExe) `
    @resultObjects @resultLibs Qt6Widgets.lib Qt6Gui.lib Qt6Core.lib Qt6Svg.lib user32.lib advapi32.lib
if ($LASTEXITCODE -ne 0) { throw 'Result table production fixture link failed.' }
$resultOldPath = $env:PATH
$resultOldPlatform = $env:QT_QPA_PLATFORM
$resultOldPlugins = $env:QT_PLUGIN_PATH
try {
    $env:PATH = (Join-Path $resultQt 'bin') + ';' + $resultOldPath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $resultQt 'plugins'
    $ErrorActionPreference = 'Continue'
    & $resultExe 2>&1 | Tee-Object -FilePath (Join-Path $resultOutput 'result_table_tests.log')
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { throw 'Result table Qt regression failed.' }
}
finally {
    $env:PATH = $resultOldPath
    $env:QT_QPA_PLATFORM = $resultOldPlatform
    $env:QT_PLUGIN_PATH = $resultOldPlugins
}
