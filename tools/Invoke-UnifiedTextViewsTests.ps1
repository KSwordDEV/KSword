# Compile actual Qt presentation components with HostX64 MSVC. Outputs use the
# established build log directory. No native clipboard writes or target I/O.
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$textRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$textOutput = Join-Path $textRepository '.codex-build-logs'
if (!(Test-Path -LiteralPath $textOutput)) { throw 'The established .codex-build-logs directory is required.' }
$textQt = Join-Path $textRepository '.deps/Qt/6.9.3/msvc2022_64'
$textVcBase = 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC'
$textVcRoot = Join-Path $textVcBase '14.44.35207'
if (!(Test-Path -LiteralPath $textVcRoot)) {
    $textVcCandidate = Get-ChildItem -LiteralPath $textVcBase -Directory | Sort-Object Name -Descending | Select-Object -First 1
    if (!$textVcCandidate) { throw 'HostX64 MSVC is required.' }
    $textVcRoot = $textVcCandidate.FullName
}
$textSdk = 'C:/Program Files (x86)/Windows Kits/10'
$textSdkVersion = '10.0.26100.0'
$textCompiler = Join-Path $textVcRoot 'bin/Hostx64/x64/cl.exe'
$textLinker = Join-Path $textVcRoot 'bin/Hostx64/x64/link.exe'
foreach ($textRequired in @($textCompiler, $textLinker, (Join-Path $textQt 'lib/Qt6Widgets.lib'))) {
    if (!(Test-Path -LiteralPath $textRequired)) { throw "Required tool or Qt library is missing: $textRequired" }
}
$textIncludes = @(('/I' + $textRepository), ('/external:I' + (Join-Path $textVcRoot 'include')))
foreach ($textModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg', 'QtTest')) {
    $textIncludes += '/external:I' + (Join-Path $textQt ('include/' + $textModule))
}
foreach ($textSdkPart in @('ucrt', 'shared', 'um')) {
    $textIncludes += '/external:I' + (Join-Path $textSdk ('Include/' + $textSdkVersion + '/' + $textSdkPart))
}
$textApp = 'Ksword5.1/Ksword5.1'
$textSources = @(
    'tools/tests/unified_text_views_tests.cpp',
    "$textApp/UI/CodeEditorWidget.cpp", "$textApp/UI/CodeTextEdit.cpp", "$textApp/UI/CodeEditorFileSession.cpp",
    "$textApp/UI/StructuredFieldView.cpp", "$textApp/UI/TypedSyntaxDocument.cpp", "$textApp/UI/DetailLayoutHost.cpp", "$textApp/UI/DetailLayoutHost.Binding.cpp",
    "$textApp/UI/DetailLayoutHost.Compatibility.cpp", "$textApp/UI/EmbeddedRowDelegate.cpp",
    "$textApp/UI/MemoryWorkbench/MemoryRowCanvas.cpp", "$textApp/UI/MemoryWorkbench/WorkbenchTextView.cpp", "$textApp/UI/MemoryWorkbench/HexCanvasFormat.cpp",
    "$textApp/UI/FlowLayout.cpp", "$textApp/UI/ThemeStatusRole.cpp", "$textApp/UI/ThemeControlGlyphs.cpp", "$textApp/UI/SmoothScrollSupport.cpp",
    "$textApp/Internationalization/LanguageManager.cpp", 'shared/evidence/memory_workbench/MemoryTextDecode.cpp'
)
$textPreviousPath = $env:PATH
$textPreviousPlatform = $env:QT_QPA_PLATFORM
$textPreviousPlugins = $env:QT_PLUGIN_PATH
Push-Location $textRepository
try {
    $env:PATH = (Join-Path $textQt 'bin') + ';' + (Join-Path $textSdk ('bin/' + $textSdkVersion + '/x64')) + ';' + $textPreviousPath
    foreach ($textHeader in @("$textApp/UI/CodeEditorWidget.h", "$textApp/UI/StructuredFieldView.h", "$textApp/UI/MemoryWorkbench/MemoryRowCanvas.h", "$textApp/UI/MemoryWorkbench/WorkbenchTextView.h")) {
        $textMoc = Join-Path $textOutput ('unified_moc_' + [IO.Path]::GetFileNameWithoutExtension($textHeader) + '.cpp')
        & (Join-Path $textQt 'bin/moc.exe') $textHeader -o $textMoc
        if ($LASTEXITCODE -ne 0) { throw "moc failed: $textHeader" }
        $textSources += $textMoc
    }
    $textObjects = @()
    foreach ($textSource in $textSources) {
        $textObject = Join-Path $textOutput ('unified_' + [IO.Path]::GetFileNameWithoutExtension($textSource) + '.obj')
        # 本次字段呈现、外壳及回归源码按 /W4 /WX 检查，其他旧依赖保持原门槛。
        $textWarningArgs = @('/W3')
        if ($textSource -match '(TypedSyntaxDocument|CodeEditorWidget|CodeTextEdit|unified_text_views_tests)') { $textWarningArgs = @('/W4', '/WX') }
        # CodeTextEdit 既有语法器的局部 data 名称沿用主工程 C4458 排除；其余警告继续为错误。
        if ($textSource -match 'CodeTextEdit\.cpp$') { $textWarningArgs += '/wd4458' }
        & $textCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD @textWarningArgs /external:W0 /O1 /Gy /bigobj `
            /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DQT_TESTLIB_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE `
            @textIncludes /c $textSource ('/Fo' + $textObject)
        if ($LASTEXITCODE -ne 0) { throw "Production Qt component compilation failed: $textSource" }
        $textObjects += $textObject
    }
    $textExe = Join-Path $textOutput 'unified_text_views_tests.exe'
    $textLinkArgs = @('/nologo', '/SUBSYSTEM:CONSOLE', '/INCREMENTAL:NO', ('/OUT:' + $textExe),
        ('/LIBPATH:' + (Join-Path $textVcRoot 'lib/x64')), ('/LIBPATH:' + (Join-Path $textQt 'lib')))
    foreach ($textSdkPart in @('ucrt', 'um')) {
        $textLinkArgs += '/LIBPATH:' + (Join-Path $textSdk ('Lib/' + $textSdkVersion + '/' + $textSdkPart + '/x64'))
    }
    & $textLinker @textLinkArgs @textObjects Qt6Widgets.lib Qt6Gui.lib Qt6Core.lib Qt6Svg.lib Qt6Test.lib user32.lib advapi32.lib
    if ($LASTEXITCODE -ne 0) { throw 'Unified text views regression link failed.' }
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $textQt 'plugins'
    $ErrorActionPreference = 'Continue'
    & $textExe 2>&1 | Tee-Object -FilePath (Join-Path $textOutput 'unified_text_views_tests.log')
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { throw 'Unified text views regression failed.' }
}
finally {
    Pop-Location
    $env:PATH = $textPreviousPath
    $env:QT_QPA_PLATFORM = $textPreviousPlatform
    $env:QT_PLUGIN_PATH = $textPreviousPlugins
}
