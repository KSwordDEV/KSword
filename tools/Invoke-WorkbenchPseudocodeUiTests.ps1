# 独立编译真实 C 页面与共享编辑器，仅复用既有插件路由 stub。
# 产物写入已存在的日志目录；不建临时目录，不执行 Java、设备或剪贴板动作。
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string[]]$TestCases = @(),
    [switch]$BuildOnly,
    [switch]$RunOnly
)
$ErrorActionPreference = 'Stop'
$cPageRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$cPageOutput = Join-Path $cPageRepository '.codex-build-logs'
if (!(Test-Path -LiteralPath $cPageOutput)) { throw 'The established .codex-build-logs directory is required.' }
$cPageQt = Join-Path $cPageRepository '.deps/Qt/6.9.3/msvc2022_64'
$cPageVcBase = 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC'
$cPageVcRoot = Join-Path $cPageVcBase '14.44.35207'
if (!(Test-Path -LiteralPath $cPageVcRoot)) {
    $cPageCandidate = Get-ChildItem -LiteralPath $cPageVcBase -Directory | Sort-Object Name -Descending | Select-Object -First 1
    if (!$cPageCandidate) { throw 'HostX64 MSVC is required.' }
    $cPageVcRoot = $cPageCandidate.FullName
}
$cPageSdk = 'C:/Program Files (x86)/Windows Kits/10'
$cPageSdkVersion = '10.0.26100.0'
$cPageCompiler = Join-Path $cPageVcRoot 'bin/Hostx64/x64/cl.exe'
$cPageLinker = Join-Path $cPageVcRoot 'bin/Hostx64/x64/link.exe'
foreach ($cPageRequired in @($cPageCompiler, $cPageLinker, (Join-Path $cPageQt 'lib/Qt6Widgets.lib'))) {
    if (!(Test-Path -LiteralPath $cPageRequired)) { throw "Required tool or Qt library is missing: $cPageRequired" }
}
# 只使用项目配置中的已知依赖路径；MSVC/SDK 头按外部依赖免报第三方警告。
$cPageIncludes = @(('/I' + $cPageRepository), ('/external:I' + (Join-Path $cPageVcRoot 'include')))
foreach ($cPageModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg', 'QtTest')) {
    $cPageIncludes += '/external:I' + (Join-Path $cPageQt ('include/' + $cPageModule))
}
foreach ($cPagePart in @('ucrt', 'shared', 'um')) {
    $cPageIncludes += '/external:I' + (Join-Path $cPageSdk ('Include/' + $cPageSdkVersion + '/' + $cPagePart))
}
$cPageApp = 'Ksword5.1/Ksword5.1'
$cPageSources = @(
    'tools/tests/workbench_pseudocode_ui_tests.cpp', 'tools/workbench_pseudocode_contract_tests.cpp',
    'tools/memwb_ui/wpJ6/wpJ6_plugin_stubs.cpp',
    "$cPageApp/UI/MemoryWorkbench/WorkbenchPseudocodeView.cpp", "$cPageApp/UI/MemoryWorkbench/WorkbenchPseudocodeView.Ui.cpp",
    "$cPageApp/UI/Decompiler/GhidraDecompiler.cpp", 'GhidraRuntimePlugin/RuntimeProfile.cpp',
    "$cPageApp/UI/CodeEditorWidget.cpp", "$cPageApp/UI/CodeTextEdit.cpp", "$cPageApp/UI/CodeEditorFileSession.cpp",
    "$cPageApp/UI/StructuredFieldView.cpp", "$cPageApp/UI/TypedSyntaxDocument.cpp", "$cPageApp/UI/DetailLayoutHost.cpp", "$cPageApp/UI/DetailLayoutHost.Binding.cpp",
    "$cPageApp/UI/DetailLayoutHost.Compatibility.cpp", "$cPageApp/UI/EmbeddedRowDelegate.cpp",
    "$cPageApp/UI/FlowLayout.cpp", "$cPageApp/UI/ThemeStatusRole.cpp", "$cPageApp/UI/ThemeControlGlyphs.cpp",
    "$cPageApp/UI/SmoothScrollSupport.cpp", "$cPageApp/UI/FlatButtonTheme.cpp", "$cPageApp/UI/ThemeBinding.cpp", "$cPageApp/UI/ThemeAccentIcon.cpp", "$cPageApp/Internationalization/LanguageManager.cpp"
)
$cPageOldPath = $env:PATH
$cPageOldPlatform = $env:QT_QPA_PLATFORM
$cPageOldPlugins = $env:QT_PLUGIN_PATH
$cPageExe = Join-Path $cPageOutput 'workbench_pseudocode_ui_tests.exe'
Push-Location $cPageRepository
try {
    $env:PATH = (Join-Path $cPageQt 'bin') + ';' + (Join-Path $cPageSdk ('bin/' + $cPageSdkVersion + '/x64')) + ';' + $cPageOldPath
    if (!$RunOnly) {
        foreach ($cPageHeader in @("$cPageApp/UI/CodeEditorWidget.h", "$cPageApp/UI/StructuredFieldView.h", "$cPageApp/UI/MemoryWorkbench/WorkbenchPseudocodeView.h", "$cPageApp/UI/Decompiler/GhidraDecompiler.h")) {
            $cPageMoc = Join-Path $cPageOutput ('c_progress_moc_' + [IO.Path]::GetFileNameWithoutExtension($cPageHeader) + '.cpp')
            & (Join-Path $cPageQt 'bin/moc.exe') $cPageHeader -o $cPageMoc
            if ($LASTEXITCODE -ne 0) { throw "moc failed: $cPageHeader" }
            $cPageSources += $cPageMoc
        }
        $cPageObjects = @()
        foreach ($cPageSource in $cPageSources) {
            $cPageObject = Join-Path $cPageOutput ('c_progress_' + [IO.Path]::GetFileNameWithoutExtension($cPageSource) + '.obj')
            $cPageWarnings = @('/W3')
            if ($cPageSource -match '(workbench_pseudocode|WorkbenchPseudocode|GhidraDecompiler|CodeEditorWidget|CodeTextEdit)') {
                $cPageWarnings = @('/W4', '/WX')
            }
            # 原主工程明确排除的旧语法器 data 局部名称警告；不屏蔽本轮新增警告。
            if ($cPageSource -match 'CodeTextEdit\.cpp$') { $cPageWarnings += '/wd4458' }
            & $cPageCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD @cPageWarnings /external:W0 /O1 /Gy /bigobj `
                /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DQT_TESTLIB_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE `
                @cPageIncludes /c $cPageSource ('/Fo' + $cPageObject)
            if ($LASTEXITCODE -ne 0) { throw "Production C page component compilation failed: $cPageSource" }
            $cPageObjects += $cPageObject
        }
        $cPageLinkArgs = @('/nologo', '/SUBSYSTEM:CONSOLE', '/INCREMENTAL:NO', ('/OUT:' + $cPageExe),
            ('/LIBPATH:' + (Join-Path $cPageVcRoot 'lib/x64')), ('/LIBPATH:' + (Join-Path $cPageQt 'lib')))
        foreach ($cPagePart in @('ucrt', 'um')) {
            $cPageLinkArgs += '/LIBPATH:' + (Join-Path $cPageSdk ('Lib/' + $cPageSdkVersion + '/' + $cPagePart + '/x64'))
        }
        & $cPageLinker @cPageLinkArgs @cPageObjects Qt6Widgets.lib Qt6Gui.lib Qt6Core.lib Qt6Svg.lib Qt6Test.lib user32.lib advapi32.lib
        if ($LASTEXITCODE -ne 0) { throw 'C page regression link failed.' }
    }
    if ($BuildOnly) { Write-Output 'WORKBENCH_PSEUDOCODE_UI_BUILD=PASS'; return }
    if (!(Test-Path -LiteralPath $cPageExe)) { throw 'Build the C page regression executable before RunOnly.' }
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $cPageQt 'plugins'
    $cPageLog = Join-Path $cPageOutput 'workbench_pseudocode_ui_tests.log'
    $cPageRunCases = if ($TestCases.Count) { $TestCases } else { @('all') }
    $cPageFailures = 0
    foreach ($cPageCase in $cPageRunCases) {
        $cPageArgs = if ($cPageCase -eq 'all') { @() } else { @('--case', $cPageCase) }
        $ErrorActionPreference = 'Continue'
        & $cPageExe @cPageArgs 2>&1 | Tee-Object -FilePath $cPageLog -Append
        $cPageExit = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($cPageExit -ne 0) {
            ++$cPageFailures
            Write-Output "WORKBENCH_PSEUDOCODE_UI_CASE=$cPageCase EXIT_CODE=$cPageExit"
        }
    }
    if ($cPageFailures) { throw "C page regression cases failed: $cPageFailures" }
}
finally {
    Pop-Location
    $env:PATH = $cPageOldPath
    $env:QT_QPA_PLATFORM = $cPageOldPlatform
    $env:QT_PLUGIN_PATH = $cPageOldPlugins
}
