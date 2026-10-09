# 串行编译实际详情宿主与编辑器，所有专属产物写入既有 output/ 目录。
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot), [switch]$ReuseFixtureObjects, [switch]$RegistryReentryOnly,
    [ValidateSet('', 'Floating', 'Geometry', 'OwnerClose')][string]$TransactionReentry = '')
$ErrorActionPreference = 'Stop'
$detailRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$detailOutput = Join-Path $detailRepository 'output'
if (!(Test-Path -LiteralPath $detailOutput)) { throw 'Existing output directory is required.' }
$detailQt = Join-Path $detailRepository '.deps/Qt/6.9.3/msvc2022_64'
$detailVc = 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207'
$detailSdk = 'C:/Program Files (x86)/Windows Kits/10'
$detailSdkVersion = '10.0.26100.0'
$detailCompiler = Join-Path $detailVc 'bin/Hostx64/x64/cl.exe'
$detailLinker = Join-Path $detailVc 'bin/Hostx64/x64/link.exe'
foreach ($detailRequired in @($detailCompiler, $detailLinker, (Join-Path $detailQt 'lib/Qt6Widgets.lib'))) {
    if (!(Test-Path -LiteralPath $detailRequired)) { throw "Missing HostX64 fixture dependency: $detailRequired" }
}
$detailIncludes = @(('/I' + $detailRepository), ('/external:I' + (Join-Path $detailVc 'include')))
foreach ($detailModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg')) {
    $detailIncludes += '/external:I' + (Join-Path $detailQt ('include/' + $detailModule))
}
foreach ($detailPart in @('ucrt', 'shared', 'um')) {
    $detailIncludes += '/external:I' + (Join-Path $detailSdk ('Include/' + $detailSdkVersion + '/' + $detailPart))
}
$detailApp = 'Ksword5.1/Ksword5.1'
$detailSources = @(
    'tools/detail_pane_tests.cpp', "$detailApp/UI/DetailLayoutHost.cpp", "$detailApp/UI/DetailLayoutHost.Binding.cpp",
    "$detailApp/UI/DetailLayoutHost.Compatibility.cpp", "$detailApp/UI/DetailLayoutRegistry.cpp", "$detailApp/UI/EmbeddedRowDelegate.cpp",
    "$detailApp/UI/CodeEditorWidget.cpp", "$detailApp/UI/CodeTextEdit.cpp", "$detailApp/UI/CodeEditorFileSession.cpp",
    "$detailApp/UI/StructuredFieldView.cpp",
    "$detailApp/UI/FlowLayout.cpp", "$detailApp/UI/ThemeStatusRole.cpp", "$detailApp/UI/ThemeControlGlyphs.cpp",
    "$detailApp/UI/SmoothScrollSupport.cpp", "$detailApp/UI/FlatButtonTheme.cpp", "$detailApp/UI/ThemeBinding.cpp", "$detailApp/UI/ThemeAccentIcon.cpp", "$detailApp/Internationalization/LanguageManager.cpp"
)
$detailMoc = Join-Path $detailOutput 'detail_pane_moc_CodeEditorWidget.cpp'
& (Join-Path $detailQt 'bin/moc.exe') (Join-Path $detailRepository "$detailApp/UI/CodeEditorWidget.h") -o $detailMoc
if ($LASTEXITCODE -ne 0) { throw 'Detail pane editor moc failed.' }
$detailSources += $detailMoc
$detailFieldMoc = Join-Path $detailOutput 'detail_pane_moc_StructuredFieldView.cpp'
& (Join-Path $detailQt 'bin/moc.exe') (Join-Path $detailRepository "$detailApp/UI/StructuredFieldView.h") -o $detailFieldMoc
if ($LASTEXITCODE -ne 0) { throw 'Detail pane structured view moc failed.' }
$detailSources += $detailFieldMoc
$detailObjects = @()
$detailHeaders = @('UI/DetailLayoutHost.h', 'UI/DetailLayoutRegistry.h', 'UI/CodeEditorWidget.h',
    'UI/CodeTextEdit.h', 'UI/StructuredFieldView.h', 'theme.h', 'SettingsDock/AppearanceSettings.h')
$detailHeaderTime = ($detailHeaders | ForEach-Object {
    (Get-Item -LiteralPath (Join-Path $detailRepository ($detailApp + '/' + $_))).LastWriteTimeUtc
} | Sort-Object -Descending | Select-Object -First 1)
foreach ($detailSource in $detailSources) {
    $detailObject = Join-Path $detailOutput ('detail_pane_' + [IO.Path]::GetFileNameWithoutExtension($detailSource) + '.obj')
    Write-Output ('DETAIL_PANE_COMPILE=' + $detailSource)
    $detailSourcePath = $detailSource
    if (![IO.Path]::IsPathRooted($detailSourcePath)) { $detailSourcePath = Join-Path $detailRepository $detailSourcePath }
    # 只可复用本夹具自己的严格编译对象，源或共用头变化后仍重新编译。
    if ($ReuseFixtureObjects -and (Test-Path -LiteralPath $detailObject)) {
        $detailObjectTime = (Get-Item -LiteralPath $detailObject).LastWriteTimeUtc
        if ($detailObjectTime -ge $detailHeaderTime -and $detailObjectTime -ge (Get-Item -LiteralPath $detailSourcePath).LastWriteTimeUtc) {
            $detailObjects += $detailObject
            continue
        }
    }
    # 既有 CodeTextEdit 与主工程一致排除局部 data 遮蔽；本次组件仍严格 W4/WX。
    $detailWarningArgs = @('/W4', '/WX')
    if ($detailSource -match 'CodeTextEdit\.cpp$') { $detailWarningArgs += '/wd4458' }
    & $detailCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD @detailWarningArgs /external:W0 /O1 /Gy /bigobj `
        /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE `
        @detailIncludes /c $detailSourcePath ('/Fo' + $detailObject)
    if ($LASTEXITCODE -ne 0) { throw "Detail pane production compilation failed: $detailSource" }
    $detailObjects += $detailObject
}
$detailExe = Join-Path $detailOutput 'detail_pane_tests.exe'
$detailLibs = @(('/LIBPATH:' + (Join-Path $detailVc 'lib/x64')), ('/LIBPATH:' + (Join-Path $detailQt 'lib')))
foreach ($detailPart in @('ucrt', 'um')) {
    $detailLibs += '/LIBPATH:' + (Join-Path $detailSdk ('Lib/' + $detailSdkVersion + '/' + $detailPart + '/x64'))
}
& $detailLinker /nologo /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:REF ('/OUT:' + $detailExe) `
    @detailObjects @detailLibs Qt6Widgets.lib Qt6Gui.lib Qt6Core.lib Qt6Svg.lib user32.lib advapi32.lib
if ($LASTEXITCODE -ne 0) { throw 'Detail pane production fixture link failed.' }
$detailOldPath = $env:PATH
$detailOldPlatform = $env:QT_QPA_PLATFORM
$detailOldPlugins = $env:QT_PLUGIN_PATH
try {
    $env:PATH = (Join-Path $detailQt 'bin') + ';' + $detailOldPath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $detailQt 'plugins'
    $ErrorActionPreference = 'Continue'
    $detailRunArgs = @()
    if ($RegistryReentryOnly) { $detailRunArgs += '--registry-reentry-only' }
    if ($TransactionReentry) { $detailRunArgs += '--' + $TransactionReentry.ToLowerInvariant() + '-reentry-only' }
    & $detailExe @detailRunArgs 2>&1 | Tee-Object -FilePath (Join-Path $detailOutput 'detail_pane_tests.log')
    Write-Output ('DETAIL_PANE_EXIT_CODE=' + $LASTEXITCODE)
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { throw 'Detail pane Qt regression failed.' }
}
finally {
    $env:PATH = $detailOldPath
    $env:QT_QPA_PLATFORM = $detailOldPlatform
    $env:QT_PLUGIN_PATH = $detailOldPlugins
}
