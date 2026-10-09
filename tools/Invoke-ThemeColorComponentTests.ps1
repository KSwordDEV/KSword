# 直接编译实际生产源码的离屏组件回归；不用生产obj/tlog，不启动主程序或访问驱动。
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$ReuseProductionObjects
)
$ErrorActionPreference = 'Stop'
$componentRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$componentOutput = Join-Path $componentRepository '.codex-build-logs'
if (!(Test-Path -LiteralPath $componentOutput)) { throw 'Existing build log directory is required.' }
$componentQt = Join-Path $componentRepository '.deps\Qt\6.9.3\msvc2022_64'
if (!(Test-Path -LiteralPath $componentQt)) { $componentQt = 'D:\Software\Qt\6.9.3\msvc2022_64' }
$componentVc = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$componentSdk = 'C:\Program Files (x86)\Windows Kits\10'
$componentSdkVersion = '10.0.26100.0'
$componentCompiler = Join-Path $componentVc 'bin\Hostx64\x64\cl.exe'
$componentExe = Join-Path $componentOutput 'theme_color_component_tests.exe'
$componentSources = @(
    'tools\theme_color_component_tests.cpp',
    'Ksword5.1\Ksword5.1\UI\CodeEditorWidget.cpp',
    'Ksword5.1\Ksword5.1\UI\CodeTextEdit.cpp',
    'Ksword5.1\Ksword5.1\UI\CodeEditorFileSession.cpp',
    'Ksword5.1\Ksword5.1\UI\StructuredFieldView.cpp', 'Ksword5.1\Ksword5.1\UI\TypedSyntaxDocument.cpp',
        'Ksword5.1\Ksword5.1\UI\GlobalUiBaseStyle.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeStatusRole.cpp',
    'Ksword5.1\Ksword5.1\UI\SvgThemeIconManager.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeControlGlyphs.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeAccentIcon.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemedMessageBox.cpp',
    'Ksword5.1\Ksword5.1\UI\WindowChrome.cpp',
    'Ksword5.1\Ksword5.1\UI\CommandExecutionPopup.cpp',
    'Ksword5.1\Ksword5.1\UI\ThemeBinding.cpp',
    'Ksword5.1\Ksword5.1\UI\TableInteractionSupport.cpp',
    'Ksword5.1\Ksword5.1\UI\TablePresentation.cpp',
    'Ksword5.1\Ksword5.1\UI\UiCommitCoordinator.cpp',
    'Ksword5.1\Ksword5.1\UI\ResultTableHost.cpp',
    'Ksword5.1\Ksword5.1\UI\TableSnapshotCompare.cpp',
    'Ksword5.1\Ksword5.1\UI\TableFreezeSupport.cpp',
    'Ksword5.1\Ksword5.1\UI\TableHeaderSortingSupport.cpp',
    'Ksword5.1\Ksword5.1\UI\TableSearchSupport.cpp',
    'Ksword5.1\Ksword5.1\UI\TableColumnAutoFit.cpp',
    'Ksword5.1\Ksword5.1\UI\GlobalUiSearch.cpp',
    'Ksword5.1\Ksword5.1\Framework\CustomTitleBar.cpp',
    'Ksword5.1\Ksword5.1\Framework\NotificationCardManager.cpp',
    'Ksword5.1\Ksword5.1\Framework\LogDockWidget.cpp',
    'Ksword5.1\Ksword5.1\Framework\Progress.cpp',
    'Ksword5.1\Ksword5.1\Framework\TaskSnapshotFeed.cpp',
    'Ksword5.1\Ksword5.1\Internationalization\LanguageManager.cpp',
    'Ksword5.1\Ksword5.1\ksword\log\log.cpp'
) | ForEach-Object { Join-Path $componentRepository $_ }
$componentHeaders = @(
    'Ksword5.1\Ksword5.1\UI\CodeEditorWidget.h',
    'Ksword5.1\Ksword5.1\UI\StructuredFieldView.h',
    'Ksword5.1\Ksword5.1\UI\CommandExecutionPopup.h',
    'Ksword5.1\Ksword5.1\UI\GlobalUiSearch.h',
    'Ksword5.1\Ksword5.1\Framework\CustomTitleBar.h'
) | ForEach-Object { Join-Path $componentRepository $_ }
foreach ($componentRequired in @($componentCompiler) + $componentSources + $componentHeaders) {
    if (!(Test-Path -LiteralPath $componentRequired)) { throw "Missing component fixture input: $componentRequired" }
}
foreach ($componentHeader in $componentHeaders) {
    $componentStem = [IO.Path]::GetFileNameWithoutExtension($componentHeader)
    $componentMoc = Join-Path $componentOutput ('theme_component_moc_' + $componentStem + '.cpp')
    & (Join-Path $componentQt 'bin\moc.exe') $componentHeader -o $componentMoc
    if ($LASTEXITCODE -ne 0) { throw "Component moc failed: $componentStem" }
    $componentSources += $componentMoc
}

# 从当前qrc只读抽取已存在的编辑器/标题栏资源；不包含glyph缓存资源，不写用户AppData。
[xml]$componentQrcSource = Get-Content -LiteralPath (Join-Path $componentRepository 'Ksword5.1\Ksword5.1\Ksword5.qrc')
$componentQrc = Join-Path $componentOutput 'theme-component-fixture.qrc'
$componentRcc = Join-Path $componentOutput 'theme-component-fixture.rcc'
$componentResourceXml = '<RCC><qresource prefix="/Icon">'
foreach ($componentResource in $componentQrcSource.RCC.qresource.file) {
    if ($componentResource.alias -notlike 'codeeditor_*' -and $componentResource.alias -notlike 'titlebar_*') { continue }
    $componentResourceFile = Join-Path $componentRepository ('Ksword5.1\Ksword5.1\' + $componentResource.InnerText)
    $componentResourceXml += '<file alias="' + [Security.SecurityElement]::Escape($componentResource.alias) + '">' +
        [Security.SecurityElement]::Escape($componentResourceFile) + '</file>'
}
$componentResourceXml += '</qresource></RCC>'
[IO.File]::WriteAllText($componentQrc, $componentResourceXml, [Text.UTF8Encoding]::new($false))
& (Join-Path $componentQt 'bin\rcc.exe') -binary $componentQrc -o $componentRcc
if ($LASTEXITCODE -ne 0) { throw 'Component fixture resource build failed.' }

$componentIncludes = @('/I' + (Join-Path $componentRepository 'Ksword5.1\Ksword5.1'))
$componentIncludes += '/external:I' + (Join-Path $componentVc 'include')
$componentIncludes += '/external:I' + (Join-Path $componentVc 'atlmfc\include')
foreach ($componentModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg', 'QtNetwork', 'QtTest')) {
    $componentIncludes += '/external:I' + (Join-Path $componentQt ('include\' + $componentModule))
}
foreach ($componentSdkPart in @('ucrt', 'shared', 'um')) {
    $componentIncludes += '/external:I' + (Join-Path $componentSdk ('Include\' + $componentSdkVersion + '\' + $componentSdkPart))
}
$componentObjects = @()
$componentThemeHeaderTime = (Get-Item -LiteralPath (Join-Path $componentRepository 'Ksword5.1\Ksword5.1\theme.h')).LastWriteTimeUtc
foreach ($componentSource in $componentSources) {
    $componentSourceKey = $componentSource.Substring($componentRepository.Length).TrimStart('\').Replace('\', '_')
    $componentObject = Join-Path $componentOutput ('theme_component_' + [IO.Path]::GetFileNameWithoutExtension($componentSourceKey) + '.obj')
    # 默认完整编译；生产冻结时可只迭代夹具，仍拒绝复用源/主题头更新前的对象。
    $componentCanReuse = $ReuseProductionObjects -and $componentSource -notlike '*\tools\*' -and
        $componentSource -notlike '*\.codex-build-logs\*' -and (Test-Path -LiteralPath $componentObject)
    if ($componentCanReuse) {
        $componentObjectTime = (Get-Item -LiteralPath $componentObject).LastWriteTimeUtc
        $componentCanReuse = $componentObjectTime -ge (Get-Item -LiteralPath $componentSource).LastWriteTimeUtc -and
            $componentObjectTime -ge $componentThemeHeaderTime
        $componentOwnHeader = [IO.Path]::ChangeExtension($componentSource, '.h')
        if (Test-Path -LiteralPath $componentOwnHeader) {
            $componentCanReuse = $componentCanReuse -and $componentObjectTime -ge (Get-Item -LiteralPath $componentOwnHeader).LastWriteTimeUtc
        }
    }
    if (!$componentCanReuse) {
        Write-Output ('COMPONENT_COMPILE=' + [IO.Path]::GetFileName($componentSource))
        & $componentCompiler /nologo /std:c++latest /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W3 /wd4702 /O2 /Gy /bigobj /external:W0 `
            /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /DQT_WIDGETS_LIB /DQT_GUI_LIB /DQT_CORE_LIB @componentIncludes `
            /c $componentSource ('/Fo' + $componentObject)
        if ($LASTEXITCODE -ne 0) { throw "Component source compilation failed: $componentSource" }
    }
    $componentObjects += $componentObject
}
$componentLibArgs = @('/LIBPATH:' + (Join-Path $componentQt 'lib'))
$componentLibArgs += '/LIBPATH:' + (Join-Path $componentVc 'lib\x64')
$componentLibArgs += '/LIBPATH:' + (Join-Path $componentVc 'atlmfc\lib\x64')
$componentLibArgs += '/LIBPATH:' + (Join-Path $componentRepository 'Ksword5.1\Ksword5.1\lib')
foreach ($componentSdkPart in @('ucrt', 'um')) {
    $componentLibArgs += '/LIBPATH:' + (Join-Path $componentSdk ('Lib\' + $componentSdkVersion + '\' + $componentSdkPart + '\x64'))
}
& (Join-Path $componentVc 'bin\Hostx64\x64\link.exe') /NOLOGO /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:REF `
    ('/OUT:' + $componentExe) @componentObjects @componentLibArgs Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Svg.lib Qt6Network.lib Qt6Test.lib `
    qtadvanceddocking.lib user32.lib advapi32.lib ole32.lib shell32.lib gdi32.lib dwmapi.lib comdlg32.lib crypt32.lib wintrust.lib imagehlp.lib
if ($LASTEXITCODE -ne 0) { throw 'Component fixture link failed.' }
$componentOldPath = $env:PATH
$componentOldPlatform = $env:QT_QPA_PLATFORM
$componentOldPluginPath = $env:QT_PLUGIN_PATH
try {
    $env:PATH = (Join-Path $componentQt 'bin') + ';' + (Join-Path $componentRepository 'Ksword5.1\Ksword5.1\lib') + ';' + $componentOldPath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $componentQt 'plugins'
    & $componentExe $componentRcc
    if ($LASTEXITCODE -ne 0) { throw 'Theme color actual-component regression failed.' }
}
finally {
    $env:PATH = $componentOldPath
    $env:QT_QPA_PLATFORM = $componentOldPlatform
    $env:QT_PLUGIN_PATH = $componentOldPluginPath
}
