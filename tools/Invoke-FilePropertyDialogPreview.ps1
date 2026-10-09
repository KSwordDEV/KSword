# Extracts the current production shell/general/theme UI into an inert fixture.
# Backend reads and actions are omitted; no target file or driver is accessed.
param(
    [string]$QtRoot = '.codex-tmp/qt-fixture/ucrt64',
    [string]$OutputDirectory = 'work/file-property-dialog-preview',
    [string]$PreviewDirectory = 'work/file-property-dialog-preview/shots',
    [string]$Compiler = 'g++'
)
$ErrorActionPreference = 'Stop'
$previewRepository = Split-Path -Parent $PSScriptRoot
$previewOldPath = $env:PATH
$previewOldPlugins = $env:QT_PLUGIN_PATH
$previewOldPlatform = $env:QT_QPA_PLATFORM
Push-Location $previewRepository
try {
    $previewQt = (Resolve-Path -LiteralPath $QtRoot).Path
    $env:PATH = (Join-Path $previewQt 'bin') + ';' + $previewOldPath
    $env:QT_PLUGIN_PATH = Join-Path $previewQt 'share/qt6/plugins'
    $env:QT_QPA_PLATFORM = 'offscreen'
    $previewOutput = [IO.Path]::GetFullPath((Join-Path $previewRepository $OutputDirectory))
    $previewShots = if ([IO.Path]::IsPathRooted($PreviewDirectory)) { $PreviewDirectory }
        else { [IO.Path]::GetFullPath((Join-Path $previewRepository $PreviewDirectory)) }
    New-Item -ItemType Directory -Path $previewOutput -Force | Out-Null
    $previewSource = [IO.File]::ReadAllText((Join-Path $previewRepository 'Ksword5.1/Ksword5.1/FileDock/FileDock.cpp'))
    $previewHelpersStart = $previewSource.IndexOf('    QPalette buildFileDetailDialogPalette(')
    $previewHelpersEnd = $previewSource.IndexOf('    // buildLogPreviewText', $previewHelpersStart)
    if ($previewHelpersStart -lt 0 -or $previewHelpersEnd -le $previewHelpersStart) { throw 'Production theme extraction markers changed.' }
    $previewHelpers = $previewSource.Substring($previewHelpersStart, $previewHelpersEnd - $previewHelpersStart)
    [IO.File]::WriteAllText((Join-Path $previewOutput 'native-dialog-helpers.inc'), $previewHelpers, [Text.UTF8Encoding]::new($false))
    $previewConstructorStart = [regex]::Match($previewSource, '        explicit FileDetailDialog\(\s+const QStringList& filePaths,').Index
    $previewConstructorEnd = $previewSource.IndexOf('        ~FileDetailDialog()', $previewConstructorStart)
    if ($previewConstructorStart -le 0 -or $previewConstructorEnd -le $previewConstructorStart) { throw 'Production constructor extraction markers changed.' }
    $previewConstructor = $previewSource.Substring($previewConstructorStart, $previewConstructorEnd - $previewConstructorStart).Replace('FileDetailDialog(', 'FileDetailDialogFixture(')
    $previewThemeStart = $previewSource.IndexOf('        void applyThemeStyle()', $previewConstructorEnd)
    $previewThemeEnd = $previewSource.IndexOf('        struct HashCalculationResult', $previewThemeStart)
    if ($previewThemeStart -lt 0 -or $previewThemeEnd -le $previewThemeStart) { throw 'Production applyThemeStyle extraction markers changed.' }
    $previewTheme = $previewSource.Substring($previewThemeStart, $previewThemeEnd - $previewThemeStart)
    $previewGeneralStart = $previewSource.IndexOf('        QWidget* buildGeneralTab()')
    $previewHeaderStart = $previewSource.IndexOf('            QFrame* header = new QFrame(page);', $previewGeneralStart)
    $previewGeneralUiStart = $previewSource.LastIndexOf('            QWidget* page = new QWidget(this);', $previewHeaderStart)
    $previewGeneralEnd = $previewSource.IndexOf('        static QComboBox* buildChangeStateCombo', $previewHeaderStart)
    if ($previewGeneralStart -lt 0 -or $previewGeneralUiStart -le $previewGeneralStart -or $previewGeneralEnd -le $previewHeaderStart) { throw 'Production general UI extraction markers changed.' }
    $previewGeneral = '        QWidget* buildGeneralTab() {' + "`n" + $previewSource.Substring($previewGeneralUiStart, $previewGeneralEnd - $previewGeneralUiStart)
    $previewDataStart = $previewGeneral.IndexOf('            const QFileInfo info(m_filePath);')
    $previewLayoutStart = $previewGeneral.IndexOf('            layout->addWidget(m_generalPropertyView, 1);', $previewDataStart)
    $previewGeneral = $previewGeneral.Substring(0, $previewDataStart) + "            refreshGeneralTab();`n" + $previewGeneral.Substring($previewLayoutStart)
    $previewGeneral = $previewGeneral.Replace('            startR0FileInfoLoad(info, m_generalNtPathText);', '')
    $previewGeneral = $previewGeneral.Replace('iconProvider.icon(QFileInfo(m_filePath))', 'QApplication::style()->standardIcon(QStyle::SP_FileIcon)')
    [IO.File]::WriteAllText((Join-Path $previewOutput 'native-dialog-members.inc'), ($previewConstructor + $previewTheme + $previewGeneral), [Text.UTF8Encoding]::new($false))

    # Use the real navigation SVG resources from the product's resource map.
    [xml]$previewResources = Get-Content -LiteralPath 'Ksword5.1/Ksword5.1/Ksword5.qrc' -Raw
    $previewAliases = @('process_details.svg','process_copy_cell.svg','file_nav_forward.svg','file_owner.svg','process_performance.svg','process_main.svg','disk_storage.svg','filter_funnel.svg','process_critical.svg','process_list.svg','process_copy_row.svg','file_find.svg','log_export.svg')
    $previewQrc = @('<RCC><qresource prefix="/Icon">')
    foreach ($previewResource in $previewResources.SelectNodes('//file')) {
        if ($previewResource.GetAttribute('alias') -notin $previewAliases) { continue }
        $previewAlias = [Security.SecurityElement]::Escape($previewResource.GetAttribute('alias'))
        $previewPath = [Security.SecurityElement]::Escape((Join-Path $previewRepository ('Ksword5.1/Ksword5.1/' + $previewResource.InnerText)).Replace('\','/'))
        $previewQrc += '<file alias="' + $previewAlias + '">' + $previewPath + '</file>'
    }
    $previewQrc += '</qresource></RCC>'
    [IO.File]::WriteAllText((Join-Path $previewOutput 'navigation.qrc'), ($previewQrc -join "`n"), [Text.UTF8Encoding]::new($false))
    & (Join-Path $previewQt 'share/qt6/bin/rcc.exe') (Join-Path $previewOutput 'navigation.qrc') -o (Join-Path $previewOutput 'qrc_navigation.cpp')
    if ($LASTEXITCODE -ne 0) { throw 'Navigation SVG resource compilation failed.' }
    $previewFlags = @('-std=c++20','-O1','-g0','-ffunction-sections','-fdata-sections','-DNOMINMAX','-DUNICODE','-D_UNICODE','-DQT_CORE_LIB','-DQT_GUI_LIB','-DQT_WIDGETS_LIB','-DQT_TESTLIB_LIB','-I.',"-I$previewOutput")
    foreach ($previewModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtTest', 'QtSvg')) {
        $previewFlags += @('-isystem', (Join-Path $previewQt "include/qt6/$previewModule"))
    }
    $previewObjects = @()
    foreach ($previewUnit in @('tools/file_property_dialog_preview.cpp',
        'Ksword5.1/Ksword5.1/UI/UIBaseFunction.cpp',
        'Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.cpp', 'Ksword5.1/Ksword5.1/UI/FlatButtonTheme.cpp',
        'Ksword5.1/Ksword5.1/UI/TablePresentation.cpp',
        'Ksword5.1/Ksword5.1/UI/ThemeControlGlyphs.cpp',
        'Ksword5.1/Ksword5.1/UI/ThemeStatusRole.cpp',
        (Join-Path $previewOutput 'qrc_navigation.cpp'))) {
        $previewObject = Join-Path $previewOutput (([IO.Path]::GetFileNameWithoutExtension($previewUnit)) + '.o')
        Write-Output "Compiling $previewUnit"
        & $Compiler @previewFlags -c $previewUnit -o $previewObject
        if ($LASTEXITCODE -ne 0) { throw "Production shell fixture compilation failed: $previewUnit" }
        $previewObjects += $previewObject
    }
    foreach ($previewShared in @('StructuredFieldView.o', 'moc_StructuredFieldView.o', 'LanguageManager.o', 'ThemeBinding.o')) {
        $previewObjects += Join-Path $previewRepository "work/file-property-view-ui-tests/$previewShared"
    }
    $previewLanguages = Join-Path $previewOutput 'languages'
    New-Item -ItemType Directory -Path $previewLanguages -Force | Out-Null
    foreach ($previewLanguage in @('zh-CN.json','en-US.json')) {
        Copy-Item -LiteralPath "Ksword5.1/Ksword5.1/languages/$previewLanguage" -Destination $previewLanguages -Force
    }
    $previewExe = Join-Path $previewOutput 'file-property-dialog-preview.exe'
    & $Compiler @previewObjects '-Wl,--gc-sections' "-L$previewQt/lib" -lQt6Widgets -lQt6Gui -lQt6Core -lQt6Test -lQt6Svg -o $previewExe
    if ($LASTEXITCODE -ne 0) { throw 'Production shell fixture link failed.' }
    & $previewExe $previewShots 2>&1 | Tee-Object -FilePath (Join-Path $previewOutput 'file-property-dialog-preview.log')
    if ($LASTEXITCODE -ne 0) { throw "Production shell layout checks failed (native exit $LASTEXITCODE)." }
}
finally {
    $env:PATH = $previewOldPath
    $env:QT_PLUGIN_PATH = $previewOldPlugins
    $env:QT_QPA_PLATFORM = $previewOldPlatform
    Pop-Location
}
