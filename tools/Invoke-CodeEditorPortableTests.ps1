# Build the actual shared Qt text editor in an isolated MinGW fixture.
# Does not build the MSVC product or open native file dialogs.
param(
    [string]$QtRoot = '.codex-tmp/qt-fixture/ucrt64',
    [string]$OutputDirectory = '.codex-tmp/code-editor-ui-tests',
    [string]$SharedObjectDirectory = '.codex-tmp/memory-row-portable',
    [switch]$Rebuild
)
$ErrorActionPreference = 'Stop'
$editorRepository = Split-Path -Parent $PSScriptRoot
$editorOldPath = $env:PATH
$editorOldPlugins = $env:QT_PLUGIN_PATH
$editorOldPlatform = $env:QT_QPA_PLATFORM
Push-Location $editorRepository
try {
    $editorQt = (Resolve-Path -LiteralPath $QtRoot).Path
    $editorOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
        [IO.Path]::GetFullPath($OutputDirectory)
    } else { [IO.Path]::GetFullPath((Join-Path $editorRepository $OutputDirectory)) }
    New-Item -ItemType Directory -Path $editorOutput -Force | Out-Null
    $editorCache = if ([IO.Path]::IsPathRooted($SharedObjectDirectory)) {
        $SharedObjectDirectory
    } else { Join-Path $editorRepository $SharedObjectDirectory }
    $env:PATH = (Join-Path $editorQt 'bin') + ';' + $editorOldPath
    $env:QT_PLUGIN_PATH = Join-Path $editorQt 'share/qt6/plugins'
    $env:QT_QPA_PLATFORM = 'offscreen'
    $editorFlags = @('-std=c++20', '-O1', '-g0', '-ffunction-sections', '-fdata-sections',
        '-DNOMINMAX', '-DUNICODE', '-D_UNICODE', '-DQT_CORE_LIB', '-DQT_GUI_LIB',
        '-DQT_WIDGETS_LIB', '-DQT_TESTLIB_LIB', '-I.')
    foreach ($editorModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtTest', 'QtSvg')) {
        $editorFlags += @('-isystem', (Join-Path $editorQt "include/qt6/$editorModule"))
    }

    function Test-EditorObjectFresh([string]$ObjectPath, [string]$DependenciesPath) {
        if (!(Test-Path -LiteralPath $ObjectPath) -or !(Test-Path -LiteralPath $DependenciesPath)) { return $false }
        $editorModified = (Get-Item -LiteralPath $ObjectPath).LastWriteTimeUtc
        $editorDependencyText = (Get-Content -LiteralPath $DependenciesPath -Raw) -replace '\\\r?\n', ' '
        $editorColon = $editorDependencyText.IndexOf(': ')
        if ($editorColon -lt 0) { return $false }
        $editorDependencyText = $editorDependencyText.Substring($editorColon + 2)
        # GCC escapes spaces in prerequisite paths; preserve those while splitting.
        $editorEscapedSpace = [char]0x1F
        $editorDependencyText = $editorDependencyText.Replace('\ ', [string]$editorEscapedSpace)
        foreach ($editorDependencyToken in ($editorDependencyText -split '\s+')) {
            $editorDependency = $editorDependencyToken.Replace([string]$editorEscapedSpace, ' ')
            if ($editorDependency -and (!(Test-Path -LiteralPath $editorDependency) -or
                (Get-Item -LiteralPath $editorDependency).LastWriteTimeUtc -gt $editorModified)) { return $false }
        }
        return $true
    }

    # Compile the real icon resource subset instead of hiding missing toolbar SVGs.
    [xml]$editorResourceDocument = Get-Content 'Ksword5.1/Ksword5.1/Ksword5.qrc' -Raw
    $editorResourceLines = @('<RCC>', '<qresource prefix="/Icon">')
    foreach ($editorResource in $editorResourceDocument.SelectNodes('//file[starts-with(@alias,"codeeditor_")]')) {
        $editorResourceFile = [IO.Path]::GetFullPath((Join-Path $editorRepository ('Ksword5.1/Ksword5.1/' + $editorResource.InnerText)))
        if (!(Test-Path -LiteralPath $editorResourceFile)) { throw "Toolbar resource is missing: $editorResourceFile" }
        $editorResourceAlias = [Security.SecurityElement]::Escape($editorResource.GetAttribute('alias'))
        $editorResourceXmlPath = [Security.SecurityElement]::Escape($editorResourceFile.Replace('\', '/'))
        $editorResourceLines += '<file alias="' + $editorResourceAlias + '">' + $editorResourceXmlPath + '</file>'
    }
    $editorResourceLines += @('</qresource>', '</RCC>')
    $editorResourceContent = $editorResourceLines -join "`n"
    $editorResourceQrc = Join-Path $editorOutput 'code-editor-icons.qrc'
    if (!(Test-Path -LiteralPath $editorResourceQrc) -or
        [IO.File]::ReadAllText($editorResourceQrc) -ne $editorResourceContent) {
        [IO.File]::WriteAllText($editorResourceQrc, $editorResourceContent, [Text.UTF8Encoding]::new($false))
    }
    $editorResourceSource = Join-Path $editorOutput 'qrc_code_editor_fixture.cpp'
    if ($Rebuild -or !(Test-Path -LiteralPath $editorResourceSource) -or
        (Get-Item -LiteralPath $editorResourceQrc).LastWriteTimeUtc -gt (Get-Item -LiteralPath $editorResourceSource).LastWriteTimeUtc) {
        & (Join-Path $editorQt 'share/qt6/bin/rcc.exe') $editorResourceQrc -o $editorResourceSource
        if ($LASTEXITCODE -ne 0) { throw 'Editor icon resource compilation failed.' }
    }
    $editorMocSource = Join-Path $editorOutput 'moc_CodeEditorWidget.cpp'
    $editorHeader = 'Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h'
    if ($Rebuild -or !(Test-Path -LiteralPath $editorMocSource) -or
        (Get-Item -LiteralPath $editorHeader).LastWriteTimeUtc -gt (Get-Item -LiteralPath $editorMocSource).LastWriteTimeUtc) {
        & (Join-Path $editorQt 'share/qt6/bin/moc.exe') $editorHeader -o $editorMocSource
        if ($LASTEXITCODE -ne 0) { throw 'Editor moc generation failed.' }
    }
    $editorFieldMoc = Join-Path $editorOutput 'moc_StructuredFieldView.cpp'
    & (Join-Path $editorQt 'share/qt6/bin/moc.exe') 'Ksword5.1/Ksword5.1/UI/StructuredFieldView.h' -o $editorFieldMoc
    if ($LASTEXITCODE -ne 0) { throw 'Structured field moc generation failed.' }
    $editorSources = @('tools/code_editor_ui_tests.cpp',
        'Ksword5.1/Ksword5.1/UI/CodeEditorWidget.cpp',
        'Ksword5.1/Ksword5.1/UI/CodeTextEdit.cpp',
        'Ksword5.1/Ksword5.1/UI/CodeEditorFileSession.cpp',
        'Ksword5.1/Ksword5.1/UI/StructuredFieldView.cpp', 'Ksword5.1/Ksword5.1/UI/TypedSyntaxDocument.cpp',
        'Ksword5.1/Ksword5.1/UI/FlowLayout.cpp',
        'Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.cpp',
        'Ksword5.1/Ksword5.1/UI/ThemeControlGlyphs.cpp',
        'Ksword5.1/Ksword5.1/UI/ThemeStatusRole.cpp',
        'Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.cpp',
        'Ksword5.1/Ksword5.1/Internationalization/LanguageManager.cpp',
        $editorMocSource, $editorFieldMoc, $editorResourceSource)
    $editorReusable = @('FlowLayout', 'GlobalUiBaseStyle', 'ThemeControlGlyphs', 'ThemeStatusRole', 'SmoothScrollSupport', 'LanguageManager')
    $editorObjects = @()
    foreach ($editorSource in $editorSources) {
        $editorName = [IO.Path]::GetFileNameWithoutExtension($editorSource)
        $editorObject = Join-Path $editorOutput ($editorName + '.o')
        $editorDependencies = $editorObject + '.d'
        if (!$Rebuild -and !(Test-Path -LiteralPath $editorObject) -and $editorName -in $editorReusable) {
            $editorCachedObject = Join-Path $editorCache ($editorName + '.o')
            if (Test-EditorObjectFresh $editorCachedObject ($editorCachedObject + '.d')) {
                Copy-Item -LiteralPath $editorCachedObject -Destination $editorObject
                Copy-Item -LiteralPath ($editorCachedObject + '.d') -Destination $editorDependencies
            }
        }
        if ($Rebuild -or !(Test-EditorObjectFresh $editorObject $editorDependencies)) {
            Write-Output "Compiling $editorSource"
            & g++ @editorFlags -MMD -MF $editorDependencies -c $editorSource -o $editorObject
            if ($LASTEXITCODE -ne 0) { throw "Code editor fixture compilation failed: $editorSource" }
        }
        $editorObjects += $editorObject
    }
    @{ qtRoot = $editorQt; flags = $editorFlags; objects = $editorObjects } |
        ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $editorOutput 'link-manifest.json') -Encoding utf8
    $editorExe = Join-Path $editorOutput 'code-editor-tests.exe'
    & g++ @editorObjects '-Wl,--gc-sections' "-L$editorQt/lib" -lQt6Widgets -lQt6Gui -lQt6Core `
        -lQt6Test -lQt6Svg -luser32 -ladvapi32 -o $editorExe
    if ($LASTEXITCODE -ne 0) { throw 'Code editor fixture link failed.' }
    $editorLanguages = Join-Path $editorOutput 'languages'
    New-Item -ItemType Directory -Path $editorLanguages -Force | Out-Null
    foreach ($editorLanguage in @('zh-CN.json', 'en-US.json')) {
        Copy-Item -LiteralPath (Join-Path $editorRepository "Ksword5.1/Ksword5.1/languages/$editorLanguage") -Destination $editorLanguages -Force
    }
    & $editorExe (Join-Path $editorOutput 'shots') 2>&1 |
        Tee-Object -FilePath (Join-Path $editorOutput 'code-editor-tests.log')
    if ($LASTEXITCODE -ne 0) { throw "Code editor Qt regression failed (native exit $LASTEXITCODE)." }
}
finally {
    $env:PATH = $editorOldPath
    $env:QT_PLUGIN_PATH = $editorOldPlugins
    $env:QT_QPA_PLATFORM = $editorOldPlatform
    Pop-Location
}
