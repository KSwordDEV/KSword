# Isolated MinGW/Qt host regression; does not build the MSVC product or access a driver.
param(
    [string]$QtRoot = '.codex-tmp/qt-fixture/ucrt64',
    [string]$OutputDirectory = '.codex-tmp/file-snapshot-host-tests',
    [switch]$Rebuild
)
$ErrorActionPreference = 'Stop'
$fixtureRepository = Split-Path -Parent $PSScriptRoot
$fixtureOldPath = $env:PATH
$fixtureOldPlugins = $env:QT_PLUGIN_PATH
$fixtureOldPlatform = $env:QT_QPA_PLATFORM
$fixtureOldTemp = $env:TEMP
$fixtureOldTmp = $env:TMP
Push-Location $fixtureRepository
try {
    $fixtureQt = (Resolve-Path -LiteralPath $QtRoot).Path
    $fixtureOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
        [IO.Path]::GetFullPath($OutputDirectory)
    } else { [IO.Path]::GetFullPath((Join-Path $fixtureRepository $OutputDirectory)) }
    New-Item -ItemType Directory -Path $fixtureOutput -Force | Out-Null
    $fixtureRows = Join-Path $fixtureOutput 'row-objects'

    # This dependency-aware entry also verifies the underlying real row views.
    & (Join-Path $PSScriptRoot 'Invoke-MemoryRowViewsPortableTests.ps1') `
        -QtRoot $fixtureQt -OutputDirectory ([IO.Path]::GetRelativePath($fixtureRepository, $fixtureRows)) -Rebuild:$Rebuild

    $env:PATH = (Join-Path $fixtureQt 'bin') + ';' + $fixtureOldPath
    $env:QT_PLUGIN_PATH = Join-Path $fixtureQt 'share/qt6/plugins'
    $env:QT_QPA_PLATFORM = 'offscreen'
    $fixtureUi = 'Ksword5.1/Ksword5.1/UI/MemoryWorkbench'
    $fixtureApp = 'Ksword5.1/Ksword5.1/UI'
    $fixtureCore = 'shared/evidence/memory_workbench'
    $fixtureFlags = @('-std=c++20', '-O1', '-g0', '-ffunction-sections', '-fdata-sections',
        '-DNOMINMAX', '-DUNICODE', '-D_UNICODE', '-DZYDIS_STATIC_BUILD', '-DQT_CORE_LIB',
        '-DQT_GUI_LIB', '-DQT_WIDGETS_LIB', '-DQT_TESTLIB_LIB', '-I.', '-Ithird_party/zydis')
    foreach ($fixtureModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtTest', 'QtSvg')) {
        $fixtureFlags += @('-isystem', (Join-Path $fixtureQt "include/qt6/$fixtureModule"))
    }
    $fixtureSources = @('tools/memory_editor_ui_tests.cpp', "$fixtureApp/MemoryEditorWidget.cpp",
        "$fixtureApp/MemoryEditorWidget.InlineAssembly.cpp", "$fixtureApp/MemoryEditorWidget.Pseudocode.cpp",
        "$fixtureApp/Decompiler/GhidraDecompiler.cpp", 'GhidraRuntimePlugin/RuntimeProfile.cpp', "$fixtureApp/HexEditorWidget.cpp",
        "$fixtureApp/MemoryEditHistory.Core.cpp", "$fixtureApp/TableHeaderSortingSupport.cpp",
        'tools/tests/memory_editor_portable_stubs.cpp', "$fixtureApp/KernelDisassemblyDialog.cpp")
    foreach ($fixtureName in @('HexCanvas', 'HexCanvas.Scroll', 'HexCanvas.Layout', 'HexCanvas.Paint',
        'HexCanvas.Input', 'HexCanvas.Edit', 'HexCanvas.Menu', 'HexInspectorPanel',
        'HexInspectorPanel.Rows', 'HexInspectorPanel.Edit', 'HexInspectorPanel.Menu',
        'HexInspectorRowView', 'HexInspectorRowView.Paint', 'HexInspectorWidgets', 'HexView',
        'HexView.Toolbar', 'HexView.Compat', 'HexView.Panels', 'HexViewSettings', 'HexFindBar',
        'HexFindSearch', 'HexGotoBar', 'HexExport')) {
        $fixtureSources += "$fixtureUi/$fixtureName.cpp"
    }
    foreach ($fixtureName in @('HexViewport', 'HexViewport.Cache', 'HexViewport.Selection',
        'MemoryTargetSession', 'MemoryValueDecode', 'MemoryAddressExpr', 'MemoryByteSearch')) {
        $fixtureSources += "$fixtureCore/$fixtureName.cpp"
    }
    $fixtureMoc = Join-Path $fixtureQt 'share/qt6/bin/moc.exe'
    foreach ($fixtureHeader in @("$fixtureApp/MemoryEditorWidget.h", "$fixtureApp/HexEditorWidget.h",
        "$fixtureApp/KernelDisassemblyDialog.h", "$fixtureApp/Decompiler/GhidraDecompiler.h",
        "$fixtureUi/HexCanvas.h", "$fixtureUi/HexInspectorPanel.h",
        "$fixtureUi/HexInspectorRowView.h", "$fixtureUi/HexView.h", "$fixtureUi/HexFindBar.h", "$fixtureUi/HexGotoBar.h")) {
        $fixtureGenerated = Join-Path $fixtureOutput ('moc_' + [IO.Path]::GetFileNameWithoutExtension($fixtureHeader) + '.cpp')
        if ($Rebuild -or !(Test-Path -LiteralPath $fixtureGenerated) -or
            (Get-Item -LiteralPath $fixtureHeader).LastWriteTimeUtc -gt (Get-Item -LiteralPath $fixtureGenerated).LastWriteTimeUtc) {
            & $fixtureMoc $fixtureHeader -o $fixtureGenerated
            if ($LASTEXITCODE -ne 0) { throw "moc failed for $fixtureHeader" }
        }
        $fixtureSources += $fixtureGenerated
    }
    $fixtureObjects = @(Get-ChildItem -LiteralPath $fixtureRows -Filter '*.o'
        | Where-Object { $_.Name -ne 'memory_row_views_portable_tests.o' }
        | ForEach-Object { $_.FullName })
    foreach ($fixtureSource in $fixtureSources) {
        $fixtureObject = Join-Path $fixtureOutput ([IO.Path]::GetFileNameWithoutExtension($fixtureSource) + '.o')
        $fixtureDependencies = $fixtureObject + '.d'
        $fixtureCompile = $Rebuild -or !(Test-Path -LiteralPath $fixtureObject) -or !(Test-Path -LiteralPath $fixtureDependencies)
        if (!$fixtureCompile) {
            $fixtureModified = (Get-Item -LiteralPath $fixtureObject).LastWriteTimeUtc
            $fixtureDependencyText = (Get-Content -LiteralPath $fixtureDependencies -Raw) -replace '\\\r?\n', ' '
            $fixtureDependencyText = $fixtureDependencyText.Substring($fixtureDependencyText.IndexOf(': ') + 2)
            foreach ($fixtureDependency in ($fixtureDependencyText -split '\s+')) {
                if ($fixtureDependency -and (!(Test-Path -LiteralPath $fixtureDependency) -or
                    (Get-Item -LiteralPath $fixtureDependency).LastWriteTimeUtc -gt $fixtureModified)) {
                    $fixtureCompile = $true
                    break
                }
            }
        }
        if ($fixtureCompile) {
            Write-Output "Compiling $fixtureSource"
            & g++ @fixtureFlags -MMD -MF $fixtureDependencies -c $fixtureSource -o $fixtureObject
            if ($LASTEXITCODE -ne 0) { throw "Portable snapshot host compilation failed: $fixtureSource" }
        }
        $fixtureObjects += $fixtureObject
    }
    # The exact link inputs let the FileDock extraction fixture reuse these
    # production objects while replacing only this executable's test entry point.
    @{ qtRoot = $fixtureQt; flags = $fixtureFlags; objects = $fixtureObjects } |
        ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $fixtureOutput 'link-manifest.json') -Encoding utf8
    $fixtureExe = Join-Path $fixtureOutput 'host-tests.exe'
    & g++ @fixtureObjects '-Wl,--gc-sections' "-L$fixtureQt/lib" -lQt6Widgets -lQt6Gui -lQt6Core `
        -lQt6Test -lQt6Svg -luser32 -ladvapi32 -o $fixtureExe
    if ($LASTEXITCODE -ne 0) { throw 'Portable snapshot host link failed.' }
    # Keep all fake installations and adapter temporary projects inside the
    # explicitly writable test workspace, including sandboxed test runs.
    $fixtureTemporary = Join-Path $fixtureOutput 'temporary'
    New-Item -ItemType Directory -Path $fixtureTemporary -Force | Out-Null
    $env:TEMP = $fixtureTemporary
    $env:TMP = $fixtureTemporary
    # A tiny executable implements only the documented headless output protocol.
    # The tests still use the real QProcess backend, SHA checks and cancellation;
    # this fixture neither imports code into Ghidra nor executes target bytes.
    $fixtureLauncherSource = Join-Path $PSScriptRoot 'tests/ghidra_fake_launcher.cpp'
    $fixtureLauncher = Join-Path $fixtureOutput 'ghidra-fake-launcher.exe'
    if ($Rebuild -or !(Test-Path -LiteralPath $fixtureLauncher) -or
        (Get-Item -LiteralPath $fixtureLauncherSource).LastWriteTimeUtc -gt
        (Get-Item -LiteralPath $fixtureLauncher).LastWriteTimeUtc) {
        & g++ @fixtureFlags $fixtureLauncherSource "-L$fixtureQt/lib" -lQt6Core -o $fixtureLauncher
        if ($LASTEXITCODE -ne 0) { throw 'Portable headless protocol fixture compilation failed.' }
    }
    & $fixtureExe (Join-Path $fixtureOutput 'shots') $fixtureLauncher
    if ($LASTEXITCODE -ne 0) { throw "Portable snapshot host failed (native exit $LASTEXITCODE)." }
}
finally {
    $env:PATH = $fixtureOldPath
    $env:QT_PLUGIN_PATH = $fixtureOldPlugins
    $env:QT_QPA_PLATFORM = $fixtureOldPlatform
    $env:TEMP = $fixtureOldTemp
    $env:TMP = $fixtureOldTmp
    Pop-Location
}
