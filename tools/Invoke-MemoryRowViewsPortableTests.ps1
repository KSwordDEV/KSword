param(
    [string]$QtRoot = '.codex-tmp/qt-fixture/ucrt64',
    [string]$OutputDirectory = '.codex-tmp/memory-row-portable',
    [switch]$Rebuild
)
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
Push-Location $repository
try {
    $qt = (Resolve-Path -LiteralPath $QtRoot).Path
    $env:PATH = (Join-Path $qt 'bin') + ';' + $env:PATH
    $output = [IO.Path]::GetFullPath((Join-Path $repository $OutputDirectory))
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $output 'shots') -Force | Out-Null
    $appSource = 'Ksword5.1/Ksword5.1'
    $uiSource = "$appSource/UI/MemoryWorkbench"
    $coreSource = 'shared/evidence/memory_workbench'
    $moc = Join-Path $qt 'share/qt6/bin/moc.exe'
    $mocSources = @()
    foreach ($header in @("$uiSource/MemoryRowCanvas.h", "$uiSource/WorkbenchDisasmView.h", "$uiSource/WorkbenchTextView.h", "$uiSource/HexViewWidgets.h")) {
        $generated = Join-Path $output ('moc_' + [IO.Path]::GetFileNameWithoutExtension($header) + '.cpp')
        if (!(Test-Path -LiteralPath $generated) -or (Get-Item -LiteralPath $header).LastWriteTimeUtc -gt (Get-Item -LiteralPath $generated).LastWriteTimeUtc) {
            & $moc $header -o $generated
            if ($LASTEXITCODE -ne 0) { throw "moc failed for $header" }
        }
        $mocSources += $generated
    }
    if (!(Test-Path -LiteralPath (Join-Path $output 'Zydis.o'))) {
        & gcc -DZYDIS_STATIC_BUILD -O1 -Ithird_party/zydis -c third_party/zydis/Zydis.c -o (Join-Path $output 'Zydis.o')
        if ($LASTEXITCODE -ne 0) { throw 'Zydis build failed.' }
    }
    $includeArgs = @('-isystem', "$qt/include/qt6", '-isystem', "$qt/include/qt6/QtCore", '-isystem', "$qt/include/qt6/QtGui", '-isystem', "$qt/include/qt6/QtWidgets", '-isystem', "$qt/include/qt6/QtTest", '-isystem', "$qt/include/qt6/QtSvg", '-Ithird_party/zydis')
    $sources = @(
        'tools/memory_row_views_portable_tests.cpp',
        "$uiSource/MemoryRowCanvas.cpp", "$uiSource/WorkbenchDisasmView.cpp", "$uiSource/WorkbenchDisasmView.Canvas.cpp", "$uiSource/WorkbenchDisasmView.Edit.cpp", "$uiSource/WorkbenchTextView.cpp",
        "$uiSource/HexCanvasFormat.cpp", "$uiSource/HexViewFormat.cpp", "$uiSource/HexViewWidgets.cpp", "$uiSource/HexViewWidgets.Text.cpp",
        "$appSource/UI/FlowLayout.cpp", "$appSource/UI/CodeTextEdit.cpp", "$appSource/UI/ThemeStatusRole.cpp", "$appSource/UI/GlobalUiBaseStyle.cpp", "$appSource/UI/ThemeControlGlyphs.cpp", "$appSource/UI/SmoothScrollSupport.cpp",
        "$appSource/UI/MemorySnapshotBytesProvider.cpp",
        "$appSource/Internationalization/LanguageManager.cpp", "$appSource/UI/MemoryAssembly.cpp", "$appSource/UI/MemoryAssembly.Core.cpp",
        "$coreSource/MemoryTextDecode.cpp", "$coreSource/MemoryDiffOverlay.cpp", "$coreSource/MemoryDiffOverlay.Patches.cpp"
    ) + $mocSources
    $objects = @()
    foreach ($source in $sources) {
        $object = Join-Path $output ([IO.Path]::GetFileNameWithoutExtension($source) + '.o')
        $dependencyFile = $object + '.d'
        $needsCompile = $Rebuild -or !(Test-Path -LiteralPath $object) -or !(Test-Path -LiteralPath $dependencyFile)
        if (!$needsCompile) {
            $modified = (Get-Item -LiteralPath $object).LastWriteTimeUtc
            $dependencyText = (Get-Content -LiteralPath $dependencyFile -Raw) -replace '\\\r?\n', ' '
            $dependencyText = $dependencyText.Substring($dependencyText.IndexOf(': ') + 2)
            foreach ($dependency in ($dependencyText -split '\s+')) {
                if ($dependency -and (!(Test-Path -LiteralPath $dependency) -or (Get-Item -LiteralPath $dependency).LastWriteTimeUtc -gt $modified)) { $needsCompile = $true; break }
            }
        }
        if ($needsCompile) {
            Write-Output "Compiling $source"
            & g++ -std=c++20 -O1 -g0 -DUNICODE -D_UNICODE -DNOMINMAX -DZYDIS_STATIC_BUILD -DQT_CORE_LIB -DQT_GUI_LIB -DQT_WIDGETS_LIB -DQT_TESTLIB_LIB @includeArgs -MMD -MF $dependencyFile -c $source -o $object
            if ($LASTEXITCODE -ne 0) { throw "Portable Qt fixture compilation failed: $source" }
        }
        $objects += $object
    }
    & g++ @objects (Join-Path $output 'Zydis.o') "-L$qt/lib" -lQt6Widgets -lQt6Gui -lQt6Core -lQt6Test -lQt6Svg -luser32 -ladvapi32 -o (Join-Path $output 'memory-row-views-tests.exe')
    if ($LASTEXITCODE -ne 0) { throw 'Portable Qt fixture build failed.' }
    $env:PATH = (Join-Path $qt 'bin') + ';' + $env:PATH
    $env:QT_PLUGIN_PATH = Join-Path $qt 'share/qt6/plugins'
    $env:QT_QPA_PLATFORM = 'offscreen'
    & (Join-Path $output 'memory-row-views-tests.exe') (Join-Path $output 'shots')
    if ($LASTEXITCODE -ne 0) { throw "Portable Qt fixture failed (native exit $LASTEXITCODE)." }
}
finally { Pop-Location }
