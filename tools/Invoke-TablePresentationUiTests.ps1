# Build actual shared table chrome with Qt offscreen. No product/driver/clipboard access.
param(
    [string]$QtRoot = '.codex-tmp/qt-fixture/ucrt64',
    [string]$OutputDirectory = 'work/table-presentation-ui-tests',
    [string]$Compiler = 'g++'
)
$ErrorActionPreference = 'Stop'
$tableRepository = Split-Path -Parent $PSScriptRoot
$tableOldPath = $env:PATH
$tableOldPlugins = $env:QT_PLUGIN_PATH
$tableOldPlatform = $env:QT_QPA_PLATFORM
Push-Location $tableRepository
try {
    $tableQt = (Resolve-Path -LiteralPath $QtRoot).Path
    $tableOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
        [IO.Path]::GetFullPath($OutputDirectory)
    } else { [IO.Path]::GetFullPath((Join-Path $tableRepository $OutputDirectory)) }
    New-Item -ItemType Directory -Path $tableOutput -Force | Out-Null
    $env:PATH = (Join-Path $tableQt 'bin') + ';' + $tableOldPath
    $env:QT_PLUGIN_PATH = Join-Path $tableQt 'share/qt6/plugins'
    $env:QT_QPA_PLATFORM = 'offscreen'
    $tableFlags = @('-std=c++20', '-O1', '-g0', '-ffunction-sections', '-fdata-sections',
        '-DNOMINMAX', '-DUNICODE', '-D_UNICODE', '-DQT_CORE_LIB', '-DQT_GUI_LIB',
        '-DQT_WIDGETS_LIB', '-I.')
    foreach ($tableModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg')) {
        $tableFlags += @('-isystem', (Join-Path $tableQt "include/qt6/$tableModule"))
    }
    $tableObjects = @()
    foreach ($tableSource in @('tools/table_presentation_ui_tests.cpp',
        'Ksword5.1/Ksword5.1/UI/TablePresentation.cpp',
        'Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.cpp', 'Ksword5.1/Ksword5.1/UI/FlatButtonTheme.cpp', 'Ksword5.1/Ksword5.1/UI/ThemeBinding.cpp',
        'Ksword5.1/Ksword5.1/UI/ThemeControlGlyphs.cpp',
        'Ksword5.1/Ksword5.1/UI/ThemeStatusRole.cpp')) {
        $tableObject = Join-Path $tableOutput (([IO.Path]::GetFileNameWithoutExtension($tableSource)) + '.o')
        $tableWarnings = if ($tableSource.EndsWith('/TablePresentation.cpp')) { @('-Wall', '-Wextra', '-Werror') } else { @() }
        Write-Output "Compiling $tableSource"
        & $Compiler @tableFlags @tableWarnings -c $tableSource -o $tableObject
        if ($LASTEXITCODE -ne 0) { throw "Table presentation compilation failed: $tableSource" }
        $tableObjects += $tableObject
    }
    $tableExe = Join-Path $tableOutput 'table-presentation-ui-tests.exe'
    & $Compiler @tableObjects '-Wl,--gc-sections' "-L$tableQt/lib" -lQt6Widgets -lQt6Gui -lQt6Core -lQt6Svg -luser32 -ladvapi32 -o $tableExe
    if ($LASTEXITCODE -ne 0) { throw 'Table presentation fixture link failed.' }
    & $tableExe (Join-Path $tableOutput 'shots') 2>&1 |
        Tee-Object -FilePath (Join-Path $tableOutput 'table-presentation-ui-tests.log')
    if ($LASTEXITCODE -ne 0) { throw "Table presentation Qt regression failed (native exit $LASTEXITCODE)." }
}
finally {
    $env:PATH = $tableOldPath
    $env:QT_PLUGIN_PATH = $tableOldPlugins
    $env:QT_QPA_PLATFORM = $tableOldPlatform
    Pop-Location
}
