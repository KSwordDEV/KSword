# Build and run the production property view with isolated Qt offscreen tests.
# This does not build the MSVC product, query file metadata or access a driver.
param(
    [string]$QtRoot = '.codex-tmp/qt-fixture/ucrt64',
    [string]$OutputDirectory = 'work/file-property-view-ui-tests',
    [string]$Compiler = 'g++'
)
$ErrorActionPreference = 'Stop'
$propertyRepository = Split-Path -Parent $PSScriptRoot
$propertyOldPath = $env:PATH
$propertyOldPlugins = $env:QT_PLUGIN_PATH
$propertyOldPlatform = $env:QT_QPA_PLATFORM
Push-Location $propertyRepository
try {
    $propertyQt = (Resolve-Path -LiteralPath $QtRoot).Path
    $propertyOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
        [IO.Path]::GetFullPath($OutputDirectory)
    } else { [IO.Path]::GetFullPath((Join-Path $propertyRepository $OutputDirectory)) }
    New-Item -ItemType Directory -Path $propertyOutput -Force | Out-Null
    $env:PATH = (Join-Path $propertyQt 'bin') + ';' + $propertyOldPath
    $env:QT_PLUGIN_PATH = Join-Path $propertyQt 'share/qt6/plugins'
    $env:QT_QPA_PLATFORM = 'offscreen'
    $propertyFlags = @('-std=c++20', '-O1', '-g0', '-ffunction-sections', '-fdata-sections',
        '-DNOMINMAX', '-DUNICODE', '-D_UNICODE', '-DQT_CORE_LIB', '-DQT_GUI_LIB',
        '-DQT_WIDGETS_LIB', '-DQT_TESTLIB_LIB', '-I.')
    foreach ($propertyModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtTest')) {
        $propertyFlags += @('-isystem', (Join-Path $propertyQt "include/qt6/$propertyModule"))
    }
    $propertyObjects = @()
    foreach ($propertySource in @('tools/file_property_view_ui_tests.cpp',
        'Ksword5.1/Ksword5.1/FileDock/FilePropertyView.cpp',
        'Ksword5.1/Ksword5.1/Internationalization/LanguageManager.cpp')) {
        $propertyObject = Join-Path $propertyOutput (([IO.Path]::GetFileNameWithoutExtension($propertySource)) + '.o')
        Write-Output "Compiling $propertySource"
        & $Compiler @propertyFlags -c $propertySource -o $propertyObject
        if ($LASTEXITCODE -ne 0) { throw "Property fixture compilation failed: $propertySource" }
        $propertyObjects += $propertyObject
    }
    $propertyLanguages = Join-Path $propertyOutput 'languages'
    New-Item -ItemType Directory -Path $propertyLanguages -Force | Out-Null
    foreach ($propertyLanguage in @('zh-CN.json', 'en-US.json')) {
        Copy-Item -LiteralPath (Join-Path $propertyRepository "Ksword5.1/Ksword5.1/languages/$propertyLanguage") -Destination $propertyLanguages -Force
    }
    $propertyExe = Join-Path $propertyOutput 'file-property-view-tests.exe'
    & $Compiler @propertyObjects '-Wl,--gc-sections' "-L$propertyQt/lib" -lQt6Widgets -lQt6Gui -lQt6Core -lQt6Test -o $propertyExe
    if ($LASTEXITCODE -ne 0) { throw 'Property fixture link failed.' }
    & $propertyExe (Join-Path $propertyOutput 'shots') 2>&1 |
        Tee-Object -FilePath (Join-Path $propertyOutput 'file-property-view-tests.log')
    if ($LASTEXITCODE -ne 0) { throw "Property Qt regression failed (native exit $LASTEXITCODE)." }
}
finally {
    $env:PATH = $propertyOldPath
    $env:QT_PLUGIN_PATH = $propertyOldPlugins
    $env:QT_QPA_PLATFORM = $propertyOldPlatform
    Pop-Location
}
