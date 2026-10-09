param(
    [string]$QtRoot = '.codex-tmp/qt-fixture/ucrt64',
    [string]$OutputDirectory = 'work/tab-wheel-tests',
    [string]$Compiler = 'g++',
    [string]$AdsStaticLibrary,
    [switch]$AdsOnly
)
$ErrorActionPreference = 'Stop'
if ($AdsOnly -and !$AdsStaticLibrary) { throw 'AdsOnly requires AdsStaticLibrary.' }
$tabRepository = Split-Path -Parent $PSScriptRoot
$tabOldPath = $env:PATH
$tabOldPlatform = $env:QT_QPA_PLATFORM
$tabOldPlugins = $env:QT_PLUGIN_PATH
Push-Location $tabRepository
try {
    $tabQt = (Resolve-Path -LiteralPath $QtRoot).Path
    $tabOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
        [IO.Path]::GetFullPath($OutputDirectory)
    } else { [IO.Path]::GetFullPath((Join-Path $tabRepository $OutputDirectory)) }
    New-Item -ItemType Directory -Path $tabOutput -Force | Out-Null
    $env:PATH = (Join-Path $tabQt 'bin') + ';' + $tabOldPath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $tabQt 'share/qt6/plugins'
    $tabFlags = @('-std=c++17', '-O1', '-g0', '-Wall', '-Wextra', '-Werror', '-DNOMINMAX', '-I.')
    foreach ($tabModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtTest')) {
        $tabFlags += @('-isystem', (Join-Path $tabQt "include/qt6/$tabModule"))
    }
    $tabExe = Join-Path $tabOutput 'tab-wheel-tests.exe'
    if (!$AdsOnly) {
        & $Compiler @tabFlags 'tools/tab_wheel_tests.cpp' 'Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.cpp' `
            "-L$tabQt/lib" -lQt6Widgets -lQt6Gui -lQt6Core -lQt6Test -o $tabExe
        if ($LASTEXITCODE -ne 0) { throw 'Tab wheel fixture compilation failed.' }
        # Also compile the production ADS adapter against its pinned public headers.
        & $Compiler @tabFlags -c 'Ksword5.1/Ksword5.1/UI/DockTabInteraction.cpp' -o (Join-Path $tabOutput 'DockTabInteraction.o')
        if ($LASTEXITCODE -ne 0) { throw 'Dock tab adapter compilation failed.' }
        & $tabExe 2>&1 | Tee-Object -FilePath (Join-Path $tabOutput 'tab-wheel-tests.log')
        if ($LASTEXITCODE -ne 0) { throw 'Tab wheel behavioral regression failed.' }
    }
    if ($AdsStaticLibrary) {
        $tabAds = (Resolve-Path -LiteralPath $AdsStaticLibrary).Path
        $tabDockExe = Join-Path $tabOutput 'dock-tab-wheel-tests.exe'
        $tabObjects = @()
        foreach ($tabSource in @('tools/dock_tab_wheel_tests.cpp', 'Ksword5.1/Ksword5.1/UI/DockTabInteraction.cpp',
            'Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.cpp', 'Ksword5.1/Ksword5.1/Internationalization/LanguageManager.cpp')) {
            $tabObject = Join-Path $tabOutput (([IO.Path]::GetFileNameWithoutExtension($tabSource)) + '.ads.o')
            & $Compiler @tabFlags -DADS_STATIC -ffunction-sections -fdata-sections -c $tabSource -o $tabObject
            if ($LASTEXITCODE -ne 0) { throw "Actual ADS fixture compilation failed: $tabSource" }
            $tabObjects += $tabObject
        }
        & $Compiler @tabObjects $tabAds `
            '-Wl,--gc-sections' "-L$tabQt/lib" -lQt6Widgets -lQt6Gui -lQt6Core -lQt6Test -luser32 -ladvapi32 -o $tabDockExe
        if ($LASTEXITCODE -ne 0) { throw 'Actual ADS fixture compilation failed.' }
        & $tabDockExe 2>&1 | Tee-Object -FilePath (Join-Path $tabOutput 'dock-tab-wheel-tests.log')
        if ($LASTEXITCODE -ne 0) { throw 'Actual ADS behavioral regression failed.' }
    }
}
finally {
    $env:PATH = $tabOldPath
    $env:QT_QPA_PLATFORM = $tabOldPlatform
    $env:QT_PLUGIN_PATH = $tabOldPlugins
    Pop-Location
}
