# Production ScannerDock + shared editor, synthetic PE only. Reuse the exact
# editor objects already built and checked from the same calling source tree.
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$LinkManifest = 'work/scanner-analysis-editor-tests/link-manifest.json',
    [string]$OutputDirectory = 'work/scanner-visual-tests'
)
$ErrorActionPreference = 'Stop'
$scannerOldPath = $env:PATH
$scannerOldPlugins = $env:QT_PLUGIN_PATH
$scannerOldPlatform = $env:QT_QPA_PLATFORM
Push-Location $RepositoryRoot
try {
    $scannerRepository = (Get-Location).Path
    $scannerManifest = Get-Content -LiteralPath $LinkManifest -Raw | ConvertFrom-Json
    $scannerQt = $scannerManifest.qtRoot
    $scannerFlags = @($scannerManifest.flags)
    $scannerOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
        [IO.Path]::GetFullPath($OutputDirectory)
    } else { [IO.Path]::GetFullPath((Join-Path $scannerRepository $OutputDirectory)) }
    New-Item -ItemType Directory -Path $scannerOutput -Force | Out-Null
    # The production UI fixture deliberately creates its synthetic files under
    # this repository-owned path regardless of the selected screenshot folder.
    New-Item -ItemType Directory -Path (Join-Path $scannerRepository 'work/scanner-visual-tests') -Force | Out-Null
    $env:PATH = (Join-Path $scannerQt 'bin') + ';' + $scannerOldPath
    $env:QT_PLUGIN_PATH = Join-Path $scannerQt 'share/qt6/plugins'
    $env:QT_QPA_PLATFORM = 'offscreen'
    $scannerApp = 'Ksword5.1/Ksword5.1'
    $scannerFlags += "-I$scannerApp"
    $scannerSources = @('tools/scanner_tests/scanner_visual_ui_tests.cpp',
        "$scannerApp/ScannerDock/ScannerDock.cpp", "$scannerApp/ScannerDock/ScannerDock.Table.cpp",
        "$scannerApp/ScannerDock/ScannerDock.Analysis.cpp", "$scannerApp/UI/BinaryOverviewBar.cpp",
        "$scannerApp/ksword/scanner/binary_scanner.cpp", "$scannerApp/ksword/scanner/atomic_file_patch.cpp",
        "$scannerApp/ksword/scanner/attack_path_detector.cpp", "$scannerApp/ksword/scanner/elf_scanner.cpp",
        "$scannerApp/ksword/scanner/iso9660_scanner.cpp", "$scannerApp/ksword/scanner/macho_scanner.cpp",
        "$scannerApp/ksword/file/pe_analyzer.cpp", "$scannerApp/ksword/string/string.cpp")
    $scannerObjects = @($scannerManifest.objects | Where-Object {
        [IO.Path]::GetFileName($_) -ne 'memory_editor_ui_tests.o'
    })
    foreach ($scannerSource in $scannerSources) {
        $scannerObject = Join-Path $scannerOutput ([IO.Path]::GetFileNameWithoutExtension($scannerSource) + '.o')
        $scannerDependencies = $scannerObject + '.d'
        $scannerCompile = !(Test-Path -LiteralPath $scannerObject) -or !(Test-Path -LiteralPath $scannerDependencies)
        if (!$scannerCompile) {
            $scannerModified = (Get-Item -LiteralPath $scannerObject).LastWriteTimeUtc
            $scannerDependencyText = (Get-Content -LiteralPath $scannerDependencies -Raw) -replace '\\\r?\n', ' '
            $scannerDependencyText = $scannerDependencyText.Substring($scannerDependencyText.IndexOf(': ') + 2)
            foreach ($scannerDependency in ($scannerDependencyText -split '\s+')) {
                if ($scannerDependency -and (!(Test-Path -LiteralPath $scannerDependency) -or
                    (Get-Item -LiteralPath $scannerDependency).LastWriteTimeUtc -gt $scannerModified)) {
                    $scannerCompile = $true
                    break
                }
            }
        }
        if ($scannerCompile) {
            Write-Output "Compiling $scannerSource"
            & g++ @scannerFlags -MMD -MF $scannerDependencies -c $scannerSource -o $scannerObject
            if ($LASTEXITCODE -ne 0) { throw "Scanner portable compilation failed: $scannerSource" }
        }
        $scannerObjects += $scannerObject
    }
    $scannerExecutable = Join-Path $scannerOutput 'scanner-visual-tests.exe'
    & g++ @scannerObjects '-Wl,--gc-sections' "-L$scannerQt/lib" -lQt6Widgets -lQt6Gui -lQt6Core `
        -lQt6Test -lQt6Svg -luser32 -ladvapi32 -lshlwapi -o $scannerExecutable
    if ($LASTEXITCODE -ne 0) { throw 'Scanner portable link failed.' }
    foreach ($scannerTheme in @('light', 'dark')) {
        & $scannerExecutable (Join-Path $scannerOutput "scanner-$scannerTheme.png") $scannerTheme
        if ($LASTEXITCODE -ne 0) { throw "Scanner $scannerTheme checks failed ($LASTEXITCODE)." }
    }
    $scannerLayout = Join-Path $scannerOutput 'binary-layout-tests.exe'
    & g++ -std=c++20 -O1 -g0 -DNOMINMAX tools/scanner_tests/binary_layout_self_test.cpp -o $scannerLayout
    if ($LASTEXITCODE -ne 0) { throw 'Binary layout helper compilation failed.' }
    & $scannerLayout
    if ($LASTEXITCODE -ne 0) { throw 'Binary layout helper checks failed.' }
}
finally {
    Pop-Location
    $env:PATH = $scannerOldPath
    $env:QT_PLUGIN_PATH = $scannerOldPlugins
    $env:QT_QPA_PLATFORM = $scannerOldPlatform
}
