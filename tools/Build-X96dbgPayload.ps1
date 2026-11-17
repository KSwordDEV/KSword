[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$ReferenceRoot,
    [string]$Qt5Root,
    [switch]$PrepareDependencies,
    [switch]$BuildTests
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
if (-not $ReferenceRoot) { $ReferenceRoot = Join-Path $RepositoryRoot '.deps\x64dbg-reference' }
if (-not $Qt5Root) { $Qt5Root = Join-Path $RepositoryRoot '.deps\Qt5-x64dbg' }
$pins = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'X96dbgIntegration\PINNED_BASELINES.json') -Raw | ConvertFrom-Json

function Assert-WorkspacePath([string]$Path) {
    $absolute = [IO.Path]::GetFullPath($Path)
    if (-not $absolute.StartsWith($RepositoryRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Build/dependency directory must be inside the repository: $absolute"
    }
    return $absolute
}
$ReferenceRoot = Assert-WorkspacePath $ReferenceRoot
$Qt5Root = Assert-WorkspacePath $Qt5Root
$buildRoot = Join-Path $ReferenceRoot 'build-x64'
$msbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
$cmake = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
if (-not (Test-Path -LiteralPath $msbuild)) { $msbuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe' }
if (-not (Test-Path -LiteralPath $cmake)) {
    $cmakeCommand = Get-Command cmake.exe -ErrorAction SilentlyContinue
    if ($cmakeCommand) { $cmake = $cmakeCommand.Source }
}
if (-not (Test-Path -LiteralPath $msbuild)) { throw '64-bit MSBuild is required.' }
if (-not (Test-Path -LiteralPath $cmake)) { throw 'CMake was not found in the configured Visual Studio installation or PATH.' }

function Invoke-Checked([string]$Executable, [string[]]$Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable exited with code $LASTEXITCODE" }
}

if ($PrepareDependencies) {
    if (-not (Test-Path -LiteralPath (Join-Path $ReferenceRoot '.git'))) {
        Invoke-Checked git @('init', $ReferenceRoot)
        Invoke-Checked git @('-C', $ReferenceRoot, 'remote', 'add', 'origin', 'https://github.com/x64dbg/x64dbg.git')
        Invoke-Checked git @('-C', $ReferenceRoot, 'fetch', '--depth=1', 'origin', $pins.x64dbg)
        Invoke-Checked git @('-C', $ReferenceRoot, 'checkout', '--detach', 'FETCH_HEAD')
    }
    Invoke-Checked git @('-C', $ReferenceRoot, 'submodule', 'update', '--init', '--recursive', '--depth=1')
    if (-not (Test-Path -LiteralPath (Join-Path $Qt5Root 'lib\cmake\Qt5\Qt5Config.cmake'))) {
        $archive = Join-Path $RepositoryRoot '.deps\qt5.12.12-msvc2017_64.7z'
        if (-not (Test-Path -LiteralPath $archive)) {
            Invoke-WebRequest -Uri $pins.qt5Url -OutFile $archive
        }
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $pins.qt5Sha256) {
            throw 'Qt5 dependency archive SHA256 mismatch.'
        }
        $tar = Get-Command tar.exe -ErrorAction SilentlyContinue
        if (-not $tar) { throw 'tar.exe is required to extract the verified Qt5 SDK.' }
        New-Item -ItemType Directory -Path $Qt5Root -Force | Out-Null
        Invoke-Checked $tar.Source @('-xf', $archive, '-C', $Qt5Root)
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $ReferenceRoot '.git'))) { throw 'Pinned x64dbg source is missing; use -PrepareDependencies.' }
$actualHead = & git -C $ReferenceRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $actualHead -ne $pins.x64dbg) { throw "Expected x64dbg source $($pins.x64dbg), found $actualHead" }
$nativeHead = & git -C (Join-Path $ReferenceRoot 'src\third_party\TitanEngine') rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $nativeHead -ne $pins.nativeTitanEngine) { throw 'Native TitanEngine submodule does not match the canonical ABI baseline.' }
$replayHead = & git -C (Join-Path $ReferenceRoot 'src\third_party\DbgEng') rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $replayHead -ne $pins.dbgEng) { throw 'DbgEng replay provider does not match the pinned PR baseline.' }
$depsHead = & git -C (Join-Path $ReferenceRoot 'deps') rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $depsHead -ne $pins.deps) { throw 'Runtime dependencies do not match the pinned PR baseline.' }
if (-not (Test-Path -LiteralPath (Join-Path $Qt5Root 'lib\cmake\Qt5\Qt5Config.cmake'))) { throw 'Verified x64 Qt5 SDK is missing; use -PrepareDependencies.' }

$patch = Join-Path $RepositoryRoot 'X96dbgIntegration\patches\x64dbg-ksword-engine.patch'
# Upstream marks C++ sources -text (CRLF), while our distributable patch is LF.
# Ignore context whitespace so checkout line endings do not change applicability.
& git -C $ReferenceRoot apply --ignore-whitespace --reverse --check $patch 2>$null
if ($LASTEXITCODE -ne 0) {
    Invoke-Checked git @('-C', $ReferenceRoot, 'apply', '--ignore-whitespace', '--check', $patch)
    Invoke-Checked git @('-C', $ReferenceRoot, 'apply', '--ignore-whitespace', $patch)
}
$extensionHeader = Join-Path $ReferenceRoot 'src\bridge\ksword_engine.h'
$extensionText = [IO.File]::ReadAllText($extensionHeader).Replace("`r`n", "`n")
$canonicalText = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'DebuggerBackend\KswordDebuggerApi.h')).Replace("`r`n", "`n")
if ($extensionText -cne $canonicalText) {
    throw 'The frontend optional KSword extension differs from the canonical in-process API header.'
}

# These environment values also cover CMake's compiler-identification probes.
# The build itself supplies all three architecture properties explicitly.
$savedArchitecture = $env:PROCESSOR_ARCHITECTURE
$savedArchitectureW6432 = $env:PROCESSOR_ARCHITEW6432
try {
    $env:PROCESSOR_ARCHITECTURE = 'AMD64'
    $env:PROCESSOR_ARCHITEW6432 = 'AMD64'
    Invoke-Checked $cmake @('-S', $ReferenceRoot, '-B', $buildRoot, '-G', 'Visual Studio 17 2022', '-A', 'x64',
        '-T', 'v143,host=x64', '-DCMKR_SKIP_GENERATION=ON', "-DCMAKE_MAKE_PROGRAM=$msbuild",
        "-DCMAKE_PREFIX_PATH=$Qt5Root", '-DCMAKE_UNITY_BUILD=ON', '-DCMAKE_UNITY_BUILD_BATCH_SIZE=6', '-DX64DBG_RELEASE=OFF')
    $architectureProperties = @('/p:PreferredToolArchitecture=x64', '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64')
    $compilerPaths = & $msbuild (Join-Path $buildRoot 'bridge.vcxproj') /p:Configuration=Release /p:Platform=x64 @architectureProperties -getProperty:VC_ExecutablePath_x64
    if ($LASTEXITCODE -ne 0 -or ($compilerPaths | Out-String) -notmatch '(?i)HostX64[\\/]x64') { throw 'MSVC did not resolve to HostX64/x64.' }
    $projects = @('exe.vcxproj', 'headless.vcxproj')
    if ($BuildTests) { $projects += 'src\tests\x64dbg_tests.vcxproj' }
    foreach ($project in $projects) {
        Invoke-Checked $msbuild (@((Join-Path $buildRoot $project), '/t:Build', '/p:Configuration=Release', '/p:Platform=x64') + $architectureProperties + @('/m:1', '/v:minimal'))
    }
} finally {
    $env:PROCESSOR_ARCHITECTURE = $savedArchitecture
    $env:PROCESSOR_ARCHITEW6432 = $savedArchitectureW6432
}
$outputRoot = Join-Path $ReferenceRoot 'bin\x64'
foreach ($filename in @('x64dbg.exe', 'x64bridge.dll', 'x64dbg.dll', 'x64gui.dll', 'TitanEngine.dll', 'headless.exe',
    'DbgEng\TitanEngine.dll', 'DbgEng\dbgeng.dll', 'DbgEng\dbgcore.dll', 'DbgEng\dbgmodel.dll',
    'DbgEng\TTDReplay.dll', 'DbgEng\TTDReplayCPU.dll')) {
    $artifact = Join-Path $outputRoot $filename
    if (-not (Test-Path -LiteralPath $artifact) -or (Get-Item -LiteralPath $artifact).Length -eq 0) { throw "Missing x64dbg artifact: $artifact" }
}
& (Join-Path $PSScriptRoot 'Build-X64DbgNavigation.ps1') -Platform x64 -Configuration Release
if ($LASTEXITCODE -ne 0) { throw 'Navigation bridge build failed.' }
$navigationBridge = Join-Path $RepositoryRoot '.deps\x64dbg-navigation\x64\Release\KSwordNavigation.dp64'
New-Item -ItemType Directory -Path (Join-Path $outputRoot 'plugins') -Force | Out-Null
Copy-Item -LiteralPath $navigationBridge -Destination (Join-Path $outputRoot 'plugins\KSwordNavigation.dp64') -Force
& (Join-Path $PSScriptRoot 'Build-X64DbgNavigation.ps1') -Platform x64 -Configuration Release -Component NoAttach
if ($LASTEXITCODE -ne 0) { throw 'No-attach control bridge build failed.' }
$noAttachBridge = Join-Path $RepositoryRoot '.deps\x64dbg-noattach\x64\Release\KSwordNoAttach.dp64'
Copy-Item -LiteralPath $noAttachBridge -Destination (Join-Path $outputRoot 'plugins\KSwordNoAttach.dp64') -Force
Write-Output "X64DBG_PAYLOAD=$outputRoot"
