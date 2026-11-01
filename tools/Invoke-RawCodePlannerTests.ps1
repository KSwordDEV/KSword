param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputDirectory = '.codex-tmp/raw-code-planner-tests'
)

$ErrorActionPreference = 'Stop'
$rawRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$rawOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
    [IO.Path]::GetFullPath($OutputDirectory)
} else {
    [IO.Path]::GetFullPath((Join-Path $rawRepository $OutputDirectory))
}

# Use the same approved installations as the main build, with an explicit
# Hostx64/x64 compiler and linker. This regression has no Qt dependency.
$rawVc = $null
foreach ($rawVcBase in @(
    'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC',
    'D:/Software/VS/VC/Tools/MSVC'
)) {
    if (!(Test-Path -LiteralPath $rawVcBase)) { continue }
    foreach ($rawCandidate in (Get-ChildItem -LiteralPath $rawVcBase -Directory |
        Where-Object Name -Match '^\d+\.\d+\.\d+$' |
        Sort-Object { [version]$_.Name } -Descending)) {
        $rawCandidateBin = Join-Path $rawCandidate.FullName 'bin/Hostx64/x64'
        if ((Test-Path -LiteralPath (Join-Path $rawCandidateBin 'cl.exe')) -and
            (Test-Path -LiteralPath (Join-Path $rawCandidateBin 'link.exe'))) {
            $rawVc = $rawCandidate.FullName
            break
        }
    }
    if ($rawVc) { break }
}
if (!$rawVc) { throw 'An approved Hostx64/x64 MSVC installation is required.' }

$rawSdk = 'C:/Program Files (x86)/Windows Kits/10'
$rawSdkVersion = $null
foreach ($rawCandidate in (Get-ChildItem -LiteralPath (Join-Path $rawSdk 'Include') -Directory |
    Where-Object Name -Match '^10\.0\.\d+\.\d+$' |
    Sort-Object { [version]$_.Name } -Descending)) {
    $rawVersion = $rawCandidate.Name
    if ((Test-Path -LiteralPath (Join-Path $rawCandidate.FullName 'um/Windows.h')) -and
        (Test-Path -LiteralPath (Join-Path $rawCandidate.FullName 'ucrt/stdlib.h')) -and
        (Test-Path -LiteralPath (Join-Path $rawSdk "Lib/$rawVersion/ucrt/x64/ucrt.lib")) -and
        (Test-Path -LiteralPath (Join-Path $rawSdk "Lib/$rawVersion/um/x64/kernel32.lib"))) {
        $rawSdkVersion = $rawVersion
        break
    }
}
if (!$rawSdkVersion) { throw 'Matching Windows SDK headers and x64 libraries are required.' }

$rawCore = Join-Path $rawRepository 'Ksword5.1/Ksword5.1/UI/Decompiler/RawCodePlanner.cpp'
$rawTests = Join-Path $rawRepository 'tools/raw_code_planner_tests.cpp'
$rawZydis = Join-Path $rawRepository 'third_party/zydis'
$rawZydisLibrary = Join-Path $rawZydis 'x64/Release/KswordZydis.lib'
foreach ($rawRequired in @($rawCore, $rawTests, (Join-Path $rawZydis 'Zydis.h'), $rawZydisLibrary)) {
    if (!(Test-Path -LiteralPath $rawRequired)) { throw "Required planner test input is missing: $rawRequired" }
}

New-Item -ItemType Directory -Path $rawOutput -Force | Out-Null
$rawExe = Join-Path $rawOutput 'raw_code_planner_tests.exe'
$rawToolBin = Join-Path $rawVc 'bin/Hostx64/x64'
$rawArguments = @('/nologo', '/std:c++20', '/Zc:__cplusplus', '/permissive-', '/utf-8', '/EHsc', '/MD',
    '/W4', '/WX', '/external:W0', '/DZYDIS_STATIC_BUILD', '/DZYCORE_STATIC_BUILD',
    ('/I' + $rawZydis), ('/external:I' + (Join-Path $rawVc 'include')))
foreach ($rawPart in @('ucrt', 'shared', 'um')) {
    $rawArguments += '/external:I' + (Join-Path $rawSdk "Include/$rawSdkVersion/$rawPart")
}
$rawArguments += @($rawTests, $rawCore, ('/Fo' + $rawOutput + '\'), ('/Fe' + $rawExe),
    '/link', '/INCREMENTAL:NO', '/SUBSYSTEM:CONSOLE', ('/LIBPATH:' + (Join-Path $rawVc 'lib/x64')))
foreach ($rawPart in @('ucrt', 'um')) {
    $rawArguments += '/LIBPATH:' + (Join-Path $rawSdk "Lib/$rawSdkVersion/$rawPart/x64")
}
$rawArguments += $rawZydisLibrary

$rawOldPath = $env:PATH
Push-Location $rawRepository
try {
    $env:PATH = $rawToolBin + ';' + $rawOldPath
    Write-Output "RAW_CODE_PLANNER_COMPILER=$(Join-Path $rawToolBin 'cl.exe')"
    & (Join-Path $rawToolBin 'cl.exe') @rawArguments
    $rawBuildExit = $LASTEXITCODE
    if ($rawBuildExit -ne 0) {
        Write-Output "RAW_CODE_PLANNER_BUILD=FAIL EXIT_CODE=$rawBuildExit"
        exit $rawBuildExit
    }
    & $rawExe
    $rawTestExit = $LASTEXITCODE
    Write-Output "RAW_CODE_PLANNER_TEST_EXIT_CODE=$rawTestExit"
    if ($rawTestExit -ne 0) { exit $rawTestExit }
    Write-Output 'RAW_CODE_PLANNER_TEST_RESULT=PASS'
}
finally {
    $env:PATH = $rawOldPath
    Pop-Location
}
