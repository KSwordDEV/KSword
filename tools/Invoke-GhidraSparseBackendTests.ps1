[CmdletBinding()]
param(
    [string]$GhidraDirectory,
    [string]$JavaExecutable,
    [string]$QtRoot,
    [string]$OutputDirectory = 'dist/ghidra-sparse-backend-tests',
    [string[]]$TestCases = @('core'),
    [switch]$BuildOnly
)
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (!$QtRoot) {
    $QtRoot = Join-Path $repository '.deps/Qt/6.9.3/msvc2022_64'
    if (!(Test-Path -LiteralPath $QtRoot)) { $QtRoot = 'D:/Software/Qt/6.9.3/msvc2022_64' }
}
$qt = (Resolve-Path -LiteralPath $QtRoot).Path
$output = if ([IO.Path]::IsPathRooted($OutputDirectory)) { [IO.Path]::GetFullPath($OutputDirectory) } else { Join-Path $repository $OutputDirectory }
New-Item -ItemType Directory -Path $output -Force | Out-Null
$output = (Resolve-Path -LiteralPath $output).Path
$vc = $null
foreach ($root in @('C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC', 'D:/Software/VS/VC/Tools/MSVC')) {
    if (Test-Path -LiteralPath $root) {
        $candidate = Get-ChildItem -LiteralPath $root -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'bin/Hostx64/x64/cl.exe') } | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
        if ($candidate) { $vc = $candidate.FullName; break }
    }
}
if (!$vc) { throw 'Hostx64/x64 MSVC is required.' }
$sdk = 'C:/Program Files (x86)/Windows Kits/10'
$sdkVersion = Get-ChildItem -LiteralPath (Join-Path $sdk 'Include') -Directory | Where-Object {
    (Test-Path -LiteralPath (Join-Path $_.FullName 'ucrt')) -and
    (Test-Path -LiteralPath (Join-Path $_.FullName 'shared')) -and
    (Test-Path -LiteralPath (Join-Path $_.FullName 'um')) -and
    (Test-Path -LiteralPath (Join-Path $sdk ('Lib/' + $_.Name + '/um/x64/kernel32.lib')))
} | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (!$sdkVersion) { throw 'A matching x64 Windows SDK is required.' }
$app = Join-Path $repository 'Ksword5.1/Ksword5.1'
$moc = Join-Path $output 'moc_GhidraDecompiler.cpp'
& (Join-Path $qt 'bin/moc.exe') (Join-Path $app 'UI/Decompiler/GhidraDecompiler.h') -o $moc
if ($LASTEXITCODE -ne 0) { throw 'Ghidra backend moc failed.' }
$includes = @(('/I' + $app), ('/external:I' + (Join-Path $vc 'include')))
$includes += '/external:I' + (Join-Path $repository 'third_party/zydis')
foreach ($part in @('include', 'include/QtCore')) { $includes += '/external:I' + (Join-Path $qt $part) }
foreach ($part in @('ucrt', 'shared', 'um')) { $includes += '/external:I' + (Join-Path $sdk ('Include/' + $sdkVersion.Name + '/' + $part)) }
$sources = @((Join-Path $repository 'tools/tests/ghidra_sparse_backend_tests.cpp'),
    (Join-Path $app 'UI/Decompiler/GhidraDecompiler.cpp'), (Join-Path $app 'UI/AsyncOperation.cpp'),
    (Join-Path $app 'UI/Decompiler/RawCodePlanner.cpp'),
    (Join-Path $repository 'GhidraRuntimePlugin/RuntimeProfile.cpp'), $moc)
$exe = Join-Path $output 'ghidra_sparse_backend_tests.exe'
$libraries = @(('/LIBPATH:' + (Join-Path $vc 'lib/x64')), ('/LIBPATH:' + (Join-Path $qt 'lib')))
foreach ($part in @('ucrt', 'um')) { $libraries += '/LIBPATH:' + (Join-Path $sdk ('Lib/' + $sdkVersion.Name + '/' + $part + '/x64')) }
& (Join-Path $vc 'bin/Hostx64/x64/cl.exe') /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /external:W0 `
    /DQT_CORE_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD @includes @sources `
    ('/Fo' + $output + '/') ('/Fe' + $exe) /link @libraries Qt6Core.lib (Join-Path $repository 'third_party/zydis/x64/Release/KswordZydis.lib')
if ($LASTEXITCODE -ne 0) { throw 'Strict sparse Ghidra backend test compilation/link failed.' }
Write-Output "GHIDRA_SPARSE_BACKEND_BUILD=PASS EXE=$exe"
if ($BuildOnly) { return }
if ($output -match '[\\/]\.[^\\/]+') { throw 'Ghidra rejects project paths with dot-prefixed elements; choose an OutputDirectory under dist or E:/Temp.' }
if (!$GhidraDirectory) {
    if ($env:KSWORD_GHIDRA_DIR) { $GhidraDirectory = $env:KSWORD_GHIDRA_DIR }
    elseif (Test-Path -LiteralPath 'D:/Software/rea-tools/ghidra_12.1.4_PUBLIC') { $GhidraDirectory = 'D:/Software/rea-tools/ghidra_12.1.4_PUBLIC' }
    else { throw 'Provide -GhidraDirectory or KSWORD_GHIDRA_DIR for real runtime tests.' }
}
$GhidraDirectory = (Resolve-Path -LiteralPath $GhidraDirectory).Path
if (!$JavaExecutable) {
    if ($env:KSWORD_GHIDRA_JAVA) { $JavaExecutable = $env:KSWORD_GHIDRA_JAVA }
    elseif ($env:JAVA_HOME -and (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME 'bin/java.exe'))) { $JavaExecutable = Join-Path $env:JAVA_HOME 'bin/java.exe' }
    elseif (Test-Path -LiteralPath 'D:/Software/rea-tools/jdk-21.0.2/bin/java.exe') { $JavaExecutable = 'D:/Software/rea-tools/jdk-21.0.2/bin/java.exe' }
    else { $java = Get-Command java.exe -ErrorAction SilentlyContinue; if ($java) { $JavaExecutable = $java.Source } }
}
if (!$JavaExecutable) { throw 'Provide -JavaExecutable or a JDK 21+ JAVA_HOME.' }
$JavaExecutable = (Resolve-Path -LiteralPath $JavaExecutable).Path
$saved = @{}
foreach ($name in @('PATH', 'KSWORD_GHIDRA_DIR', 'KSWORD_GHIDRA_JAVA', 'KSWORD_SPARSE_TEST_OUTPUT', 'TEMP', 'TMP')) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:PATH = (Join-Path $qt 'bin') + ';' + $saved['PATH']
    $env:KSWORD_GHIDRA_DIR = $GhidraDirectory; $env:KSWORD_GHIDRA_JAVA = $JavaExecutable
    $env:KSWORD_SPARSE_TEST_OUTPUT = Join-Path $output 'results.json'
    $testTemp = Join-Path $output 'temp'; New-Item -ItemType Directory -Path $testTemp -Force | Out-Null
    $env:TEMP = $testTemp; $env:TMP = $testTemp
    $testArguments = @()
    foreach ($case in $TestCases) {
        if ($case -eq 'all') { continue }
        if ($case -eq 'core') { $testArguments += '--core' }
        else { $testArguments += @('--case', $case) }
    }
    $ErrorActionPreference = 'Continue'
    & $exe @testArguments 2>&1 | Tee-Object -FilePath (Join-Path $output 'runtime.log')
    $testExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($testExit -ne 0) { throw "Sparse Ghidra backend tests failed (exit $testExit)." }
}
finally { foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') } }
