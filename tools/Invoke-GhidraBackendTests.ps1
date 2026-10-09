param(
    [string]$QtRoot = '.codex-tmp/qt-fixture/ucrt64',
    [string]$OutputDirectory = '.codex-tmp/ghidra-backend-tests',
    [string]$GhidraDirectory,
    [string]$JavaExecutable,
    [string[]]$TestArguments = @(),
    [switch]$BuildOnly
)
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$oldPath = $env:PATH
$oldGhidra = $env:KSWORD_GHIDRA_DIR
$oldJava = $env:KSWORD_GHIDRA_JAVA
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
Push-Location $repository
try {
    $qt = (Resolve-Path -LiteralPath $QtRoot).Path
    $env:PATH = (Join-Path $qt 'bin') + ';' + $env:PATH
    $output = [IO.Path]::GetFullPath((Join-Path $repository $OutputDirectory))
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    $testTemp = Join-Path $output 'temp'
    New-Item -ItemType Directory -Path $testTemp -Force | Out-Null
    $env:TEMP = $testTemp
    $env:TMP = $testTemp
    $app = 'Ksword5.1/Ksword5.1'
    $backend = "$app/UI/Decompiler/GhidraDecompiler"
    $mocOutput = Join-Path $output 'moc_GhidraDecompiler.cpp'
    & (Join-Path $qt 'share/qt6/bin/moc.exe') "$backend.h" -o $mocOutput
    if ($LASTEXITCODE -ne 0) { throw 'Decompiler moc failed.' }
    $executable = Join-Path $output 'ghidra-backend-tests.exe'
    & g++ -std=c++20 -O1 -g0 -DUNICODE -D_UNICODE -DNOMINMAX -DQT_CORE_LIB `
        -isystem "$qt/include/qt6" -isystem "$qt/include/qt6/QtCore" "-I$app" `
        tools/tests/ghidra_decompiler_backend_tests.cpp "$backend.cpp" $mocOutput GhidraRuntimePlugin/RuntimeProfile.cpp `
        "-L$qt/lib" -lQt6Core -o $executable
    if ($LASTEXITCODE -ne 0) { throw 'Decompiler backend test host compilation failed.' }
    if ($BuildOnly) { Write-Output "GHIDRA_BACKEND_BUILD=PASS $executable"; return }
    if ($GhidraDirectory) { $env:KSWORD_GHIDRA_DIR = (Resolve-Path -LiteralPath $GhidraDirectory).Path }
    if ($JavaExecutable) { $env:KSWORD_GHIDRA_JAVA = (Resolve-Path -LiteralPath $JavaExecutable).Path }
    & $executable @TestArguments
    if ($LASTEXITCODE -ne 0) { throw "Actual Ghidra backend regression failed ($LASTEXITCODE)." }
}
finally {
    Pop-Location
    $env:PATH = $oldPath
    $env:KSWORD_GHIDRA_DIR = $oldGhidra
    $env:KSWORD_GHIDRA_JAVA = $oldJava
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
}
