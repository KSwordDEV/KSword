param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$CompilerPath = 'g++',
    [string]$OutputDirectory = 'work/pe-property-model-tests'
)
$ErrorActionPreference = 'Stop'
Push-Location $RepositoryRoot
$peOriginalPath = $env:PATH
try {
    $peCompiler = (Get-Command $CompilerPath -ErrorAction Stop).Source
    $peOutput = [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $OutputDirectory))
    New-Item -ItemType Directory -Path $peOutput -Force | Out-Null
    $peExecutable = Join-Path $peOutput 'pe-property-model-tests.exe'
    $peSources = @('tools/file_property_tests/pe_property_model_tests.cpp',
        'Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.cpp',
        'Ksword5.1/Ksword5.1/ksword/string/string.cpp')
    & $peCompiler -std=c++20 -O1 -Wall -Wextra -Werror -DNOMINMAX @peSources -o $peExecutable
    if ($LASTEXITCODE -ne 0) { throw 'PE property model compilation failed.' }
    $env:PATH = (Split-Path -Parent $peCompiler) + ';' + $peOriginalPath
    & $peExecutable
    if ($LASTEXITCODE -ne 0) { throw 'PE property model regression checks failed.' }
}
finally {
    $env:PATH = $peOriginalPath
    Pop-Location
}
