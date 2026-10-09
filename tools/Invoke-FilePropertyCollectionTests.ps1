# Verify the production FltLib enumeration control flow with injected API results.
# No Qt GUI, real filter enumeration, target metadata or driver access is involved.
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$CompilerPath = 'g++',
    [string]$OutputDirectory = 'work/file-property-collection-tests'
)
$ErrorActionPreference = 'Stop'
$collectionOldPath = $env:PATH
Push-Location $RepositoryRoot
try {
    $collectionCompiler = (Get-Command $CompilerPath -ErrorAction Stop).Source
    $collectionOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
        [IO.Path]::GetFullPath($OutputDirectory)
    } else { [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $OutputDirectory)) }
    New-Item -ItemType Directory -Path $collectionOutput -Force | Out-Null
    $collectionSource = [IO.File]::ReadAllText((Join-Path (Get-Location).Path 'Ksword5.1/Ksword5.1/FileDock/FileDock.cpp'))
    $collectionStart = $collectionSource.IndexOf('        using NativeFilterFirst = ', [StringComparison]::Ordinal)
    $collectionEnd = if ($collectionStart -ge 0) {
        $collectionSource.IndexOf('        static void appendNativeInstance(', $collectionStart, [StringComparison]::Ordinal)
    } else { -1 }
    if ($collectionStart -lt 0 -or $collectionEnd -le $collectionStart) {
        throw 'Production native filter collector markers were not found.'
    }
    $collectionHeader = Join-Path $collectionOutput 'native_filter_collection.inc'
    [IO.File]::WriteAllText($collectionHeader,
        $collectionSource.Substring($collectionStart, $collectionEnd - $collectionStart),
        [Text.UTF8Encoding]::new($false))
    $collectionExecutable = Join-Path $collectionOutput 'file-property-collection-tests.exe'
    $collectionLog = Join-Path $collectionOutput 'file-property-collection-tests.log'
    $collectionFlags = @('-std=c++20', '-O1', '-Wall', '-Wextra', '-Werror', '-DNOMINMAX', "-I$collectionOutput",
        'tools/file_property_tests/native_filter_collection_tests.cpp', '-o', $collectionExecutable)
    & $collectionCompiler @collectionFlags 2>&1 | Tee-Object -FilePath $collectionLog
    if ($LASTEXITCODE -ne 0) { throw 'Native file property collector compilation failed.' }
    $env:PATH = (Split-Path -Parent $collectionCompiler) + ';' + $collectionOldPath
    & $collectionExecutable 2>&1 | Tee-Object -FilePath $collectionLog -Append
    if ($LASTEXITCODE -ne 0) { throw 'Native file property collector regression checks failed.' }
}
finally {
    $env:PATH = $collectionOldPath
    Pop-Location
}
