param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$QtRoot = '',
    [string]$CppCompiler = 'g++',
    [switch]$RunIsolatedWin32
)
$ErrorActionPreference = 'Stop'
$documentRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
if (!$QtRoot) { $QtRoot = Join-Path $documentRepository '.deps\Qt\6.9.3\mingw_64' }
$documentQt = (Resolve-Path -LiteralPath $QtRoot).Path
$documentOutput = Join-Path $documentRepository '.codex-tmp\registry-document-tests'
$documentExe = Join-Path $documentOutput 'registry_document_tests.exe'
New-Item -ItemType Directory -Path $documentOutput -Force | Out-Null
$documentIncludes = @(
    ('-isystem' + (Join-Path $documentQt 'include')),
    ('-isystem' + (Join-Path $documentQt 'include\QtCore'))
)
$documentSources = @(
    (Join-Path $documentRepository 'tools\registry_document_tests.cpp'),
    (Join-Path $documentRepository 'Ksword5.1\Ksword5.1\RegistryDock\RegistryDocument.cpp')
    (Join-Path $documentRepository 'Ksword5.1\Ksword5.1\RegistryDock\RegistryDocumentApply.cpp')
    (Join-Path $documentRepository 'Ksword5.1\Ksword5.1\RegistryDock\RegistryDocumentApply.Win32.cpp')
)
& $CppCompiler -std=c++17 -Wall -Wextra -Werror -O2 -DUNICODE -D_UNICODE @documentIncludes @documentSources `
    ('-L' + (Join-Path $documentQt 'lib')) -lQt6Core -ladvapi32 -o $documentExe
if ($LASTEXITCODE -ne 0) { throw 'Registry document fixture build failed.' }
$documentOldPath = $env:PATH
try {
    $env:PATH = (Join-Path $documentQt 'bin') + ';' + $documentOldPath
    & $documentExe $documentOutput
    if ($LASTEXITCODE -ne 0) { throw 'Registry document file/codec regressions failed.' }
    $mockTransactionExe = Join-Path $documentOutput 'registry_document_transaction_tests.exe'
    & $CppCompiler -std=c++17 -Wall -Wextra -Werror -O2 -DUNICODE -D_UNICODE @documentIncludes `
        (Join-Path $documentRepository 'tools\registry_document_transaction_tests.cpp') `
        ('-L' + (Join-Path $documentQt 'lib')) -lQt6Core -o $mockTransactionExe
    if ($LASTEXITCODE -ne 0) { throw 'Mock registry transaction fixture build failed.' }
    & $mockTransactionExe
    if ($LASTEXITCODE -ne 0) { throw 'Mock registry transaction regressions failed.' }
    if ($RunIsolatedWin32) {
        $transactionExe = Join-Path $documentOutput 'registry_document_win32_tests.exe'
        & $CppCompiler -std=c++17 -Wall -Wextra -Werror -O2 -DUNICODE -D_UNICODE @documentIncludes `
            (Join-Path $documentRepository 'tools\registry_document_win32_tests.cpp') `
            (Join-Path $documentRepository 'Ksword5.1\Ksword5.1\RegistryDock\RegistryDocument.cpp') `
            ('-L' + (Join-Path $documentQt 'lib')) -lQt6Core -ladvapi32 -o $transactionExe
        if ($LASTEXITCODE -ne 0) { throw 'Registry transaction fixture build failed.' }
        & $transactionExe
        if ($LASTEXITCODE -ne 0) { throw 'Isolated Win32 registry transaction regressions failed.' }
    }
}
finally { $env:PATH = $documentOldPath }
