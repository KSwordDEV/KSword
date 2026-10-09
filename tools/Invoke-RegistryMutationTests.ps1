# 以生产 MSVC/Qt 编译真实事务状态机和内存夹具；不创建临时构建目录或访问真实注册表。
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$registryRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$registryOutput = Join-Path $registryRepository '.codex-build-logs'
$registryQt = Join-Path $registryRepository '.deps\Qt\6.9.3\msvc2022_64'
$registryVc = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$registrySdk = 'C:\Program Files (x86)\Windows Kits\10'
$registrySdkVersion = '10.0.26100.0'
$registryCompiler = Join-Path $registryVc 'bin\Hostx64\x64\cl.exe'
$registryIncludes = @('/I' + (Join-Path $registryVc 'include'))
foreach ($registryPart in @('', 'QtCore')) {
    $registryIncludes += '/external:I' + (Join-Path $registryQt ('include\' + $registryPart))
}
foreach ($registryPart in @('ucrt', 'shared', 'um')) {
    $registryIncludes += '/external:I' + (Join-Path $registrySdk ('Include\' + $registrySdkVersion + '\' + $registryPart))
}
$registryLibraries = @('/LIBPATH:' + (Join-Path $registryVc 'lib\x64'))
foreach ($registryPart in @('ucrt', 'um')) {
    $registryLibraries += '/LIBPATH:' + (Join-Path $registrySdk ('Lib\' + $registrySdkVersion + '\' + $registryPart + '\x64'))
}
$registrySources = @(
    (Join-Path $registryRepository 'tools\registry_value_transaction_tests.cpp'),
    (Join-Path $registryRepository 'Ksword5.1\Ksword5.1\RegistryDock\RegistryValueTransactions.cpp')
)
$registryExe = Join-Path $registryOutput 'registry_value_transaction_tests.exe'
Push-Location -LiteralPath $registryOutput
try {
    & $registryCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /external:W0 `
        /DNOMINMAX /DUNICODE /D_UNICODE @registryIncludes @registrySources ('/Fe' + $registryExe) `
        /link @registryLibraries (Join-Path $registryQt 'lib\Qt6Core.lib')
    if ($LASTEXITCODE -ne 0) { throw 'Registry mutation fixture compilation failed.' }
    $registryPreviousPath = $env:PATH
    try {
        $env:PATH = (Join-Path $registryQt 'bin') + ';' + $registryPreviousPath
        & $registryExe
        if ($LASTEXITCODE -ne 0) { throw 'Registry mutation fixture failed.' }
        # 优化页通过实际 Access/DocumentApply/ValueTransactions 运行，本机/32/64 均用独立内存键。
        $registryOptimizationSources = @(
            (Join-Path $registryRepository 'tools\registry_optimization_transaction_tests.cpp'),
            (Join-Path $registryRepository 'Ksword5.1\Ksword5.1\RegistryDock\RegistryOptimizationTransactions.cpp'),
            (Join-Path $registryRepository 'Ksword5.1\Ksword5.1\RegistryDock\RegistryValueTransactions.cpp'),
            (Join-Path $registryRepository 'Ksword5.1\Ksword5.1\RegistryDock\RegistryDocumentApply.cpp'),
            (Join-Path $registryRepository 'Ksword5.1\Ksword5.1\RegistryDock\RegistryDocumentApply.Access.cpp')
        )
        $registryOptimizationExe = Join-Path $registryOutput 'registry_optimization_transaction_tests.exe'
        & $registryCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /external:W0 `
            /DNOMINMAX /DUNICODE /D_UNICODE @registryIncludes @registryOptimizationSources ('/Fe' + $registryOptimizationExe) `
            /link @registryLibraries (Join-Path $registryQt 'lib\Qt6Core.lib')
        if ($LASTEXITCODE -ne 0) { throw 'Registry optimization shared fixture compilation failed.' }
        & $registryOptimizationExe
        if ($LASTEXITCODE -ne 0) { throw 'Registry optimization shared fixture failed.' }
        # 原样包含正式 Win32 KTM 后端，所有 Win32 事务 API 均由内存 resource manager 替换。
        $registryAtomicSource = Join-Path $registryRepository 'tools\registry_atomic_move_tests.cpp'
        $registryAtomicExe = Join-Path $registryOutput 'registry_atomic_move_tests.exe'
        & $registryCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /external:W0 `
            /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE @registryIncludes $registryAtomicSource ('/Fe' + $registryAtomicExe) `
            /link @registryLibraries (Join-Path $registryQt 'lib\Qt6Core.lib')
        if ($LASTEXITCODE -ne 0) { throw 'Registry actual KTM fixture compilation failed.' }
        & $registryAtomicExe
        if ($LASTEXITCODE -ne 0) { throw 'Registry actual KTM fixture failed.' }
    }
    finally { $env:PATH = $registryPreviousPath }
}
finally { Pop-Location }
