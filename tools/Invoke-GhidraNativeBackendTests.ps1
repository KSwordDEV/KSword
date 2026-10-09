# 使用既有日志目录和生产 MSVC/Qt，运行真实 Ghidra 的离线字节夹具。
param([string[]]$TestArguments = @(), [switch]$BuildOnly)
$ErrorActionPreference = 'Stop'
$ghidraRepo = Split-Path -Parent $PSScriptRoot
$ghidraOutput = Join-Path $ghidraRepo '.codex-build-logs'
$ghidraQt = Join-Path $ghidraRepo '.deps/Qt/6.9.3/msvc2022_64'
$ghidraVc = 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207'
$ghidraSdk = 'C:/Program Files (x86)/Windows Kits/10'
$ghidraSdkVersion = '10.0.26100.0'
$ghidraApp = Join-Path $ghidraRepo 'Ksword5.1/Ksword5.1'
$ghidraMoc = Join-Path $ghidraOutput 'ghidra_native_moc.cpp'
& (Join-Path $ghidraQt 'bin/moc.exe') (Join-Path $ghidraApp 'UI/Decompiler/GhidraDecompiler.h') -o $ghidraMoc
if ($LASTEXITCODE -ne 0) { throw 'Ghidra native moc failed.' }
# ghidraIncludes 指向项目内依赖及约定工具链；不搜索整盘或创建构建目录。
$ghidraIncludes = @(('/I' + $ghidraApp), ('/external:I' + (Join-Path $ghidraVc 'include')),
    ('/external:I' + (Join-Path $ghidraQt 'include')), ('/external:I' + (Join-Path $ghidraQt 'include/QtCore')))
foreach ($ghidraPart in @('ucrt', 'shared', 'um')) {
    $ghidraIncludes += '/external:I' + (Join-Path $ghidraSdk ('Include/' + $ghidraSdkVersion + '/' + $ghidraPart))
}
$ghidraSources = @('tools/tests/ghidra_decompiler_backend_tests.cpp',
    'Ksword5.1/Ksword5.1/UI/Decompiler/GhidraDecompiler.cpp', 'GhidraRuntimePlugin/RuntimeProfile.cpp')
$ghidraObjects = @()
foreach ($ghidraSource in $ghidraSources + @($ghidraMoc)) {
    $ghidraFullSource = if ([IO.Path]::IsPathRooted($ghidraSource)) { $ghidraSource } else { Join-Path $ghidraRepo $ghidraSource }
    $ghidraObject = Join-Path $ghidraOutput ('ghidra_native_' + [IO.Path]::GetFileNameWithoutExtension($ghidraSource) + '.obj')
    & (Join-Path $ghidraVc 'bin/Hostx64/x64/cl.exe') /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD `
        /W4 /WX /external:W0 /DQT_CORE_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE `
        @ghidraIncludes /c $ghidraFullSource ('/Fo' + $ghidraObject)
    if ($LASTEXITCODE -ne 0) { throw "Ghidra native strict compilation failed: $ghidraSource" }
    $ghidraObjects += $ghidraObject
}
$ghidraLibraries = @(('/LIBPATH:' + (Join-Path $ghidraVc 'lib/x64')), ('/LIBPATH:' + (Join-Path $ghidraQt 'lib')))
foreach ($ghidraPart in @('ucrt', 'um')) {
    $ghidraLibraries += '/LIBPATH:' + (Join-Path $ghidraSdk ('Lib/' + $ghidraSdkVersion + '/' + $ghidraPart + '/x64'))
}
$ghidraExe = Join-Path $ghidraOutput 'ghidra-native-backend-tests.exe'
& (Join-Path $ghidraVc 'bin/Hostx64/x64/link.exe') /nologo /SUBSYSTEM:CONSOLE /INCREMENTAL:NO `
    ('/OUT:' + $ghidraExe) @ghidraLibraries @ghidraObjects Qt6Core.lib
if ($LASTEXITCODE -ne 0) { throw 'Ghidra native fixture link failed.' }
if ($BuildOnly) { Write-Output 'GHIDRA_NATIVE_BUILD=PASS'; return }
# 运行时使用已安装插件；只导入人工字节，不执行样本或访问真实目标。
$ghidraOldPath = $env:PATH
$ghidraOldPlugin = $env:KSWORD_PLUGIN_ROOT
try {
    $env:PATH = (Join-Path $ghidraQt 'bin') + ';' + $ghidraOldPath
    $env:KSWORD_PLUGIN_ROOT = Join-Path $ghidraRepo 'plugin'
    & $ghidraExe @TestArguments | Tee-Object -FilePath (Join-Path $ghidraOutput 'ghidra-native-backend-tests.log')
    if ($LASTEXITCODE -ne 0) { throw "Actual Ghidra native backend regression failed ($LASTEXITCODE)." }
}
finally { $env:PATH = $ghidraOldPath; $env:KSWORD_PLUGIN_ROOT = $ghidraOldPlugin }
