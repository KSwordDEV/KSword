# Isolated real parser/install transaction/runtime profile tests. Downloads are
# replaced only by the production installer's explicit test-build asset entry.
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$QtRoot = '.codex-tmp/qt-fixture/ucrt64',
    [string]$OutputDirectory = 'work/ghidra-plugin-tests',
    [string]$OfficialGhidraArchive,
    [string]$OfficialJavaArchive,
    [string]$OfficialInstallRoot,
    [switch]$ForceWindowsPowerShell,
    [switch]$UseMsvc
)
$ErrorActionPreference = 'Stop'
$pluginOldPath = $env:PATH
$pluginOldTemp = $env:TEMP
$pluginOldTmp = $env:TMP
$pluginOldFixturePython = $env:KSWORD_PLUGIN_TEST_PYTHON
Push-Location $RepositoryRoot
try {
    $pluginRepository = (Get-Location).Path
    $env:KSWORD_PLUGIN_TEST_PYTHON = (Get-Command python -ErrorAction Stop).Source
    $pluginQt = (Resolve-Path -LiteralPath $QtRoot).Path
    $pluginOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
        [IO.Path]::GetFullPath($OutputDirectory)
    } else { [IO.Path]::GetFullPath((Join-Path $pluginRepository $OutputDirectory)) }
    New-Item -ItemType Directory -Path $pluginOutput -Force | Out-Null
    # 编译临时文件复用既有输出目录，不额外创建临时构建目录。
    $pluginTemporary = $pluginOutput
    $env:PATH = (Join-Path $pluginQt 'bin') + ';' + $pluginOldPath
    $env:TEMP = $pluginTemporary
    $env:TMP = $pluginTemporary
    $pluginHeader = Join-Path $pluginOutput 'production_plugin_helpers.inc'
    & python (Join-Path $pluginRepository 'tools/tests/extract_ghidra_plugin_helpers.py') `
        --repository-root $pluginRepository --output $pluginHeader
    if ($LASTEXITCODE -ne 0) { throw 'Production plugin helper extraction failed.' }
    $pluginExecutable = Join-Path $pluginOutput 'ghidra-plugin-tests.exe'
    $pluginInertExecutable = Join-Path $pluginOutput 'inert-runtime-fixture.exe'
    if ($UseMsvc) {
        # MSVC 使用仓库的标准 Qt 库；对象与测试文件写入指定的已有输出目录。
        $pluginFlags = @('/nologo', '/std:c++20', '/Zc:__cplusplus', '/EHsc', '/utf-8', '/MD', '/DNOMINMAX',
            '/DUNICODE', '/D_UNICODE', '/DQT_CORE_LIB', '/DQT_NETWORK_LIB',
            '/DKSWORD_PLUGIN_INSTALL_TESTING', '/I.', "/I$pluginOutput", "/I$pluginQt/include",
            "/I$pluginQt/include/QtCore", "/I$pluginQt/include/QtNetwork", "/Fo$pluginOutput/")
        & cl.exe @pluginFlags tools/tests/ghidra_fake_launcher.cpp "/Fe$pluginInertExecutable" `
            /link "/LIBPATH:$pluginQt/lib" Qt6Core.lib
        if ($LASTEXITCODE -ne 0) { throw 'Inert x64 runtime fixture compilation failed.' }
        & cl.exe @pluginFlags tools/tests/ghidra_plugin_install_tests.cpp `
            GhidraRuntimePlugin/RuntimeProfile.cpp Ksword5.1/Ksword5.1/PluginHost.Upstream.cpp `
            Ksword5.1/Ksword5.1/PluginHost.Distribution.cpp Ksword5.1/Ksword5.1/PluginHost.Archive.cpp "/Fe$pluginExecutable" `
            /link "/LIBPATH:$pluginQt/lib" Qt6Network.lib Qt6Core.lib
        if ($LASTEXITCODE -ne 0) { throw 'MSVC upstream plugin test compilation failed.' }
    } else {
    $pluginFlags = @('-std=c++20', '-O1', '-g0', '-DNOMINMAX', '-DUNICODE', '-D_UNICODE',
        '-DQT_CORE_LIB', '-DQT_NETWORK_LIB', '-DKSWORD_PLUGIN_INSTALL_TESTING', '-I.', "-I$pluginOutput")
    foreach ($pluginModule in @('', 'QtCore', 'QtNetwork')) {
        $pluginFlags += @('-isystem', (Join-Path $pluginQt "include/qt6/$pluginModule"))
    }
    & g++ @pluginFlags tools/tests/ghidra_fake_launcher.cpp "-L$pluginQt/lib" -lQt6Core -o $pluginInertExecutable
    if ($LASTEXITCODE -ne 0) { throw 'Inert x64 runtime fixture compilation failed.' }
    & g++ @pluginFlags tools/tests/ghidra_plugin_install_tests.cpp `
        GhidraRuntimePlugin/RuntimeProfile.cpp Ksword5.1/Ksword5.1/PluginHost.Upstream.cpp Ksword5.1/Ksword5.1/PluginHost.Distribution.cpp Ksword5.1/Ksword5.1/PluginHost.Archive.cpp `
        "-L$pluginQt/lib" -lQt6Network -lQt6Core -o $pluginExecutable
    if ($LASTEXITCODE -ne 0) { throw 'Portable Ghidra plugin test compilation failed.' }
    }
    if ($ForceWindowsPowerShell) {
        if (!$UseMsvc) {
        $pluginCompilerDirectory = Split-Path -Parent (Get-Command g++ -ErrorAction Stop).Source
        foreach ($pluginRuntimeName in @('libstdc++-6.dll', 'libgcc_s_seh-1.dll', 'libwinpthread-1.dll')) {
            $pluginRuntimeInput = Join-Path $pluginCompilerDirectory $pluginRuntimeName
            if (!(Test-Path -LiteralPath $pluginRuntimeInput)) { throw "Compiler runtime unavailable: $pluginRuntimeName" }
            Copy-Item -LiteralPath $pluginRuntimeInput -Destination (Join-Path $pluginOutput $pluginRuntimeName) -Force
        }
        }
        $env:PATH = (Join-Path $pluginQt 'bin') + ';' + (Join-Path $env:SystemRoot 'System32') + ';' +
            (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0')
    }
    if ($OfficialGhidraArchive -or $OfficialJavaArchive -or $OfficialInstallRoot) {
        if (!$OfficialGhidraArchive -or !$OfficialJavaArchive -or !$OfficialInstallRoot) {
            throw 'Both official archives and the owned install root are required for the native smoke check.'
        }
        & $pluginExecutable $pluginOutput $pluginInertExecutable --official-install `
            (Resolve-Path -LiteralPath $OfficialGhidraArchive).Path `
            (Resolve-Path -LiteralPath $OfficialJavaArchive).Path `
            ([IO.Path]::GetFullPath($OfficialInstallRoot))
    } else { & $pluginExecutable $pluginOutput $pluginInertExecutable }
    if ($LASTEXITCODE -ne 0) { throw "Portable Ghidra plugin test failed ($LASTEXITCODE)." }
}
finally {
    Pop-Location
    $env:PATH = $pluginOldPath
    $env:TEMP = $pluginOldTemp
    $env:TMP = $pluginOldTmp
    $env:KSWORD_PLUGIN_TEST_PYTHON = $pluginOldFixturePython
}
