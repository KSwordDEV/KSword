# 使用最新生产对象和 Qt Test 验证共享编辑器，输出放在既有构建日志目录。
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot), [switch]$BuildOnly)
$ErrorActionPreference = 'Stop'
$testRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$testOutput = Join-Path $testRepository '.codex-build-logs'
$testQt = Join-Path $testRepository '.deps\Qt\6.9.3\msvc2022_64'
if (!(Test-Path -LiteralPath $testQt)) { $testQt = 'D:\Software\Qt\6.9.3\msvc2022_64' }
$testVcRoot = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$testSdkRoot = 'C:\Program Files (x86)\Windows Kits\10'
$testSdkVersion = '10.0.26100.0'
$testCompiler = Join-Path $testVcRoot 'bin\Hostx64\x64\cl.exe'
$testLinker = Join-Path $testVcRoot 'bin\Hostx64\x64\link.exe'
$testSource = Join-Path $testRepository 'tools\memory_editor_ui_tests.cpp'
$testContractsSource = Join-Path $testRepository 'tools\workbench_pseudocode_contract_tests.cpp'
$testContractsObject = Join-Path $testOutput 'workbench_pseudocode_contract_tests.obj'
$testIntegrationSource = Join-Path $testRepository 'tools\workbench_integration_regression_tests.cpp'
$testIntegrationObject = Join-Path $testOutput 'workbench_integration_regression_tests.obj'
$testObject = Join-Path $testOutput 'memory_editor_ui_tests.obj'
$testExe = Join-Path $testOutput 'memory_editor_ui_tests.exe'

# testIncludeArgs 指向生产使用的 Qt/VC/SDK 头文件；不执行 VS 安装或扫描盘根。
$testIncludeArgs = @('/I' + (Join-Path $testVcRoot 'include'))
foreach ($testModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtTest')) {
    $testIncludeArgs += '/external:I' + (Join-Path $testQt ('include\' + $testModule))
}
foreach ($testSdkPart in @('ucrt', 'shared', 'um')) {
    $testIncludeArgs += '/external:I' + (Join-Path $testSdkRoot ('Include\' + $testSdkVersion + '\' + $testSdkPart))
}
& $testCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /external:W0 `
    /DQT_WIDGETS_LIB /DQT_GUI_LIB /DQT_CORE_LIB /DQT_TESTLIB_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX `
    /DUNICODE /D_UNICODE /DKSWORD_EDITOR_PRODUCTION_OBJECT_TESTS @testIncludeArgs /c $testSource ('/Fo' + $testObject)
if ($LASTEXITCODE -ne 0) { throw 'Memory editor UI test compilation failed.' }
& $testCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /external:W0 `
    /DQT_WIDGETS_LIB /DQT_GUI_LIB /DQT_CORE_LIB /DQT_TESTLIB_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX `
    /DUNICODE /D_UNICODE @testIncludeArgs /c $testContractsSource ('/Fo' + $testContractsObject)
if ($LASTEXITCODE -ne 0) { throw 'Shared pseudocode contract test compilation failed.' }
& $testCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /external:W0 `
    /DQT_WIDGETS_LIB /DQT_GUI_LIB /DQT_CORE_LIB /DQT_TESTLIB_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX `
    /DUNICODE /D_UNICODE @testIncludeArgs /c $testIntegrationSource ('/Fo' + $testIntegrationObject)
if ($LASTEXITCODE -ne 0) { throw 'Workbench integration regression compilation failed.' }
if ($BuildOnly) { Write-Output 'UNIFIED_SNAPSHOT_TEST_TUS=PASS'; return }

# 使用实际主程序链接记录里的对象和依赖，替换入口，不重新编译整套生产源码。
$testLinkCandidates = @(
    'Ksword5.1\Ksword5.1\x64\Release\Ksword5.1.tlog\link.command.1.tlog',
    'Ksword5.1\Ksword5.1\Ksword5.1\x64\Release\Ksword5.1.tlog\link.command.1.tlog'
) | ForEach-Object { Get-Item -LiteralPath (Join-Path $testRepository $_) -ErrorAction SilentlyContinue }
$testLinkLog = ($testLinkCandidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$testLinkLines = Get-Content -LiteralPath $testLinkLog
$testInputs = @()
$testLinkFlags = $null
for ($testLineIndex = 1; $testLineIndex -lt $testLinkLines.Count; ++$testLineIndex) {
    if ($testLinkLines[$testLineIndex] -match '/OUT:"[^"\r\n]*\\KSWORD5\.1\.EXE"') {
        $testInputs = @($testLinkLines[$testLineIndex - 1].TrimStart('^').Split('|'))
        $testLinkFlags = $testLinkLines[$testLineIndex]
    }
}
if (!$testLinkFlags -or $testInputs.Count -lt 2) { throw 'Production link record was not found.' }
if (!($testInputs | Where-Object { $_ -match 'SNAPSHOTWORKBENCHWIDGET\.EDITING\.OBJ$' })) {
    throw 'The selected production link record does not contain the inline editor.'
}
$testMainObjects = @($testInputs | Where-Object { [IO.Path]::GetFileName($_) -ieq 'main.obj' })
if ($testMainObjects.Count -ne 1) { throw 'Production entry point is ambiguous.' }
# 主程序现在把 Zydis/zstd 作为静态库工程（KswordZydis.lib / KswordZstd.lib）链接，它们在链接记录里是 .LIB 输入；
# 只留 .OBJ 会丢掉它们，链接报 Zydis*/ZSTD_* 未解析。所以 .LIB 输入一并保留（与 Qt 库重复无害）。
$testInputs = @($testInputs | Where-Object { $_ -notin $testMainObjects -and $_ -match '\.(OBJ|LIB)$' })

# testResponse 移除原产物路径和 Windows 入口；保留生产库、LTCG 与依赖。
$testResponse = [regex]::Replace($testLinkFlags, '/(?:OUT|PDB|IMPLIB|LTCGOUT):(?:"[^"]*"|\S+)', '', 'IgnoreCase')
$testResponse = [regex]::Replace($testResponse, '/SUBSYSTEM:\S+|\S+\.RES\b', '', 'IgnoreCase')
$testResponse += ' /OUT:"' + $testExe + '" /SUBSYSTEM:CONSOLE /INCREMENTAL:NO "' + $testObject + '"'
$testResponse += ' "' + $testContractsObject + '"'
$testResponse += ' "' + $testIntegrationObject + '"'
$testResponse += ' /LTCG:INCREMENTAL /LTCGOUT:"' + (Join-Path $testOutput 'memory_editor_ui_tests.iobj') + '"'
$testResponse += ' "' + (Join-Path $testQt 'lib\Qt6Test.lib') + '"'
$testResponse += ' /LIBPATH:"' + (Join-Path $testVcRoot 'lib\x64') + '"'
$testResponse += ' /LIBPATH:"' + (Join-Path $testVcRoot 'atlmfc\lib\x64') + '"'
$testResponse += ' /LIBPATH:"' + (Join-Path $testRepository 'Ksword5.1\Ksword5.1\lib') + '"'
foreach ($testSdkPart in @('ucrt', 'um')) {
    $testResponse += ' /LIBPATH:"' + (Join-Path $testSdkRoot ('Lib\' + $testSdkVersion + '\' + $testSdkPart + '\x64')) + '"'
}
foreach ($testInput in $testInputs) { $testResponse += "`r`n`"" + $testInput + '"' }
$testResponseFile = Join-Path $testOutput 'memory-editor-ui-tests.rsp'
[IO.File]::WriteAllText($testResponseFile, $testResponse, [Text.Encoding]::Unicode)
$testLinkPreviousPath = $env:PATH
try {
    # 清单嵌入调用 rc/mt，必须提供同一 SDK 的 x64 工具目录。
    $env:PATH = (Join-Path $testSdkRoot ('bin\' + $testSdkVersion + '\x64')) + ';' + $testLinkPreviousPath
    & $testLinker ('@' + $testResponseFile)
    $testLinkExit = $LASTEXITCODE
}
finally { $env:PATH = $testLinkPreviousPath }
if ($testLinkExit -ne 0) { throw 'Memory editor UI test link failed.' }

# 只生成已知协议的 Java/Ghidra 进程夹具，不下载或执行样本。
$testFixtureLauncher = Join-Path $testOutput 'ghidra-unified-fixture.exe'
# 独立夹具也使用生产同版本 VC/SDK 库，不依赖调用终端是否加载过开发环境。
$testFixtureLibraryArgs = @()
$testFixtureLibraryArgs += '/LIBPATH:' + (Join-Path $testQt 'lib')
$testFixtureLibraryArgs += '/LIBPATH:' + (Join-Path $testVcRoot 'lib\x64')
foreach ($testSdkPart in @('ucrt', 'um')) {
    $testFixtureLibraryArgs += '/LIBPATH:' + (Join-Path $testSdkRoot ('Lib\' + $testSdkVersion + '\' + $testSdkPart + '\x64'))
}
& $testCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD /W4 /WX /external:W0 `
    /DQT_CORE_LIB /DNOMINMAX /DUNICODE /D_UNICODE @testIncludeArgs `
    (Join-Path $testRepository 'tools/tests/ghidra_fake_launcher.cpp') `
    ('/Fo' + (Join-Path $testOutput 'ghidra-unified-fixture.obj')) ('/Fe' + $testFixtureLauncher) `
    /link @testFixtureLibraryArgs Qt6Core.lib
if ($LASTEXITCODE -ne 0) { throw 'Shared C protocol fixture compilation failed.' }

# 离屏运行只使用测试快照；Qt/ADS DLL 从已构建 Release 定位。
$testOldPath = $env:PATH
$testOldPlatform = $env:QT_QPA_PLATFORM
$testOldPluginPath = $env:QT_PLUGIN_PATH
try {
    $env:PATH = (Join-Path $testRepository 'Ksword5.1\x64\Release') + ';' + (Join-Path $testQt 'bin') + ';' + $testOldPath
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $testQt 'plugins'
    & $testExe $testOutput $testFixtureLauncher
    if ($LASTEXITCODE -ne 0) { throw 'Memory editor Qt regression failed.' }
}
finally {
    $env:PATH = $testOldPath
    $env:QT_QPA_PLATFORM = $testOldPlatform
    $env:QT_PLUGIN_PATH = $testOldPluginPath
}
