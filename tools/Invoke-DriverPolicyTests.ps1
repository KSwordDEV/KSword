[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

# 固定 Release 测试产出；复用仓库 Qt，不复制运行时、不加载驱动、不改变宿主策略。
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$qt = Join-Path $root '.deps\Qt\6.9.3\msvc2022_64'
if (!(Test-Path -LiteralPath $qt)) { $qt = 'D:\Software\Qt\6.9.3\msvc2022_64' }
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (!(Test-Path -LiteralPath $vcvars)) { $vcvars = 'D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat' }
if (!(Test-Path -LiteralPath $vcvars) -or !(Test-Path -LiteralPath $qt)) { throw 'HostX64 and repository Qt required.' }
$output = Join-Path $root 'Ksword5.1\x64\Release\driver-policy-tests'
New-Item -ItemType Directory -Path $output -Force | Out-Null
Write-Output "DRIVER_POLICY_TEST_OUTPUT=$output"
$source = 'Ksword5.1\Ksword5.1'
$hostProcess = [Diagnostics.Process]::GetCurrentProcess()
$oldPriority = $hostProcess.PriorityClass
$savedEnvironment = @{}
foreach ($name in @('PATH', 'TEMP', 'TMP', 'QT_PLUGIN_PATH', 'QT_QPA_PLATFORM')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    # 先降低构建宿主优先级，编译器和链接器继承，不干扰前台操作。
    $hostProcess.PriorityClass = [Diagnostics.ProcessPriorityClass]::BelowNormal
    $env:TEMP = $output
    $env:TMP = $output
    $compile = 'call "' + $vcvars + '" && cl /nologo /EHsc /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /MD /W4 /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DZYDIS_STATIC_BUILD'
    foreach ($include in @("$qt\include", "$qt\include\QtCore", "$qt\include\QtGui", "$qt\include\QtWidgets", "$qt\include\QtNetwork", "$qt\include\QtSvg", "$root\third_party\zydis", "$root\third_party\zstd", "$root\$source")) {
        $compile += ' /I"' + $include + '"'
    }
    # 实际生产弹窗、策略后端、异步控制器与翻译器参与链接，只有系统 I/O 由测试注入。
    $compile += ' tools\tests\driver_policy_tests.cpp ' + $source + '\Framework\WindowsDriverPolicy.cpp ' + $source + '\UI\DriverLoadFailureDialog.cpp ' + $source + '\UI\AsyncOperation.cpp ' + $source + '\Framework\BackgroundTaskRegistry.cpp ' + $source + '\Internationalization\LanguageManager.cpp'
    $compile += ' /Fo"' + $output.Replace('\', '/') + '/" /Fe"' + $output + '\driver_policy_tests.exe" /link /LIBPATH:"' + $qt + '\lib" Qt6Core.lib Qt6Gui.lib Qt6Widgets.lib Qt6Network.lib Qt6Svg.lib User32.lib Advapi32.lib'
    & $env:ComSpec /d /s /c $compile
    if ($LASTEXITCODE -ne 0) { throw "Driver policy tests failed to compile: $LASTEXITCODE" }
    $env:PATH = (Join-Path $qt 'bin') + ';' + $env:PATH
    $env:QT_PLUGIN_PATH = Join-Path $qt 'plugins'
    $env:QT_QPA_PLATFORM = 'offscreen'
    & (Join-Path $output 'driver_policy_tests.exe')
    if ($LASTEXITCODE -ne 0) { throw "Driver policy tests failed: $LASTEXITCODE" }
} finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    $hostProcess.PriorityClass = $oldPriority
}
