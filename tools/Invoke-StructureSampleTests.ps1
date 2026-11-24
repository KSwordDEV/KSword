[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),
    [switch]$IncludeExactProfiles,
    [switch]$IncludeStackSymbols,
    [switch]$BuildVmFixture,
    [string]$StackWin10Image,
    [string]$StackWin11Image
)

# 只构建并执行合成回执回归；不会打开宿主机驱动，也不等同于 VM 现场验收。
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path # 当前仓库的唯一根目录。
$int = Join-Path $root 'KswordCLI\x64\Release' # 复用 CLI 固定 IntDir，但每个测试对象使用独立名称。
$out = Join-Path $root 'Ksword5.1\x64\Release' # 只使用统一正式 Release，不复制运行时到临时目录。
$msbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
if (!(Test-Path -LiteralPath $msbuild)) {
    $msbuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe'
}
if (!(Test-Path -LiteralPath $msbuild)) { throw 'Approved x64 MSBuild was not found.' }
$vs = $msbuild.Substring(0, $msbuild.IndexOf('\MSBuild\', [StringComparison]::OrdinalIgnoreCase)) # 本次 MSBuild 对应的 VS 安装根。
$setup = Join-Path $vs 'Common7\Tools\VsDevCmd.bat' # 与构建宿主配套的 x64 工具链环境。
$process = [Diagnostics.Process]::GetCurrentProcess() # 构建子进程继承当前宿主的低优先级。
$priority = $process.PriorityClass # 退出时恢复调用者原优先级。
Push-Location $root
try {
    $process.PriorityClass = 'BelowNormal'
    $environment = & cmd /d /s /c "`"`"$setup`" -arch=x64 -host_arch=x64 >nul && set`"" # 只读取标准 VS 环境。
    if ($LASTEXITCODE) { throw 'Cannot initialize the x64 compiler environment.' }
    foreach ($entry in $environment) {
        if ($entry -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
    $compiler = (Get-Command cl.exe -ErrorAction Stop).Source # 必须实读 HostX64，不能只依赖参数偏好。
    if ($compiler -notmatch 'HostX64\\x64\\cl.exe$') { throw "Unexpected compiler: $compiler" }
    New-Item -ItemType Directory -Path $int, $out -Force | Out-Null
    Write-Output "INTDIR=$int"
    Write-Output "OUTDIR=$out"
    Write-Output "COMPILER=$compiler"
    # 原生完整 v4 回归与 CLI 使用同一个静态解压库；构建沿用当前 BelowNormal 宿主。
    & $msbuild 'third_party\zlib\ZlibStatic.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 `
        /p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 /m:1 /v:minimal
    if ($LASTEXITCODE) { throw 'Native v4 decompression library build failed.' }
    $flags = @('/nologo', '/MD', '/O2', '/EHsc', '/std:c++20', '/W4', '/WX', '/utf-8') # 所有测试与生产客户端使用相同 CRT。
    $units = @(
        @('shared\usermode\StructureSampleProjection.cpp', 'StructureSampleTestsImplementation.obj'),
        @('shared\usermode\ThreadLayoutProfile.cpp', 'StructureSampleTestsProfile.obj'),
        @('shared\usermode\ThreadLayoutPack.cpp', 'StructureSampleTestsPack.obj'),
        @('Launcher\Json.cpp', 'StructureSampleTestsJson.obj'),
        @('Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverStructureSampling.cpp', 'StructureSampleTestsClient.obj'),
        @('shared\usermode\LiveKernelThreadStack.cpp', 'LiveKernelStackWireImplementation.obj')
    ) # 独立对象名避免覆盖生产工程的同名 .obj。
    foreach ($unit in $units) {
        & $compiler @flags /c ("/Fo" + (Join-Path $int $unit[1])) $unit[0]
        if ($LASTEXITCODE) { throw "Test compile failed: $($unit[0])" }
    }
    # 直接编译生产 C 范围检查器；只有头文件编译环境不同，不复制或改写算法。
    & $compiler /nologo /MD /O2 /W4 /WX /utf-8 /TC /DKSW_SAVED_STACK_CHECK_USERMODE /c `
        ('/Fo'+(Join-Path $int 'SavedStackCheck.production.obj')) 'KswordARKDriver\src\features\thread\thread_stack_snapshot_check.c'
    if ($LASTEXITCODE) {throw 'Saved stack production bounds checker compile failed.'}
    $tests = @(
        @('tools\tests\structure_sample_projection_tests.cpp', 'StructureSampleProjectionTests', @('StructureSampleTestsImplementation.obj', 'StructureSampleTestsProfile.obj')),
        @('tools\tests\structure_layout_pack_tests.cpp', 'StructureLayoutPackTests', @('StructureSampleTestsProfile.obj', 'StructureSampleTestsPack.obj', 'StructureSampleTestsJson.obj')),
        @('tools\tests\structure_sample_client_tests.cpp', 'StructureSampleClientTests', @('StructureSampleTestsImplementation.obj', 'StructureSampleTestsClient.obj')),
        @('tools\tests\live_kernel_stack_wire_tests.cpp', 'LiveKernelStackWireTests', @('LiveKernelStackWireImplementation.obj')),
        @('tools\tests\live_saved_stack_check_tests.cpp', 'LiveSavedStackCheckTests', @('SavedStackCheck.production.obj')),
        @('tools\tests\live_saved_stack_wire_tests.cpp', 'LiveSavedStackWireTests', @('LiveKernelStackWireImplementation.obj'))
    ) # 分别覆盖采样解码、真实客户端拒绝和独立在线栈回执验证器；全部只是合成测试。
    foreach ($test in $tests) {
        $objects = @($test[2] | ForEach-Object { Join-Path $int $_ }) # 本测试实际链接的生产对象。
        if ($test[1] -eq 'StructureLayoutPackTests') {
            $objects += Join-Path $root 'third_party\zlib\x64\Release\KswordZlib.lib'
        }
        $exe = Join-Path $out ($test[1] + '.exe') # 固定的辅助测试产物。
        & $compiler @flags ("/Fo" + (Join-Path $int ($test[1] + '.main.obj'))) ("/Fe" + $exe) $test[0] @objects /link /INCREMENTAL:NO ("/PDB:" + (Join-Path $out ($test[1] + '.pdb')))
        if ($LASTEXITCODE) { throw "Test link failed: $($test[1])" }
        $arguments = @() # 仅投影测试可额外接收已发布的精确分片。
        if ($test[1] -eq 'LiveSavedStackCheckTests') {
            if ([bool]$StackWin10Image -ne [bool]$StackWin11Image) {throw 'Supply both exact NT images or neither; do not compare mismatched platforms.'}
            if ($StackWin10Image) {$arguments=@((Resolve-Path -LiteralPath $StackWin10Image).Path,(Resolve-Path -LiteralPath $StackWin11Image).Path)}
        }
        if ($IncludeExactProfiles -and $test[1] -eq 'StructureSampleProjectionTests') {
            foreach ($kind in @('thread_layouts', 'process_layouts')) {
                foreach ($identity in @('34404-329465876-17059840', '34404-3986539294-17063936', '34404-2952155935-21299200')) {
                    $profile = Join-Path $root "Ksword5.1\Ksword5.1\profiles\$kind\$identity.tsv" # 三套明确身份，不选择邻版。
                    if (!(Test-Path -LiteralPath $profile)) { throw "Exact profile missing: $profile" }
                    $arguments += $profile
                }
            }
        }
        if ($test[1] -eq 'StructureLayoutPackTests') {
            $arguments = @((Join-Path $out 'profiles\ark_dyndata_pack_v4.json.qz'), (Join-Path $root 'Ksword5.1\Ksword5.1\profiles'))
        }
        & $exe @arguments
        if ($LASTEXITCODE) { throw "Regression failed: $($test[1])" }
    }
    if ($IncludeStackSymbols) {
        # 符号回归只读取正式驱动 PE/PDB；生产共享投影被直接链接，不访问宿主设备。
        $symbolSources=@(
            'Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverThreadStackSymbols.cpp',
            'Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverClient.cpp',
            'Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverError.cpp',
            'Ksword5.1\Ksword5.1\ksword\string\string.cpp',
            'shared\usermode\backend\driver\DriverQueries.cpp',
            'shared\usermode\backend\driver\DriverFormatting.cpp',
            'shared\usermode\backend\NtApi.cpp'
        )
        $symbolObjects=@() # 独立前缀保护生产工程对象。
        foreach ($source in $symbolSources) {
            $object=Join-Path $int ('StackSymbolTests.'+[IO.Path]::GetFileNameWithoutExtension($source)+'.obj')
            & $compiler @flags /Gy /c ('/Fo'+$object) $source
            if ($LASTEXITCODE) {throw "Symbol regression compile failed: $source"}
            $symbolObjects+=$object
        }
        $exe=Join-Path $out 'LiveThreadStackSymbolTests.exe' # 不进入正式发行清单的固定测试 EXE。
        & $compiler @flags ('/Fo'+(Join-Path $int 'StackSymbolTests.main.obj')) ('/Fe'+$exe) 'tools\tests\live_thread_stack_symbol_tests.cpp' @symbolObjects /link /INCREMENTAL:NO /OPT:REF ('/PDB:'+(Join-Path $out 'LiveThreadStackSymbolTests.pdb'))
        if ($LASTEXITCODE) {throw 'Symbol regression link failed.'}
        & $exe (Join-Path $out 'KswordARK.sys') $out '9e4e1'
        if ($LASTEXITCODE) {throw 'Local symbol projection regression failed.'}
        # 直接链接生产身份会话，只替换采集、枚举和符号边界，回归注释异常及目标退出不丢失/伪造帧。
        $sessionObject=Join-Path $int 'StackSessionTests.implementation.obj'
        & $compiler @flags /Gy /c ('/Fo'+$sessionObject) 'Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverThreadStackSession.cpp'
        if ($LASTEXITCODE) {throw 'Shared stack session compile failed.'}
        $sessionObjects=@($symbolObjects|Where-Object {[IO.Path]::GetFileName($_) -in @(
            'StackSymbolTests.ArkDriverClient.obj','StackSymbolTests.ArkDriverError.obj','StackSymbolTests.string.obj')})
        $sessionExe=Join-Path $out 'LiveThreadStackSessionTests.exe'
        & $compiler @flags ('/Fo'+(Join-Path $int 'StackSessionTests.main.obj')) ('/Fe'+$sessionExe) `
            'tools\tests\live_thread_stack_session_tests.cpp' $sessionObject @sessionObjects `
            /link /INCREMENTAL:NO /OPT:REF ('/PDB:'+(Join-Path $out 'LiveThreadStackSessionTests.pdb'))
        if ($LASTEXITCODE) {throw 'Shared stack session test link failed.'}
        & $sessionExe
        if ($LASTEXITCODE) {throw 'Shared stack session regression failed.'}
    }
    if ($BuildVmFixture) {
        # 只构建已有自有 CLI 夹具，不在宿主运行，更不把它作为现场回溯结果。
        $fixture=Join-Path $out 'LiveKernelDiagnosticVmTarget.exe'
        & $compiler @flags ('/Fo'+(Join-Path $int 'LiveKernelDiagnosticVmTarget.obj')) ('/Fe'+$fixture) 'tools\tests\live_kernel_diagnostic_vm_target.cpp' /link /INCREMENTAL:NO ('/PDB:'+(Join-Path $out 'LiveKernelDiagnosticVmTarget.pdb'))
        if ($LASTEXITCODE) {throw 'VM fixture build failed.'}
    }
    Write-Output 'STRUCTURE_SAMPLE_SYNTHETIC_TESTS=PASS'
}
finally {
    $process.PriorityClass = $priority
    Pop-Location
}
