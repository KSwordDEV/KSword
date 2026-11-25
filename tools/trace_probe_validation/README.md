# 页面执行探针机制夹具

验证普通页保护、既有线程执行进入、统一暂停后的受控放行。不含 shellcode，不注入目标，不加载驱动，不操作 UI 或系统安全设置。

- `ThreadpoolExecutionProbe.cpp`：合法线程池预热后执行自有映像函数；复现 Guard 一次性、读取消耗 Guard、NX 恢复 X 时其它线程可进入的窗口。
- `StopWorldExecutionProbe.cpp`：固定两个事先就绪的自有原生线程；用 `SuspendThread` 加 `GetThreadContext` 建立停止屏障，只放行一个线程 TF 前进到页外，重设 NX 后再放行另一个。
- `TraceProbeValidation.vcxproj`／`.filters`：MSVC v143，`Release|x64`、`/W4 /WX`，无 Qt。

停止实验只覆盖这两个自有工作线程，同进程控制器继续运行；它不提供任意进程线程枚举、新线程门控、跨进程注入或生产调试会话。

构建前把 `$probeMsbuild` 设为本机 **amd64 MSBuild.exe** 的绝对路径。于仓库根目录执行，构建宿主必须先降为 `BelowNormal`：

```powershell
$probeHost = [System.Diagnostics.Process]::GetCurrentProcess()
$probePreviousPriority = $probeHost.PriorityClass
try {
    $probeHost.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
    & $probeMsbuild 'tools\trace_probe_validation\TraceProbeValidation.vcxproj' `
        /t:Build /p:Configuration=Release /p:Platform=x64 `
        /p:PreferredToolArchitecture=x64 `
        /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 `
        /m:1 /v:minimal /nologo
    if ($LASTEXITCODE -ne 0) { throw "Probe build failed: $LASTEXITCODE" }
} finally {
    $probeHost.PriorityClass = $probePreviousPriority
}
& '.\Ksword5.1\x64\Release\TraceProbeValidation.exe'
if ($LASTEXITCODE -ne 0) { throw "Probe failed: $LASTEXITCODE" }
```

工程打印实际 IntDir、OutDir、HostX64；固定中间目录为 `tools/trace_probe_validation/x64/Release/`，正式输出为 `Ksword5.1/x64/Release/TraceProbeValidation.exe` 和 PDB。不复制 Qt、不建立临时运行目录，也不修改任何测试配置。

以 `RESULT=PASS failures=0`、`STW_RESULT=PASS failures=0` 和退出码 0 一起判定通过。`unguarded_second_entry_is_missed` 等负控的 PASS 表示成功复现限制，不代表持续追踪功能通过。

机制证据及未覆盖范围见[2026-11-24 验证记录](../../docs/非虚拟化页面执行探针验证-20261124.md)。单次运行不能给出性能或长期稳定性结论。
