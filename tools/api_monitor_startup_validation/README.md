# API Monitor 创建期注入验证

## WOW64 合作应用启动验收

使用本工程的 `Release|Win32` 目标 `ApiMonitorStartupTarget_x86.exe`，从仓库根目录运行 `py -3.12 -B tools/action_analyze_validation/cli/cooperative_api_capture.py --win32`。Python 控制端使用现有 x64 Python、正式 CLI 和统一 Release 目录。Win32 目标在自己的进程内加载同目录 `APIMonitor_x86.dll`，显式启用合作采集，并在首个业务调用前等待本地启动门闩。夹具核验目标和 Agent 的 I386 PE 机器类型、进程的 WOW64 身份、首个调用的原包，以及正常停钩和清退。

## 创建期研究夹具

只创建并操作本夹具自己的 x64／x86 进程。运行 `./Invoke-Validation.ps1`，使用 HostX64、BelowNormal 宿主和统一 Release；不加载驱动，不接触 Explorer／DWM，不复制运行时，不修改产品 Agent。

三个时点、两个架构分别验证：

1. `fresh`：CREATE_SUSPENDED 刚返回、不恢复主线程，直接调用生产 `injectAgentNative`；当前系统预期错误299。随后不装 Agent 正常运行，核对 TLS／构造／main 三处文件标记，证明阴性不是无效目标。
2. `entry`：原生调试推进到 EXE AddressOfEntryPoint，恢复自有断点字节和IP，用一个显式挂起持有主线程，完成事件并脱离调试；真实 Release Agent 加载并发 HooksInstalled 后才归还挂起。验证构造和main首调已采集，已经执行的TLS明确漏采。x86处理WOW64断点异常码。
3. `early-import`：目标保持最初挂起，定点修改**仅该自有目标内存**中的导入目录，把测试引导 DLL 放入初始导入；磁盘EXE不变。首次恢复后，引导DLL的最小、无CRT DllMain只安装该自有EXE的 CreateFileW IAT Hook，无加载DLL／线程／等待。验证它先于EXE TLS安装，三阶段调用都被捕获，原文件写入及正常退出保留。

`early-import`不是完整API Monitor：它没有调用生产HookEngine、没有宣称898项Hook已在TLS前就绪，也未覆盖依赖DLL的更早TLS／DllMain、direct syscall、自修改或内联普通store。它证明创建期布置和EXE TLS前最小拦截可行。完整Agent的异步worker不会因更早映射DLL而自动更早就绪；需要单独的早期安全子集和覆盖交接。

输出：

- 最终EXE／测试DLL／PDB：`Ksword5.1/x64/Release/`。
- 中间产物：本目录的`x64/Release/`、`Win32/Release/`及`bootstrap/<platform>/Release/`。
- 日志／原始失败／元数据：`.codex-build-logs/behavior-planning/apimon-startup-*`。
- 临时标记：本目录固定`test-artifacts/<architecture>-<mode>/`，退出时逐文件删除并移除空目录。
- Agent配置按生产固定PID路径创建，使用CREATE_NEW，结束只删除本次成功创建的配置和stop；Agent与退役代码随自有进程正常退出释放。

完整结果与复用边界见[验证报告](../../docs/ActionAnalyze启动挂起注入与最早窗口验证-20261124.md)。此前夹具TLS阶段误用CRT导致的崩溃及WOW64异常码漏处理均只发生于自有测试进程；原始失败日志保留，最终通过不覆盖失败记录。
