# Explorer 页面执行探针实测

仅用于用户明确授权的本机会话 `explorer.exe`，是独立机制夹具，不接入产品。程序要求显式 PID，校验 Windows 目录中的映像路径、进程创建时间、会话、x64 和已有调试器占用；不启用特权、不操作 DWM、不加载驱动或目标 DLL。

异常接收者是外部子进程 `ExplorerProbeValidation.exe --child`：Windows 将目标的异常以原生调试事件交付给它。目标中不安装自有 VEH。父进程负责发消息刺激、独立回读结果及监护，不拥有子进程的 Wait/Continue 会话。

## 默认测试

1. `image-natural`：观察现有 `USER32!DispatchMessageW` 所在 RX 映像页；给 Explorer 窗口投递 WM_NULL，捕获既有线程的自然执行，完成八轮页外重设防。系统映像字节不改。
2. `private-version1`：在目标内分配自有两页内存，写入只用易失寄存器做计算并返回的29字节测试函数。四个新线程分别执行，独立线程句柄回读返回值 `0x13570001`。
3. `private-version2`：同一映射修改立即数、读回字节、恢复 RX 和刷新指令缓存，再执行四次，返回值变为 `0x24680002`。这是真实受控写入，不是同字节 COW，也不是自动发现未知写入者。
4. `cross-page-fetch`：只设防第二页，让一条10字节指令从第一页跨页取指；分别核对 RIP 和 fault VA，四个线程仍须返回正确值。
5. `abort-inside-page`：第一步后 RIP 仍在区域内时主动撤探针；恢复原保护、清除并读回自有 TF、配对归还挂起计数，原计算正常返回。

Windows 调试事件提供进程暂停语义。恢复 X 期间，控制器额外持有非选定线程的挂起计数；新建线程的真实 CREATE_THREAD 事件到达时，若正在步进则加入停止账。代码中这条“步进期间新建”分支不因存在就算已测：当前运行的 `creates_during_step=0`，尚未覆盖该竞争。

原始事件线程／进程句柄由 Windows 在退出事件继续时关闭；控制器只关闭自己的复制句柄。Toolhelp 可能仍列出已交付 EXIT_THREAD 的退出对象，按 TID 加创建时间与真实退出事件核对，不能把它当成遗漏的活线程。

## 构建与运行

从仓库根目录执行，PID 必须来自当前已授权的 Explorer：

```powershell
& .\tools\explorer_probe_validation\Invoke-Validation.ps1 -ExplorerPid <PID>
```

脚本以 BelowNormal 宿主启动 amd64 MSBuild，传入三项 x64 属性；工程打印绝对 IntDir、OutDir 和 HostX64。固定中间目录 `tools/explorer_probe_validation/x64/Release/`，统一正式输出 `Ksword5.1/x64/Release/ExplorerProbeValidation.exe`／PDB。文本日志及元数据保存 `.codex-build-logs/behavior-planning/explorer-probe-<time>-*`。无 Qt、临时运行副本或测试配置。

入口文件及职责：

- `ExplorerProbeMain.cpp`：目标校验、已知来源写入、结果回读、父监护及自有内存清理。
- `ExplorerDebugSession.cpp`：唯一原生调试事件 owner，线程账、NX/TF、重设防与主动中止。
- `ExplorerProbe.h`：测试私有的配置、结果及恢复账，不是产品机器契约。
- `.vcxproj`／`.filters`：独立 MSVC Release x64 工程。

正常路径要求各 CASE_RESULT 通过、RESULT=PASS、退出码0；默认通过不包含下一节。

## 已确认失败：持有 NX 异常时结束控制器

`-IncludeControllerDeathProbe` 会额外运行 `guardian-at-nx`。这是**已造成 Explorer 桌面功能失效的破坏性负控**，默认不运行。该开关不是已经解决的恢复方案，也不应加入无人值守的正常回归。

负控在首个 NX 原生事件仍 pending、尚无自有 TF／显式挂起时，让父进程先恢复页保护并结束子控制器。2026-11-24 实测：恢复页保护与 `DebugSetProcessKillOnExit(FALSE)` 均不足以使待处理异常正常结束。目标线程返回 `0x5bb` 而非计算结果，原任务栏 HWND 失效。按用户授权结束旧 Explorer 并重启后恢复桌面。不能把这次失败改为通过，也不能把“先正常 Continue/Detach 后再杀控制器”的另一场景当成修复。

普通 R0 路线尚未运行：不能用本夹具的原生调试门控或任何通过数替代 R0 owner 死亡恢复验证。

失败时不擅自释放可能仍在执行的远程内存，输出精确 retained_allocation。仅在独立确认本次测试线程全部退出后，可用 `--release-retained <PID> <base> <created-ticks>` 清理；该入口还要求目标身份、精确自有字节及两页私有 RX 映射全部匹配。目标进程已经退出时，其测试内存随进程释放。

详细证据、失败版本和最终正常回归见 [Explorer 验证记录](../../docs/ActionAnalyzeExplorer复杂环境验证-20261124.md)。
