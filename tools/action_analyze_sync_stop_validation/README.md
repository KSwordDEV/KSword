# SB02 自有目标同步停点验证

在仓库根目录执行 `pwsh -NoProfile -File tools/action_analyze_sync_stop_validation/Invoke-Validation.ps1`。脚本使用 BelowNormal、AMD64 MSBuild 和 HostX64 工具分别构建 Release/x64 和 Release/Win32，然后运行 x64 owner。中间文件位于本目录的 `x64/Release/` 和 `Win32/Release/`。两个 EXE 及 PDB 位于 `Ksword5.1/x64/Release/`，文件名分别以 `ActionAnalyzeSyncStopValidationX64` 和 `ActionAnalyzeSyncStopValidationX86` 开头。日志和核验元数据记录在 `.codex-build-logs/behavior-planning/action-analyze-sb02-*`。

每种架构均启动一次成功夹具和一次失败夹具。x64 owner 以 `DEBUG_ONLY_THIS_PROCESS` 创建固定 EXE，并在首次 Resume 前核对实际 WOW64 架构、对象身份和私有 Job。子进程通过专用异常提交预编译站点及固定槽地址，同一 owner 线程核对主映像范围、站点指令、实际线程和代次后确认路由。每个有效停点只读取登记槽和 origin 的只读控制上下文。预编译 `INT3` 后接 `RET`，继续时使用当次原生事件，不修改代码、保护或寄存器上下文。

| 阶段 | 判据 |
| --- | --- |
| `call-enter` | 原调用计数为 0，持有事件时主线程状态和工作线程心跳均保持。 |
| `call-return` | `ReleaseSemaphore` 只发生一次，调用方仍未收到结果。成功释放私有信号量，失败时请求释放两份并得到 `ERROR_TOO_MANY_POSTS`。返回位及立即读到的 `LastError` 随槽发布。 |
| 继续后 | 工作线程心跳再次推进。调用者看到相同返回位及 `LastError`。零超时等待独立核对信号量是否真实释放。成功路径的 `LastError` 为实测值，Win32 不承诺该成功值。 |
| 异常归属 | 同一入口地址上的旧代次和另一地址上伴随有效返回槽的断点均按 `DBG_EXCEPTION_NOT_HANDLED` 投递，由子进程局部 SEH 接收。 |
| 退出 | 原生退出事件正常继续，精确子进程句柄获信号并与原生退出码对照。脚本回读四个已登记 PID，无需按名称清理任何进程。 |

工作线程只承担可暂停、可恢复的心跳见证。QPC 用于记录本次观测顺序和有意持有区间。覆盖范围为受支持 Windows x64 上的单个固定良性调用和已声明工作线程。并发命中、嵌套、在途关闭、线程门控、跨进程停止组、异常展开和 owner 死亡后的正常续行均未验证。私有 Job 的失败清理策略是结束自有夹具。该策略的超时和异常路径不计入正常通过项。
