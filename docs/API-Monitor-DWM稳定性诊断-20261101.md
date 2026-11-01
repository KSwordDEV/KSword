# API Monitor：DWM 与多进程稳定性诊断

本轮只在 Windows10-20H2 来宾 `DESKTOP-D2161R7` 附加系统进程。宿主机仅构建、分析转储及运行自有回归夹具，没有附加宿主机 DWM。后续因已加载 Agent 使用 PIN，曾有计划地重启来宾以加载修复版本；这与目标在采集期间崩溃／重启分开记录。

## 已定位的问题

原版线程栈停在 `MonitorWorkerThread → InstallConfiguredHooks → InstallRawFallbackHooks → InstallInlineHookAtAddress → AllocateNear → VirtualQuery`。随后插桩确认不止一个耗时点。

| 同一默认 Raw 配置的阶段 | 原版实测 | 修复后插桩实测 |
| --- | ---: | ---: |
| 首轮安装结束，8097 个 Raw 绑定 | 71704 ms | 3093 ms |
| 后续补装达到9909个 Raw 绑定 | 87704 ms | 4187 ms |
| 邻近地址查询累计次数 | 42979700 | 0（使用 VirtualAlloc2） |
| 邻近分配累计耗时 | 47278.701 ms | 1205.101 ms |
| 安装／补装读取线程上下文累计耗时 | 20999.206 ms | 4.817 ms |
| 移除阶段 | 22297 ms | 93 ms |
| 最终覆盖排空 | 2秒超时，仅发到第3520项 | 约610 ms，修订3完整写完 |

以上是指定来宾中的阶段计时，不是所有进程的固定耗时。全程 elapsedMs 还包含请求采集时长、加载、补装及停止排空；不能把整个命令时间称为地址扫描时间。不同进程加载模块、导出数量、线程和并发活动不同。优化没有缩小默认 Raw 模块集或删除定义。

1. 原 `AllocateNear` 对每个 Hook 按64KiB步进反复扫描约±2GiB，未按占用区大小跳过。现在优先使用系统地址约束分配，兼容路径按内存区域跳跃并检查取消。包含式最高地址必须是分配粒度边界减一；已用真实 `VirtualAlloc2` 成功调用回归防止参数错误悄悄退回扫描。[地址约束契约](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-mem_address_requirements)
2. 每个入口分别暂停／恢复线程并读取上下文。现在先准备 trampoline，再在一次连续暂停区间内检查并提交一组入口；恢复后不复用 RIP/EIP。移除同样批量恢复。失败页保护保留原值，后续重试不能把临时RWX误作原保护。
3. 32字节入口检查原先逐字节重复查询；Strong身份检查对每个Raw导出重建整张表的键；活动入口查找还扫描所有退役记录。现分别改为按区域复制、不可变身份索引和活动区间索引。入口字节、重叠冲突、RIP/EIP及解码器的保守拒绝条件继续保留。
4. 发送线程每64个快照包固定等25ms，大快照的理论等待就超过停止排空预算。现在有积压时连续发送，仍保留管道背压和有界停止。正常关闭不调用会丢弃未读数据的 `DisconnectNamedPipe`。[管道关闭契约](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe)
5. `HooksRemoved.snapshotRevision` 声明最终修订，CLI继续读到EOF后核对；半包或缺失最终修订仍报告错误／过期。复用既有1000字节布局，旧Agent的0表示未声明。安装超时／取消会停止后续准备并清理已经提交的入口，未真正生效的记录保留失败状态。

没有证据表明本次卡顿是“APC打断后把Agent线程关闭”。曾在超时后抓到同一worker回到等待新会话；不能把超时等同于线程被杀或永久死锁。

## 扩展测试发现的线程退出边界

Explorer 的首次扩展测试没有崩溃，但全部入口被安全检查拒绝，错误为 `SuspendThread error=5`。独立的来宾专用原生探针确认4个线程对象仍被枚举，但暂停返回 `0xC000004B (STATUS_THREAD_IS_TERMINATING)`、句柄等待结果为0。连续10轮均复现；这不是活线程访问拒绝。

线程守卫现只跳过已经确认结束的线程，并处理检查后立即退出的竞态。仍存活线程暂停／上下文失败时继续拒绝打补丁。逐线程记录是否实际暂停，恢复时不会因中间跳过线程而漏恢复后续线程。专项回归同时验证结束句柄、退出竞态、活线程拒绝及恢复次数。来宾重启后，Explorer首次／重复监控成功；再次原生探测仍能找到4个已结束对象，修复实际覆盖了该情况。

## 32位重复会话的地址碎片与异常处理

扩展测试中，32位记事本在第二轮Raw监控崩溃。WER为 `0xC0000409 / FAST_FAIL_FATAL_APP_EXIT`；恢复原异常上下文后，堆栈明确为 `std::bad_alloc → PublishConfiguredCoverage → RetryPendingHooks → MonitorWorkerThread`。转储内约1.86GB地址仍空闲，但分为约30342段，最大连续空闲区只有65536字节，覆盖快照的大块分配因此失败。不能把该fastfail误称为已证明的栈覆盖。

修复为32位trampoline、Raw/Fake stub及回调thunk共用64KiB保留区，逐4KiB页提交并独立封为RX；释放未发布准备页不影响已发布的相邻页。已发布／退役代码仍按原安全策略保留。工作线程和从Hook触发的补装增加C++异常边界：请求停止、报告AgentFailure并尝试安全清理；未确认恢复不发送HooksRemoved。CLI把AgentFailure及提前停止计为失败／部分结果，不虚构完整采集。

修复后的同一个32位记事本连续6轮Raw采集全部完成、Hook正常移除、丢包为0、无新错误／转储，最后正常退出0。第6轮最大连续空闲区1403518976字节。内存仍随保留的退役代码增长（本次提交内存约515.9MB），本轮没有实现退役代码回收或DLL完整卸载。

## 插桩与产物

`KSWORD_APIMON_DIAGNOSTICS` 由两个工程的 `ApiMonitorDiagnostics` 属性控制，默认0。插桩源码保留；正式构建传 `/p:ApiMonitorDiagnostics=0`。关闭宏不求值参数，不链接计数／日志函数，不保留诊断路径或阶段字符串，`/Od` 回归也验证了这一点。暂停其他线程时不执行日志文件操作。

构建和实际测试分别验证两个位数的DLL；来宾加载文件的SHA256与本机产物核对。来宾为最终DWM／svchost预建了可写插桩文件，关闭宏后应保持0字节，不能用权限拒绝冒充插桩关闭。

## 验证结果与范围

HostX64构建CLI与x64/x86 Agent通过，0警告、0错误。核心入口：

```powershell
python tools/api_monitor/run_regressions.py --no-ui
python tools/api_monitor/run_regressions.py --architecture x86 --no-ui
```

两个位数各37项通过，覆盖真实异步I/O、APC完成回调、七个Winsock扩展、Raw/Fake ABI、跨位数注入、退役代码、取消、批处理、保护恢复、32位代码页及工作线程异常边界等。主程序Release构建也通过，`BUILD_RESULT=SUCCESS / EXIT_CODE=0`、双语审计通过。现有带Qt的完整入口在 `test_ui_coverage.py` 因夹具与当前 `CoverageViewState` 字段失配而未通过；本轮没有改版或验收主程序图形页面，不将该入口算作通过。

最终来宾系统目标已完成DWM Raw／普通／重复／30秒采集和安装中取消，以及独占BTAGService的svchost Raw／普通／重复。每轮保留原PID／创建身份，正常轮次取得HooksInstalled、HooksRemoved、完整最终覆盖；未出现进程崩溃、错误1000/1001、转储或丢包。DiagTrack仍被系统签名／动态代码策略拒绝加载（错误577），未绕过该策略，不能算作监控通过。

扩展的Explorer、ctfmon、RuntimeBroker、PowerShell、64位记事本首次／重复监控通过。两次编号文件检查分别48/48、47/47；按 `HooksInstalled` 起算的**请求采集窗口**核对，停止后的排空时间不计入应观测编号。自有PowerShell和64位记事本均正常返回0。32位记事本的重复崩溃修复后另完成上述6轮验收。

CLI虚拟机77项曾通过；代码页／异常边界修复后的最终全套CLI、CMD扩展测试及整套系统目标重跑尚未完成。用户随后停用虚拟机并明确要求立即收尾提交，因此停止所有虚拟机操作，不将这些未完成项算作通过。版本保持工作区现有的5.2.1.0。

返回6／partial仍可能来自缺失导出、保守解码器拒绝等真实覆盖边界。完整快照不等于所有API都成功安装，有限时长、指定负载的试验也不构成所有进程永不崩溃或全部调用零遗漏的保证。

## 停止与完整卸载

本轮按用户对稳定性的选择保留DLL常驻。`HooksRemoved`表示入口恢复和监控停止，不表示模块已从地址空间卸载。Agent使用 `GET_MODULE_HANDLE_EX_FLAG_PIN`，Windows约定该模块驻留至进程结束；当前进程中的PIN不能通过普通 `FreeLibrary` 撤销。[PIN契约](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw)

新版本理论上可以实现完整卸载，但须统一处理新调用准入、所有在途detour／回调、退役stub／trampoline、COM/vtable引用、Agent线程和模块引用。只恢复入口或只检查线程当前IP不足以证明后续不会返回DLL；某些未完成异步操作还会阻止有限时间内完成回收。本轮没有伪造完整卸载能力，也没有强卸已经固定的Agent。
