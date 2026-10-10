# ETW R3 命令（迁移项 41）

```powershell
KswordCLI.exe help monitor
KswordCLI.exe monitor etw help
KswordCLI.exe monitor etw providers help
KswordCLI.exe monitor etw providers enum --json
KswordCLI.exe help monitor etw capture
KswordCLI.exe monitor etw capture --provider Microsoft-Windows-Kernel-Process --duration-ms 1000 --json
```

`providers enum` 返回共享后端的 34 个保留 Kernel Provider 预设及默认启用／级别／关键字设置；这是静态预设，不枚举当前系统所有 Provider，不创建会话。`capture` 支持 `--provider default`（默认启用预设）、一个预设名称或标准 `{GUID}`，`--duration-ms 100..120000`（1000）、`--pid`（正数，事件头记录上下文）、`--level 0..5`（5，最大详细程度；0 由 Provider 定义）、`--keywords`（64 位十进制／十六进制，0）、`--limit 1..100000`（5000，保留最近行数）。均支持 `--backend r3`、`--json`。

使用原共享实时 ETW 控制器启用 Provider、消费事件并在限时／取消后停止自己创建的会话、关闭 consumer、join 线程；名称包含 PID、计时和进程内序号，碰撞直接失败，不停止同名既有会话。要求相应 ETW 会话和 Provider 权限，不自动提权或启用权限，不调用驱动。开始控制器返回不等于消费线程成功；所有原始步骤独立记录，默认预设部分启用失败也只能返回部分结果。成功启用未注册／未发射的 Provider 可以无事件，不能据此宣称 Provider 有事件活动。

data 提供 source、requestedDurationMs/elapsedMs、cancelled、sessionName、startAttempted/startSucceeded/startWin32Error、threadStartFailed、providers（name/guid/enabled/win32Error）、enabledProviderCount、openAttempted/openWin32Error、processAttempted/processCompleted/processTraceWin32Error、closeAttempted/closeTraceWin32Error、sessionStopped、stopWin32Errors、consumerJoined、statisticsKnown、eventsLost/logBuffersLost/realTimeBuffersLost、receivedCount/filteredCount/matchedCount/returnedCount/droppedFromBufferCount、callbackFailed、filter 和 events。未调用或未取得的状态／丢失统计为 null；计数为十进制字符串，关闭返回待完成状态与已 join 的证据分开保留。

completedRequestedInterval 表示采集是否等待完请求时长；消费者提前正常结束也返回部分结果，不把 ProcessTrace 返回 0 当作足时采集。事件提供 timestampFileTime（系统时钟 FILETIME 的十进制字符串）、localTimeDisplay、providerGuid、headerPid/headerTid、eventId/version/level/opcode/task、keyword（十六进制）、summaryDisplay。当前后端只保存头部元数据，不解码载荷；headerPid/headerTid 代表记录上下文，不能冒充被操作目标。PID 筛选按此语义进行。会话显式选择系统时钟时间域，避免把 QPC 当作 FILETIME 显示。

完整采集／清理且无损失为 0，完整有效空结果也为 0；启动／打开／无可启用 Provider、消费失败且无结果为 3（明确未支持为 5）；部分启用、事件丢失、缓冲区丢行、回调错误、取消、采集或清理不完整为 6。限时约束采集等待，原生 API 和消费者退出可能延长 elapsedMs，不宣称原生操作硬超时。停止失败时保留会话所有权，关闭消费者并在 join 后重试停止；原失败回执不会被后续成功覆盖。测试日志不放入项目目录；VM 用自建 SDK Provider 发射固定描述符，通过独立状态核对事件与缓冲区丢行，并用 logman 核对会话已消失。help 不创建 ETW 会话。启用异步返回与消费者待关闭定义见 [EnableTraceEx2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)、[CloseTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace)。
