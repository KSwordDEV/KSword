# 监控 R3 命令

## API Monitor

```powershell
KswordCLI.exe help monitor api capture
KswordCLI.exe monitor api capture --pid 1234 --categories file,registry --duration-ms 3000 --confirm --json
KswordCLI.exe monitor api capture --pid 1234 --raw 1 --auto-children 1 --limit 20000 --confirm --json
KswordCLI.exe monitor api capture --pid 1234 --r0-inject 1 --confirm --json
KswordCLI.exe monitor api capture --pid 1234 --options-file monitor-options.ini --confirm --json
KswordCLI.exe monitor api capture --pid 1234 --call-stack 1 --timeline 1 --pre-exclude-apis 'KernelBase!ReadFile' --post-exclude-modules 'user32' --confirm --json
```

使用 x64 CLI，配套两个位数的 Agent DLL 放在 CLI 同目录，或用 `--agent PATH` 指定；标准 DLL 文件名按目标位数自动切换，自定义 DLL 校验 PE 位数。采用主程序相同的注入器、Global PID 会话租约、UTF-16 原子配置、受验证管道、子进程 broker 及 `CoverageSnapshotReceiver`。默认 R3 注入，不要求驱动、不自动提权；需要目标进程注入／VM 权限。`--r0-inject 1` 显式选择现有 R0 驱动注入，失败直接报告，不回退 R3；开启自动子进程时，broker 在身份认证后也使用 R0 注入子进程，失败直接报告。`--r0-inject 0` 为默认。目标创建时间在驱动请求前后由用户态检查，但现有驱动协议仅包含 PID，仍存在请求到驱动查找之间的 PID 复用窗口。`injectionBackendRequested` 报告选择，`reusedResident=true` 表示无需再次注入；DLL 加载或线程启动本身不等于 Hook 安装成功。help 与参数错误不加载 Agent。

必填 `--pid >4`、`--confirm`。`--duration-ms 100..120000` 默认1000，从收到根目标 HooksInstalled 后计时；`--limit 1..100000` 默认5000，保留最近事件，继续读取控制事件及覆盖快照；`--startup-timeout-ms` 默认30000、`--stop-timeout-ms` 默认15000，两者范围1000..120000。注入器和系统 API 自身的有界等待可能延长 elapsedMs。`--categories` 为逗号分隔的 file、registry、network、process、loader、clipboard、memory、thread、service、security、crypto、com、window、gui；省略时采用 Agent 默认分类，其中 gui 默认关闭。GUI 包含 GDI、绘图及 DC 调用；窗口生命周期、消息和菜单属于 window。`--raw 0|1`、`--raw-modules`、`--raw-exclude`、`--raw-default-denylist 0|1` 配置 Raw；两个列表用分号分隔。`--auto-children 0|1` 启用经过 broker 验证的后代自动注入及采集，支持 x64/x86 混合进程树。

`--options-file` 从现有 INI 的 `[monitor]` 节导入 enable_file/registry/network/process/loader/clipboard/memory/thread/service/security/crypto/com/window、auto_inject_child、capture_call_stack、enable_raw_fallback、raw_use_default_denylist、raw_modules、raw_denylist、fake_success_enabled、fake_success_raw_fallback、fake_success_rules、detail_limit、clipboard_read_action/write_action/enum_action。新分类选项缺失时继承 enable_process，显式值独立生效。可直接取主程序生成的 INI；控制端 PID、会话、管道、停止路径、SID、broker 字段一律重新生成。显式命令行选项覆盖 INI；规则使用原 Agent 的格式和能力边界，Fake Success／剪贴板拦截会改变目标行为，默认不启用。

`capture_call_stack=1` 可选择采集强类型调用栈，默认关闭，会增加开销。事件 JSON 的 `callStackAvailable` 表示该事件是否携带有效栈，`callStack` 是最多 8 个十六进制地址，可能包含监控内部帧；Raw 调用和详情空间不足时可能没有栈。空数组不代表调用方没有堆栈。

`--call-stack 0|1` 可直接设置该选项，并覆盖 `--options-file` 中的值。`--filter-file PATH` 可选导入界面保存的 `winapi-filter.cfg` v1/v2，保留被排除模块中的单函数允许例外；默认不自动加载。`--pre-exclude-modules`、`--pre-exclude-apis`、`--post-exclude-modules` 和 `--post-exclude-apis` 接受分号分隔的精确名称，API 写作 `模块!函数`，作为额外的强制排除，即使导入配置中有允许例外也会生效。模块比较不区分大小写，函数区分大小写。无路径且没有扩展名的模块按 `.dll` 匹配，例如 `KernelBase` 与 `KernelBase.dll` 等价；带路径或其他扩展名的模块不做这种转换。前置在管道接收验证后、加入有界事件缓冲前拒收；后置仅隐藏最终保留事件中的匹配项。内部控制和覆盖事件始终保留，两个筛选都不改变已安装的 Hook；`preFilteredCount` 和 `postFilteredRetainedCount` 分别报告两个阶段的数量，后者不包含此前已被缓冲淘汰的事件。

`--timeline 1` 输出按 API 分类和 FILETIME 聚合的 `timeline`：起始桶宽 10 毫秒，时间跨度扩大时自动合并到最多 2048 个时间桶；每个非空类别单元包含数量及该类别在桶内的最早／最晚时间。它统计前置筛选通过的普通 API 调用，包含后置隐藏和缓冲淘汰的事件，不包含 Agent 丢失、前置拒收或异步阶段事件；`missingTimeCount` 单独统计缺时间的调用。它不保存每个事件的图形点，也不代表完整轨迹。默认关闭，关闭时为 `null`。

Raw 入口事件的 `rawAbi` 提供 Agent 实际采集到的寄存器和栈槽十六进制值；数据截断或格式不完整时为 `null`。它们只是 ABI 位置，不代表已知函数参数个数、类型或浮点寄存器值。`--signatures 1` 可选读取 CLI 同目录 `profiles/api_monitor_definitions.json`，仅在该文件 SHA-256 与事件的 Agent 定义哈希一致时给事件附加 `declaration`，列出函数声明、参数名、类型和方向。`abiEvidence` 区分项目强类型声明、Windows SDK 已核对 ABI 与未核验第三方参考；未核验声明的方向为 `unknown`。旧 Agent 未提供哈希或哈希不同时不附加声明，分别用 `declarationCatalogMatchesAgent=null/false` 表示。声明不意味着 Hook 已安装或参数值已采集，不读取目标指针。

JSON envelope 沿用 schemaVersion=1／backend=r3。data 包含 pid、sessionId、agentPath、configPath、stopPath、configPublished、reusedResident、requestedDurationMs、elapsedMs、cancelled、completedRequestedInterval、stopWritten、cleanupComplete、receivedCount、returnedCount、bufferDroppedCount、invalidPacketCount、autoChildren、options、processes、events。计数／FILETIME 为十进制字符串，地址／会话身份为十六进制字符串。

events 提供 pid/tid、timestampFileTime、category、module/api/detail、resultKind、resultCode、eventKind、apiId、operationId、sessionIdentity、definitionSha256；EntryOnly 的 resultCode 为 null，不伪造 OK。processes 提供保留的进程创建身份、connected、hooksInstalled、hooksRemoved、targetExited、installFailed、partialHooks、pipeWin32Error、agentDroppedCount、coverageComplete/Stale/Revision、coverageStateCounts 和完整 coverage。覆盖项 state 为 Installed=0、SharedEntry=1、CategoryDisabled=2、WaitingModule=3、ExportMissing=4、RuleExcluded=5、RetryableFailure=6、Unsupported=7、Removed=8；hookKind 为 Strong=0、Raw=1、Fake=2、DynamicExtension=3。仅完整有序快照替换上一次结果，中断保留原完整数据并标记 stale。

普通业务调用事件仅在 Agent 明确标记采集成功时提供 `returnValueAvailable=true`、`returnValue`（十六进制原始位模式字符串）以及 `durationAvailable=true`、`duration100ns`（100 纳秒单位的十进制字符串）。两项独立可用；未采集值为 `null`，0 是有效值。旧 Agent、Raw 入口和没有相应标记的调用不会推断返回值或耗时；耗时只覆盖受测原函数附近的调用区间，不包含异步操作完成时间。

正常结束／Ctrl+C 均先发布停止标记、通知 broker 的全部已受理后代，再继续读到 HooksRemoved 和管道排空，或确认原目标已经退出。清理完成后释放会话租约；保留停止标记供迟到的加载线程／常驻 Agent 检查。DLL、退役 trampoline 和回调按现有 Agent 策略保持到目标退出，重复采集复用常驻 DLL。强制杀死控制端不保证优雅清理，需通过正常停止流程恢复。

`processes.finalCoverageRevision` 是 `HooksRemoved` 声明的最终覆盖修订（十进制字符串，旧 Agent 未声明时为0）。正常 EOF 不算管道故障；半包、提前断开或最终修订未收齐仍标记错误／过期。新 Agent 在安装过程中检查停止标记，取消后直接移除已提交入口并返回 `HooksRemoved`；未真正生效的 Hook 保留失败／取消原因，不伪装为已移除。

完整采集且无损失返回0；部分 Hook、Agent 丢包、缓冲截断、取消、提前退出、覆盖过期或未确认停止返回6；启动失败3，参数错误1，非 x64 宿主5。分类项不可用、保守解码拒绝和严格 CFG/CET／受保护进程仍有原有边界，完整覆盖列表不代表全部 API 已安装；任意 COM／直接系统调用不保证覆盖。

真实回归入口 `tools/Test-KSwordCliApiMonitor.ps1`，参数为 Cli、Fixture64、Fixture32、ReportRoot；自有目标源 `tools/api_monitor/cli_capture_fixture.cpp` 分别在 HostX64 的 x64／x86 编译环境以 `/MT /W4 /WX /std:c++20` 编译。脚本验证真实文件事件、双位数选择、常驻复用、输出截断、配置隔离、会话冲突和跨位数子进程，保留每次 JSON 回执与正常退出证据。

## ETW（迁移项 41）

```powershell
KswordCLI.exe help monitor
KswordCLI.exe monitor etw help
KswordCLI.exe monitor etw providers help
KswordCLI.exe monitor etw providers enum --json
KswordCLI.exe help monitor etw capture
KswordCLI.exe monitor etw capture --provider Microsoft-Windows-Kernel-Process --duration-ms 1000 --json
```

`providers enum` 返回共享后端的 34 个保留 Kernel Provider 预设及默认启用／级别／关键字设置；这是静态预设，不枚举当前系统所有 Provider，不创建会话。`capture` 支持 `--provider default`（默认启用预设）、一个预设名称或标准 `{GUID}`，`--duration-ms 100..120000`（1000）、`--pid`（正数，事件头记录上下文）、`--target-pid`（正数，只匹配明确的载荷目标）、`--decode 0|1`（默认 0，使用目标筛选时自动启用）、`--level 0..5`（5，最大详细程度；0 由 Provider 定义）、`--keywords`（64 位十进制／十六进制，0）、`--limit 1..100000`（5000，保留最近行数）。均支持 `--backend r3`、`--json`。

使用原共享实时 ETW 控制器启用 Provider、消费事件并在限时／取消后停止自己创建的会话、关闭 consumer、join 线程；名称包含 PID、计时和进程内序号，碰撞直接失败，不停止同名既有会话。要求相应 ETW 会话和 Provider 权限，不自动提权或启用权限，不调用驱动。开始控制器返回不等于消费线程成功；所有原始步骤独立记录，默认预设部分启用失败也只能返回部分结果。成功启用未注册／未发射的 Provider 可以无事件，不能据此宣称 Provider 有事件活动。

data 提供 source、requestedDurationMs/elapsedMs、cancelled、sessionName、startAttempted/startSucceeded/startWin32Error、threadStartFailed、providers（name/guid/enabled/win32Error）、enabledProviderCount、openAttempted/openWin32Error、processAttempted/processCompleted/processTraceWin32Error、closeAttempted/closeTraceWin32Error、sessionStopped、stopWin32Errors、consumerJoined、statisticsKnown、eventsLost/logBuffersLost/realTimeBuffersLost、receivedCount/filteredCount/matchedCount/returnedCount/droppedFromBufferCount、callbackFailed、filter 和 events。未调用或未取得的状态／丢失统计为 null；计数为十进制字符串，关闭返回待完成状态与已 join 的证据分开保留。

completedRequestedInterval 表示采集是否等待完请求时长；消费者提前正常结束也返回部分结果，不把 ProcessTrace 返回 0 当作足时采集。事件提供 timestampFileTime（系统时钟 FILETIME 的十进制字符串）、localTimeDisplay、providerGuid、headerPid/headerTid、eventId/version/level/opcode/task、keyword（十六进制）、summaryDisplay。headerPid/headerTid 代表记录上下文，不能冒充被操作目标；`--pid` 筛选按此语义进行。会话显式选择系统时钟时间域，避免把 QPC 当作 FILETIME 显示。

可选 TDH 载荷解码在事件回调期间读取当前真实 schema，输出 eventName、原始入参类型和顶层字段；单事件最多 32 个属性、每个属性最多 2048 字节，并保存最多 256 字节原始载荷十六进制前缀。数组、结构体、自定义 schema 和不可读取字段不猜测布局，`complete=false` 与 `skippedPropertyCount` 保留解码边界；无 TDH 信息时保留错误码及原始前缀。解码结果除行数限制外还受 16 MiB 总预算约束，淘汰行计入 `droppedFromBufferCount`，ETW 提供者／会话丢失计数独立保留。

`--target-pid` 仅匹配顶层标量 `TargetProcessId` 或 `NewProcessId`，不将事件头或一般 `ProcessId` 当成目标。缺少或无法可靠解码目标的事件不视作匹配，计入 `targetUnknownCount`；确定不匹配的计入 `targetFilteredCount`。因此匹配结果并非所有关联目标事件的完整集合；存在未知目标或部分解码返回 6。`--decode` 解码过程在 ETW 消费线程执行，可能增加高频采集压力，应结合 provider、级别、关键字和损失统计判断证据。当前仍为限时收集后输出，不提供持续流式输出。

完整采集／清理且无损失为 0，完整有效空结果也为 0；启动／打开／无可启用 Provider、消费失败且无结果为 3（明确未支持为 5）；部分启用、事件丢失、缓冲区丢行、回调错误、取消、采集或清理不完整为 6。限时约束采集等待，原生 API 和消费者退出可能延长 elapsedMs，不宣称原生操作硬超时。停止失败时保留会话所有权，关闭消费者并在 join 后重试停止；原失败回执不会被后续成功覆盖。测试日志不放入项目目录；VM 用自建 SDK Provider 发射固定描述符，通过独立状态核对事件与缓冲区丢行，并用 logman 核对会话已消失。help 不创建 ETW 会话。启用异步返回与消费者待关闭定义见 [EnableTraceEx2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)、[CloseTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace)。
