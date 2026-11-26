# ActionAnalyze 普通 R0 准入核查

2026-11-25。**指定来宾的普通 R0 准入被 OS build 检查阻塞。** VMware 缓存报告 build `26100`、完整版本 `26100.9711`。当前驱动源码要求 `RtlGetVersion().dwBuildNumber == 26300`。已验证正式 Release CLI 的能力公告及停止组离线契约。普通 R0 专项来宾运行共 `0 / 29` 项。

范围以[双后端设计 §4–6](../../docs/ActionAnalyze双后端独立全流程设计.md#4-选择独占与资料身份)、[通信设计 §5.1、§7.4](../../docs/ActionAnalyze多通道通信与控制施工设计.md#51-r0-通知与权威状态分别持有)、[A4–A7 施工表](../../docs/ActionAnalyze施工任务与契约落点.md#4-a4a7真实控制来源传播及执行)及[指定来宾工程基线](../../docs/ActionAnalyze工程开工基线.md#验收范围与运行环境)为准。源码采样时工作区 HEAD 为 `235bc23a31234424364be8a65d940ce2b5665472`。CLI 和 SYS 的身份分别按下文实读哈希登记。

## 指定来宾及证据时效

| 核查项 | 实际读回与判定 |
| --- | --- |
| 目标与 OS | `E:\VMs\Windows11-24H2\Windows 10 x64.vmx:121` 的 VMware Tools 缓存为 `bitness='64'`、`buildNumber='26100'`、`kernelVersion='26100.9711'`。原始 `prettyName` 为 `Windows 10 Home, 64-bit (Build 26100.9711)`，工程基线登记为 Windows 11 24H2。VMX 文件名、`displayName`、`guestOS` 和缓存营销名称不参与驱动 build 判定。 |
| 最后运行状态 | `E:\VMs\Windows11-24H2\vmware.log:2297` 记录 VMware Tools 提交 guest detailed info。第 2303 行记软挂起成功，第 2615 行在 `2026-11-25T02:42:35.361Z` 记录 `suspended`。VMX 第 123 行保留对应 `.vmss` 引用。`2026-11-25T04:29:35Z` 以 `Win32_Process` 匹配该 VMX 的宿主进程为 0。以上均为宿主读取，来宾实时 OS 和服务查询未执行。 |
| OS、平台与映像条件 | 从 VMX 提取 `26100`，从实际源码谓词提取 `26300`，等值检查为 `false`。同一准入路径还分别检查代码完整性状态、单处理器组、当前 AMD64 PE 身份、RSDS GUID/Age 及上下文例程。私有映像条目包含 `26100.9711`，其数值属于 PE 版本。该条目无法满足独立的 OS build 谓词。[驱动准入源码](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach_hook.c#L86) |
| 来宾服务与策略 | 上一批工程环境记录为已有 `TESTSIGNING`、`KSwordARK` 服务未注册、驱动未加载，配套签名候选未暂存。本轮缺少来宾实时 SCM、驱动和安全状态回执。[工程基线](../../docs/ActionAnalyze工程开工基线.md#验收范围与运行环境) [工程推进记录](../../.claude/memory/ksword-action-analyze-engineering.md#当前验收决定) |
| 现有宿主 SYS | `Ksword5.1/x64/Release/KswordARK.sys` 为 3,665,008 字节，SHA-256 `96F6310DC74C72ECA4FA3FDD7EDC35F8E0CEE1F394A7BC10FDA2D8E9892CEC39`。宿主 `Get-AuthenticodeSignature` 返回 `UnknownError`、`Authenticode`，状态消息明确指出证书链终止于不受信任根。该结果仅对应此文件与宿主信任库。该文件与本批来宾运行证据未绑定。 |

## 实际运行的只读核验

| 项目 | 实际结果 |
| --- | --- |
| 宿主缓存准入负控 | 使用 PowerShell 只读提取 VMX OS 字段、VMware 挂起记录和源码 build 谓词。断言退出 `0`，确认 `26100 != 26300`。此回执属于元数据和源码对照。 |
| 正式 CLI 能力正控与负控 | 在宿主运行现有 `Ksword5.1/x64/Release/KswordCLI.exe`，三次调用前后 SHA-256 均为 `52185FAECBCE347C9FF8CF98A3F818447ADB4C8AA593817F50B766B8E01497AC`。`analyze capabilities --backend offline --json` 退出 `0`，外层 `status=success`，`data.backend=offline`、`data.nativeCapture=false`、`data.schemaVersions=[1]`。12 项方法与目录逐项一致，无 `control.*`。将同一命令的后端分别改为 `r0`、`r0-noattach`，两次均退出 `1`，返回 `status=failed`、空 `data` 与 `unsupported backend for this command`。这是 ActionAnalyze 当前命令入口的可用性证据。[方法目录](../../schemas/action_analyze/method-catalog.json#L1) [命令登记](../../KswordCLI/ActionAnalyze/Cli/Commands.cpp#L142) [分派前校验](../../KswordCLI/CommandRegistry.cpp#L217) |
| 停止组序列化 | 按 schema README 的向量校验运行 `python -B -`，通过 `96 / 96` 项，退出 `0`。该组检查确认冻结集合、命中 origin、附带暂停、未来线程门控及未决责任的投影约束。真实停点归属、具体继续权限和逐项恢复需由控制所有者证明。[验证命令](../../schemas/action_analyze/README.md#停止组只读投影草案) [快照契约](../../schemas/action_analyze/stop-group-snapshot-draft.md) |

驱动确有独立的 `KERNEL_NOATTACH` 控制入口和 `QUERY` 分支。合法无会话查询可返回驱动能力与 `CLOSED`／`UNSUPPORTED`。预检会初始化内部锁或填充诊断缓存。已有真实会话的同文件 `QUERY` 会刷新本会话的租约。`OPEN` 才进入明确的内核修改安全门禁及异常消费安装流程。因此历史读取只使用归档，普通 R0 专项 T01 仍须保存指定来宾上、未 `OPEN` 时的真实驱动状态回执。普通 Driver CI 排除了该控制入口的 `OPEN`，且相邻 `KERNEL_NOATTACH_PROBE` 实验入口有单独的危险操作排除。[注册表](../../KswordARKDriver/src/dispatch/ioctl_registry.c#L388) [控制入口](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach.c#L367) [租约分支](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach.c#L495) [IOCTL 门禁](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach_ioctl.c#L26) [CI 排除项](../driver_functional_ci/driver_test_plan.json#L3082)

## A4 / A7 验收缺口

| 工单 | 当前能定位的实现 | 待取得的验收证据 |
| --- | --- | --- |
| A4.1 恢复账本 | 单全局会话，只有 primary 持异常现场，另有 7 个附加线程的 OS 挂起槽。批量恢复忽略各项 `Resume` 返回并清空槽，`KnaReleaseIdentity` 先发布 `CLOSED`。旧前端的临时上下文读取另调 `SuspendThread`／`ResumeThread`，失败仅留下恢复标志等有限信息。[会话结构](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach.h#L35) [批量释放](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach.c#L149) [临时读取](../../DebuggerBackend/KswordIndependentFrontend.cpp#L528) | 每项是否归还、退出或仍欠恢复的权威回执。第 N 项失败时保留同一对象及精确重试权，保护和上下文责任在同一账本，保留外部挂起。 |
| A4.2 Query、Wait 与失联 | 已有同文件／同进程所有者查询校验和对应文件清理回调。30 秒租约由查询续期，超期检查位于异常处理等待。该控制入口使用同步分派，尚无 A4 专用的逐文件 `WAIT` 取消、状态序列和独立 watchdog 证据。[Cleanup](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach.c#L250) [查询校验](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach.c#L495) [异常等待](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach_events.c#L103) | 真实通知丢失后可权威查询。取消与完成竞态、不同文件相互隔离、所有者退出、文件 cleanup、无新异常时的超时回收和恢复失败持续可查。 |
| A4.3 三端消费与同步路由 | 旧静态审计里的 Qt `reason=5`／最多八条回读缺陷，当前已有编译期校验覆盖合法普通响应和越界负控。原生 facade 另行检查应答头与容量。普通异常分支当前接受限定线程的已登记 AV/DR/TF，Agent 的已绑定同步软断点入口仍缺证据。正式 CLI `controller.capabilities` 只登记离线能力。 [Qt 解析器](../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkHvmNoAttachClient.cpp#L7) [原生 facade](../../DebuggerBackend/KswordDebuggerBackend.cpp#L318) [异常范围](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach_events.c#L176) [CLI 能力](../../KswordCLI/ActionAnalyze/Cli/Controller.cpp#L77) | 两条回读路径通过真实合法包、旧包、坏包和未决责任负控。三端分别证明同一停点只能继续一次，按选定后端接管和恢复，未验证范围拒绝严格同步绑定。 |
| A7.1 区域及版本 | 旧前端记录一个查询得到的原保护和范围，保护修改先于驱动登记。回滚及退休均有忽略 `VirtualProtectEx` 结果的路径。[旧观察槽](../../DebuggerBackend/KswordIndependentFrontend.cpp#L382) | 实际写入范围、映射／内容代次、分页保护事务、别名／COW 与同址重用的独立回执，覆盖 P01–P16 对应的 D/X/P/A 判据。[路径矩阵](../../docs/ActionAnalyze执行覆盖与逐路径验收.md#3-路径矩阵) |
| A7.2 执行屏障与重设防 | AV 显式限定 primary 并在命中时清空观察槽。线程通知只处理 primary 退出，未提供新线程准入。旧前端命中后退休观察槽并尝试恢复保护。[AV 消费](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach_events.c#L69) [线程通知](../../KswordARKDriver/src/features/kernel_noattach/kernel_noattach.c#L293) [旧前端命中](../../DebuggerBackend/KswordIndependentFrontend.cpp#L281) | 真实执行尝试／实际执行独立计数，完整执行者和新线程门控，已知页绑定 `regionReady`，复位 NX 并读回后再释放其它责任，覆盖共页／并发、跨页和关闭时恢复失败。 |
| A7.3 栈与控制转移 | 暂无普通 R0 ActionAnalyze 产品证据链贯通真实异常与保护来源、帧／槽代次、执行交接。[A7.3 验收条目](../../docs/ActionAnalyze施工任务与契约落点.md#L69) | 实际保护失败及控制转移证据、帧槽退休与资源冲突。良性切栈、尾调用和展开作为独立负控。[验收对照](../../docs/ActionAnalyze成品验收对照.md#L76) |

本轮普通 R0 外部判据 `T01–T29` 全部为 **未执行**。宿主能力回执、停止组离线向量、旧 Qt 回读编译记录和历史 R3 夹具各按自身范围计数。指定来宾运行、三端真实消费、端到端首跳与多跳、故障恢复和性能均无本轮普通 R0 回执。验证使用既有统一 Release 二进制，产出为本报告，未生成构建或测试配置。来宾未启动或恢复，无来宾登录、驱动加载、设备 IOCTL 或策略变更。
