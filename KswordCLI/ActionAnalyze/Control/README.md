# A4.3／SB CLI 停止责任账本

`StopLedger` 由 CLI 的单一控制执行者串行调用，接收外部调试 owner 为自有合作目标核验的原生事件证据。当前模型支持每个 owner 一条待处理 Debug Event 和顺序发生的多组停点。事件 owner 保存真实句柄、异常处置、事件序号及调用结果，并负责在错误或拒绝后继续持有实际事件。输入使用采样、后端、进程和线程的强实例 ID。源证据的原生身份核验归事件 owner。

| 接口 | 接入职责 |
| --- | --- |
| `Freeze(FrozenStopGroup)` | 在开启停点路由前预留记录。冻结请求线程、成员修订和上游计算的 SHA-256。规范化线程顺序并检查重复。本地检查 hash 文本格式，成员规范编码和 hash 计算归冻结范围的调用方。 |
| `AdoptNativeStop(groupId, NativeStop)` | 收到已认领的真实事件后导入。owner 实例和单调事件序号构成事件身份。原始站点异常和不同代次由适配器事先区别处置。已确认归属但阶段未知时，`phase` 留空并保留实际事件线程及责任。 |
| `ObserveMember`、`ObserveIncidental`、`SealMembership` | 提交逐项证据。仅同一原生事件进程内、经核验的冻结成员可标记为覆盖。附带线程独立提交集合质量，排除请求成员及独立展示的 origin。多个成员共享同一原生责任和 `stopId`。`SealMembership` 只结束首轮成员收集，后续仍可接受有序证据。 |
| `BeginRelease`、`QueryRelease` | 校验活 owner、epoch、事件身份、`stopId` 和预期状态修订。首次接受返回单次 `effect`。接受过的同 ID 同载荷返回 `Duplicate`，可查询原请求回执。同 ID 异载荷返回冲突。CLI 传输仍负责全局请求 ID 及拒绝回执的幂等。 |
| `RecordReleaseReceipt`、`RecordReleaseReadback` | 保存 exact attempt 的原生结果。成功只确认自身事件责任已释放。`StillPending` 需要核验事件确实未消耗，且旧尝试无法再调用 Continue。确认后可用新命令和当前修订明确重试。超时、结果丢失或未核验的失败保留待确认或恢复责任。 |
| `ObserveOriginExit`、`RecordRetiredOnExit`、`ConfirmNoNativeEvent` | 可单独记录范围外 origin 线程退出。退休需要证实精确原生事件已清退且其进程确实退出。无事件路径先确认路由没有武装或已排空，再结束证据已明确的冻结组。 |
| `Query`、`UnresolvedNativeResponsibility`、`CanRetireLedger` | 读取只读投影及内部仍待处置的事件责任。关闭调用方把后者作为独立门槛，继续核对路由清退、其它资源和真实脱离。 |

`HeldComplete` 适用于当次冻结成员。附带集合处于 `Partial` 或 `NotCollected` 时，真实事件仍保持全部进程级释放责任。附带成员在终态中保留为历史观察。确认继续后，原来未知成员的 `NotHeld` 只描述本账本已无持有，`MemberSnapshot::evidence` 仍保留当时证据。事件与成员状态均无法证明线程已经调度执行。

内部快照的 `nativeEventState` 保留组内原生事件的最后责任状态。相同的成员汇总（如 `Ended`）可对应已确认继续的 `Released`、已核验退出清退的 `RetiredOnExit`，或从未接纳原生事件时的空值。`Retryable` 和 `Indeterminate` 也分别保留。该字段只提供状态，不含原生事件身份或控制令牌。

`StopGroupSnapshot` 为内部类型。全部冻结成员已确认退出且原生 origin 仍持有时，内部投影 `OriginHeld` 对应草案的 `origin-held`。已提交释放和待恢复分别优先投影为 `ReleasePending` 和 `RecoveryRequired`。原生事件仍持有但 origin 已退出，或缺少可投影阶段且没有已核验成员持有时，内部保留 `UnprojectableNativeHold`。调用方使用内部责任查询继续追踪，不能把该状态写成终态。公开 JSON 投影、成员分页和命令注册是后续接入。本增量的释放单位是单个原生事件。指定单个成员继续、显式 Suspend/Resume、多个原生事件待决、其它资源回退、未来线程准入门控和 owner 死亡接管需独立验证。

每个账本保留 64 个组，每组最多 1024 个请求成员、1024 个已知附带成员和 64 条已接受释放命令。达到上限时保留已有账目，并返回 `Capacity`。如发生在恢复路径，仍可提交确切结果、读回或退出清退证据。下一步接入须核对预留失败和重复请求。冻结成员、已接受命令和历史组保留至该账本退休，历史组从未提供继续动作，重启后恢复实时控制不在本增量范围内。

从仓库根目录运行 `pwsh -NoProfile -File KswordCLI/ActionAnalyze/Control/tests/Invoke-Validation.ps1`。隔离工程构建并直接运行 `Ksword5.1/x64/Release/ActionAnalyzeStopLedgerValidation.exe`。测试沿用 [离线协议模型](../../../tools/trace_protocol_validation/test_protocol_model.py) 的重复命令、旧 epoch 和清理责任判据，直接编译并执行此处的 C++。构建和测试证据保存在 `.codex-build-logs/behavior-planning/action-analyze-cli-stop-ledger-*`。

原生接入门槛是同一真实调试 owner 关联 SB02 自有夹具，验证事件采用和 Continue 唯一性、丢失回执后的读回语义、关闭交错、成员及实际目标退出。原始 OS 处置与验证仍由实际适配器提供。

## CLI 的 R3 执行断点 owner

`NativeDebugOwner::ArmBreakpoint` 只接纳当前 CLI 宿主直接创建、显式授权且 PID 与创建时刻匹配的同用户同会话原生 AMD64 子进程。不派生采样对象，只有一个目标实例、一个断点绑定。使用当前已加载映像的完整 DOS 路径和 RVA 或区分大小写的非转发 PE 导出名，不支持 PDB、延迟加载绑定、WOW64 或其它后端。RVA 必须由调用方确认是指令边界。模块卸载触发退役，不自动跟随同址映像。

- `ArmBreakpoint` 的 `Accepted` 只表示已提交附加。以 `Query().breakpoint.state` 回读 `Armed`、`Held` 或退役/失败。初始停点完成武装，新线程在 `CREATE_THREAD_DEBUG_EVENT` 尚未继续时安装并读回同一 DR0 执行断点；有其它活动调试寄存器或 TF 时不接管。
- 命中形成停止组时，以及明确继续／步进释放事件之前，原 owner 按实际线程对象补齐登记；枚举先于创建事件看见的新线程也沿用当前绑定。步进中新增同伴由原步进运行时取得一次挂起计数，创建事件随后到达时不重复挂起。停止组及其 origin／寄存器仍保持原事件身份。NX 模式仅登记强线程对象，不使用或覆盖 DR0／TF；真正发起步进时仍单独核对所选线程的竞争状态。这一增量尚未构建或运行验证。
- `Query` 在实际单步异常到达并通过事件、进程、线程、地址、DR6/DR7 复核后提供 `breakpointHit`、停止组和继续义务。组中的线程是本次冻结快照；原生事件暂停目标进程，不暂停其它进程。使用完整 `ReleaseRequest` 继续同一个事件，历史回执可查询，重复命令不会再次放行。断点正常继续后仍保持绑定。
- `Close` 撤销整个绑定。在未继续的工作事件或受到核验的标准调试中断上恢复自有寄存器，再继续并脱离。确认失败则保留相应责任和错误，可用 `Query` 观察；不把请求成功算作清洁脱离，不保证任意 owner 死亡后恢复。最多核验 1024 个活线程，保留 63 次断点命中，继续最后一次命中时退役；不得把容量退役当作持续覆盖。

正式 CLI 已登记 `NativeDebugOwner`、`NativeBreakpointImage` 和 `StopLedger`，实际入口为 `analyze breakpoint session`。HostX64 Release 增量构建已通过。未验证三端一致性、性能或普通 R0。

正式 `KswordCLI.exe` 的 JSONL 和 REPL 合计通过 30 项运行检查。独立确认首次命中前函数体未执行，有效继续后执行，同址再次获得不同停点；停止时退出，回执为 `clean=true`、`attached=false`，原子进程第二次执行后退出 `0`。JSONL 的旧修订和重复继续 ID 均未放行第二次停点。正式运行日志为 `.codex-build-logs/behavior-planning/action-analyze-product-breakpoint-20261125-033030-7079019-run.log`。

## 合作目标清退回执

- `NativeControlResult::retirement` 只记录成功的 `DebugActiveProcessStop`，或经 `ContinueDebugEvent` 成功消费的精确退出事件。退出事件回执保留 owner、原生事件序号及退出码。未附加的拒绝可以 `clean=true`，但没有调试清退回执。
- `firstRecoveryFailure` 保留当前记录最早的未清退错误和当时的事件身份。恢复寄存器失败、尚未调用 Continue 时，`StopLedger` 保留该精确事件与 `StillPending` 回执，允许用当前修订重试。原生 Continue 结果不确定时仍保留 `Indeterminate`，不重发，也不将后续查询当作恢复。清退成功后仍可对账首次错误与最终回执。
- `OwnedBreakpointGroup` 保留发起清退的原因和各成员的原生结果，`exitCode` 来自启动时保存的进程对象已经发出终止信号后的读取。`clean` 只表示启动门及原生调试责任都已清退；启动门已打开的合作目标可继续运行并在随后查询时报告退出。调试所有者死亡后的自动恢复未受支持；关闭 Windows 的 kill-on-exit 行为不证明事件、线程或寄存器已恢复。

从仓库根目录运行 `pwsh -NoProfile -File KswordCLI/ActionAnalyze/Control/tests/Invoke-NativeDebugOwnerValidation.ps1 -RecoveryOnly`，只构建并运行独立合作双目标夹具。用例覆盖开门前取消、目标正常退出，以及可重试的断点恢复冲突。

2026-11-26 CodeBuddy：原生 `1072 PASS`；正式 CLI `--cooperative-pair` 主动关闭双脱离、自然退出双回执，进程句柄读回退出码 `0 / 0`。日志位于 `.codex-build-logs/behavior-planning/`，分别以 `action-analyze-native-debug-owner-20261126-054714` 和 `action-analyze-product-breakpoint-long-20261126-055730` 开头。

## 原生停点步进控制接口

`NativeStep.h` 定义本端内部请求和回执，`NativeStepRuntime` 只在原 `NativeDebugOwner` 调试线程上管理 TF、DR1 与线程挂起债务。没有第二个 debug owner，也不依赖目标线程执行清理代码。CLI、Qt、Light 的控制工程均登记这些源；各端实际入口及运行验收分别记录。

| 接口 | 语义 |
| --- | --- |
| `Step(NativeStepRequest)` | `release` 携带完整 owner、group、stop、原生事件和预期状态修订，`thread`、`tid`、`threadCreationTime` 必须是当前事件的精确强线程实例。`release.requestId` 使用 `continue/N`，和普通继续共用内部单调序列。 |
| `QueryStep(requestId)` | 返回该内部请求的回执；最多保留 128 条。Running 仅表示原事件已释放并等待步进事件；Completed、Interrupted、Cancelled 等状态须结合 `resourcesRestored`、`stopGroupId` 和当前恢复状态解释。历史回执不授予新的控制权。 |
| `CancelStep(requestId)` | 在原调试 owner 中请求中断，随后在实际原生事件上恢复资源并形成新停点。调用返回不等于已清退或已恢复执行。 |

`Into` 使用与 NX 跨页取指相同的有界 AMD64 长度解码，支持其已登记的普通内存读写、算术、分支、near CALL／RET 和部分 SSE／AVX 编码，不再限制为寄存器运算的小白名单。只读取实际一条指令，最多15字节；长度不代表完成，仍由精确线程的真实 BS 事件确认。`OverCall` 在精确解码的 `E8` 或 `FF /2` CALL 返回边界用选中线程 DR1 停止；其它受支持指令使用同一owner的一次TF，保留请求模式且`destination:null`，不按指令长度猜测下一IP。后一种真实单条TF完成可形成`instruction-completed`，CALL返回边界不形成该证据。Qt、Light和CLI及执行集合复用同一机制。`Out` 仅接受实际 `C3` 返回边界，或本 owner 刚以真实 CALL 单步捕获、RIP/RSP/栈上返回地址仍一致的入口帧。未知指令、未知调用帧、POPF／SS／特权转换、用户 INT3 冲突及竞争 TF/DR 状态明确拒绝，不猜指令长度或任意栈槽。新增普通指令及步过支持尚未构建／实测。

步进期间其余已登记线程增加且仅恢复本端一次挂起计数；新线程在其创建事件继续前先门控。完成或应用异常中断形成新停止组，旧组保留已继续回执。普通步进停点没有 `breakpointHit`；提前命中原有 DR0 用户停点时保留原命中语义。调用方只能在实际 `breakpointHit` 上执行断点条件自动继续，不能把前一次条件带到新的步进停点。应用异常的继续保持原生异常分发，未证明为本端事件时不吞异常。

本批原生实测与未覆盖范围由作者派发的 CodeBuddy 写入 `docs/action-analyze-planning/native-stop-stepping.md`；本段接口说明本身不代表测试通过，不改变 owner 死亡恢复、普通 R0 或 GUI 的既有边界。

## 私有执行位置绑定接口

`NativeBreakpointRequest::executePointerExport=true` 选择映像中的 AMD64 指针数据导出；同时要求 `writeWatchBytes=0`、`writeWatchPointerExport=false`、没有 RVA 且导出名非空。该模式保持执行 DR0 与 `ExecutionEnterAttempt`，不产生数据变化掩码。`NativeBreakpointBinding::executePointerExport` 区别间接执行与间接写关注；`address` 是实际执行地址，`rva` 是选择器数据导出的 RVA，`pointerExportAddress` 是选择器地址。

`NativePrivateExecutionSite.h` 提供 `ResolveNativePrivateExecutionSite` 与 `VerifyNativePrivateExecutionSite`。前者复用同一 AMD64 PE 导出解析器，允许可读的非执行映像数据（含只读数据），读取完整且对齐的 64 位指针。目标必须为已提交的 `MEM_PRIVATE` 区域，保护为 `PAGE_EXECUTE`、`PAGE_EXECUTE_READ` 或 `PAGE_EXECUTE_READWRITE`，排除空指针、非执行和 Guard。它冻结选择器区域、指针值、目标分配基址、区域边界及保护属性，不修改内存或页面保护。

安装期间、每个新线程登记前、每次命中及步进新停点接纳前、原生事件放行前核对这些属性。发现变化时清退原绑定及本端调试资源，不重新解析并跟随新地址。复核来自停止期间的原生观察；外部进程并发改写仍可能发生，不能将属性相同当成分配代次相同，也不证明代码字节未改变。选择器所在模块卸载沿用原模块卸载清退路径。

合作目标沿用调用方的 Ready/Gate：先完成私有代码初始化并公开指针，等待绑定实际 `Armed` 后再运行；EOF 取消由原合作入口处理。本 owner 不另建目标控制管道或调试所有者。支持的私有指令 Into 继续使用原 TF 白名单和 StopLedger；`PAGE_EXECUTE` 绑定不保证调试器有权读取指令，解码不可用时必须明确拒绝。

用户已暂时禁止 CodeBuddy 新派发、续接和失败重试。本批只完成核心实现及工程依赖登记，没有替代测试、GUI 或产品构建；RX/RWX 正例、负控、新线程、旧停点与清退的真实运行证据仍待恢复 CodeBuddy 后验收，并由其写入 `docs/action-analyze-planning/private-execution-watch.md`。原生步进先前失败记录也尚不能由此实现声明关闭。

## 停点调查与项目证据

`CaptureNativeStopMemory` 借用断点／步进会话的原 `NativeDebugOwner`，在同一调用方串行控制线程执行。请求必须带当前会话采样及用户显示时冻结的目标、完整停止令牌和明确读取范围，且只能使用 `HeldEvent`。读取前后分别查询原 owner；不申请暂停，不提交继续，也不创建第二个调试所有者。旧修订、事件、会话或目标不一致时拒绝，不回退实时读取。

`NativeStopRegisters` 在实际命中／步进停止时一次采集 AMD64 的全部通用寄存器、RIP 和 EFlags；`NativeStopRegisterFields` 为三端详情及条件的唯一目录。`NativeStopCondition` 按调用者原阶段生成有序字段绑定，投影时核对实际事件线程，不对运行线程补读。新增字段使用 `stop.thread.<小写寄存器名>`，均为 u64；EFlags 零扩展。Query 不重新采集，主动暂停仍不形成寄存器或执行证据。本批仅源码接线，构建与运行待验。

已保存RVA定义的可选 `imageSha256` 沿冻结sample传入 `AttachImageExecution`／`NativeBreakpointRequest`。`NativeBreakpointImageIdentity` 保留原调试装载事件文件，用实际模块基址选择，再通过原文件对象的独立读句柄流式计算SHA256，全部相符后才安装DR0。不会重开同名路径替代原装载文件；不能取得事件文件或散列不符则拒绝并由原owner清退。绑定只发布实测成功值，不认证目标映像页的运行时内容。三端接线及工程登记已补，尚未构建／运行；PDB定位仍未实现。

原生步进的新线程和冻结枚举统一使用 `NativeStepRuntime::HoldPeer`，按保留句柄对象及PID／TID／创建时间登记，同一对象不重复Suspend。CREATE_THREAD由 `EnrollCreated` 核对真实事件；枚举先发现的线程仍可在当前事件中经 `Enroll` 纳入。EXIT_THREAD在原owner移除槽位前提供强句柄，只免除对应对象自己的暂停／上下文责任，不能用所选线程退出抵消其它peer债务。进程级免除要求真实退出事件或原强进程句柄终止。重复DR0登记回读实际槽位；NX异常线程尚未登记时，在当前异常事件内补齐真实线程覆盖后再判定命中。此批只更新共享原生路径，Qt／Light／CLI沿同一owner消费，未构建或运行。

读取复用 `SelectedMemorySnapshot`，成功页保留实际字节，失败页保留原错误，不填零。结果中的 `completeRange` 只描述范围字节；`heldAtBothChecks` 独立描述前后两次精确停点核对，不能声称其它进程的外部写入者也已冻结。`WriteProcessGroupMemorySnapshot` 把读取模式及两个停点随字节写入独立 `raw-memory` 段。

`OwnedDataWatchSession::Start` 可接受项目已登记的 `sampleId`；省略时沿用独立采样身份。绑定必须在启动前确定，保存不能事后将旧结果改写为另一采样。`CaptureMemory` 复用原 owner 及上述读取路径，`SaveExecution` 则从原 owner 重新查询精确当前事件后调用 `WriteNativeExecution`。两者都不执行写入条件的自动继续；普通写入停点不会因保存操作生成执行事实。执行观测保存到独立 `raw-native`，历史读取不构造活继续请求。

调用方保留同一项目写租约、各流的已核验前序和写入失败回执，继续及清退仍归原会话。桌面接线和正式 CLI 命令由各端独立组织；本节记录源码接口，不替代真实运行回执。
