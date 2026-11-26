# ActionAnalyze 跨进程证据图读侧接线

> **当前约束：** 产品仅使用 KSword 自有采集链路。下文涉及 Sysmon 的方案及向量为已取消的历史设计，不是读侧输入、后续工单或验收依据。替代路线的实测边界见 [AA-10](validation-handoff.md#aa-10-ksword-自有线程创建证据)。

2026-11-25 工作区源码核对。覆盖产品验收第 4 项的证据读取、投影和回查。`BuildCrossProcessEvidenceGraph` 已有实现和独立 C++ 夹具。第 7 节记录只读归档适配器，CLI 已接入显式图视图。Qt 的底部对象图和 Light 的引用预览仍是后续接线入口。本页产品验收用例均待执行。[产品验收清单](../ActionAnalyze产品验收清单.md) · [图接口](../../KswordCLI/ActionAnalyze/Detection/CrossProcessEvidenceGraph.h) · [图夹具](../../KswordCLI/ActionAnalyze/Detection/tests/CrossProcessEvidenceGraphTests.cpp)

## 1. 三端投影入口

三端由本端工作任务持有读取请求和不可变结果。先冻结 `projectId`、`sampleId`、`descriptionHash`、采样来源和已核验水位，再把该页的类型化事件或带锚点的上下文交给 `BuildCrossProcessEvidenceGraph`。在读取器仍持有已解封正文时做来源适配。完整原包和可回读位置归来源读取器，界面只持有有界证据投影。对需要段尾或检查点确认的输入，先暂存本段投影，复核通过后才并入视图。同一冻结范围三端共用判据和锚点规则，各自发布界面或命令结果。[项目原始证据接口](../../KswordCLI/ActionAnalyze/Project/ProjectRawEvidence.h) · [图实现](../../KswordCLI/ActionAnalyze/Detection/CrossProcessEvidenceGraph.cpp)

| 端 | 已有可达入口 | 计划接点 |
| --- | --- | --- |
| Qt | 「监控 → 行为分析 → 项目与采样 → 打开采样归档」，`ActionAnalyzeWorkspace.cpp` 调用 `OfflineSegmentOverview::openSampleArchive`。也可在「总览」打开独立归档段。`OfflineSegmentOverview::openSegment` 把冻结请求交给后台 `ReadOfflineSegment`。 | 在 `OfflineSegmentReader.cpp` 的 `ReadCommittedSegment`、`ReadQtRawReplay` 和 `ReadStandalone` 的 API 解封分支暂存少量 `GraphInput`，沿用各分支的完整性门槛。在后台生成与事件表共享身份及水位的快照。用 `OfflineSegmentOverview.Loading.cpp` 的 `ResultTableHost::submitGroup` → `publish` → `setActiveSnapshot` 同代次发布。`OfflineSegmentOverview.Objects.cpp::updateObjectEvidence` 是底部展示和回跳接点。现有 `OfflineObjectEvidence` 的样本内对象引用保留原标签，强关系使用带类型的节点键。Qt 当前未归档的实时行有本端观测序号，可继续作实时详情，等可寻址的事件位置或已核验 raw 位置出现后再进入该图。 |
| Light | 「监控 → ActionAnalyze → 打开归档 → 回放采样」，`MonitorFeature.cpp` 通过 `WorkspaceHost` 延迟创建 `CreateActionAnalyzePage`。`ReplaySelectedSample` → `Open` → 后台 `Load` → `ReadProjectReplay` 或 `OpenStoredEvidence`。 | 在 `ProjectReplay.cpp::ReadRawSegment` → `StoredEvidence.cpp::ReadOpenStoredEvidence` 的解封路径提取事实，按 `ReadProjectReplay` 的连续检查点门槛发布。`Load` 构建图和原生行视图，`PublishSnapshot` 一次交换快照。`UpdateDetails` 和 `PaintGraph` 所在的底部引用区承接同一证据，窄窗在详情中提供同样的关系及锚点。当前 Light 识别 CLI ETW 检查点与导入 API 段，Qt 自写 raw 的专用封尾契约需单独接入与验收。 |
| CLI | `analyze session` 的项目方法表包括 `project.open`、`sample.query` 和 `archive.inspect`。`ArchivedCapture.cpp::ReadArchivedCapture` 读取 ETW 回执。`ApiMonitorEvidenceCommand.cpp::Replay` 可回读完整核验的 API 原包。`SysmonThreadCommand.cpp` 的 retained / follow 是独立来源入口。 | `ProjectCommands.cpp` 已为 `archive.inspect` 接入显式 `view:"graph"`。REPL 用 `archive inspect SAMPLE_ID raw ORDINAL graph`。归档适配器复用 `ReadSample`、`ReadEtwCheckpoint`、`ReadRawEvidenceSegment` 和 API 尾记校验。续页使用相同采样、段号及前缀 SHA-256。当前结果含带锚点的上下文及未知字段。Sysmon 采样定位和 CLI 正式回放待验。 |

[Qt 读取器](../../Ksword5.1/Ksword5.1/ActionAnalyze/OfflineSegmentReader.cpp) · [Qt 发布](../../Ksword5.1/Ksword5.1/ActionAnalyze/OfflineSegmentOverview.Loading.cpp) · [Qt 底部证据入口](../../Ksword5.1/Ksword5.1/ActionAnalyze/OfflineSegmentOverview.Objects.cpp) · [Light 页面](../../KswordARKLight/Features/ActionAnalyze/ActionAnalyzePage.cpp) · [Light 项目回放](../../KswordARKLight/Features/ActionAnalyze/ProjectReplay.cpp) · [CLI 方法表](../../KswordCLI/ActionAnalyze/Cli/ProjectCommands.cpp) · [CLI 归档回执](../../KswordCLI/ActionAnalyze/Cli/ArchivedCapture.cpp)

## 2. 真实输入和当前缺口

| 输入 | 现有源码可回查的字段 | 当前允许的投影 |
| --- | --- | --- |
| `ProjectDocument::ReadSample` 与 Stored `CanonicalEvent` | 项目 UUID、采样 UUID、标题、创建时间、冻结修订及描述散列。事件正文可有 `eventOrdinal`、接收 QPC、来源／代次字典编号、actor／target／thread 对象编号及原始记录引用。当前 Qt/Light 行模型里的字典和对象编号仍未解析。 | 从已登记样本取得标签和范围。对象编号可作样本内引用。冻结描述没有 `machineId`、`bootId`，段头创建时间与采样时间也无法补全。只有解析过的原事件、来源字典和对象身份记录能进入强实例路径。 |
| 原始 API 导入及被动尾读 | `ApiMonitorClueReadback::Accept` 校验分类、源行顺序及计数尾记。`ArchivedApiMonitorClue` 有完整包、来源 `events.jsonl` 行号、可选的调用方创建时间声明。包有 sessionIdentity、报头调用 PID/TID、时间、模块／API、结果标记。`PassiveApiArchiveTail::Poll` 可从已授权读句柄核对同次会话和调用方声明，返回完整行及覆盖状态。 | `ProjectArchivedApiCall` 只认核过模块和分类的 `WriteProcessMemory`、`CreateRemoteThread`、`CreateRemoteThreadEx`。精确返回标记存在才取返回位和独立 Win32 状态。旧包仍为 `RawOnly`／`LegacySummaryOnly`。其余已分类 native API、APC、上下文、映射等保留分类和原包锚点。目标实例、历史句柄归属、输出字段有效性、实际完成写长、新线程创建时间、执行均未知。`detailText`、请求长度和接收时看到的活动 PID 不参与绑定。 |
| 被动 ETW、Qt 自写档与进程观测 | `ReadArchivedEtwObservation` 有 provider GUID、source epoch、描述符、头部 PID/TID、FILETIME、可空接收 QPC／频率、载荷长度和异常标志。CLI 计划有筛选用 `headerPid` 和 `processCreationFileTime`。Qt 自写 raw 可另见 `liveSequence`、进程区间观测的 `creationFileTime` 与 CPU/I/O 计数。 | `ProjectPassiveEtwContext` 接收原 `PassiveEtwRecord`。归档适配应从核验过的元数据和原始已存字节走相同的上下文判据，保留 `EtwContextOnly`、截断、坏包和覆盖回执。计划绑定只描述采集范围，区间计数只描述同实例观测。actor、target、新线程实例和实际写入／执行未从这些字段得到。头字段留在来源详情。 |
| 原始线程回调 v1 | `ProjectCallbackThreadCreation` 校验版本、大小、类别、操作、源序号、目标 PID/TID。成立时，`originatingProcessId/ThreadId` 是该通知定义的创建上下文，`targetProcessId/ThreadId` 是明确报告的目标。 | `Validated` 的创建通知和四个提示字段可回查。协议 v1 没有进程或线程创建 FILETIME，当前三端采样读链也未提供该回调的已提交档案。缺强实例时无原生创建或归属边。 |
| 本机 Sysmon Event 8 v2 | 读器按结构化 System/EventData 取得 channel、provider 名及 GUID、Computer、EventID、Version、EventRecordID、TimeCreated、双方 ProcessGuid/PID、新 TID、起始地址及可选映像／提供者推断名称。 | 已验真且绑定采样锚点的记录可生成 `SysmonThreadReported`。现有查询／订阅只返回来源记录及回执，缺采样归档位置。进程和线程创建时间、执行 RIP、写入事实和本机启动期保持未知。 |
| 静态调查、脏页与原生停点的已有读数 | `InjectionSurveyProjection` 可核验当前已绑定的调查对象和报告。`PassiveDirtyMemory` 区分已采页内容与独立执行证据，其 `ExecutionObservation` 是内部上游输入。`NativeDebugOwner` 声明目标创建 FILETIME。 | 调查、区间字节差、入口地址和单次停点上下文分别保留原类别。当前 CLI 脏页入口用 `sampleId` 填 `machineId` 和 `bootId`，此处只能当本次观察范围的占位。三端当前回放入口未见同时具备已验证线程实例、明确执行阶段、实际 IP 和可回读采样锚点的 `Detection::ExecutionObservation` 生产适配器。 |

[采样描述](../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h) · [类型化来源适配](../../KswordCLI/ActionAnalyze/Detection/InjectionTelemetry.cpp) · [旧 API 包解析](../../shared/evidence/ApiMonitorClue.h) · [被动 API 尾读](../../shared/evidence/PassiveApiArchiveTail.h) · [ETW 正文](../../shared/evidence/ArchivedEtwObservation.h) · [Qt 自写档](../../Ksword5.1/Ksword5.1/ActionAnalyze/LiveSampleArchive.cpp) · [回调记录布局](../../shared/driver/KswordArkCallbackMonitorIoctl.h) · [Sysmon 字段](../../KswordCLI/ActionAnalyze/Detection/SysmonThreadSource.h) · [调查适配](../../KswordCLI/ActionAnalyze/Detection/InjectionSurveyProjection.cpp) · [脏页适配输入](../../KswordCLI/ActionAnalyze/Memory/PassiveDirtyMemory.h) · [脏页宿主](../../KswordCLI/ActionAnalyze/Cli/DirtyMemoryCommand.cpp)

## 3. 强实例、关系和证据定位

- **强实例。** 原生进程键为 `(machineId, bootId, pid, creationFileTime)`。进程绑定须同时属于当前采样的机器与启动期，PID 为非零 u32，创建 FILETIME 已存在且非零，`bootId` 拒绝泛用 `live`。线程键为 `(宿主进程实例, tid, creationFileTime)`，TID 非零，线程创建时间至少为宿主创建时间，与来源角色及提示无冲突。每项绑定还应有事件发生时的可信来源与适用时段。只从归档对象/生命周期材料复核，禁用现场 PID/TID 补全。当前 `GraphThreadInstance` 接受创建 FILETIME，线程原生序号形态在本接口仍待适配。[强身份闸门](../../KswordCLI/ActionAnalyze/Detection/InjectionDiscovery.cpp) · [事件身份契约](../ActionAnalyze事件身份与协议契约.md#3-实例与区域版本)
- **原生关系。** `ExternalWrite` 需要可信返回／完成阶段、两侧强实例、成功或可信部分完成的非零实际范围。缺区域版本可保留写入事实。`ThreadCreated` 从已验证创建者指向新线程，`ProcessOwnsThread` 从宿主指向线程。创建者未知时，已核实的成功创建和宿主仍可产生归属边。同进程创建可以有创建边，是否跨进程以 `finding.externalOperation` 为准。已核实的取指尝试和执行确认分别显示，当前图只用它们支撑线程归属，创建者与执行者分别保留。`CorrelateWriteExecution` 属于独立候选关联，要求不同 `sourceId` 和 `sourceGroup`、独立锚点、相同目标实例及区域版本、同事实时钟严格先后、执行确认且实际 IP 落在已写半开区间。图中多个角色共享节点不能据此导出因果或补写结论。[事实判定](../../KswordCLI/ActionAnalyze/Detection/InjectionDiscovery.cpp) · [图关系投影](../../KswordCLI/ActionAnalyze/Detection/CrossProcessEvidenceGraph.cpp)
- **采样标签。** 标题使用冻结采样的项目、采样标题／UUID 与采样时间，同时显示当前实际数据来源、来源代次和已读范围。目录草稿、正在读的新采样和仍显示的旧快照独立标记。项目回放显示 `descriptionHash` 绑定的已验证段水位与完整性。单段显示真实 `stream`、段号、文件身份和字节前缀，并标为独立预览。采样创建时间、日志事件时间、事实时间和接收 QPC 分别保存。以接收时钟排序的视图按原值标示时钟，等时间和接受序号只用于稳定展示。[总览锚点](../ActionAnalyze总览交互与验收.md#状态和证据锚点) · [事件顺序](../ActionAnalyze事件身份与协议契约.md#4-规范事件)
- **规范位置。** `EvidenceRef` 绑定同一 `projectId/sampleId`、`sourceId/sourceEpoch`，优先用可回查的规范 `eventOrdinal`，其 0 有效。再保留已解析的 `RawLocator{segmentOrdinal, sequence}`。裸 source 序号、Sysmon `EventRecordID`、记录流封装序号、字节偏移和字典 ID 各有自己的字段。回读先复核采样、流、真实段号和水位，再核对来源、记录号及正文，最后从同一已验证范围打开原包。仅有 raw 归档可使用已核验的 raw 坐标。遇到 `records` 行的原始引用时先解析跨流索引。路径、文件名和预览位置无法补全锚点。[EvidenceRef](../../KswordCLI/ActionAnalyze/Detection/InjectionDiscovery.h) · [Stored 契约](../../schemas/action_analyze/base-contract-v1.md)
- **已知兼容边界。** Stored 夹具含合法 raw 序号 0，`HasDisplayLocation` 和 `HasEvidenceLocation` 当前拒绝 `raw.sequence == 0`，即使同时有规范锚点。唯一已核实位置为 raw 0 时在来源详情保留原值，当前图报 `EvidenceUnavailable`。接线前统一契约并补夹具，或明确把该档限制为预览。图同边去重键只取规范 ordinal 或 `(raw 段号, raw 序号)`，依赖调用方确保坐标在该样本全局唯一。异档同坐标、独立流、不同水位或同坐标异正文先由读侧核验。图仍保留逐输入观察，聚合边的证据条数按锚点去重，来源组独立性要另算。同原包派生两个不同规范事件可支撑同一边两次，但代表一份原始包。源包仅声明相同 `sessionIdentity` 或 `sourceSequence` 时不获得全局身份。[定位与去重](../../KswordCLI/ActionAnalyze/Detection/CrossProcessEvidenceGraph.cpp) · [Stored 零值夹具](../../KswordARKLight/Features/ActionAnalyze/tests/StoredEvidenceValidation.cpp)
- **上下文位置。** 对锚点有效的上下文或解码失败，经 `GraphEventInput::contextEvidence` 保留定位和 `Issue`，无需原生机器／启动期。`ProjectArchivedApiCall` 和 `ProjectPassiveEtwContext` 目前先调用要求机器／启动期的 `HasEvidenceLocation`。旧档缺这两项时从已经核验的归档坐标直接走上下文入口，保留真实缺口和源详情。若 `event.observation` 存在但其锚点无效，图不会自动退回 `contextEvidence`。也不得把 `EvidenceRef` 的存在解释为该记录已持久化或在当前窗口。[上下文入口](../../KswordCLI/ActionAnalyze/Detection/CrossProcessEvidenceGraph.cpp) · [来源适配](../../KswordCLI/ActionAnalyze/Detection/InjectionTelemetry.cpp)

### Sysmon 来源命名空间

图节点键为 `GraphSysmonProcess{Computer 原文本, 规范 ProcessGuid}`。规范化只处理 GUID 大括号、十六进制大小写和格式，零 GUID 无效。Computer 拼法逐字保留，主机短名、FQDN、大小写变化和机器改名不能自行折叠。Sysmon 名称空间纵向独立，无机器或启动期时仍能按同一采样汇总验真的来源报告。重合 PID/TID、同名镜像和邻近时间均不提供原生绑定。图内回验把记录自带 TargetGuid 传回解码器，验证结构自洽。调用方负责核对用户所选 TargetGuid、授权来源和采样成员关系。[Sysmon 解码](../../KswordCLI/ActionAnalyze/Detection/SysmonThreadSource.cpp) · [图中 Sysmon 投影](../../KswordCLI/ActionAnalyze/Detection/CrossProcessEvidenceGraph.cpp)

`sourceId` 区分来源实例，由所属采样登记，原生日志身份保留 Computer、channel、provider GUID 和日志来源。`sourceEpoch` 由采样读取器登记到明确的日志快照／订阅代次。日志清空、替换或订阅失连续时记录断点，只有新的已核验来源代次才能继续回读。同一日志的历史查询与实时订阅可保留各自 epoch，`sourceGroup` 标记同一底层来源。`EventRecordID` 仅为日志范围内的原生提示，附带 Computer、channel、provider、版本和时间复核。当前 live／retained CLI 数据没有 `EvidenceRef`，继续显示为来源记录。后续只有已登记的规范事件或采样 raw 坐标才用于项目图。导入的文本、CRC 检查和来源自称都不足以设置 `InputTrust::Validated`。[CLI Sysmon 结构输出](../../KswordCLI/ActionAnalyze/Cli/SysmonThreadCommand.cpp) · [基础身份契约](../../schemas/action_analyze/base-contract-v1.md)

## 4. 容量与发布

| 层 | 当前边界或接线验收建议 |
| --- | --- |
| Qt／Light 读档窗口 | 现有独立段扫描至 64 MiB 或界面配额，当前行窗口上限 4096。已核验的项目多段回放保留最近 4096 行。API 导入／回放需过完整段落尾记，预览行窗口不代替读档校验。连续项目遍历到终段或首个缺失／失败检查点，4096 是保留上限。Qt 自写档与 CLI 检查点使用各自核验路径，发布同时报告实际段和行范围。 |
| 图构建 | 建议首版复用每快照最多 4096 条输入。当前构建器自身无容量闸门，每条生成一项 observation，至多引入 3 个节点、2 条边和 2 次边证据引用。输入上限对应最多 12,288 节点、8,192 边和 8,192 次引用，这是结构数量上界。来源文本、来源索引和预览字节仍各自有界。先裁定输入范围与字节配额，再构图。后台同视图一个在途任务，只提交最新请求，过期数据不能淘汰当前选择。界面先显示有界邻接关系列表，按页展开证据。超限报告选中窗口、已验证数、实际投影数和省略范围。 |
| CLI 页 | API replay 单页上限 100 行，输入归档上限 32 MiB。`ReadArchivedCapture` 的 ETW 单段回执读取上限为 4 MiB／512 观察。已接入的图页每帧最多 100 条有界来源观察，超过 `kResultBytes` 时返回 `response-too-large`。续页在同一项目、采样和段号使用上一页的 SHA-256。 |
| 来源窗口 | 历史 Sysmon 默认 32 条、最多 128 条匹配，扫描 4096 条／5 秒，批次 16，单次渲染 64 KiB、文本字段 1024 字符。订阅队列至多 256 条，满时计数并丢新，CLI 每批 drain 8 条。`Retained-log-exhausted` 只表示已读到保留结果末尾。订阅中断、尾部未确认、队列掉包和版本不支持分别计入覆盖回执。被动 API 尾读每轮最多 64 KiB、单行最多 8192 B，半行等下一轮，最终回执和丢失计数独立显示。 |

三端统一显示未读、读取中、已核验空窗口、部分、不可用和失败。在核验水位内没有图边但保留线索时，标为「当前窗口未建立关系」，并列出覆盖或字段原因。读到可验证前缀时标明该前缀与尾部原因。取消、换样本、快速重读导致的迟到回包按请求代次丢弃。Qt 同一文件重读由 `publish` 保留旧完整快照。Light 当前可发布已核验的较短前缀，接线时把旧选择的详情及其上次证据水位单独保留，再标明本次无该锚点。记录客户端扫描、图构建、序列化和 UI 提交各阶段的行数、耗时和内存峰值，容量数字为实施建议，性能门槛等实测确定。[Qt 容量](../../Ksword5.1/Ksword5.1/ActionAnalyze/OfflineSegmentReader.cpp) · [Light 容量](../../KswordARKLight/Features/ActionAnalyze/StoredEvidence.h) · [CLI 帧预算](../../KswordCLI/ActionAnalyze/Cli/Protocol.h) · [API 查询限额](../../KswordCLI/ActionAnalyze/Cli/ApiMonitorEvidenceCommand.cpp) · [Sysmon 限额](../../KswordCLI/ActionAnalyze/Detection/SysmonThreadSource.h)

## 5. 同一选择与回跳

1. 事件选择键为 `(projectId, sampleId, eventOrdinal)`，raw 退回 `(projectId, sampleId, raw, segmentOrdinal, sequence)`，并在归属快照中核对来源、水位及文档身份。保存图节点用带种类的强实例键，保存关系用 `(同采样, relation, fromKey, toKey)`，边内证据另保留事件／raw 锚点。Qt 当前事件联动以 `m_sequence` 定位，Light 的 `PublishSnapshot` 在同路径、请求及段身份下按 `segmentOrdinal + sequence` 恢复。接线时复用筛选、详情与滚动入口，将只适用于单次投影的数组行号、边号和节点号限制在该快照内部。[Qt 筛选与选择](../../Ksword5.1/Ksword5.1/ActionAnalyze/OfflineSegmentOverview.cpp) · [Light 快照发布](../../KswordARKLight/Features/ActionAnalyze/ActionAnalyzePage.cpp)
2. 同采样追加、排序、筛选、当前窗口暂时裁掉该行时保留同一个选择和最后可用详情，标注「已筛除」或「超出当前窗口」。显示过滤恢复时若同锚点重新出现，复原可见选中态。用户选择关系先显示其依据，显式「打开证据」才回跳。如果证据在当前页外，按同采样冻结范围读对应页，保留筛选条件与焦点并给出可见性提示。回查失败保留旧选择、真实来源与原位重试。换项目、样本或源档时按新请求独立发布，旧键不自动迁到同 PID/TID 或同显示行号。[总览选择契约](../ActionAnalyze总览交互与验收.md#时间范围焦点和动作对象)
3. Qt 总览继续使用工作台内容框、`TablePresentation`、`ResultTableHost` Compact、共享详情宿主和单一 `StructuredFieldView` 文档。底部图与键盘关系列表共享选择及文档。关系需要更多列时按概览／来源分成互补列组。对照进程定向监控和 WinAPI 监控的时间线与详情接法。Light 继续使用 `WorkspaceHost`、`VirtualListView`、原生焦点与 DPI 布局，现有单选证据表操作条为 None，窄窗详情中保留关系列表入口。图上本期可用动作是查看证据、按真实键筛选及复制可读证据标识，缺身份时从该条来源详情访问。请求范围由显式提交冻结，选中节点本身无需访问目标。[Qt 对照一](../../Ksword5.1/Ksword5.1/MonitorDock/ProcessTraceMonitorWidget.Ui.cpp) · [Qt 对照二](../../Ksword5.1/Ksword5.1/MonitorDock/WinAPIDock.Ui.cpp) · [共享结果表](../../Ksword5.1/Ksword5.1/UI/ResultTableHost.h) · [Light 对照](../ActionAnalyze总览交互与验收.md#win32-a9-首个只读切片)

## 6. 合成正反例

使用纯数据样本。令 `A=(PID 10, 创建 100)`、`B=(PID 20, 创建 100)`、`T=(宿主 B, TID 30, 创建 101)` 共享一组可信 machine/boot 及冻结采样。每条来源记录分配确实可回读的位置。三端用同一窗口比较关系类型、有向键、缺口、规范锚点与原始字节，排除数组顺序差异。标为「已有断言」的项目是静态读到的夹具覆盖，三端正式回放均待验。[现有图向量](../../KswordCLI/ActionAnalyze/Detection/tests/CrossProcessEvidenceGraphTests.cpp)

| 场景 | 输入差异 | 预期核对 |
| --- | --- | --- |
| 真实完成的外来写入 | 可信 Return，A→B，实际范围非空，规范事件 `0`；另输入第二枚规范序号以及一枚完全重复锚点 | 一条 `ExternalWrite`，两个规范证据位置，三条输入观察可追溯。`0` 可选择及回读。缺区域版本仅影响候选执行关联。已有相应断言。 |
| 未完成或字段矛盾 | 入口附缓存 finding；只有请求长；Failed 却报告完成长；RawOnly；同一事件一个 PID 两个代次；实际范围溢出 | 无写入边。按输入显示阶段、实际范围、结果、来源或身份缺口。独立可核实的角色仍可展示。 |
| 线程创建与未知创建者 | A 创建 T，B 是宿主；第二条换为未知创建者，或使用同进程 B→T | A→T `ThreadCreated`、B→T `ProcessOwnsThread`。未知创建者时保留 B→T 及未知归因。同进程创建保留创建边并标 `externalOperation=false`。已有前两类断言。 |
| PID／TID 重用与错宿主 | 新 A 创建 120，新 T 创建 130；追加错 boot、同号不同宿主或线程创建早于宿主 | 不同代次为不同节点。冲突的线程绑定不建立归属边，强角色缺失时保持未知。相同数字不会成为跨代次回跳键。 |
| 取指与执行 | 先后送可信 `FetchAttempt` 和 `Executed`，都使用 T；再送入口地址、旧静态栈或单独的脏页差 | 前两条分别显示 `ExecutionFetched`／`ExecutionConfirmed`，两条支撑线程归属且归因未知。后三类作为自身来源上下文或快照，无独立执行结论。 |
| 候选关联负控 | 保留写入与独立执行确认，分别改变区域版本、时钟域、来源组、证据位置，或令 IP 落在区间右端 | 各单项已成立的事实保留。任何一项不符，`CorrelateWriteExecution` 均无候选关联。满足全部独立、时序及范围条件时只返回候选。 |
| Sysmon 双空间 | Event 8 v2 报告的 PID/TID 恰与 A/B/T 相同。两台 Computer 使用同一对 GUID。另输入错误版本、地址校验失败及未经确认来源 | 每个有效 Computer 分组各有一条 Sysmon 报告边，和原生键分离。`reportedStartAddress`、原生记录号、时间正确。无 `newThread` 和原生 finding，保留线程实例／执行未知。错误输入保留缺口。已有相关断言。 |
| 来源锚点 | ETW 截断尾、API 导入尾记损坏、`sourceSequence` 单独存在、错采样、唯一 raw 序号 `0`、两个输入声称同坐标但原文不同 | 合法上下文保留定位和截断状态，坏尾按原读侧门槛发布。源序号单独使用及错采样均缺有效定位。raw 0 当前仅来源预览。坐标冲突由读侧在构图前拒绝。 |
| 窗口和重读 | 同采样分段追加超过 4096，超帧结果，检查点缺失／损坏及请求逆序返回 | 图与表只出现已验证的范围。省略数和下一页状态可见。旧选择按原锚点保留详情，任何过期回包不得顶替当前结果。等预算缩页时验证每条记录完整且不重复。 |
| 桌面同选 | 鼠标／键盘分别选同一事件与边，排序、筛除、清除、重读、换采样后返回，使用同号不同代次；窄窗压缩底图 | 表、时间线、证据详情和关联依据同步到稳定键。确认隐藏状态、失败恢复、无焦点跳转及真实段号。Qt 核对深浅主题、双语、背景模式和首帧。Light 核对原生控件通知、100%／150%／200% 和窄窗详情回退。 |

## 7. 已实现的归档读侧 API

Detection 提供 `ReadArchivedEvidenceGraph(project, request, page)`。调用方显式提供已打开的项目、已登记采样 UUID、raw 段号、`afterSequence` 和页容量。当前支持完整核验的 API 导入段和双流检查点已验证的 ETW 段。回执含冻结采样描述散列、实际 raw 段前缀 SHA-256、末块位置和下一页游标。每条 `records[i]` 含实际段号、块号、记录序号、记录头与内联数据文件偏移及内联长度，和 `graph.observations[i]` 对应。续页带回 `expectedSha256` 时核对同一前缀。当前归档均输出带回读位置的来源上下文，原生强角色及关系保持未知。CLI 通过 `archive.inspect` 的图视图消费该接口。[读侧接口](../../KswordCLI/ActionAnalyze/Detection/ArchivedEvidenceGraph.h) · [方法契约](../../schemas/action_analyze/method-contract-v1.md#archive-inspection)

接线顺序从三端同一已核验归档的上下文页和锚点回读开始，随后补 Sysmon 采样定位，再接具有事件时强身份的原生事实。实施批次分别登记源码、三端构建、合成读回和正式 GUI 验收。

交接保留用户原话「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。当前目标是产品第 4 项的只读证据图接线。CLI 接入已实现，正式构建与归档回放由集成批次验收。剩余 Qt 和 Light 投影、桌面锚点回跳、Sysmon 采样定位和正式产品矩阵。下一个实施入口是 Qt `ReadOfflineSegment` 和 Light `ReadProjectReplay` 的同一冻结样本上下文页。先对齐 raw 序号 0 兼容方案并核查三端一致回读。
