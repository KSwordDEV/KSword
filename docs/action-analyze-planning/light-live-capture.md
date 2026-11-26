# Light 实时采集与归档

用户原话「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。本批交付 Light 只读采集契约、`LiveCapture`、`NativeLiveSession`、工作台接线及工程登记。主协调者负责正式集成。验收对应 [ActionAnalyze 产品清单](../ActionAnalyze产品验收清单.md)第 3、8、9 项中适用于 Light 的部分。

## 真实入口和所有权

| 入口 | 现有实现和接入位置 |
| --- | --- |
| Light → 监控 → ActionAnalyze | 模块命令 `40006`，`WorkspaceHost` 稳定页 ID `3`，工厂 `CreateActionAnalyzePage`。继续使用原生时间线、`VirtualListView`、详情、`AppTheme`、`Dpi` 和 `TextFindSupport`。证据表沿用无额外操作条。开始、停止和归档状态放在公共操作区，显示筛选只改变结果投影。 [模块登记](../../KswordARKLight/Features/FeatureRegistry.cpp) · [监控工厂](../../KswordARKLight/Features/Monitor/MonitorFeature.cpp) · [现有工作台](../../KswordARKLight/Features/ActionAnalyze/ActionAnalyzePage.cpp) |
| Light → 监控 → ETW 事件／内核回调监控 | 页 ID `1` 保持默认，进程菜单的 ETW 筛选仍直达此页。页 ID `2` 保持原有回调任务。两个入口供对照原生表格、主题、状态与收尾协议。ActionAnalyze 使用同一共享 ETW 实现的独立实例。 [ETW 页](../../KswordARKLight/Features/Monitor/EtwMonitorView.cpp) · [回调页](../../KswordARKLight/Features/Monitor/CallbackMonitorView.cpp) |
| Light 长期任务 | Light 使用 `Ui/BackgroundWork.h` 的 `BackgroundWorkRegistry` 接入申请、关闭和清退。`MainWindow` 经 `kBeginNativeRetirementMessage`、`kPollNativeRetirementMessage`、`kCancelNativeRetirementMessage` 协调已物化页面。登记一份 ActionAnalyze 业务所有者，采集工作线程持有生命周期租约，收尾失败保留值所有权，按现有入口重试。Qt 的 `BackgroundTaskRegistry`／`TaskManagerDialog` 适用于 Qt 产品。 [Light 登记](../../KswordARKLight/Ui/BackgroundWork.h) · [Light 关闭链](../../KswordARKLight/App/MainWindow.cpp) · [运行时控制开发规范](../运行时控制开发规范.md) |

Light 在显式开始后持有一个活动会话。切换模块、暂停跟随和打开历史时，采集与归档持续推进。`NativeLiveSession` 在后台维护最近 256 条进程区间和 3840 条 ETW 观察。页面可见且跟随开启时以 400 ms 节拍请求最新快照，表格共用历史结果模型。选中实时行时暂停跟随，可显式恢复。时间线沿用现有 ETW 泳道，进程区间可在表格与详情查看。`AsyncSnapshotTask` 承载可替换的归档读。采集线程串行调用 `Start`、`Poll`、`Stop`。GUI 投递停止意图并使用原生关闭协议等待回执。停止已接纳后，取消关窗恢复新任务准入。 [异步与关窗消息](../../KswordARKLight/Ui/AsyncTask.h) · [采集会话](../../KswordARKLight/Features/ActionAnalyze/NativeLiveSession.cpp)

## 采集范围与证据身份

- 开始请求冻结 PID、进程创建 FILETIME、启用的 provider、项目清单身份与修订。工作线程仅以 `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` 打开实例，复核创建时间，保留原句柄至清退。退出立即结束该实例的采样。在相同 PID 上开始新采样须重新确认身份。 [现有 Qt 活动查询](../../Ksword5.1/Ksword5.1/ActionAnalyze/LiveEtwCapture.cpp)
- 进程活动按实际单调区间保存 CPU 100ns 增量及独立的读／写传输字节差。首个快照作为基线，零值表示实测零。I/O 查询失败或者计数回退使相应值未知，同时保留诊断。进程总 I/O 字节可以包含文件、网络、设备等来源。 [Light 进程统计适配](../../KswordARKLight/Features/Process/ProcessTelemetry.h)
- 可选 ETW 走 `PassiveEtwSource` → `EtwSessionController` 的原生记录入口。首版每次至多一个经用户选择的 provider。保留 Level、Keyword、原生描述符、FILETIME、接收 QPC、原始报头 PID/TID、ActivityId 和有界 UserData 前缀。报头过滤用于记录上下文范围，actor/target 保留未知。来源拒绝或失效独立显示，进程活动继续。任何代码路径均受当前令牌和 Windows 的 ETW 权限约束。 [原生控制器](../../shared/usermode/backend/monitor/EtwSessionController.h) · [被动来源](../../shared/usermode/backend/monitor/PassiveEtwSource.h)
- 实时和归档使用同一采集值。项目 ETW 观察按批分配 `projectId + sampleId + raw/1 + segmentOrdinal + recordSequence` 坐标，检查点提交后随行返回。表格、时间线和详情按坐标定位。原生来源代次、接收顺序、文件序号和将来规范事件 ID 各自保存。切换显示筛选、合并刷新及预览滑窗淘汰均单独统计。 [事件身份与时间域](../ActionAnalyze事件身份与协议契约.md)
- 首批代码提交 ETW 双流，并交付进程活动的会话内实时值。现有 `VerifyRaw` 逐条要求 `etw-observation-v1`，且 `records` 段仅接受一个 ETW Coverage。进程区间与 ETW 共档需要扩展跨端契约并实现 Light、CLI、Qt 读写互认。Qt 当前活动记录为端内 `qt-process-activity-v1`，未列入 Light 首批可写能力。 [双流验证器](../../KswordCLI/ActionAnalyze/Project/ProjectEtwCheckpoint.cpp) · [Qt 当前活动格式](../../Ksword5.1/Ksword5.1/ActionAnalyze/LiveSampleArchive.cpp)

## 提交和重开

1. 在工作线程核验目标和输入。用户回放项目内一个采样，再到实时视图显式勾选「ETW 写入项目」。此动作冻结该项目路径和 UUID。工作线程读取当前修订，再由 `ProjectDocument` 取得唯一写租约、复核项目 UUID 和修订并登记新采样。目标、项目或修订失败时原展示继续保留。进程活动无项目即可运行。项目归档要求提供 ETW provider。 [项目读写接口](../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h)
2. 后台有界批次写入 Stored `raw/<ordinal>`。使用运行计划、同批原始 ETW 观察和分段尾回执。先完成原始段写入及刷盘，再由 `PublishEtwCheckpoint` 校验前缀并生成、刷盘、回读 `records/<ordinal>` Coverage。最后发布同序号标记，发布成功才推进已归档水位。首批候选使用每批最多 128 条、单条载荷前缀最多 4 KiB、源队列最多 512 条。上层按积压/节拍调用 `Poll`，每次最多处理一批，避免新建逐事件 UI 任务。 [CLI 的同格式分段](../../KswordCLI/ActionAnalyze/Cli/LiveSession.cpp) · [双流规则](../../KswordCLI/ActionAnalyze/Project/ProjectEtwCheckpoint.cpp)
3. 停止后记录触发原因，清退自有 ETW，排空接纳队列，再提交终段。报告分别给出原生清退、来源覆盖及归档完成。STOP 或 CloseTrace 失败保留原实例，等待重试。档案失败后保留已提交前缀，关闭该样本的写入。磁盘错误详情和最早失败段可见。下一次采集登记新样本。 [来源清退](../../shared/usermode/backend/monitor/PassiveEtwSource.h) · [存储恢复设计](../ActionAnalyze项目存储格式与恢复设计.md)
4. 重开冻结项目及采样描述，依次验证标记、同序双流、SHA-256、块边界、序号和采样身份。末段无标记时仅发布此前连续前缀。已经见到持续采集计划但首次标记缺失时显示等待或中断候选。错误标记或依赖损坏保留前段与已有详情。独立打开 `.ksaseg` 属于诊断预览。中断后重开以只读证据恢复为限。 [现有 Light 回放](../../KswordARKLight/Features/ActionAnalyze/ProjectReplay.cpp)

首批实现由同一后台工作线程串行查询进程、排空 ETW 并提交段。原生 ETW 回调继续使用共享来源的有界队列。慢盘期间进程采样间隔可能变长，ETW 队列可能满，停止意图会在当前磁盘操作返回后推进。十分钟验收需同时观测这些阶段。

## 十分钟验收输入

运行前记录正式 Light 及自有样本哈希、Windows build、令牌完整性和驱动状态、CPU／逻辑核、内存、卷和可用空间。记录项目 ID／采样 ID、源 GUID／Level／Keyword、PID／创建时间、节拍、队列与前缀边界、作用域和监测工具。使用现有普通权限启动选项核对真实入口。支持的自有 ETW provider 做正例，原权限下被拒绝的 provider 做降级例。仅在另行授权的批次执行正式程序或窗口验收。 [既有普通权限入口与同样本回放](../ActionAnalyze总览交互与验收.md#light-普通权限打开归档)

| 窗口 | 固定输入和核对 |
| --- | --- |
| 基线与正常负载 | 沿用自有 provider `d4a71ada-81b0-4b15-a173-417f33bc8107` 和 8 字节载荷 `(iteration, transferBytes)`，每秒安排 10 组自有文件读写，各发两条标记，目标是 600 秒内 12,000 条。记录实际成功量。无采集基线运行同一组读写与 CPU 工作，活采集每 150 秒换阶段，依次为页面可见、切到另一模块、切回、暂停跟随。核对选择、采样连续性、首条进程区间、第一条 ETW、最后一个终态标记。 [自有样本实现](../../tools/action_analyze_validation/cli/live_etw.py) |
| 负载阶梯与故障 | 单独跑 200、600、1,200 条／秒各 60 秒的目标负载，报告实测速率及尺寸。用另一次受控隔离归档和现有原生夹具分别核对慢写／满额、provider 被拒、STOP 重试、目标退出／身份不符、关窗、标记缺失、坏尾、错采样与重开。报告处理终态、清退回执与已核验前缀。 [现有原生夹具](../../tools/native_etw_controller_validation/README.md) |
| 性能记录 | 每 10 秒记录目标及 Light 程序 CPU 时间、目标完成量／耗时、Light 私有提交和工作集、句柄／线程数、队列高水位与最老记录年龄、写入字节、时间线及 GUI 提交时长。用 QPC 对齐从接收、展示、持久水位到原生清退的各段延迟，报告 n、P50/P95/P99、最大值及无法测得的字段。停止后记录资源回落和残留计数。初始容量是实现设置，公开性能阈值由实测冻结。 |
| 丢失对账 | 自有 producer 保存完成发出的标记序号，三端回读比对唯一序号、载荷前缀与重复。分别报告 provider 回调、报头范围抑制、接纳、队列满丢弃、接纳后范围排除、已归档、归档前失败未提交及当前在途。队列完全排空后核对 `接纳 = 已提交 + 已排除 + 未提交`（已请求项目归档），原生 `eventsLost`／`logBuffersLost`／`realTimeBuffersLost` 用原单位列示，未知填空。载荷截断、畸形、预览淘汰分别记账。正常支持路径要求预期 producer 标记无未解释缺口，最终检查点可重开，清退须有原生回执。 |

Light 工程已登记 `LiveCapture`、`NativeLiveSession`、`PassiveEtwSource` 和 `KernelFileEvidenceProjection`，复用现有 `EtwSessionController`、`ProjectDocument`、`ProjectRawEvidence` 及 `ProjectEtwCheckpoint`。Light 固定中间目录为 `KswordARKLight/x64/Release/obj/`，正式输出为 `Ksword5.1/x64/Release/`。HostX64 语法检查以 BelowNormal 执行。正式构建、窗口和十分钟采集由主协调者集成后验收。 [Light 工程](../../KswordARKLight/KswordARKLight.vcxproj) · [Light 归档回归](../../KswordARKLight/Features/ActionAnalyze/tests/StoredEvidenceValidation.vcxproj)
