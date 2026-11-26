# 第 6 项：Qt／Light 进程集合控制

本批实现本端显式进程集合的产品页面与异步所有者。用户顺序限制仍有效：Qt／Light 当前只做源码接线和适配检查，不构建、不启动 GUI，不重复既有 NativeDebugOwner 或 CLI 实测。用户持续推进原话：「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。

## 入口与布局责任

| 端 | 导航入口 | 页面类型 | 共享入口 |
| --- | --- | --- | --- |
| Qt | 监控 → 行为分析 → 进程集合控制 | 清单管理＋参数执行＋原生生命周期 | `ParameterWorkspace` 参数独立滚动与固定配置动作；结果成员表 `TablePresentation`／`ResultTableHost`、操作条 `None`；`SecondaryPageLayout` 表单；`FlowLayout` 窄窗换行；`StructuredFieldView` 单一字段来源 |
| Light | 监控 → 行为分析 → 进程集合控制 | 原生清单管理＋参数执行＋生命周期 | `WorkspaceHost` 惰性工厂；`Ui::ParameterWorkspace` 独立参数滚动、`LayoutParameterActions` 固定动作换行；共享 ListView 三列清单，操作条语义为 `None`；完整详情使用原生 EDIT＋`TextFindSupport`／`ExportUtil` |

Qt 工厂为 `ActionAnalyze/ProcessGroupPage.h/.cpp`，独立后台为 `ProcessGroupSession.h/.cpp`。Light 工厂为 `Features/ActionAnalyze/ProcessGroupPage.h/.cpp`，页面控件状态与布局拆至 `ProcessGroupPageState.h`、`ProcessGroupPageLayout.cpp`，独立后台为 `LightProcessGroupSession.h/.cpp`。两端使用各自所有者，不创建外部第三方窗口或 CLI 子进程。

Qt 的内存参数与字段投影另放 `ProcessGroupMemoryPane.h/.cpp`，避免将内存归档和清单交互堆入单页文件。底层快照只读复用 `Control/ProcessGroupMemorySnapshot`、`Memory/SelectedMemorySnapshot`、`Memory/PassiveDirtyMemory` 和 `Project/ProjectMemorySnapshot`，工程与 filters 同步登记。

Qt 工程此前未登记共享 `backend/Common.cpp`，本批为 `OwnedProcessGroup`／`PassiveDirtyMemory` 的 `UniqueHandle` 实现补入该唯一源码；Light 已有同一实现，不重复登记。散列通过现有 BCrypt 依赖，读取器自带 `#pragma comment(lib, "bcrypt.lib")`，不引入新运行库。

Light 原有写入页文件仍拥有旧工作台工厂。在 `MonitorFeature.cpp` 用外层共享 `WorkspaceHost` 保留旧工厂到“工程、采集与写入停点”，将“进程集合控制”接为行为分析下直接子页。用户随后明确授权本端写入／步进页接入读取与归档，本批在保留原私有写入及步进路径的前提下局部修改该页。恢复 GUI 验收时需检查此新增父级对既有自动导航脚本的影响。

## 用户任务与身份

1. 输入 PID 和原始十进制创建 FILETIME，显式加入目标草稿。最多 16 个实例，重复 PID 拒绝；编辑输入不附加、不暂停、不继续。
2. 明确授权整张草稿列表，执行“冻结并配置集合”。后台从精确进程句柄回读创建时间和映像路径，并调用 `OwnedProcessGroup::Configure` 核对整个目录；Configure 不暂停。
3. 查看冻结成员列表，再执行暂停全部或暂停选中。请求固定点击时的全部目标，不从首行推断全组选区。
4. 查看每成员真实回执。未暂停、等待、完整持有、部分持有、拒绝和恢复责任分别呈现；`HeldComplete` 仅为原生回读汇总，不表示多个进程在同一时刻原子冻结。
5. 继续全部或继续选中时，逐成员复制本轮完整 `ProcessGroupStop`（PID、creation、group、stop、backend/event、revision）。任一所选缺失令牌就不提交；不把旧停点 ID 或历史票据转换为新继续资格。
6. 历史操作票据保留原请求与成员回执。Recover 使用原 Continue 的 `group/N` 请求 ID；不新造继续请求。新暂停与继续共享本端递增的 `group/N` 空间。
7. 关闭交由原所有者逐项清退。`Closing` 或恢复未决时保留同一会话，不销毁 `NativeDebugOwner`。原 Close 调用真实确认 `clean` 后才结算本端线程并允许显式建立下一集合；配置未成功时原生仍可为 `Idle`，该状态不伪装为 `Closed`。
8. 内存只读明确选择单个持有完整原生停点的成员，输入 base／bytes，显式读取。Held 模式复制全部当前停止令牌，前后核对同一停点；失败不回退实时。结果包含成功页、失败页、实际字节、QPC 采时及每页状态，最多显示每成功页前 256 字节预览；完整成功原字节由后台保留，不填零。
9. 可在冻结配置前显式选择尚不存在的独立内存快照项目目录。本端创建 `ProjectDocument` 与真实 sample，再把同一 sample ID 赋给该组原生所有者。读完后“保存本次内存快照”仅归档点击时显示的同一结果，写 `raw-memory/N` 并同步回读核验；不抢其它工作台项目 writer。不提供项目目录时仍可实际读取，保存入口禁用，下一集合可显式选择项目。

内存 Plan 的 machine／boot 标签分别采用原停止组的 session／epoch，同一会话稳定，不充当跨会话系统身份；每次显式读取的 trackingEpoch 独立。真实目标复核仍使用冻结 PID 与创建 FILETIME、同一个原所有者及完整停点。当前页面不提供跨采样分配代次或原子快照保证。归档前序取前段 `flushed.lastSequence`，不把段号误作记录序号；任何写入或核验失败均阻止追加并保留现场，不靠跳段或覆盖原文件恢复。

集合保存调用 `WriteProcessGroupMemorySnapshot`，完整传递点击时冻结的 `ProcessMemorySnapshotResult`，由共享 writer 的可选 `readContext` 保存 source／stage／error／before／after／heldAtBothChecks；不只传内层 `snapshot`。sample 在读取前创建并绑定 group，后续保存仍使用原 sample，不用新采样 ID 改写旧 Plan。普通非集合快照的 writer 与格式继续由其原作者维护。

失败不清空前次冻结身份和结果；草稿、当前成员状态、历史票据、后台执行错误分别保留。来源时间是后台实际回读 FILETIME，不用 GUI 重绘时间冒充采样。R3 只控制本会话显式集合，不扩展后代或系统进程范围，不提供 R0 或任意所有者死亡恢复承诺。

## 实现与后台生命周期

底层接口唯一来源为 `KswordCLI/ActionAnalyze/Control/OwnedProcessGroup.h/.cpp`，本批只读，不修改该控制器。每端串行提交自己的值请求，原生查询在后台执行。Qt GUI 定时器仅复制本地发布快照，不进行 OpenProcess 或原生 Query；原生后台登记为 `monitor.action_analyze.process_group`，管理器不提供暂停恢复责任的入口。

Qt 会话同时取得现有 `AsyncCleanupRegistry` 的退出租约。主窗口开始正常退出时，弱引用回调只置 Close 标志并唤醒原线程；租约留在线程闭包中，等 `Run()` 确认 Close clean、销毁 group 和项目写租约后才归还。未清退期间主窗口现有异步退出门禁保持等待，不能用页面对象销毁或固定超时替代恢复。后台初始化和线程创建失败尚未附加任何进程，发布 `failed + retired`，不让构造异常逃出线程。

Qt 参考 `SystemTimePage`、`VirtualLocationPage`、`DataWriteWatchPage` 以及各共享结构；Light 参考既有写入会话及监控／工作台页。新代码按产品页面、后台 owner 和接线分工，不使用 `.inc`，不创建第二套主题或调试账本。

## SOURCE 与验证回执

此前作者将适配检查交给 CodeBuddy，工具权限为 `PowerShell(*)`／`Bash(*)`，主协调者复用实际回执。用户最新强制指令为“从现在开始暂时不允许派发CodeBuddy任务，我会在可用时告诉你”：不再新派发、续接、重试或新增自动任务；已有任务保留，不擅杀、不复制，不自行替代测试、不新增验收子代理。新增产品代码继续，后续检查只登记待验。

Qt 追加回执已完成：8 项无构建调度模型通过，彼时正式双语审计 `32149 source strings`／退出0。本轮随后新增写入／步进读取、执行保存、退出清退、固定动作位置和前后停点投影，**不在该回执覆盖内**。Light 独立内存模块此前 SOURCE＋24 项纯模型负控通过；本轮切换完整capture writer、接入集合worker／页面及后续源码修正尚未复验。Light 页面／session原任务已结束，退出0不构成源码或产品验收通过。

- [Qt SOURCE 与异步适配回执](process-group-qt-source.md)：由独立 CodeBuddy 检查产品源码、调度、完整令牌、原票据恢复、工程登记和双语审计后写入。
- Light 页面／session最终回执 `process-group-light-source.md`：原任务已经结束，但没有交付该文件；不将预期回执列为已存在证据。
- [内存范围 SOURCE 与适配回执](process-group-memory-source.md)：只覆盖新增读取／保存适配，核心快照沿用主协调者已有原生回执，不重复运行。
- [Light 独立内存模块初版回执](process-group-light-memory-source.md)：仅初版纯值及后台状态模块，后续wrapper和产品接线未复验。

正式原生／CLI 结果沿用相应底层作者回执；本批 SOURCE 或调度替身测试不构成真实进程暂停／恢复的产品运行证据。

## 后续实机验收门槛

当前构建：未执行。当前 GUI：未执行。实际视觉合规、性能和系统调用成功结论：无。

恢复桌面验收顺序后，使用固定 Release、HostX64 与 BelowNormal 构建；Qt 使用仓库正式包装脚本，Light 复用现有驱动并跳过驱动重建和签名。GUI 在独立非输入桌面执行，逐端验证：多选子集、混合状态、失效 FILETIME、重复 PID、部分附加失败、全组继续资格、原票据恢复、页面／程序关闭未决责任、重开新集合、语言切换、窄窗／DPI／长文本／深浅主题／背景模式。不能用构建或 SOURCE 通过代替该范围。

产物只允许固定工程 IntDir／统一 Release；本轮仅源码、文档和 CodeBuddy 文本日志，不生成运行副本、Qt DLL 部署或测试配置。未暂存、未提交，不修改用户暂存区。

## 执行证据的责任边界

进程集合普通 Pause 不产生执行断点，本页不从暂停、内存内容或部分字节派生 `NativeExecutionEvidence`，不向 `raw-native` 写伪执行记录。主协调者新增 `ProjectNativeExecution` 的核心测试复用其独立 CodeBuddy 回执。

用户已追加授权本端产品接线。真实入口为 Qt `监控 → 行为分析 → 写入停点`，Light `监控 → 行为分析 → 工程、采集与写入停点 → 写入停点`。Qt 原 `SessionOwner::session` 和 Light 原 `backend` 均保留为 `OwnedDataWatchSession`，没有第二owner，没有CLI协议或子进程。核心 `CaptureMemory`／`SaveExecution` 实现位于新增 `Control/OwnedDataWatchSessionArchive.cpp`，两端工程及filters连同 `ProjectNativeExecution` 登记。

Qt `NativeStopMemoryArchive.*` 和 Light `LightNativeStopArchive.*` 各自持有本端独立项目写租约。先创建全新项目目录与真实sample，再Start绑定该sample；无目录可读取，保存禁用。范围草稿显式执行，读取不调用条件ApplyCondition，完整capture保留真实before/after并传入 `WriteProcessGroupMemorySnapshot`。执行保存只对 `NativeExecutionFromOwnedStop` 实际可提取事件启用，普通dataWrite不可保存。`SaveExecution` 由原session只读回查当前精确事件后写入，失败保留receipt并只阻断raw-native，不阻止内存或清退。

两端执行流只支持本次显式新项目的新sample，其raw-native前链初始为空，不打开既有采样追加。保存成功后用真实flushed末序号O(1)推进；同backend/serial事件返回原段坐标，去重上限4096，回看历史不会解除坏尾阻断。未来若增加打开已有sample，必须先一次性完整核验前链，不允许从段号猜前序。

Qt 参数和结果继续复用ParameterWorkspace/StructuredFieldView；内存读/保存动作移到固定FlowLayout工具区。Light新增共享 `Ui/ParameterWorkspace.*` 承担参数唯一滚动职责，宽窗左右、窄窗上下，动作固定、结果保持独立滚动，键盘Tab会揭示参数。Light结果沿用本项目原生EDIT＋TextFindSupport；Qt CodeEditorWidget不可跨原生工具链直接使用，此为该端已有共享文本适配，视觉和完整导出仍待GUI验收。两端新增可见Qt文本均定点同步双语；暂停派发后未运行新语言审计。

Qt写入页退出租约使用现有AsyncCleanupRegistry；清退任务等待原唯一在途回合，持续调用原session.Close，真实clean且无附加后在原worker关闭项目租约，再归还退出租约。Light复用现有BackgroundWork清退。该生命周期实现未构建、未GUI、未作性能或故障恢复实测。

## 本轮源码修补与明确未验边界

原内存只读审查任务 `20261126-034938-31a82d6f` 已于 `2026-11-26T04:40:18-04:00` 完成。早期报告退出1并抓到F1及F2–F6；其最终快照为 `2026-11-26T08:38:02Z`，已登记Qt修补，并通过70项静态检查，`hard_failures=0 findings=1`。默认脚本退出0不表示无发现：严格发现模式仍为3，残留F2见下表。此为既有任务回执登记，本端没有重跑、续接或新派发；后续代码不在该快照覆盖内。

| 旧发现 | 当前源码处理 | 尚未完成 |
| --- | --- | --- |
| F1 无项目sample非UUID | Qt Configure前生成sample/backend UUID；session/epoch沿用本会话UUID，不再把显示标签传给账本。 | 无项目真实Pause／Held读取待验。 |
| F2 拒绝且未访问页面仍可保存空段 | 两端按钮及writer适配均要求实际round且pages非空；已访问但全失败的轮次可保存真实失败元数据，不写不存在的字节。 | **共享writer与CLI仍未闭合**：最终审查确认 `ProjectMemorySnapshot::PrepareRows` 对无round被拒捕获可写出已核验空段，须由核心作者处理；本端不越权修改。Qt／Light真实拒绝、空轮次及部分访问负控仍待验。 |
| F3 缺采样器诊断与未访问页 | Qt／Light投影state、issue.stage、Win32/NTSTATUS、计划/已访问/未访问页数。 | 拒绝／退出／取消显示待验。 |
| F4 同会话来源标签不稳定 | 两端纯值适配均取原停止组session/epoch；不宣称系统机器/启动身份。 | 跨两次读取的归档字段核对待验。 |
| F5 后台异常无原因 | Qt初始化与工作回合保存有界异常摘要，独立于原生stage/错误；自动Query不清除上一笔摘要。 | 分配失败及异常清退路径待验。 |
| F6 半创建目录不显示 | 实际请求目录在Create前保留；Start／Configure前失败关闭项目租约，不删除现场，后续需显式选择新目录。 | 半创建失败、清退换目录恢复待验。 |

另外，内存保存保留独立 `memoryArchiveSource`／`archiveSource`。坏尾后新读取不会把旧归档回执重新标成新范围；归档坐标在没有新快照时也保留。执行流的首次失败另存纯值快照，旧成功事件重放同时展示原坐标和后续首次阻断的原因、段号及真实写入/刷盘端点。Light写入worker在发布inactive前显式关闭项目租约；Qt写入页的Closed／Detached／Ended均在原串行回合关闭writer，Qt集合则在发布retired前释放writer。Configure异常仍保留实际目录和sample，原生状态未知时由原Close结算，不自动假定配置失败等于没有责任。

Light原生参数动作改由共享 `Ui::LayoutParameterActions` 按可用宽度自然换行，测量阶段不移动控件；参数区独立滚动并在Tab导航时揭示焦点。极矮窗口、DPI/字体缩放、复杂长文本和所有状态下的可读性**尚未验证**，不能宣称全页面UI合规。文本结果通过同一完整文档搜索、复制和UTF-8导出；未触碰真实剪贴板或弹出文件对话框做验收。

### Light集合源码整合已落盘，验收后置

原Light作者任务 `20261126-033240-c8df8f61` 于 `2026-11-26T04:42:32.5359515-04:00` 结束，状态 completed／ok=true／exit0。最终文本只有工程登记进行中的一句说明，没有预期SOURCE报告。该任务与内存审查任务均已结束；本轮仅登记旧回执，没有续接、重试或复制任务。

原作者结束后，已在其文件上完成以下源码整合，均为**未构建、未运行、未取得新SOURCE回执**的实现：

1. `LightProcessGroupSession` 原串行worker持有不可移动的 `optional<LightProcessGroupMemoryState>`；新集合在旧group已clean释放后显式 `emplace()` 重置状态。Configure前创建独立新项目和真实sample，无项目使用新UUID身份，不重写旧capture的Plan。
2. `ReadMemory`／`SaveMemory` 使用同一队列，点击时复制完整请求或不可变capture指针。读取不调用条件或暂停／继续；保存传递完整capture与readContext，使用独立raw-memory前链。
3. 配置入队即冻结草稿并置busy；自动Query也占用原单在途槽。后台异常保留原因与原控制器，显式动作结论和原operation三字段独立于后续Query，历史最多128票据。新集合Configure发布时清除旧集合历史控制入口，票据号继续严格递增。
4. Close确认clean后先归还writer，再发布closedClean。没有group、半创建失败及Idle＋clean路径也能显式清退；未clean保留原owner，只接受Query／原Continue票据Recover。程序退出准入先清退，worker留到页面真正销毁，避免取消退出后失去可用会话。
5. 页面接入新项目目录、base／bytes草稿、唯一选中Held成员读取、原capture保存、归档来源与采样诊断。配置失败解开等待态，必须清退并显式“准备新集合”才开放下一草稿；准备时保留旧归档结果，不因关闭静默清空。
6. 页面按业务／状态／布局分文件，参数进入共享独立滚动正文，固定动作通过共享自然换行。列表只放PID、成员状态和清退三列；原始创建时间、完整令牌和诊断在详情。该紧凑清单不触发密集表A/B列组条件，也不新增表头菜单。
7. 详情搜索、复制与UTF-8导出来自同一完整文本。所有动作具有悬停释义；集合与子集暂停／继续、恢复及清退动作需要文字区分范围，保留文字。Light使用既有原生EDIT适配，Qt的CodeEditorWidget不跨本端工具链引入。说明与标签显式允许折行，结果区扣除详情工具行高度，隐藏页只停投影定时器，原责任worker不停止。
8. 新增布局／状态文件及最终page／session已登记Light工程和filters；源码读回修正了Run缺类内声明、错误历史索引、非法创建时间校验，以及两端身份读取异常路径的句柄释放。新Configure实际开始时撤下旧集合的活成员和控制票据投影，异常时只保留原恢复、回查与清退资格，避免新配置异常后误用旧令牌。此处“读回”是实现过程，不是替代SOURCE审查或测试回执。

当前正式产品验收结论：无。SOURCE、语言审计、HostX64 Release整合构建、真实GUI、故障恢复和性能均待恢复相应验收授权后取得回执；不能由本节实现清单推导通过。极矮窗口、DPI／字体缩放、深浅主题、背景模式、长文档及退出取消／重新配置时序尤其需要实机验证。

### 限定文件与后续验收

- Qt集合：`ActionAnalyze/ProcessGroupPage.*`、`ProcessGroupSession.*`、`ProcessGroupMemoryPane.*`，既有导航接线及主工程/filters。
- Qt写入／步进：`ActionAnalyze/DataWriteWatchPage.cpp`、`NativeStopMemoryArchive.*`、双语定点项及主工程/filters。
- Light独立模块／写入页：`Features/ActionAnalyze/LightProcessGroupMemory.*`、`LightNativeStopArchive.*`、`LightDataWatchSession.*`、`DataWatchPage.cpp`、`Ui/ParameterWorkspace.*`，工程/filters。
- Light集合：`LightProcessGroupSession.*`、`ProcessGroupPage.h/.cpp`、`ProcessGroupPageState.h`、`ProcessGroupPageLayout.cpp` 与既有 `Features/Monitor/MonitorFeature.cpp` 入口；原作者结束后整合其源码，未暂存、未提交。
- 核心 `OwnedProcessGroup.*`、`OwnedDataWatchSession*`、快照及项目writer只读使用，原作者负责底层实证。

用户明确恢复后，由改动作者按新源码重新取得适用SOURCE与双语回执，再按用户顺序进行HostX64 Release整合构建及独立桌面产品验收。不因暂停派发自行运行替代模型或审计。当前新增构建/测试产物：无；新增测试配置：无；运行副本/Qt部署：无；无需删除正式Release或原作者取证。
