# ActionAnalyze 工程推进记录

## 持续推进与交接

- **2026-11-26 新授权最多3项测试。** 用户原话「我再批3个测试的额度，可继续调用codebuddy。」计划按条件解析、历史线程恢复失败、集合追加成员各一项，限制focused场景，禁止整批重跑、GUI或额外子派发。主代理仍负责功能源码；所有测试改动、执行、结果落盘归CodeBuddy。已用2/3：条件文本字段最多8组（sh_21812235f001qocCy95j8uXwn2）、历史线程恢复最多2场景（sh_21813eecb001fKXDq9hTcc2QML）已直接派出；剩余1项在集合追加源码提交后派发。只允许第三项构建完整CLI一次，前两项编译独立小夹具，固定IntDir/统一Release。自动等回执，不轮询、不擅自续接。最新goal重激活不撤销本次数量边界。

- **2026-11-26 第4/6项运行中追加实例源码。** OwnedExecutionGroup::AppendMembers按显式授权+原collectionId接收新站点，总计16个不同PID；先统一校验和分配，逐新成员独立Attach，原成员仅QueryWithoutCondition、不Continue/重建。Start无项目也只生成一个sample，后续沿用。ExecutionGroupArchive使用原sample冻结定义解析，追加失败独立memberSetupError，保留旧setup/writer。CLI新增members-append/control.members.append及原execution/N重放；Qt/Light原worker与固定动作栏接当前完整表单，Qt模型末尾insert不reset。导航为监控→行为分析→执行断点集合，参数执行+None管理清单+共享字段详情，复用ParameterWorkspace/FlowLayout/原生适配；对照DataWriteWatchPage与ProcessGroupMemoryPane及其共享实现。没有新增轮询、驱动协议、页面或源码文件；双语及CLI帮助文档同步。主代理未执行构建/测试/GUI，运行交第三项CodeBuddy，尚未通过；不自动后代或全系统激活。

- **2026-11-26 第10项文本字段等值源码。** 原FilterAst新增TextFieldComparison布尔叶，准备时绑定双方当前阶段Text目录，v3解析`left.field ==/!= right.field`，原常量/null/v1/v2路径保留。解释器左到右读取，完整Known按原UTF-8区分大小写比较，两个显式Null相等、Null/空文本不同；缺失/截断/读失败为Unknown，不因同字段折叠，原预算/UTF-8故障保留。Qt规则草稿说明、CLI catalog内置help、README/CLI文档及双语同步；Light预置回放复用同一核心，不新增字段或页面。仅源码，无构建/测试/GUI/派发/验收记录/推送。另已核对执行集合AddRange实际已有三端完整接线，不再重复实现。

- 文本字段间比较随后调整为先走原二元优先级再归并叶；不能在Atom中提前生成bool，避免`bool == textA == textB`被错误接受为`bool == (textA == textB)`。临时字段叶只在当前阶段两Text的==/!=归并，未归并交原类型准备拒绝；不修改原文本常量语法。仍仅源码未测。

- **2026-11-26 第9项独立历史失败发布补齐。** Qt保存本次原生失败摘要，即使首次无可发布快照或保留旧完整树仍显示真实段/阶段/Win32；取消沿原取消态。达到4096段的已核验独立原生窗口不再被旧Complete拦住。Light普通raw缺失、原生链坏时沿原失败回执显示raw-native段及项目错误，不清诊断或伪装空成功。只改原异步读侧及共享状态文案，无布局/计时器/所有者变动。CLI新增共享include的三级父路径已直接核对为仓库shared。源码未构建/测试/GUI/推送，无新增验收记录；原用户KswordCLI.cpp改动保留。

- **2026-11-26 第5/6项非CALL步过源码。** 原`NativeStepRuntime::Destination`对OverCall的非CALL分支改用既有TF路径，CALL继续DR1返回边界；请求模式不改写、无目的地表示单条TF，不预测跳转或RET后IP。`NativeStepUsesSingleInstructionTrap`统一证据及同时DR0/TF事件分类，完成的真实单条TF可形成instruction-completed，CALL返回/Out/内部NX推进仍不冒充。Qt、Light、CLI单目标及集合沿同一runtime，无新增owner、轮询或页面布局；CLI内置help/文档同步。历史“仅用户Into”边界由此源码扩为“用户Into或非CALL Over的真实单条TF”，不是运行通过。无构建/测试/GUI/验收记录/派发/推送，历史线程退出及取消失败仍待验。

- **2026-11-26 第9项独立原生历史源码。** 共享`ApiNativeExecutionProjection`新增最近512条独立观察及`NativeExecutionHistorySource`；不要求匹配API，完整来源含原生段号/序号/偏移/块/端点/SHA256及原文。Qt归档关系树第十根、Light原生历史状态根加入叶项，按原物理坐标和散列续持选择，共用原字段/文本详情；只有raw-native的采样沿原项目异步回放入口接入，不伪报API/ETW终段。CLI新增`analyze execution history --after N --limit N`共享同一读侧，摘要分页默认32/最大128、全链上限4096，完整原文沿execution read。导航为监控→行为分析→项目与采样→归档关系，类型主树+共享详情；对照原API关系树、原生候选字段视图和Light候选树，不新增布局/观察器。内置help、CLI文档及双语同步，CLI登记共享cpp。仅源码，无构建/测试/GUI/验收记录/推送；既有其他核心缺口继续推进，禁止新CodeBuddy派发仍有效。

- **2026-11-26 第1/2项启动展示源码归位。** 提交此前遗留的Qt条件块位置修正：先组合API启动阶段再判断状态文本是否变化，执行观察的if声明与其字段块保持同一作用域，避免阶段存在性错误门控状态刷新。Light将启动详情与原诊断按实际区块排列；语言包/CLI文档仅归位已有启动字段与同步采集说明，无新增采集行为。源码未构建/运行，正式Release未更新。

- **2026-11-26 第10项bool等值比较新增源码。** 复用BooleanBinary扩展Equal/NotEqual，v3 bool字段保留原null测试，其它比较交共享优先级解析器，支持bool字段/括号/函数/三元谓词之间==/!=。两侧左到右，任一未知即Unknown、两个未知不推断相等；大小比较和bool/u64混用仍拒绝，v1/v2仍走原解析。三端提示、CLI内置help、规则README及双语同步。此前回执中bool字段间==为无的边界已由这批源码扩展，但未构建、测试、GUI或派发，不能改为运行已通过。

- **2026-11-26 第10项布尔非短路源码闭合。** v3解析器按两侧静态输出选择BooleanBinary/u64 NumericBinary，解释器按左到右依次计算bool &/^/|，算术和预算故障仍使最终Unknown；同为bool或同为u64，混合拒绝，v1/v2不开放。Qt规则草稿、写入停点、Light说明与CLI内置help、两份文档及双语同步。CodeBuddy确认已有主体无新增行为缺口，仅修FilterAst契约注释，主代理补RuleExpression.h过时说明。只是有限C#风格谓词，不是完整C#执行环境；bool字段间==仍为无。无构建/运行/GUI/新增验收记录/推送。

- **2026-11-26 第5/6项线程恢复源码整合。** 接收CodeBuddy原限定任务的两处改动：`NativeStepRuntime::Restore`在上下文失败时仍逐真实线程对象结清已signaled退出对象的暂停债，存活债保留；`NativeDebugOwner::RestoreStep`在step资源为空的返回之前先处理仍开放的NX页。主代理只整理新增注释和代码排版，没有重复完整审查或执行验收。历史线程退出/取消后Continue异常保持待验，未构建/测试/GUI/推送。

- **2026-11-26 第5/6项执行集合成员内存源码。** 原`OwnedExecutionGroup::CaptureMemory`核对原owner/完整Held后复用该成员`OwnedDataWatchSession::CaptureMemory`；不求同伴条件、不Continue、不改为实时读取。`ExecutionGroupArchive`保留最新读取和独立保存来源，复用原writer/sample的`raw-memory`，独立段号/前序、同读取去重、真实写入失败阻止后续追加。CLI接`memory-read/control.memory.read`及`memory-save/control.memory.save`，原execution/N重放；保存按trackingEpoch指定当前原字节。Qt复用ProcessGroupMemoryPane参数及新AppendCapture字段入口，隐藏重复项目；Light沿原参数正文及唯一worker；两端Close置已有取消位、读取收尾后原集合清退。导航仍为监控→行为分析→执行断点集合，页面类型参数执行＋None清单＋共享字段详情，对照写入停点与原停止组内存页。本批无构建、测试、GUI、验收记录或推送，产物未更新。
- **2026-11-26 两项CodeBuddy恢复任务结束。** 长宿主自动回执两项ok，布尔245004ms、线程恢复170694ms；均只源码。布尔作者确认已有v3 &/^/|的bool/u64路径闭合，仅修正FilterAst.h契约注释，指出RuleExpression.h旧说明需同步。线程作者新增DischargeExitedHold，仅按真实线程对象signaled证明免除退出对象暂停债，存活债务保留；RestoreStep先回关NX再判断step资源。不得推断历史CountPeerTicks=0或取消后0xC0000005已运行修复。限定两次授权已结束，继续禁止新派发/续接/重试，自动回执位置仍在.codex-build-logs/codebuddy-two-dispatch。

- **2026-11-26 第4/6项集合同采样API源码。** 原`ExecutionGroupArchive`借本轮唯一writer/sample和`CaptureNativeBoundApi`采另一明确来源，拒绝来源为任一集合成员；前后`QueryWithoutCondition`不求条件、不Continue、不自动保存执行事件。Qt复用`NativeSessionApiPane`、原worker和200ms投影，Light复用`NativeSessionApiFields`和原250ms快照；两端关闭立即置原取消位，排空后才Close成员及writer。CLI `api-capture execution/N ... REPLSESSIONTOKEN [progress]`／`control.api.capture`用唯一完整sessionToken、原128回执流水；解析/完整报告复用单目标入口，stdout响应、stderr可选进度。CLI有限同步采集期间控制排队，不能声称在途取消。本批仅源码，未构建、测试、GUI、验收落盘或推送。
- **2026-11-26 两项CodeBuddy网络恢复授权。** 用户明确「网络环境炸了刚才，你可以继续跑那两个炸掉的」。原批次90秒首token超时退出1；首次恢复宿主误设后台120秒超时退出143，已确认无残留派发/CodeBuddy进程后，同两项改为30分钟宿主上限重跑，当前`sh_217ef3fbd001zM5SIntRv2cBgQ`。仍只允许条件布尔/线程恢复原限定源码，不测试/构建/GUI/验收/再派发，等自动最终通知，不轮询；本次恢复不开放其他CodeBuddy任务。

- **2026-11-26 第6项集合冻结定义源码。** `ExecutionGroupArchive::ResolveSites`在首个成员附加前以副本解析全部模块RVA站点的可选`definitionId`，复用`ResolveSampleImageDefinition`读取本轮sample冻结启用定义，核对模块名/RVA并继承映像散列；冲突、缺项目或不支持定位在附加前失败并释放未使用writer。Qt/Light/CLI同入口，结果保留实际解析后站点和期望散列；隐藏模式保留草稿但不发送。项目失败沿原空集合清退再启动恢复。只是显式实例站点引用，不是完整全局定义自动激活，不解析PDB。本批未构建、测试、GUI、派发或推送。

- **2026-11-26 执行集合显式保存三端源码。** `Project/ExecutionGroupArchive`在原worker准备可选新项目／打开项目及本轮新sample，全部原成员沿用真实sample；保存前`OwnedExecutionGroup::QueryWithoutCondition`回读原owner完整事件，不求同伴条件、不Continue。`native-execution-v3`原写入器保留18寄存器、事件绑定、NX范围及实测散列，backend/serial去重；真实追加失败阻止跳段，保留首次失败及written/flushed/verified。CLI `--project PATH [--open-project]`与`execution-save`／`control.execution.save`；Qt／Light原执行集合参数页、原worker、详情同步接入。导航为“监控→行为分析→执行断点集合”，类型为参数执行＋管理表（None）＋同源字段详情，沿用ParameterWorkspace；对照原DataWriteWatch及ProcessGroupMemoryPane。全部新增仅源码，无构建／测试／GUI／验收回执／推送。继续禁止新增CodeBuddy任务，已派两项仍等待自动最终消息，不轮询。

- **2026-11-26 进度口径纠正，交接保留。** 用户质疑“整体70%”是否为应付目标；主代理已明确收回整体70%及±10%说法。这些数值没有统一任务分母或权重，混合了历史实证与新源码接线，不能证明达到70%目标。以后按“历史正式产品已验范围／新增源码已接待验／明确未实现”报告，不以新增提交数量或主观平均数提高完成度，不为重新算百分比增加审查和验收任务。
- **2026-11-26 `278d1e4df` 同采样API在途启动源码。** 共享`NativeBoundApiProgress`携带原项目、采样、来源及native目标身份，沿原采集线程发布实际里程碑。Qt复用原200ms值刷新，Light复用原状态快照；CLI `api-capture ... confirm [progress]`或`params.startupProgress:true`向stderr输出带身份JSONL，stdout仍为原最终响应。完整采集/归档仍看最终回执。本批未构建、未测试、未GUI、未推送，不新增验收记录。

- **2026-11-26 当前开发批次，均仅源码且未推送。** `ff32000ba` 将真实Agent启动阶段接入CLI stderr与Qt/Light原快照；`353ccd441` 从已核验终段回放同一启动快照，旧档为null，归档详情不查询当前PID。`56b2dd4bf` 为执行集合各模块站点接可选SHA256，原owner验证装载事件文件，完整成员票据保留实测值，桌面保留期望值草稿。`c72a380f2` 聚合嵌套恢复责任，单成员Step/Cancel前置回读不自动释放其它成员。`234dddf40` 接Qt/Light同采样API关闭取消，原采集排空后再串行关闭native；启动前取消不装Agent、不创建API流。`ef27b3382` 新写`native-execution-v3`，保存同一事件原绑定、已纳入NX范围、实测文件散列；继续读旧v1/v2，不把历史绑定还原成控制。未执行构建、测试、GUI或新增验收记录，旧回执不覆盖这些变化。
- **CodeBuddy本轮唯一两次例外。** 用户仅批准直接派2项后等回执，再恢复静默；已一批直接派【条件布尔运算】与【线程恢复】，两项只做限定源码修正，不测试/构建/GUI/再派发/提交推送。最终文本在`.codex-build-logs/codebuddy-two-dispatch/`，批次宿主`sh_217a8b3fe001t52NhqCaDy67Ji`。等待自动最终通知，不轮询、不重试、不续接。布尔运算主体与三端提示尚未提交，等原直接任务回执后收整；历史线程退出/等待取消失败仍不得标修复通过。交接须保留这条限额，goal重激活不撤销限制。

用户2026-11-26最新明确「不需要测试」：当前阶段继续产品实现，不执行测试、不为测试构建、不新增CodeBuddy任务或验收回执。用户询问的五小时目标为第1、2、4、5、6、9、10项源码功能链路各推进到70%以上；这是开发目标，不能把新增代码当作运行通过。原生范围与TF推进、Light工具条及单页入口、AAIM1内存生命周期三位作者继续独立完整开发，主协调完成Qt/CLI及共享消费衔接。

用户原话：「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。进度答复后继续执行当前任务。该原话、未完成项目及下一可执行步骤须保留在压缩摘要和交接记录。按 [11 项产品验收清单](../../docs/ActionAnalyze产品验收清单.md) 更新状态，正式产品实证明确到入口、产物和测试范围，闭合批次仅推送 `ActionAnalyze`。

- **2026-11-26 验收纠偏补充。** 用户批准当前失败的CodeBuddy验收继续，要求核验必要性、削减约70%非必要门禁并明确边界。只恢复已有失败任务；同会话唯一续跑、CLI单次共享构建、失败仅复跑受影响场景。主协调已唯一续接旧CLI步进会话，先裁剪默认场景42→12（计划减少约71%），暂不授予构建/运行工具，等并行产品源码完成再明确允许实测；不扩验新增协议或GUI，不再并行续接相同会话。边界见[缩减批次](../../docs/action-analyze-planning/validation-reduced-batch.md)。
- 第4、5、6项本批新增源码：`CooperativeApiRequest::boundSampleId`复用原写租约和冻结采样，`RequireUnusedApiArchive`拒绝已有raw/checkpoints（含空目录或坏尾）；正式原生CLI的`control.api.capture`显式采另一来源实例，保留原native/memory控制。`BreakpointFollowProtocol`接`control.execution.follow`/`execution-follow`，独立128票据、原地址/完整当前停点核验、不Continue。原生作者已返回源码READY，新增`NativeWriteExecutionTransition.cpp`须由直接编译owner的自定义脚本一并链接。新功能、Qt/Light及新增协议仍未实测；旧失败续跑只按缩减范围，不自动扩大覆盖。
- 缩减源码续跑已结束，默认focused/full及skip-build已落盘。其回执仍有full空跑选择错误和内存两附加调用未计数，已在同一旧CodeBuddy会话下一次续跑要求修正（实际14/42约减67%）、禁止零场景PASS/异常不计失败、跳构建不伪报exit0，并授权产品READY后的四入口串行实测。当前唯一运行`sh_21715e4b1001abcgnDQDC1IVN3`，会话`01a216aa-73ca-7be7-8ebd-495384c02f91`；不再另派同会话副本，最终结果到达前不重试或轮询。

- **2026-11-26 最新限制优先于当前 goal，压缩与交接必留。** 用户原话：「从现在开始暂时不允许派发CodeBuddy任务，我会在可用时告诉你」「这个限制在goal之上，记得在上下文中保留。旧的继续。」已派发的旧任务继续运行；收到结果可登记，但用户明确恢复前不得新增派发、续接、失败重试或自动后续 CodeBuddy 任务。主协调与开发子代理继续写核心产品，未验部分保持待验，不自行替代原验收分工。
- **2026-11-26 双端集合源码接线收尾。** Light原作者任务033240及内存审查034938均已结束，前者未交付SOURCE报告，后者70项静态检查仍有共享writer／CLI的F2发现。原作者结束后Light集合已接原worker的Held范围读取、完整capture保存、新项目sample、clean后writer释放和显式下一集合；业务／状态／布局分文件并登记工程。Qt／Light写入页真实执行保存沿原OwnedDataWatchSession，普通Pause不构成执行证据。全部后续源码、双语、构建、GUI与退出取消时序仍待验，不新增派发或替代测试；详见[双端集合交付记录](../../docs/action-analyze-planning/process-group-desktop.md)。
- 最新优先级为「少在视图下功夫，多在全局调试和后端下功夫」。用户要求全部其他项完成前延后 Qt 和 Win32 GUI 桌面实测。现阶段允许相应正式构建、无窗口原生回归和正式 CLI 本机实测，历史桌面回执继续按各自范围记录。恢复 GUI 实测时复用 `tools/action_analyze_validation/isolated_desktop.py`，在独立非输入桌面执行。
- 用户最新要求「全面减少构建，只有当真的需要实测的时候才构建」。Qt／Light 后续源码改动累积至恢复桌面实测再整合构建；CLI 与无窗口验证只为实际待实测的批次构建。第 3、7、8 项保留后置顺序。
- 用户再次明确：主协调者优先写核心产品代码、整理职责；GUI 和 CLI 验收（包括夹具维护、实际执行、失败回执和落盘）交给子代理，由其用 CodeBuddy 在本机跑。复用已有效的回执，不为重复坐标和已覆盖行为追加轮次；改产品代码只做与实际变化相关的必要验收。
- 项目是默认工作单位。入口必须可新建和打开项目，并保留新一轮扫描入口。每次扫描生成独立采样和冻结配置。目录选择只进行只读分析，证据回查继续绑定该采样真实坐标。Qt 在独立桌面已验证同一项目两轮扫描及重启回放，记录见产品验收清单。
- 合作直连由 `Project/CooperativeApiCapture` 和 `Project/ProjectApiClueArchive` 复用采集与封段；CLI、Qt、Light 各保留本端会话、停止及项目租约。新桌面入口只编译合作控制分支（`KSWORD_APIMON_COOPERATIVE_ONLY`），不添加自动装载。合作流水号与 `raw` 坐标分列，规则在封段后回读；不得用已有同档回放、构建或静态门禁冒充桌面直连。[本批正式回执](../../docs/action-analyze-planning/validation-results.md#合作采集项目后端复验)

## 2026-11-24 首批工程启动

- 用户授权多 agent 并发编码、按功能分批提交和推送。主协调者负责分工、接口对齐、证据审查、集成排序、Git 和工程记录。逻辑闭合的工作包可先提交到 `ActionAnalyze`，适用构建可随后执行。分别记录源码、构建、原生和产品验收状态，产品验收项凭对应产品证据关闭。
- 新增或重构文件每文件上限 2000 行，沿用仓库建议的 1000 行组织目标。按职责拆 `.h`／`.cpp`，驱动用适用 `.h`／`.c`，禁止 `.inc` 堆叠。重构逐项登记受影响的旧功能与入口、行为、端／架构、复测判据、实际结果和待测范围。优先单独提交可验证的结构改动。
- R3 是正式后端，必须在 KSword 驱动未加载或不可访问时独立完成受支持用户态全流程。采样显式选择后端，活采样禁止静默切换。更换时原所有者先完成恢复并确认脱离，之后新建采样与会话代次，旧停点令牌和恢复责任留在原后端。
- 已确认同步下断使用命中线程直接进入已登记原生停点、目标外所有者接管。首个双架构夹具用自有合作目标验证调试所有权、进入／返回阶段和原调用语义。
- 用户指定 Qt 的唯一挂载点为「监控 → 行为分析」。总览、项目与采样、后续规则和断点等均是该工作台的子页。MonitorDock 管理根宿主，实际页签、全局搜索和 Taskbar 共用 `monitor.action_analyze` 导航树。
- 新增桌面工作包覆盖显示筛选、底部进程与线程右键和 Dump 导出、随采样自动归档网络流量元数据、出站 IP 和实际通信字节。网络写入沿用采样内 `raw`、`records`、BlobStore 和检查点。采样身份贯穿筛选、菜单与归档。[桌面交互计划](../../docs/ActionAnalyze总览交互与验收.md#显示筛选对象菜单与网络证据实施计划)
- 停止调试后的目标处置，以及单步时是否扩大依赖线程放行范围，仍由调用方显式决定。发现影响持久格式、恢复语义、采集范围或无驱动承诺的歧义时，先在依赖方之间对齐。产品需求变更写回共享基线并通知全部受影响 owner。

首批分工已启动，状态为开发进行中。A0 类型与 Stored 契约、CLI 离线外壳、Stored 归档与恢复、CLI 项目生命周期、离线规则回放、R3 停点夹具、被动环境入口目录、既有上游目录按行数拆分，各自独立编辑，统一审查提交。CLI `.vcxproj`／`.filters`、入口接线与内置帮助、文档同步在接口交付后统一分配，并串行运行共用构建工程。

## 当前验收决定

全范围完成验收后才能最终关闭。R3 在本机验证。普通 R0 在指定来宾 `E:\VMs\Windows11-24H2` 阻塞。普通 R0 入口要求 `RtlGetVersion` 报告 OS build `26300`，来宾 OS 为 `26100.9711`，SYS 就绪也无法通过。来宾已有 `TESTSIGNING`，KSwordARK 服务未注册、驱动未加载，现有产物来源与验证批次不匹配，配套签名候选产物未暂存。29 项普通 R0 外部判据尚未运行。历史夹具沿用各次授权和原始证据。环境详见本地计划 `docs/ActionAnalyze工程开工基线.md` 的「验收范围与运行环境」。

## 已接收批次与证据

| 提交 | 内容与证据 | 分支状态 |
| --- | --- | --- |
| `69f490db2` | 离线协议模型，本次无写入重跑 31/31 通过。 | 已推送 `origin/ActionAnalyze` |
| `f28f7fd5a` | 自有目标的 R3 原生步进夹具，本批沿用历史 106 项断言通过的证据。 | 已推送 `origin/ActionAnalyze` |
| `f04142e96` | 自有目标的传输夹具，保留历史 37 项 IPC 回归、7 项父进程终止后的子进程清理、TCP 权限负控。实际成功断连待验。 | 已推送 `origin/ActionAnalyze` |
| `f0efdde80` | 固定规则来源目录，共 24 个文件。11 个分片顺序拼接与原索引字节一致，批次内各文件最多 2000 行。 | 与 `10e0f370f` 同批推送至 `origin/ActionAnalyze` |
| `10e0f370f` | 自有目标页面执行探针夹具，沿用历史 21 项检查通过的证据。 | 与 `f0efdde80` 同批推送至 `origin/ActionAnalyze` |
| `055fef531` | SB02 自有目标同步停点夹具。Windows 10 19045，BelowNormal、HostX64 构建 x64 及 Win32 两个 Release，分别运行原生 x64 与 WOW64 目标。386 项断言通过，四个自有子进程，8 次真实停点、8 次旧代次或外来事件正确转交，四个正常退出事件，零测试配置、零残留夹具进程。[SB02 夹具说明](../../tools/action_analyze_sync_stop_validation/README.md) | 已推送 `origin/ActionAnalyze` |
| `6b459325e` | CLI 离线会话外壳和命令帮助。共用正式工程 HostX64 Release 构建退出 0，0 警告、0 错误，产物 `Ksword5.1/x64/Release/KswordCLI.exe`。旧 shell smoke 已独立运行并通过。本机构建日志 `.codex-build-logs/action-analyze-cli-shell-20261124-223330.log`。[旧 shell 回执](../../tools/action_analyze_validation/cli/README.md#first-shell-build-evidence) | 已推送 `origin/ActionAnalyze` |
| `5adc91d33` | A0 基础和 Stored v1 静态契约。66 项基础用例、35 项 Stored 用例及 CRC／UUID 检查通过。[基础契约](../../schemas/action_analyze/base-contract-v1.md) | 已推送 `origin/ActionAnalyze` |
| `a7d40bc27` | A0 离线 CLI 方法静态契约。62 项请求、传输及输出向量通过。[方法契约](../../schemas/action_analyze/method-contract-v1.md) | 已推送 `origin/ActionAnalyze` |
| `121ef3ea2` | Stored v1 分段读写与前缀扫描，覆盖封装范围与 CRC。记录语义解码另验。[归档验证范围](../../tools/action_analyze_validation/archive/README.md) | 已推送 `origin/ActionAnalyze` |
| `d2f246c8e` | 类型化离线规则回放与有界筛选。仓库夹具使用内存事件投影，完整 DSL、真实归档接线和实时策略继续按工单验收。[规则夹具范围](../../tools/action_analyze_validation/rules/README.md) | 已推送 `origin/ActionAnalyze` |
| `9a5449304` | 离线项目、配置修订和采样持久化。HostX64 Release 原生夹具 71 项以及 Python 文件与语义校验通过。最终可达代次链为 `6 → 4 → 3 → 2 → 1`，第 5 代保持未提交。[验证回执](../../tools/action_analyze_validation/project/ValidationReceipt.md) | 已推送 `origin/ActionAnalyze` |
| `96b9f38bd` | 被动环境证据来源索引归档。覆盖资料目录的静态清点，运行覆盖按独立判据验收。[来源索引](../../docs/action-analyze-planning/environment/README.md) | 已推送 `origin/ActionAnalyze` |
| `9c52f1847` | 原生停止责任账本与 C++ 夹具。账本处理单原生事件的释放责任。[账本范围](../../KswordCLI/ActionAnalyze/Control/README.md) | 已推送 `origin/ActionAnalyze` |
| `c0543c4dd` | Qt 普通 R0 回读解析器构建通过。R0 运行未执行。 | 已推送 `origin/ActionAnalyze` |
| `14509b8aa` | A0.2 离线项目／采样方法，62 项基础向量及 47 项项目方法向量通过。 | 已推送 `origin/ActionAnalyze` |
| `221cda4ba` | 正式 CLI 离线项目生命周期接线。HostX64 Release 构建退出 0，0 警告、0 错误。正式 CLI 的 `project_v1` 验证通过，临时验证目录已清理。 | 已推送 `origin/ActionAnalyze` |
| `923e36acc` | 保留 origin 的停止快照契约，96 项离线停止向量通过。 | 已推送 `origin/ActionAnalyze` |
| `59046a957` | 自有合作目标的原生停点与责任账本夹具。集成 495 项、基线 415 项、独立账本 124 项通过，范围限于各自夹具。 | 已推送 `origin/ActionAnalyze` |
| `345472b89` | Stored 格式分类与截断覆盖。469 项截断检查、35 项 A0 封装向量通过。 | 已推送 `origin/ActionAnalyze` |
| `a302d03cc` | 已提交采样的项目归档段解析器。28 项原生检查及 71 项项目生命周期夹具检查通过。 | 已推送 `origin/ActionAnalyze` |
| `a7f117606` | 正式 CLI 接通 `archive.inspect`。HostX64 Release 构建、12 方法的传输回归、项目及归档验收通过，测试目录已清理。[归档回执](../../tools/action_analyze_validation/cli/README.md#archive-v1-build-and-test-receipt) | 已提交 `ActionAnalyze` |

`221cda4ba` 的构建日志为 `.codex-build-logs/action-analyze-cli-project-20261124-224716.log`。受测正式产物 `Ksword5.1/x64/Release/KswordCLI.exe` 的 SHA-256 为 `54569FA5788D53160D1A6B2D37744A839E0B2A5D525E50BA834ECB9B0752710B`。`42c5977e6` 回执记录 `project-v1` smoke 通过 16 项请求、22 项传输向量及回执缓存条数和字节上限检查。[正式 CLI 验证回执](../../tools/action_analyze_validation/cli/README.md#unified-project-v1-build-and-test-receipt)

原 SB02 本机证据为 `.codex-build-logs/behavior-planning/action-analyze-sb02-20261125-022401-3067253-35208-metadata.json`。后续 `59046a957` 已验证自有目标夹具接线。并发命中、控制所有者死亡恢复与产品接入继续待验。

## CLI 接入与待验项

- 2026-11-25 正式 HostX64 CLI `b05abcd310b28515036802d70c5ab8cbbf7b74815ec35f63c7f70b1d8f74e37a` 复验自有 AMD64 子进程 131 次停点、130 次继续、128 条继续回执窗口和正常脱离。持续内存流通过 70 轮及精确 4 字节差异、四类输入收尾、stdout 断开和背压超时，以及退出后的计数对账。日志位于 `.codex-build-logs/action-analyze-cli-product-breakpoint-current.log` 和 `.codex-build-logs/action-analyze-cli-product-memory-current.log`。夹具已清理。全局停止组和故障恢复仍待验。
旧 `KswordCLI/KswordCLI.cpp` 已有 8398 行。ActionAnalyze 沿用它现有的委派入口，经 `KswordCLI/CommandRegistry.cpp` 接入，新增逻辑按职责拆分。上述 smoke 已覆盖实际帮助、旧入口查询及异常参数处理。其余回归按工单记录实际结果。

Qt 和 Win32 总览作者开工前均须读 `design-taste-frontend`。Qt 首版离线项目与采样通过正式 Release 构建，Win32 离线读取单个 Stored 段。实际窗口和旧入口回归另行验收。[当前离线切片](../../docs/ActionAnalyze总览交互与验收.md#当前离线切片)

Light 与独立 Stored 验证器的正式 Release 构建均以 BelowNormal 优先级使用 HostX64 工具链，两项构建均为 0 警告、0 错误。验证器通过 35 项 Stored 向量和 2 项 Win32 文件用例。正式产物为 `Ksword5.1/x64/Release/KswordARKLight.exe` 和 `Ksword5.1/x64/Release/KswordARKLightStoredEvidenceValidation.exe`。签名驱动镜像的 SHA-256 构建前后一致。[Light 构建与验证回执](../../docs/ActionAnalyze总览交互与验收.md#light-构建与验证回执)

## 网络证据的离线验收

网络草案通过 39 项静态向量。原生网络归档夹具在固定 `KswordCLI/x64/Release/ActionAnalyzeNetworkEvidenceValidation` 中构建并从统一 Release 运行，HostX64 `/W4 /WX` 的 539 项断言通过。包含 65,536 字节逐字节往返、队列回绕、源及队列丢失回执、实际截断文件后的已验证前缀。夹具段、对象文件和 EXE 已清理。投影夹具通过 112 项合成检查，包括八个 ETW 双栈收发描述符、IPv4 UDP／IPv6 TCP 原始内容及截断前缀。

旧 R3 `PacketRecord` 交付的实际字节最多 4,096，归档 writer 内联上限 65,536。ETW 计数按仅元数据处理。归档 writer 运行在样本单写者持有的串行通道，段刷新只产生文件前缀回执。实时接线、规范事件引用、BlobStore、检查点及跨端项目重开须单独验收。[网络草案](../../schemas/action_analyze/README.md#网络证据)

CLI `analyze network-capture` 已接入源码。冻结单一进程实例，依赖系统接受 ETW 载荷 PID 和事件 ID 筛选，保存回环端点及方向，关档后核对 `raw/1` 并返回记录坐标。采集字段只含元数据，ETW 窄筛选兼容性与正式回查见待验 AA-06。[验收交接](../../docs/action-analyze-planning/validation-handoff.md#aa-06-cli-实时回环网络元数据归档)

阶段依据保存在本地计划 `docs/ActionAnalyze工程开工基线.md`、`docs/ActionAnalyze施工任务与契约落点.md` 和 `docs/ActionAnalyze同步全局断点与性能复查.md`。首次启动时工作区有既有规划、验证夹具和资料目录尚未提交。集成须用限定路径提交，逐批核对来源、文档链接依赖、生成文件和行数。

## 被动 ETW 桌面回放

- 2026-11-25 正式 CLI 与 Light 共用 9 段持续 ETW 项目。CLI 记录 624 条 ETW 观察并查询 4,101 个不同 ID。Light 检查终段、624 条 ETW 筛选结果、跨段末观察的归档坐标和重读选择。移走第 2 段检查点后窗口报告该段尚未发布并只显示第 1 段的 14 条原始记录。截断第 3 段覆盖流后报告核验失败并显示前两段的 28 条。恢复后读回全部 642 条。旧 ETW 单段与五类 API 归档在同一 Light 产物复测通过。窗口正常退出，测试配置恢复，固定目录清理完成。日志 `.codex-build-logs/action-analyze-light-continuous-etw.log`，构建产物位于 `Ksword5.1/x64/Release/`。指定普通 R0 及 Light 实时采集仍待验。
- `3403fe3dc` 已推送至 `origin/ActionAnalyze`。Qt 项目入口重开冻结的项目及采样描述，再复用 CLI 校验 `raw/1` 与 `records/1`。只读句柄验证相同 raw 散列后，仅投影已提交前缀。标记缺失显示旧档回退，缺依赖或错采样保留原表和选择。独立段入口保留诊断式部分预览。
- 正式 Qt HostX64 构建、双语及主题门禁通过。真实 Qt 复验 14／12 行、同一详情、未提交尾部、缺 Coverage、错采样、旧档回退和恢复重读。窗口退出 `0`，测试项目和配置均已清理或恢复。浅色及右侧详情已验，Light 项目回放及完整桌面矩阵继续验收。[Qt 回执](../../tools/action_analyze_validation/qt/ETW-Readback.md#qt-项目检查点)

## 被动 API 检查点与离线规则

- 正式 CLI、Qt、Light 回放同一四段采样，验证缺标记仅读首段、第三段坏尾只保留前两段、修复恢复六条并定位 `raw/3 #9`。CLI 后续图页又通过 SHA-256 续页、候选原始坐标、检查点缺口拒绝和终段空页。来源诊断仅给出读端状态和历史声明，生产方连接和覆盖保持未知。[三端回执](../../tools/action_analyze_validation/qt/ETW-Readback.md#项目工作台与三端同采样)
- 正式 Qt 浅色独立桌面通过两组汇总、五类细分、原始坐标、坏尾重试和草稿保留。Qt 独立段网络读回通过双栈方向、实际 300 字节和 256 字节预览，完整／截断／坏 CRC 分别为 9／7／7 行。[规则回执](../../tools/action_analyze_validation/rules/README.md#协调登记与验收)
- AA-01 已通过 Qt／Light 候选与来源标签。AA-03 的 CLI 合作目标 Agent 就绪、线索回查及被动 API 跟随，AA-04 的 Qt／Light 同采样关系浏览，以及 AA-05 的 CLI 项目规则回放均已接入源码，独立验收会话负责构建和实测。Sysmon 正例、指定来宾普通 R0、条件停点与发行范围继续记录在 11 项清单。用户原话继续保留于本页首节。[验收交接](../../docs/action-analyze-planning/validation-handoff.md)
- 新版 `codebuddy-fast-dispatch` 已能用 `-Workspace` 和精确 `-AllowTools 'PowerShell(<命令>)'` 运行本机正式验收。命令不附加重定向、管道或其它语句；由派发宿主保存 JSON 回执。等 Release 链接完成后再启动对应产品测试，避免 Win32 32。AA-08 浅色隔离桌面和 AA-09 CLI 逐段命中已通过，[实测结果](../../docs/action-analyze-planning/validation-results.md#2026-11-25--codebuddy-本机-aa-08aa-09)。
- 合作采集和已结束 JSONL 共用封装，只有整段与尾记通过后才展示输入方式。`cooperative-pipe` 的源序号是普通包流水号，`closed-jsonl` 是行号，缺字段兼容旧档；不凭尾记认证历史生产者。Qt 的总览、采样摘要、规则报告及 Light 详情沿用同一回读值。
- 第 9 项跨段候选树在桌面既有归档扫描内消费共享 `ApiTransferChain`，每段暂存、整段检查点成功后提交；独立导入只在当前文件内串链。`shared/evidence/ApiTransferCandidateWindow.h` 保留 1024 写入行与 256 候选对，双方详情独立于 4096 主表窗口。恢复树选择需使用写入与创建双方坐标，不能只用创建包坐标（重叠写入可共用创建包）。来源声明不增加强对象或进程操作资格。[接口、CodeBuddy 回执及后置桌面范围](../../docs/action-analyze-planning/api-transfer-tree.md)；Qt／Light 构建和 GUI 仍后置，不能由源码接入推断通过。
- APC 桌面增量已接入源码：`ApiTransferCandidateWindow` 在同一 `Accept` 后调用 `AcceptApc`，共用 1024 写状态／详情，不另建写窗口；APC 独立保留 128 对 `write`／`queue`，两端快照公开 `apcTransferCandidates`／`apcTransferCandidateCount`。树选择恢复必须含类型＋双方坐标；Qt 第四组与 Light 第二根不混入线程创建组。单行 AAAP1 字段走 Qt 原规范文档／Light 原文本详情，接受入队不证明投递或执行。遵守最新禁令，本批未派发／续接 CodeBuddy、未构建、未测试、未 GUI；旧线程创建回执不覆盖本批，恢复验收须等用户明确授权。
- 上下文候选桌面后续源码已接入：共享窗口 `ContextCandidates()`／`ContextCandidateCount()` 独立 128 对 `write/context`，同一 `Accept` 后调用 `AcceptContext`，共用原 1024 写链和详情；Qt／Light 快照 `contextTransferCandidates`／`contextTransferCandidateCount`，独立树类型＋双方坐标恢复及 4096 外详情。活采从原 `contextCandidateCount/recentContext` 回执投影，Qt 本端 `contextTransferCandidates/latestContextTransfer` 及 `AppendApiContextProgress`，Light 原正文追加，无新 timer/query。不改布局，contextApplied/执行始终未知，不升级角色或控制权；七个双语键定点补齐，Detection/CLI/CooperativeApiCapture 未改。本批不构建、不测试、不 GUI、不 CodeBuddy，未提交暂存。
- AACT1／AASM1 桌面仅接入单行详情：行字段 `apiContext`／`contextOutcome`、`apiSectionMap`／`sectionMapOutcome` 消费源端独立结果函数，Qt 在原 `FieldDocument` 追加、Light 从原 `ApiTransferDetails` 分派。缺位未知，输入句柄不授身份；上下文 IP/SP/flags/ABI 仅请求；映射请求／实际返回范围分列，sectionOffset 原输入，sectionHandle 非别名身份。未建立新候选树。APC 活采 progress 复用已发布回执：Qt 本端 receipt 新增 `apcTransferCandidates`／`latestApcTransfer`，Light 原 `ApiTransferProgress` 追加，无新 timer/query。27 个双语源键和两端工程/filters 已定点登记。当前仅源码完成，不 CodeBuddy、不构建、不 GUI、不测试；详情及回执实际验收待用户恢复授权。范围见 [跨段候选树记录](../../docs/action-analyze-planning/api-transfer-tree.md)。
- 本批作者直接派发 CodeBuddy 后，候选树语言审计明确输出通过（32032 源文本），45 个相关双语键齐全、六份工程 XML／路径检查通过。专用无窗口工程首次 C4459 来自测试全局 `scope` 遮蔽，已改 `testScope`；唯一重试因真实 CLI 验收互斥占用退出 2，修正后工程未取得编译及运行通过。固定验证入口 `tools/action_analyze_validation/api_transfer_tree/run_validation.py`；后续由作者在空闲验收批次续接，不重复既有正式 CLI 整批。命名互斥的 `ERROR_ALREADY_EXISTS` 只证明对象存在，必须检查 `WaitForSingleObject(0)`，Python Win32 HANDLE 必须声明指针宽度。
- `memory track`／`memory stream --observe-threads` 复用被动线程记录。`previousThreadObservationRound` 指前一次实际枚举尝试的轮号；首次或本轮没尝试时为空，无字节轮不会更新基准。只读轮询不是实际断点；正式回执与清理情况见[验收回执](../../docs/action-analyze-planning/validation-results.md)。
- 本机 `python -B` 已通过 CodeBuddy 的精确命令授权，正式 CLI 流式观察三轮记录前序 `null / 1 / 2`；同一线程从首次可见到确认退出。该回执早于线程枚举失败的续持修补。修补后失败轮保留原线程句柄以确认其退出，但仍报告 `unknown`，不当作新线程的完整基准。
- 选中内存产品实现使用 `Memory/SelectedMemorySnapshot` 复用 `PassiveDirtyMemory::PollCapture`，成功页才交真实字节；项目独立 `raw-memory` 流通过 `ProjectMemorySnapshot` 写入。集合调查保存必须传完整 `ProcessMemorySnapshotResult` 到 `WriteProcessGroupMemorySnapshot`，不能只提取 `snapshot` 而丢失原读取模式和读前/读后停点。`completeRange` 与 `heldAtBothChecks` 是独立结论，历史上下文不授活控制权；格式见 [selected-memory-v1](../../schemas/action_analyze/selected-memory-v1.md)。各作者直接调用 CodeBuddy 负责适用测试及回执，未有回执不按源码推断运行通过。
- 原生执行证据入口为 `Control/NativeExecutionEvidence`，只从同一活原生所有者的当前精确事件提取 DR0 进入尝试或 Into 单指令完成。`Project/ProjectNativeExecution` 保存独立 `raw-native` 段，历史读取不构造活释放请求；格式见 [native-execution-v1](../../schemas/action_analyze/native-execution-v1.md)。`Detection/NativeTransferAssociation` 仅按已报告目标/线程代次与实际地址范围做一致性候选，两类档案尚无共同启动期时钟证明时不比较 QPC 先后，也不提升来源认证、区域版本或因果归因。
