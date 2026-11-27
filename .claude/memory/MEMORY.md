# Memory Index

- **2026-11-27 最新正式CLI与跨空档接管。** 任务4已结束：c75f889ac增量Build一次SUCCESS/EXIT0，正式CLI SHA256 A1C31FF8BC2D1C51F454ACA2011B71209860B514D55BA8C3230FEF316FD14232；只ApiTransferHandoff.cpp编译链接，BelowNormal/HostX64/固定Release，无运行。任务5 sh_21c13f5c70018sJlLV3VbTCvz4/PID40148新增且只运行一次A存活、B退出后留空档再接C场景，固定handoff_idle_gap夹具，不重跑原三目标链；日志codebuddy-resumed-10/handoff-idle-gap，当前额度5/10。等待自动回执不轮询；当前正式CLI输入冻结，不借源码/构建宣称运行通过，GUI后置。

- **2026-11-27 当前接续优先。** 最新产品c75f889ac（08f Ready投影、668窗口外恢复、c75取消暂停），任务3停止场景已结束：CLI取消6/双目标自然0/清退和归档成立，但owner/Ready迟到准入不可直接观测，43检查0FAIL1UNIMPLEMENTED整体BLOCKED，不能标整链通过。任务4 sh_21c1212d2001znJdFPVXnqMBNl/PID39612唯一执行最新CLI增量构建一次，禁止运行/重试；授权额度4/10。详见工程记录。不得重复已过ETW/三目标链，不为测试新增关闭后查询接口；后续应在控制器存活期间观察失败目标清退和迟到接管。用户持续推进原话有效。

- **2026-11-27 最新恢复CodeBuddy授权及Ex2复验。** 用户授权约10项，已用3/10；任务1 sh_21c0462170010iLK65j3Ogsn2j完成：产品a44a89734上CLI一次增量Build成功，Ex2一次运行CLI0/27检查通过，stubRan/counter1、recursiveAgentReady=true、AAAP1结构化flags0x3f且queueFlags=0有效。源子目标由driver cleanup终止码1，未验证自然成功退出。回执codebuddy-resumed-10/recovery-ex2/receipt.md；旧失败原档保留。任务2 sh_21c04c8080012wSIOLlLeleXPx已交付主动停止/迟到请求夹具但未运行；任务3 sh_21c0a6526001d202agwFY1veFI负责其固定路径编译/运行一次，CLI停止契约6，owner/Ready状态不可观测项保持BLOCKED。主协调继续源码工作，因此任务3验证只覆盖其启动时冻结产品。不可扩大为GUI、其它链或完整11项通过。

- **2026-11-27 最新用户限制与Ex2结果。** 历史「不得调用CodeBuddy」已被用户随后明确恢复约10项授权所覆盖；当前3/10。Ex2旧失败运行只一次、CLI6/pipeError109/coverageStale，原日志及项目保留；后续冻结版a44a89734定向一次复验CLI0/27通过及AAAP1结构化flags验证，不能混淆两份结果或扩成全流程通过。详见工程推进记录。

- **2026-11-27 NT Ex2最新续跑。** 产品4c57b774e新增NtQueueApcThreadEx2调用前同步接管、AAAP1全部参数/flags/NTSTATUS及三端原展示/关联接入，尚未构建实测；唯一构建sh_21bec46130013Dh5kCaf4Em70G/PID4392使用hy4flash，只两Agent+CLI各一次，日志native-ex2-build，不运行目标/GUI。原APC2契约任务在约20分钟仅工具链查询后已核对精确进程并结束，最终failed；APC2驱动任务超时无文件，不重复。详见[工程记录](ksword-action-analyze-engineering.md)。用户原话「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」有效；测试/夹具/回执仍全部交CodeBuddy，主协调写产品，等待时不虚构通过或扩充无关防御。

- **2026-11-27 03时接续优先。** CLI30313DBE…/Agent40372585…新包三目标链一次实际运行9/9、CLI0、A/B/C退出0、三个计数各1；样本5505df0a-91e2-4e04-a439-8ee0d3a0a553，B第二范围tid41928/create134402358157052790，三范围各5条真实IP，清退leftOwned0。回执local-thread-integrated/runtime-receipt.md。原夹具只留samples导致正式CLI replay缺项目根，AAIP1离线核对待sh_21bcdb6710011ny1zT3pU2kpIo，不再重复replay或整链。5bde7e334逐入口entryObservation已一次正式CLI构建成功，hash4F1C01D0…4002339、entry-build.log；未实测该增量，不借旧链覆盖。APC2/主动停止准备旧任务超时仅有读取；同短批重新限定只写APC2源码，禁止运行。所有验收及记录仍CodeBuddy负责，主协调写产品，GUI继续后置；完整11项未闭合，持续推进要求有效。

- **2026-11-27 最新接续。** 第456项旧样本已离线结构化核对：三范围各5条顶层instructionAddress观察且精确命中入口，第二范围tid2792/create一致；旧字节命中判据作废。0134a8303/318ae1a34两Agent+CLI正式增量成功（CLI30313DBE…、x6440372585…、x86106C6581…），回执codebuddy-five-tests/local-thread-integrated/receipt.md。独立读侧任务超时143，无结果不计通过、不续跑。唯一新包整合运行sh_21bba2127001dQowZaXEppOuXX待自动回执，只准一次、复用产物禁构建，旧证据保留，GUI后置；不轮询或重复ETW。主协调持续推进产品，测试/夹具/验收记录仍交CodeBuddy。用户原话「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。下一步按新包真实回执修实际问题，再补QueueUserAPC2及统一停止恢复尚缺实证；详见[工程记录](ksword-action-analyze-engineering.md)。

- **2026-11-27 当前接续（优先于下方旧回执状态）。** 第8项单跳真实Agent混采：CLI0、5观察、普通段+末段、45000ms/segmented及2检查点、清退成立；强驱动14/18的4项取证/断言缺陷保留，不重跑。第456项已有CLI c1a3fc19…/Agent9f9318aa…三目标两跳+本地第二范围副作用各1、三个admission成功及CLI0/清退；CodeBuddy夹具修正后实际额外运行两次（越过单次边界，必须披露），raw-native原字节命中不算真实IP，正在只离线解码核对。主协调新增0134a8303本地CreateThread真实线程身份、318ae1a34共享分类及返回判定，未构建旧结论不覆盖；唯一整合构建sh_21bb65b49001dcDEKtV0oOJ374仅两Agent+CLI、禁运行；另本地读侧专项sh_21bb4e6e10012Cjo5IB8rBjsHO及离线证据sh_21bb61a0e001lNI9NhDu7B05TX，等待自动回执不轮询。用户再次明确shell执行时继续独立开发，不因后台暂停；全部测试/夹具/验收记录交CodeBuddy、主协调写产品，GUI仍后置。详见[工程记录](ksword-action-analyze-engineering.md)。

- **2026-11-27 当前优先级。** 用户明确「你把第八个弄完过后就去直接打通456」。集中4/5/6自动接管、脏页新线程和统一下断恢复；GUI继续后置。etw-stream回执已确认发布规则修正生效、持续ETW9普通段+1终段与历史回读通过；B目标stubRan/counter/exit0与清退成立，但配套ETW零观察使CLI退出3。9f0b1d35f修正显式附加遗漏生命周期ETW及STOP前零回调误判，CodeBuddy本批一次两Agent+CLI构建和原B待回执，后接456两跳/同进程新范围。053a33b6c/5a429796e已提交本地私有线程调用前设防、暂停归还及Close语义。额度消耗可不计，旧数量限制为历史；测试/夹具/回执全交CodeBuddy，主协调写核心。详见[工程记录](ksword-action-analyze-engineering.md)。

- **2026-11-27 凌晨源码接续。** 用户要求主协调直接写核心，仍用stop-that-shit，测试/脚本/回执交CodeBuddy且GUI后置。`98f018cb4`在ReceiveBreakpoint最先冻结所选线程异常CONTEXT，Observe/叠加TF共用原值，新增observedFlags/observedDr7供解释零DR6，不改变未知异常分派。`3f41e3c2f`自有Agent ETW单来源追加报头PID、三端参数及混合计划/读取、双语，`dfa9d06ef`保留APC2原flags并兼容14/15/16字段AAAP1、三端详情，`e8769313e`ETW先封段再把独立agentEtw结果写入API终段并复用三端同一文档，均已本地提交未推送。新CodeBuddy异常原值任务`sh_21b2548f1001sDFyGw787OfnyS`仅一次CLI增量(跳引用复用旧Agent)、B一次、i18n一次，等自动最终回执；后续APC2/终段增量不借其旧Agent或不明编译时序算通过。原用户脏文件仍保留。当前重点仍为NX第一条指令后中断，待原始事件值定位；全部目标未完成，不停止开发。

- **2026-11-26 深夜续跑（覆盖下方11:54收工状态）。** 当前目标仍为API Monitor调用前同步发现私有范围并接管下一目标，CLI本机实测交CodeBuddy，Qt/Light GUI后置；用户最新再次明确持续推进并授权CodeBuddy承担验收。`319bb4f73`缓存Ready前递归包、`982230b61`保留Ready后的非致命HooksPartial、`df5e9a971`内部NX状态、`6468f5237`同源多目标网络归档及三端接线、`20cd5b5c4`QueueUserAPC2调用前交接与同源入口关联均已本地提交，未推送。最新已结束B仍无stubRan且目标STATUS_SINGLE_STEP/CLI6，不能以27/27认定通过；旧回执把EFlags66054误说TF置位，实际0x10206不含0x100。NX诊断同一CodeBuddy会话`01a21b17-82d8-7e00-96cb-854847e9a3fe`首次宿主120秒结束且未构建，已确认无相关残留后续接为`sh_21b1a4c0b001KF2rg1t1HlQza9`，最多一次CLI Build（跳工程引用复用既有Agent）、一次B、一次i18n；等自动回执、不轮询、不追加C或GUI。最新hook尚不在旧Agent中。保留原用户脏文件和测试证据，主代理只改产品及组织方向，测试/夹具/回执均由CodeBuddy落盘。详见[工程记录](ksword-action-analyze-engineering.md)。

- **2026-11-26 11:54已冻结并清退。** 收工优先于持续推进，不再启动新任务。新增5项额度最终用3/5。最后CodeBuddy已完成CLI正式增量Build（exit0、SHA256 `CBB7034F96693C6939EFD4C51520DF9164332F145E692AB30506CC508E42298A`）及i18n（32875源串/exit0），日志位于`.codex-build-logs/codebuddy-five-tests/final-close/`；整理receipt未及时完成，11:54按硬截止结束精确宿主3864、node41936及子bash/conhost，未在编译/运行中中断产品。11:54:12实际核对：本次三个宿主/子node与MSBuild/cl/link/python/CLI/自有夹具残留数0，11:55 automation已删除。旧dispatch status.json可能仍写running，但不是活进程，明日不得据此重做构建或认为仍在执行。未写完receipt不算已有；B/C未执行。原脏文件与runtime证据原样保留，全部产品改动和夹具已有本地提交，未推送。

- **2026-11-26 本地恢复点。** 当前`ActionAnalyze`最新源码提交`a0e5abe25`；本轮所有产品改动、共享记忆和新增入口夹具已提交，未推送。保留用户原有`KswordCLI/KswordCLI.cpp`、`Control/tests/Invoke-NativeStepValidation.ps1`及未跟踪`product_execution_group_append.py`、`TextFieldComparisonValidation.cpp`、runtime测试证据，禁止回滚/清空。原11:55收尾automation已删除，不留明日自动作业；最后CodeBuddy只做收尾，不运行新场景。

- **2026-11-26 关机前收尾约束与当前状态。** 用户已执行`shutdown -s -t 1380`，要求本机12:00前收工；随后说明无需列剩余事项，只要确保没有执行中的任务、明天原地恢复。不得取消关机；停止本次后台任务前核对精确PID/命令，不触碰无关进程。新增5项CodeBuddy额度现用3/5：第1项1800秒超时143，CLI/x64及x86 Agent构建日志成功、入口场景A PASS，B/C未执行且无最终回执；第2项已正常结束，theme PASS、i18n两个源串四项缺失已定点修正；第3项`sh_2188b3835001RPmN7PXTSBkZuA`仅最终CLI增量Build、i18n复查及原日志回执整理，最晚11:54退出，不增加运行场景。`bb1ebe216`提交解除固定上限，`52bb756d9`提交三端EXE/递归接管/同采样网络整合，`d4591fa80`修正NX owner先恢复再等待Agent清退。全部未推送，最新修正不能借旧日志算运行通过。

- **2026-11-26 最新 CodeBuddy 授权覆盖旧限额：新增最多5项。** 用户原话「按照先前的codebuddy任务量，你还可以布置5个新的。」当前新增额度已用1/5；第1项核心接管实测独占正式CLI/Agent构建，宿主`sh_2186eb512001kWHvAfOrt7eumS`，最多挂起入口/首次转移/追加范围三场景，等自动回执。由主协调统一计数，测试、夹具、回执与验收记录均交CodeBuddy，源码作者不自行替测。未派不算通过，失败不自动追加第6项。Qt/Win32 GUI实测仍后置，继续核心源码与三端接线。

- **2026-11-26 最新核心方向：自动接管及EXE挂起启动。** API Monitor发现跨进程行为后自动解析私有范围并接管下一目标；入口增加选择EXE→启动挂起→附加，同时保留已有实例。零窗口需Hook放行前目标外owner同步交接，异步回传不能承诺。网络采集复用现有“网络→流量监控”，HTTPS解析后置。64页NX/16成员是代码上限。十一项源码粗估与历史实证分开；CodeBuddy测试额度3/3耗尽仍有效。详见[工程记录](ksword-action-analyze-engineering.md)。

- **2026-11-26 最新测试额度3/3已用完，三个宿主均已结束。** 追加正式CLI构建及6组138检查PASS，i18n448项FAIL；历史线程恢复cancel通过、thread-exit仍FAIL；文本比较宿主1800秒超时143，无最终运行回执，不算通过。主代理继续功能和已知文本分区修复，不执行实测、续接或重试，GUI仍后置；goal重激活不恢复无限授权。原自动日志、产物范围及源码状态见[工程记录](ksword-action-analyze-engineering.md)。

- **2026-11-26 原两项CodeBuddy已返回。** `sh_217ef3fbd001zM5SIntRv2cBgQ` 两项均返回ok源码回执；布尔任务仅修改契约注释、线程恢复修改退出线程债务及NX恢复顺序。未测试/构建/GUI，历史失败不得标修复通过。授权次数已用完，继续静默，不新增派发或续接。源码结果见[工程记录](ksword-action-analyze-engineering.md)。

- **2026-11-26 原两项CodeBuddy恢复获准。** 用户明确「网络环境炸了刚才，你可以继续跑那两个炸掉的」。恢复范围只有原【条件布尔运算】/【线程恢复】源码任务；不扩为验收、其他派发或任意续接。网络首token超时及一次120秒宿主超时均无完成结论；无残留进程后已给同两项30分钟宿主上限，当前`sh_217ef3fbd001zM5SIntRv2cBgQ`，等自动最终回执、不轮询。细节见[工程记录](ksword-action-analyze-engineering.md)。

- **2026-11-26 CodeBuddy 两次限额例外。** 用户最新原话：「派2个任务给codebuddy，然后等回执，不要开subagent再转换给codebuddy。这两次过后继续静默。注意约束和节省。」本轮已直接通过 `codebuddy-fast-dispatch/scripts/dispatch.ps1` 一批派出两个任务：条件布尔运算源码闭合、原生线程恢复源码修正。两项均禁止测试/构建/GUI/续接/再次派发/提交推送，最终文本回执位于 `.codex-build-logs/codebuddy-two-dispatch/`。收到这两次回执后继续禁止新增 CodeBuddy 派发、续接和重试，除非用户再次明确恢复；goal重激活不撤销限制。不因CLI调用成功就标源码或运行通过。

- **2026-11-26 最新验收纠偏。** 用户批准「当前验收失败的…继续跑」，同时要求减少约70%的非必要门禁并明确CodeBuddy边界。授权仅恢复已有失败任务，不扩大为全部新验收；同一会话单实例、CLI单次共享构建、已过不整批重跑，失败不靠删断言或纯自旋绕过。[缩减任务边界](../../docs/action-analyze-planning/validation-reduced-batch.md)：原计划42→12；源码回执显示内存另执行错代次和raw保留两个调用，须按实际14/42（减少约67%，接近70%）登记，不能藏附加调用凑数字。产品已READY，同一旧会话开始串行focused运行；构建与通过凭本轮回执，不复用旧160/202/666数字。
- **2026-11-26 最新用户限制，优先于当前 goal，交接必须保留。** 用户原话：「从现在开始暂时不允许派发CodeBuddy任务，我会在可用时告诉你」「这个限制在goal之上，记得在上下文中保留。旧的继续。」已派发旧任务继续运行；用户明确恢复前，禁止新增 CodeBuddy 派发、续接、重试和自动后续任务。功能开发继续，待验不得标通过；所有开发子代理同样遵守。
- **用户持续推进要求，压缩和交接必留。**「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。回答进度后继续当前工作。交接同时保留当前目标、未完项目和下一可执行步骤。ActionAnalyze 以[11 项产品验收清单](../../docs/ActionAnalyze产品验收清单.md)记录实证与缺口，验收闭合批次仅推送 `ActionAnalyze`。
- **ActionAnalyze 产品来源只用 KSword 自有采集组件。** 用户明确禁止使用 Sysmon。旧查询、订阅、归档及三端回放回执只作历史，不算产品能力。自有回调 v1 的 PID/TID 和原包坐标只形成线索，不证明事件时强实例、写入或执行。[验收交接](../../docs/action-analyze-planning/validation-handoff.md#aa-10-ksword-自有线程创建证据)
- **最新验收责任。** 用户原话：「以后谁写的代码谁来调用CodeBuddy测试和排查，不准出现subagent做了你又来看。」改动作者直接派发 CodeBuddy、排查及记录回执。主协调者汇总指标与集成，复用各作者的验收结论。
- **ActionAnalyze 开发与验收分工。** 用户让当前开发会话继续写功能，由用户转交另一个模型运行构建及测试。开发会话将命令及通过条件写入[验收交接](../../docs/action-analyze-planning/validation-handoff.md)，验收模型直接追加[验收回执](../../docs/action-analyze-planning/validation-results.md)。AA-01 候选与来源标签已通过。AA-03 待验合作目标 Agent 就绪、CLI 线索归档和被动跟随，AA-04 待验 Qt／Light 同采样关系分组及定位。活采集、强关系、完整调试清退和发行仍按产品清单推进。
- **ActionAnalyze 下一阶段 11 项各达到 70%。** 并行推进采集、停止与恢复、网络、关系图、规则五条线。关键路径和正式门槛写入[70% 路线图](../../docs/action-analyze-planning/roadmap-70.md)。用户明确要求验收提示词由其转交，开发会话按交付范围准备提示和落盘路径。

- [隐藏进程检测方法与证据范围](../../docs/隐藏进程检测方法.md) — 1–66 逐项执行与回执、两个入口的独立默认值、真实位图转储及 Hyper-V 来宾验收、外部设备前提

- [操作心智模型与结果身份](../../docs/操作心智模型审查.md) — 按任务选择控件、选择与执行分离、批量动作、草稿保护、结果来源和失败恢复；含本轮实际覆盖入口及手动验收边界
- [进程/窗口准星与 Ctrl 预览](ksword-window-picker.md) — 原生物理坐标、全不透明与默认60°/悬停75°、外部进程信息、全屏、176 项缩放回归及实机验证边界

- [进程列表矩形面积视图与选择保留](ksword-process-metric-area.md) — 度量表头入口、主列表快照同步、树/友好嵌套、聚合行选区、原进程菜单与零值语义
- [进程强开控制台](ksword-process-console.md) — 无自定义DLL、双位数远程例程、UCRT/STL步骤、超时页保留与真实菜单回读

- [硬件 Dock 字段回填](ksword-hardware-dock.md) — USB/设备栈/HID/总线普通页的后台值投影、采集状态默认折叠与实机验收边界

- [默认 UI 状态与首帧](ksword-ui-input-first-frame.md) — 鼠标/键盘焦点区分、默认几何、首次主题准备、原生分栏及安全队列边界

- [磁盘队列、I/O 日志与 MFT 索引](ksword-ntfs-index.md) — 只读 MFT/USN 快照、硬链接与尺寸口径、卷队列和有界 Kernel-File 日志

- [未跟踪文件审查与原生回归补齐](../../docs/未跟踪文件审查-20261014.md) — 生成夹具与规范源区分、真实进程目录/受控 R3 目标、完整文件 UTF-8 解码须结束流状态

- [MCP 设置与本次启停](ksword-mcp-settings.md) — 二级设置布局、会话状态与自动启动偏好分离、PID 配置预览及关闭后重新创建桥

- [CKS 新版免重置研究](../../docs/CKS新版免重置启用研究.md) — 官方首次启用重置要求、旧 SSDE 与 2026 年锁定状态实验、精确 build/CI 文件身份和未验收边界
- [CKS 本机登记链深入研究](../../docs/CKS本机登记链深入研究.md) — 精确 CI/winload/SKCI 登记与刷新门禁、安装迁移候选、HVCI 运行查询及静态证据边界

- [DynData v4 配置读取与分模块回执](ksword-dyndata-profile-loading.md) — 协议统一 ID 目录、1401 整包拒绝、PDB 提取缺口、匿名 union/位域语义与离线 Qt 消费回归

- [Taskbar 页面平铺导航](ksword-taskbar-page-overview.md) — 独立透明 RGB 分列窗口、实际页面目录、WM_COPYDATA 身份校验与逐层跳转

- [CLI 崩溃报告与 VMware 验收](ksword-cli-crash-report.md) — Unicode CRT 日志 fastfail、旧 OS build 门禁归因、参数/状态诊断、VIX 自动通道与只读回归
- [SCM 驱动镜像路径](ksword-driver-image-path.md) — Issue #236：驱动路径不加命令行引号，Win10 20H2 新建及覆盖旧配置实测
- [驱动加载失败与 Windows Driver Policy](../../docs/Issue-233-驱动安装报错核对.md) — Issue #233：新弹窗仅处理截图中的4551，577沿用原弹窗；UI只讲原因及处理方法，按更新显示禁用或博客帮助；实机策略/重启未验收，官网暂缓

- [ETW 解析与进程归属](ksword-etw-decoding.md) — 事件头与关联身份、映像枚举、数组/结构体布局、网络端口和 TraceLogging 缓存

- [API Monitor 生命周期与事件协议](ksword-api-monitor.md) — GUI/GDI分类与Raw门禁、898项强类型、x86/x64逐项实测、自动注入、异步/覆盖协议、会话互斥与退役Hook保留
- [Syscall 监控与 SysWhispers 兼容形态](ksword-syscall-monitor.md) — QPC 栈关联、进入/退出布局、系统映像信任、静态调用号边界与有界离线回归
- [恶意行为单点追踪与调试能力规划](../../docs/恶意行为单点追踪与调试能力规划.md) — 非虚拟化、来源/区域版本/实际执行线程及多跳；2026-11-24 明确命中后可统一停止再按需放行；包含已答 UI/API/ETW 语义及结构、内存与 UI 性能预算，产品引擎未实施
- [页面执行探针机制验证](../../docs/非虚拟化页面执行探针验证-20261124.md) — 2026-11-24 Win10 19045 自有夹具21项通过，夹具源码已随 `10e0f370f` 推送；Guard一次性/读取消耗、NX直接恢复X的漏报负控、两个自有线程停止后TF推进到页外重设NX再放行；控制器未停，不代表完整线程集合/新线程门控/驱动/代码洞篡改已覆盖
- [Explorer复杂环境探针实测](../../docs/ActionAnalyzeExplorer复杂环境验证-20261124.md) — 用户授权本机Explorer结束/重启，排除DWM。历史本地夹具 `tools/explorer_probe_validation/` 持外部原生debug owner，不装目标VEH；最终PID8120/165线程五类正常场景79PASS：既有USER32页8次命中/510TF、真实私有代码两版本各四线程、跨页RIP≠faultVA、页内主动中止；8KiB已释放、无残留夹具。重要负控失败：持有NX事件时父监护恢复RX再杀debug子进程，即使kill-on-exit=false，目标线程0x5bb、原任务栏失效；按授权结束精确旧PID4000并重启8120后恢复。不能保证不崩溃，不能把默认PASS算owner死亡恢复通过；破坏负控默认禁用。修夹具提前关闭OS事件句柄和EXIT事件后Toolhelp迟留问题；creates_during_step=0，普通R0/任意死亡恢复/自动传播未验。正式测试EXE/PDB在统一Release，无产品改动/驱动加载
- [行为语义规则模板收集与并入规划](../../docs/行为语义规则模板收集与并入规划.md) — 本地沙箱601条候选及公开上游、授权/字段/真实时序缺口；全类别收集，默认同线程、聚合可展开、缺字段逐规则配置；不直接执行上游Python，不将全部候选常驻加载
- [ActionAnalyze 多通道通信与控制施工设计](../../docs/ActionAnalyze多通道通信与控制施工设计.md) — 2026-11-24 用户授权分支隔离和subagent验证；目标外控制所有者、传输/生效/回读分层、必需覆盖/配置/探针Ready屏障、恢复责任与三端内部模块；模型/自有IPC/产品验收分开，不因分管道假定暂停Agent仍可执行
- [ActionAnalyze 普通 R0 恢复审计门槛](../../docs/ActionAnalyze多通道通信与控制施工设计.md#74-普通-r0-后端的静态审计门槛) — 2026-11-24 静态复核：单全局primary、批量Resume失败清账、R3原保护/临时挂起缺完整恢复账、租约只在异常循环检查、Qt客户端拒reason5及5–8记录；§5.1通知只唤醒/权威Query/per-file取消；29项R0用例全部待执行，未修产品未加载驱动
- [ActionAnalyze R3／R0独立双后端](../../docs/ActionAnalyze双后端独立全流程设计.md) — R3 在本机验收无 KSword 驱动的受支持用户态全流程。普通 R0 仅在 `E:\VMs\Windows11-24H2` 验证，结果待验。采样显式选择，异常所有者唯一，活采样禁止静默切换。R0 辅助部署的用户 Agent 仍运行在 R3。Explorer 死亡负控未关闭。
- [ActionAnalyze 挂起创建与最早窗口](../../docs/ActionAnalyze启动挂起注入与最早窗口验证-20261124.md) — 历史本地夹具 `tools/api_monitor_startup_validation/` 自有x64/x86六例68项/退出0：生产injectAgentNative在原始CREATE_SUSPENDED均299；调试到EXE入口再显式挂起/脱离可装真实Release Agent并捕获构造/main，但TLS已执行。独立CRT-free首导入/IAT测试bootstrap在首次Resume前布置，先于EXE TLS安装并捕获三阶段首调；不是完整898项Agent早期验证/依赖DLL覆盖。最终212423日志/metadata，exe87B48722…；固定IntDir/统一Release，无R0/Explorer/DWM/样本/产品改动，测试配置/标记/进程已清理。API Monitor可大量复用但启动/阶段/强类型/Ready交接需改造
- [ActionAnalyze 工程开工基线](../../docs/ActionAnalyze工程开工基线.md) — 用户确认 Agent 命中线程直接进入已登记停点，由目标外所有者接管。主程序提交同一协调者。origin 与冻结停止组独立，R3 真实附带暂停、完整线程门控和死亡恢复分别核对。首批工单覆盖离线、R3、来源、规则、E01–E16、调查及三端接入。停点快照与向量已有 A0 草案，产品运行与性能阈值待实测。
- [ActionAnalyze 工程推进记录](ksword-action-analyze-engineering.md) — 多 agent 并发实施，逻辑闭合的工作包可先提交到 `ActionAnalyze`，构建和验收逐项登记。最终关闭须完成全范围验收。文件上限 2000 行，重构登记受影响入口与复测。CLI 外壳 HostX64 Release 与 A0 基础／Stored／方法静态向量分别登记。
- [ActionAnalyze 桌面总览交互与验收](../../docs/ActionAnalyze总览交互与验收.md) — Qt／Win32 作者先读 `design-taste-frontend`。离线切片分别验收项目采样与归档段。完整总览的时间／类别框选、证据锚点、12 项动作和实机验收待完成。
- [ActionAnalyze SB02 同步停点夹具](../../tools/action_analyze_sync_stop_validation/README.md) — `055fef531` 已推送。x64/WOW64 自有目标 386 项断言通过，8 次停点、8 次旧代次或外来事件转交、4 个正常退出。并发命中、所有者死亡恢复与产品接入待验，本机证据路径见工程推进记录。
- [ActionAnalyze 长程 CLI 会话与结构协议设计](../../docs/ActionAnalyze长程CLI会话与结构协议设计.md) — 用户明确长程不能仅启动参数；活进程内人工REPL/AI JSONL双向命令，独立输入/控制/输出，背压不等于ACK交付；禁止退出后凭sessionId接管；模块cpp/h清晰分工、无.inc堆叠、适度重构须标回归范围；命令和解析器尚未实施
- [ActionAnalyze 分析项目与多次采样](../../docs/ActionAnalyze分析项目与多次采样设计.md) — 用户明确断点/采集结果等归分析项目，一个项目多次采样；项目配置修订、单次实际快照和活运行控制分开，新采样重绑断点不迁移stop/句柄/挂起权；横向比较暂列待做，非首版实现
- [ActionAnalyze 完整开工审查](../../docs/ActionAnalyze完整开工审查与实施总表.md) — 2026-11-24第二轮设计盘点列 A0–A10、29 项不确定项及真实导航/调查后台化/仲裁/失联/预算/发行条件。R0 恢复另有 29 项判据，R3 的完整线程门控与快速下一跳独立验收。终止调试目标处置、步进依赖扩放两项默认待定，当前工程状态见开工基线。
- [ActionAnalyze 下一层施工](../../docs/ActionAnalyze施工任务与契约落点.md) — A0–A10 拆为 33 项、12 类接口和 V1–V5 切片。首批按接口并发施工，CLI、Qt、Win32 各自持有本端会话，按端及后端逐项等待产品验收。
- [ActionAnalyze 规划遗漏复查](../../docs/ActionAnalyze规划缺口复查与补齐任务.md) — G01–G16补两处规范/旧状态冲突、九处执行契约和五处未展开分支；机器契约唯一根schemas/action_analyze。KnaThreadNotify目前只处理退出，notify不作阻塞闸门；完整线程门控、普通store新区域发现、NX异常中关闭及sourceReady/regionReady启动与失效仍有机制门槛。补TF/DR预约、断点/步进、快照重入/TOCTOU、中介执行、CLR版本、absence水位、分析器真实入口、CLI查询/包搬运与驱动CI登记。关机前保存，开机续查补全部专项反链与实际frontend保护问题：write一律RO去X、execute一律RW可能加W、首段原保护/先改保护后注册/回滚失败清账；仅规划修复未改产品。Ex NonSystem在新线程回调仍不授阻塞等待；WMI的CIM_UINT64/VT_BSTR分开保存，callback读回不算目标seen。未实施/构建/运行/关机操作
- [ActionAnalyze 执行覆盖](../../docs/ActionAnalyze执行覆盖与逐路径验收.md) — 用户追问依脏区机制是否直接覆盖各种注入：已设防实际区域的NX取指发现与CreateRemoteThreadEx/APC/劫持/Hollowing/反射DLL等调度手法无关；前提为先设防和完整线程/新线程门控。新复制/解码区与共享别名不自动跟随，ROP/正常模块可离开脏页；D区域/X执行/P后续/A归因四轴、P01–P16负控，未实现产品全覆盖
- [ActionAnalyze 反反虚拟机行动](../../docs/ActionAnalyze反反虚拟机与环境实验行动方案.md) — 用户明确深入研究/行动方案、所有相关项不能停技术口号；E01–E16、15个RAV任务、X01–X07，具体字段/机制/旁路/跨接口profile/原始-substituted-seen-path四级/恢复。优先WMI同步Get→注册表value→固件一致组；CPUID/RDTSC内联和共享时钟页不由API或普通R0自动截获，有限DR/TF站点研究不宣称透明全覆盖，不重走旧HVM TSC_OFFSETTING路线。默认被动、不改真实固件/网卡/光标、不默认跳分支，三端各自owner；本轮只规划，无产品/新实验/R0
- [ActionAnalyze 规则转换施工](../../docs/ActionAnalyze规则来源与转换施工清单.md) — 自有证据语义+声明式IR+开发期上游转换，9源固定SHA；规划资料docs/action-analyze-planning已存9完整blob树21468行/12810保守候选文件、本地601 ID/JSON Pointer、7份包级许可原字节hash。文件数不等规则数，上游bodySha256/ruleCount保留null；逐规则枚举/许可例外/三端字段/转换/真实回放未完成，不执行上游Python，不冒充产品schema或规则包
- [ActionAnalyze 事件身份与协议](../../docs/ActionAnalyze事件身份与协议契约.md) — 字段/强实例/区域版本/阶段/入口族/方法及aa-cjson-v1；eventId=sample+ordinal，原source序号单列，JSONL严格无BOM、页500/max2000、输出硬限256KiB、乱序2秒且不凭空闲推进。A0 有机器契约和向量草案，产品读写接入与跨端验收待做。
- [ActionAnalyze 筛选与规则语言](../../docs/ActionAnalyze筛选器与规则语言设计.md) — 六域条件分开，硬范围内P∨C保留、依赖冲突拒绝、保守超集下推；强Kleene三值、有限C#风格DSL/有界NFA、阶段白名单/count/sequence/lease游标；旧前置筛选是收包后归档前丢弃，非Hook开关/调用前停点，旧bool invert/坏regex回退不可照搬；活采样规则包冻结无热替换
- [ActionAnalyze 项目存储与恢复](../../docs/ActionAnalyze项目存储格式与恢复设计.md) — 目录+小JSON+CRC32C分段/独立blob/可重建索引，Stored必备/zstd显式能力、系统SQLite仅可选cache、无QtSql/CBOR/外部7z必需；ksapack受限顺序容器、单写者/跨流依赖水位/坏尾/GC/满盘策略已建议，字节布局未作互读或掉电验收，旧stop文件不授控制权
- [ActionAnalyze 栈破坏与控制流劫持](../../docs/ActionAnalyze栈破坏与控制流劫持发现设计.md) — 用户指出遗漏后补专项：栈耗尽/越界/GS与CFG/CET保护/pivot/ROP分开，同进程CPU写可无远程API或新RX页，返回地址等控制数据破坏在范围内；异常/保护源、有限现场、frame/slot生命周期、显式watch、真实转移/归因/负控分层。Minidump现有过强释义列修正待办，未改产品；无通用检测/攻击/R0实测
- [Action Scope功能与实现核查](../../docs/ActionAnalyze对ActionScope功能与实现核查.md) — 2026-11-24用户授权subagent全面静态研究官方历史包，version=20191230/外hash e25903af…，内38文件/19PE与外安装器分开；pefile/Capstone及本机Ghidra12.1.4 headless已实跑。ROP现用NULL回调提前返回不构成10帧跟踪、shellCode用初始模块表、heapSpray扫描/输出门控未闭合；WMI方法与结果干预按架构配置核对，Get前后helper只格式化未发送。tcpLog/udpLog是日志客户端，WinINet字节只证x86专用路径；Loaded早于HookAll，PROCESS/FILE_NEW无成功门禁、双端口共用发送线程、wait队列空不等于交付。同步A0/A5/A6/A7/A9候选，不运行第三方/注入/驱动，不自动扩大首版；诊断文本在.codex-build-logs/behavior-planning
- Action Scope返回契约补核 — 同上报告§3.2及SDK分路§9：x64默认After在引擎0x9118用回调RAX覆盖原结果，WMI Get尾部清EAX，Hook成功且正常返回时HRESULT低32位被改0，即使属性未命中；默认Before普通C返回值无所核跳过语义。不能泛推x86/自定义trampoline/异常路径；getReturnValue该实现只保留调用时RAX，不补造setReturnValue导出。
- Action Scope主控分路已收尾 — 总报告§6.6/6.7：24入口证据分层、343映射/341唯一ID（不是346行规则）、Jet只读打开密码无效未读schema；x64 globalHook纯数据解压后证实globalhook管道→逗号两字段→LoadLibraryA/GetProcAddress/无参调用，exit只终辅助宿主。update配置/HTTP文本/版本包/终进程/停删syslist/备份/ZIP ExtractAll已静态核对；外install仅资源等有限识别。Python SDK仅市场安装配置未随包交付，主控受保护不搬旧RVA；五路静态研究范围收尾，动态/后端/规则正文未知保留，无第三方执行/激活/驱动/安装
- [ActionAnalyze PPT工具栏逐项核对](../../docs/ActionAnalyze工具栏逐项功能核对.md) — 回滚外部操作和热重载延期，保留其余 12 项。网络作用于选中进程，链条为重新启用跟踪，三箭头为逐过程／逐语句／跳出。调试器保留自有恢复责任。两套后端按开工基线分别验收。
- [ActionAnalyze 通信机制验证](../../docs/ActionAnalyze通信机制验证-20261124.md) — 原次离线模型31项、自有Windows IPC37项通过；同执行者背压负控/独立控制正控，冻结三个已声明应用线程后须外部放行控制线程才有新ACK；该次只验私有Job设置未注入杀父，后续故障实测见下一项，不作为生产恢复；4KiB配额可见1MiB待写；不证明全线程/驱动/生产Agent/CLI或性能
- [ActionAnalyze R3补充验证](../../docs/ActionAnalyzeR3机制补充验证-20261124.md) — 历史自有 R3 授权下实测37项IPC正常回归，7项杀父Job终止自有冻结子进程（不是恢复，子exit可为0），EXE D95DFD61…替代83358064…；独立R3已知MASM调用步入/步过/跳出及提前断点/UD2/中止清理106断言通过，EXE 02E7F3E1…；进程TCP未提权317，12项权限负控通过、成功断连未测，不触碰SSH/规则；shared Connections.cpp将317固定归连接不存在需后续纠正。该轮未运行 R0。
- [单点追踪共享采集架构与 CLI 设计](../../docs/单点追踪共享采集架构与CLI设计.md) — 2026-11-24 用户改为 Qt/Win32/CLI 各自组织业务与会话，停止共享宿主/公共追踪 DLL/统一 runtime 方案；原文为历史备选。自动调查不创建页面/Dock/隐藏控件；保留既有底层复用、唯一驱动协议及资源冲突检查，trace 命令仅历史草案，未实施

- [欢迎页采样与 GPU 遥测蓝屏](ksword-welcome-gpu-telemetry.md) — 首页采样范围、GetNodePerfData 空指针现场、17763 系列禁用与 WDDM 2.4 门槛
- [KSword UI/主题架构](ksword-ui-architecture.md) — theme.h 动态/静态 token 边界与构建期门禁、全局样式块链路、WindowChrome 标题栏染色、周期后台刷新与全局进度通知边界
- [复杂报告二级子页](../../docs/Issue-223-复杂报告子页.md) — 高密度三列字段、范围/类型直达、附加属性去重与共享原文编辑器
- [窗口控件检查](ksword-control-inspection.md) — UIA/Win32 独立树、悬停与选中分离、一次性拾取配对、透明覆盖裁剪及隐藏桌面 UIA 回归边界
- [内存工作台重写（进行中）](ksword-memory-workbench-rewrite.md) — 用户拍板的 D1–D4 决策、Phase 0 七个 Qt-free 逻辑类与 2587 条断言已落地登记、后续阶段与暂定参数、等价变异体的坑；设计文档在 docs/内存工作台重写设计.md
- [内存工作台夹具并行变异的四个坑](ksword-memwb-parallel-mutation-pitfalls.md) — 环境变量进程级会互相覆盖、并行构建写满系统盘、/W4 /WX 下常量条件变异编不过、NO_SUMMARY 不算被抓到
- [QTimer 戳阻塞 exec() 的两个坑](ksword-qtimer-popup-race-crash.md) — 嵌套第二层 singleShot 按引用捕获局部变量会在栈销毁后写入（整进程崩溃）；固定毫秒数在机器忙时会错过弹窗窗口，改 0ms 单层定时器 + 之后显式排空事件循环
- [统一内存编辑器与汇编](ksword-memory-editor.md) — Tab4/Tab6/R-1 共用快照编辑器、Intel 汇编语法、暂存与后端绑定、写前比对和最终回读
- [标题栏全局搜索/双模式输入](ksword-global-ui-search.md) — GlobalUiSearch 架构、页面路径/高亮跳转链路、i18n 审计恒等词条与语言包定点插入约定
- [MSVC/WDK 构建恢复](ksword-build-recovery.md) — `LNK1000 IMAGE::BuildImage` 的一次性 WPO 禁用重建，以及驱动 x64 `ApiValidator` 后置校验边界
- [RXPF HVCI 写入屏障](ksword-rxpf-hvci-write-barrier.md) — MmChangeImageProtection 只对原本 RX 的页释放 SLAT 写保护；.data/.rdata 第一步 CHANGE 就拿不到 RW 别名；g_CiOptions 结构性不可写
- [RXPF 没有影子 IDT 等于半成品](ksword-rxpf-is-half-useless-without-shadow-idt.md) — HVCI 下只能改 .text 字节且不可执行；DSE/hook/热补丁/所有常见用例全部结构性不可行；**物理机 LIDT 实测 2026-10-18 = `STATUS_PRIVILEGED_INSTRUCTION`，影子 IDT 路线终局关死**
- [RXPF mode=1 restore 结构性拒绝](ksword-rxpf-mode1-restore-structural-fail.md) — 对测试驱动的 .rxpftst 段 mode=1 恒返回 0xC0000005（内容未改也拒），SHA-512 digest 救不了；顺带修 MDL 别名顺序与 Hyper-V 下 SELF_IMAGE_TEST 门禁
- [RXPF mode=1 在 26H2 实体机实证](ksword-rxpf-mode1-realhardware-26h2-confirmed.md) — 全防护开启（CI/HVCI/HVCI Strict/Secure Boot，TestSigning 关），mode=1 restore 保留 0xB7；本项目目前最强的 HVCI 被绕过实证
- [Claude 把 RXPF 能力推理错了](claude-rxpf-capability-confusion.md) — WRITE ok ≠ 项目可用；一个会话连犯三次；读到 ok=True 时必须进一步看 alias 保护位
- [VBS 三层机制分开看](ksword-vbs-hvci-kdp-hvpt-distinction.md) — HVCI/KDP/HVPT 分管执行/物理帧/翻译；HVPT 才是封 remap 的那一层；SecurityServicesRunning 含 7 才是 HVPT running
- [现有 RXPF handler 的受理范围](ksword-rxpf-current-handler-scope.md) — 三道门：只接内核取指 NX fault（P=1/W=0/I/D=1/CR2==RIP）、PFN 身份复核、注册时 lock PFN；任何改 PFN 或接数据缺页的方案不是现代码能承载
- [Claude 把 VBS 三层机制混成一堵墙](claude-conflated-vbs-mechanisms.md) — "HVCI 页表只读"是统称错误；讨论 PTE/PFN/translation 方案前先查 HVPT 是否在跑
- [驱动候选地址安全读取](ksword-driver-safe-read.md) — 不可信内核地址统一使用 `KswordARKRuntimeReadMemory`，以及 Release 同构函数符号归因注意事项
- [KSecDD 驱动加载引导方案](ksword-ksecdd-dse-bootstrap.md) — KExecDD/LSASS 与 KexecDDPlus/Server Silo 的前置条件、许可证与运行风险边界
- [已卸载驱动来源布局](ksword-unloaded-driver-layout.md) — NtosActive 与单项可用性的区别、精确全局 RVA 的局部运行时布局补全、离线回归与实机边界
- [驱动 OS build 上限策略](ksword-driver-os-build-gate.md) — 2026-10-03 按用户要求注释 R0/Launcher 上限拦截与 runtime fallback build 防护，保留最低版本及逐功能校验；附历史 fail-closed 策略
- [蓝屏 BGP、截图基线与崩溃前解析缓存](ksword-bugcheck-bgp.md) — `BPP=1` 延迟探测、24/32 BPP 预生成、四区截图布局、进程/模块缓存、Stop Code 白名单归因与 fail-closed 边界
- [蓝屏 Shield PatchGuard 安全缓冲](ksword-bugcheck-shield.md) — 只走公共 BugCheck reason 回调、多阶段有界 stall、KSHL 确认令牌、绝不写私有 ntoskrnl 状态
- [CI 合并回归恢复](ksword-ci-merge-recovery.md) — Actions 日志收敛顺序、共享 IOCTL 编号兼容、WDK 令牌声明与 `/WX` 协议头约束
- [FileDock 文件元数据编辑](ksword-file-metadata-editor.md) — FILE_BASIC_INFO 零值写入、重解析点句柄、文件身份复核、结构性属性保留与异步回读
- [文件占用扫描与解锁](ksword-file-handle-usage.md) — 模块映射无可关闭句柄、自身进程保护、R3 35% 阶段、路径查询等待上限与不完整结果
- [句柄页 R3/R0 关闭](ksword-handle-close.md) — 行快照菜单、内核创建时间、独立关闭 IOCTL、挂起/恢复回执与旧枚举布局兼容
- [FileDock 右键菜单与特殊权限启动](ksword-file-context-menu.md) — 不可用动作隐藏、菜单顺序、System/TI/管理员/普通用户令牌启动及验收边界
- [FileDock 大目录响应性](ksword-filedock-latency.md) — 快照模型、缓存排序、后台重解析标记与状态查询、十万项全选回归
- [R0 文件删除边界](ksword-file-delete.md) — POSIX 路径移除、共享检查高风险模式、回执兼容与 Win10 动态入口
- [Win32k 消息 Hook 筛选](ksword-message-hook-filtering.md) — 同侧原子筛选、目标/所有者 UI 范围、异步旧结果抑制、Hook 独立预算与诊断
- [快捷键清除与跨版本规则匹配](ksword-hotkey-clear-matching.md) — 规范目标与逐项回执、USER会话及EnterCrit ABI、当前映像通用C规则和v4变更门禁；六组静态证据见[跨版本记录](../../docs/快捷键跨版本规则匹配-20261025.md)
- [Win32k 窗口 Band 事务](ksword-window-band-control.md) — 跨 UIAccess 原生顺序、精确版本 ABI、GUI 调用线程、恢复及未完成的实机验收
- [R0-only 进程身份校验](ksword-process-r0-identity.md) — 内核枚举身份、0x8b 三项退出证据、CID 按 owner 局部否决、无精确偏移双机实测与客体部署/SSH
- [线程内核诊断与 APC 功能规划](../../docs/线程内核诊断与APC功能规划-20261121.md) — 区分入队、投递、终止信号；精确 KTHREAD PE/PDB（DBI Age）与 getter 交叉核验；CLI 的 R0 线索不算帧，ETW 事件栈与线程瞬时快照分开验收
- [实时结构采样与独立回执验收](ksword-live-structure-sample.md) — 双VM严格过半；保存上下文原始等待/忙线程内核链均到用户机器帧，四路并发及逐字节复核通过；两份精确内核、CLI-only及未覆盖边界
- [进程列表 R0 字段显示](ksword-process-list-fields.md) — 保护来源提示、PS_PROTECTION 名称解码与 HandleTable 空值/不可用区别
- [KernelDock 内核知识中心](ksword-kernel-knowledge.md) — 71 专题双语目录、R3/R0 现场证据协议、业务 IOCTL 映射、只读站内路由与验证器约束
- [内核回调监控通道](ksword-callback-monitor.md) — Callback Monitor v1 多游标 ring、回调 try-lock 发布、Minifilter 双消费者与高频 Qt 模型提交边界
- [Object Callback 安全注销](ksword-object-callback-remove.md) — PDB RegistrationHandle 语义、EX 行身份/代次重验证、ObUnRegisterCallbacks 与移除后复核边界
- [扩展回调注销研究](ksword-callback-remove-research.md) — OpenArk/WinObjEx64 源码、Registry Cookie 校准、特殊类别真实参数、Image Verification 包装器计数与 ETW/EMP 句柄缺口
- [HVM 常驻生命周期保护](ksword-hvm-resident-lifecycle.md) — Intel/AMD 准入与 UI 状态发布、S0 电源回调、处理器拓扑冻结、DriverUnload 互锁与全核退出边界
- [调试器共享后端与 x64dbg 适配](ksword-debugger-backend.md) — 原生会话借用、64 导出 ABI、真实 Windows 停止事件、HVM 执行断点、独立调试器与控制日志 Tab
- [不附加内存调试](../../docs/内存调试模式.md) — R3 单线程检查、目标主动接入 VEH 单步、独立 MBEC/MTF 实验后端与分层验证边界
- [AMD SVM/NPT 实验与重启续接](ksword-hvm-amd-lab.md) — 待硬件验收实现、双启动脚本、VMware 克隆、构建证据与未完成的多核验证
- [KswordARKLight 调查工作台骨架](ksword-arklight-investigation-workbench.md) — 跨进程驱动租约、二级页懒加载、EntityRef 路由、证据会话与独立测试/CI 门禁
- [内核池分配分析](ksword-pool-allocation-analysis.md) — PoolTrace v2 真实布局、会话隔离、未知位置丢失配对、历史栈来源、共享 DbgHelp 锁与 Qt 6.9 窄窗
- [剪贴板保护会话生命周期](ksword-clipboard-guard.md) — Agent 配置热更新、停止标记、管道整包读取与 Hook 就绪状态
- [UAC 安全桌面助手生命周期](ksword-uacdesk-lifecycle.md) — 父进程阻塞等待与取消、ETW 清理、所有配置禁用文件/调试日志及验证边界
- [驱动功能矩阵 CI](ksword-driver-functional-ci.md) — 185 IOCTL 全量处置门禁、危险操作模式排除、targetGuard 目标校验、PatchGuard 延迟崩溃的归因降级
- [进程注入痕迹检查](ksword-injection-trace-check.md) — InjectionSurvey 判据层分层与不变式、能力限制与覆盖缺口的分界、交叉视图矛盾分档、两项需按能力单独提权的采集

- [Light R3 shared backend migration](ksword-r3-backend-migration.md) — 逐功能迁移至 shared、保留行为、HostX64 编译与测试后独立提交
- [启动项服务删除权限回退](ksword-startup-service-delete.md) — SCM 对象接管、最小授权、删除前恢复权限、warn 回调和无真实服务修改回归
- [Serena 迁移的项目历史记忆](serena-imported-memory.md) — 迁移原文，包含旧工具引用，使用前核验。
- [PSDirect Copy-Item -ToSession 对大 binary 静默损坏](ksword-psdirect-copy-item-binary-corruption.md) — WinRM 对 3+MB kernel driver .sys 产生 corruption（size 不变 hash 变），sc start error 193；用 base64 encode + Add-Content 分块 512KB 绕过；判据：VM 侧 Get-FileHash 必须与 host 一致
- [TSC_OFFSETTING 在 Hyper-V Gen2 来宾结构性不可行](ksword-tsc-offsetting-hyperv-gen2-structural-limit.md) — Gen2 无 HPET、Hyper-V 参考 TSC 页周期重写撕开累积偏置、CPL=3 可读共享页旁路驱动；本机 N=30 实测 timing P50=8842 min=7985, 全部 > 1000 阈值；项目 docs/虚拟化规范要点.md:576 已自认 "RDTSC 可补偿但跨线程 race 难掩盖"
- [多 agent 并行推 VM staging race](ksword-parallel-agent-vm-staging-race.md) — Restart-VM 跨 agent 竞争会让 ks-stage 的 .sys 被 zero-filled (前 64 字节全 0), sc start error 193; 推 VM 前先 git log 核并行 commit, 发现并行就停止 VM 推送只 land 代码
- [Hyper-V Gen2 console autologon 在 PSDirect-only 不触发](ksword-hyperv-gen2-console-autologon-blocker.md) — 四种方法 (registry/vmconnect/Msvm_Keyboard CAD/LsaStorePrivateData) 全部失败, session 1 无 interactive user; CE autorun lua 可以 bypass (不依赖 window station), x64dbg GUI UIAutomation 不可用; backend 可用性验证优先用 CE 代理, 不用 x64dbg sweep
- [Backend 3 IDT 写被 PTE RO 挡死](ksword-backend3-idt-ro-pte-blocks-poc.md) — HVCI off 下写 IDT 就 BugCheck 0xBE（PTE bit1=0）；SEH 挡不住；推翻 workflow #3 的 "PatchGuard 是唯一 blocker" 预期；原地改 IDT 结构性死，CR0.WP/PFN remap 各有坑
