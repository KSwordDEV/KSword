# ActionAnalyze 施工任务与契约落点

日期 2026-11-24。**首批工作包已并行开工，产品验收仍待完成。** 这里把 A0–A10 拆为 33 项，原专项提供语义依据，本文确定任务边界、状态所有者、输入输出与验收归属。已领取的工作和变更记录见[工程推进记录](../.claude/memory/ksword-action-analyze-engineering.md)，总体判据见[开工总表](ActionAnalyze完整开工审查与实施总表.md)。

## 1. 开工顺序和状态口径

A0 逐项提供所需契约子集，CLI 本端先打通离线项目／原事件回放／查询／长程 I/O 的纵向链，Qt、Win32按同一契约分别接入。各工作包按实际前置并行，三端各自拥有本端会话。R3 验证在本机执行，普通 R0 验证仅在 `E:\VMs\Windows11-24H2` 执行。控制后端尚未接通时，CLI capabilities 只公布实际离线能力，夹具控制结果保留夹具标识。[验收范围与运行环境](ActionAnalyze工程开工基线.md#验收范围与运行环境)

任务按 `design-ready / implemented / built / native-verified / product-verified / blocked` 分别登记。以下 33 项逐项凭适用证据更新，最终关闭须达到全范围验收。主协调者可将逻辑闭合的工作包先分批提交到 `ActionAnalyze`，适用构建随后执行。交付记录修改文件、固定 IntDir／OutDir、构建日志、原生与产品证据及未覆盖项，按端、后端与路径明确待验状态。CLI 离线外壳的构建与 A0 子集的静态检查已登记，产品链与 R0 验收待完成。[工程推进记录](../.claude/memory/ksword-action-analyze-engineering.md)

环境专项另列 16 个探测面、15 个 RAV 任务和 7 组独立实验，接入 A0/A1/A2/A4/A5/A8/A9/A10 的适用职责。首批工程只接被动来源工作，主动实验继续按专项准入与运行授权执行。研究清单本身不计入基础任务验收。[环境实验行动方案](ActionAnalyze反反虚拟机与环境实验行动方案.md)

依赖取下表前置的**适用接口**，不要求前包所有可选能力完成才开始后包。Stored 归档、基本查询和有限语义是首条链；zstd／SQLite缓存、完整内容扫描按能力分别交付。完整候选目录继续维护，首条链的规则数不限制最终收集范围。

双后端和启动期的 DB01–DB07 是 A 任务的追加交付条件。R3 是正式交付路径，在 KSword 驱动未加载或不可访问时独立完成受支持用户态全流程。R3 的本端控制与恢复账独立于 A4 的 R0 修复，A6／A7／A8 采用所选后端的适用接口。每次采样显式选定后端，活采样禁止静默切换。原所有者完成恢复并确认脱离后，才能以另一后端新建采样与代次，停点令牌和恢复责任留在原后端。原 33 项基础编号继续用于双后端和三端的独立验收。[双后端独立全流程](ActionAnalyze双后端独立全流程设计.md)

SB01–SB08 约束同步停点、组范围、故障与性能验收。首批工单可按各自输入开始，A0 先提供各自依赖的契约子集。S 目录已有停止组快照与正反例草案。[工程开工基线](ActionAnalyze工程开工基线.md) · [同步下断专项](ActionAnalyze同步全局断点与性能复查.md)

## 2. 文件与所有者约定

| 缩写 | 真实根或建议目录 | 所有者边界 |
| --- | --- | --- |
| Q | `Ksword5.1/Ksword5.1/ActionAnalyze/`，计划新增 | Qt本端会话，不由页面拥有原生责任 |
| W | `KswordARKLight/Features/ActionAnalyze/`，计划新增 | Win32本端会话，静态CRT、无Qt依赖 |
| C | `KswordCLI/ActionAnalyze/`，首批施工目录 | CLI本端会话，stdin/stdout工作者归同一存活进程 |
| D | `KswordARKDriver/src/features/kernel_noattach/`，既有 | 普通R0后端实际责任；专题新增文件用 `.c/.h`，不混入HVM |
| P | `shared/driver/`，既有 | 唯一驱动协议；handler在`src/dispatch/ioctl_registry.c`登记 |
| S | `schemas/action_analyze/` | 唯一机器契约目录及黄金向量。首份停止组快照为 A0 草案，完整契约待冻结 |
| R | `docs/action-analyze-planning/`，本轮资料目录 | 规划来源锁和候选索引；不能直接当产品规则包或schema |

下表 `Q/W/C: X.*` 表示三端分别以普通 `.h/.cpp` 按职责实现，不要求机械复制全部类名。头文件明确调用线程、对象寿命和取消后的结果取回义务；不建空壳继承树或公共 runtime。已存在的 EvidenceJson、采集底层和符号锁可复用，但不以此引入跨端会话所有者。

新增或重构文件上限为每文件 2000 行，按职责拆分。重构须在变更说明和工程推进记录中登记受影响的现有功能、实际入口、端／架构与行为契约，附复测判据、实际结果及待测范围。

## 3. A0–A3：可独立施工的格式、归档、规则与CLI

每行的“独立验收”是该工单需要取得的产品证据。已有机制夹具的结果保留原环境、目标与适用范围。

| 任务／前置 | 文件和状态所有者 | 输入 → 独立产物 | 失败、取消与恢复 | 独立验收／开通条件 |
| --- | --- | --- | --- | --- |
| A0.1 值与身份；原事件契约 | S:`value.schema.json`、`identity.schema.json`、`field-catalog.json`；Q/W/C:`EventTypes.h`、`IdentityLedger.*` | 原生字段及来源证据 → 有类型字段、实例键、阶段可用性目录 | 无法确认创建身份保留weak／unknown；重用产生新实例，不能猜补 | 零／最大u64、地址位宽、重复键、UTF、PID/TID重用反例；每字段有类型、单位、来源、阶段、缺失状态 |
| A0.2 方法与计划；A0.1 | S:`method-catalog.json`、`plan.schema.json`、请求／结果／能力schema；C:`MethodCatalog.*` | 已定方法、六域、预算、显式结束策略 → 必需参数／状态／能力／幂等分类 | 未知方法／字段按版本契约拒绝；旧stop与未知副作用不可自动重发 | help／REPL／JSONL同元数据；两个未决处置默认保留必填，无默认猜测 |
| A0.3 格式与跨端向量；A0.1/2 | S:`archive-format.json`、`vectors/`、`compatibility.json` | 存储布局、aa-cjson-v1与DSL语义 → 字节布局表、向量索引、预期结果及拒绝原因 | 未知major／requiredFeature拒绝，不忽略后另存“完整旧版” | 每个偏移、CRC域、长度上限有向量；每向量有独立预期和来源，不由writer自产自验 |
| A1.1 项目及配置；A0 | Q/W/C:`ProjectDocument.*`、`SampleCatalog.*`、`ProjectLock.*` | 配置草稿、保存修订 → 项目、独立sample和实际快照 | 锁冲突只读／拒写；创建半途失败保留可识别partial，旧manifest不覆盖 | 同项目两sample、取消保存、第二写者、历史不访问驱动；ASLR只重绑定义，不迁移stop |
| A1.2 Stored与恢复；A1.1 | Q/W/C:`SegmentWriter.*`、`SegmentReader.*`、`BlobStore.*`、`CheckpointWriter.*`、`RecoveryScanner.*` | 有界原包／事件／blob → 分段、依赖水位及完整前缀 | 短写／flush失败保留最早失败点；坏尾只读扫描不截原件；归档失败不阻塞控制 | 每头／payload／flush／checkpoint边界故障；缺依赖不宣布durable；进程强杀与断电分别记 |
| A1.3 查询、导入与留存；A1.2 | Q/W/C:`ArchiveQuery.*`、`IndexAdapter.*`、`PackageReader.*`、`PackageWriter.*`、`RetentionPlan.*` | checkpoint／查询／导出选择 → 固定分页、可重建索引、ksapack | 游标失效明确报错；取消留partial不覆盖完整包；GC保留引用及活lease | 三端互读、索引删后重建、>4GiB包、越界路径、并发只读与GC；SQLite/zstd缺失仍可Stored查询 |
| A2.1 六域与类型；A0 | Q/W/C:`FilterAst.*`、`PredicateParser.*`、`PredicateValidator.*`、`FilterPlanner.*` | 编辑器／结构请求 → typed AST、字段阶段检查、保守下推计划 | 坏regex／未知字段拒绝；依赖冲突不静默关规则；取消准备不发布半计划 | Strong Kleene三值、not／截断、P∨C保留、原事件／历史查询同向量；不向entry提供未来返回值 |
| A2.2 规则编译；A2.1＋来源准入 | 开发期转换目录待创建；Q/W/C:`RuleCompiler.*`、`RuleDependencyIndex.*` | 固定规则IR、字段能力、闭包与预算 → PreparedRuleSet／逐条阻塞报告 | 不支持的算子、授权／字段缺口保留全部原因；准备失败不替换活采样规则包 | [规则施工清单](ActionAnalyze规则来源与转换施工清单.md)逐条件对照；循环依赖／状态超限反例；目录浏览不编译全集 |
| A2.3 有界状态与回放；A2.2/A1.2 | Q/W/C:`SemanticProcessor.*`、`RuleStateStore.*`、`AnalysisRun.*` | 原事件及连续水位 → 单事件／共现／序列／计数结果与证据引用 | source gap／迟到／预算淘汰标incomplete；取消analysis不改原sample | 独立原始事件正反例，实例／句柄重用、无序不伪成有序；冷却只抑制动作不抹命中 |
| A3.1 命令与输入；A0.2/A2.1 | C:`Commands.*`、`InputReader.*`、`RequestDecoder.*`、`ReplParser.*` | 人工REPL或UTF-8 JSONL分片 → 同一种Request | 超长未换行有界拒绝；坏请求逐项返回；不交shell执行 | 同一进程追加请求、UTF／引号／64位、两请求乱序；同步内置help和`docs/CLI使用文档.md` |
| A3.2 派发与输出；A3.1 | C:`MethodDispatcher.*`、`OutputWriter.*`、`DiagnosticWriter.*`、`ProtocolJson.*` | Request及订阅 → 唯一stdout writer与requestId账本 | stdout／stderr独立背压；重复ID回原结果，同ID异参冲突；交付失败不否认已生效 | 停读两标准流仍可控制；不能抢占已阻塞的OS写；长程返回后旧dispatch不追加第二文档 |
| A3.3 生命周期；A3.2/A1 | C:`Session.*`、`LifecycleSupervisor.*`、`ControlCoordinator.*` | EOF／Break／期限／父身份变化 → orderly-close和终态summary | Ctrl-C取消前台job；未知原生责任不退出伪称clean；不建daemon接管 | 先假后端验I/O，后真实后端验恢复；两类报告分开；旧命令退出码、JSON和取消不回归 |

## 4. A4–A7：真实控制、来源、传播及执行

| 任务／前置 | 文件和状态所有者 | 输入 → 独立产物 | 失败、取消与恢复 | 独立验收／开通条件 |
| --- | --- | --- | --- | --- |
| A4.1 恢复账本；A0 | D:`kernel_noattach.c`、`kernel_noattach_context.c`、`kernel_noattach_breakpoints.c`及按职责新文件；P:现有协议扩展审定 | 精确stop token／逐项操作 → 原生hold、TF/DR、保护与临时资源责任 | 第N项恢复失败不清账；单primary限制先显式报告，再按容量方案扩展；不盲归还外部挂起 | 通信§7.4源码缺陷逐项修复，T01–T29对应外部判据，待在指定 R0 来宾运行 |
| A4.2 Query、Wait与失联；A4.1 | D:`kernel_noattach_events.c`、`kernel_noattach_ioctl.c`、`debugger/noattach_ownership.h`；P及registry | file／owner身份、通知 → 权威Query、per-file取消、cleanup／独立watchdog | 通知丢失可Query；cleanup不可等待死owner；租约不依赖下一次异常才处理 | 多file、迟到ACK、owner死、无新异常、设备关闭及恢复失败；原单线程后端独占回归 |
| A4.3 三端消费及协调；R3依赖DB02/DB05的适用接口，R0依赖A4.1/2的适用接口 | Q/W/C本端R3原生adapter或R0 client；Q驱动访问只经`ArkDriverClient/`；本端`StopLedger.*`、`ControlCoordinator.*` | 实际后端／槽容量／reason／结果 → 一致状态快照与可达recover | R0消费reason5、5–8问题单独修；R3不依赖该修复；坏包明确失败，不自动换后端 | 双后端各自版本／容量／外部挂起；同stop一次继续，退出／旧epoch负控；R3无驱动调用独立完成 |
| A5.1 API、broker与阶段；A0/A1 | `APIMonitor_x64/core/MonitorPipe.*`及x86对应实现、`shared/ApiMonitorInjectionBroker.*`；Q/W/C:`ApiSource.*` | 原包、安装及配置ACK → typed entry/exit/complete、原字节与覆盖记录 | Hook失败不报Ready；异步submit不叫完成；旧包显式adapter，队列满区分来源损失 | 双架构、失败／部分写、句柄生命周期、旧监控停钩与归档；不把898定义当实际覆盖 |
| A5.2 ETW、callback、异常；A0/A1 | 既有ETW／callback低层；Q/W/C:`EtwSource.*`、`KernelSource.*`、`ExceptionSource.*` | 借用EVENT_RECORD／真实内核记录／异常 → 深拷贝事件、时钟与对象身份 | 解析／权限／provider失败分开；不能从ETW事后事件生成前置闸门；不抢调试事件消费者 | provider/event/version/opcode逐行；头PID与payload目标不同、丢包、普通fail-fast及工具自身操作负控 |
| A5.3 脚本、WMI及网络；A5.1/2适用来源 | Q/W/C:`ScriptBlockAssembler.*`、`WmiSource.*`、`NetworkObjectLedger.*` | 实际可采字段 → 分片正文、方法／对象、连接／请求代次；各为独立能力 | 分片缺失不拼完整正文；WMI未接则unsupported；无字节源明确未采，不生成PCAP | ScriptBlockId重组、COM架构／方法、socket／request重用与异步长度；候选WMI不因Action Scope存在就自动首版开通 |
| A6.1 根与身份；A4/A5 | Q/W/C:`TargetBinding.*`、`AdmissionCoordinator.*`、`TrackingReasons.*` | 根定义／传播候选及强身份 → 来源准备事务与sourceReady、原因引用集合；不等待所有未来区域 | PID已重用拒绝；取消根不撤另一根责任；控制器／必需peer排除自动部署但保留事实 | 多根同对象、循环、迟到绑定、源退出；未知目标字段不能按当前同PID补边 |
| A6.2 Ready与快速下一跳；A6.1 | Q/W/C:`AdmissionCoordinator.*`；broker及Agent受支持闸门adapter | A的受支持迁移请求 → B读端、必需配置／覆盖／执行探针回读 → 放行令牌 | prepare失败／超时保留已取得闸门；只取消自有资源，禁止以LOADED放行；异步来源只报事后 | 真实短间隔A→B→C、并发准入合并、B首段就影响C；独立执行计数对照，不用日志到达先后替代 |
| A6.3 关系、缺口与退休；A6.1/2 | Q/W/C:`PropagationLedger.*`、`CoverageLedger.*` | 来源事实、执行关联及退出 → 直接边／候选边／策略边、有效时段 | 再次普通业务不自动继承永久恶意标签；资源达限停新扩展，已有恢复责任保留 | 同宿主正常线程负控、边多父、取消／重新纳入区间；每边可展开原事件与缺口 |
| A7.1 区域及版本；A5与A6.1身份／来源准备 | Q/W/C:`RegionLedger.*`、`ContentVersionLedger.*`、`MappingAliasIndex.*` | 写入、映射、保护及实际字节证据 → mapping代次／内容版本／区间关系；不等待A6.2全部迁移已放行 | 请求长度不充成功范围；未知并发写保留区间不确定；释放／地址重用退休旧版本 | [逐路径矩阵](ActionAnalyze执行覆盖与逐路径验收.md)P01–P16；碎片／重叠／共享别名／COW，hash相等不当来源证明 |
| A7.2 执行屏障及重设防；所选后端A4/A7.1 | R3原生debug／用户态保护实现或普通R0专题＋Q/W/C:`ExecutionProbeCoordinator.*`、`PageProtectionLedger.*` | 已纳入区域／真实异常 → 所选后端绑定mapping的regionReady、实际线程、进入尝试、执行确认与probe epoch；A6.2只消费本次required集合 | 未完整持有线程／新线程门控不开放X；长页内到预算保持可控停点；保护冲突不写旧值，恢复权限不冒充已继续异常 | 两后端各验既有／新生线程、共页、并发异常、跨页、循环；重设NX先于放行，逐项恢复；R3不加载驱动 |
| A7.3 栈与控制转移；A2/A4/A5 | Q/W/C:`StackIntegrityAnalysis.*`、`FrameLedger.*`、`ControlSlotWatch.*` | 真实异常、保护、栈快照或显式watch → 保护失败／pivot候选／槽位变化／转移证据 | 无边界不宣称任意越界；slot随帧退休，DR不足拒绝；不从call字节外形声称完整ROP | 同进程控制数据写、GS/CFG/CET来源、良性纤程／尾调用／展开；当前Minidump过强释义仅在相关实现时修正并回归 |

## 5. A8–A10：动作、三端工作台与交付

A9 的两套桌面总览共用交互验收矩阵，Qt 和 Win32 分别回填入口与实机结果。[桌面总览交互与验收](ActionAnalyze总览交互与验收.md)

| 任务／前置 | 文件和状态所有者 | 输入 → 独立产物 | 失败、取消与恢复 | 独立验收／开通条件 |
| --- | --- | --- | --- | --- |
| A8.1 12项动作及步进；A4–A7适用部分 | Q/W/C:`ActionPlan.*`、`StepCoordinator.*`、`BreakpointBindings.*` | 冻结对象／stop及定义 → T01–T04、T06–T10、T14真实结果 | 提前异常／断点／退出保留真原因；取消不假报已停；TF／临时断点与用户责任分别清理 | 同帧／递归／同返回地址其它线程、锁依赖、部分失败；T12/T13无按钮／命令；两项默认未定前显式参数 |
| A8.2 后台调查及dump；A1/A4/A5 | Q/W/C:`InvestigationJobs.*`、`StopSnapshotLease.*`、`MemoryEvidenceWriter.*`；原页面helper最小抽取 | stop或明确live范围 → 原始现场先保存、后符号／解码；T05和调查预设独立 | 缺页sidecar不补零；continue竞争校验lease；取消合作收尾，符号网络不占控制线程 | 零页面／Dock／隐藏控件；字节独立核对；旧ThreadStackWindow／RegionDump流程回归；每端架构分别公告 |
| A8.3 进程断连；A0/A5网络身份 | 既有`shared`连接底层；Q/W/C:`ConnectionAction.*` | 冻结进程实例／连接快照 → T11逐连接断开及回读 | 修317固定误诊；查询失败不强用缓存；UDP/IPv6分别不支持／实测；不改整机网络 | 提权环境目标TCP确断且非目标存续、快速重连、四元组重用；当前仅权限负控，不宣布成功 |
| A9.1 后台与投影；A1/A2/A6/A8 | Q/W/C:`PresentationFeed.*`；Q后台任务登记／W本端管理 | 同sample事实 → 有界列表、图、瀑布增量与现场状态 | 隐藏停投影不停止归档；UI队列淘汰可重建；历史不携活控制令牌 | 可见／隐藏、换sample／改筛选／迟到结果；四类运行状态及实际水位分开 |
| A9.2 入口与编辑；A9.1 | Q:`MonitorNavigationSchema.h`、`MonitorDock.cpp`、`MainWindow.cpp`＋新工作台；W:`FeatureRegistry.cpp`、`MonitorFeature.cpp`、`WorkspaceHost` | 真实导航→页面分类→共享布局；规则／断点草稿 → 显式保存／apply | 页面关闭不丢owner；请求时冻结选择；权限／准备失败原位恢复 | Qt/Win32真实factory、全局搜索／Taskbar、ShortcutRegistry；ParameterWorkspace／详情／表格模式逐页核对，深浅／窄窗／DPI／首帧实机验 |
| A9.3 CLI真接通及三端差异；A3/A4–A8 | C:`MethodDispatcher.*`与本端adapter；S:能力对照 | 同契约方法 → 各端真实能力、原因和证据链接 | unsupported不冒充空成功；CLI不调用Qt会话；历史query不attach | 同数据三端输出身份／语义一致，分别记录来源和机制差异；不能将CLI成功计作两GUI完成 |
| A10.1 基线及故障；适用纵向链 | 固定验收工程／日志、Q/W/C诊断计数 | 冻结环境／数据集／配置 → CPU、RSS、队列、归档、冻结／恢复和UI分位数 | 达限区分正常过期／丢失／预算淘汰；恢复预留不借给数据；满盘不自动删证据 | 无规则／全部适用、慢盘／停读输出、循环传播、1小时、休眠；用真实测量冻结公开阈值 |
| A10.2 工程、依赖及旧入口；每次相关改动 | 各`.vcxproj/.filters`、语言包、原help、许可证／NOTICE及正式Release | 已验证模块与依赖 → HostX64产物／语言主题门禁／逐源发行清单 | Light CRT／无Qt、zstd与系统SQLite实际能力分开；链接失败按仓库恢复流程 | BelowNormal、固定IntDir／OutDir；Qt只用仓库脚本；旧API／ETW／debugger／CLI原生回归，不能只测新页 |
| A10.3 交付矩阵；A10.1/2 | 支持矩阵、证据索引、已知缺口和用户手册 | 每端／环境／路径／规则结果 → 可复核版本声明 | 未跑R0／GUI／性能各自pending；未决恢复不得clean；不提交／推送或发布未授权成品 | 每项声明连到实证，正式输出位置及临时配置清理结果齐全；候选数量与可发布规则数量分别列 |

## 6. 关键接口需要冻结到什么程度

以下是接口职责草案，名称可调整；正式字段和错误枚举在A0生成。跨端一致的是资料与可观察行为，各端拥有自己的对象、线程和句柄。

| 接口／唯一owner | 输入与前提 | 输出／提交点／结果取回 |
| --- | --- | --- |
| `ProjectDocument.saveDraft` | project、baseRevision、draft及写锁 | 新不可变revision或冲突；保存不发布到目标 |
| `Session.prepareSample` | 已保存revision、明确策略、根定义及预算 | sampleId＋冻结计划；Ready须另经目标实际回读 |
| `Source.prepare` | source plan、架构、目标强实例及required集合 | 逐项installed/configApplied/probeArmed与原始错误；transported不作Ready |
| `Admission.prepareTarget/commitRelease` | 强目标、来源请求、所需能力闭包及expectedRevision | admission token、逐项Ready；只有唯一协调者消费token一次 |
| `IdentityLedger.resolve` | 来源实例证据及其有效时段 | 强身份／弱候选／冲突，不隐式查询当前PID覆盖历史 |
| `RegionLedger.applyFact` | mapping、实际写范围、版本、原事件引用 | 不可变版本变化及关系；不能以“脏”布尔抹掉原内容版本 |
| `ExecutionProbe.arm/query/disarm` | mapping/content代次、范围、预留槽和后端能力 | probe epoch、真正覆盖范围、恢复责任；仅已绑定main不宣称全部线程 |
| `ControlCoordinator.submit/query` | requestId、epoch、对象、stop、expectedRevision | accepted与操作ticket，另取applied／observed；取消以后仍能查原结果 |
| `EvidenceArchive.append/barrier` | 不可变批次、依赖引用和预算 | 有界接纳、written／durable独立水位；barrier不占控制线程 |
| `SemanticProcessor.prepare/consume/finish` | 固定规则包、typed事件、水位／gap | PreparedRuleSet、behavior ID与完整依据分页；gap不能被finish掩盖 |
| `InvestigationJobs.capture` | 明确stop lease或live范围、预设及预算 | jobId、易变证据提交与后续analysis；同stop同范围合并、每触发引用保留 |
| `PresentationFeed.readDelta` | viewSample、queryHash、generation、水位 | 有界delta／需要重建；不持采集或原生控制权 |

所有异步接口都明确“取消请求已接纳”和“作业已结束”两个状态。错误包含原始来源／码、失败阶段、已发生副作用和remaining obligations，不用一个bool承载。query返回实际快照且无隐式启动；权威回读在后端，本端缓存标采样时刻和来源。

## 7. 首条纵向链与后续放行门槛

| 切片 | 明确输入与输出 | 能证明／仍不能证明 |
| --- | --- | --- |
| V1 离线资料链 | 独立手写原事件／坏格式向量 → C项目两sample → Stored归档／重开 → 简单同线程语义及历史query | 验资料、缺字段、关联及查询；输入标fixture，不证明任何真实采集或R0 |
| V2 长程交互链 | 一个存活CLI → REPL/JSONL追加／取消／订阅 → 假后端与归档背压 → 正常关闭 | 验真实I/O与生命周期；假applied必须注明backend=fake，不公告真暂停 |
| V3 来源链 | 自有良性操作 → 既有真实来源 → 规范化／原包／语义／导出 | 每来源／字段／阶段真实核对；单事件通过不等于完整候选全集 |
| V4 控制与首跳链 | 本机所选 R3 后端就绪，或普通 R0 修复且指定来宾就绪 → A写B＋B既有线程执行 → 停止／调查／重设防／继续 | R3须在KSword驱动不可用时独立运行；两后端各核对执行与归因，未测共享store／新生线程／快速C不开放对应声明 |
| V5 多跳与产品链 | 所选后端下快速A→B→C及路径矩阵 → Q/W真实工作台＋C真实方法 → 长期／故障／发行 | 三端与两后端分别验收，最终关闭须完成当前全范围。已明确延期的比较、回滚、热重载及候选干预沿原范围登记 |

每个切片有正向与“故意撤掉必要输入”的漏跟负控，且保存独立结果判据。工作包可以并行实施，切片按 V1–V5 的前置证据逐级放行。V1–V3 与本机 R3 纵向链可独立推进，普通 R0 单列来宾证据。资料工作可先进行，需要目标处置或步进依赖放行的操作继续显式传参。[总表§13 两项默认决定](ActionAnalyze完整开工审查与实施总表.md#13-真正还需要用户决定的默认行为)

## 8. 与旧工作包及专项的对照

通信D0/D1落实A0与A5；C0/I0对应A4；I1对应A6；I2对应A7.2；I3对应A1/A2/A7.1；I4对应A8/A9。规则W0–W3对应A0/A2.2的开发期来源与转换，W4/W6对应A2.3，W5对应A9，W7/W8对应A10。项目P0对应A1；工具T0由A8各动作覆盖。原29项U账继续保留，不能因为本表拆完就关闭U项。

| 总账项 | 具体关闭任务 | 关闭所需的证据归属 |
| --- | --- | --- |
| U01、U02 | A2.1–A2.3、A0.3 | 六域／类型／三值／状态处理同向量与资源反例 |
| U03、U04、U05 | A0.1/A0.3、A1.1/A1.2、A6.3 | 强身份／不可变版本、三端互读、坏尾及引用恢复 |
| U06 | A0.2、A3.1–A3.3 | catalog/help同源、活进程真实I/O／取消与旧命令回归 |
| U07、U13 | A5.1–A5.3、A6.2 | 每入口真实阶段／字段、Agent角色及目标持锁负控 |
| U08、U28 | A6.1–A6.3 | 快速下一跳、去循环、控制对象排除与候选边保留 |
| U09、U10 | A7.1/A7.2 | 完整线程／新线程门控、共页／别名／长页内／自修改 |
| U11、U12 | A4.1–A4.3、A5.1/2 | R0逐项恢复与T01–T29、精确系统／ABI和能力负控 |
| U14、U15 | A3.3、A4.2/3、A8.1 | 唯一控制提交、停止／取消／close竞争及owner死恢复 |
| U16 | A8.3 | 权限成功／拒绝、非目标存续、四元组复用与317诊断 |
| U17、U18 | A8.1/A8.2 | 无UI调查、现场lease、原字节、架构／符号／步进边界 |
| U19 | A2.2、规则W0–W3/W6/W8 | 全候选状态、许可与字段／条件对照、真实原事件验证 |
| U20、U21、U26 | A9.1–A9.3 | 同ID投影、真实导航／共享结构、三端独立能力及GUI |
| U22、U27 | A10.1、A3.3、A4.2 | 实测预算、休眠／恢复后身份／时钟／Ready及责任 |
| U23、U25 | A1.1–A1.3、A10.3 | 锁／外部导入／GC／保留／脱敏及审计，不自动删证据 |
| U24 | A10.2/A10.3 | HostX64正式产物、语言／主题／许可和旧来源回归 |
| U29 | A5.2、A7.3 | 真实保护／frame/slot／转移证据与合法切栈负控 |

存储、规则、执行、栈、通信、CLI、项目和工具栏专项均以本文作为下一层任务索引；一个专项的可选候选仍按原范围，不由表格中的模块名自动变为首版必需实现。实测未通过时更新实际能力和阻塞，不能仅把测试删掉或放宽预期。

用户提出的“不要停在口号”作为后续关闭任务的统一条件：每项必须有具体入口／旁路、输入字段及原始证据、状态owner、真实执行及提交点、失败／取消／恢复、独立正负控、端／环境限制、可核验产物。机制无可行路径时交付反证／限制报告与明确替代流程；不能用“R0实现”“智能关联”“自动跟随”“支持反沙箱”作为完成记录。所有新规范仍是待实施检查条件，不把文档齐全标为产品完成。

再次复查发现的16项具体缺口见[规划缺口复查G01–G16](ActionAnalyze规划缺口复查与补齐任务.md)，作为原任务追加关闭条件，不增加已完成计数。尤其A6的sourceReady与A7特定区域的regionReady分别准备，避免循环前置；完整新线程门控、本地普通store的新落点、异常消费／关闭恢复及Ready失效仍是机制门槛。新增／删除／调整驱动IOCTL同步`tools/driver_functional_ci/driver_test_plan.json`及plan_gate，未执行的R0测试显式排除／pending，不能标通过。
