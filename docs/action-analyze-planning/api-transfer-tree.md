# 第 9 项：跨段写入与线程创建候选树

用户持续推进要求：「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。本批为实际产品开发；第 3、7、8 项及 Qt／Light 构建、GUI 实测仍依协调顺序后置。本页只记录本作者负责的候选树，不覆盖四 Hook 生产者、CLI 消费者、活采集或数据步进。

## 产品接口与边界

- Qt 导航：监控 → 行为分析 → 总览 → 归档关系。页面类型为已有结果列表／树及字段详情；复用 `TablePresentation`（操作条 `None`）、现有 `ArchiveRelationModel`、`selectRecord` 与 `StructuredFieldView`。现有对象图和对象菜单不变。
- Light 导航：监控 → ActionAnalyze → 回放采样 → 底部候选树。复用原页面的原生控件、主题、筛选、虚拟列表定位和现有只读详情；旧分类下拉与来源上下文保留。新原生树封装在 `ApiTransferCandidateTree.{h,cpp}`，无新页和进程操作。
- 对照原 Qt `OfflineObjectEvidence` 的采样内对象引用和关系树，以及 Light `ActionAnalyzePage` 的归档分类／原包定位。新候选节点不转换为规范进程、线程对象，不能据此获得对象菜单资格。
- `shared/evidence/ApiTransferCandidateWindow.h` 只适配桌面行缓存，复用 `Detection/ApiTransferChain` 判定；来源 ID、代次与 `ArchivedEvidenceGraph` 一致。不设置 `InputTrust::Validated`。
- 每个候选可展开写入、线程创建两个真实 `raw/段 #序号`。Qt Enter／双击沿用 `selectRecord`；Light Enter／双击沿用列表选择和原详情。原写入已滚出事件表窗口时使用候选自身保留的双方只读行，保留筛选草稿。
- 同采样重读按双方坐标恢复候选分支、根节点、叶项选择与展开状态；同一创建匹配多个重叠写入时分别保留。切换项目、采样描述或实际读取路径不沿用旧候选详情。Light 隐藏候选树时将树内键盘焦点交回可见筛选入口。
- Light 树纳入原有 `NavigateControls` 的 Tab／Shift+Tab 顺序和控件子类处理；原生方向键浏览、Enter 和双击仅在树内生效，没有新全局快捷键或常驻任务。
- 范围仅是来源声明的写入实际完成区间包含后续线程请求入口；不证明实际执行、区域版本或强归因。源包自述不认证历史生产者。

## 后台核验与容量

- Qt `ReadApiFollowReplay`、Light `ReadApiProjectReplay` 在既有 `ReadApiCheckpoint` 回调暂存候选及写入状态；整段散列、范围、计划与检查点通过后提交。失败段的链状态和候选丢弃，已核验前缀和页面旧结果继续按原发布规则处理。
- 同一采样连续核验过程中保留共享匹配器的 1024 条写入状态；双方详情缓存同样 1024。最近候选窗口 256 对，累计候选总数、写入淘汰数独立呈现；候选淘汰数可由总数减保留数得到。
- 单独打开 API 导入段只消费当前段，不读取、推断或连接未核验的其他段。整文件和导入尾记通过后才发布候选。
- 主表原有 4096 行近期窗口不扩大；候选窗口独立于 API／ETW 混采窗口裁剪，UI 不进行全归档扫描或文件读取。
- 新源文件及共享头已登记 Qt／Light 工程和 filters；Light 现有 StoredEvidence 原生验证工程补链接 `ApiTransferChain.cpp`，只为保持其后续可构建，本批未运行。
- Qt 既有 `tools/action_analyze_validation/qt/Test-OfflineSegmentReader.ps1` 补链接共享匹配器；本批不运行该入口。Light 新树实现独立于既有 `ActionAnalyzePage.cpp`；该旧宿主原已超过 2000 行，本次只增加必要接线，未将其声明为完成整体拆分或全页 UI 验收。

## 本批验证要求与当前状态

源码已实现；Qt／Light 产品构建和 GUI 未运行。作者直接派发 CodeBuddy 完成源码审查、语言与工程门禁。专用无窗口测试首次编译因测试自身 C4459 失败，变量已修；唯一一次重试遇到 CLI 验收互斥真实占用，退出 2，未启动构建或测试。修正后的测试尚无编译成功或断言通过的实证；准确命令及实际结果见下方回执。

本次 CodeBuddy 范围：源码审查、项目／filters 路径与 XML、定点双语键及语言审计；可维护专用无窗口候选窗口测试，但禁止 Qt／Light 产品构建、GUI 和离屏 GUI。不得编辑其它作者拥有的四 Hook、CLI 消费者、活采集展示、数据步进文件。正式 CLI 与整批实测使用 `Local\KSword.ActionAnalyze.CliValidation` 互斥；需要构建时必须 BelowNormal、HostX64、固定 IntDir／统一 Release，禁止运行时复制。本次先完成源码和语言门禁，原生行为实测按结果记录，不重复已有有效 CLI 验收。

后置桌面人工／独立桌面验收：同段与跨段双方展开；Enter／双击定位；关键字／API／ETW／时间筛选隐藏原包；写入滚出事件表而候选仍保留；候选重叠多写入；旧树选择与展开保留；坏段／缺检查点后旧结果保留及修复重读；混采通道、窄窗、DPI、长文本、深浅主题和首帧。源码通过不能替代这些运行结论。

## CodeBuddy 实际回执

执行者：CodeBuddy｜跨段候选树验证（作者直接派发）。范围严格限定为本批源码审查、工程/filters 与语言门禁、专用无窗口测试；未构建 Qt/Light，未运行 GUI 或离屏 GUI，未运行 CLI 整批验收，未改动产品源码，未提交/暂存/删除并行更改。

已完成的源码审查（均以当前工作树为准，未修改）：

- `shared/evidence/ApiTransferCandidateWindow.h:25-40` 的 `ApiTransferEvidence` 与 `KswordCLI/ActionAnalyze/Detection/ArchivedEvidenceGraph.cpp:127-128` 的 `ApiContext` 使用同一套 `api-monitor-import:`/`api-monitor-follow:` + sessionIdentity、`api-import:` + sampleId / followEpoch、`api-monitor` 来源身份；该结构不携带 `InputTrust`，候选窗口未设置 `InputTrust::Validated`。
- `ApiTransferCandidateWindow.h:67-71` 的 256 对候选、`87-91` 的 1024 写详情缓存与 `ApiTransferChain.cpp:9,49-52` 的 1024 写链状态一致；`EvictedWrites()` 转发链淘汰数。
- `OfflineSegmentReader.cpp:731-734,779-788`（项目 API 跟随）与 `KswordARKLight/Features/ActionAnalyze/ProjectReplay.cpp:112-115,141-148`（Light 项目回放）均以 `stagedTransfers`/`stagedEpoch` 逐段暂存，段校验失败时不提交链状态、候选和来源代次；独立导入段分别由 `OfflineSegmentReader.cpp:474-499` 与 `StoredEvidence.cpp:533-548` 在整段及尾记通过后发布。
- Qt `OfflineSegmentOverview.cpp:1305-1334` 在所选原包滚出主表窗口时回退到 `m_snapshot->transferCandidates` 的双方只读行；Light `ActionAnalyzePage.cpp:1058-1078` 同样在表中找不到时保留 `selectedCandidate`。Qt 树 `activated`（`OfflineSegmentOverview.Objects.cpp:423-431`）与 Light `NM_DBLCLK`/`TVN_KEYDOWN+VK_RETURN`（`ActionAnalyzePage.cpp:2171-2181`）覆盖双击和 Enter。失败回读保留旧结果：Qt `OfflineSegmentOverview.Loading.cpp:142-155` 与 Light 回放失败分支不替换已发布快照。
- 未发现已确认的阻断级源码问题。上述结论仅为源码核对，不构成实机视觉或运行验收。

语言门禁（实际执行）：

- `python -B tools/i18n_language_pack.py audit --source-root Ksword5.1/Ksword5.1 --zh-pack Ksword5.1/Ksword5.1/languages/zh-CN.json --en-pack Ksword5.1/Ksword5.1/languages/en-US.json` 的日志明确输出 `i18n audit passed: 32032 source strings`。实际派发命令通过 Bash 的 `tail` 管道展示结果，工具报告退出 0；该管道退出码不单独证明 Python 退出码，审计结论依据明确的通过输出。
- 另有一次性 Python 键核对：本批候选树相关 45 个 `source_translations` 原始文本键在 zh-CN/en-US 两包均存在且值非空，缺失 0。验证者未修改语言包；本批作者新增的双语键已在当前工作树内。

工程/filters 与路径检查（实际执行）：

- `python -B tools/action_analyze_validation/api_transfer_tree/check_projects.py` → 退出码 0，`RESULT errors=0`。六个 XML 均解析成功：`Ksword5.1.vcxproj`(1572 includes)、`Ksword5.1.vcxproj.filters`(1573)、`KswordARKLight.vcxproj`(740)、`KswordARKLight.vcxproj.filters`(737)、`StoredEvidenceValidation.vcxproj`(32)、`StoredEvidenceValidation.vcxproj.filters`(31)；本批新增的 `ApiTransferCandidateTree.{h,cpp}`、`ApiTransferPresentation.{h,cpp}`、`ApiTransferChain.{h,cpp}`、`ApiTransferCandidateWindow.h` 在项目与 filters 中均登记且解析后路径存在。脚本为本批新测试产物，位于固定目录 `tools/action_analyze_validation/api_transfer_tree/`。

专用无窗口原生测试（未运行，已按互斥要求停止）：

- 新增测试源码 `tools/action_analyze_validation/api_transfer_tree/ApiTransferCandidateWindowTests.cpp`（203 行）、工程 `ApiTransferCandidateWindowValidation.vcxproj` 及对应 filters。工程只链接 `ApiTransferChain.cpp` 及必要的 `LosslessValue.cpp`/`ObjectIdentity.cpp`；固定 `IntDir=KswordCLI/x64/Release/ApiTransferCandidateWindowValidation/`、统一 `OutDir=Ksword5.1/x64/Release/`，`TargetName=ApiTransferCandidateWindowValidation`。用例覆盖：构造 4 个 API 的 AAIP1 显式包；跨段一对真实原行（写入 raw/1 #2、创建 raw/2 #3）；260 次配对保留 256 对且总数不回退；1025 写淘汰 1 条；消费复制草稿不污染原状态；不同代次与会话来源隔离。该测试不读真实归档，不替代段校验失败回滚或桌面定位实测。
- 首次回执更正：上一轮记录的 `MUTEX_BUSY=1`/退出码 2 依据的是旧脚本仅凭 `CreateMutexW` 的 `ERROR_ALREADY_EXISTS` 判定，该标志只证明互斥对象已存在，**不能证明对象正被占用**，故该次“busy 未运行”结论不准确，作废。作者随后修正脚本为显式 `HANDLE`/restype、`WaitForSingleObject(0)` 判定真实占用并在 `finally` 释放；同时补 NT 创建分支、中文注释与 `.vcxproj.filters`。

最终单次复验（作者直接派发，按修正后脚本执行）：

- `python -B tools/action_analyze_validation/api_transfer_tree/check_projects.py` → 退出码 0，`RESULT errors=0`，六个工程/filters XML 仍解析通过、新增路径仍存在（第二次观察到 Qt 两份 include 数为 1574/1575；并行工作树发生变化，数量不用于判断本批登记范围）。
- 第 1 次 `python -B tools/action_analyze_validation/api_transfer_tree/run_validation.py` → 输出 `MUTEX_HELD=1 PRIORITY=BelowNormal HOST=HostX64`，互斥真实获得、宿主 BelowNormal、HostX64；MSBuild 启动并编译，但 `ApiTransferCandidateWindowTests.cpp` 因测试内全局 `scope` 与共享头构造参数同名触发 C4459（`TreatWarningAsError` 下为错误 C2220），`BUILD_EXIT=1`，测试未运行。此为专用测试自身错误，未改动产品源码。
- 仅修本批测试错误：将测试内全局 `scope` 改名为 `testScope`，并同步所有构造实参；未改产品、未扩大范围。
- 必要的一次重试 `python -B tools/action_analyze_validation/api_transfer_tree/run_validation.py` → 输出 `MUTEX_BUSY=1`，退出码 2。修正后的 `WaitForSingleObject(0)` 证明 `Local\KSword.ActionAnalyze.CliValidation` 此刻确实被另一宿主持有，本次**真实 busy**，未启动 MSBuild、未编译、未运行测试二进制；按要求不再重试。
- 最终真实状态：原生行为断言本轮仍未取得运行实证。真实原因是编译首次失败（已修）后，唯一一次重试遇到 CLI 验收互斥真实占用；非权限拒绝。1024/256 有界、跨段双方坐标、复制草稿隔离、来源隔离在专用测试源码中已覆盖，但无本轮通过的运行结果。
- 产物核查：`Ksword5.1/x64/Release/ApiTransferCandidateWindowValidation.exe` 不存在（编译未成功产出）。固定 `KswordCLI/x64/Release/ApiTransferCandidateWindowValidation/` 保留首次失败构建生成的 `ApiTransferChain.obj`、`LosslessValue.obj`、`ObjectIdentity.obj`、`vc143.pdb` 及构建跟踪文件，供后续增量构建复用；未清理正式中间目录。无运行时副本和测试配置，未删除正式产物。
- 作者收尾核对：本批所属路径 `git diff --check` 无输出、退出 0；未提交、未暂存。Qt／Light 产品编译、真实归档读侧和桌面视觉／交互矩阵仍按既定顺序后置。

## 返回主协调的接口与缺口

- 两端快照公开 `transferCandidates`（双方原包值副本）、`transferCandidateCount`（累计总数）和 `evictedTransferWrites`（累计写入淘汰）；Qt 关系模型第三组及 Light 独立 `ApiTransferCandidateTree` 消费这些字段。
- 原生验证下一步是在协调者安排的空闲 CLI 验收批次中，由作者续接同一 CodeBuddy 会话运行固定 `run_validation.py`，取得修正后工程编译及断言结果；当前不宣称原生通过，不再竞争已占用的互斥。
- 产品缺口为 Qt／Light 整合构建、真实同段／跨段归档与坏段恢复、4096 行外双方定位，以及上文列出的桌面矩阵。现有 Light 宿主整体拆分未实施。候选不增加实际执行、强归因或进程操作资格。

## APC 读侧／树增量：源码已接入，未构建未测

本节为后续独立产品开发，不能沿用上文线程创建批次的门禁结果作为本批通过依据。最新用户限制优先于 goal：禁止 CodeBuddy 新派发、续接、重试，不构建、不运行 GUI、不测试；旧任务允许继续。本批未调用任何验收入口。上述“空闲时续接”的后续步骤也须等用户明确恢复派发后才能执行。

- 导航与类型沿用原入口：Qt「监控 → 行为分析 → 总览 → 归档关系」为结果树及字段详情，继续使用 `TablePresentation` 的 `None` 模式、原关系树、`selectRecord`、`FieldDocument`／`StructuredFieldView`；Light「监控 → ActionAnalyze → 回放采样 → 底部候选树」沿用同一原生 TreeView、系统字体、共享主题、虚拟列表与原详情文本。本批无新页面、布局、按钮、菜单或操作资格。
- 对照了 Qt `OfflineObjectEvidence`／已有归档关系树，以及 Light 旧线程创建候选树与原包详情；复读 `UI/StructuredFieldView.h`、Light `Ui/Theme.h` 和根 UI 规范。交互仍为选择已核验采样 → 浏览来源候选 → Enter／双击定位原包 → 同一详情；筛选草稿独立，坏段按既有读侧保留已核验前缀／旧结果。
- `SegmentApiClue`／`EvidenceRecord` 新增 `apiApc` 与 `apcOutcome`，调用共享 `ReadApiApcFields`／`ApiApcCallOutcome`；原协议与 Hook 不在本批所有权。Qt `AppendApiApcFields` 将 AAAP1 十四字段及结果加入唯一规范文档；Light `ApiApcDetails` 经原 `ApiTransferDetails` 调用链进入既有文本详情。缺身份有效位显示未知，合法零请求地址保留，Win32 的第二／第三 APC 参数显示不适用。
- `ApiTransferCandidateWindow` 每包先 `Accept` 再 `AcceptApc`，复用同一链的 1024 写入状态及既有详情缓存；独立保留 `ApiApcCandidateRows<Row>{link, write, queue}` 最多 128 对，公开 `ApcCandidates()`／`ApcCandidateCount()`。线程创建仍保留 256 对。两端快照新增 `apcTransferCandidates`／`apcTransferCandidateCount`，写入淘汰继续共用 `evictedTransferWrites`。
- 独立导入仅在整文件／尾记核验通过后发布；连续项目仍复制整段候选状态，检查点通过后提交，APC 状态与线程创建一同回滚。两端发布时同步写入／入队双方的来源标签，不读取未核验的其它段。
- Qt 原关系树新增第四根「写入 → APC 入队候选」，与线程创建第三根分离；Light 在同一控件中新增独立根。双方叶项保留真实 raw 段号／序号及 API 名，按候选类型＋双方坐标恢复父项、叶项和展开，不将重叠写入或跨组同写入合并。主表仍为 4096 行，双方详情在独立候选窗口内续持，定位不修改筛选。
- 队列结果仅显示接受入队／失败／未知；详情与 Qt APC 节点提示明确“接受入队不证明 APC 已投递或执行”。请求例程不作为实际执行地址；未新增规范 actor／target／thread 角色，未提升 `InputTrust` 或控制能力。
- 双语包定点新增 16 个源文本键；Qt／Light 工程及 filters 登记已有的 `ApiApcFields.h`。未运行语言审计、工程校验、编译或任何测试；本批没有生成构建产物、运行副本或测试配置。CLI graph、`CooperativeApiCapture`、原生关联、数据步进和进程集合页面未由本作者修改。

当前状态仅为源码接入。待用户恢复验收后再核对 AAAP1 两 API 成败／未知、缺有效位、合法零地址、同段／跨段、128 对裁剪、写入淘汰、重叠候选分支恢复、坏段草稿丢弃及 4096 行外定位；深浅主题、DPI、窄窗和首帧均未实际验证，不宣称 UI 全部合规。

## AACT1／AASM1 单行详情与 APC 活采摘要：源码已接入，未构建未测

本批遵守用户最新限制：禁止 CodeBuddy 新派发／续接／重试，不构建、不运行 GUI、不测试、不调用验收工具；仅完成产品源码和必要登记。已落盘结果接口为 `ApiContextOutcome`／`ApiContextCallOutcome(packet)`、`ApiSectionMapOutcome`／`ApiSectionMapCallOutcome(packet)`，均有独立 `Unknown`／`Failed`／`Accepted`；协议头、Hook、Detection、CLI 和 `CooperativeApiCapture` 仍归原作者所有，本批只读消费。

后续上下文候选桌面批次已接入源码：共享窗口新增 `ApiContextCandidateRows<Row>{link, write, context}`、`ContextCandidates()`／`ContextCandidateCount()`，独立保留 128 对并复用原 1024 写链／详情。Qt／Light 快照新增 `contextTransferCandidates`／`contextTransferCandidateCount`，沿用整段核验后提交及坏段丢弃草稿。原树新增独立上下文分类，类型＋双方坐标恢复选择和展开；4096 行外双方仍可定位到原详情，筛选和布局不改。Qt 本端活采回执新增 `contextTransferCandidates`／`latestContextTransfer`，展示函数 `AppendApiContextProgress`；Light 原 `ApiTransferProgress` 消费 `contextCandidateCount`／`recentContext`，无新 timer/query。IP/SP/ABI 仅请求，单行及摘要均明确 contextApplied／执行未知，不升级强图角色或控制资格。新增七个双语键，未新增源码文件；未动 Detection／CLI／CooperativeApiCapture 或源端节映射关联。本批未构建、测试、GUI 或 CodeBuddy 派发／续接／重试，未提交暂存，未产生新产物。此前“首次仅单行、无上下文候选树”仅描述上一批范围，不再代表当前源码范围。

- 导航及共享结构不变：Qt「监控 → 行为分析 → 总览 → 归档行详情」为字段详情，仍由 `FieldDocument`／`StructuredFieldView` 提供唯一搜索、复制和导出源；Light 归档列表选择后的原生文本详情仍从 `ApiTransferDetails(record)` 进入原宿主。对照既有 AAIP1／AAAP1 两类详情与共享字段入口。本批不修改页面布局、表格列、Tab、树、菜单或操作资格。
- `SegmentApiClue`／`EvidenceRecord` 新增 `apiContext`／`contextOutcome`、`apiSectionMap`／`sectionMapOutcome`，两端原包投影调用共享解码及结果函数。独立导入和项目回放继续复用现有完整核验后发布路径，不额外扫描归档。首次仅做单行详情，未消费 `AcceptContext`、未建立上下文或节映射候选树。
- Qt `AppendApiContextFields`、Light `ApiContextDetails` 展示 AACT1 十五字段及原结果。源／目标／线程身份、ContextFlags、IP/SP 各按有效位显示；缺位未知，有效零值保留。ABI 是源端已解码的 32／64 位请求布局。明确 IP/SP/flags/ABI 仅为请求，接受请求不证明上下文生效或执行；输入线程句柄及 CONTEXT 指针不建立对象身份，也不供解引用。
- Qt `AppendApiSectionMapFields`、Light `ApiSectionMapDetails` 展示 AASM1 十五字段及原结果。请求 base/bytes 与返回 mappedBase/bytes 分列，后者缺位不使用请求值回填。`sectionOffset` 保持原输入位模式，不伪装系统调整输出；节句柄不建立节对象或别名身份，进程句柄不授予目标身份。映射返回不证明写入、别名传播、归因或执行。身份缺失时稳定性显示未知，而非根据默认零误报已知否。
- APC 活采摘要已补：Qt 本端 `PassiveApiCaptureOwner` 从已有 `CooperativeApiTransferReceipt` 回调复制 `apcCandidateCount` 与 `recentApc.back()` 到 `apcTransferCandidates`／`latestApcTransfer`，`PassiveApiCapturePane` 调用同一展示模块的 `AppendApiApcProgress`；Light `ApiTransferProgress(receipt)` 在原正文内追加，复用既有活采及最终回执调用点。只显示累计数、原始双方坐标、身份与请求例程，不增加 timer、query、回调订阅或采集接口。
- 新增函数与变量用途均配中文说明，保留正常多行风格；两个展示实现仍低于 1000 行。双语包定点新增 27 个源文本键；Qt／Light 项目及 filters 均登记现有 `ApiContextFields.h`、`ApiSectionMapFields.h`，没有整体重写语言包或新建协议副本。

源码复读已核对解码、单行分派、有效位、输入／输出区别及原回执链路。未执行编译、语言审计、工程校验、测试或真实 GUI，不能据此宣称运行通过或视觉合规。当前批次无构建产物、运行副本和测试配置，无需清理；未提交、未暂存，不覆盖其它作者改动。待用户恢复验收后再查两上下文 API 与节映射的成功／失败／未知、缺位、合法零值、32／64 位 ABI、请求／返回不同值、sectionOffset 高位、原详情搜索复制导出，以及 APC 活采回执的零候选／仅 APC／两类并存与阶段更新。
