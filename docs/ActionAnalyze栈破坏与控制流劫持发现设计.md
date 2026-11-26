# ActionAnalyze 栈破坏与控制流劫持发现设计

[缺口G05–G09／G12](ActionAnalyze规划缺口复查与补齐任务.md)补充本专项的异常转交、slot与步进／环境实验的DR竞争、返回边界、原始快照及托管代码版本。一个#DB、某方法加载或工具自身INT3写入不能提升为样本劫持；工具字节变更单列来源，未知异常保持原owner语义。

日期：2026-11-24。状态：根据用户指出的遗漏补充设计；没有实现检测器、修改目标保护、构建夹具、执行攻击或运行R0。本文与[主规划](恶意行为单点追踪与调试能力规划.md)、[开工总表](ActionAnalyze完整开工审查与实施总表.md)、[事件协议](ActionAnalyze事件身份与协议契约.md)、[筛选规则](ActionAnalyze筛选器与规则语言设计.md)共同使用。下文[P1]–[P9]为本轮核对的官方资料，地址见末节；它们不证明本产品已经接入对应信号。

下一层为[施工任务A5.2／A7.3／A8.2](ActionAnalyze施工任务与契约落点.md)，逐项列异常来源、帧／槽位owner、输出、退休与失败判据；[执行矩阵P13](ActionAnalyze执行覆盖与逐路径验收.md)明确未修改正常代码中的ROP可不触发既有脏页探针，不能由“代码跑到哪跟到哪”口号抹掉此分支。

## 1. 为什么必须单列

先前主线重点讨论跨进程影响、区域内容版本和实际执行线程，未充分展开栈缓冲区越界写、返回地址破坏及代码复用。只收集远程写API、只找新建可执行内存或只对载荷页设NX，都不能作为本分支的完整发现方案。ROP可复用现有映像代码片段[P9]，即使没有新可执行页，也可能改变控制流。

既有“仅数据攻击暂不纳入”不排除本分支：返回地址、异常处理目标、函数指针等虽保存在数据内存，改变它们并造成异常控制转移属于控制流问题。单纯修改业务标志／余额等而不涉及控制转移的分析继续按原范围延期。发现程序缺陷、确认保护触发、确认劫持及证明外部恶意输入来源是四种不同结论。

## 2. 术语与成熟度

| 情况 | 能确定的事情 | 不能直接确定 |
| --- | --- | --- |
| 栈空间耗尽，通常0xC00000FD | 线程无法继续扩展栈；递归／大栈分配等需要调查[P1] | 不能仅据异常码称缓冲区被覆盖或发现攻击 |
| 栈缓冲区越界读／写 | 有可信对象边界及实际访问，才可确认越界；ASan重编译场景可提供此类报告[P2] | 普通栈地址被写入本身合法；栈整体范围不等于每个局部缓冲区边界 |
| /GS cookie检查失败 | 保护检查报告不一致；/GS在选定函数插入检查，有明确覆盖边界[P3] | 不自动知道哪次写、谁提供输入、是否已经执行恶意代码 |
| 泛化fail-fast | 原始异常码、参数和真实来源；__fastfail常以0xC0000409及首参数子码报告[P4] | 0xC0000409不等于全部是栈溢出；不能将普通主动退出都报攻击 |
| 返回／间接调用完整性失败 | 真实CFG／影子栈信号能说明相应检查失败[P5/P6] | CFG与返回地址影子栈不是同一种检查；检查失败不证明输入归因 |
| 栈指针／展开异常、疑似pivot | 当前上下文与已知栈／运行时说明冲突，是调查线索 | 用户代码可在系统初始栈外执行，纤程也有自己的栈；不能一律判攻击[P7] |
| ROP／其它代码复用 | 需真实控制转移序列及来源／完整性证据；ROP复用已有代码[P9] | “栈里有很多代码地址”“某函数前不是call”“一次展开失败”均不足以确认 |

成熟的是具体保护／诊断机制，不是无条件通用发现：有源码并可重编译时，ASan类插桩能更早定位具体访问；只有成品EXE时，需要目标实际保护、异常来源或明确的动态观测能力。普通R0能提高控制与取证能力，但不因此获得所有CPU store和所有局部对象边界。

公开能力拆成：`observed protection failure`、`observed slot write`、`observed invalid transfer`、`suspected stack anomaly`、`attributed exploit chain`，各自报告支持／覆盖；不发布一个“栈攻击发现=是”的合并布尔值。

## 3. 本仓库已有能力与缺口

已读`Ksword5.1/Ksword5.1/MinidumpDock/MinidumpCodeText.cpp`：有0xC00000FD、0xC0000409等异常与FAST_FAIL子码释义；这是离线解释表，不是持续监视器。部分文字把cookie失败直接称“货真价实的溢出”、把旧GS子码等同越界写，结论强于目前证据；后续接入须同步纠正文案及zh-CN/en-US，本轮不修改这些产品文本。

现有线程栈／DbgHelp可复用捕获和解析基础，但原R3临时挂起、恢复失败处理及架构限制须先接新责任账本，见总表§8。已有R3调试106断言只覆盖固定良性调用／步进，不证明本分支发现率；已有NX夹具也不证明ROP覆盖。

尚未发现可据此交付的ActionAnalyze栈破坏事件流、保护失败adapter、frame/slot生命周期或恶意来源归因器。本文不把已有转储释义和未来处理器硬件功能计作已完成产品。

## 4. 四层发现计划

### 4.1 保护与来源清单

绑定目标时只读收集进程DEP／ASLR／CFG／用户影子栈策略、目标架构、模块PE保护元数据及采样时刻。配置与实际异常分开；PE含CETCOMPAT不等于本次已启用，审计模式／兼容模式／严格模式及硬件条件分别保存[P5/P6]。查询拒绝、OS不支持和字段未采分别表示，不把失败填false。

不自动启用Exploit Protection、IFEO、WER LocalDumps、GFlags、Application Verifier，不更改cookie／CET／进程缓解策略来“制造可检测性”。内核硬件栈保护另有平台前提，本方案不为此新增虚拟化或改HVCI／系统策略；若现场已有合法诊断，仅按实际来源读取，不能推广为R0栈执行监视已具备。

### 4.2 事件入口与异常现场

首版优先接现有合法原生调试会话的异常事件、可获得的保护审计／WER资料及导入dump；每个来源独立登记实时／迟到／离线、权限、schema、丢失和可否保持现场。不得抢已有调试器或新建第二个Wait/Continue消费者；没有已验证异常源时只能公告离线能力，不靠普通ETW目录存在就声称获得全部异常。

按完整ExceptionRecord、ExceptionInformation原始数组、first/second chance（来源可得时）、continuable、命中寄存器及精确实例记录。0xC0000409先解析实际子码；子码未采则unknown。只认原生精确保护来源或一致现场，不因攻击者手工构造同异常码而确认真实检查失败。__fastfail是不可继续的第二次机会异常，普通VEH／try-catch不构成其可靠采集后端[P4]。

捕获顺序为原始异常／CONTEXT→SP附近有限原字节／实际映射→模块与展开元数据→符号与解释；不能先依赖已经损坏的栈完整展开成功。事件时寄存器与稍后停止现场分开。常规异常来源原有调试停止权单独记账，不为R0优先再做一次多余挂起。

### 4.3 一致性调查与候选评分

后台核对SP与声明栈／纤程范围、范围采样来源和时间、可展开帧、返回槽位、代码映射／内容版本、可信影子栈证据（实际可得才用）及最近明确控制转移。初始栈界限只是一种声明，不当通用合法栈全集[P7]。

检查候选包括：返回槽位由已观测写覆盖、经实际branch/exception来源看到异常转移、栈切换缺乏已知运行时说明、真实保护失败及调用前后异常。PE与符号只能提供布局／解释，不能凭模块签名证明某返回合法。栈上扫描到的地址标`scanned-candidate`，可信unwind标`unwind-derived`，实际分支标`observed-transfer`，不得互换。

合法纤程／协程、自定义栈、JIT、异常展开／longjmp、尾调用、优化省帧、系统回调、正常Hook与调试器都列负控。运行时登记／解释也只是证据，恶意程序可能伪造；不能一条allowlist隐藏其它真实写入／保护失败。没有来源上下文时保留候选及unknown，不强出“ROP confirmed”。

#### API入口的轻量候选来源

根据对[Action Scope历史分发包的静态核查](ActionAnalyze对ActionScope功能与实现核查.md)，补入不依赖目标编译保护的候选来源：在已启用API入口保存原调用地址、原始SP／可得上下文、当次模块与区域版本，后台检查调用点字节形态、声明栈范围与映像归属的一致性。这类API边界启发式可在保护异常前提供线索，不要求新RX页或远程写；也不能由此证明最初越界写和完整ROP链。

实际来源须保存`api-caller-anomaly`原始条件与阶段，先用有限成本触发有界调查，再按真实槽位写入／保护失败／转移证据升级。反汇编指令边界、优化／尾调用、Hook／JIT／晚加载模块、合法切栈以及不可读现场分别负控；仅“前面不像call”不发布确认攻击。参数快照与调用点读取依来源预算，不能在同步规则谓词内临时无界展开。

该包外框的10次上限因NULL回调提前返回而未形成实际多帧路径，初始化模块表也不能证明当前模块身份。借鉴入口与分层思路，不复用这些旧判据强度或将其检测率／暂停能力当KSword验收依据。具体接入仍归A5来源与A7完整性工作包，未实施。

### 4.4 指定现场的写入及转移监视

用户可在已验证stop上显式选择返回槽位／关键控制数据位置，准备有界数据断点或选择性控制转移跟踪。数据断点存在架构、尺寸、数量和实际写入上下文限制[P8]；槽位绑定frameInstance＋stackRegionVersion＋地址及有效时段，不保存成下次采样的裸地址。

首版建议数据watch默认关闭，打开时默认单个选中线程、一个精确槽位，使用实际剩余能力，不能占掉其它调试器／步进已拥有的DR资源。准备时读回武装与覆盖；帧退休、异常展开、栈切换、线程退出或映射变化时撤自有watch，旧地址复用不继承监视。新线程未Ready、其它写入线程、远程写、内核代写或共享别名未覆盖均记gap，不能将仅监视受害线程的watch当完整写入者跟踪。

watch 命中记录受监视位置的访问或变化及实际时序。原数组边界需要独立证据。在控制转移前保持现场需要所选后端证明具体时机和并发屏障。该后端拥有控制、上下文和清理责任。

选择性控制转移记录是后续能力开通项，必须标实际记录机制、起止、丢分支与预算；不默认启用全进程逐指令单步／动态二进制插桩。处理器trace／全量DBI可另行评估，首版不引入新必需依赖，不据此承诺全ROP/JOP发现。单纯每隔一段时间读栈不作为成熟的执行链证据。

## 5. 事件、规则与传播模型

补充字段目录`exception.*`、`stack.*`、`controlFlow.*`、`mitigation.*`，不从本地化crash摘要倒推。建议事件族：`exception.observed`、`protection.failure-observed`、`stack.slot-write-observed`、`stack.snapshot`、`control-flow.transfer-observed`；`stack-integrity.anomaly`与`control-flow.hijack-candidate`为派生结论。

| 字段组 | 必备字段或缺失说明 |
| --- | --- |
| 异常／保护 | 原码／flags／参数数组／子码、firstChance、continuable、fault/context地址及架构、真实signalKind／provider、策略快照引用 |
| 栈／帧 | threadInstance、stackInstance／regionVersion、declaredRange及来源、observedSP/IP、frameInstance与生存时段、unwind quality／错误、returnSlot位置和已得字节 |
| 实际写入 | actor线程／进程、目标stack/slot、实际重叠范围、before/after字节可得性、入口／完成／trap-after时序、覆盖缺口；仅快照差异不称某线程写入 |
| 控制转移 | from/to IP、branchKind及取证机制、目标mapping/contentVersion、原SP／新SP（可得时）、实际与推测区分、调用／返回关联证据 |
| 归因 | 输入／文件／网络／跨进程operation引用、对应捕获区间、explicitBinding或candidate、缺失／迟到；无可靠字节或对象绑定不补造污染链 |

frameInstance与stackInstance为sample内有生命周期对象，不以`TID+RSP`永久标识；纤程切换不造新线程，同一线程可有多个stack实例，同一纤程跨线程需有实际证据才关联。栈region可写，不能强套“可执行载荷区域”类型。

规则分开命名：栈耗尽诊断、可信cookie检查失败、可信CFG／影子栈检查失败、返回槽位已观测写入、疑似pivot、已观测异常控制转移。诊断／候选不自动升级恶意归因。启用规则将对应异常、策略、映射、栈生命周期及控制转移来源加入P依赖闭包；硬排除冲突仍拒绝，显示筛选不影响发现。参数只用捕获快照，同步谓词不临时unwind或读目标内存。

主链新增同进程分支：`输入或写入依据（可未知）→栈／控制槽位版本→实际或候选控制转移→后续行为／跨进程影响`。漏洞被利用的进程是执行主体，不自动成为恶意样本来源；即使后续B→C，根因也不能只按PID相同倒推。A远程写B栈与B自己处理外部数据后越界写分别保存。

## 6. 停止、恢复、存储与UI

保护触发可能已经进入不可继续／待终止状态；“发现”“系统已阻止”“KSword请求暂停”“已建立真实stop”分别呈现。没有可靠可继续现场时，仅保存证据，不显示可安全步进。继续必须由原异常所有者执行原生语义，不吞异常、伪造DBG_CONTINUE、跳过校验或修复返回地址来假装恢复。调试器自身临时责任仍精确释放；不承诺修复被破坏的目标栈，不重新启用已延期的样本外部回滚。

字节／CONTEXT／异常参数／模块和策略快照按[存储契约](ActionAnalyze项目存储格式与恢复设计.md)归原sample及evidence，派生判断另有analysisRun，原记录不可变。错误栈／缺符号不妨碍保存原字节；历史导入不启动原目标或触发自动暂停。缓解配置的读取时间不能被展示为攻击发生时的确定状态。

一键调查增加`stack-integrity`预设，使用现有编辑器／详情结构，不新增第13个工具栏按钮。中央语义行显示“栈耗尽／保护触发／疑似劫持”等精确类型，可展开原事件、槽位变化、栈与实际转移；图允许同进程内部关系，不只画进程创建／远程写边。详情沿用StructuredFieldView＋CodeEditorWidget／专业内存视图。

初始预算：异常现场每线程最多64 KiB原始栈字节、一次快速捕获累计1 MiB、后台至多64帧；更大范围用显式调查预算，不扫描全栈来凑攻击特征。异常风暴按相同实例／异常类别做有界展示汇总，但原生异常处置、必要保护事实及恢复不可降为普通可丢UI事件；不能归档全部必需事实时按ArchiveDegraded停止新准入并记录gap。预算计入总表原有接收／规则／调查额度，不额外开无界池。

## 7. 实施与验收

归属现有A0字段／schema、A2规则、A5来源、A7执行完整性、A8调查／控制、A9投影，不新增统一runtime。异常解释表调整作为相关旧功能回归项。首版先做到异常／真实保护信号保存和候选分析，再逐机制开通精确槽位监视与控制转移证据；不能让后两层未实现时UI宣称通用发现已完成。

| 测试 | 必须验证的区分 |
| --- | --- |
| 良性递归／大栈分配耗尽 | 报栈耗尽，不能确认攻击或缓冲区越界 |
| 自有受控cookie破坏及普通fail-fast／主动退出 | 保存原码／子码及真实来源，普通退出不升级保护被攻破 |
| 同进程本地越界写、不调用WriteProcessMemory | 不被远程API限定条件漏掉；无入口来源仍诚实显示缺口 |
| 同页内不触及cookie的受控越界 | 有边界插桩时可诊断；无边界不能假报覆盖 |
| 自有固定返回槽位写入、帧返回后地址复用 | 命中实际监视范围，退休不误跟后续栈帧；早／晚时序明确 |
| 只复用既有RX代码的固定无害转移序列 | 不依赖新可执行页；无真实branch证据时不称确认ROP |
| 正常纤程／异常展开／尾调用／JIT／缺符号 | 不用单特征确定攻击，缺数据为unknown而非默认恶意 |
| CFG／影子栈开启、关闭、审计、unsupported | 能力／策略与实际信号分别验；不更改用户系统策略来补条件 |
| WOW64／native AMD64、并发线程／远程及内核写、DR冲突 | 每架构／写入者上下文与资源分别验收，未覆盖明确gap |
| 不可继续异常、现场读取失败、取消／父死、满盘／导入重放 | 不吞异常、不损失自有责任、不在历史重放动作 |

以上是将来使用固定、自有、无持久化副作用目标的验收设计，不是本轮执行授权；不引入真实利用样本或可迁移攻击载荷。先做R3适用范围，R0构建／加载／运行继续等用户环境。硬件／系统条件不具备时标blocked，不自动改策略。本轮没有本分支检测率／误报率或性能结果。

## 8. 官方依据

2026-11-24核对以下一手资料；它们用于机制边界，不代表本产品支持。为便于离线文档保留，地址以代码文本记录：

- [P1] Microsoft《Debugging a Stack Overflow》：`https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-a-stack-overflow`。
- [P2] Microsoft《AddressSanitizer error: stack-buffer-overflow》：`https://learn.microsoft.com/en-us/cpp/sanitizers/error-stack-buffer-overflow?view=msvc-170`。
- [P3] Microsoft《/GS (Buffer Security Check)》：`https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check?view=msvc-170`。
- [P4] Microsoft《__fastfail》：`https://learn.microsoft.com/en-us/cpp/intrinsics/fastfail?view=msvc-170`；《Fail Fast Exception C0000409》：`https://learn.microsoft.com/en-us/shows/inside/c0000409`。
- [P5] Microsoft《Control Flow Guard》：`https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard`。
- [P6] Microsoft《PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY》：`https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_user_shadow_stack_policy`；《GetProcessMitigationPolicy》：`https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy`。
- [P7] Microsoft《GetCurrentThreadStackLimits》：`https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadstacklimits`；《Fibers》：`https://learn.microsoft.com/en-us/windows/win32/procthread/fibers`。
- [P8] Microsoft《Processor Breakpoints》：`https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/processor-breakpoints---ba-breakpoints-`。
- [P9] Microsoft，Raymond Chen《A quick introduction to return address protection technologies》（2024-10-15），ROP与返回地址保护说明：`https://devblogs.microsoft.com/oldnewthing/20241015-00?p=110374`。
