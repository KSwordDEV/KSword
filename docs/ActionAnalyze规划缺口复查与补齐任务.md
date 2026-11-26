# ActionAnalyze 规划缺口复查与补齐任务

日期：2026-11-24。状态：用户要求查找不具体及未规划部分；按现有文档、真实源码和微软公开接口资料复查。只补设计，不开始产品实现、构建、目标运行或R0验证。原33项任务、U01–U29、P01–P16和RAV清单继续有效；本文G01–G16是其补充关闭条件，不以新编号增加完成数。

## 1. 复查结论与范围

**仍有缺口，不能宣称“所有方案都已具体、只差写代码”。** 本次发现两处明确文字／目录冲突，九处已有要求但缺执行契约，五处未独立展开的来源或功能分支。下表分别给出原缺口、具体补法、责任与独立验收；“已补规划”不等于机制可行性已证实。两项用户处置默认继续保留必填，不在本次代选。

检索范围为ActionAnalyze各专项、主规划、规则规划、共享记忆，并定点读回普通R0的`kernel_noattach.c`／`kernel_noattach_events.c`、Agent的`HookTargets.cpp`等。检索未发现某术语只作为定位线索，不能单凭零搜索结果判断全仓库没有该能力。本轮没有重新研究Action Scope二进制或重跑来源采集。

## 2. 缺口清单与可开工输入

| 编号／性质 | 原缺口及影响 | 本次确定的具体补法／产物 | owner／原任务 | 独立验收与失败处理 |
| --- | --- | --- | --- | --- |
| G01 目录冲突 | 事件契约写`schemas/action_analyze/`，施工表S却写`docs/action-analyze-contracts/`，会产生两套规范源 | 唯一机器契约根确定为`schemas/action_analyze/`；docs只放解释。A0登记相对文件清单、格式版本、字段／方法稳定ID与向量索引，生成物引用源hash | A0.1–A0.3；各端catalog适配器 | 禁止创建第二规范根；同目录向量在三端独立运行，字段ID删除后保留墓碑不得复用；本轮仅修文，未创建schema |
| G02 旧状态冲突 | 主规划仍写探针“尚未选型”、DSL“待设计”，与专项已定建议混在一起 | 已设防区域首个原型明确NX取指＋外部停止账＋选定线程推进／重设防；Guard／DR等保留各自用途。DSL按专项现有类型、运算符及预算执行，不重新临场选型 | A2.1、A7.2；主规划／原规则规划 | 搜索旧语句并改为实际剩余条件；不能把“原型路线确定”改写成完整屏障已实现 |
| G03 机制未闭合 | 完整线程／新线程门控尚无经过实测的普通 R0 机制。当前 `KnaThreadNotify` 只处理退出 | `ThreadBarrierFeasibility` 定义创建事件、首次用户执行、集合入账、冻结／放行的时序。通知只提交有界事实或使屏障失效 | A4.1、A5.2、A7.2。驱动对应 feature／本端 ExecutionProbeCoordinator | 自有创建风暴、远程创建、创建后立即取指与首次 store，以独立计数检查是否漏入。R3 原生调试事件作为正式 R3 后端单独验收。两后端各自在证明门控后开放相应集合的 X 放行 |
| G04 发现机制未闭合 | 复制／解密／共享普通store后“发现新区域”未写实际触发机制 | 首个自动发现子集仅以成功write／map／protect等实际事件、显式区域纳入和初始映射快照触发；快照只证明当时存在。另研究限定范围写保护观察：保留映射／原保护，写AV→写前字节→受控推进→写后快照，不能由一次快照声称捕获全部store或解密算法 | A5.1/2、A7.1/2；RegionLedger／PageProtectionLedger | 自有普通memcpy／循环store到既有RWX、RW/RX别名、COW、写完立即执行；故意无来源时必须报告D/P/A缺口。GetWriteWatch不能当任意既有进程内存写入者追踪器；未通过前无“自动跟随任意解码”声明 |
| G05 异常契约未闭合 | 原生异常／NX／TF／DR的消费、转交与关闭顺序没有一张统一表 | 新增`ExceptionDisposition`记录异常owner、first/second chance、原现场、自有原因位、continue方式和保护前提；先完成并回读本次动作要求的转换，再提交相应继续：step登记临时X责任，close恢复原保护，不把每次推进误作永久撤探针。未知AV、外部DR、不可继续异常保留原后端语义 | A4.1/2、A5.2、A8.1；本端ExceptionSource与驱动原handler | NX命中时close、保护恢复第N项失败、目标自带VEH、非自有AV、混合DR/TF、用户异常中断步进；恢复失败留账，不能先消费异常再让目标重复撞NX。当前源码Close分支清TF／DR后handled=TRUE不构成完整页保护恢复证明 |
| G06 资源仲裁未闭合 | 用户断点、步进临时断点、页探针、栈slot和环境CPUID实验争用TF／DR／字节，缺共享占用规则 | 每端以本端Coordinator登记`resourceKind/target/thread/mapping/owner/revision/token`；驱动复用现有noattach所有权链。DR按真实可用槽分配并验证尺寸／对齐；同一线程现场的TF只有一个推进owner；同地址临时断点引用计数，冲突拒绝，不自动拆用户资源 | A4.3、A7.3、A8.1、RAV4.1 | 同地址多原因、DR满、外部调试器、自有环境实验与step冲突、owner退出；恢复只归还本方资源。跨端不新增公共runtime，外部工具未受本方预约约束时明确conflict/unknown |
| G07 断点施工未闭合 | 模块RVA／符号已列，但软件字节补丁和可重用定义缺具体退休规则 | `BreakpointBindings`分别保存逻辑定义和真实地址绑定；模块未载入为pending，卸载即stale。软件断点须显式允许改码，写前比对mapping/content／原字节，写后读回及刷新指令缓存；自修改导致不符时停止旧绑定，禁止盲写回旧字节。命中计数按定义修订／真实事件去重，one-shot在一次命中仲裁后禁用 | A0.2、A8.1；本端Bindings与既有后端 | ASLR、forwarder／同导出多包装、同地址用户与临时断点、卸载重用、自修改、并发命中；无法可靠改码时拒绝该机制，不用“armed”掩盖安装失败 |
| G08 步进施工未闭合 | 固定CALL／叶函数夹具不能确定通用step-over/out | `StepPlan`固定起始stop／frame／stack、真实解码字节和候选返回边界；普通指令TF、CALL临时返回点须有支持证明；返回点按线程及帧／栈条件校验。尾调用、异常展开、longjmp、递归、REP及系统调用列独立形态，不能把“下一个#DB”一律算整条指令或整次调用完成 | A8.1；StepCoordinator／既有解码及unwind | 同返回地址别的线程先到、递归、被调函数不返回、异常提前结束、页内预算耗尽；保存真实停止原因。无法保证重新截获时拒绝开始，锁依赖扩放仍须显式参数 |
| G09 入口快照未闭合 | API名和字段表未解决原型ABI、重入、错误状态及输入缓冲竞态 | 在现有wrapper逐项核对入参寄存器／栈／返回类型，Raw不猜XMM或浮点原型；保存／恢复原LastError及适用WSA错误。入口只用有界安全复制／预分配，嵌套工具调用带来源／bypass原因。记录capture区间与phase，原入口快照不冒充内核实际消费字节；异步输出仅按真实完成长度读取 | A5.1、RAV0.2／3；Agent现有HookTargets／按职责adapter | 坏指针、并发改buffer、短写、异常退出、嵌套调用、OVERLAPPED重用／取消后晚完成；无返回事件记incomplete，不补造成功。旧代码已有局部reentry／error保存，需逐入口审查而非另建整套Hook引擎 |
| G10 准入状态未闭合 | A6等待ProbeArmed而A7依赖A6，有启动循环；Ready后模块／Hook失效也缺即时降级 | 区分`sourceReady`与特定mapping／probeEpoch的`regionReady`；A6先具备身份／来源，A7登记已知区域，再由具体迁移请求核对required集合。分配成功后才知道地址的路径不得伪造事前区域Ready；必要时保持已取得闸门并记录其它既有线程的缺口。Hook卸载、映射变化、丢失必需源时使对应Ready失效 | A6.1/2、A7.1/2；AdmissionCoordinator／CoverageLedger | 无初始区域、已知写目标、新分配、模块晚加载／卸载、配置更新时在途操作；旧ACK不重新授权。没有可靠门控的路径只报事后覆盖，不能让全target布尔Ready掩盖 |
| G11 未独立规划 | 服务、任务、WMI／COM／RPC等中介执行未纳入明确传播路径，只列过相关事件族 | 先登记请求actor／实际executor、服务／任务／WMI对象实例、operation及Activity/RelatedActivity（来源真正提供时）、结果阶段和输出进程证据；建“请求／配置／执行观察”三类边。没有关联键只候选，不按父PID或同名命令强串；对broker纳入仍走用户范围及原准入 | A5.3、A6.3；各端MediatedOperationLedger计划模块 | 自有无害本地服务／任务／WMI测试分别验证请求成功但未执行、另一客户端同名请求、重启后新实例；既有仅事后来源不能宣称已前置拦住。默认不部署全系统服务，不扩大网络／SSH控制范围 |
| G12 未独立规划 | JIT只作为良性排除；托管方法版本与async线程切换没有具体来源计划 | CLR runtime／rundown按provider/event/version登记，保存runtime实例、module／method、native范围及可得ReJITID；事件版本由真实schema决定，不混用文档不同事件ID。rundown只描述已有方法；方法产生／地址可见不等于执行。async任务ID来源单列，默认同线程规则绝不暗改为同逻辑任务 | A5.2/3、A7.1、A2.2；本端ManagedCodeLedger候选 | 自有动态方法、同方法多native版本、卸载／重用、工作线程切换；不自动启用profiler／ReJIT，不新增公共DLL。V8／其它JIT无可信专用来源时保留普通区域候选与缺口 |
| G13 语义水位未闭合 | 已禁止空闲推进，却未确定absence／有限历史的结束条件及迟到修订 | 首版实时来源没有覆盖证明时，absence／精确等于阈值的肯定结论保持U；只对声明范围、截止点、无gap且依赖源均有结束／有效水位的窗口定案。离线sealed仅证明归档收尾，不自动证明来源完整。迟到证据追加新analysisRun或派生修订／supersedes，不删原命中，也不重放旧动作 | A2.3、A1.2；SemanticProcessor／AnalysisRun | 源静默、断线、缺包后seal、事件迟到推翻否定、同输入同水位不同调度回放；比较语义结果集合与依据，不比较随机behavior UUID或展示顺序 |
| G14 未独立规划 | “YARA扫描／反编译／符号超时”列了预设，尚未选实际可调用能力与取消边界 | 调查目录逐项标`implemented-adapter/needs-extraction/unavailable`及真实函数／依赖／许可。现有小型规则子集不能叫完整YARA；未选择完整engine前该能力unavailable。符号／DbgHelp与反编译在已捕获证据上后台运行；取消只停止排队／后续消费，不承诺终止不可取消的库调用，不能占住现场lease等待符号 | A8.2、A10.2、规则W3；InvestigationJobs及现有适配器 | 无引擎／离线符号／错误PDB／慢网络／库调用不返回；先保存原始证据后释放不再需要的现场lease。取消晚返回只归原job代次，禁止杀工作线程或暗建新服务 |
| G15 未独立规划 | 产品允许浏览／导出／删sample及包搬运，但CLI目录只笼统写evidence.query/export | catalog补`evidence.query(kind=event/behavior/relation/object/coverage/snapshot)`的判别联合、字段白名单、固定水位、分页／超长字段引用；blob分块读取必须有固定hash／offset／长度及上限，不往stdout塞完整dump。另登记project.close、sample.delete和project.package.import/export，语义复用存储专项，不引入跨sample比较 | A0.2、A1.3、A3.1/2、A9.3；本端catalog及adapter | 每种kind真实非空／空／unsupported，翻页稳定、坏范围拒绝、包取消／只读／活sample拒删。方法为本次提案，未注册成CLI命令；同步内置help和CLI文档后才能发布 |
| G16 未独立规划 | 新增IOCTL虽要求唯一头与registry，原施工表未登记驱动功能CI清单 | 任何新增／删除／调整IOCTL同步`tools/driver_functional_ci/driver_test_plan.json`；能安全执行的登记case，不能运行的写精确排除原因，执行plan_gate检查。驱动逐句中文注释、Warning as Error零警告、源码／filters登记；R0运行仍等用户环境 | A4、A5.2、A10.2；相关驱动feature与既有CI | 元数据未登记必须门禁失败；静态gate、编译、驱动加载与真实恢复分别报告，不能因case被排除就标passed。本轮未修改驱动或CI计划，无构建产物 |

## 3. 四项必须先做的机制验证设计

以下是未来实现／验证授权下的操作步骤，本轮不执行。每项失败都保留原目标状态与责任，不以放宽预期关闭。

1. **新线程屏障（G03）**：以自有原生线程创建器及目标页独立计数建立基线；记录notify实际上下文、线程入账和第一条用户指令；分别在建屏障期间、恢复X期间、重设NX期间创建线程；检查新执行者是否可能在未登记前进入。用显式R3原生debug事件作行为对照，普通R0候选必须独立过相同用例。不能用队列里收到创建消息充当用户态尚未运行的证据。
2. **本地写与别名（G04）**：同一自有数据在普通RW、既有RWX、RW/RX共享视图分别普通store后执行；保存视图／offset／COW及写前后字节；逐次去掉写入来源、目标设防或视图关联，确认系统准确报告是哪一轴失去覆盖。写保护试验单独统计写入扰动和页共用影响，不改成周期扫描主链。
3. **异常中关闭（G05）**：自有NX命中后分别正常continue、close、控制端失联和第N项恢复失败；独立检查原保护／TF／DR以及目标能否按原语义处理异常。重点验证保护未恢复时不能先把AV宣告已处理。未知目标异常只转原owner，不跳过指令制造成功。
4. **准入启动与失效（G10）**：零已知区域开始、首个写入区域已知、分配返回后才有地址三种输入分别验证sourceReady和regionReady；随后卸载模块／撤必需Hook／切映射，确认实际失效会阻止新的放行。晚ACK、重复Ready和旧probeEpoch不能重开闸门；无法事前拦住的并发行为保留缺口。

### 3.1 G03：普通通知、Ex通知与真实门控分别验证

官方文档区分传统通知在创建者线程执行，以及`PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem, ...)`在新线程执行。后者列为**需研究的精确候选入口**，不再笼统写“R0通知可解决”，也不因运行在新线程就假定允许在回调内等待控制器。

研究产物必须分别列：注册类型／支持build、当前执行线程／被通知线程、callback进入与返回、预分配登记成功、候选延后停止机制的实际提交与回读、首次用户指令，以及取消／退出／容量不足的时序。若采用延后工作项／APC等，只能在独立证据证明其在必要用户执行前完成时授予门控能力；仅成功排队不够。Windows公开notify best practices不因换Ex入口而豁免。找不到合法且可证明的时序，就记录该普通R0路径不可提供完整屏障，保持NX或拒绝开始需恢复X的推进。

### 3.2 G04／G05：页保护的真实代码问题与事务顺序

后续获授权的[Explorer实测](ActionAnalyzeExplorer复杂环境验证-20261124.md)为G05补入真实负控：父监护恢复RX后结束仍持有NX异常事件的原生debug控制器，关闭kill-on-exit也未保证目标继续，造成任务栏窗口失效并需重启Explorer。保护恢复、TF／计数归还、待处理异常继续结果和detach必须分别记责；不得用恢复页权限冒充异常已完成，也不得把先正常detach后杀空闲控制器的另一场景替代此门槛。五类正常场景79项通过不关闭该失败，普通R0仍待指定环境独立验证。

本轮续查读回`DebuggerBackend/KswordIndependentFrontend.cpp::tightenedProtection/addMemoryWatch/retireMemoryWatchLocked`，确认以下为实际源码行为而非猜测，尚未修复产品：

| 当前实现 | 会影响的新能力 | 具体施工要求 |
| --- | --- | --- |
| write一律`PAGE_READONLY`，execute一律`PAGE_READWRITE` | 前者会移除原代码页执行权限，后者可能给原RX页新增写权限；不是只修改所需权限位 | 新`PageProtectionPlan`逐段按原保护族生成计划：支持的RX执行观察转RO、RWX转RW；支持的RW写观察转RO、RWX转RX。COW／execute-only／guard／large-page等未证明正确的组合拒绝或单列能力，不盲目复制modifier |
| 只用首个`VirtualQueryEx`结果及单个`originalProtection`覆盖整个length | 跨页异保护不能用一个值恢复；API返回旧保护也只代表第一页 | 按实际页大小、allocation/mapping与同保护连续区间分段；每段保存原值、预期当前值、调用返回及回读。跨reserve、未commit、未知映射或溢出在副作用前拒绝 |
| `addMemoryWatch`先`VirtualProtectEx`，再登记驱动watch；恢复／回滚返回被忽略 | 存在保护已改变而可信异常接收未Ready的窗口；失败会丢失恢复事实 | 在完整线程／新线程门控成立后预留账和异常接收资源，准备真实映射，逐段安装，核对接收／保护代次后发布armed，再按事务放行。任一步失败按逆依赖逐段恢复及回读，失败项不清账 |
| 驱动命中后退休watch，frontend在消费停点时恢复原保护 | 无法直接给出新引擎“保持NX→全线程屏障→受控放X”的保证；owner死亡也不能只依赖frontend恢复 | 现有独立调试器与新执行探针使用显式不同的arm/rearm契约，不能无条件沿用命中即解除。探针保存原保护与临时X状态，close／owner-death按同一责任链恢复；真实结果unknown则保持未决 |

实际执行及恢复归本次显式选定的后端。额外权限变化、临时软件断点和工具写入单列 `tool-origin`。权限转换的适用范围以对应保护组合和原生验收为准。[双后端独立全流程](ActionAnalyze双后端独立全流程设计.md)

消费探针异常还须同时匹配强对象、当前mapping/probe代次、实际访问类型与故障地址，并证明是本工具限制了原本允许的访问；原页本就不可执行时的AV不能归本方探针。RIP／异常地址／fault VA分字段保留，跨页指令不能硬要求三者相等或只按起始RIP所在页归属。指令尚未完整推进时保留进入尝试／部分推进，不生成完整执行确认。

测试至少包含原RX页仍不可写、原RWX页写观察期间仍可正常执行、相邻异保护页各自正确恢复、跨页指令、REP的部分推进、多线程并发、外部VirtualProtect及映射换代。不能只检查“收到了一次AV”，也不能以未崩溃代替权限位、字节与真实执行结果回读。

### 3.3 G09／RAV：WMI类型与目标所见的最后一跳

WMI同时保存`CIMTYPE`与实际`VARIANT.vt`，二者不是同一枚举。官方Numbers资料中的64位CIM整数使用`VT_BSTR`，`uint32`可以用`VT_I4`承载；原始字符串、位模式及有界解释分开保存，不能因看到BSTR就一律当普通描述字符串，或给`TotalPhysicalMemory`硬写`VT_UI8`。profile writer按精确class/property/CIMTYPE及实际合法表示生成替代，未知组合拒绝变更并保留原返回；数组／NULL和调用者不请求pType的情况另验。

四级证据必须收紧：静态指令位置／字符串仅是candidate；`observed`需要实际查询／执行证据；`substituted`需要真实提交的输出／现场及原契约。回调内读回替代buffer只证明交付边界的值，不等于目标之后实际读取。`seen`需要自有detector独立输出或可信目标执行读取证据，普通第三方目标缺此证据时保留`seen-unknown`；后续不退出也不能自动提升为`path-observed`的因果证明。该条件不要求新增通用读指令追踪器，不能通过填充假证据“补齐最后一跳”。

## 4. 检索依据与真实边界

本轮只检索官方接口资料，以下支持接口约束，不证明KSword的实现成立：

- [PCREATE_THREAD_NOTIFY_ROUTINE](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_thread_notify_routine)：传统创建通知运行于创建者线程上下文，不能从当前回调TID猜新线程；Ex变体仍须按实际登记类型另审。
- [PsSetCreateThreadNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutineex)：NonSystem类型在新线程上下文调用，是具体研究入口，不自动授予阻塞等待或完整门控保证。
- [Windows process/thread callback best practices](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-process-and-thread-manager)：通知回调保持短小，不阻塞、不等待用户态／其它线程；排队后等待完成也不能解决这个限制。
- [Debugging Events](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events)：原生调试事件具有进程线程暂停语义，CREATE_THREAD事件先于新线程用户态执行；这不能直接移植成普通R0 notify的保证。
- [GetWriteWatch](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-getwritewatch)：依赖MEM_WRITE_WATCH分配，查询的是页写入状态而非通用写入者／变换归因；分开查询与reset存在竞态。
- [Writing the Debugger's Main Loop](https://learn.microsoft.com/en-us/windows/win32/debug/writing-the-debugger-s-main-loop)：代码写入与FlushInstructionCache、真实事件继续属于调试执行职责，不能靠UI显示已改字节替代。
- [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)：旧保护返回仅第一页，范围／reserve／mapped-view有约束；需要逐段记录恢复，不能统一写回首值。
- [Numbers (WMI)](https://learn.microsoft.com/en-us/windows/win32/wmisdk/numbers)及[IWbemClassObject::Put](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-put)：CIM数值与Automation表示不同，64位整数使用字符串表示；这里只核对表示，不建议向真实WMI provider写入配置。
- [Method runtime events](https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-method-events)及[CLR ETW Providers](https://learn.microsoft.com/en-us/dotnet/framework/performance/clr-etw-providers)：方法／代码范围与版本、runtime／rundown的区别；不把方法加载当调用或完整执行轨迹。

## 5. 收尾与下一步

本次已直接修正G01／G02的规范源和过时语句，其余G项已补到明确任务／owner／输入输出／失败判据。G03／G04／G05／G10仍存在必须源码实现和实测才能关闭的关键机制问题，不能称本次已解决。G11／G12为来源候选分支，不因列入目录就默认为首版必需或已获运行授权；G14的可选分析器必须先查现有真实入口和许可，未具备时如实不可用。

后续先按A0统一机器契约及目录，再将G03／04／05／10的正负控绑定到相应产品门禁；纯离线A0–A3仍可独立按实施授权推进。终止调试目标处置、步进依赖扩放两项默认未定；规则正文枚举／许可／字段／转换仍待完成。没有修改产品源码、工程、语言包、驱动CI或正式Release，没有运行样本、GUI、构建或R0，没有提交／推送。

关机前已保存首轮16项及静态检查；开机续查仅补充反向契约、上述真实页保护行为、Ex通知与WMI类型／所见边界。后续完成记录分别附设计位置、源码／构建、独立运行证据，不以本报告替代其中任何一项。

最终结构与链接检查结果保存在`.codex-build-logs/behavior-planning/action-analyze-planning-static-check.json`；它只验证文档及规划资料，不能作为本文机制通过证据。16项清单是本轮已确认的问题集合，不承诺穷尽任意软件／系统情形，也不将明确延期的比较／外部回滚／热重载重新当缺漏纳入实施。
