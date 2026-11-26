# ActionAnalyze 事件、身份与协议契约

日期：2026-11-24。状态：本轮补齐的首版实施建议，未实现、未冻结 ABI 数值、未通过产品测试。与[开工审查](ActionAnalyze完整开工审查与实施总表.md)、[通信施工](ActionAnalyze多通道通信与控制施工设计.md)、[CLI 设计](ActionAnalyze长程CLI会话与结构协议设计.md)共同使用。本文补齐此前“实现时再定”的字段、顺序和方法；用户已明确的边界优先。

## 1. 格式所有者与兼容

三端各自拥有业务模块、线程和活会话。共同的是可读写的数据规范、测试向量、字段目录和唯一驱动协议；不新增公共追踪 DLL、统一 runtime、宿主或跨端活会话 IPC。已有 `shared/evidence` 的无损值、身份与采集结果按真实语义复用，不把共享数据定义扩大成共享执行器。

`schemas/action_analyze/` 统一存放协议、项目、配置、事件、规则与证据的 Schema、目录及向量。首份停止组快照与正反例已进入 A0 草案，随 A0 单独发布。各端使用相同目录核对元数据。IOCTL 数值及固定布局在 `shared/driver/` 登记。[已发布的 A0 基础契约](../schemas/action_analyze/base-contract-v1.md)

各格式独立 `major/minor`：major 改变意义或必需字段；minor 只增可忽略的数据字段／可选能力。控制请求和计划默认封闭键集，未知操作、flag、目标条件拒绝；离线数据遇未知可选字段保留原字节，未知必需事件种类可浏览原记录、不得以旧语义执行。未来版本项目只读打开或明确拒绝，禁止自动降级覆盖。

版本协商报告本端、Agent、驱动、字段目录、规则 DSL 和存储版本。单一 version 数字不能代替逐能力查询。旧 Agent 仍适配旧监控入口；新追踪会话不能将旧 `HooksInstalled` 推断为新准入 Ready。

## 2. 基础类型与标识

| 类型 | 规范表示与约束 |
| --- | --- |
| 稳定 ID | 新 project/sample/controller/session/epoch/job/definition/analysis ID 使用随机 UUID，输出小写带连字符；载入时严格校验。短示例 ID 仅为说明 |
| 顺序 ID | sample 内 `eventOrdinal`、状态修订、配置修订使用 u64；JSON 为无前导零十进制字符串，0 合法。sample序号溢出前结束采样；本端可控来源序号溢出前换source epoch，不能对外部来源伪造epoch，绝不回绕复用 |
| 地址 | JSON `0x` 加固定 16 位小写十六进制；保存目标 pointerWidth=32/64，32 位上半部必须为零；不经 double |
| PID/TID | JSON 整数 uint32，仅是属性；不能作为可变更请求的唯一身份 |
| 整数 | 字段目录明确 i32/u32/i64/u64，禁止隐式符号或位宽转换；64 位 JSON 均用规范十进制字符串 |
| 时间 | 原始 FILETIME100ns／QPC ticks 为 u64 字符串；QPC 同存频率、boot 标识和时钟域；展示 UTC 用 RFC3339，不能用展示文本排序事实 |
| 范围 | `base,length` 且检查加法溢出，语义为半开区间；长度为 0 只表示空范围，不表示全部 |
| 字符串／字节 | JSON 严格 UTF-8；原 UTF-16／ANSI 字节另保留编码、长度、截断及 blob 引用；显示替换字符不替代原证据 |
| hash | SHA-256 小写 64 位十六进制，包含算法字段；CRC 仅检测损坏，不证明来源可信 |
| 值状态 | known/null/notCollected/unsupported/accessDenied/readFailed/truncated/decodeFailed/redacted；known 的零、空串、空数组有效，null 不是通配 |

`FieldValue={state,type,value?,reason?,rawRef?,capturedLength?,originalLength?}`；只有 known 可当完整值使用，truncated 可有部分 value，匹配必须按筛选器契约保留不确定性。容器通过字段目录描述，不逐字段在内存分配巨大 JSON 对象；JSON 是交换表示。

不可变项目文档`revisionId`／`snapshotId`采用UUID，项目`revisionNumber`为单项目递增u64；`expectedProjectRevision`比较精确revisionId及hash。本次运行的desired/effective/stateRevision和每个断点定义的修订号为各自作用域u64，不与文档UUID或存储字典ID混用。存储核心头的`...DictionaryId`只是无损引用编号，解引用后仍保留原UUID／修订及作用域。

### 2.1 规范序列化与hash

首版定义`aa-cjson-v1`，供三端共同黄金向量验证，规则如下：

- 先按schema解析成有类型值并拒绝重复键、非法UTF-8／孤立代理项、溢出、未知语义键；规范化不能把非法输入变合法。默认值只有schema明确规定时才补齐，未采／null／省略的不同意义保留。
- 对象键按其解码后UTF-8字节无符号词典序排序；数组保持顺序，只有schema声明集合的字段才按指定稳定键排序并拒重复。文本不trim、不折叠大小写、不做Unicode归一。
- 输出UTF-8无BOM／空白／尾换行。引号和反斜杠用`\"`／`\\`，U+0000–001F统一小写`\u00xx`，其它合法标量直接UTF-8；`/`不转义。同一字符串不同合法JSON转义必须得到同字节。
- JSON number仅用于schema规定的有界整数，十进制最短形式、负零归零；i64/u64／时钟／地址继续用规范字符串，禁止浮点number、指数或经double中转。API浮点原位是带类型的bit字符串。
- 文件原始hash为原字节SHA-256；语义hash为`SHA256(ASCII("KSAA") || 0x00 || ASCII(domain) || 0x00 || canonicalBytes)`。domain至少区分`plan-v1`、`ast-v1`、`query-v1`、`request-v1`；输出同时带profile/domain。规则包同时保留来源原hash、正文hash及typed AST语义hash，互不替代。

typed AST去除注释／空白／源码位置，保留节点类型、运算符、字段／函数目录ID、已解析有类型常量及子节点顺序；不交换AND顺序、不做代数重写来声称等价。语义hash一致只表示该profile的规范表示一致，不证明两个任意表达式逻辑等价。动态lookup／外部表均以冻结版本／hash引用。

同requestId比较同一已校验方法的`method/session/expected/params`规范值；requestId本身不纳入效果hash，客户端等待时限只有在方法定义为非副作用参数时才可剥离。同ID同hash返回原执行状态；同ID异hash返回idConflict，不再次执行。requestId为1–128个UTF-8字节的合法字符串，不含NUL／控制字符，不trim或归一；账本只对本存活controller保证去重，重启后旧ID不授权重放副作用。

## 3. 实例与区域版本

| 对象 | 强身份最少组成 | 缺失处理 |
| --- | --- | --- |
| 进程 | machine/boot、PID、创建时间，来源与校验时段 | 弱身份只浏览／候选关联，变更前绑定真实句柄及创建身份 |
| 线程 | 所属进程实例、TID、创建时间／可信原生序号 | 未知请求线程不以 ETW header 或回调当前 TID 补造 |
| 模块映射 | 进程实例、映射代次、base/size、装载／卸载区间、可得的文件身份 | 同名／相同基址不合并；映像文件 SHA/PDB 身份与映射身份分别保存 |
| 区域 | 进程实例、allocation/mapping 代次、base/size、关联 backing 标识 | VA 重用生成新区域；共享 backing 只有证据支持时建 alias 边 |
| 栈／帧／控制槽位 | stack实例／mapping代次、frame实例与生存时段、slot地址／用途／绑定修订 | 同一线程可切栈，同一地址可属于后续帧；没有可靠frame边界不编造局部缓冲区或返回槽位 |
| 内容版本 | regionId、版本号、捕获时段、范围、已得字节 hash、写入事实引用 | 未采完整字节时不称完整区域 hash；观察写入不等于每次内容变化都已观测 |
| 文件 | 卷实例＋fileId＋生命周期／USN（可得时），保留路径历史 | 路径只是名字；无法确定时不硬关联同名文件 |
| 句柄／socket | 进程实例、数值、创建／退休代次及来源 | 新代次与旧引用分离；缺创建证据标候选 |
| 连接 | 进程实例、协议、端点、观察代次／起止与可得原生身份 | 四元组重用、TCP API 无 PID 的执行竞态另报，不能称原子身份锁定 |
| 驱动／内核线程 | boot、映像装载代次与精确 PE/PDB，原生对象实例（可得时） | 任意地址落某模块不授予停止内核线程资格 |

引用对象另有 sample 内稳定 `objectId`，扩展字段保留身份强度与冲突证据。先创建候选对象后获得创建时间时，追加 identity-resolution 记录，保留 alias 与此前依据，不覆盖原事件的已知程度。

## 4. 规范事件

所有事实事件不可变；迟到富化、身份解析和分析结论各自产生新记录。全样本 ordinal 只保证本端接纳顺序；同时间戳、相邻 ordinal 或按时间排序不能证明跨源因果。

| 字段组 | 最少字段 |
| --- | --- |
| 记录身份 | recordVersion、projectId、sampleId、eventId（sampleId＋ordinal）、eventOrdinal |
| 来源 | sourceId/sourceKind、sourceEpoch、sourceSequence（含有效性）、adapterVersion、rawRef |
| 时间 | rawClock/domain/value/frequency、receivedQpc、UTC 锚点引用、估计误差／有效性 |
| 操作 | category、精确 eventType、operationId、phase=entry/return/submit/complete/observation、API/provider/syscall 描述引用 |
| 主体／客体 | actorProcess/actorThread、targetProcess/targetThread、observedOnThread、parent/causedBy 明确分开 |
| 参数与结果 | typed fields、输入／输出方向及采集阶段；resultKind、真实返回位、errorDomain/errorCode/errorValid、实际完成长度 |
| 实际配置 | captureRevision、逐来源 effectiveRevision、coverageSnapshotId、breakpointBindingId（适用时） |
| 完整性 | field availability、decode outcome、关联缺口、trusted/candidate 标记及其来源 |

每个原始包可解码零到多个规范事件。包到事件是显式一对多映射，不能将数量差直接当丢失。独立来源重复观察保存 `observesSameOperation` 候选关系，不按 API 名和时间去重原始证据。异步提交／完成用真实 operationId 与资源代次连接，不把 Cancel 请求当 Complete。

### 4.1 字段目录

首版目录包含 `event.*`、`source.*`、`time.*`、`actor.*`、`target.*`、`api.*`、`args.<declaredName>`、`result.*`、`memory.*`、`file.*`、`registry.*`、`network.*`、`coverage.*`、`relation.*`、`rule.*`、`control.*`，并补充 `exception.*`、`stack.*`、`controlFlow.*`、`mitigation.*`。每个 fieldId 登记类型、单位、可用 phase、来源／版本、长度上限、大小写和规范化方式；参数名以精确 API 定义为准，不从 detailText 逆解析。

headerPID/headerTID 与 actor/target 各保留；未知字段放 source 专有空间，不能因叫 PID 就赋予身份意义。Raw 槽位明确 ABI、位宽和捕获寄存器集合，不猜原型、浮点值、返回结果或指针所指内容。

### 4.2 派生资料

| 记录 | 必须保留 |
| --- | --- |
| relation | 起终对象与版本、有向关系类型、直接事实／候选／策略推断、依据 eventId、有效时段、分析版本 |
| behavior | ruleId/version/hash、analysisRunId、相关对象、命中窗口、依据引用、实际覆盖与缺字段状态 |
| enrichment | 被附加 ID、查询／计算时间、源版本、输入 hash、结果与状态；不得写回原事件 |
| coverage | 来源／字段／API／线程范围、配置修订、生效起止、known gaps、unknown tail、suppression 与原因 |
| control receipt | request/stop/admission、expected/actual 修订、阶段、逐项机制与错误、责任创建／释放结果 |
| snapshot | 捕获批次、对象／区域版本、每项起止、格式、长度、缺页、hash；跨进程不称同刻原子快照 |

来源归因和持续追踪分离：线程可保留“曾关联”，当前活动只按明确进入／返回／后续影响事实或标为策略推断；关联过不自动把未来全部行为归因样本。

## 5. 来源与能力矩阵

实施登记必须细到“端×机制×目标架构×精确系统／保护状态×阶段×字段×恢复能力”，状态为 unknown/unsupported/available/partial/failed/conflict。unknown 不作为 unsupported，available 也不代表已经验证。实际安装及当前 Ready 另列。

| 来源／动作 | 可规划职责 | 必须保留的缺口 |
| --- | --- | --- |
| 强类型 API | 调用参数、结果、受支持入口前闸门／子准入 | 898 定义不等于898安装，更不等于全部具备前闸门；先列精确 Hook 和参数矩阵 |
| Raw API | 已捕获入口槽、返回位置及 ABI | 无原型／返回值／正文，不能提供依赖完整参数的规则 |
| ETW | 进程／线程／映像／文件／注册表／网络／选定 provider 的异步观察 | provider/schema/build、启用权限、丢事件、已有对象 rundown 不等于刚发生 |
| R0 回调 | 精确回调允许的操作元数据与阶段 | Pre 通知不等于安全可长停；回调 requestor 与当前线程分开 |
| R3原生控制 | Windows真实调试事件、上下文／TF/DR／断点及用户态保护事务，唯一Wait/Continue所有者 | 不需KSword驱动或目标VEH；R3不调试驱动；NX在途owner死亡恢复已失败，不能公告无损恢复 |
| 普通 R0 控制 | 适用线程停止／上下文／TF/DR、页保护事务的真实能力 | 现有单primary、恢复丢账及版本门禁先修，仅约束R0链，不阻塞R3；任意内核线程不列默认可停 |
| 页面执行探针 | 区域执行命中与重设防 | 完整线程集合／新线程门控、共页、共享别名、自修改均为开通门槛 |
| 调查查询 | 已停止现场、后查模块／签名／栈／内存 | 查询时间与事件时事实分开；不创建页面；不能承诺目标已停就全组一致 |
| TCP 断连 | 目标 IPv4 TCP 已有连接的逐项操作／回读 | 提权、317、执行竞态、重连；IPv6/UDP 不冒充覆盖 |
| 栈／控制流发现 | 原始异常／保护信号、有限栈现场、指定槽位watch及实际转移证据 | 异常码不单独证明攻击；本地CPU越界写可无远程API／新RX页。来源、可信边界与写入后时序见[专项设计](ActionAnalyze栈破坏与控制流劫持发现设计.md) |
| COM／WMI方法 | 精确接口／方法、查询／类别／属性、实际返回与调用现场 | 通用API表不等于COM覆盖；命名空间、对象类别、同步／异步、逐架构绑定分开。参考[历史包核查](ActionAnalyze对ActionScope功能与实现核查.md)，方法存在／配置触发／日志入队不得混为一项 |

远程写、远程线程、APC、上下文转移、映射／解除映射／保护变化、句柄复制、子进程建立逐入口登记：Win32 包装、native API、直接 syscall、内核代写各一行。未覆盖路径产生 coverage gap，不因为监测同类 Win32 包装就宣称全路径可拦。共享映射普通 CPU store 的写入者来源不能靠映射建立事件补齐。

### 5.1 首批必须登记的入口族

下表是需要施工／验证的目录，不是现有支持表。每行再按实际导出／版本／架构展开，入口返回／异步完成分记录；真实call-before拦截状态默认unknown，读源码与实测后逐项填充。

| 入口族 | 最少入口／来源候选 | 事实与必要字段／负控 |
| --- | --- | --- |
| 进程建立 | CreateProcess A/W、AsUser、WithToken、WithLogon、NtCreateUserProcess | 原始flags／父身份、实际子PID/创建时间、返回结果、初始线程；原CREATE_SUSPENDED不能解除，后置日志不能当首条执行前已纳入 |
| 远程读写 | WriteProcessMemory、NtWriteVirtualMemory、受支持写接口 | actor/target实例、handle代次、VA／请求与实际写长、成功／partial、字节快照；失败不造写入边，kernel代写缺口另记 |
| 分配／释放 | VirtualAlloc/Ex、NtAllocateVirtualMemory、Free/Ex、NtFreeVirtualMemory | 进程、真实allocation范围／状态／映射代次；reserve/commit/decommit/release区分 |
| 改保护 | VirtualProtect/Ex、NtProtectVirtualMemory | 原始请求／页舍入后范围、旧／新保护、结果；跨页异保护、外部保护变更与恢复冲突 |
| 节与映射 | CreateFileMapping、OpenFileMapping、MapViewOfFile/Ex、NtCreate/OpenSection、NtMap/UnmapViewOfSection | backing/section/handle/offset／视图身份、share/COW与实际结果；同section不证明同内容，更不提供普通store来源 |
| 远程线程 | CreateRemoteThread/Ex、NtCreateThreadEx、适用RtlCreateUserThread | actor/target、实际新线程／创建身份、入口／参数／flags；线程建立≠执行到入口 |
| APC | QueueUserAPC、NtQueueApcThread/Ex等实际版本 | 发起者、目标thread实例、routine/args、入队结果；入队／投递／执行分开，缺投递证据不能确认执行 |
| 线程上下文 | Get/SetThreadContext、Wow64Get/Set、NtGet/SetContextThread | 目标架构、有效context flags、请求与实际写入字段／结果；context修改≠目标执行 |
| 线程暂停／恢复 | Suspend/ResumeThread、NtSuspend/ResumeThread及实际进程级接口 | actor/target、来源、前计数／结果（可得时）；外部变化只观察，不授予本会话责任 |
| 句柄生命周期 | OpenProcess/Thread、DuplicateHandle、NtDuplicateObject、CloseHandle等 | owner／目标实例、访问掩码、数值与代次、成功／关闭；不是每个看见的裸handle都能回溯对象 |
| 映像／加载 | LoadLibrary/Ex、LdrLoadDll、ETW／R0 image、卸载 | 实际module mapping／路径与精确文件身份、事件阶段；rundown≠新装载，模块字符串不替代identity |
| 文件 | Create/Open/Read/Write、异步submit/complete/cancel、rename/delete及minifilter元数据 | fileId/handle generation、路径namespace／版本、范围与实际字节、结果；IO状态与用户请求分开 |
| 注册表 | Open/Create/Query/Set/Delete及R0 Pre/Post | root/HKEY/子路径、SID/WOW64视图、值名／类型／真实数据长度、输出／结果；旧摘要缺data不补造 |
| DNS／socket／HTTP | DNS query、socket/connect/accept/send/recv、IOCP/APC完成、WinHTTP/WinINet实际接口 | 请求／socket代次、端点、方向与真实完成、DNS question/answers有效性；长度不等于正文 |
| 进程／线程退出 | API与ETW/R0生命周期、保留原生对象退出状态 | 真实instance、退出码／时段、未知尾部；断管道不单独等于退出 |
| 其它语义源 | PowerShell分片／ScriptBlockId、WMI consumer/filter/binding、服务／任务相关真实事件 | provider/schema/权限与字段；全类别目录保留，不由字符串猜对象或执行成功 |
| 中介执行来源候选 | 服务／计划任务／WMI／COM／RPC的请求、对象配置和实际执行来源 | 原始actor与executor分开；实际提供的Activity/RelatedActivity／operation才可关联，无键保留候选；按[缺口G11](ActionAnalyze规划缺口复查与补齐任务.md)逐项建目录，不默认追踪全部系统broker |
| 托管代码来源候选 | CLR runtime／rundown的精确provider/event/version，适用method／module／native范围及ReJITID | 方法加载不是调用，rundown不是新执行；按[缺口G12](ActionAnalyze规划缺口复查与补齐任务.md)保留代码版本，async来源不暗改同线程规则作用域 |

WMI方法级来源另列IWbemServices::ExecQuery/CreateInstanceEnum及适用IWbemClassObject::Get，保存接口／命名空间／对象与属性、原始返回、类型／长度、来源和实际阶段；单纯属性名不能确定CPU／BIOS等对象。分析器自身初始化查询标为工具来源。该目录是规划候选，未实现COM Hook或将环境伪装纳入默认采集。若后续显式授权主动干预，原返回、干预动作／配置、替代值与目标最终所见分记录，格式化／入队／接收／证据提交亦分别报告。

用户现已要求反反虚拟机的深入行动方案，具体见[环境实验方案](ActionAnalyze反反虚拟机与环境实验行动方案.md)。A0后续补EnvironmentObservation／InterventionPlan／InterventionAttempt／TargetSeenEvidence四类schema与profile修订引用，原始事实、目标所见及真实采证时钟不能互相覆盖；目前只定记录职责，没有生成这些产品schema或运行干预。

API父包装与native调用可能同一操作两次观察，保存wrapper关系或operation绑定，缺唯一证据不强去重；direct syscall绕过包装的缺口明示。ETW/TI可用性、受保护provider权限和R0拦截合法上下文单独验证，不凭存在名字把它列为同步来源。

首版主控制端建议 AMD64；x86/WOW64 API 来源按已有双 Agent 可独立接入，但逐来源、上下文布局和控制恢复分开验收；ARM64、ARM64EC、跨架构内核上下文不预告支持。离线阅读允许任何记录架构。Windows build 上限不一刀切；可选字段按能力降级，必要控制按精确 ABI／系统身份准入。不得自动关闭 HVCI、Secure Boot 或更改测试签名。

## 6. 请求方法补全

所有变更先冻结请求对象，经过同一 Coordinator 仲裁。`expected` 缺少必需字段即拒绝；部分多选逐项结果，目标集合不随 UI 选择改变。下表补全 CLI 原方法族，名称仍属实施提案，实际公开方法由同源 catalog/help/schema 决定。

| 方法族 | 关键输入／前提 | 结果 |
| --- | --- | --- |
| project.create/open/query/save | 路径／projectId、expectedProjectRevision、草稿 hash | 只管理资料，锁／只读状态和已提交修订 |
| project.close | projectId、expectedProjectRevision及明确草稿处理 | 释放资料引用；仍有活session／writer引用则busy，不隐式停采或丢草稿 |
| sample.list/query | project/sample、cursor/filter/watermark | 历史列表／当前归档状态，绝不启动采集 |
| sample.delete | 强project/sample、expectedProjectRevision、明确删除意图 | 按存储契约提交墓碑／处理lease，活采样及未决责任拒删；不是清空视图 |
| project.package.import/export | 包／输出路径、只读快照／水位、范围／完整性策略、预算 | 独立job、实际自包含范围／partial／hash；不把证据表CSV当项目搬运包 |
| plan.load/validate | 有界正文／文件、schema、依赖能力 | draftId/hash、错误位置、缺字段与计划差异 |
| session.open | project、savedRevision/draftHash、target definitions、显式后端选择、budgets、结束／失联策略 | 新sample/session/epoch，记录所选／实际后端与能力；R3流程不依赖驱动，逐阶段准入不提前Ready |
| target.add/remove/list | 强实例或新绑定定义、expected state/config、remove 时 holdPolicy | 新追踪范围及实际生效；remove 不静默恢复停点 |
| capture.validate/apply | capture draft、expectedDesiredRevision | 依赖闭包、逐来源 effectiveRevision 和不可恢复的覆盖变化 |
| view.validate/set/query | filter、viewId、sample、generation | 显示条件／分页，不改变来源 |
| breakpoint.validate/apply/list | definition revision、trigger/phase/scope/predicate/actions、expectedDesiredRevision | 校验／实际 binding，保存项目另走 save |
| rule.validate/prepare | rule package hash、enabled IDs、analysis options | 编译／能力报告，供下一采样或独立analysisRun使用；首版不热替换活采样规则包 |
| analysis.start/query/cancel | sample、input watermark、规则快照、范围、预算 | 独立离线／追加分析，禁止触发原控制副作用 |
| control.pause | strong targetIds、scope、expected stateRevision | 接纳返回请求票据。后续查询取冻结范围、逐项 stopId／实际机制和停止组状态 |
| control.continue | stop/group token、选定责任、expected stateRevision | 逐项释放与回读，不 Resume 到零 |
| control.step | stopId、threadInstance、mode=into/over/out、granularity默认instruction，sourceLine仅匹配PDB／后端明确支持时允许、budget、dependencyPolicy | 起止现场、实际停止原因、临时资源及未决项；指令步进不冒充源码语句步进 |
| control.query/recover | 原 owner/session/epoch/stop/token；recover 精确责任 | 权威当前状态／重试清理，不授予新会话接管权 |
| tracking.disable/enable | 当前对象、定义范围、expected revision、有停点时 holdPolicy | 逐项退订／重新 Ready、缺口及旧责任；对应断链／链条 |
| dump.start | 强对象／regionVersion、format、范围、预算；使用停点须 stopId | jobId，实际文件／sidecar／缺页和 hash；对应相机 |
| network.disconnect | 强进程集合、连接快照／范围、expected identity | 每连接 requested/applied/observed/failed/unsupported/ended/unknown，重连另记 |
| investigation.start | preset revision、scope、stop/对象身份、预算 | 各子任务独立状态，调查完成不继续目标 |
| job.query/cancel | jobId 和所有者代次 | 取消申请、终态、临时资源；取消不删除部分证据 |
| evidence.query/export | kind=event/behavior/relation/object/coverage/snapshot的封闭判别联合；IDs或有水位查询、格式／完整性策略 | 每kind独立字段／筛选目录，固定快照分页／异步导出、实际范围与partial；不支持的kind明确unsupported |
| evidence.blob.read | 本sample已登记blob ID／固定hash、u64 offset、length；单次最多32 KiB原字节并受输出帧限制 | base64分块及原长度／完整性、实际offset／nextOffset／hasMore；不读任意文件，不回传完整dump；越界拒绝，offset等于末尾可返回合法空块 |
| subscription.set | message kinds、view filter、rate | 只调整 stdout 事件投影；控制响应不被筛掉 |
| request.query/cancel | 原 requestId | 原执行状态／提交前取消，不用新 ID 重发副作用 |
| session.deadline.set/clear | session 与 deadline revision | 绝对控制器单调时限及实际策略，不等于单请求等待时限 |
| session.stop/close | stopPolicy、expected stateRevision、收尾预算 | 停采／保留所有者／释放自有责任与归档分别报告 |
| controller.shutdown | 无活会话或可执行结束策略 | summary 与退出码；有未决责任不假报 clean |

本轮不增外部操作回滚、样本热重载、跨采样比较或跨端接管方法。方法引入时同步 `KswordCLI` 内置 help 和 `docs/CLI使用文档.md`；文档提案不是可执行命令。

Agent 同步命中由已绑定原生站点提交到目标外所有者，同样进入本端控制账本。命中线程持有状态、冻结集合停止结果、附带暂停、未来线程门控及区域屏障分别取证。[同步全局断点契约](ActionAnalyze同步全局断点与性能复查.md)

查询判别联合、项目关闭／删除／搬运和blob分块补自[缺口G15](ActionAnalyze规划缺口复查与补齐任务.md)，仍由A0 catalog冻结精确参数及错误，不注册第二套同义公开入口。中介执行、托管代码及环境实验均按独立能力准入，不由表中出现名字自动成为首版完整支持。

## 7. 运输与 CLI 初始边界

以下是编码／夹具用初始限制，公开前通过产品压力测试调整并写入 capabilities；不是已批准性能承诺。

| 项目 | 初始提案 |
| --- | --- |
| CLI JSONL | 单行JSON正文最大1 MiB（不含终止CRLF/LF），最大深度32、单对象128键、数组4096项；严格UTF-8且输入／输出均无BOM；允许 CRLF/LF；文档文件导入可另接受一个开头BOM |
| 输入错误 | 重复键、非法 UTF-8／类型／闭集键拒绝；超过未换行上限进入 protocol-failed 后停止输入并按失联策略收尾；不无限等后续换行 |
| 输出帧 | 目标64 KiB，硬上限256 KiB；大结果分页／job／blob，不能塞 dump/Base64 全文 |
| 在途请求 | 64 普通＋16 生命周期／查询保留；控制已有责任另预留，不由此队列拒绝精确恢复 |
| 去重 | 已接纳变更累计100000个ID、32 MiB identity账本先到限者；未决不淘汰，满后拒绝新普通变更但保留查询／恢复／收尾 |
| 队列 | 结果／状态4 MiB、普通订阅8 MiB、诊断1 MiB分别限额；结果满触发交付故障与关闭策略，不静默扔掉 completed |
| 单查询 | 默认500条、最大2000条，正文受输出帧限制，超长字段引用／分段；游标含 sample、queryHash、排序、watermark 与 indexGeneration |
| 取消与重复 | 同requestId规范参数 hash相同则查询原状态；冲突报request-id-conflict；查询原结果永不重复变更 |
| Agent 控制帧 | 建议固定64字节头＋最大256 KiB载荷；显式序列化 little-endian，不直接 memcpy C++结构；布局与对齐先做32/64位静态断言再冻结 |

Agent 新控制帧头建议：magic[8]、major/minor u16、headerBytes u16、kind u16、flags u32、payloadBytes u32、connectionEpoch[16]、messageSequence u64、requestKey[16]，合计64字节。身份／配置／stop前提在有类型载荷中，非适用 requestKey 全零；未知 flags 拒绝。运输 requestKey 对应控制器账本，不把可变长 CLI requestId 硬截成16字节。挑战与真正 peer PID/创建身份同时核对；帧 hash 不是鉴权。

stdout 单写者按序分配 streamSequence；请求结果、state、gap、summary 都不能被普通事件过滤。bootstrap 诊断不混 stdout。旧 `_O_U8TEXT` 和宽流需隔离，实际 writer 所有权改造列回归。分页超帧返回有效截页与 nextCursor，不产生被截断的非法 JSON。

## 8. 顺序、水位与可重复分析

单来源使用 sourceEpoch＋sourceSequence，关联 API entry/return 用 operationId；来源不提供 sequence 时明确 absent，不由收包序号假造源顺序。时钟校准保留多锚点，系统时间跳变不改变原始 QPC。休眠／恢复、ETW 重启和 Agent 重连产生状态记录，必要时换 epoch。

实时分析建议2秒乱序窗口、最大65536事件／32 MiB；空闲来源不凭“等够时间”推进证据水位。规则区分同源强顺序、显式操作因果、仅可比较时钟的候选顺序；跨源不确定时不产生严格因果命中。迟到超窗仍归档，标 late，后续新 analysisRun 可重算；原实时动作不倒放。

离线／历史查询冻结已提交水位，活跃尾部另用易失水位明确标记。分析结果记录输入范围、规则与适配器 hash、字段目录、预算、乱序／缺口策略、实际结束状态；重算产生新版本，不修改原始事件。离线回放只能输出“若当时”的候选命中和证据，不能调用 pause、dump-live、网络动作。

## 9. 验收与尚未消除的风险

必须产出三端同一黄金数据的读写／查询一致性；JSON数值／Unicode／未知字段正反例；32/64布局及坏包；源header/actor/target分离；PID/TID/VA/句柄复用；entry/return跨配置；异步重复与取消；时钟跳变／丢包／乱序；分页稳定、重复ID和已提交未知结果。

基础字段、Stored 布局与离线方法子集已有机器契约和静态向量。真实来源覆盖、新线程屏障、页内推进、所有者死亡、精确 R0 ABI 与性能仍各有验收项。[A0 基础契约](../schemas/action_analyze/base-contract-v1.md) · [A0 方法契约](../schemas/action_analyze/method-contract-v1.md) · [验收范围与运行环境](ActionAnalyze工程开工基线.md#验收范围与运行环境)
