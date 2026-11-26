# ActionAnalyze 反反虚拟机与环境实验行动方案

日期：2026-11-24。状态：用户明确要求深入研究并给出行动方案；本轮落实研究／施工输入，不开始产品实现，不执行恶意样本、第三方包、注入或R0。这里的“反反虚拟机”指在授权分析目标中识别环境探测、解释其对执行路径的影响，并以可审计、限定范围的环境实验验证能否继续观察行为。沿用非虚拟化主路线，不新建hypervisor、公共追踪DLL、TraceHost或统一runtime。

关联：[主规划](恶意行为单点追踪与调试能力规划.md)、[施工任务](ActionAnalyze施工任务与契约落点.md)、[规则来源](ActionAnalyze规则来源与转换施工清单.md)、[逐路径执行验收](ActionAnalyze执行覆盖与逐路径验收.md)、[Action Scope静态研究](ActionAnalyze对ActionScope功能与实现核查.md)。本文将原“环境干预候选”推进到具体任务／实验／判据，不把研究方案直接变成默认启用的产品能力。

后续[缺口复查G03–G10](ActionAnalyze规划缺口复查与补齐任务.md)补充本方案依赖的线程门控、普通store发现、异常继续、TF／DR争用、类型快照和Ready失效契约。RAV4有限指令站点不得绕过统一资源预约，未知异常不得为实验吞掉；WMI／注册表替代也必须逐入口验证重入、错误状态和输入输出竞态。

E01–E16 已进入工程总表。RAV0/1 从入口目录、字段核对和被动规范化开始，RAV2 可并行准备 profile 校验，主动实验依各自 X 用例逐项放行。[工程开工基线](ActionAnalyze工程开工基线.md)

## 1. 需要交付的实际结果

每个探测面必须交付六件事：**探测入口及旁路、真实字段、干预机制及作用范围、跨接口一致性约束、原始／替代／最终所见证据、正负控与退出条件**。找不到可行机制时，交付可复核限制与替代工作流，不再只写“以后做R0隐藏”。

结果分四级：`observed`需要实际查询／执行证据，静态字符串或指令位置另标candidate；`substituted`是工具确实改变了本次返回／局部现场；`seen`是目标独立见到了替代值；`path-observed`是在对照条件下看到了预先定义的后续执行。Hook安装成功只属于准备状态，不等于后续级别。回调内读回输出只证明交付边界值，不能单独证明目标读取；缺独立证据时保留seen-unknown。未观测到真实条件分支时，只报告“返回值变化且后续轨迹不同”，不能称已证明该条件决定分支。

最小产品流程建议为“发现探测 → 查看证据及覆盖缺口 → 选一项明确实验 → 准备一致性闭包 → 新采样显式执行 → 查看原始与最终所见及后续轨迹”。被动采样永不自动改变目标。默认不开强制跳分支、全机伪装、删服务／文件、改真实SMBIOS、全局加速时间或模拟鼠标输入；这些不能被一个总开关悄悄带入。

## 2. 已核对的现有基础与缺口

| 真实落点 | 能复用什么 | 本任务不能据此宣称什么 |
| --- | --- | --- |
| `APIMonitor_x64/api_monitor_definitions.json`及双架构Agent | 898项定义中实际可检索到DeviceIoControl／NtDeviceIoControlFile、NtQueryInformationProcess、CoCreateInstance/Ex、GetAdaptersAddresses、GetCursorPos、GetLastInputInfo等 | 定义不证明所需输出结构已复制，也不证明Hook实际安装；本轮未在该定义表搜到GetSystemFirmwareTable、GetSystemInfo、GlobalMemoryStatusEx、QPC／GetTickCount等具名项，Raw发现也须实际核对 |
| `APIMonitor_x64/core/MonitorPipe.*`与`shared/ApiMonitorCoverage.h`等 | 原事件、覆盖、配置及生命周期经验 | 现在没有统一的环境替代事务／最终所见证明；新字段不能挤进320 wchar摘要后再猜类型 |
| 普通`kernel_noattach`与目标外控制协调方案 | 明确停点／上下文／DR/TF候选、逐项恢复工作包 | 普通R0不会自动拦截所有用户态CPUID/RDTSC；全线程门控和恢复仍需A4/A7真实验证 |
| `MonitorDock/WmiEventArchive.h`及既有WMI监控 | 已有WMI事件字段展示与临时归档经验 | 不是目标IWbemClassObject::Get结果捕获／替代器；Qt QDataStream临时格式不是三端项目共同格式 |
| Action Scope WMI／注册表／鼠标静态研究 | 方法级COM观察入口与干预问题的具体反例 | x64 Get After返回0会覆盖HRESULT、VARIANT类型／所有权及完整POINT有缺口、Get文本未发送；不能复制其插件或把它算可靠方案 |
| 固定capa／CAPE／Sigma／本地候选 | 可提取反VM／反沙箱线索条件、正常软件排除和所需字段 | 规则名称不证明目标已发现虚拟机；许可与逐规则输入矩阵继续独立准入 |

仓库共享记忆已记录一次HVM／Hyper-V Gen2研究：参考TSC页可被用户态直接读、跨线程竞速不能靠单线程偏置消除，既有N=30计时结果也没有消掉指纹。**本方案不重走TSC_OFFSETTING补偿路线**，不将该旧HVM研究数字当本次非虚拟化实验结果。

## 3. 探测面与行动矩阵

下面每一行都是要落实的研究任务。`API局部替代`表示未来显式环境实验中只作用于精确目标／调用、保持原返回契约的候选，不表示现有Agent已可做；`观察优先`表示先完成识别及字段，没有闭合机制前不开替代。

| 编号／探测面 | 要记录的真实输入输出 | 干预候选与工程动作 | 必测旁路／一致性及退出条件 |
| --- | --- | --- | --- |
| E01 WMI硬件属性 | namespace／class／objectPath／property、CIMTYPE／VARIANT tag、原HRESULT及实际值 | 先接同步ExecQuery／枚举／Get的对象身份；只对已识别对象的已成功返回做类型正确的局部替代；数组／异步sink独立能力 | 同名属性不同类不能改；GetNames／GetObjectText／IWbemObjectAccess等不覆盖则显式缺口；失败返回及未命中不变 |
| E02 注册表VM痕迹 | hive／view／key／value、句柄代次、query／enum阶段、类型／容量／实际长度／原状态 | 补RegOpen→句柄、Query输出正文；先替代明确已成功value，不全局删除键；存在性隐藏需另做open/query/enum一致事务 | Nt直接调用、WOW64两视图、枚举／通知／后续open交叉验证；未实现闭包时不宣称键不存在 |
| E03 文件、目录及设备痕迹 | 规范路径、对象／句柄、打开／枚举／属性、结果和目录游标 | 观察优先；若研究目标内只读隐藏，须先定义open／enum／attributes一致视图及错误码，不改真实磁盘 | 直接Nt、reparse、短名、大小写、枚举游标／重试；不能只让FindFirst漏项却CreateFile仍成功并称完整隐藏 |
| E04 进程、服务及模块痕迹 | 枚举来源、进程创建身份、SCM查询对象、返回项及原状态 | 观察优先；按接口族审查一致枚举候选，不终止真实监控进程／删服务 | Toolhelp／PSAPI／NtQuerySystemInformation／WMI／SCM及直接打开交叉检查；没全覆盖标partial，不能影响SSH管理对象 |
| E05 SMBIOS／ACPI／固件 | provider/table ID、枚举列表、两阶段容量／长度、完整有界原字节 | `FirmwareTableAdapter`候选；从同一冻结profile生成合法结构与字符串索引，只替代目标API结果，不写物理固件 | WMI原始SMBIOS／属性与firmware一致；size probe、buffer too small、未知表／双NUL／校验结构负控；未知结构不盲改字符串 |
| E06 CPU／内存／磁盘规模 | API及WMI类型、processor group／affinity、内存物理／可用量、volume／disk身份／单位 | 先记录各入口，建立真实约束；实验优先选择满足最低条件的授权环境，局部报告替代只做明确profile | cores/logical/groups、available≤total、free≤size、磁盘映射一致；报告变大不等于实际可分配／调度能力，不伪造ISA支持 |
| E07 磁盘设备标识／IOCTL | 精确control code、输入输出长度、实际完成／状态、对象身份及结构偏移 | 白名单只读查询解码，例如存储属性类；profile字段经有界结构writer生成，不在通用DeviceIoControl盲写 | 异步IO_STATUS_BLOCK、长度探测、offset／字符串终止、不同device class；未知IOCTL原样透传并报覆盖缺口 |
| E08 网卡／MAC／网络配置 | adapter LUID／GUID及生命周期、地址family／长度、DNS等原值 | 先观察；实验只改变明确报告字段且满足关联约束，不改真实网卡、路由、防火墙或管理连接 | IP Helper／WMI／注册表／实际路由不一致要暴露；隐藏唯一网卡不得让真实网络事实看似全覆盖 |
| E09 内联CPUID及hypervisor线索 | 已执行位置／字节版本、leaf/subleaf、EAX/EBX/ECX/EDX、调用线程 | 普通API Hook不覆盖；先对自有已知指令站点研究精确DR或受控单步现场观察，有限站点局部替代另作显式实验 | 动态生成代码／多站点／新线程／自校验／拓扑leaf交叉检验；实体机VBS／Hyper-V也是负控，hypervisor位不直接证明运行于来宾；超4个DR槽不假装无限，CPU能力位不能任意开 |
| E10 RDTSC/RDTSCP／共享时钟页 | 实际指令位置、前后计数及频率／TSC_AUX、线程／CPU、外部真实耗时 | 观察与开销归因优先；有限站点实验可验证目标所见，但不构造全机统一假时间；共享页读取单列来源缺口 | QPC／Tick／FILETIME／共享页／双线程计数竞赛／外部时钟；单线程阈值过关不算计时隐藏成功，结构性无解则关闭该能力 |
| E11 Sleep／等待及延迟执行 | 原相对／绝对期限、alertable、wait对象、真正结果、原始真实耗时 | 先测延迟与真实等待；只在自有夹具研究简单无对象delay缩短，区分时间补偿；对象等待不一律立即成功 | NtDelayExecution、WaitFor*、线程池timer、APC／取消／超时、服务器时间；不把对象未signaled改成成功，调试停顿不从证据时钟抹掉 |
| E12 鼠标／最后输入／会话活跃 | POINT完整两坐标、success、屏幕／DPI／virtual desktop、dwTime与计数回绕 | 先观察；目标API结果的确定性profile候选，默认不移动真实鼠标／发系统输入 | GetCursorPos／GetLastInputInfo／Raw Input等不等价；完整8字节POINT、失败输出、静态恒值／不可能轨迹负控 |
| E13 用户痕迹／语言／路径／运行历史 | OS版本、用户／主机、locale、时区、文件路径和可验证历史来源 | 先选合法自有测试资料及明确workspace；不为逼出行为捏造真实凭据／企业身份；局部字段替代显式标synthetic | GetUserName／环境变量／registry／WMI／路径交叉；不保证所有历史痕迹可合成，真实机无历史也可能被探测 |
| E14 反调试／监控痕迹 | API结果／PEB直接读候选、DR/TF状态、异常路径、Hook入口字节 | 观察与低扰动采集优先；有限返回替代须单列实验；不把反调试一并宣传成“反VM全解决” | 直接PEB读取、自校验、线程隐藏／异常消费、外部调试器冲突；当前NX/单步本身会扰动时序及标志 |
| E15 网络可用性／远端判定 | 实际DNS／连接／TLS等已有来源、目标／端点、失败原因、响应原字节 | 默认观察；自有实验用本地明确端点回答已知协议，记录为模拟服务；不接未知C2或全机透明代理 | 证书固定、服务器时间、外部环境判断无法由本地字符串替代；离线缺网络不当VM证据，非目标连接保持 |
| E16 多信号评分／探测后退出 | 同线程／同对象的原事件、可观测分支或已知夹具阶段、结束原因 | 规则保留各探测证据，按有界窗口关联；先单变量实验，再做一致性组实验，不自动跳过条件分支 | 正常资产管理／安装器负控；一次不退出不等成功，随机／网络／锁依赖等混杂因素必须记；来源不全不称确认因果 |

“找不到API日志”不等于没有探测。CPUID、RDTSC、PEB／共享页读取、直接syscall与内存里的自校验可能没有现有包装事件；静态反汇编发现指令只叫候选位置，执行确认仍需要可信现场。脏页探针可在已设防区域进入时提供调查起点，但不能自动记录所有正常模块内的探测指令。

## 4. 一致环境profile与提交条件

profile不是一袋独立替换字符串，最少包含：profileId／revision／hash、适用目标与架构、字段原类型／单位、候选替代来源、接口映射、约束／不覆盖项、必需adapter集合、资源预算及结束策略。真实基线保存在sample环境证据，synthetic值在独立干预记录，永不改写主机真实信息页。

| 一致性组 | 必须一并审查的关系 | prepare拒绝条件 |
| --- | --- | --- |
| 主板／BIOS／系统 | WMI ComputerSystem／BIOS／BaseBoard，RSMB字符串及raw结构 | 同class属性身份不明、长度／类型不合法、只改Name却宣称全硬件一致 |
| CPU与规模 | WMI cores/logical、系统API／group／affinity、CPUID拓扑与真实可用ISA | 拓扑自相矛盾、夸大ISA导致真实非法指令、以报告容量替代真实资源能力 |
| 存储 | disk／volume映射、标识、size/free、WMI／IOCTL／firmware相关值 | 单位错、free>size、结构offset越界、异步完成无支持 |
| 时钟与活动 | 单调／UTC／uptime／睡眠、用户输入时刻、真实外部耗时 | 回退／无整数范围检查、混同QPC频率与CPU频率、将真实采证时钟也改掉 |
| 资源存在性 | open／query／enumerate／属性／对象生命周期 | 只截一条入口却要求“不可见”保证，枚举游标／错误路径不完整 |

prepare生成逐接口支持和冲突报告；required缺失拒绝应用，显式选partial时列清范围及其余真实值。新sample冻结profile与required closure，运行中不热替换；未读到某字段时不能拿替代值填成“采集成功”。不引入公共persona服务，三端按同资料格式在本端准备。

## 5. 原始／干预／最终所见的记录与恢复

拟新增`EnvironmentObservation`、`InterventionPlan`、`InterventionAttempt`、`TargetSeenEvidence`四类记录，正式schema归A0，不在本轮生成产品schema。记录关联sample／operation／source／强实例、API或COM对象／指令站点、阶段、原始类型／返回码／字节、替代字段／字节、最终回读或独立目标证据、profileHash、工具来源与覆盖缺口。

原调用成功且输出有效时才允许默认的value substitution；未命中profile保留原返回位、LastError、缓冲区和类型，不能像历史Action Scope路径无条件把HRESULT清0。失败转成功属于另一个完整响应模拟能力，必须构造合法输出、类型、长度与所有权；首个切片不实现这一能力。

WMI变更必须正确处理VariantClear／VariantCopy、BSTR与SAFEARRAY所有权、CIMTYPE与VT_NULL/VT_EMPTY、COM apartment及对象生命周期，不能写指向临时字符串的payload。固件与IOCTL使用两阶段长度语义及有界writer；鼠标写完整POINT；未知结构不改。原输出的复制和替代提交先预留所需有界证据／控制容量，必要证据无法保留时不开始该次替代，不等待慢盘／UI。

CIMTYPE与VARIANT.vt分别保存：例如WMI的CIM_UINT64可由VT_BSTR表示，CIM_UINT32可由VT_I4承载，不能因字段概念是整数就硬写VT_UI8。原始表示与解释后有界数值分开；不支持的class/property／类型组合只观察、不替代。具体依据和负控见[缺口复查§3.3](ActionAnalyze规划缺口复查与补齐任务.md#33-g09ravwmi类型与目标所见的最后一跳)。

挂钩、局部断点、TF、页保护及目标内替代资源仍归本会话责任账，撤销先阻止新替代、等已进入回调在安全点排空，再按真实引擎能力退役；不能为“卸载干净”释放仍被调用的trampoline。已返回给目标的替代值不能撤回，后续目标副作用也不承诺回滚。禁用只停止未来替代，保留干预历史；这与延期的“外部操作回滚”无冲突。

R3 与普通 R0 由采样显式选择。两条链各自由目标外控制者持有其恢复责任。`applied` 以实际副作用为准，恢复能力以实测为准。目标独立所见及证据缺失分别使用 `seen-unknown`／`evidence-gap`。[双后端设计](ActionAnalyze双后端独立全流程设计.md)

## 6. 分阶段任务与具体文件职责

下表均为待实施任务。本端根目录仍为Q/W/C的`ActionAnalyze/`，模块放`Environment/`子目录；Agent只扩展现有双架构采集项目，不新建公共追踪DLL。驱动协议只在`shared/driver/`、Qt设备访问只经ArkDriverClient、dispatch只注册handler。普通`.cpp/.h`按职责拆分、中文说明输入输出和变量用途、不堆`.inc`，同步工程／filters。

| 任务／前置 | 文件／owner与独立产物 | 具体动作及完成判据 |
| --- | --- | --- |
| RAV0.1 全入口目录；本方案 | 开发期`environment-entry-catalog.jsonl` | E01–E16逐API／方法／指令族展开到module/export或interface/method、双架构、输入输出、阶段、原native替代路径及旁路；每行附源码／官方依据，不留笼统“WMI支持” |
| RAV0.2 字段缺口；A0/A5 | Q/W/C:`EnvironmentObservation.*`与逐端字段矩阵 | 先核现有898及Raw实际字段，所需输出结构定点扩展；每字段available/unknown/needs-capture有证据；不按定义数算支持 |
| RAV1.1 被动规范化；RAV0 | Q/W/C:`EnvironmentProbeClassifier.*`、`EnvironmentEvidenceFeed.*` | 从真实事件形成探测尝试／成功输出／候选指令分层；输出原事件引用，正常管理／安装器不默认恶意 |
| RAV1.2 良性基线；RAV1.1 | 计划固定工程`tools/anti_analysis_validation/AntiAnalysisValidation.vcxproj`及正常`.cpp/.h` | 自有detector每项独立保存返回值及分支计数；固定IntDir `tools/anti_analysis_validation/x64/Release/`、OutDir统一Release；x86单独固定配置，不复制Qt；本轮不创建／构建 |
| RAV2.1 profile准备；A0/A2 | Q/W/C:`EnvironmentProfile.*`、`ProfileConstraintValidator.*` | typed profile→逐接口计划／冲突／required closure；违反表中关系拒绝，partial显式；正反例含同名属性不同类 |
| RAV2.2 生命周期及记录；A1/A4/RAV2.1 | Q/W/C:`InterventionCoordinator.*`、`InterventionLedger.*` | prepare/apply/query/disable由本端Session拥有；逐调用原始／替代／seen分开；未完成必需证据预留则不提交 |
| RAV3.1 WMI同步切片；A5/RAV2 | Agent:`WmiObservation.*`、`WmiValueSubstitution.*`；本端`WmiObjectLedger.*` | 先确定对象来源和同步Get；x86/x64、VT_BSTR／整数／NULL、原失败、未命中、重复VariantClear及并发；最终独立目标值与预期一致，原失败不变 |
| RAV3.2 注册表切片；RAV3.1适用契约 | Agent:`RegistryValueObservation.*`、`RegistryValueSubstitution.*` | 明确hive/view/handle代次与实际值；QueryInfo／enum等未覆盖不称键隐藏；A/W、短缓冲、null长度探测、多线程／失败负控 |
| RAV3.3 固件及结构化结果；RAV2 | Agent:`FirmwareTableObservation.*`、`FirmwareTableSubstitution.*`、按需`StorageQueryAdapter.*` | 合法RSMB解析／两次size query／完整输出；profile与WMI一致；未知table及IOCTL透传，异常结构拒绝不越界 |
| RAV4.1 指令站点观察；A4/A7 | Q/W/C:`InstructionProbePlan.*`、`InstructionSiteLedger.*` | 自有已知CPUID／RDTSC站点，DR／TF分别测真实输出、开销、新线程与槽容量；先只观察，再决定有限替代是否值得产品化 |
| RAV4.2 时间／等待研究；RAV4.1 | Q/W/C:`TimingExperiment.*`、`WaitExperiment.*` | 真实外部QPC计时与目标时钟双记录；多时钟／多线程／共享页负控；明确不可覆盖路径及开销，不做全局TSC补偿 |
| RAV4.3 其它探测面；RAV1/2 | 独立`ActivityObservation.*`等按实际接口拆 | E03/04/06/08/12–15逐项先字段再有限机制；每面输出可行／partial／无可行非虚拟化路径的证据，不能无期限挂研究中 |
| RAV5.1 多信号实验；RAV3/4通过子集 | Q/W/C:`EnvironmentExperimentRun.*` | 单变量、相关接口一致组、自有组合detector；保存profile、环境基线、原始输入、分支独立计数及混杂因素；不自动横向比较所有sample |
| RAV5.2 产品入口；A9/RAV5.1 | 方案编辑ParameterWorkspace、结果表Compact、字段详情／CodeEditorWidget | 入口建议“行为追踪→环境实验”；显示观察／实验模式和实际范围；运行中不能热改；CLI方法help／文档同源，后台无页面 |
| RAV6.1 退出与发行；A10 | 支持矩阵、许可／来源、实机／恢复／性能报告 | 每端每架构每探测面分别公告，未验不开放；崩溃／停采／owner失联、目标及非目标原状态分别证明，既有监控回归 |

RAV0/RAV1不依赖环境替代产品化；RAV3优先WMI与注册表，再固件的一致性闭包，RAV4指令／计时独立研究，不能用其困难阻塞可完成的被动观察。任一机制试验不满足正确性／清理要求即保持disabled，产出限制报告及可选“在符合条件的授权实体环境重新采样”建议，绝不自动更换环境／关闭系统防护。

## 7. 必须执行的实验步骤与对照

正式实现后，各实验先在自有良性detector执行，不借真实病毒是否“恰好跑起来”作为唯一判断。每次启动为同项目中的新sample，手动明确选择baseline或指定profile；跨sample自动横向比较仍延期，只提供各自可导出的标准证据。

1. 固定EXE／PDB／源版本、OS／架构、系统保护实际状态及现有采集组件hash。用独立真实时钟、原始查询结果和预先定义的分支计数建立baseline；同一配置至少重复3次用于检查确定性，计时另作分布测量，3次不代表统计结论。
2. 开启“只观察”再跑同一detector，核对返回、状态、输出字节及分支与baseline是否一致；捕获本身造成的时序／异常／DR/TF差异如实记录。只观察已改变结果则先修观察器，不进入替代。
3. 单变量profile只选择一项可完整承载的字段；prepare先列出required接口及未覆盖项，失败不进入运行。执行时保存原值、替代attempt与目标独立所见；至少一个“未命中／原失败／输出太短”的负控。
4. 相关接口一致组检查同一值从WMI、registry、firmware／API读出的身份／类型／单位关系；故意配置冲突必须在prepare拒绝。partial实验则明确只检验其声明范围，不要求未覆盖接口返回替代值。
5. 组合detector依次查询多项后走已知分支；先单项，再一致组，独立记录哪项被实际读取及分支结果。第三方目标无独立分支证据时保留候选解释，不根据API日志顺序强称条件因果。
6. 禁用实验后新调用恢复baseline行为，停止、目标退出、控制端异常和恢复失败各自验收；原始历史／profile／seen证据保留。不得为看似干净而清空未决责任。

| 实验组 | 输入／负控的最少覆盖 | 成功标准 |
| --- | --- | --- |
| X01 WMI | 成功BSTR／整数／NULL、CIM_UINT64＋VT_BSTR及CIM_UINT32＋VT_I4、原失败、未匹配属性、相同Name不同class、重复查询、多线程、x86/x64 | 值／类型／HRESULT／所有权正确，独立目标见值，无未匹配返回改0；Get文本真正进归档；仅回调读回时不标seen |
| X02 注册表 | A/W／两view、open/close重用、容量0／短buffer、失败、enum与直接Nt旁路 | 已覆盖调用原契约正确、旁路显式可见／未知；不误称全面隐藏 |
| X03 固件／IOCTL | size probe／准确容量／短buffer、坏length/offset、未知provider/code、异步完成 | 两阶段长度一致、结构可独立解析、原失败／未知类型不被改成功；WMI相关值一致 |
| X04 CPU及内联站点 | leaf/subleaf、多个站点／线程、动态新增页、同地址版本变化、DR满 | 已知站点实际观测可复核；槽满／未知代码不静默覆盖；有限替代不能称无痕全拦截 |
| X05 计时／等待 | QPC/Tick/FILETIME/TSC/共享页、跨线程、真实Sleep／对象等待、取消／APC、暂停／恢复 | 分清真实时间与目标所见，正常等待语义不损坏；旁路／开销公开，不承诺计时全隐藏 |
| X06 活动及其它面 | 完整POINT／失败、DPI／屏幕、最后输入／Tick回绕；进程／文件／网络只观察及合法查询 | 不移动用户真实光标／改网络，未覆盖入口不伪装；正常管理／安装器不误报恶意 |
| X07 多信号及生命周期 | 单变量／一致组／冲突、部分支持、目标退出、日志满／满盘、owner死及恢复第N项失败 | 每级observed/substituted/seen/path独立成立；无未决丢账、其它目标与管理连接不受影响 |

## 8. 能力发布与退出研究的明确判据

每个E项最终交付一行“具体入口／架构／阶段＋observed/substituted/seen/path级别＋支持环境＋证据case＋旁路＋失败恢复＋性能”。没有证据的级别留pending。一个组只要必需入口或清理不可靠，就不对外标完整；可提供已验证部分，但标题和GUI明确范围。

实验只能证明“该profile和该已知探测条件下，观察到相应行为”，不承诺骗过任意多信号、时序和自校验探测。普通R0没有全用户态指令陷阱，单步／局部patch会暴露扰动，计时交叉预言机可能直接否定透明伪装；此时关闭相关替代能力，保存失败证据并保留被动解释和明确环境选择工作流。

本期不把“反反虚拟机”宣传成系统不可识别，也不因实验方案新增外部操作回滚、热重载、跨sample自动比较或整机代理。计划项一律按本节具体输入／产物／判据关闭，不能用“支持反沙箱”“R0可解决”或开关存在当完成证据。

## 9. 本轮依据及未执行边界

已读回仓库API定义、WMI归档实现、页面探针验证、Action Scope环境／返回契约及共享计时研究记忆。只读访问官方资料核对：

- [IWbemClassObject::Get](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-get)：HRESULT、VARIANT及CIMTYPE、失败不修改输出和调用者所有权。
- [GetSystemFirmwareTable](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable)：RSMB／ACPI、容量探测、返回长度、raw SMBIOS及WMI旁路。
- [Acquiring high-resolution time stamps](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)：QPC可在用户态完成、不等于TSC频率、跨线程±1 tick次序歧义以及多时钟区别。
- [__cpuid／__cpuidex](https://learn.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex?view=msvc-170)：生成内联指令，leaf/subleaf与四寄存器结果，不能按普通DLL导出Hook。

以上依据只支持机制／接口设计，不证明KSword已实现或通过实验。本轮未创建新产品源码／工程／语言包或测试配置，未构建／操作GUI／修改真实环境／运行样本／加载R0。RAV各任务为下一层可审查施工输入；实测仍按用户授权和指定环境推进。
