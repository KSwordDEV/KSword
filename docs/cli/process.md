# 进程命令（R3）

使用 `help process` 逐层查找。已有命令不指定后端时继续使用原 R0 行为；显式选择 R3 不会自动切换到 R0。

## 原生枚举（迁移项 19）

```powershell
KswordCLI.exe process enum --backend r3 [--pid PID] [--name NAME] [--limit N] [--json]
KswordCLI.exe process enum --backend r3 --name notepad.exe --json
```

来自 NtQuerySystemInformation/SystemProcessInformation 的一次快照，保留原顺序。
pid 精确匹配（0 可显式选择 Idle）；name 按映像名称不区分大小写精确匹配；limit 只限制显示行数。
省略后端或使用 `--backend r0` 的原参数与原输出保持兼容，不接受 R3 专属筛选参数混用。

输出 source、complete、malformed、ntStatus、totalCount、matchedCount、returnedCount、missingPathCount、processes。
每项包含 pid、parentPid、creationTime（FILETIME，未知为 null）、name、nameSource、path、pathWin32Error、
sessionId、threadCount、handleCount、basePriority、kernelTime100ns、userTime100ns、cycleTime、
workingSetBytes、peakWorkingSetBytes、privatePageBytes、privateWorkingSetBytes、virtualSizeBytes、commitBytes、
pagedPoolBytes、nonPagedPoolBytes、pageFaultCount、I/O 三类操作次数与字节总数。
64 位时间／大小／计数为十进制字符串；basePriority 为有符号 JSON 整数。CPU 与 I/O 字段为累计值，不伪造采样速率。

映像路径通过保留的进程句柄读取；已知创建时间必须与快照一致，否则不把复用 PID 的新映像路径附到旧记录。
路径无法取得时为 null，保留原始错误码；nameSource 区分原生名称与原后端的显示占位名称。
匹配行中缺少路径返回 6，但原生身份和计数仍可用；有效空筛选返回 0。原生调用失败返回 3，
入口或信息类不可用返回 5；结构边界／字符串范围无效返回 4，不能把解析提前中止当成完整枚举。

## 按需扩展字段（迁移项 20）

```powershell
KswordCLI.exe process detail fields list [--backend r3] [--json]
KswordCLI.exe process detail fields query --pid PID [--creation-time FILETIME] [--fields NAME[,NAME...]|all] [--backend r3] [--json]
KswordCLI.exe process detail fields query --pid 1234 --fields command-line,user,dep,cfg,job --json
```

list 返回可选择的字段名。默认选择 command-line,user,architecture,elevated；all 选择所有已注册字段。
命名覆盖名称／路径、命令行、用户、架构、描述、提升状态、效率模式、运行状态、签名、PPL、程序包、作业、
UAC 虚拟化、DEP、CFG、硬件栈保护、DPI、企业上下文、GPU 利用率／引擎／显存，以及累计 CPU、内存、I/O 字段。
字段名未知、重复或逗号空项返回 1。R0 EPROCESS 字段和没有真实采样的 CPU／网络速率不在本组发布。
发行与虚拟机部署应同时复制 Release 中的 MSVCP140.dll、VCRUNTIME140.dll、VCRUNTIME140_1.dll；
新工具链构建的标准库代码不能依赖来宾系统里更旧的 VC 运行库。测试通道校验 EXE 与这些 DLL 的哈希。

命令行沿用后端展示规范：换行转为空格并去除首尾空白。
查询保持目标进程句柄直到结束，核对创建时间，并在收集结束时检查目标是否退出。
可传枚举得到的 creation-time 阻止跨进程实例读取；目标不存在、身份不匹配或期间退出返回 3。
使用共享按需后端，只采集所选字段所需的附加数据；内部的 NtQuery／Toolhelp 回退始终是 R3。
旧 `process detail --pid PID` 的 R0 调用入口仍在中间层 help 中，省略后端时行为不变。

输出 target（pid、creationTime、identityMatched、win32Error）、source、requestedCount、availableCount、fields。
每个字段含 name、available、value、nativeStatus、display。value 为类型明确的布尔、数值、字符串或对象；
没有可靠证据时为 null，不能根据 display 中的“失败／关闭／个人”等文字推导成功或状态。
有明确原生状态的签名与企业上下文保留 nativeStatus；其他后端未提供状态时为 null。
所有所选字段可用返回 0，部分可用返回 6，全无证据返回 5。

程序包为空且 available=true 表示未打包；缓解策略区分 enabled／disabled／enabled-permanent／not-applicable，未知为 null。
PPL 为公开 ProtectionLevel 枚举的十六进制值，不伪造 EPROCESS 的 Protection 字节。
签名 value 包括 trusted、publisher、display，nativeStatus 保留 WinVerifyTrust 结果；它不执行在线吊销检查。
企业上下文 value 为原生 states 位图和 identity；WIP 不可用时不把后端展示回退“个人”当作已确认状态。
GPU 首次 PDH 采样可能仍在预热，虚拟机可能缺少计数器；此时返回不可用，不能把 0 当作成功采样。
无映像描述或缺少读取权限时，后端不足以区分有效空值与查询失败，本命令明确保留为不可用。

## 限时遥测（迁移项 21）

```powershell
KswordCLI.exe process telemetry sample --pid PID [--creation-time FILETIME] [--interval-ms N] [--network on|off] [--backend r3] [--json]
```

默认间隔 1000 ms，范围 100..30000 ms。保留目标身份句柄，收集前后两个原生进程快照；
CPU 按实际 elapsedMs 和全部逻辑处理器数归一化，输出 cpuKnown、cpuPercent、cpuBefore100ns、cpuAfter100ns。
diskRateKnown／diskBytesPerSecond 描述本进程读取与写入 I/O 字节差，不是物理磁盘吞吐；
同时给出 ioReadBytesBefore/After、ioWriteBytesBefore/After、workingSetDeltaBytes、pageFaultDelta。
有符号增量与 64 位计数使用十进制字符串；counter 回退／重置时速率为 null，返回 6。

network 默认 off，不创建 ETW 会话。on 时使用本实例私有的 Microsoft-Windows-Kernel-Network 实时会话，
不接管 NT Kernel Logger。输出 networkRequested、networkRateKnown、networkBytesPerSecond、
networkRxBytesBefore/After、networkTxBytesBefore/After、networkHealth、networkFinalHealth。
网络累计字节从本次会话开始；只描述 Provider 已送达的事件，存在缓冲延迟与平台可见性限制。
health 包含 running、dataLossDetected、eventsLost、win32Error（无法取得原生码时为 null）、errorText。
未启动、丢事件或尚无有效基线时速率为 null，CPU/I/O 可用结果保留并返回 6。

完成采样停止自建 ETW 会话并等待消费线程退出；异常、目标退出或 Ctrl+C 也由同一实例析构释放。
取消返回 6 且 cancelled=true；目标退出、身份错误或原生快照失败返回 3，不发布旧实例速率。
无损完整结果返回 0，格式错误返回 4。只读采样不调整目标进程状态或权限。
原生样本获取失败保留 stage、ntStatus、malformed 与后端诊断。

## 进程控制（迁移项 22）

```powershell
KswordCLI.exe process suspend --pid PID [--creation-time FILETIME] --confirm --backend r3 [--json]
KswordCLI.exe process resume --pid PID [--creation-time FILETIME] --confirm --backend r3 [--json]
KswordCLI.exe process settings set-priority --pid PID --level idle|below-normal|normal|above-normal|high|realtime [--creation-time FILETIME] --confirm [--backend r3] [--json]
KswordCLI.exe process settings efficiency enable --pid PID [--creation-time FILETIME] --confirm [--backend r3] [--json]
KswordCLI.exe process settings efficiency disable --pid PID [--creation-time FILETIME] --confirm [--backend r3] [--json]
KswordCLI.exe process settings critical enable --pid PID [--creation-time FILETIME] --confirm [--backend r3] [--json]
KswordCLI.exe process settings critical disable --pid PID [--creation-time FILETIME] --confirm [--backend r3] [--json]
KswordCLI.exe process terminate --pid PID [--creation-time FILETIME] [--exit-status NTSTATUS] --confirm --backend r3 [--json]
KswordCLI.exe process terminate chain --pid PID [--creation-time FILETIME] --confirm [--backend r3] [--json]
KswordCLI.exe process terminate-tree --pid PID [--creation-time FILETIME] [--exit-status NTSTATUS] --confirm [--backend r3] [--json]
```

创建时间可从 process enum 或其他进程查询取得；省略时本次先取得身份，再把该时间传给共享动作后端。
操作期间保留身份句柄。身份不匹配、进程退出或访问失败返回 3，不作用于复用 PID 的新实例。
沿用后端保护：系统 PID 不可操作，返回 5。纯 R3 路径不调用驱动。
既有 terminate/suspend/resume 必须显式选择 R3，默认 R0 的参数、输出和行为保留。

输出 target、action、requestSucceeded、verified、evidence、observed；原生错误和 NTSTATUS 独立保留，
没有原始状态时为 null。优先级、效率和 critical 状态有前后回读；挂起／恢复有原生线程状态回读。
API 请求完成但效果未确认返回 6，可靠回读匹配才返回 0；不支持返回 5，实际调用失败返回 3。
效率模式先尝试公开读取接口，再复用后端 NtQueryInformationProcess 原生回退；两侧错误独立保留。
效率模式设置后最多等待 500 ms 进行只读状态回读，以覆盖状态传播延迟；未确认仍返回 6。
critical enable 设置 BreakOnTermination，之后异常终止目标可能使系统蓝屏；先 disable 并确认后再终止。
共享后端按原行为在 critical 操作中尝试启用当前 CLI 的 SeDebugPrivilege；实时优先级和效率模式可能因权限或系统能力被拒绝。

普通 terminate 默认退出码为 0xC000013A，可指定 exit-status；使用保留的句柄等待最多 2 秒并读取实际 exitCode。
terminate-tree 按原生快照子进程优先处理，每个目标重新核对创建时间并等待退出，输出逐项结果和 confirmedCount／failedCount。
父 PID 被复用时不会把更早创建的旧子进程纳入新树。快照后创建的子进程不在本次覆盖范围，部分完成返回 6。

用 `help process terminate` 发现具体方法叶子：win32、nt、wts、winstation、job、nt-job、restart-manager、
restart-manager-force、duplicate-handle、threads、nt-threads、debug、ntsd、unmap-ntdll。
这些叶子的语法均为 `process terminate METHOD --pid PID [--creation-time FILETIME] --confirm [--backend r3] [--json]`。
它们保持共享方法自身的退出行为，并在保留身份句柄上确认退出；后端没有提供的原始状态不从文本推导。
方法调用失败或在此系统不可用时保留 backendDetail，返回失败／不可用，不声称已退出。
chain 复用两轮组合方法链，返回每步 requestSucceeded、querySucceeded、presentAfter 和诊断；存在性查询失败不能当成目标退出。

## 基本信息（迁移项 23）

```powershell
KswordCLI.exe process detail basic query --pid PID [--creation-time FILETIME] [--backend r3] [--json]
```

通过 `help process detail`、`help process detail basic`、`help process detail basic query` 逐层发现命令。
旧 `process detail --pid PID` 保留默认 R0 行为。本命令默认 R3，保留目标句柄并在收集前后核对进程实例和存活状态；
不存在、创建时间不匹配或收集期间退出返回 3。查询不写入 PEB，不要求 KswordARK 驱动。

输出 target、source、requestedCount、availableCount、fields。19 个字段为 name、parent-pid、parent-name、threads、
image-path、command-line、bitness、session、user、integrity、elevated、creation-time、priority-class、handles、
peb、affinity、working-set、private-bytes、io-bytes。每项包含 available、value、win32Error、ntStatus；
查询缺少可靠证据时 value 为 null，原始状态未取得时为 null。后端展示文字不用于判断查询成功。

PEB 和亲和性掩码使用十六进制字符串；创建时间是 Windows FILETIME 的 100 ns 计数，内存／I/O 字节使用十进制字符串。
priority-class 为 Win32 优先级常量。io-bytes 是读、写、其他 I/O 传输计数的饱和和，不表示磁盘实际吞吐。
命令行保留远程原文，有效空值输出空字符串；与 fields query 的展示规范不同。
父进程可能已经退出，因此 parent-name 可不可用；名称快照和统计并非同一瞬间的原子视图。
读取命令行需要 PROCESS_VM_READ；受保护进程或跨架构布局限制可能使该字段不可用。
全部字段有可靠证据返回 0，部分返回 6，全无证据返回 5。后端的“打开成功”不能替代各字段可用性。

## 线程（迁移项 24）

```powershell
KswordCLI.exe process thread enum --pid PID [--creation-time FILETIME] [--tid TID] [--limit N] [--backend r3] [--json]
KswordCLI.exe process thread affinity query --pid PID --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] [--backend r3] [--json]
KswordCLI.exe process thread suspend --pid PID --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] --confirm [--backend r3] [--json]
KswordCLI.exe process thread resume --pid PID --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] --confirm [--backend r3] [--json]
KswordCLI.exe process thread terminate --pid PID --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] --confirm [--backend r3] [--json]
KswordCLI.exe process thread set-affinity --pid PID --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] --processors GROUP:INDEX[,GROUP:INDEX]|follow --confirm [--backend r3] [--json]
```

用 `help process thread` 发现直接子命令，`help process thread affinity` 发现亲和性查询；叶子 help 才显示参数。
所有命令默认 R3，无驱动依赖。enum 保留进程身份句柄，输出 complete、skippedCount、matchedCount、returnedCount、truncated、threads。
线程行含 tid、pid、creationTime、basePriority、deltaPriority、startAddress、suspendCount，以及 identityEvidence／startEvidence／suspendEvidence。
计数不再使用后端原来的固定零值：suspendCount 通过原生只读查询取得，失败为 null。优先级有符号；地址为十六进制字符串，创建时间为 FILETIME 十进制字符串。
查询起始地址先申请 THREAD_QUERY_INFORMATION，权限不足时仍以有限权限保留身份信息；原始 NTSTATUS 与 Win32 错误独立输出。
limit 默认 1000 且必须正数。输出截断、缺字段或跳过已变更所属进程的快照行返回 6；有效空筛选返回 0。
枚举中目标进程退出返回 3，快照失败返回 3；快照中途错误保留已采集结果并返回 6。

动作和亲和性查询必须传入枚举所得 thread-creation-time。CLI 与共享动作后端均核对线程所有者、线程创建时间和进程创建时间，
保留双方句柄直到操作及回读完成；身份不匹配或目标退出返回 3，避免对复用 TID 操作。
suspend／resume 只增减一次挂起计数；输出 previousSuspendCount 及 observed.before／after，resume 原计数为 0 时保持 0。
terminate 使用后端退出码 1，等待至多两秒，在原线程句柄上确认退出与实际 exitCode。
requestSucceeded 表示动作请求成功，verified 表示效果回读匹配；请求成功但证据不完整返回 6，失败返回 3。

affinity query 输出 usesCpuSets、followsProcess 和 processors（group、logicalIndex、cpuSetId、coreIndex、efficiencyClass、available、selected、parked、constrained）。
set-affinity 以 group:index 坐标选择处理器，拒绝重复、空项和越界坐标；follow 清除线程独立 CPU Set 规则。
CPU Sets 不可用时共享后端回退当前处理器组的 group affinity，此时 follow 选择该组活动处理器掩码。
CPU Set 设置后的回读失败会尝试恢复旧选择；输出 writeAttempted、writeSucceeded、rollbackAttempted、rollbackSucceeded、rollbackVerified。
rollbackSucceeded 记录回滚 API 结果，rollbackVerified 另行对比设置前后的选择；写入后未确认恢复旧状态返回 6，不能当成未写入的普通失败。
原始错误后端未提供时为 null，保留诊断文字但不解析它推导状态。
跨处理器组的传统亲和性设置不支持；选择平台不可用的坐标在写入前失败。

## 模块（迁移项 25）

```powershell
KswordCLI.exe process module enum --pid PID [--creation-time FILETIME] [--base ADDRESS] [--name NAME] [--limit N] [--backend r3] [--json]
KswordCLI.exe process module unload --pid PID --base ADDRESS [--creation-time FILETIME] [--module-path PATH] [--image-size N] --confirm [--backend r3] [--json]
KswordCLI.exe process module thread suspend --pid PID --base ADDRESS --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] [--module-path PATH] [--image-size N] --confirm [--backend r3] [--json]
KswordCLI.exe process module thread resume --pid PID --base ADDRESS --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] [--module-path PATH] [--image-size N] --confirm [--backend r3] [--json]
KswordCLI.exe process module thread terminate --pid PID --base ADDRESS --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] [--module-path PATH] [--image-size N] --confirm [--backend r3] [--json]
```

使用 `help process module`、`help process module thread` 和叶子 help 逐层发现；本组默认 R3，无 R0 回退。
枚举保留进程身份句柄，需要 PROCESS_QUERY_INFORMATION 与 PROCESS_VM_READ；权限失败返回 3，后端入口不可用返回 5。
name 按完整模块文件名忽略大小写筛选，base 按模块句柄筛选，limit 默认 1000。
输出 target、source、enumeration、threadEnumeration、matchedCount、returnedCount、truncated、modules。
模块行含 handle、name、path、base、imageSize、infoEvidence、pathEvidence、representativeThread。
地址为十六进制字符串；不可用的路径／映像信息为 null，并保留原始 Win32 错误。
关联线程按真实起始地址是否位于映像范围选取，提供 tid 与创建时间；没有关联线程可以是有效结果。
路径截断、代表线程证据缺失或输出截断返回 6，结构字节数不对齐返回 4。
模块表增长时最多重试四次，持续增长只处理实际已填入的容量并标记不完整，避免空槽位冒充模块。

unload 在完整模块快照上核对 base，可附 module-path 和 image-size 约束预期模块。
共享后端定位目标中 FreeLibrary 所属模块后按函数偏移调用；找不到模块／有效范围或跨位数时返回 5，不能使用本机绝对函数地址猜测远程入口。
保留进程身份句柄并等待远程线程至多 10 秒，输出 remoteThreadCreated、waitResult、freeLibraryResult、win32Error、requestSucceeded、verified、observed。
requestSucceeded 仅表示 FreeLibrary 返回非零；重新枚举确认原基址消失才返回 0。
仍有引用、基址仍存在或回读不可用返回 6。返回零或创建远程线程失败返回 3；等待超时返回 6，远程线程可能在 CLI 退出后继续。
CLI 不强行杀死等待中的远程线程；卸载仍被目标代码使用的模块可能使目标不稳定。
模块加载／卸载与快照存在时序窗口，路径／大小约束和回读不能替代目标内部的加载器同步。

模块 thread 动作另外核对 TID、线程创建时间和起始地址与映像范围的关联，再复用共享模块线程动作。
输出 module 与 threadAction，后者包含身份、requestSucceeded、verified、previousSuspendCount 和 observed。
suspend／resume 一次只增减一次计数；模块后端 terminate 的退出码为 0（线程命令族 terminate 为 1），均在原句柄上回读验证。
身份或关联不匹配返回 3，请求成功而效果未确认返回 6。GUI 导航、复制和跳转等辅助操作不作为命令发布。

## 令牌（迁移项 26）

```powershell
KswordCLI.exe process token classes list [--backend r3] [--json]
KswordCLI.exe process token query --pid PID [--creation-time FILETIME] [--classes NAME[,NAME...]|all] [--limit N] [--max-bytes N] [--backend r3] [--json]
KswordCLI.exe process token raw query --pid PID --class NAME|NUMBER [--creation-time FILETIME] [--max-bytes N] [--backend r3] [--json]
KswordCLI.exe process token raw set --pid PID --class NAME|NUMBER [--creation-time FILETIME] (--hex HEX|--data-file PATH) --confirm [--backend r3] [--json]
KswordCLI.exe process token privilege enable --pid PID --name PRIVILEGE [--creation-time FILETIME] --confirm [--backend r3] [--json]
KswordCLI.exe process token privilege disable --pid PID --name PRIVILEGE [--creation-time FILETIME] --confirm [--backend r3] [--json]
```

按 `help process token`、`help process token raw` 或 `help process token privilege` 逐层查找操作，再查询叶子参数。
默认 R3，保留进程身份句柄；读取通过共享 R3 后端取得目标令牌，不使用 Light 的 R0 fallback。
classes list 展示后端的 1..80 信息类名称；名称用于指定原生信息类，不代表系统保证支持或允许设置该类。
query 默认读取 TokenUser、TokenGroups、TokenPrivileges、TokenElevationType、TokenElevation、TokenIntegrityLevel、TokenSessionId。
classes 可传名称／编号列表，拒绝重复、空项和未知名称；all 查询后端的全部 80 类，在较旧系统上通常得到部分结果。

输出 target、source、requestedCount、availableCount、classes。每类含 informationClass、name、available、win32Error、malformed、byteSize、truncated、value。
用户／完整性有 SID 与可解析的账户名，组有 SID 与原始 attributes，权限有名称、LUID、attributes、enabled 和名称解析错误；
提升／虚拟化／UIAccess 为布尔，session 和 elevation type 为原生数值。未解码的信息类及 raw query 输出十六进制字节。
无证据为 null，原始错误独立保留；不能把后端“刷新完成”当作所有信息类成功。
limit 默认 128，范围 1..65535，限制组与权限表；max-bytes 默认 512，范围 1..1048576，限制原始字节展示。
截断或部分信息类不可用返回 6；全无证据时，平台不支持返回 5，实际查询失败返回 3。返回长度或 SID／数组边界无效返回 4。
原始缓冲区中的指针、句柄仅描述这次采集，不可直接用于之后的设置；关联令牌返回的拥有句柄在记录数值后关闭，遵循
[TOKEN_LINKED_TOKEN 所有权](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_linked_token)，不因遍历或重复查询泄漏。

privilege enable／disable 调整已存在的目标权限，不能增加令牌没有的权限；AdjustTokenPrivileges 返回 TRUE 且错误为 1300（NOT_ALL_ASSIGNED）仍为失败。
输出请求方向、requestSucceeded、verified、身份、原始错误及 beforeAttributes／afterAttributes；原生属性回读匹配才成功。
若需要调整当前 CLI 权限后在同一进程执行命令，应使用 `privilege run`；本组调整的是指定目标进程令牌。

raw set 接收 1..16 MiB payload，调用已有 NtSetInformationToken，保留精确 NTSTATUS；只把 0 状态认作请求成功。
需令牌 QUERY／ADJUST_DEFAULT／ADJUST_SESSIONID 权限以及该类要求的特权；只读信息类或平台不支持返回 5 或 3，依据原生状态区分。
输出 payloadSize、requestSucceeded、verified、readbackKnown、readbackComparable、ntStatus、win32Error。
requestedHex／readbackHex 展示最多 512 字节的请求与回读，另有 readbackSize、双侧 truncated 标志和 readbackWin32Error。
仅 session、sandbox、virtualization、UIAccess、mandatory-policy 等稳定标量类能进行字节等值回读；含指针的类不会因原始缓冲区地址不同而伪造匹配。
请求成功但回读不可用、不匹配或无法比较时返回 6；读取、身份或实际设置失败返回 3。
例如 `--class TokenMandatoryPolicy --hex 01000000` 设置四字节小端标量；原始设置不替用户推断结构布局或把读取快照中的地址重定位。
UIAccess 等标量设置可能需要调用方 SeTcbPrivilege；普通管理员未持有该权限时会被拒绝。
MandatoryPolicy 修改也可能因令牌已在使用（STATUS_TOKEN_ALREADY_IN_USE）拒绝，并非具有权限后即可修改所有运行中令牌字段。
在已经持有该权限的 CLI 上下文中，可用 `privilege run --enable SeTcbPrivilege -- process token raw set ...` 保证启用与设置在同一进程中；
作用域执行不会授予当前令牌原本没有的权限。
