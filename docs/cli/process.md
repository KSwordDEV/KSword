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
