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
