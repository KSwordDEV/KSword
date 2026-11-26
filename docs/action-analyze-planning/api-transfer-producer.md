# API 转移参数源端

本轮范围为 API Monitor 的四个专用 Hook：`WriteProcessMemory`、`NtWriteVirtualMemory`、`CreateRemoteThread`、`NtCreateThreadEx`。API Monitor 是检测主链，Syscall 为辅助，回调仅补充。本文件只记录源端，不代替消费者整合验收。

## 已实现的接口

- 共享契约 `shared/evidence/ApiInjectionFields.h` 保持只读。`ApiInjectionObservation.{h,cpp}` 在既有 `ScopedHookGuard` 内采集，同一个业务包通过 `SendRawEventWithMetrics` → `SendMonitorEventRawWithMetrics` → 原有队列发送；没有额外业务包。
- 普通 `ApiCall` 保持 1000 字节，`coverageState=0x49505631` 明确标记，`detailText` 为 `AAIP1|` 加固定 14 个十六进制字段。字段写入不受原文本摘要长度限制。原返回位、耗时、声明 SHA 和会话身份沿用原发送路径；普通 Hook、Raw、coverage 的可选参数默认空。
- 源进程创建 FILETIME 从当前进程句柄查询；目标 PID/创建 FILETIME 只从输入句柄查询。查询失败保留未知，原始输入句柄不当作身份，也不另开外部目标。
- 请求地址/长度或请求线程入口原样记录。调用前后分别采 QPC，返回 QPC 在遥测身份和输出查询之前采集。目标输入句柄前后解析到相同 PID 与创建 FILETIME，才设置 `ApiInjectionTargetStable`。
- 写入输出长度只在原 API 成功且 SEH 安全读取成功后设置有效位；空指针、失败或不可读不补成零或请求长度。线程身份只从成功返回的线程句柄查询；NT 返回线程句柄先做成功门禁和 SEH 安全读取。四函数原有的不安全输出解引用已移除。
- 所有额外查询和发包都位于重入保护内；不替换原参数、不更改原返回、NTSTATUS 或调用方可见 LastError。观察到写入/请求线程入口不证明入口实际执行。
- 新源已登记 `APIMonitor_x64/APIMonitor_x64.vcxproj`、`APIMonitor_x86/APIMonitor_x86.vcxproj` 及各自 filters。

## 验收状态

源码实现完成。作者直接调用 CodeBuddy 自主维护定向夹具、构建正式双 Agent、在本机自有父子目标中验证实际写入与自有导出线程、失败负例，并在本文件追加最终回执。禁止 GUI、本机驱动、Sysmon 和其他用户进程注入。构建使用 BelowNormal、HostX64、工程固定 IntDir 和统一正式 Release；正式产物与小型文本证据分开保存。

正式构建和实测结论待 CodeBuddy 最终回执；不得把本节源码核对算成运行通过。测试必须分别核对四函数成功/失败、无输出计数、不可读输出安全性、目标身份/前后稳定性、线程创建身份、QPC、原返回/LastError/NTSTATUS、1000 字节、definition SHA、普通/Raw/coverage 默认语义，以及测试自有进程/配置清理。

## 最终回执（CodeBuddy，2026-11-26）

### 结论

源端正式验证完成：生产 helper 负测 x64/x86 各 35/35 通过；真实 Release Agent 自有父子夹具实测 x64/x86 各 **172/172 通过**。四 Hook 中 `WriteProcessMemory`、`NtWriteVirtualMemory`、`NtCreateThreadEx` 的全部契约项在两个架构实测通过；`CreateRemoteThread` 存在一个**产品级 Hook 不可达缺陷**（见下），需要作者修复后定向复验。

### 产品缺陷（需作者修复）

**`CreateRemoteThread` Hook 在本机 OS 构建上对真实调用不可达。** 实测证据：`kernel32!CreateRemoteThread` 是真实函数体（非转发/跳转桩，已核对进程内字节），其实现直接调用 `KernelBase!CreateRemoteThreadEx`，从不经过 `KernelBase!CreateRemoteThread`。因此 `HookTargets.cpp:3025` 的 `HookedCreateRemoteThread`（携带 `ApiInjectionObservation`）从未执行；覆盖行却报告 `CreateRemoteThread` 状态 Installed，与真实路径不符。真实事件来自 `ApiMonitorWrappers.inc` 生成的 `HookedCreateRemoteThreadEx` Raw 包装：detail 为 `process=... start=... tid=...` 文本，**无 `AAIP1` 结构字段、无 `0x49505631` marker**，即消费侧永远收不到 CreateRemoteThread 的注入观察字段。修复建议：把注入观察挂到 `KernelBase!CreateRemoteThreadEx` 路径（或在生成的 Ex 包装上补观察字段）。作者修复后，用 `tools/api_monitor/api_transfer_validation/run_api_transfer_live.py` 定向复验（届时需把夹具 `r`/`t` 用例的期望从 CRTEx Raw 事件改回 `CreateRemoteThread` AAIP 事件）。

附注（非缺陷，消费侧需知）：spawn 子进程时父进程 `CreateProcess` 写入子进程参数的 `NtWriteVirtualMemory` 调用同样被观察为合法 AAIP 注入事件（目标是自有子进程）；生成 Raw 包装的 resultCode 记录的是调用前保存的 LastError，语义与手写 Hook 的调用后 LastError 不同。

### 构建回执

- BelowNormal（`start /belownormal`）、64 位 MSBuild（`D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe`）、HostX64 三属性齐备；工程固定 IntDir，产物统一在 `Ksword5.1\x64\Release\`。日志在 `.codex-build-logs/api-transfer-producer\`（8 个文本 log + 2 个证据 JSON）。
- 构建 exit code：fixture x64/x86 = 0，helper x64/x86 = 0，Agent x64/x86 = 0（脚本 `build_api_transfer_validation.cmd` 分步执行，全部 `EXIT=0`）。
- 产物 SHA256：
  - `APIMonitor_x64.dll` `c5a25ad89623df8f2948258dce7b9119d85126936052652cb1109797a224959c`
  - `APIMonitor_x86.dll` `c0c984f06b2889b3c048cbfb83f7bcbc4473a8c70e38ff6b8b6be976dd3fbf6e`
  - `ApiTransferValidationFixture64.exe` `19562cdfa9799b7d9419599f24cd81ca270bc48e04d28fff9d5f2daca364b63c`
  - `ApiTransferValidationFixture32.exe` `22247556f759dad23ff990e89d977c6add7dbf569bde358187318dd0871cae9e`
  - `api_monitor_definitions.json` `67aa8a6476434d7af2564b1a2dc1a8f12aa16fd792cfe55e2ee2b6489cd049d1`（与每个事件包 `definitionSha256` 实测一致）

### 逐项核对结果（每架构 172 项检查）

1. 四 API 成功/失败原包：`WriteProcessMemory` 成功/ERROR_PARTIAL_COPY(299)/ERROR_ACCESS_DENIED(5)/已关闭句柄(6)；`NtWriteVirtualMemory` 成功/STATUS_PARTIAL_COPY(0x8000000D)/STATUS_INVALID_HANDLE(0xC0000008)/已关闭句柄；`NtCreateThreadEx` 成功/无效句柄；`CreateRemoteThread` 经真实 `CreateRemoteThreadEx` 路径（见缺陷）。事件的 resultCode/返回位与调用方实测值逐一相等，NTSTATUS 未被修补。
2. 目标身份与前后稳定：目标 PID + 创建 FILETIME 从输入句柄解析且与子进程实测一致；前后复核后 `ApiInjectionTargetStable` 置位；查询失败（仅 `PROCESS_VM_WRITE` 句柄、已关闭句柄、无效句柄）一律保留未知，不补值。
3. 线程身份：`NtCreateThreadEx` 成功后 `targetTid` 非零、线程创建 FILETIME 非零、自有导出例程实际执行（共享计数器 ≥2，目标缓冲模式串写入被读回证实）。
4. 输出长度：仅成功且 SEH 安全读取成功才置 `ApiInjectionCompletedLength`；null 输出、失败、部分写均无该位且 completedBytes=0；VM_WRITE-only 句柄 `NtWriteVirtualMemory` 成功时 completed=16 有效而目标身份保留未知。
5. QPC：每个事件 `enterQpc>0` 且 `returnQpc>=enterQpc`。
6. 输入句柄：原样记录（正常句柄、受限句柄、已关闭句柄、无效句柄 `0x1234`），不当作身份。
7. 1000 字节与 definition SHA：泵入所有包断言 size=1000、version=0x20261003、pid/session 匹配、SHA 与 definitions JSON 一致。
8. 短 detailLimit 不截断结构字段：`detail_limit=64`（产品下限）下 AAIP1 全长 243 字符完整、解码通过、marker 置位；同一配置下普通事件 detail 被截到 ≤64，证明截断生效。
9. 普通 Raw/coverage 不带 marker：全部非注入事件（含 `ReadProcessMemory`）与全部覆盖行 state ≠ `0x49505631`。
10. 重入保护：每命令恰一事件（`WriteProcessMemory` 5、`NtWriteVirtualMemory` 5、`NtCreateThreadEx` 2、CRTEx Raw 2），无嵌套重复包。
11. 清理：每轮退出前关闭自有句柄、终止自有子进程（`Q`）、删除 `config_<pid>.ini`/`stop_<pid>.flag`；运行结束无残留夹具/子进程；无随机构建目录（曾由 OutDir 路径错误产生的 `tools\Ksword5.1\` 已删除并修正两个 vcxproj 的 OutDir）。

### 生产 helper 负测（不经 Hook 与管道）

x64/x86 各 35/35：LastError 保持、QPC 顺序、null/失败/不可读输出（PAGE_NOACCESS 守卫页 SEH）、线程输出 null/失败/不可读/无效句柄、无效目标句柄无身份、编码往返与拒绝语义（截断/错标/非规范十六进制/flags 越界）、四 API 成功/失败/部分/未知基线、文本长度契约。修复的 4 个测试侧问题（非产品问题）：`INVALID_HANDLE_VALUE` 是当前进程伪句柄、roundtrip 未设 `snapshotIndex` 返回值标记、overflow 用例须先解码再核对、NT 返回位必须等于 resultCode。

### 夹具修复记录（自有测试目录）

- `PROCESS_CREATE_THREAD` 补入正常句柄权限（原先 `NtCreateThreadEx` 直接失败 `0xC0000022`）。
- `t`/`T` 失败用例改用非伪句柄 `0x1234`（`-1` 是当前进程伪句柄：`CreateRemoteThread(-1)` 曾真实在父进程创建入口 `0x1000` 的线程导致异步 AV 崩溃，崩溃地址实测 `0x1000`）。
- 32 位导出别名 `/EXPORT:ApiTransferRemoteProc=_ApiTransferRemoteProc@4`（原先子进程 `GetProcAddress` 查不到无装饰名，spawn 失败）。
- 崩溃诊断用未处理异常报告器、helper 独立 IntDir、fixture/helper OutDir 修正。

### 范围与缺口

- 未覆盖（按任务禁令）：GUI、本机驱动、Sysmon、其他用户进程注入。
- `CreateRemoteThread` 的 AAIP 契约项（目标/线程身份、startAddress、QPC、marker）因上述产品缺陷未能在真实路径验证，待作者修复后复验。
- `NtCreateThreadEx` 无效句柄只断言「NTSTATUS 为负且与事件逐位一致」，未固定具体 NTSTATUS（OS 相关）；WOW64 跨架构（x64 父写 x86 子）不在本轮。
- 消费者整合验收由主协调者另行负责；本轮不提交、不改 shared/CLI/GUI/MonitorAgent.cpp。

### 测试目录产出

`tools/api_monitor/api_transfer_validation/`：`ApiTransferValidationFixture.{cpp,vcxproj,filters}`、`ApiTransferValidationHelper.{cpp,vcxproj,filters}`、`build_api_transfer_validation.cmd`（修复 start 空命令）、`run_api_transfer_live.py`（新增运行器）。正式产物在 `Ksword5.1\x64\Release\`；小型证据在 `.codex-build-logs\api-transfer-producer\`。

## 复验回执（CodeBuddy，2026-11-26，第二轮）

### 结论：先前缺陷已关闭

作者修复（`HookTargets.cpp:2062-2068`，`TryInstallBinding` 对 `CreateRemoteThread` 以 `installModule = L"kernel32.dll"` 安装到 kernel32 公共真实入口，其余绑定沿用原 module；API 身份/definitionSHA/AAIP1 格式不变，coverage 记录实际安装地址）经两架构全套定向复验**通过**。上一轮的「172/172」是在 CreateRemoteThread 不可达缺口下取得的，只覆盖三个 Hook 的契约，**不能视为四 API 验证完成**；该缺口证据已保留为 `.codex-build-logs\api-transfer-producer\api_transfer_live_{x64,x86}_initial_gaprun.json`。

### 复验结果（每架构 201/201，全部通过）

- **安装入口与 coverage 一致**：覆盖行 `CreateRemoteThread` 的 hookAddress 落在夹具进程 kernel32.dll 模块范围内，且与磁盘同架构 `kernel32.dll`（x64 System32 / x86 SysWOW64）导出表解析的 `CreateRemoteThread` RVA 完全相等：x64 hook@`0x7FF99666C350`（base `0x7FF996630000`，RVA `0x3C350`），x86 hook@`0x778B52E0`（base `0x77880000`，RVA `0x352E0`）；入口字节实测为 Hook 补丁（`E9 ...` 跳转，随后为搬移的原函数前导 `44 8B 54 24 78...`/x86 `8B 45 1C...`）。
- **真实外层 AAIP1 事件**（包身份仍为 `KernelBase`/`CreateRemoteThread`）：成功用例核对 operation=ThreadCreate、startAddress=自有导出例程地址、目标 PID+创建 FILETIME 与子进程一致且 Stable、真实线程 TID 与夹具报告 TID 相等、线程创建 FILETIME 非零、原返回位=夹具实测返回的线程句柄值（`ApiReturnBits` 为句柄原始位）、输入句柄、QPC 顺序。
- **失败完整未知语义**：无效句柄（非伪句柄 `0x1234`）用例无目标身份、无线程身份、completedBytes=0，resultCode=6 与返回位 0 原样保留。
- **无嵌套重复业务包**：外层 CRT 触发时 `CreateRemoteThreadEx` 包为 0、无多余 `NtCreateThreadEx` 包；计数 `WriteProcessMemory` 5 / `NtWriteVirtualMemory` 5 / `CreateRemoteThread` 2 / `NtCreateThreadEx` 2，恰好一命令一事件。本轮没有直接调用 Ex；初始轮仅证明当时外层 CRT 路径产生的 Ex 事件无 AAIP，不能替代修复后直接 Ex 的独立实测。直接 Ex 的当前运行语义仍待针对性验收，源码路径未改。
- 其余 11 项契约（QPC、1000B、definitionSHA、短 detailLimit、普通事件无 marker、覆盖行无 marker 等）在本轮全部重新核对通过。

### 构建与清理

- 产品修复后双 Agent 各做一次适用增量构建（BelowNormal、64 位 MSBuild、HostX64、工程固定 IntDir，exit 0）；fixture 因 `r` 用例补充打印返回句柄而重建（exit 0）。helper 未改不重建，重跑确认 35/35。
- 新产物 SHA256：`APIMonitor_x64.dll` `f532324cd22b8f9f0130849ceec6df85e8070788331fd99d8b59a0cc4bb43789`；`APIMonitor_x86.dll` `07f4152e1ea59f933716cb4ea911354dab502231a92ffe61172e31334af7c64b`。
- 新证据：`.codex-build-logs\api-transfer-producer\api_transfer_live_{x64,x86}.json`（含 hookAddress、模块基址、RVA、入口字节）；初始缺口证据已重命名保留。
- 清理核实：无残留夹具/子进程，`config_*/stop_*` 为 0，未触碰 GUI/驱动/Sysmon/他人进程。运行器新增的模块枚举/内存读取仅针对本轮自有夹具进程。

## 后续三类源端接口（2026-11-26，源码完成、待验）

用户最新强制指令暂停所有 CodeBuddy 新派发、续接、重试和自动后续任务，直至主协调传达恢复；不自行替代验收。本节仅登记继续授权的核心代码与接口，**未做扩展后的构建或运行验收**。上一节四 API 的双架构 201/201 是已固定 SHA 的历史产物实证，不覆盖新增 APC/上下文/映射代码。现有任务已正常返回；没有新派发、续接或测试 subagent。

### 独立契约及消费入口

| 族 | 新共享头 | marker / prefix | 精确源 API | 结构 / 解码入口 |
| --- | --- | --- | --- | --- |
| APC 入队 | `shared/evidence/ApiApcFields.h` | `0x41505631` / `AAAP1\|` | `QueueUserAPC`、`NtQueueApcThread` | `ApiApcFieldsV1` / `ReadApiApcFields` |
| 请求上下文 | `shared/evidence/ApiContextFields.h` | `0x43545631` / `AACT1\|` | `SetThreadContext`、`NtSetContextThread` | `ApiContextFieldsV1` / `ReadApiContextFields` |
| 节映射 | `shared/evidence/ApiSectionMapFields.h` | `0x534d5631` / `AASM1\|` | `NtMapViewOfSection` | `ApiSectionMapFieldsV1` / `ReadApiSectionMapFields` |

旧 AAIP1 operation 1/2 和只读头不变。每族使用自己的 operation enum，目前分别只有 Queue/Set/Map=1，不能把不同族的 operation 数值互相解释。固定 1000B 包、协议版本、返回位 marker、耗时 marker、definition SHA、会话身份和原队列均沿用。只有对应 Hook 传入新增可选字段；普通 Hook、Raw、coverage 默认不传。三族文本长度分别 243/260/260 字符，写入不受摘要 detailLimit 截断；末尾仍可由原有栈 trailer 在空间允许时保存调用栈。解码器核对 marker、前缀、固定长度、规范十六进制、类别和 Strong/ApiCall/返回 marker，再核对字段有效位与零值关系；消费者还必须独立匹配精确 API 和模块族、原返回语义、来源和归档身份。

### APC 字段顺序与语义

14 个固定 64 位十六进制字段：`operation, flags, actorCreationFileTime, targetPid, targetCreationFileTime, targetTid, targetThreadCreationFileTime, routineAddress, enterQpc, returnQpc, inputThreadHandle, argument1, argument2, argument3`。

flags 位 0/1/2/3/4 分别为源进程身份、目标进程身份、目标线程身份、请求例程地址、目标前后稳定。Win32 入队只有 argument1，另两个参数按该原 API 的参数形态置零；NT 保留三个原始参数地址，不解引用。

`ApiApcCallOutcome` 精确检查两个 API 的模块族、返回位和 resultCode；返回 Unknown/Failed/Accepted。**Accepted 只表示调用接受入队，既不表示投递，也不表示例程执行。** NULL 例程依然是已记录的请求地址，不推断合法或可执行。

### 线程身份采集与成本边界

`ApiThreadTargetObservation.{h,cpp}` 是 APC/上下文共用的纯采集辅助，不定义 wire 操作。源身份来自当前进程句柄；目标线程 ID、owner PID、创建 FILETIME 来自原输入线程句柄。目标进程创建 FILETIME 从只读 `NtQuerySystemInformation(SystemProcessInformation)` 快照中匹配，前后夹取线程句柄身份，并检查进程创建时间不晚于线程创建时间；不另开外部进程或线程，不读取目标内存。调用后重新检查线程身份和进程创建代次一致才 Stable。权限不足、进程快照失败、调用中句柄关闭/复用、未知代次均保留缺失位，不使用裸句柄或仅 PID/TID 作为强身份。

快照缓冲按调用线程复用，初始 256 KiB，上限 8 MiB；单次查询最多一次扩容重试。查询和分配都在既有 ScopedHookGuard 内，不递归监控。该路径对跨进程调用的开销、缓冲峰值、WOW64 原生布局和长期压力仍待专门验收；当前不宣称性能结论，也不通过共享全局缓存补造调用时身份。

### 上下文字段顺序与语义

15 字段：`operation, flags, actorCreationFileTime, targetPid, targetCreationFileTime, targetTid, targetThreadCreationFileTime, contextFlags, requestedIp, requestedSp, contextArchitecture, enterQpc, returnQpc, inputThreadHandle, inputContextAddress`。

flags 位 0/1/2/3/4/5 分别为源身份、目标进程身份、目标线程身份、安全读取到 ContextFlags、读取到当前 ABI 的 CONTROL 请求寄存器、目标前后稳定。`contextArchitecture` 为当前 Agent 原生 CONTEXT ABI 的 32 或 64；**本次不覆盖 Wow64SetThreadContext**。请求在原调用前 SEH 安全读取，不修改 CONTEXT；只有 ContextFlags 含本 ABI 的 CONTEXT_CONTROL 才读取 EIP/ESP 或 RIP/RSP。局部不可读时保留已成功读取的 flags，IP/SP 保持未知。原 API 成功只证明接受上下文设置请求，不证明该 IP 被执行；输入快照也不能证明并发调用方没有修改原缓冲。

### 映射字段顺序与语义

15 字段：`operation, flags, actorCreationFileTime, targetPid, targetCreationFileTime, requestedBase, requestedBytes, mappedBase, mappedBytes, sectionOffset, inputSectionHandle, requestedProtection, enterQpc, returnQpc, inputProcessHandle`。

flags 位 0/1/2/3/4/5/6/7 分别为源身份、目标身份、目标前后稳定、调用前安全读取到请求 base、请求 size、输入 section offset、成功后读回 mapped base、成功后读回 mapped size。输入 section handle 只作原始参数，不作为节对象身份或共享别名关联键。可选 offset 指针为空时保持未知，不能补成已知零；实际映射范围只在 NT_SUCCESS 且 SEH 安全读回后分别标记。映射成功不证明 payload 写入、跨进程别名传播或执行。

### 工程及待验范围

新增 `.cpp/.h` 仅位于 `APIMonitor_x64/hook/`，已登记正式 x64 与实际 `APIMonitor_x86/APIMonitor_x86.vcxproj` 两工程及 filters。HookTargets 只组合现有 guard、时钟、原调用、独立 observation、原发送路径；未新增 inc。主协调消费者及 `ApiTransferChain.cpp` 当前消费者验收文件未触碰，GUI 后置。

恢复 CodeBuddy 后由作者直接派发定向验收，至少分别核对双架构真实 APC 成功入队/失败与未投递负控、上下文成功/失败/无 CONTROL/不可读输入、映射成功/失败/不可读输出、目标代次/线程代次/Stable、QPC、原返回/LastError/NTSTATUS、短 detailLimit、1000B/定义 SHA、旧 AAIP1/普通 Raw/coverage 默认语义、无递归重复、配置和自有进程清理。**当前三类均待构建、待实测；未完成项不是“无”。** 本次只完成源码读取和定向 diff 空白检查，没有创建运行副本或新运行产物。

### 源端注释与所有权补齐（2026-11-26）

按主协调转达的最新要求，本轮为三个新协议、五个 observation 辅助模块及受影响 Hook/发送入口补中文用途注释；说明字段、局部变量、函数参数、有效位、借用句柄和资源边界，并展开单行函数、分支、多变量声明及编码字段列表。此轮只做注释、排版和局部变量可读性命名，没有改变公开字段顺序、类型、枚举数值、marker、前缀或解析/采集条件。AAIP1 共享头未改。

`shared/evidence/ApiApcFields.h` 由 API 源端独占维护；主协调仅 include，独立实现消费者 APC 关联、归档图与 CLI 投影。AAAP1 最终接口仍为上述 14 字段、`0x41505631`、`AAAP1|`，成功接受仍由 `ApiApcCallOutcome` 表达；关联还需消费者独立核对同来源、目标线程创建代次及先前实际写入范围。接受入队不证明投递或执行。后续若需要改公开协议，源端须先主动告知主协调。

本轮未新增/续接/重试 CodeBuddy，未自行运行替代验收、构建或 GUI。仅做定向源码和空白检查；三个新增协议的双架构构建、运行及性能结论仍待验。未提交或推送。

### 上下文及映射原返回接口补齐（2026-11-26，开发完成、未验收）

源端独占的两个协议头新增以下纯判定接口，均位于 `Ksword::Evidence`：

- `ApiContextOutcome ApiContextCallOutcome(const ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept`，枚举为 `ApiContextOutcome::{Unknown, Failed, Accepted}`。
- `ApiSectionMapOutcome ApiSectionMapCallOutcome(const ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept`，枚举为 `ApiSectionMapOutcome::{Unknown, Failed, Accepted}`。

两函数分别先调用自身 `ReadApiContextFields` / `ReadApiSectionMapFields`；结构无效即 Unknown，再要求原 `resultKind=StatusCode`。API 名大小写精确匹配；模块名只折叠 ASCII 大写，完整匹配指定模块名或其 `.dll` 形式，不接受路径或子串。Context 只认 kernel32/kernelbase 的 `SetThreadContext` 和 ntdll 的 `NtSetContextThread`；Map 只认 ntdll 的 `NtMapViewOfSection`。Win32 原 BOOL 位只能为 0 或 1，1 必须同时满足 resultCode=0；0 按原失败返回处理，保留原 LastError（即使为零也不反推成功）。NT 原返回低 32 位与 resultCode 的 32 位编码必须逐位一致，之后按 resultCode 有符号非负接受、负值失败。矛盾或不支持的包保持 Unknown，不修补原包。

Context 的 Accepted 仅表示上下文设置请求被接受；Map 的 Accepted 仅表示映射请求被接受，均不证明写入或执行。调用者仍需独立核对来源、目标代次、寄存器/范围有效位及关联条件。此次只追加枚举和函数，不改任何协议布局、marker、前缀、字段顺序或既有 AAIP1/AAAP1；未改 Detection、消费者或 CLI。遵照当前限制，没有构建、测试或 CodeBuddy 调用，本节不记验收通过。
