# ActionAnalyze R3 机制补充验证

日期 2026-11-24。本报告按该轮授权记录自有良性 R3 机制。后续全范围验收环境见[当前开工基线](ActionAnalyze工程开工基线.md#验收范围与运行环境)。

## 1. 本轮产品范围调整

- 回滚样本外部操作、热重载均延期，不增加占位／禁用按钮，也不实现对应 CLI 命令或副作用备份框架。
- 网络动作改为针对选中进程的连接断开，不做整机隔离，保留非目标管理连接；已有连接断开不等于禁止重连。
- 分析项目、独立采样与断点定义复用保留，横向比较继续待做。调试器自身挂起／临时断点／页保护的恢复仍为必需责任。

当前范围见[工具栏契约](ActionAnalyze工具栏逐项功能核对.md)。没有运行恶意样本、第三方注入、GUI、驱动或修改系统网络规则。

## 2. IPC 正常回归与杀父故障

工程与入口：`tools/action_transport_validation/ActionTransportValidation.vcxproj`、`Invoke-ParentDeathValidation.ps1`。Windows `10.0.19045` x64，amd64 MSBuild、MSVC `14.44.35207` HostX64，BelowNormal，`/W4 /WX`。

固定 IntDir：`tools/action_transport_validation/x64/Release/`；正式输出：`Ksword5.1/x64/Release/ActionTransportValidation.exe` 和 PDB。没有运行副本、Qt 部署或测试配置。

| 检查 | 实际结果 | 证据边界 |
| --- | --- | --- |
| 改动后正常三阶段 | 37 项断言通过，构建／运行退出 0，阶段 735／484／734 ms | 三个已声明自有应用线程；不证明完整线程集合或性能分布 |
| 杀父前负控 | 冻结子进程在 5009 ms 观察期仍存活，超过子端 4500 ms 用户态期限；父仍活着 | 被暂停的应用线程不能靠自身 deadline 清理 |
| 精确杀父 | 按本次创建的父句柄终止；子句柄按映像和创建时间核验 | 没有按进程名称或宽泛 PID 清理其它对象 |
| Job 清理 | 子进程在杀父后本次观测 4 ms 内退出；父未执行正常清理；无应急清理 | 私有不继承 KILL_ON_JOB_CLOSE Job **终止**自有子进程，不是生产目标恢复 |
| 故障监督断言 | 7 项通过，0 项失败；父子均已退出 | 单次故障实验，不提供硬时延保证 |

当前 EXE SHA-256：`D95DFD61006AF324ED3C377E2F020475F94D50E61F43B54AB1AA831780E33FE0`。此前 `83358064...` 为已被增量构建替换的旧产物身份。

初次增量构建因 `/WX` 检出总会抛出的超时路径后存在不可达 return，删除该 return 后构建成功。首次故障监督把“子进程退出码非零”作为通过条件，实际 Job 终止得到退出码 0，因此该条件失败；保留初始日志，改用真实前后存活状态、精确杀父、子进程退出与无父正常清理记录作为判据。修正仅涉及监督脚本，使用源／EXE hash 核验后的 `-UseVerifiedBuild` 执行故障路径，未无理由重复正常构建与 37 项回归。

正常运行元数据的 `parentKillFaultInjectionTested=false` 仅指正常那次调用；独立故障元数据为 true，二者不互相覆盖。文件均在 `.codex-build-logs/behavior-planning/`：`action-analyze-transport-*`、`action-analyze-parent-death-*`；首次失败保留为 `action-analyze-parent-death-initial-*`。

## 3. 进程 TCP 断连：权限门槛已复现

入口：`py -3 -B tools/action_transport_validation/validate_process_tcp.py`。使用现有 Python、R3 IP Helper、一个自建良性客户端及自有 IPv4 回环连接；另建一条非目标控制连接验证选择边界。没有触碰真实 SSH、外网连接、防火墙、网卡或驱动。

夹具固定客户端原生进程句柄及创建时间，以 PID 和四元组查找／复核唯一 ESTABLISHED 行，仅将该行传入 `SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)`。接口本身没有 PID 参数，表查询至修改之间仍可能存在竞态，不能据此宣布产品对象身份校验已经完备。

| 检查 | 实际结果 |
| --- | --- |
| 环境及权限 | Windows `10.0.19045`，进程未提权 |
| 精确对象及连接复核 | 自建子进程创建时间、PID 和唯一四元组匹配，执行前再次核验 |
| 删除调用 | 返回 **317**，Microsoft 文档定义为未提权而无法设置 TCP 项 |
| 拒绝后目标 | 原连接仍存在且可请求／响应 |
| 非目标控制连接 | 拒绝后仍可双向通信 |
| 正常结束 | 客户端退出 0，无强杀清理，无持久配置 |
| 权限负控 | **12 项断言通过，0 项失败**；整体 **BLOCKED_PERMISSION**，命令非零退出 |

`positiveDeleteTested=false`、`permissionNegativeControlPassed=true`。首次直接要求删除成功的结果保留为 `action-analyze-process-tcp-initial-*`，随后把已实际遇到的权限拒绝路径补为明确负控，没有将它升级为删除成功。当前记录为 `action-analyze-process-tcp-run.log`／`action-analyze-process-tcp-metadata.json`。

待提权环境验证的成功路径已经准备：目标连接实际中断、非目标通道继续通信、原目标可建立新连接。IPv6、UDP、禁止重连及真实 SSH 链路均未验证。当前不提权、不触发 UAC、不改系统安全配置。

依据：[Microsoft SetTcpEntry](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-settcpentry)，明确列出 317 的提权限制及接口只允许 DELETE_TCB。

可复用源码同时核对：主程序 `ksword/network/network_connection_tools.h::TerminateTcpConnectionByRecord` 已有 IPv4 原始端点与执行前连接表匹配；`shared/usermode/backend/network/Connections.cpp::CloseTcpConnection` 为既有 R3 入口。本夹具直接验证 OS 机制，没有调用这两条产品路径。后者将 `ERROR_MR_MID_NOT_FOUND(317)` 固定提示为连接不存在，与本次未提权仍有活连接的实证不符，后续接入须改为结合实际权限与回读结果诊断；本轮未修改产品。现有主程序封装还在表查询失败时允许缓存行回退，不能无条件沿用到要求严格目标身份的批量动作。已有函数可复用不等于无需接入审查。

## 4. R3 调试步进

工程：`tools/action_debug_validation/ActionDebugValidation.vcxproj`；入口：同目录 `Invoke-Validation.ps1`。父会话已读回 `DebugSession.cpp/.h`、`DebugScenarios.cpp`、固定 MASM 及声明、工程／filters、脚本、README 和实际元数据／现场／清理记录。

Windows `10.0.19045` x64、amd64 MSBuild、MSVC `14.44.35207` HostX64、BelowNormal、`/W4 /WX`；构建／运行退出均 0，最终 **106 项断言通过，0 失败**。固定 IntDir：`tools/action_debug_validation/x64/Release/`；统一 Release 产物：`Ksword5.1/x64/Release/ActionDebugValidation.exe`／PDB，SHA-256 `02E7F3E109054C67DC3E308442E8160B53985ADD1F55757DB043A071EA316BF2`。关闭 vcpkg 部署，没有测试配置或运行副本。

| 场景 | 实际证据与结果 |
| --- | --- |
| 机器指令逐语句／CALL 步入 | 真实 `EXCEPTION_SINGLE_STEP`，NOP 后 RIP 恰好前进 1；CALL 后到达固定被调入口，RSP 减少 8，栈上返回地址符合解码 CALL |
| 已知当前帧跳出 | 受控无 prologue 叶函数的 `[RSP]` 返回地址，真实临时 INT3 事件；线程、RIP、调用前 RSP 和 RAX=42 一致 |
| CALL 逐过程 | 已知 CALL 落点临时断点，核对实际返回边界及同一线程现场 |
| 提前用户断点 | 被调函数内真实用户断点先命中；不报告步过完成，恢复原字节、撤销临时断点并回读，单步原 NOP 后显式重新武装 |
| 提前异常 | 固定 UD2 引发真实首机会 `EXCEPTION_ILLEGAL_INSTRUCTION`，保存原因及现场；只按夹具已知策略跳过两字节，撤销／重武装后验证返回 |
| 停止中受控中止 | 撤销并回读自有断点、清除并回读 TF，精确终止自有子进程，排空退出事件并核对原生退出码 99 |

四个正常场景全部退出 0、无强制终止；受控中止是第五场景，明确 `forced=1 expectedAbort=1 exit=99`，不能当成原目标恢复。五个子进程均先以 `DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED` 创建、首次 Resume 前分配并回读私有不继承 KILL_ON_JOB_CLOSE Job。最终保留句柄计数为 0，元数据记录存活夹具子进程为空；该调试夹具本身未做杀父测试，不与 §2 的 IPC 实验证据混算。

前两轮失败证据分别以 `134740-1099493-48336`、`134933-5778782-39200` 标识保留：先修正 MASM PROC 地址经链接 thunk 与真实 CALL 目标不一致的问题，再纠正即时 Job ActiveProcesses 必须归零的错误判据。最终 `jobActive=1` 如实保留，退出依据为真实退出事件、进程获信号、原生／事件退出码一致及外部存活查询，而非 Job 记账值猜测。退出事件由 ContinueDebugEvent 结束时 Windows 关闭相关 debug-event 进程／线程句柄，夹具自行关闭自己另外持有的句柄及事件文件句柄。

最终证据前缀：`.codex-build-logs/behavior-planning/action-analyze-r3-debug-20261124-135112-8301522-22728-`，含 `build.log`、`run.log`、`metadata.json`、`source-review.log`。

限制：仅自有 AMD64 已知固定调用／叶函数、Win32 原生调试事件；没有通用解栈、递归／尾调用、多线程临时断点所有权、未知异常恢复、源码行、取消时获取新停点、任意进程 attach／detach 或性能结论。UD2 的显式跳过不适用于任意目标。不能替代完整线程屏障、生产追踪引擎、R0 后端或 GUI 验收。

## 5. 未完成的产品门槛

本轮不重跑此前已通过的离线模型和页面探针。报告当时仍待验的范围包括真实 A→B→C 来源／准入、未知既有线程与新线程门控、并发页面异常、共享映射／代码洞归因、生产 Agent、长程 CLI、项目持久化及故障恢复、资源与 GUI 性能。R0 审计的 29 项外部判据在该轮均未运行。
