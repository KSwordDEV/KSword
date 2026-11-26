# OwnedProcessGroup 原生夹具本机验收回执

日期：2026-11-26。执行者：本会话 CodeBuddy（自主构建、自主运行、自主记录，非只读审计）。
被测源码：`KswordCLI/ActionAnalyze/Control/OwnedProcessGroup.{h,cpp}`（主协调新写的第 6 项）。
夹具与测试：`KswordCLI/ActionAnalyze/Control/tests/OwnedProcessGroupTests.cpp`、
`Invoke-OwnedProcessGroupValidation.ps1`。

## 1. 范围与约束

- 目标是**自有良性 AMD64 子进程**：当前测试 EXE 以 `--heartbeat` 自举为子进程，两个真实工作线程各自等待私有脉冲事件并回执。父进程通过 `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` 只继承 6 个事件句柄，并把子进程放入 `KILL_ON_JOB_CLOSE` 私有 Job。心跳在附加前、暂停时、继续后、Close 后分别读回，不用模拟状态代替真实调度。
- 组层所有停止/释放结论来自 `NativeDebugOwner` 的真实原生停点（CREATE_PROCESS_DEBUG_EVENT、精确 `ReleaseRequest`、`release.receipt`），不复制组层账本逻辑做自证。
- 未构建 CLI / Qt / Light 主产品；CLI 作者后续整合。未使用 GUI、Sysmon、驱动、第三方系统目标。
- 宿主进程设为 `BelowNormal`，编译宿主限定 `Hostx64\x64\cl.exe`（构建脚本逐项回读并打印 INTDIR / OUTDIR / HOSTX64 / PRIORITY）。
- 固定 IntDir：`KswordCLI/ActionAnalyze/Control/tests/x64/Release/OwnedProcessGroup/`；统一 OUTDIR：`Ksword5.1/x64/Release/`；EXE 直接链入该 Release，无随机工程、无运行副本、无临时部署目录。
- 未提交、未暂存：执行前后 `git diff --cached --name-only` 均为 7 项（用户原有暂存），本批新增文件全部保持未跟踪。

## 2. 命令与退出码

从仓库根目录 `E:/Projects/Ksword5.1` 执行：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& 'KswordCLI/ActionAnalyze/Control/tests/Invoke-OwnedProcessGroupValidation.ps1'
```

最终执行（新增 Close 后 Recover 断言）与之前两次稳定复跑（PE 时间戳/PDB GUID 导致哈希逐次不同）：

| 项 | 最终执行 | 前序复跑 1 | 前序复跑 2 |
| --- | --- | --- | --- |
| BUILD_EXIT_CODE | 0 | 0 | 0 |
| RUN_EXIT_CODE | 0 | 0 | 0 |
| 结果 | `RESULT=PASS checks=1018` | `RESULT=PASS checks=1017` | `RESULT=PASS checks=1017` |
| EXE SHA256 | `E9F9EE9959CBC1F2CF89E1703DD99DB29C0740FCEA28742BAFC97F649DBD09BC` | `5B4B5C358C40262EB93BEA0CD92E15305053AEF1D7E4E6D653FF08E243967D56` | `D91801894F33E96298884BFD5B59DADC0CEC048888B21108A674F4C4E7BD56C9` |
| OS_BUILD | 10.0.19045.0 | 10.0.19045.0 | 10.0.19045.0 |
| 证据前缀 | `.codex-build-logs/behavior-planning/action-analyze-owned-process-group-20261126-074207-3555178-34620` | `.codex-build-logs/behavior-planning/action-analyze-owned-process-group-20261126-074031-7776751-40428` | `.codex-build-logs/behavior-planning/action-analyze-owned-process-group-20261126-074100-3158249-30488` |

每组前缀下有 `-build.log`（含 INTDIR / OUTDIR / HOSTX64 / PRIORITY / 各编译单元 / BUILD_EXIT_CODE）和 `-run.log`（含 OS_BUILD / RUN_EXIT_CODE / EXE_SHA256 / RESULT）。

### 2.1 续接批次：SaveRejected 与 ProcessGroupMemorySnapshot

主协调收到 CLI 作者指出的票据缺口后已修 `OwnedProcessGroup`：格式合法 `group/N` 的准入拒绝现在冻结内容/错误并推进 highWater。本会话据此调整旧测试（不再用同一 ID 纠正过期令牌后执行），补拒绝票据与 control adapter 最小集，做**一次适用增量构建 + 真实运行**（编译错误修正后的重建除外），不重复无变化复跑。前次 1018 项历史保留在上表，不作为本批通过结论。

| 项 | 续接批次最终执行 |
| --- | --- |
| BUILD_EXIT_CODE | 0 |
| RUN_EXIT_CODE | 0 |
| 结果 | `RESULT=PASS checks=1313` |
| EXE SHA256 | `5E393B67EAD9A9DAF7D06CD19A933E089C0B717B826986F480A92CD7A3897025` |
| OS_BUILD | 10.0.19045.0 |
| 证据前缀 | `.codex-build-logs/behavior-planning/action-analyze-owned-process-group-20261126-074838-0121536-14396` |

该次链接源新增 `ProcessGroupMemorySnapshot.cpp`、`Memory/SelectedMemorySnapshot.cpp`、`Memory/PassiveDirtyMemory.cpp`，仍只产出固定 IntDir 与统一 Release 下的独立测试 EXE，未构建 CLI/Qt/Light 主产品。

## 3. 实际断言（均由真实进程与原生事件支撑）

### 3.1 Configure 只 pin 不暂停（容量/身份门禁）

- 空集合、未显式授权、`Unspecified` disposition、17 个目标均被拒，且 `Query()` 仍为 `Idle`，不发布部分集合。
- 16 个**真实进程**配置成功：`Ready`、`clean`、16 项固定顺序成员、无 `operation`；逐项 `creationFileTime` 与独立 `OpenProcess`/`GetProcessTimes` 一致；逐项 `CheckRemoteDebuggerPresent == false`，两个心跳线程都响应。第二次 Configure 被拒。
- 错误代次（`creationFileTime + 1`）、PID 0、自身 PID 在 16 项边界内进入 Pin 并分别被拒；重复 PID 在组层被拒（`Conflict`），未产生附加。
- 配置后 17 项只能作为容量上界拒绝证据；身份类门禁改在 16 项上验证，避免被容量门禁提前短路。

### 3.2 全组与子集 Pause、真实停点、成员/组汇总分离

- 3 个成员 Pause 后 `group/1` 票据保留 3 项成员回执；轮询到 `HeldComplete` 时逐成员 `control->group->state == HeldComplete`、`stop` 有值、`clean == false`，且三个目标都 `CheckRemoteDebuggerPresent == true`、心跳在 45ms 内无回执。
- 重复 `group/1` 返回 `Duplicate`，`operation` 为原票据而 `state` 为当时现态；三次心跳仍冻结，证明没有第二次暂停。
- 同一 `group/1` 改成 2 项目标返回 `Conflict`，原停点不变。
- 错误代次令牌（篡改 `stateRevision`）：单项与“有效+过期混合”的两项 Continue 都在**任何释放前**整体拒绝；三项仍全部冻结，证明不存在部分放行。
- 单成员 `group/2` 继续后组汇总降为 `HeldPartial`：成员 0 `clean` 且无 `stop` 并恢复心跳/脱离，成员 1、2 仍持有精确停点且心跳冻结。
- 重复 `group/2` 返回 `Duplicate`，已恢复成员不被再次操作，其它成员仍停。
- 新一代 `group/3` 暂停成员 0：新 `backendInstanceId` 与新 `NativeEventKey`（与旧事件整体不等）。旧 `Recover("group/2")` 只回读原继续票据，新代次停点仍冻结且事件身份不变。
- 全集 `group/4` 继续三项后组为 `Active`，三目标均脱离并恢复心跳；`Recover("group/4")` 回读三项原票据且不再产生动作；以 Pause 票据或未知票据 Recover 均被拒。
- Close 后 `Closed`/`clean`，三目标仍存活且心跳继续；Close 后新 Pause 被拒，Query 保持 `Closed`。Close 后 `Recover("group/4")` 仍返回原继续票据的 3 项回执且不改变 `Closed`，证明清退不丢弃原票据。
- 另设独立场景：`Pause` 后**仍持有时**直接 `Close`，逐成员 `CheckRemoteDebuggerPresent == false`、目标仍存活且心跳恢复，证明 Close 是真实脱离而不是记账清零。

### 3.3 已附加冲突与部分成员失败

- 另一个 `backendInstanceId` 的 `NativeDebugOwner` 先附加并持有成员 1 的真实停点；组 Pause 三项时成员 0、2 接纳，成员 1 返回 `Rejected` 且 `win32Error == ERROR_BUSY` 且 `clean`（真实 ERROR_BUSY 回执，不是模拟标志）。
- 组汇总为 `HeldPartial`：成员 1 无 `stop`，不能把“两个成员原生 Hold”算成整个进程集合完整；健康两成员心跳冻结。
- 继续健康两成员后它们脱离恢复；外部 owner Close 后冲突成员才恢复；组 Close 为 `clean`。

### 3.4 目标自然退出与错误代次

- 目标自然退出后再 Configure，`Pin` 因 `WaitForSingleObject != WAIT_TIMEOUT` 返回 `ERROR_PROCESS_ABORTED`，组层报 `IdentityMismatch` / `process-group-pin-instance`。
- 配置完成后目标自然退出再 Pause，原生 owner 返回 `Rejected`，组为 `Active` 且 `clean`，不伪称持有。

### 3.5 128 滚动票据与无第二套 Suspend 账

- 非规范 ID、`group/0`、`group/01` 均被拒（不进入回执目录）。
- 64 次真实 Pause→Hold→Continue 周期占满 `group/1..group/128`，每轮都有 `ReleaseResult::Continued` 原生回执且目标恢复心跳。
- 第 129 张票据仍受理；此时 `group/1` 已淘汰，重放返回 `ReplayExpired`；继续第 130 张后 `group/2` 淘汰，其 Recover 返回 `ReadbackRequired`。
- 句柄稳态：首轮后 `GetProcessHandleCount` 为 109，第 2、3、63 轮仍为 109，最终回读相等。首轮相对配置后基线 +3 属于一次性初始化，已单独核对并非逐代增长；用例从第二轮起断言稳态，未把首轮增长算作通过。组层只复用 `NativeDebugOwner` 的继续票据，没有 `SuspendThread` 第二套账。

### 3.6 续接：格式合法拒绝也占票据（SaveRejected）

- 旧测试已改：过期令牌的单次/混合 Continue 分别用新 `group/2`、`group/3`，真实继续改用 `group/4`；后续新代次 Pause、全集 Continue、Close 后 Pause/Recover 相应顺延为 `group/5..group/7`，不再以同一 ID “纠正内容后执行”。
- 拒绝的 `group/2` 冻结首次 `ledgerResult=StaleRevision`、`stage=process-group-stale-stop`、`win32Error=ERROR_INVALID_STATE`、空 outcomes；其 `Recover` 只回读该拒绝并返回 `ReadbackRequired`，不执行原生释放，原停点仍精确相等且目标仍冻结。
- 独立场景：`group/1` 用“未配置目标”触发真实 Pause 拒绝，同内容重复返回 `Duplicate` 且回执保留首次 `IdentityMismatch`/`ERROR_INVALID_PARAMETER`，目标从未附加且心跳继续；同 ID 换成有效目标返回 `Conflict` 且仍未附加；新 `group/2` 才成功附加。随后 `group/3` 的过期 Continue 同样冻结拒绝回执，`Recover` 只回读、同内容 Duplicate、换有效令牌 Conflict，原停点保持；新 `group/4` 才释放。
- 滚动目录用 `group/1` 作为拒绝票据种子，64 轮真实 Pause/Continue 占 `group/2..group/129`；写入第 129 张时淘汰最低序号，拒绝票据 `group/1` 重放得到 `ReplayExpired`，`group/130` 后 `group/2` 淘汰且 Recover 得 `ReadbackRequired`。

### 3.7 续接：ProcessGroupMemorySnapshot control adapter 最小集

- 自有良性目标：测试 EXE 以 `--memory` 自举子进程，继承共享节与 ready/stop 事件，写入自身视图基址和 64 字节已知模式（由父进程在同一物理内存读回校验），置于 `KILL_ON_JOB_CLOSE` 私有 Job。不修改系统进程、不注入、不改目标保护。
- `LiveRead` 无 stop：真实只读采样成功，`completeRange=true`，捕获的子范围字节与已知值逐字节相等；`before/after` 为空、`heldAtBothChecks=false`，请求中的 sample/range 保持原选择。
- `LiveRead` 带 stop：被 `process-memory-live-read-cannot-borrow-stop` 拒绝（`ERROR_INVALID_PARAMETER`、无 snapshot），不降级为实时读取，目标仍为未附加。
- `HeldEvent` 完整令牌 + 同 sample：读前/读后令牌逐字段相等且等于请求 stop，`heldAtBothChecks=true`，64 字节与已知模式相等；读后组仍 `HeldComplete`、停点不变、`CheckRemoteDebuggerPresent=true`，证明读取未继续目标。
- 旧令牌（`stateRevision+1`）与错误 sample 均被 `process-memory-stale-stop` 拒绝（`ERROR_INVALID_STATE`、无 snapshot、无 before/after），原停点精确不变且目标仍持有。
- Close 后目标脱离并正常退出 0；未重复测 `SelectedMemorySnapshot`/`PassiveDirtyMemory` 核心（由另一 CodeBuddy 负责）。

## 4. 失败与修复记录

按时间顺序，均为**测试/夹具侧**问题；`OwnedProcessGroup.{h,cpp}` 源码未发现需要修改的缺陷，本批未改产品源码：

1. `C2664`：`std::span` 不接受花括号初始化列表。改用显式 `std::vector<ProcessGroupTarget/ProcessGroupStop>` 帮助函数与具名变量。
2. 运行失败 `wrong-creation-generation-rejected`：身份门禁用例误传 17 项，先被容量门禁短路。改用 16 项真实目标作为身份用例基数。
3. 运行失败 `evicted-pause-ticket-rejected`：第 128 张票据刚填满目录，`Reserve` 在下一次 Save 前才淘汰。把“淘汰后拒绝重放”断言移到第 129/130 张票据之后。
4. 运行失败 `repeated-native-generations-release-handles`（106→109）：诊断打印确认第 0/1/2/63 轮均为 109，增长只发生在首轮（`CoCreateGuid`/OLE 与首次附加的一次性初始化）。把稳态基线改到第 1 轮之后，并在本回执如实披露首轮 +3。
5. 初稿残留占位代码与必然失败的哨兵轮询，已在首次构建前删除。
6. 续接批次 `C2653: 'memory' is not a class or namespace name`：测试 TU 的 using 指令未能解析嵌套命名空间，改用 `ks::cli::action_analyze::memory::Range/Plan` 全限定后编译通过。
7. 续接批次首轮运行的票据 ID 复用会让旧断言在 `SaveRejected` 新语义下失效，已按 3.6 的编号重排，未修改产品源码以适配测试。

未以“派发成功”“命令启动成功”或“源码可编译”替代运行结论；上述每次失败都对应源码/断言修正后重新完整构建与运行。本批未改 `OwnedProcessGroup`、`ProcessGroupMemorySnapshot` 或其它产品源码，仅调整测试与独立构建脚本。

## 5. 清理

- 心跳子进程与内存子进程全部置于 `KILL_ON_JOB_CLOSE` 私有 Job；续接批次最终运行后 `tasklist /FI "IMAGENAME eq ActionAnalyzeOwnedProcessGroupValidation.exe"` 为 “No tasks are running”，无残留心跳或内存子进程。内存共享节仅由父子进程持有，随进程退出关闭。
- 未创建任何测试配置文件或运行副本，因此无该类临时配置需要删除。
- 固定 IntDir 仅含编译中间产物（`.obj`/`.pdb`），位于 `KswordCLI/ActionAnalyze/Control/tests/x64/Release/OwnedProcessGroup/`（与同目录其它原生验证一致，非随机目录、非系统临时目录）；测试 EXE 在统一 `Ksword5.1/x64/Release/ActionAnalyzeOwnedProcessGroupValidation.exe`。两者均未纳入暂存。
- 日志仅文本，位于 `.codex-build-logs/behavior-planning/action-analyze-owned-process-group-*`。
- 用户原有 7 项暂存未改动；未执行 `git add` / `git commit`。

## 6. 未验证 / 边界

- 未验证 owner 进程异常死亡后的接管、保护进程/提权进程、WOW64 与非 AMD64 目标、多原生事件并发待决、新线程在创建事件前的完整门控，以及单个进程内部原生冻结组为 `HeldPartial`（部分线程未冻结）的情形；本批的“部分”是成员级失败与组汇总分离。
- 未验证 Close 过程中出现原生清退失败时的未决责任保留（`Closing`/`RecoveryRequired`）：本组只用 Pause/Continue，良性目标下 Close 均可一次脱离，缺少可确定性注入 detach 失败的夹具；已验证的是正常清退后原继续票据仍可回读。
- 未验证 `NativeStepRuntime` 的步进语义；底层 `NativeDebugOwner`/`NativeStepRuntime` 正由另一作者修步进，本批只把它们作为链接依赖，不覆盖也不重复其步进验收。
- 未验证 CLI / Qt / Light 的真实命令入口、JSONL/REPL 接入与三端一致性；按分工由 CLI 作者后续整合。
- 未验证 R0/驱动、GUI、Sysmon、第三方系统目标或长时间性能阈值；本机 OS 为 19045。
- 句柄核对于 64 代稳态成立，不能外推为任意代次后绝对不变；PE 哈希逐次构建不同，不能用单次 SHA 作为源码不变证明。
- 内存适配器只覆盖 control adapter 最小集，未重复 `SelectedMemorySnapshot`/`PassiveDirtyMemory` 核心（另一 CodeBuddy 在测）；未验证跨页范围、不可读/无权限页、取消、目标退出中的读取、外部写入者并发以及进程级原子性——`heldAtBothChecks` 只表示本 owner 令牌未变，内存仍是逐页采样。
- Configure 只 pin 身份、实际 Pause 才核对 AMD64/同用户是刻意两阶段；本批真实测试未指出错误执行，故未扩改该行为。
