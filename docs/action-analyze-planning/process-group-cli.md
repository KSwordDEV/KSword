# 第 6 项：进程集合 CLI 正式入口本机验收回执

日期：2026-11-26。执行者：本会话 CodeBuddy（自主构建、自主运行、自主排查与落盘，非只读审计）。
被测对象：正式 `KswordCLI.exe` 的 `analyze process-group session` 入口（`KswordCLI/ActionAnalyze/Cli/ProcessGroupCommand.{h,cpp}`）与其底层 `KswordCLI/ActionAnalyze/Control/OwnedProcessGroup.{h,cpp}`。
本批只做命令层实测与夹具维护；未修改底层、原生 owner、断点命令与其它作者代码，未做 git 提交、暂存或分支操作。

## 1. 正式入口

```
KswordCLI.exe analyze process-group session --targets PID:CREATION,PID:CREATION --confirm --disposition resume-detach [--input repl|jsonl]
```

- `--targets`：1–16 个规范十进制 `PID:CREATION`（创建 FILETIME）实例；同一 PID 重复拒绝。
- `--confirm` 与 `--disposition resume-detach` 必填，缺任一项或 `--input` 非 `jsonl|repl` 时入口以退出码 `1` 拒绝。
- R3 后端；`--backend` 只能是 `r3`。无自动后代、无系统目标。
- 配置阶段只固定并核对实例身份，不附加、不暂停（hello 回执 `groupProtocol.configurationPauses=false`）。

协议（本次按源码逐字段核对后实现，未凭推测）：

| 面 | 用法 |
| --- | --- |
| JSONL | `control.pause` `params:{}`（初始固定全集）或 `params:{targets:[{pid,creationFileTime}]}`；`control.query` `params:{}`；`control.continue` `params:{}` + `expected:{stops:[完整 members[].stop 原值]}`；`control.recover` `params:{requestId:原 continue 的 group/N}`；`controller.shutdown` `params:{}` |
| REPL | `status`、`pause group/N [all\|PID:CREATION,...]`、`continue group/N PID:CREATION:GROUP_ID:STOP_ID:BACKEND_ID:SERIAL:REVISION,...`、`recover group/N`、`close` |
| 票据 | pause 与 continue 共用严格递增 `group/N`；同 ID 同内容为 `duplicate`（不重新执行），同 ID 异内容为 `conflict`；格式正确但被拒绝的请求同样占用该 ID；窗口 128 项，淘汰后旧 ID 为 `replay-expired` |
| 会话 | 变更类请求必须带 hello 的 `session`；错误 session 与缺失 session 分别以 `wrong-session`／`session-required` 拒绝 |

## 2. 构建、退出码与产物身份

正式 CLI 增量构建与整批实测在**同一个 PowerShell 线程、同一把命名互斥**下完成：

```
tools/action_analyze_validation/cli/Invoke-ProcessGroupCliValidation.ps1
```

| 项 | 值 |
| --- | --- |
| 互斥 | `Local\KSword.ActionAnalyze.CliValidation`，`WaitOne` 取得所有权，`try/finally` 在同线程 `ReleaseMutex`（最终批次起始时该互斥被上一个异常退出的持有者遗弃，`WaitOne` 抛 `AbandonedMutexException` 但仍授予所有权，脚本记录该事实后照常执行并正常释放） |
| 宿主优先级 | `BelowNormal`（构建与实测子进程沿用） |
| MSBuild | `D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe`（64 位） |
| 构建参数 | `/p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 /p:SolutionDir=<repo>\Ksword5.1\ /p:BuildProjectReferences=false /t:Build /m:1 /v:minimal` |
| 构建退出码 | `0`（`BUILD_RESULT=SUCCESS`） |
| 实测退出码 | `0`（`RESULT=PASS checks=530`） |
| IntDir | `E:\Projects\Ksword5.1\KswordCLI\x64\Release`（固定，未改） |
| OutDir | `E:\Projects\Ksword5.1\Ksword5.1\x64\Release`（统一正式 Release，未改） |
| HostX64 | `D:\Software\VS\VC\Tools\MSVC\14.44.35207\bin\HostX64\x64`（`VC_ExecutablePath_x64`） |
| 受测 exe | `Ksword5.1\x64\Release\KswordCLI.exe` |
| SHA-256 | `6D18CAD805CE9DBDD31CDF642D4094FAA47A5E22B38B4E06A284B1BF46202C64` |

`CLToolPath`／`CLToolExe`／`VCBinDir` 在本工程不是已定义的 MSBuild 属性，`-getProperty` 回读为空；等价的 HostX64 工具路径由 `VC_ExecutablePath_x64` 给出并已校验为 `HostX64\x64`。构建前打印并校验了绝对 `IntDir`／`OutDir`，与工程既有固定值一致。

并行开发会话同时链接同一正式产物时，链接阶段会以 `LNK1104` 失败。脚本只在识别到该占用时等待 20 秒后重试同一增量构建（不重复编译），其它失败立即中止并保留输出。

证据：

- 日志：`.codex-build-logs/action-analyze-process-group-cli.log`（含每一步 TX/RX 原始帧）
- 小型元数据：`.codex-build-logs/action-analyze-process-group-cli.json`
- 最终批次时间：`2026-11-26T04:15:20-04:00`（日志首行）

### 首错记录

1. 第一次构建失败在**他人新增的** `KswordCLI/ActionAnalyze/Control/NativeExecutionEvidence.cpp`（`C2065: EXCEPTION_DEBUG_EVENT 未声明`），该文件缺少 Windows 头入口。本批**未编辑该文件**，等待作者在同日 03:51 自行补齐后继续；本批自身的 `ProcessGroupCommand.cpp` 与 `OwnedProcessGroup.cpp` 在同一次构建中已成功编译。
2. 中途两次链接失败为 `LNK1104`（并行开发会话同时链接同一个正式产物），不是产品缺陷，已由构建脚本按占用识别后等待重试。
3. 夹具首轮失败全部是本批夹具自身的可修正问题（详见第 4 节末段），与产品行为无关。

## 3. 自有受控目标

夹具源码 `tools/action_analyze_validation/cli/product_process_group_child.c`，由本批新增；夹具驱动 `tools/action_analyze_validation/cli/product_process_group.py`。

- 每个目标是本批自己创建的 AMD64 子进程，两个真实工作线程，共享内存里维护单调心跳计数，并用继承的事件句柄提供脉冲应答。
- 编译：HostX64 `cl.exe`，`/W4 /WX /O2 /MT /utf-8`；固定 IntDir `KswordCLI/ActionAnalyze/Control/tests/x64/Release/ProcessGroupTarget/`，统一 OutDir `Ksword5.1/x64/Release/`，产物 `ActionAnalyzeProcessGroupTarget.exe`（另编译 WOW64 版 `ActionAnalyzeProcessGroupTarget32.exe` 用于非 AMD64 拒绝用例）。
- 未接触 Explorer、DWM、系统目标或用户既有进程；未使用 Sysmon、驱动、第三方目标；未启动 GUI，未构建 Qt 或 Light。
- 目标退出全部由自身 `stop` 事件触发并读回退出码 `0`；失败路径才由夹具强制终止。

判定依据是外部可观测事实：共享内存计数在冻结时停止前进、恢复后继续前进；`CheckRemoteDebuggerPresent` 独立回读附加状态；脉冲在冻结时不应答、恢复后应答。命令回执与这些外部事实逐项交叉核对。

## 4. 实测项与结果

本次共 530 项断言全部通过（`RESULT=PASS checks=530`）。

| # | 实测项 | 结果 |
| --- | --- | --- |
| 1 | 正式 CLI 帮助：`help "analyze process-group session"` 列出语法、`--targets`／`--confirm`／`--disposition resume-detach` 与 JSONL／REPL 方法 | 通过，退出码 `0` |
| 2 | 配置只核对不暂停：hello 的 `configurationPauses=false`，成员 `control=null`、`stop=null`，三个目标均未被附加、心跳计数持续前进 | 通过 |
| 3 | 查询不生成动作：`control.query` 回读 `operation=null`，不改变集合状态 | 通过 |
| 4 | 全集暂停：`control.pause params:{}` → 集合 `held-complete`，三成员各有真实停点令牌，原生回执 `state=held`、`stage=create-process-debug-event-held`、`pending.ledgerOwned=true`；三个目标计数冻结且脉冲无应答 | 通过 |
| 5 | 精确全部继续：按 `members[].stop` 原值提交 → 三成员 `release.result=continued`，全部脱离并恢复计数 | 通过 |
| 6 | 同 ID 同内容重放：重复暂停与重复继续均返回 `duplicate`，票据内容逐字段不变，目标未被二次操作 | 通过 |
| 7 | 同 ID 内容冲突：同 `group/1` 换内容 → `conflict`／`process-group-request-conflict`，集合状态不变 | 通过 |
| 8 | 令牌拒绝：错 `stateRevision`、错 `event.serial`、错 `backendInstanceId` 三种令牌全部 `stale-revision`／`process-group-stale-stop`，且**没有任何成员被局部放行**（三成员仍冻结、仍附加、停点未变） | 通过 |
| 9 | 过期票据：已退出目标上循环 129 个 `group/N`（不产生真实附加），随后 `group/1` → `replay-expired`／`process-group-replay-expired`，无操作、无附加 | 通过 |
| 10 | 拒绝也占 ID：`group/2` 被拒后再用同 ID 同内容 → `duplicate`；同 ID 换内容 → `conflict`，两者都不释放任何成员 | 通过 |
| 11 | 子集暂停／继续：只暂停一个成员 → 集合 `held-partial`，其余成员保持运行；只继续该成员 → 仅该成员恢复，其余成员状态不变；对仍被持有的成员再次暂停 → `invalid-transition`／`process-group-member-still-owned` | 通过 |
| 12 | 成员退出后的部分失败：一成员在配置后退出 → 该成员 `rejected`／`process-already-exited`／`1067`，另一成员仍真实持有并可被单独继续 | 通过 |
| 13 | Recover：按原 continue ID 回读原票据（`action=recover`，三成员票据不变，不暂停任何目标）；对暂停票据、未知 ID、被拒的 continue 票据分别 `readback-required`／`process-group-original-release-required`，且从不执行 | 通过 |
| 14 | 关闭：`controller.shutdown`／`close` → 集合 `closed`、`clean=true`、成员 `state=closed`／`attached=false`，目标仍存活、仍运行、已脱离；CLI 自行以退出码 `0` 结束 | 通过 |
| 15 | 身份门禁：错误 creation → `process-group-pin-instance`／`identity-mismatch`；重复 PID → `process-group-duplicate-pid`／`conflict`；系统目标 PID 4 → `process-group-pin-instance`／`ERROR_ACCESS_DENIED`；三者均退出码 `3`，且从未附加目标 | 通过 |
| 16 | 授权与输入门禁：缺 `--confirm`、`--disposition` 非 `resume-detach`、`--input` 非法 → 退出码 `1` 与明确错误文本 | 通过 |
| 17 | 会话门禁：错误 session id 与错误 epoch → `wrong-session`；缺失 session 的暂停与关闭 → `session-required`，集合与目标均未受影响 | 通过 |
| 18 | 非 AMD64：WOW64 目标在暂停时被原生层拒绝 `native-amd64-target-required`／`ERROR_NOT_SUPPORTED`，从未附加 | 通过 |
| 19 | REPL 全流程：`status`、`pause group/1 all`、`continue group/2 <七段令牌>`、`recover group/2`、`recover group/1`（被拒）、`close` 全部按预期，CLI 退出码 `0` | 通过 |
| 20 | 夹具自检：心跳前进、脉冲应答、自然退出码 `0` | 通过 |

命令层未发现需要修改的缺陷：`ProcessGroupCommand.{h,cpp}` 与 `OwnedProcessGroup.{h,cpp}` 在本批全部通过，未做任何源码改动。首轮失败全部来自本批夹具自身的可修正问题（`LONG32` 与 `LONG` 宽度不匹配、`CreateFileMappingW` 参数个数、`wintypes.SECURITY_ATTRIBUTES` 不存在、共享内存结构体未取 `contents`、构造失败未清退子进程、REPL 下误用 JSONL 查询），已逐项修正后重跑通过；产品行为未因此改变。

## 5. 是否复用原生 Pause 范围

- 复用：底层 `NativeDebugOwner` 的原生停点语义（附加后由 CREATE_PROCESS 原生事件形成真实持有、精确 `ReleaseRequest` 继续、继续后脱离）以及 `OwnedProcessGroup` 的票据与成员语义。命令层只负责协议解析与投影。
- 未复用为证据：底层原生夹具 `KswordCLI/ActionAnalyze/Control/tests/OwnedProcessGroupTests.cpp` 的 1,072 项结论仍是独立回执，本批没有把它当作本命令层的实测结果；本批所有暂停、继续、脱离与拒绝结论都由正式 CLI 的外部可观测事实独立取得。
- 未覆盖：`control.memory.snapshot`（同一入口内并发开发中的内存快照能力）不在本批范围；Qt／Light 端同能力仍只有源码接线，见 [进程集合桌面接线](process-group-desktop.md)。

## 6. 清退与清理

- 夹具产物：`Ksword5.1/x64/Release/ActionAnalyzeProcessGroupTarget.exe`、`ActionAnalyzeProcessGroupTarget32.exe` 与固定 IntDir `KswordCLI/ActionAnalyze/Control/tests/x64/Release/ProcessGroupTarget/` 在本批结束时全部删除；实测后复核目录中已无这两个文件，该 IntDir 已不存在。
- 进程：所有自有目标进程在结束时均已退出或被夹具终止；实测后复核 `ActionAnalyzeProcessGroupTarget*` 与 Release 目录下的 `KswordCLI.exe` 进程均为空。
- 未动：正式产物 `Ksword5.1/x64/Release/`、夹具源码、本批新增的脚本与日志。源码与证据保持未跟踪状态，未 `git add`／`commit`／`stash`／`reset`，未改动用户原有暂存。
- 日志与元数据留在 `.codex-build-logs/`（该目录不在版本控制内）。

## 7. 未验证边界

1. **原生故障注入未执行。** `KswordCLI/ActionAnalyze/Control/` 下没有可用的受控故障注入钩子，因此本批的 Recover 只验证了**无故障路径**的原票据回读：它证明了「按原 continue ID 回读同一份释放票据、错误 ID 一律 `readback-required` 且从不执行」，**不能**据此宣称「原生 Continue 失败后由 Recover 真正恢复」。真实脱离失败、事件不确定（`continuationIndeterminate`）与 `firstRecoveryFailure` 的恢复路径未实测。
2. **未决清退时的原 owner 保留未实测。** `End()` 中「原所有者保留并等待清退」的分支需要真实的未决原生责任，本批无法在无故障注入条件下触发；本批所有关闭路径都已是 `clean`，CLI 均为自行退出（`CLI_EXIT=0 SELF_EXIT=true`），夹具从未强杀带未决责任的 CLI 进程。
3. **窗口过期用的是已退出目标。** 按要求，128 项窗口的过期用「已退出目标 + 无副作用循环」覆盖，没有为单项做 130 轮真实暂停；因此真实附加下的票据淘汰时序未单独观测。
4. **无全局、无自动后代、无新线程门控。** 本入口只控制用户显式枚举的固定实例集合（上限 16），不派生、不跟随后代、不做新线程准入；系统目标、Explorer、DWM 与其它第三方目标一律不接触。
5. **普通 R0 后端未涉及。** 本入口固定 R3；普通 R0 与指定来宾环境不在本批范围。
6. **桌面未验。** Qt／Light 的进程集合页面仍只有源码接线，未构建、未启动窗口；本回执只覆盖 CLI 端。
7. **非 Windows 与其它架构未涉及。** 仅本机 Windows 10 x64，宿主与目标均为原生 AMD64。
