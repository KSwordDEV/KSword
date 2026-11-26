# 持有停点内存归档 wrapper 最小原生验收回执

日期：2026-11-26。执行者：本会话 CodeBuddy（自主构建、自主运行、自主记录，非只读审计）。

被测源码：`KswordCLI/ActionAnalyze/Project/ProjectMemorySnapshot.cpp` 的
`WriteProcessGroupMemorySnapshot`（主协调新补，未跟踪文件）。该 wrapper 把完整
`ProcessMemorySnapshotResult` 写入采样专属 `raw-memory/N`，冻结请求身份与读前/读后令牌，
并在 plan 元数据写入可选 `readContext`。

复用边界：原生 `ProcessGroupMemorySnapshot` 控制适配器的真实 held/live 最小集与
1313 项组矩阵见 [process-group-native.md](process-group-native.md)。本批直接调用该适配器，
**不重跑 1313 项或任何内存核心矩阵**；`SelectedMemorySnapshot` / `PassiveDirtyMemory` /
`WriteSelectedMemorySnapshot` 旧函数由另一 CodeBuddy 测试，本批不改其逻辑或接口；
`MemorySnapshotReader` 由另一作者加兼容，本批不改它、也不链接它，直接用
`ProjectDocument::ReadRawEvidenceSegment` 回读原记录。

## 1. 范围与约束

- 单一自有良性 AMD64 子进程：测试 EXE 以 `--memory` 自举，继承共享节写入自身视图基址和
  64 字节已知模式，置于 `KILL_ON_JOB_CLOSE` 私有 Job；父进程只读核对同一物理内存。
  不碰系统进程、不注入、不改保护、不用 Sysmon/驱动/GUI。
- **先创建 sample，再以该 sample 的 `sampleId` 配置 group**；`Plan.sampleId` 与 group 身份同源。
  全流程只有一次 `Pause`、一次精确 `Continue`，归档写入期间目标始终持有且仍被附加。
- 宿主进程设为 `BelowNormal`，编译宿主限定 `HostX64\x64\cl.exe`（脚本逐项回读并打印
  INTDIR / OUTDIR / HOSTX64 / PRIORITY / WARNINGS）；编译参数 `/W4 /WX /std:c++20 /permissive-`。
- 固定 IntDir：`tools/action_analyze_validation/group_memory_archive/x64/Release`；
  统一 OUTDIR：`Ksword5.1/x64/Release`；测试 EXE 直接链入该 Release，无随机工程、无运行副本、
  无临时部署目录。测试工程按标准登记为
  `tools/action_analyze_validation/group_memory_archive/ActionAnalyzeGroupMemoryArchiveValidation.vcxproj`
  （含 `.filters`，`PreferredToolArchitecture=x64`，`WarningLevel=Level4` + `TreatWarningAsError`）。
- 未构建 CLI / Qt / Light 主产品、驱动、Sysmon 或系统进程。
- 未提交、未暂存：执行前后 `git diff --cached --name-only` 均为用户原有 7 项。

## 2. 命令与退出码

从仓库根目录 `E:/Projects/Ksword5.1` 执行：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& 'tools/action_analyze_validation/group_memory_archive/Invoke-GroupMemoryArchiveValidation.ps1'
```

最终执行（含全部断言）：

| 项 | 最终执行 |
| --- | --- |
| BUILD_EXIT_CODE | 0 |
| RUN_EXIT_CODE | 0 |
| WATCHDOG | False |
| 结果 | `RESULT=PASS checks=359 failures=0` |
| EXE SHA256 | `7EBE3BD4676D7A4628A4A2BBBFDE197C714CBEC2E461000C0FD7CAB44149E94F` |
| OS_BUILD | 10.0.19045.0 |
| 残留夹具进程 | 无 |
| 证据前缀 | `.codex-build-logs/behavior-planning/action-analyze-group-memory-archive-20261126-080847-1367977-36228` |

前缀下有 `-build.log`（含 INTDIR / OUTDIR / HOSTX64 / PRIORITY / WARNINGS / 全部编译单元 /
BUILD_EXIT_CODE）、`-run.log`（OS 输出与 `RESULT`）和 `-metadata.txt`（各退出码、哈希、残留、
RESULT、日志路径）。测试 EXE 与中间产物位于上述固定 IntDir 和统一 Release，均未暂存。

## 3. 实际断言（359 项，均由真实进程与原生停点支撑）

### 3.1 真实 held 读取与独立 sample raw-memory/1

- 真实 `LiveRead` 采样成功后，同一 group 精确 `Pause` → `HeldComplete`，读前/读后令牌逐字段
  等于请求 stop，`heldAtBothChecks=true`，读后组仍 `HeldComplete` 且 `CheckRemoteDebuggerPresent=true`。
- wrapper 写入独立 `raw-memory/1`，回执 `verified`、`ordinal=1`、`completeRange=true`、
  `capturedBytes=64`、`unavailablePages=0`、`flushed` 与整段 SHA-256 均有效。
- 归档写入前后各读回一次 group：停点仍精确相等、目标仍附加，**没有 Continue 目标**。
- 同一 `ProjectDocument` 读句柄回读：`readContext.source=held-event`、`stage` 原值、
  `win32Error`、`before`/`after` 四项令牌字段均等于真实 stop、`heldAtBothChecks=true`；
  页 `sha256` 等于从归档原字节独立计算的 SHA-256，64 字节逐字节等于夹具已知模式，
  段前缀哈希等于回执 SHA。

### 3.2 heldAtBothChecks=false 且 after 变化：保留证据不伪称 held

- 以真实 held 捕获为基，保留 `before==request.stop`，将 `after` 改为 `stateRevision+1` 的令牌，
  设 `heldAtBothChecks=false`；wrapper 仍写入并回读成功。
- 回读 `readContext.source` 仍为 `held-event`，`heldAtBothChecks=false`，`before` 保持原令牌、
  `after` 保持变化后的令牌；页字节与 SHA 独立核对完整。历史停点变化不被重分类为 live，
  也不声称两次检查都持有。

### 3.3 Live 新 wrapper 与旧 live writer 格式兼容

- 新 wrapper 写 `live-read` 格式：`source=live-read`、`heldAtBothChecks=false`、
  `before`/`after` 均为 null，字节完整。
- 旧 `WriteSelectedMemorySnapshot` 在同 sample 的 `raw-memory/2` 以真实前序链接写入，回读
  plan 中**没有** `readContext` 字段，页字节与 SHA 完整；旧 live 归档格式未变。

### 3.4 明确拒绝（不写归档、不改停点）

- 参数 sample 不等、snapshot.plan 的 sampleId / trackingEpoch / target / range 任一不等均拒绝。
- held 场景：伪造 `before` 令牌、`heldAtBothChecks=true` 而 `after` 不等均拒绝。
- live 场景：借用 stop 拒绝。
- 所有拒绝后 group 仍 `HeldComplete`、原停点精确不变、目标仍附加；所有归档写完后才显式释放，
  group 正常 `Close`、目标恢复心跳并正常退出码 0。

## 4. 失败与修复记录

按时间顺序，均为**测试/夹具/脚本侧**问题；被测 wrapper 在本次执行所用的源码状态下
未发现需要本会话修改的明确缺陷。

1. `C2660 ReadSegment 不接受 7 参数`：三处调用漏传可选 `prefixHash`，补 `nullptr`。
2. `C2589/std::min 宏冲突`：Archive 源需要 `NOMINMAX`，脚本补 `/DNOMINMAX`（vcxproj 已有该定义）。
3. 运行 `FAIL create project win32=2`：`ProjectDocument::Create` 不递归建父目录，脚本先创建空 scratch 父目录。
4. 运行 `FAIL held-capture-succeeds`：原生适配器要求 `group.sampleId == plan.sampleId`；
   夹具身份原用固定 UUID，与项目随机 sampleId 不同。改为用真实 sampleId 构造 `OwnerIdentity`。
5. 脚本误判 FAIL：Windows 下 stdout 为 `\r\n`，`(?m)$` 被 `\r` 挡住；校验前先去除 `\r`。

期间主协调者并发硬化了被测 wrapper（非空 stage、令牌 UUID/序号/代次与 after 目标核验）。
本批最终构建在该硬化之后，因此上述 PASS 覆盖的是硬化后的当前源码，而非最初读到的版本。
本会话没有改动 `ProjectMemorySnapshot.cpp`、`ProcessGroupMemorySnapshot.*`、`MemorySnapshotReader.*`
或任何旧函数源码。

## 5. 清理

- 唯一自有子进程置于 `KILL_ON_JOB_CLOSE` 私有 Job；最终运行后
  `tasklist /FI "IMAGENAME eq ActionAnalyzeGroupMemoryArchiveValidation.exe"` 为 “No tasks are running”。
- 测试项目目录 `group-memory-archive-fixture` 在脚本 `finally` 中删除，执行后固定 IntDir 仅剩编译
  中间产物（`.obj`/`.pdb`），无测试配置、无运行副本。
- 日志仅文本，位于 `.codex-build-logs/behavior-planning/action-analyze-group-memory-archive-*`。
- 用户原有 7 项暂存未改动；未执行 `git add` / `git commit`。

## 6. 未验证 / 边界

- `Plan` 中 `rounds` / `intervalMs` / `authorizedOwnedProcess` 不写入归档 plan；本批按归档身份
  核对 sampleId、trackingEpoch、target、range 的伪造不一致拒绝，未把这三项当作归档身份字段。
- 未验证 Reader 对新 `readContext` 与各变化组合的语义解析（另一作者负责），本批只证明 writer
  产出的记录可被同一 `ProjectDocument` 读句柄按字节与 SHA 原样回读。
- 未验证跨页范围、不可读/无权限页、取消、目标退出中读取、外部写入者并发或进程级原子性；
  `heldAtBothChecks` 只表示本 owner 令牌未变，内存仍是逐页采样。
- 未验证 R0/驱动、GUI、CLI/Qt/Light 命令入口、Sysmon、第三方目标或长时间性能阈值；本机 OS 为 19045。
- "before 相同、after 变化"场景由真实 held 捕获派生 `after` 令牌构造，未由并发释放触发原生
  `process-memory-stop-changed-during-read` 路径；端到端并发变化留给控制适配器后续验收。
