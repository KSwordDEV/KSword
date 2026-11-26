# SelectedMemorySnapshot / ProjectMemorySnapshot 本机原生验证回执

- 日期：2026-11-26
- 范围：仅本批库级原生测试（`KswordCLI/ActionAnalyze/Memory/SelectedMemorySnapshot`、`Memory/PassiveDirtyMemory` 新增 `PollCapture`、`Project/ProjectMemorySnapshot`）。未构建 CLI/QtLight 主产品，未触碰 GUI、驱动、Sysmon、第三方系统进程。
- 结论：6 场景 311 项本机断言全部通过，EXE 退出码 0，连续两次运行结果一致。生产侧修复 2 处本批新逻辑缺陷（见下）。

## 测试工程与运行方式

- 工程与脚本（均未跟踪，随本批交付）：
  - `KswordCLI/ActionAnalyze/Memory/tests/MemorySnapshotNativeTests.cpp`
  - `KswordCLI/ActionAnalyze/Memory/tests/ActionAnalyzeMemorySnapshotValidation.vcxproj`（`/W4 /WX`、`stdcpp20`、`MultiThreaded`、HostX64 工具偏好）
  - `KswordCLI/ActionAnalyze/Memory/tests/ActionAnalyzeMemorySnapshotValidation.vcxproj.filters`
  - `KswordCLI/ActionAnalyze/Memory/tests/Invoke-MemorySnapshotValidation.ps1`
- 构建：`D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe`（64 位入口），`/p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64`，构建宿主与 cl/link 子进程均为 BelowNormal。
- 构建前读回并核对：`IntDir=KswordCLI/ActionAnalyze/Memory/tests/x64/Release/`（工程内固定）、`OutDir=Ksword5.1/x64/Release/`（统一正式 Release）、`VC_ExecutablePath_x64` 以 `HostX64\x64` 结尾且存在 `cl.exe`。不符合即中止。
- 运行：`ActionAnalyzeMemorySnapshotValidation.exe <scratch>`，scratch 为 `KswordCLI/x64/Release/ActionAnalyzeMemorySnapshotValidation`，由脚本独占创建并断言未被 Git 跟踪；脚本结束删除 exe、pdb 与 scratch。
- 该测试自采样本进程内存、挂起并终止自有子进程作退出目标负控，全部为良性自有目标；未进行窗口自动化。

## 结果

- 最终连续两次运行均 `RESULT=PASS scenarios=6 checks=311`，`RUN_EXIT_CODE=0`。
- EXE SHA256（每次全量/增量重链接后不同，记录两次通过运行）：
  - 首次通过：`AB6D4BB1F42F6CBE75034784746FEA499E2D223DDF86A2DFFCCB362EBBBC4995`
  - 复跑：`464C78E1E4BBE4FE1119D92475C6D8D77E454C37B965EECDD007E24B9852F064`
- 日志（文本，`.codex-build-logs/memory-snapshot/`）：
  - 通过运行：`memory-snapshot-native-20261126-081510-7139984-44992-{build,run}.log`、`memory-snapshot-native-20261126-081527-7227289-44668-{build,run}.log`
  - 修复过程日志保留于同目录，按时间戳递增，含每次失败的 FAIL/WRITE-ERROR/EXPECT-ERROR 行。

## 场景覆盖

1. **本机自采样**：跨 5 页非对齐范围（首尾页内偏移 0x40/−0x100），逐页已知字节模式精确比对；`captured.bytes` 独立重算 SHA-256 与页观测 `content.sha256` 一致；页基址等于真实分配地址；`sampledRange` 与范围交集一致；基线 version=1；前后映射稳定且 protection 记录正确；`completeRange=true`、`plannedPages`、QPC 窗口与 returnedBytes 核对。
2. **失败页部分结果**：NOACCESS→NotReadable、已 decommit→NotCommitted、RW|PAGE_GUARD→Guarded、纯 reserve→NotCommitted；成功页捕获字节精确，`unavailablePages=3`；捕获仅 1 页；失败页无 returnedBytes、无伪造 issue；**采样后 Guard 位仍在、NOACCESS 保护未变**（未读取、未改变 Guard）。
3. **拒绝与边界**：错 creation→Rejected/ProcessMismatch；挂起自有子进程终止后作为退出目标→TargetExited/ProcessLifetime；开始前取消→Canceled 且无轮次；零长度、`base+length` 溢出、空 base、rounds=1、超过 64 页、未授权选区→Rejected/ValidatePlan。
4. **旧 Poll 行为与 PollCapture 所有权**：旧 Poll（无回调）首轮 Baseline、未到期不出轮、StatusOnly 不消耗轮次；写内存后下一轮 Changed version=2、difference 恰为 64 字节单区段、未改页 Unchanged；计划轮数结束→Completed。PollCapture：访问器只对 Sampled 页按地址升序调用；记录的借用指针与快照复制存储不同且内容精确；**借用视图不跨回调（实现为即时复制）**；间隔内二次 PollCapture 不出轮、访问器不再被调；调用者显式 Stop；捕获路径不消耗 Guard 位。
5. **归档写入与回读**：正式 `ProjectDocument` 同 sample 写 `raw-memory/1`（完整 2 页）与 `raw-memory/2`（部分 1 页成功+1 页 NotCommitted），前序链回读验证；plan 元数据逐字段核对（kind/projectId/sampleId/source/qpcFrequency/range/target），`atomicProcessSnapshot=false`、`allocationGenerationVerified=false` 显式留存；每页 `sha256` 与归档原字节独立重算一致、页字节精确；端记录 completeRange/capturedBytes/unavailablePages/visitedPages/allPagesVisited 正确且完整与部分不可混淆；回执 `verified`、`capturedBytes`、`unavailablePages`、`completeRange`、`ordinal`、flush 端点与整段前缀散列核对；第二段写入后 raw-memory/1 字节不变；错误前序读取→UnexpectedSequence。
6. **拒绝与坏段**：重复 ordinal 1→AlreadyExists 且 raw-memory/1 未被覆盖；错误前序→RecoveryRequired；请求 sampleId 与快照不符→InvalidArgument；effectivePlan 身份篡改→memorySnapshotIdentity；页序断档→memorySnapshotPageOrder；缺/多捕获字节→memorySnapshotMissingBytes/ExtraBytes；捕获字节无声明 sha 或与声明 sha 矛盾→memorySnapshotBytesMismatch；部分结果谎称/完整结果否认 completeRange→memorySnapshotCompleteness；未登记 UUID 采样→NotFound；只读项目→ReadOnly；真实短尾→Truncated 仅保留前序完整块且不改原件；位翻转→VerifiedBoundary 失败。

## 生产修复（本批新逻辑）

1. `Project/ProjectMemorySnapshot.cpp`：PrepareRows 此前只按观测身份配对捕获字节（范围与 sha 声明一致），不校验实际字节是否哈希到页声明的 `content.sha256`——合成或错误调用者可归档与记录摘要矛盾的原字节且回读仍判 verified。新增 `PageDigestVerifier`（BCrypt SHA-256）对每个捕获页重算摘要，不一致→`memorySnapshotBytesMismatch`（fail-closed：BCrypt 打开失败同样拒绝）。同时合并了并行 CLI 作者加入的 `readContext`/`WriteProcessGroupMemorySnapshot` 流程，未改动其语义。
2. `Project/ProjectMemorySnapshot.cpp`：`WriteSnapshot` 的 append 回调在 `Append` 失败时原返回通用 `IoError "memorySnapshotWrite"`，掩盖项目层对原生错误的映射（重复段号应为 AlreadyExists）。改为停止后续页并让 `writer.Finish()` 原样上报，`WriteRawEvidenceSegment` 经 `WinFailure` 保留真实映射（ERROR_FILE_EXISTS→AlreadyExists 等）。

测试夹具自身修正（不影响产品）：`SyntheticSnapshot` 最初为失败页也生成空捕获条目；Guard 复查顺序错误；0xAA 变异与模式碰撞；场景 6 误用只读重开；缺失采样改用未登记 UUID（`ReadSample` 要求 UUID 形态）。

## 并发协作说明

- 本轮期间 CLI 作者并行推进 `ProjectMemorySnapshot.cpp`（新增 `WriteProcessGroupMemorySnapshot` 与 `readContext`）。我的修复在其最新工作树上重新合并后构建验证，未覆盖其改动。
- 未登记主产品工程新源（由 CLI 作者负责）；仅新增 `Memory/tests/` 测试工程。未执行 git add/commit/push，未触碰既有暂存（含他人已暂存的 `pair-condition-validation.md` 删除）。

## 清理

- `Ksword5.1/x64/Release/ActionAnalyzeMemorySnapshotValidation.exe`、同名 `.pdb`、`KswordCLI/x64/Release/ActionAnalyzeMemorySnapshotValidation/` 均已删除；`.codex-build-logs/memory-snapshot/` 仅保留文本日志；固定 IntDir `Memory/tests/x64/Release/` 保留常规 obj 构建残留。

## 未验证 / 边界

- 编译与断言通过不替代实机视觉或产品级 GUI 验收（本批无 UI 改动）。
- 未验证：驱动/R0 路径、跨进程真实目标（测试只采本机自有进程）、PollCapture 与归档在多线程归档工作线程下的串行化（由上层调用者保证）、`WriteProcessGroupMemorySnapshot` 新路径（CLI 作者范围）、性能预算、断电/满盘恢复。
- 采样为显式单轮快照，`allocationGenerationVerified=false` 与 `atomicProcessSnapshot=false` 是归档明确声明，不代表进程级原子一致性已验证。
- EXE SHA256 每次重链接不同（非确定性构建）；回执以上述两次通过运行的记录为准。
