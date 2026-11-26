# 进程集合「选中内存」SOURCE 审查（Qt 适配 + 底层契约）

日期：2026-11-26
范围：`ProcessGroupMemoryPane.*`、`ProcessGroupSession.*`、`ProcessGroupPage.cpp`，以及只读底层
`Control/ProcessGroupMemorySnapshot.*`、`Memory/SelectedMemorySnapshot.*`、`Memory/PassiveDirtyMemory.*`、
`Project/ProjectMemorySnapshot.*`、`Project/ProjectDocument.*`。为核对段链契约，另读了
`Project/ProjectRawEvidence.*`、`Archive/RawEvidenceArchive.h`、`Project/ProjectStorage.cpp`、
`Control/StopLedger.*`、`Control/OwnedProcessGroup.cpp`、`Cli/ProcessGroupCommand.cpp`、`Cli/MemorySnapshotCommand.cpp`。

审查方式：只读源码 + 纯 Python 模型。**没有**编译 Qt / Light / CLI，没有启动主程序或任何 GUI，
没有执行 `CaptureProcessGroupMemory` / `DebugActiveProcess` / `ReadProcessMemory`，没有创建或写入项目目录。
所有结论都是静态结论；运行时行为（尤其 Pause/读取异常路径）没有被实测。

**被审的 Qt 文件在审查期间被其它 CodeBuddy 连续修改（两小时内多次换哈希）。**
本文对 Qt 文件按符号（类/函数/字段）引用，不把行号当契约；CLI 文件给本轮行号。
复现以脚本为准。审查过程中确认已修复的问题仍记录在 §2，防止回归。

本文快照（`utc=2026-11-26T08:38:02Z`）：

| 文件 | SHA-256 |
| --- | --- |
| `ActionAnalyze/ProcessGroupMemoryPane.h` | `449403d2206b2729411f1906f006d4db2c71b995750a9061606d867e01e440d4` |
| `ActionAnalyze/ProcessGroupMemoryPane.cpp` | `eb373a53ad363e58be8f7a4494e840601a0243f7705b613e9ad997a004a65ed3` |
| `ActionAnalyze/ProcessGroupSession.h` | `76d7e32df8d706ab3933d4a906dfc15159437253f12e020512d0ef6b016923ea` |
| `ActionAnalyze/ProcessGroupSession.cpp` | `57c8f6ec71f3452eb632af3d8ac8dcf603c56b1e421cd83dea532b2205a7fd7b` |
| `ActionAnalyze/ProcessGroupPage.cpp` | `5678a6fcb85c466a1f7e7d3b75dfaab97a8785b6c2ee2279e4f55620398c6e82` |
| `Control/ProcessGroupMemorySnapshot.cpp` | `c0c5e3d50babd1e94e803cbe4a3ba032d478d42d9595c61938f6e7c0e7e3fd08` |
| `Control/ProcessGroupMemorySnapshot.h` | `49b6830ca0010afc8d94bd982839a1b4e02bf6a9700d774a93a30d397e90f1b4` |
| `Project/ProjectMemorySnapshot.cpp` | `2d4e57cd6078c66399b1285f8b860eaece5ee7297573001eaa34e30336e9899b` |
| `Memory/PassiveDirtyMemory.cpp` | `0e0c5b4ec223158c0de04936bf57f7dbb431404d1fc34f3e63feb4f127c9dfa0` |
| `Memory/SelectedMemorySnapshot.cpp` | `1a2de91582a727945d60b8bf403bc76f7906dcb793ea01ddf9e49f6c3e45d519` |
| `Project/ProjectDocument.cpp` | `1fd53b6563454b8d2f7da66a23da667f09a6ce1e136c0fb98fd039ebe3cb3c6b` |
| `Project/ProjectRawEvidence.cpp` | `61491c3311a56a9f485ec01ff6ab18159c6f99814b522d66085ada595d46e8c3` |

脚本：`tools/action_analyze_validation/qt/process_group_memory_source.py`（新增，只读）。
输出：`.codex-build-logs/process-group-memory-source-20261126-final.log`。

---

## 1. 逐项结论

| 要求 | 结论 | 证据（符号） |
| --- | --- | --- |
| Held 读取与 Continue/Close 在同一 group、同一串行线程 | 通过 | `ProcessGroupSession::Shared::Run` 中唯一的 `CaptureProcessGroupMemory` 调用点位于 `case ProcessGroupCommand::ReadMemory`；`Submit` 单在途（`ended/pending/busy/closing` 拒绝）；pane/session/page 中无 `ProcessMemorySource::LiveRead` |
| 选中唯一成员的完整 stop token，sampleId 必须同原 group | 通过 | `Prepare` 复制 `*member->stop`，`plan.sampleId` 取自 `member->control->group->sampleId`；底层 `MatchesHeld` + `group->sampleId != plan.sampleId` 复检，读后再 `Query` 对比 |
| 输入 base/字节冻结，拒绝空与溢出 | 通过 | `Prepare` 的 `toULongLong` 失败、`!base`、`!bytes`、`bytes > UINT64_MAX - base` 分支；范围写入 `capture.plan.range` 后不再读控件 |
| Plan rounds 在 2..64 且 wrapper 只采一轮 | 通过 | `capture.plan.rounds = 2`；`PassiveDirtyMemory.cpp:69` 要求 2..64；`SelectedMemorySnapshot.cpp:22` 只调用一次 `PollCapture`，`:30` 再 `Stop()` |
| 失败不 fallback live、不继续 | 通过 | 适配层无 Live 分支；`CaptureProcessGroupMemory` 读前/读后只 `group.Query()`，失败直接返回，不调用 Continue/Recover |
| 保存显示的是不可变内存指针，不随选择/草稿变化 | 通过 | 页面点击时取 `m_shown.memory`；会话按指针比对 `memoryToSave != lastMemory`，要求 `lastMemory->request.plan.sampleId == sampleId`；`memoryArchiveSource` 把回执绑定到实际保存的 capture |
| Configure 可选新建项目与 sample，本端持租约，group 用实际 sample | 通过 | `case Configure` 先 `Create`、再 `CreateSample`，随后 `groupIdentity.sampleId = sampleId` 重建 group；失败时 `project->Close()` 释放半创建租约并保留请求目录（见 §2 F6） |
| 无项目可读、但不能保存 | 通过 | owner 四个标签均由 `QUuid` 生成（§2 F1）；保存要求 `projectDirectory` 非空 |
| 保存仅在实际成功页、不填零 | 通过（Qt 路径） | 保存门槛要求 `snapshot->round && !round->pages.empty()`；`SelectedMemorySnapshot` 只回调完整页；`PrepareRows` 校验页序、字节长度并重算 SHA-256。共享 writer/CLI 仍缺同守卫（§3 F2） |
| raw-memory 段号/前序只在 Write 返回后核验确认 | 通过 | `case SaveMemory`：`ordinal = nextMemoryOrdinal`；仅 `verified && raw.flushed` 时 `previousMemorySequence = raw.flushed->lastSequence` 并 `++nextMemoryOrdinal`；失败置 `memoryArchiveBlocked` |
| 范围结果显示成功页/失败页/字节/QPC 与原生错误 | 通过 | `Append` 显示 `status.state`、`status.issue.stage/win32Error`、`plannedPages`、未访问页、`NTSTATUS`、成功/失败页、实读字节、QPC，以及前后停点与逐页 QPC |
| 独立 SOURCE 脚本验证接线与有意义负控 | 通过 | 70 项接线/契约检查 + 段链负控；本轮 `hard_failures=0 findings=1`，退出码 0（`--strict-findings` 为 3） |

底层关键契约：`previousSequence` 是**前一段最后一条记录的 archive sequence**，不是段号。
`Project/ProjectRawEvidence.cpp:70-81` 用 `ordinal - 1` 段回读并比较
`checked.checked->lastSequence != *request.previousSequence`；`Archive/RawEvidenceArchive.h:18-22,53`、
`Archive/tests/RawEvidenceArchiveTests.cpp:100`、`Cli/LiveSession.cpp:195`、`Cli/PassiveApiCapture.cpp:444`
的生产写法都证明这一点。会话层现在用的正是 `receipt.raw.flushed->lastSequence`。

---

## 2. 审查过程中确认已修复（保留记录，防回归）

### F1 [原 P0 → 已修复] 无项目 owner `sampleId` 非 UUID 导致 Pause 抛异常

原问题：页面对 `OwnerIdentity` 传字面量 `sampleId="desktop-process-group"` 与
`backendInstanceId="qt-process-group/<id>"`；`Control/StopLedger.cpp:81-85` 要求四个标签都是 36 字符 UUID，
否则 `throw std::invalid_argument`。`OwnedProcessGroup::Pause` 只重分配 `backendInstanceId`，`sampleId`
原样进入 `ledger_`，于是无项目路径 Pause 必然抛异常，Held 读取不可达；异常又被 `catch (...)` 吞成
「后台执行失败」。

现状：页面改为 `sample = QUuid::createUuid()`、`backend = QUuid::createUuid()`、`session/epoch = m_sessionId`，
四个标签均为规范 UUID；带项目时 `groupIdentity.sampleId` 仍是真实 sample UUID。
脚本以 `owner identity built from variables` + `owner sample/backend are fresh UUIDs` 守住。

### F3 [原 P1 → 已修复] 范围结果不显示内存 `Status.state` / `Status.issue` / 计划页

原问题：只显示成功页、`unavailablePages`、字节和 QPC；超 64 页、地址越界、跨用户等 `Rejected` 结果与
「0 页读到」无法区分；中途取消时未访问页不计入失败页。

现状：`Append` 增加 `状态`、`采样诊断阶段码`、`Win32 错误`、`计划页数`、`未访问页数`、`NTSTATUS`，
保留成功/失败页、实读字节、QPC 与逐页 QPC。脚本四项 `ui memory status …` 守住。

### F4 [原 P2 → 已修复] 归档 `machineId`/`bootId` 每次读取新 UUID

原问题：`plan.target` 写成 `{trackingEpoch, trackingEpoch, ...}`，同一 sample 的多次快照声称不同机器/启动标识。

现状：`plan.target` 改为 `{group->sessionId, group->epoch, processInstanceId, pid, creationFileTime}`，
与 CLI 参考实现（`Cli/ProcessGroupCommand.cpp:478-479`）一致；脚本以 `plan machine/boot from group labels` 守住。

### F5 [原 P2 → 已修复] 后台异常丢弃原因

原问题：`catch (...)` 只置 `failed`，页面只有「后台执行失败」。

现状：`Run` 分别捕获 `std::exception`（写入 `workerDiagnostic` 摘要）与 `...`，`ProcessGroupPage` 在状态行
与字段详情显示该摘要；`workerDiagnostic` 注释明确「不冒充原生 stage 或 Win32 错误」。

### F6 [原 P3 → 已修复（保留提示）] 半创建项目占用写租约

原问题：`Create` 成功、`CreateSample` 失败时项目仍打开，且页面看不到实际目录。

现状：失败分支先 `project->Close()` 再返回错误，`projectDirectory` 在尝试前就回填请求目录；
用户至少能看到失败目录。仍需注意：该目录已被创建，`Create` 对已存在目录返回 `AlreadyExists`，
同一会话内不能原目录重试，必须清退后换新目录。

---

## 3. 残留发现

### F2 [P2] 共享 writer 与 CLI 仍未拒绝「无轮次的被拒捕获」写成已核验空段

证据：

- `ProjectMemorySnapshot` 的 `PrepareRows` 在 `snapshot.round == nullopt` 时只写「plan 元数据 + end」两行，
  `complete=false` 与 `snapshot.completeRange=false` 自洽；`WriteSnapshot` 随后写入、刷盘、回读，
  `receipt.verified = true`。`WriteSnapshot` 内没有 `status.state` 守卫。
- `Cli/MemorySnapshotCommand.cpp` 的 `Capture` 在 `Begin` 拒绝（超 64 页 `PassiveDirtyMemory.cpp:328`、
  地址越界 `:323-325`、跨用户/受保护目标）时仍调用 `WriteSelectedMemorySnapshot`。
- Qt 路径已闭合：`ProcessGroupMemoryPane::Update` 的 `m_save->setEnabled` 要求
  `shown.memory->snapshot->round && !round->pages.empty()`。

真实后果（CLI/独立调用者）：项目中出现一条通过段链校验、SHA-256 正确、`verified=true` 的 raw-memory 段，
却没有任何内存字节；后续 `analyze memory read` 会把它当已核验快照展示（end 记录 `state` 为 Rejected，
需要读者自行解释）。这与「保存仅写实际成功页」的语义不符。

修复建议：把 Qt 的门槛下沉到 `PrepareRows`/`WriteSnapshot`：
`status.state == State::Stopped && round && !round->pages.empty()`，否则 `InvalidArgument` 且不消耗段号；
CLI 与独立调用者一并受保护。

---

## 4. 已验证（未发现问题的具体路径）

- 单在途：`Submit` 在 `ended`/`pending`/`busy`/`closing`（除 Recover）时拒绝；`Run` 每回合只取一项。
- 读前/读后证据：前后各一次 `group.Query()`；`heldAtBothChecks` 只在 `*observed->stop == *request.stop` 时为真，
  变化时置 `ERROR_RETRY` 但保留已读字节。
- 保存补核 read context：`WriteProcessGroupMemorySnapshot` 校验 `before == request.stop`、
  groupId/stopId/backendInstanceId 为 UUID、`stateRevision` 非零、`target` 与 plan 一致，并把
  `source`/`before`/`after`/`heldAtBothChecks` 写入 `readContext`；停点变化过的快照也带真实标记。
- 段链：ordinal 1 → 无前序；ordinal>1 → 必须前序；前段必须 `VerifiedBoundary` 且末序号相等
  （`Project/ProjectRawEvidence.cpp:57-81`）。
- 段回读：同一只读句柄扫描，逐行比较 metadataJson 与原字节，并对整段取 SHA-256，最后校验刷盘端点。
- 逐页字节：`SelectedMemorySnapshot.cpp:25-29` 用 `captured.size() == pages.size()` + 每页 `Sampled && content`
  + `status == Active` 计算 `completeRange`；写入侧再重算每页摘要。
- 结果身份：`Append` 不引用 `m_base`/`m_bytes`；成功页预览取 `captured` 字节，页状态取 `round->pages`；
  前后停点直接显示 `read.before/after`。
- 工程登记：`Ksword5.1.vcxproj` / `.filters` 已含两个新 Qt 单元；`ProcessGroupMemorySnapshot.cpp`、
  `SelectedMemorySnapshot.cpp`、`PassiveDirtyMemory.cpp`、`ProjectMemorySnapshot.cpp`、`RawEvidenceArchive.cpp`、
  `ProjectRawEvidence.cpp`、`ProjectDocument.cpp`、`ProjectStorage.cpp`、`SampleCatalog.cpp`、`ProjectLock.cpp`
  均已进入 Qt 工程。
- 语言包：新增可见文本（含 `计划页数`、`采样诊断阶段码`）在 `zh-CN`/`en-US` 的 `source_translations` 中都存在；
  `python tools/i18n_language_pack.py audit ...` → 退出码 0（32149 strings）。
- 共享面板：`PrepareNative` 只构造一个 `ProcessGroupMember` 后转交 `Prepare`；`MoveExecutionActions`
  只搬运读/存两个按钮。写入/步进页复用该面板时，原生侧仍由 `CaptureNativeStopMemory` 的 `HeldNativeStop`
  重新核对身份与停点。

---

## 5. 命令与退出码（真实执行）

```bash
# 语言包审计（只读）
python tools/i18n_language_pack.py audit \
  --source-root Ksword5.1/Ksword5.1 \
  --zh-pack Ksword5.1/Ksword5.1/languages/zh-CN.json \
  --en-pack Ksword5.1/Ksword5.1/languages/en-US.json
# -> i18n audit passed: 32149 source strings ; EXIT=0

# SOURCE 检查 + 模型（只读；-B 不生成 pyc）
python -B tools/action_analyze_validation/qt/process_group_memory_source.py --print-hashes
# -> hard_failures=0 findings=1（F2）; EXIT=0
python -B tools/action_analyze_validation/qt/process_group_memory_source.py --strict-findings
# -> EXIT=3（存在 FINDING）
```

完整输出（含文件 SHA-256）：
`.codex-build-logs/process-group-memory-source-20261126-final.log`。

脚本负控含义（纯模型，不代表原生运行）：

- `current policy: 3 verified saves chain` 通过 → `(ordinal, flushed->lastSequence)` 可连续写 3 段。
- `regression: ordinal-as-sequence breaks 2nd write` 通过 → 把段号当前序时第 2 段必定
  `archivePreviousSegment`（审查早期版本的真实缺陷，现已修）。
- `regression: pre-increment then failure -> archiveWriter` 通过 → 先 `++ordinal` 再调用时，一次失败后永久死锁。
- `blocked policy: no segment and no ordinal use after failure` 通过 → 现有 `memoryArchiveBlocked` 不跳段。
- `gap demonstrated: rejected capture archives an empty verified segment` 通过 → 复现 F2 的 writer 行为。

脚本把 `rounds`、`PollCapture` 次数、`!base/!bytes/溢出`、`HeldComplete`、`group->sampleId`、
`group->sessionId/epoch`、指针与 sample 绑定、`flushed->lastSequence`、`!projectDirectory.empty()`、
`round && !pages.empty()`、`Append` 不读草稿、`Status.state/issue/plannedPages` 显示、
`PrepareNative` 转交、owner 身份由 QUuid 生成等写成硬检查。

---

## 6. 边界与未完成

- 未编译任何目标，未运行主程序/GUI，未做 `isolated_desktop.py` 自动化，未加载驱动，未附加任何进程。
  读取/Pause 的实际运行时行为未被本审查实测。
- Light 端代码本轮未读（用户说明由另一 CodeBuddy 生成）；`CaptureNativeStopMemory` 的 Light 对接标记为待完成。
- `DataWriteWatchPage.cpp` 复用本面板的新路径只做了面板侧审查；其工作线程如何把 `ProcessGroupRequest`
  转成 `CaptureNativeStopMemory` + `WriteProcessGroupMemorySnapshot` 不在本轮文件清单内，未核对。
- 未修改任何产品源码、语言包或他人测试；新增仅限本文件与
  `tools/action_analyze_validation/qt/process_group_memory_source.py`。同目录既有
  `process_group_session_model.py`（会话调度模型）和 `group_memory_archive/`（原生归档测试）未改动、未运行。
- 被审 Qt 文件仍在被并发修改；若哈希与上表不同，先重跑脚本再看结论，不要沿用本文行号。
