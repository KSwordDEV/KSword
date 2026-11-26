# 第 4 项：API 转移消费者链路与跨段候选回读

用户原话：「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。本文记录消费侧（`ApiTransferChain`、`ArchivedEvidenceGraph`、正式 CLI 图视图与本机活采候选回读）的实测回执。源端 Hook 参数采集与正式 Agent 构建由源端作者负责，本文不重跑其内部用例，也不把源端缺失的最终回执算作通过。

## 1. 范围与结论

| 项 | 结果 | 证据 |
| --- | --- | --- |
| 原生图/链夹具 | **PASS** | `ActionAnalyzeCrossProcessEvidenceGraphValidation.exe` 78/78，包含原有 31 项、回调归档与新增转移/坏段用例。 |
| 正式 CLI 合成跨段候选回读 | **PASS** | 两段 API follow 采样，写入 `1#2`、线程创建 `2#4`，候选 1 条；缺首检查点/首段损坏均失败关闭。 |
| 正式 CLI 本机活采候选回读 | **PASS** | 自有父/子目标，正式 Agent 与正式 CLI；写入 `2/39`、线程创建 `3/44`，候选 1 条，执行未知；图重投影一致。活采作者另有独立回执 [live-api-transfer-validation.md](live-api-transfer-validation.md)（CLI `8952df93…`）；本页在并发重建后的 `c2d46be2…` 上又核对一次消费侧，不重跑源端内部用例。 |
| 源端最终回执 | **未取得** | 本轮未重跑源端内部用例；不能以消费侧通过替代源端回执。 |
| 真实驱动回调入档、事件时强实例、执行确认 | **无** | 本轮只证明来源声明的写入→创建请求候选，不证明线程执行。 |

因此第 4 项仍未关闭；消费侧核心链路已具备本机正式产品证据。

## 2. 构建与运行环境

- 仓库：`E:\Projects\Ksword5.1`，分支 `ActionAnalyze`。
- 构建宿主：64 位 MSBuild，`PreferredToolArchitecture=x64`、`PROCESSOR_ARCHITECTURE=AMD64`、`PROCESSOR_ARCHITEW6432=AMD64`；正式 CLI 经 `tools/Invoke-KSwordNativeBuildCheck.ps1 -Product CLI`，宿主与子进程 `BelowNormal`。
- 固定 `IntDir`：`E:\Projects\Ksword5.1\KswordCLI\x64\Release`；统一 `OutDir`：`E:\Projects\Ksword5.1\Ksword5.1\x64\Release`。
- 互斥：整批构建与实测持 `Local\KSword.ActionAnalyze.CliValidation`；期间检测到前一持有者异常退出（`WAIT_ABANDONED=0x80`）并按同一互斥恢复，未绕过。
- 主批次（构建 + 原生 + 合成跨段 + 规则身份）：受测正式 CLI SHA-256 `8dad7486c9b5ccc7fd8be07392b9f5f7f69fb07e7ae26db8bca0e5727ac474f0`（`tools/Invoke-KSwordNativeBuildCheck.ps1 -Product CLI`，HostX64/Release，日志 `.codex-build-logs/action-analyze-transfer-rule-batch-20261126-041029.log`）。
- 活采批次：`live_api_transfer.py --build` 在互斥内再次构建并实测，CLI SHA-256 `83c8350f6afa9429f0d4df583013d1b8837c2be24761152bac8aee42a0c45692`；随后并发工作流重建到 `6d18cad8…`、`bde6ab63…`、`c2d46be2…`，消费侧夹具在各产物上均以稳定哈希复跑通过。本页在最后一次 `c2d46be2…` 上做了合成与规则复核，不把它称作本批构建产物。
- 正式 Agent：`APIMonitor_x64.dll` SHA-256 `f532324cd22b8f9f0130849ceec6df85e8070788331fd99d8b59a0cc4bb43789`；辅助 DLL `LiveApiTransferHelper.dll` SHA-256 `fee52b260d52184a8b8584bba2b9d9d4ed32be0b6cc86a778e9aeee9adfff5f7`。
- 批处理入口：`python -B tools/action_analyze_validation/cli/run_transfer_batch.py`（持互斥，构建 CLI、构建/运行原生夹具、运行合成跨段与规则身份夹具，并执行 i18n/diff 门禁）。
- 日志：`.codex-build-logs/action-analyze-live-api-transfer-20261126.log`、`.codex-build-logs/action-analyze-consumer-fixtures-20261126.log`、`.codex-build-logs/action-analyze-transfer-rule-batch-20261126-041029.log`。
- 未执行：GUI、主程序、驱动、Sysmon、第三方进程注入。

## 3. 原生夹具（78/78）

工程 `KswordCLI/ActionAnalyze/Detection/tests/ActionAnalyzeCrossProcessEvidenceGraphValidation.vcxproj` 复用同一 `CrossProcessEvidenceGraphTests.cpp`，新增 `TestApiTransferCandidates` 并扩展回调归档坏段用例：

- 同源/同会话/同代次/同 QPC 顺序：只有全部一致才形成候选；不同 `sourceId`、`sourceEpoch`、`sessionIdentity`、actor/target 创建时间、target PID、QPC 相等或逆序均断开。
- 实际写入半开区间 `[address, address + completedBytes)`：起点、末字节有效，右端和起点之前无效；部分完成只用 `completedBytes`，不用请求长度。
- 失败调用按源端契约不携带实际完成长度，不形成区间；缺地址/完成长度/请求入口均不形成候选。
- 跨段：写入 `raw{1,2}`、创建 `raw{2,2}` 保留双方真实坐标；坏锚点（零段号、零序号、缺 raw、错采样、空来源）拒绝；重复原包不增加状态；1024 写入窗口淘汰后不能再关联旧写入。
- 候选不证明执行：同一创建请求作为来源上下文进入图后，`finding`、`observedThread`、节点和边均为空。
- 回调归档坏段：缺第 2 段、错前缀摘要、损坏首段均返回失败且不替换调用方旧页；恢复字节后重新发布完整页。

运行命令（固定夹具根，结束时删除）：

```powershell
Ksword5.1\x64\Release\ActionAnalyzeCrossProcessEvidenceGraphValidation.exe `
  Ksword5.1\x64\Release\action-analyze-cross-process-graph-validation
```

输出：`CrossProcessEvidenceGraph: 78/78 passed`，退出码 `0`；夹具根已删除。

## 4. 正式 CLI 合成跨段候选回读

夹具：`tools/action_analyze_validation/cli/api_transfer_archive.py`。输入是明确标注为合成的 1000 字节 API 包：写入包与创建包均带 `coverageState=0x49505631` 和固定 `AAIP1|` 14 字段；两包写入同一 JSONL 源，由正式 CLI 的 JSONL 跟随入口分别提交到第 1、2 段。

通过条件与实际结果：

- 第 2 段图 `archiveSource=api-follow-checkpoint`，`apiTransferCandidates.count=1`、`evictedWrites=0`、`truncated=false`。
- 写入原坐标 `raw 1#2`，创建原坐标 `raw 2#4`；双方 actor/target PID 与创建 FILETIME 一致；`writtenAddress` 与 `requestedStartAddress` 落在实际区间；`writtenBytes` 使用实际完成值。
- `link.execution=null`；创建观察 `execution=null`、`finding=null`，含 `thread-instance-unknown`、`execution-unknown`；`nodes=[]`、`relations=[]`。
- 写入所在第 1 段候选数为 `0`，观察仍含 `actual-write-range-unknown`。
- 图页给出的 `raw.inlineOffset/inlineBytes` 回读出的字节与两份合成原包逐字节一致（不依赖单段结束尾记）。
- 移除首段检查点后第 2 段返回 `project-data-not-found`；损坏首段后返回 `project-corrupt`/等同错误且不发布候选；恢复后候选重新完整出现。
- 结束清理：`action-analyze-cli-validation` 已删除；发布规则文件摘要保持 `45a1438f3ecb31467a5d780502d38f423dbeb2c0865ab5d38b58c78cbe2d27f4`。

样本：`56cd55a4-4dab-4a98-bd99-6aa618f142b5`（本批构建 `8dad7486…`）；并发重建后的 `c2d46be2…` 复核样本为 `2085174d-1bd5-4ab1-8c94-c22d41c32d1b`，断言一致。

限制：合成输入只验证消费者读侧和 CLI 契约，不证明真实 Hook 采集或执行。

## 5. 正式 CLI 本机活采候选回读

夹具：`tools/action_analyze_validation/cli/live_api_transfer.py`。自有父进程加载正式 `APIMonitor_x64.dll` 并主动加入合作采集；自有子进程持有写入缓冲区和自有导出线程入口。父进程执行成功的 `WriteProcessMemory` 与 `CreateRemoteThread`，另执行失败写入和区间外合法入口负例；以已发布检查点水位分段，不使用固定睡眠猜测。

实际结果（活采批次 CLI `83c8350f…`、Agent `f532324c…`；并发重建后的 `c2d46be2…` 复核结果一致）：

- `candidateCount=1`、`evictedWrites=0`、`recent=1`、`windowTruncated=false`。
- 跨段坐标：活采批次（`83c8…`）写入 `raw 2#41`、源序号 `39`，线程创建 `raw 3#46`、源序号 `43`；并发复核（`c2d4…`）为写入 `raw 2#39`、源序号 `37`，创建 `raw 3#44`、源序号 `41`。两轮均跨段且各自稳定。
- actor PID/创建 FILETIME 与父进程一致；target PID/创建 FILETIME 与子进程一致；`writtenBytes=6`；`requestedStartAddress` 等于实际写入起点。
- `execution=unknown`；图重投影 `GRAPH_LINKS=1`，双方记录坐标与 CLI 报告一致。
- 采样：`b8336ae5-e808-4a28-8725-346f83fc7346`（`83c8…` 活采批次，`sourceRows=54`、`clueRows=4`）；并发重建后的 `c2d46be2…` 复核为 `b6135769-9036-485d-b8c5-b674d3fab078`（`sourceRows=52`、`clueRows=4`），两轮均 `archive.status=readback-verified`、`committedSegments=5`、`finalSegment=true`。
- 采集回执为 `capture-partial`（退出码 `6`），原因是 `partialHooks=true`（并非本次四个候选 Hook 缺失）；`invalidPackets=0`、`omittedClues=0`、`cleanupComplete=true`、`hooksRemoved=true`、`cleanPipeEof=true`。
- 清理：自有会话文件数 2 已删除，会话目录已删除，固定测试根已删除；未发现遗留 `KswordCLI.exe` 或夹具进程。

限制：活采只证明来源声明的写入与创建请求候选；不证明创建线程实际执行，也不证明真实驱动回调入档。活采作者的独立回执见 [live-api-transfer-validation.md](live-api-transfer-validation.md)，本页只复跑消费侧并记录并发重建后的产物哈希；源端四 Hook 作者的最终回执仍未取得，不将其计为已通过。

## 6. 源码核对与发现

- `KswordCLI/ActionAnalyze/Detection/ApiTransferChain.cpp:25-70`：同源、同会话、同代次、同 QPC 顺序、实际半开区间；候选只包含两份 `EvidenceRef`，无执行字段。
- `KswordCLI/ActionAnalyze/Detection/ArchivedEvidenceGraph.cpp:174-212`：连续核验前序段保留写入状态；第 2 段创建请求可关联第 1 段写入；坏段不发布。
- `KswordCLI/ActionAnalyze/Cli/ProjectCommands.cpp:345-367`：图页输出 `apiTransferCandidates`，`execution` 显式为 `null`。
- 未改产品 `ApiTransferChain` 逻辑。

发现（未修，交主协调裁定）：

1. `shared/evidence/ApiInjectionFields.h:135-140` 的 `ApiInjectionCallOutcome` 对“失败调用 + 已置完成长度”返回 `Partial`，而源端契约声明完成长度只在成功且安全读取后置位。最小复现：`WriteProcessMemory` 包 `hookAddress=0`、`resultCode=0`、完成长度标志置位且 `completedBytes=requestedBytes` 时返回 `Partial`；`ApiTransferChain::Accept` 接受 `Partial`，因此该契约外组合可成为候选来源。本轮原生夹具按源端契约改为“失败且无完成长度”，未擅自改分类器。是否加固为拒绝该组合需产品决定。
2. `analyze api-evidence replay` 只读取单段 `raw/1` 并要求结束尾记，不能用于多段 API follow 采样；`tools/action_analyze_validation/cli/rule_profile_identity.py` 原先在坏规则阶段用它验证跟随档，已改为图入口验证跟随档、另用关闭导入验证 `api-evidence replay`。这是命令能力边界，不是本次产品改动。

## 7. 未完成与下一步

- 源端作者最终回执未取得；不重复源端内部用例。
- 真实驱动回调入档、事件时强实例、线程执行确认仍为无。
- Qt/Light 归档行详情的实际桌面显示未验（用户要求桌面实测后置）。
- 下一可执行步骤：主协调收到源端最终回执后，按第 4 项产品清单判定是否关闭；消费侧本轮证据可直接复用，不需重跑本页命令。
