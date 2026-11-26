# 活采候选链定向验收回执

本批只做第 4 项「跨进程转移监控」的**正式 CLI 本机实测**与本批消费者源码/语言检查。不构建 Qt/Light、不做 GUI 实测、不碰本机驱动/Sysmon/其他用户进程、不改步进/附加/候选树作者文件。实测夹具、排查和源码语言检查由本 CodeBuddy 自主完成。

- 夹具：`tools/action_analyze_validation/cli/live_api_transfer.py`（新增，固定名）。
- 自有导出线程助手：`tools/action_analyze_validation/cli/live_api_transfer_helper.cpp` + `.vcxproj` + `.vcxproj.filters`（新增，仅一个导出 `LiveTransferThreadProc`，x64 Release 输出到统一 `Ksword5.1/x64/Release`）。仅本夹具子进程加载，不注入外部进程。
- 构建优先级 BelowNormal、HostX64、工程固定 `IntDir`、统一 `Ksword5.1/x64/Release`。CLI 增量用 `tools/Invoke-KSwordNativeBuildCheck.ps1 -Product CLI`；助手用随附 `.vcxproj`。`.codex-build-logs/` 只写文本日志。
- 正式 CLI 构建与整批运行全程持 `Local\KSword.ActionAnalyze.CliValidation` 命名互斥，主线程 `try/finally` 释放。曾观察到 `WAIT_ABANDONED`（前一宿主异常退出未释放），本夹具显式回收后继续，并在日志打印 `CLI_VALIDATION_MUTEX_ABANDONED_RECOVERED=True`。CLI 被其它并行任务临时重建/占用（`Win32 32`、`WinError 2`、文件忙）时只重试/重取产物，不终止他人进程。

## 1. 实测拓扑与协议顺序

自有父进程加载**正式 Release Agent** 并显式 opt-in，自有子进程提供写入目标与自有导出线程入口。按真实协议组织动作，不靠固定睡眠猜测分段：

1. 父进程 `LoadLibrary` 正式 `APIMonitor_x64.dll`，调用 `KSwordApiMonitorEnableCooperativeCapture`（`ERROR_NOT_READY` 按 25ms 轮询直至成功）。
2. 控制器 CLI `analyze api-evidence capture --confirm --duration-ms 20000` 先核验驻留并发布本 PID 的 `config_<pid>_<creation>.ini`（私有会话目录末段名必须为 `KswordApiMonCooperative`）。
3. 父进程调用 `KSwordApiMonitorWaitForCooperativeStartup(30000)` 等到 Hook 安装与覆盖发布完成，才做业务调用（`READY`）。
4. 子进程分配 `PAGE_EXECUTE_READWRITE` 可执行文件区与独立数据缓冲区，报告 helper 模块基址与两块地址。父子各自映射同一 helper DLL，用同一 RVA 保证跨进程入口一致。

**动作分在两个不同检查点，以发布水位握手分段**：

- 预热失败调用（只读句柄 `WriteProcessMemory`）publish 首个检查点（水位 1）。
- 检查点 W：父进程把位置无关线程机器码 `B8 41 52 54 4C C3`（`mov eax,0x4C545241; ret`）写入**可执行文件区起点**，回读 6 字节逐字节核对，然后 `published_watermark` 确认新段发布（水位 2）。
- 检查点 T：`CreateRemoteThread` 的入口就是刚写入区间的首字节（落在写入范围内），`WaitForSingleObject` 正常返回且 `GetExitCodeThread == 0x4C545241`，再确认新段发布（水位 3）。
- 区间外负例：`CreateRemoteThread` 入口为**自有 helper DLL 导出**（合法可执行、正常返回同一常量），但地址不在本次写入区间内 → 不得形成候选。绝不使用不可执行的数据地址作为入口，避免目标崩溃。
- 失败负例：只读句柄写入失败（`ERROR_ACCESS_DENIED`），不得形成候选。

## 2. 正式产物与命令

实测时刻产物（并行任务在此前后仍在重建 CLI/Agent，故以本夹具日志内记录的实测哈希为准）：

| 产物 | SHA-256（实测时刻） |
| --- | --- |
| `KswordCLI.exe` | `8952df93d2ae8e83c129cc135b8da283ff1f285639ddf3d306bac3f6627ee8d7` |
| `APIMonitor_x64.dll` | `f532324cd22b8f9f0130849ceec6df85e8070788331fd99d8b59a0cc4bb43789` |
| `LiveApiTransferHelper.dll` | `fee52b260d52184a8b8584bba2b9d9d4ed32be0b6cc86a778e9aeee9adfff5f7` |

命令（根目录 `E:/Projects/Ksword5.1`，均在命名互斥内）：

```
python -B tools/action_analyze_validation/cli/live_api_transfer.py --build --build-helper
```

`--build` 在互斥内执行 `tools/Invoke-KSwordNativeBuildCheck.ps1 -Product CLI`（`BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`）；`--build-helper` 编译助手 DLL。最终整批运行退出码 `0`。

## 3. 实测结果（正式 CLI，非夹具自证）

- `analyze api-evidence capture` 退出码 `6`（`capture-partial`），但 `completedInterval=true`、`cancelled=false`、`targetExited=false`、`cleanupComplete=true`、`hooksRemoved=true`、`cleanPipeEof=true`、`coverageRevision=2 == requiredFinalCoverageRevision=2`、`invalidPackets=0`、`agentReportedDrops=0`、`omittedClues=0`、`archivedPackets=ordinaryPackets=52`、`committedSegments=5`、`finalSegment=true`。`partialHooks=true` 来自源端四 Hook 的安装条件，与候选链无关；本批不改源端。
- `apiTransfers`：`evidence=reported-api-write-to-thread-create`、`execution=unknown`、`candidateCount=1`、`evictedWrites=0`、`windowTruncated=false`、`recent` 恰 1 条。
- 唯一候选坐标：`write = raw/2 #39 / 源序 37`，`threadCreate = raw/3 #44 / 源序 41`；`actorPid/targetPid` 与父子真实身份一致，`actorCreationFileTime/targetCreationFileTime` 与父子 FILETIME 一致，`writtenBytes=6`（实际完成长度，非请求值），`writtenAddress == requestedStartAddress == 可执行区起点`。
- 负例成立：只读句柄失败写入（`raw/1 #35 / status=5`）与区间外 helper 导出线程（`raw/4 #52`）均未形成候选；`candidateCount` 保持 1。
- 原包 `coverageState=0x49505631`、`detailText` 均为 `AAIP1|` 固定 14 字段，成功写入/两次线程创建解析出版本化字段，失败写入保留返回位但无有效完成长度位——与候选链判定一致。
- **坐标双源对账**：候选 `write/threadCreate` 的段号、raw 序号、源序号同时与 (a) CLI `apiTransfers` 报告、(b) `api-evidence replay --packet 1` 原包、(c) `archive.inspect ... raw ORDINAL graph` 的 `apiTransferCandidates.links`（`execution=null`）三处一致。`LIVE_TRANSFER_GRAPH=PASS`、`LIVE_TRANSFER_RECEIPT=PASS`、`LIVE_API_TRANSFER=PASS`。

## 4. 源码与语言检查（定向）

- Qt「监控 → 行为分析 → 合作 API 活采详情」：`PassiveApiCaptureOwner.cpp` 的 `onTransfers`（第 6 个回调）只把 `candidateCount/evictedWrites/recent.back()` 拷入跨线程回执；`PassiveApiCapturePane.cpp` 复用 `ParameterWorkspace` 结构并调 `AppendApiTransferProgress`；`ApiTransferPresentation.cpp` 用 `StructuredFieldView` 追加「API 转移候选」分区，坐标只取最近候选、不读当前选择。
- Light「监控 → ActionAnalyze → 活采详情」：`NativeLiveSession.cpp` 的 `onTransfers` 在同一采集线程先于 `onCommitted` 更新 `latestTransfers`，详情由既有原生文本外壳的 `ApiTransferProgress` 追加，保留单线程回调先后与结果身份。
- 两端 progress 摘要均标注「候选仅关联实际写入与后续创建请求，不证明实际执行 / execution unknown」，未把请求入口写成执行证据。
- 授权范围内三处（CooperativeApiCapture transfers 逻辑、CooperativeTransfersReport、两端 progress 摘要）复核未发现明确缺陷，实测正例/负例/坐标/graph 对账均通过；`CooperativeTransfersReport` 的 `recent` 中每条 `EvidenceRef.raw` 由 `ApiTransferChain::Accept` 的入口门禁保证非空，无解引用风险。**未改产品代码**（四 Hook 源端、NativeStep、CLI 步进、既有条件、规则 SHA 逻辑一律未碰）。
- 语言包：新增标签此前已在双包；本轮 audit 曾报 `sourceEpoch` 双包缺恒等词条，已在 `zh-CN.json`/`en-US.json` 的 `sourceSha256` 后各定点插入一条（只补键、不改键序/缩进）。复跑 `python tools/i18n_language_pack.py audit --source-root Ksword5.1/Ksword5.1 --zh-pack Ksword5.1/Ksword5.1/languages/zh-CN.json --en-pack Ksword5.1/Ksword5.1/languages/en-US.json` → 退出码 `0`，`i18n audit passed: 32032 source strings`。新增/修复标签在双包各恰好一次、无重复键。

## 5. 边界与缺口

- 本批未做 Qt/Light GUI 实测、未构建 Qt/Light；桌面仅源码合规，深浅主题/DPI/窄窗/键盘遍历/复制导出仍需用户后续实机确认。
- `windowTruncated=true`（>32 候选）、`evictedWrites>0`（>1024 写入）、发布失败水位不增长、通知抛异常不阻止清退：这些**滚动窗口/故障边界**本批未用独立原生生产函数夹具逐一打满，仅由 `CooperativeApiCapture` 逻辑复核（窗口 32 条上限、`EvictedWrites()` 累计、通知 `try/catch` 后仍走清退）与单次实测 `windowTruncated=false` 覆盖；列为后续可补项，不宣称已实测。
- 真实驱动回调入档、事件时强实例、线程入口实际执行证据、跨会话串链负例仍为 AA-04 完整范围缺口，本批未涉及。
- 源端四 Hook 由另一作者负责且在此批多次重建 Agent；本批复用锁后实际最新 Agent，未重建 Agent 工程。

## 6. 清理

- 固定临时项目目录 `Ksword5.1/x64/Release/action-analyze-cli-validation` 由 `owned_project_path` 原子占用并在结束时删除（`Cleaned ...`）。
- 私有会话目录 `KswordApiMonCooperative` 的 `config_*.ini`（2 个）与 `stop_*.flag` 校验身份/内容后删除（`OWNED_SESSION_FILES_REMOVED=2`、`COOPERATIVE_SESSION_DIRECTORY_REMOVED=True`）。
- 自有父/子进程经关闭 stdin 正常退出（`parent.returncode==0`），未强制终止任何-owned 之外的进程。
- 夹具日志 `.codex-build-logs/live_api_transfer_full_run.log` 为唯一新增文本证据；`.codex-build-logs/live_api_transfer_protocol_run.log` 为受阻阶段日志。助手 DLL 的 `.lib/.exp/.ilk/.pdb` 随统一 Release 产物生成，未复制到临时目录。
