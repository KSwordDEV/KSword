# 显式 R3 Agent 附加

入口：`analyze api-evidence attach --project PATH --title TITLE --pid PID --creation-filetime FILETIME --confirm [--duration-ms MS] --json`。

实现复用 `CaptureCooperativeApi` 的原包分段、检查点、规则和候选流水线，由 `AttachedApiCapture` 执行独立的确认及后端准入。请求末尾新增 `mode`，缺省仍为合作驻留，title/revision 只借用于同步调用。附加请求在共享控制器中单独冻结创建 FILETIME；严格观察开关拒绝行为配置、R0 和后代注入。桌面 `KSWORD_APIMON_COOPERATIVE_ONLY` 编译路径拒绝附加。

模块装载与就绪、采集、归档、清退各自报告。就绪需同一核验管道内的 SessionReady、成功 HooksInstalled、完整且当前的对应覆盖修订，并至少有一个活动观察 Hook。完整覆盖快照不表示全量 API 可用。持续采集只在原合作模式和新增显式附加模式允许，普通 monitor 入口有限时契约保持。

构建和实测仅交作者直接派发的 CodeBuddy 执行。要求全程持 `Local\KSword.ActionAnalyze.CliValidation` 互斥，BelowNormal、HostX64、固定 IntDir、统一 Release；仅自有无窗口目标，不加载驱动、不使用 Sysmon、不接触其它用户进程、不运行 GUI。回执在本页追加。

终段在附加模式额外保存历史 `attachmentReceipt`，分别记录当时的身份、装载、模块、Ready、停钩、EOF 和清退状态；合作默认计划与终段不因此增加字段。历史回执不授予重开后的控制权，也不能认证任意外部归档生产者。

2026-11-26 作者首次 CodeBuddy 派发在源码读取阶段以 `exitCode=1`、`no final result` 退出；没有构建或实测结论。已续接同一会话执行，最终实际回执另列。

## 2026-11-26 本机实测回执（显式非合作附加）

### 结论

正式 CLI 的显式非合作 R3 附加在本机自有 x64、启动时未装载 Agent 的目标上通过：CLI 按精确 PID＋创建 FILETIME 确认后从自身同目录装载产品 Agent，模块装载/身份核验与 Hook 就绪分开报告，1000ms 有限采集和 `--duration-ms 0` 持续采集分别完成分段归档、回读和清退。验收中定位并修复了一处共享控制器就绪门槛缺陷（见“实现修复”）。范围仅限本机自有无窗口目标、单次真实活动、不要求全部 API 成功；一般第三方目标、全活动覆盖、GUI、R0/驱动、WOW64 与长程持续时间均未验证。

### 验收环境与构建

宿主：`tools/action_analyze_validation/cli/attached_api_capture.py`。历史有效轮次中，构建、夹具编译和全部产品测试都在持 `Local\KSword.ActionAnalyze.CliValidation` 期间执行；但该两轮的测试文件与测试项目删除发生在退出互斥之后（`035422` 日志 `MUTEX=released` 之后的 `CLEANED`／`CLEANUP`），属于夹具收尾次序缺口，只影响收尾次序，不改变已记录的产品实测结论。现测试脚本已把清理移入互斥内并显式 `ReleaseMutex`，仅经语法与静态检查，未重跑实测，不能据此宣称历史轮次已按新次序执行。互斥获取：最近一轮等待到前持有者进程退出后以 `WAIT_ABANDONED` 取得（前轮宿主只 `CloseHandle` 未 `ReleaseMutex`），未终止任何其它进程。

- 构建命令（宿主内调用，宿主与 MSBuild 均 BelowNormal）：`pwsh -NoProfile -File tools/Invoke-KSwordCliBuildCheck.ps1`
- `IntDir=E:\Projects\Ksword5.1\KswordCLI\x64\Release`，`OutDir=E:\Projects\Ksword5.1\Ksword5.1\x64\Release`
- HostX64：`D:\Software\VS\VC\Tools\MSVC\14.44.35207\bin\HostX64\x64\cl.exe`
- 夹具目标：`tools/action_analyze_validation/cli/attached_api_capture_target.c`，编译到统一 Release，中间目录固定 `KswordCLI/x64/Release/AttachedApiCaptureValidation`；目标不 `LoadLibrary`、清除 `KSWORD_APIMON_COOPERATIVE_SESSION_V1`、只调用自身 `WriteProcessMemory`／`ReadProcessMemory`。

| 轮次（日志） | CLI SHA-256 | CLI 大小 | Agent SHA-256 | 夹具 SHA-256 | 断言 |
| --- | --- | ---: | --- | --- | --- |
| `033900`（首次有效全通过） | `f3675beae6d58f66de65a3c0a257285d36513df4f8562fc42c35d45594aaf691` | 7,446,016 | `c5a25ad89623df8f2948258dce7b9119d85126936052652cb1109797a224959c` | `228494800188642b6683e2e8f644396293e23b3d8e7a106b7d08cd877afbb1ca` | 99/99 PASS |
| `035422`（最近有效全通过） | `35b4f0dc03f37ff1c1519ffc0af05c795dea25d466629840c7b568c99682e22b` | 7,542,784 | 同上 | `3b117f621f4f5d20a5dc8f3700628c94fa5b0809a86592bcc4fe434552cdeead` | 100/100 PASS |

两轮均 `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`。CLI 字节在各自整轮实测前后一致（`artifact` 断言）。各轮只认证表中列出的 CLI SHA 及其对应日志，不从两轮 SHA 差异反推源码原因。文本日志：`.codex-build-logs/action-analyze-attached-api-capture-20261126-033900.log`、`.codex-build-logs/action-analyze-attached-api-capture-20261126-035422.log`（完整逐项输出与断言行）。

终端段在附加模式下另写 `attachmentReceipt`（身份/装载/模块/Ready/停钩/EOF/清退）。本轮核验的是终段是否有限、是否与写入端水位一致；该内嵌字段的逐字段内容未单独回读断言。

### 实现修复（本批范围）

首次实测在就绪门槛处失败（`033344` 轮 95/99）：`agentReady=false`、`readyCoverageRevision=null`、`errors=["resident Agent did not report an installation coverage revision"]`，同时 `sessionReady=true`、`hooksInstalled=true`、`coverageRevision=2`、`coverageSnapshotCurrent=true`。

根因：配置驱动（非合作）安装路径的 Agent 在首个覆盖快照发布前发送 `HooksInstalled`，该控制包本身不带 `snapshotRevision`（`APIMonitor_x64/MonitorAgent.cpp` 非合作分支使用无修订的 `SendMonitorEvent`；`APIMonitor_x64/core/MonitorPipe.cpp` 的 `SendHooksInstalledEvent` 才从 `LatestCoverageSnapshot()` 取修订）。共享控制器旧逻辑把修订 `0` 直接判为永久启动失败，使附加路径无法就绪。

修复（`shared/ApiMonitorCapture.cpp` 启动屏障）：安装回执修订为 `0` 时不再硬失败，改由同一核验继续要求“成功 HooksInstalled＋当前完整未陈旧且修订非零＋至少一个活动观察 Hook”；合作驻留路径的修订非零，仍按原 `revision >= installRevision` 比较，行为不变。修复后同一源码通过 99/99，随后 100/100。

### 有限 1000ms 正例（`035422`，退出 6 = partial）

命令：`KswordCLI.exe analyze api-evidence attach --project <project> --title "Attached explicit R3 finite" --pid <PID> --creation-filetime <FILETIME> --confirm --duration-ms 1000 --json`

- 采样 `ea364501-fb71-4326-8845-7c18c912449e`，`status=capture-partial`（存在部分 Hook，未要求全部 API 成功）
- 装载与就绪分开：`attachmentIdentityVerified=true`、`agentLoadAttempted=true`、`agentModuleVerified=true`、`agentPath=<Release>\APIMonitor_x64.dll`；`agentReady=true`、`sessionReady=true`、`hooksInstalled=true`、`coverageSnapshotCurrent=true`、`configPublished=true`、`connected=true`、`readyCoverageRevision=1`、`coverageRevision=2`
- 采集与归档：`ordinaryPackets=41`、`archivedPackets=41`、`omittedClues=0`、`committedSegments=2`、`clueRows=36`、`sourceRows=41`、`finalSegment=true`、`archiveSource=cooperative-pipe`、`status=readback-verified`；`readyAfterMs=141`、`intervalElapsedMs=1000`
- 回读：`analyze api-evidence replay --project <project> --sample ea364501-... --limit 100 --packet 1 --json` 退出 `0`，36 行、2 段；末坐标 `raw/2 #42`。逐行核对段号/记录号严格递增、1000 字节包 `version=0x20261003`、包内 PID/TID/会话与冻结实例及本采样会话一致、时间戳落在冻结实例窗口内；第二次回读返回完全相同的原包字节。
- 清退分别核验：`completedInterval=true`、`stopMarkerWritten=true`、`hooksRemoved=true`、`cleanPipeEof=true`、`cleanupComplete=true`、`targetExited=false`；目标仍存活且 Agent 仍加载，随后正常退出 `0`（`{"calls":969,"agentLoaded":true}`）。不声称 DLL 卸载。

### 持续 `--duration-ms 0` 与 CtrlBreak（`035422`，退出 6）

命令同上但 `--duration-ms 0`；CLI 以新进程组加入共享控制台，5 秒后向该进程组发送 `CTRL_BREAK_EVENT`。

- 采样 `c372b657-c7d4-4a41-aa25-9ac056ef109b`，`status=capture-partial`、`cancelled=true`、`completedInterval=false`
- `ordinaryPackets=184`、`archivedPackets=184`、`committedSegments=5`、`clueRows=164`、`finalSegment=true`、`readyAfterMs=109`、`intervalElapsedMs=4875`
- `hooksRemoved=true`、`cleanPipeEof=true`、`cleanupComplete=true`、`stopMarkerWritten=true`、`targetExited=false`；目标在取消后仍存活，随后正常退出 `0` 并保持 Agent 加载。终段提交与清退分别成立。

### 负控（同一轮，全部通过）

| 用例 | 结果 |
| --- | --- |
| 缺 `--confirm` | 退出 `1`，`status=invalid-attachment-scope`；未装载 Agent、未发布配置、未新增采样 |
| 错误创建 FILETIME | 退出 `3`，`status=capture-failed`，`attachmentIdentityVerified=false`，`errors=["capture target identity changed: <PID>"]`；未装载、未发配置、`committedSegments=0`。失败前已登记空采样目录，如实记录 |
| `--backend r0` | 退出 `1`，`unsupported backend for this command`（命令 `supportsR0=false`） |
| `--r0-inject 1` | 退出 `1`，`unknown option --r0-inject`，且拒绝后目标仍未装载 |
| 普通 `monitor api capture --duration-ms 0` | 退出 `1`，`--duration-ms must be 100..120000`，目标未装载 |

`source-gate` 两组为源码＋预处理核对，不是桌面运行时的 `KSWORD_APIMON_COOPERATIVE_ONLY` 实测：对 `shared/ApiMonitorCapture.cpp` 分别以不带/带 `-DKSWORD_APIMON_COOPERATIVE_ONLY` 预处理，确认带宏时保留 `valid = valid && resident && !attached;`、不带时保留附加准入；并核对严格观察拒绝行为选项、拒绝不完整 opt-in 落入旧路径、拒绝后代注入与 R0，以及桌面/Light 工程定义该宏、CLI 工程不定义。运行时负控只有上表 CLI 入口层用例。

### 无效轮次与失败归类（不得计为成功）

- `033224`：遗留中间目录导致在用例前中止，7/7，无产品实测，非验收结果。
- `034440`：本批构建因 `LNK1104` 失败但宿主仍继续，使用已有旧 EXE 跑完 97/100；该轮无效，不计成功。
- `035041`：真实 `LNK1104`（其它批次同时链接同一统一 Release）构建失败，未执行任何产品实测。
- `033900`、`035422`：构建成功且实测全通过，作为本批有效回执。
- 现测试脚本一次适用构建，失败即中止，不自动重试 `LNK1104`、也不使用已有旧二进制继续实测；该修正仅静态检查，未重跑。

### 清理与范围

- 清退自有目标后删除 `ActionAnalyzeAttachedApiCaptureTarget.exe/.pdb/.lib/.exp` 与固定中间目录 `KswordCLI/x64/Release/AttachedApiCaptureValidation`（含测试项目），删除前核对绝对路径位于统一 Release／固定 IntDir。
- 逐 PID 删除产品写入的机器级会话文件 `%WINDIR%\Temp\KswordApiMon\config_<pid>.ini`、`stop_<pid>.flag`（本轮 PID 30000、41660，以及此前的 32444、37896、16168、38432 等）；结束时该目录为空。未复制产品 DLL，未加载驱动，未使用 Sysmon，未运行 GUI，未接触其它用户进程；仅保留文本日志。
- 测试脚本收尾改进（未重跑产品测试，仅语法检查）：互斥显式 `ReleaseMutex`、恢复 `sys.stdout` 而不吞 `ValueError`、清理移到互斥退出之前且清理失败计入最终结果。

### 未覆盖

一般第三方/系统目标、WOW64 目标、全活动与全部 API 覆盖、GUI（Qt/Light）附加入口、R0/驱动路径、Sysmon、其它用户进程、DLL 卸载、超过 5 秒的附加持续时长与并发附加。就绪只证明同一管道的 SessionReady＋成功 HooksInstalled＋当前完整且含活动观察 Hook 的覆盖，不证明全量 API 已挂载或目标全部活动被捕获。
