# 合作 WinAPI 持续采集

本批只修改第 2 项合作驻留采集的运行时限。正式 CLI 入口为 `analyze api-evidence capture`；仓库当前没有独立的 `analyze api-capture` 命令。Qt「监控 → 行为分析」合作采集及 Light「监控 → ActionAnalyze」合作采集继续由本端所有者持有会话和停止责任，默认请求 `durationMs=0`。

## 实现范围

- 本批将 `shared/ApiMonitorCapture` 的合作驻留模式接入 `durationMs=0`。验收期间另一工作包把严格观察谓词扩展为 `strictObservation()`（合作驻留或显式附加），本批未修改其附加准入；本回执的持续模式正例只覆盖合作驻留。运行循环保留取消、目标退出、管道错误、提前停钩和 Agent 失败检查。启动就绪及清退仍使用独立超时。
- 项目包装与 CLI 同步接受 `0`，原 1,000–120,000 ms 有限时范围及默认 3,000 ms 保持原语义；普通 `monitor api capture` 不接受 `0`。
- Qt 与 Light 原有悬停提示同步说明持续到明确停止或目标退出；Qt 双语词条定点同步。未改布局、主题或控件结构。
- 持续采集未发生有限时完成，`completedInterval=false`。显式停止及目标自然退出仍返回部分采样 `6`，分别保留 `cancelled`／`targetExited`、清退及原始归档终段原因，不把目标退出冒充停钩确认。
- 不修改协议、规则摘要接线、跨进程链、工程登记和 `ProjectCommands.cpp`。用户已有暂存保持原样。本批不执行 GUI、驱动或 Sysmon 验收，不为 Qt／Light 源码默认值变更单独启动整合构建。

## 验收记录

<a id="2026-11-26-正式-cli-长程实测通过"></a>

### 2026-11-26 正式 CLI 长程实测（通过）

- 命令：`powershell -NoProfile -File tools/action_analyze_validation/cli/Invoke-ContinuousCooperativeCapture.ps1`。包装脚本在**同一 PowerShell 线程**（线程号见日志）创建并持有命名互斥 `Local\KSword.ActionAnalyze.CliValidation`，`try/finally` 覆盖一次构建与全部实测，结束由该线程 `ReleaseMutex`；日志 `.codex-build-logs/continuous-cooperative-capture.log` 记录 `MUTEX_ACQUIRED` → `MUTEX_RELEASED`。
- 固定脚本：`tools/action_analyze_validation/cli/continuous_cooperative_capture.py`；复用 `cooperative_api_capture` 与 `cooperative_capture_lifecycle` 的自有目标、管道见证、`ctrl+break` 私有 console 与归档回读。长程自有目标在本批子进程入口把 `TARGET_TIMEOUT` 从 65 秒调整为 240 秒、`BUFFER_SIZE` 调整为 16000，不修改共享夹具全局值；就绪只以真实管道 `HooksInstalled` + 两条已排空普通自写为屏障，不用经过时间猜就绪。
- 构建：构建宿主先设 `BelowNormal`，`tools/Invoke-KSwordCliBuildCheck.ps1`（amd64 HOSTX64 / `PreferredToolArchitecture=x64` / `PROCESSOR_ARCHITECTURE=AMD64` / `PROCESSOR_ARCHITEW6432=AMD64` / `BuildProjectReferences=false`）。构建前读回并打印绝对 `IntDir`（仓库内 `KswordCLI/x64/Release`）、`OutDir`（`Ksword5.1/x64/Release`）、`VC_ExecutablePath_x64`（`HostX64/x64`）。最终通过轮次为 `EXIT_CODE=0`、`BUILD_RESULT=SUCCESS`；实测当时 `KswordCLI.exe` SHA-256 `423586A7732C61AEE20F6BC09E486B5A780714BAD0EE8812A325592DB7942E7D`。锁释放后其他工作包再次重建了正式 Release，目录后续哈希不同；本回执绑定测试时构建读回的哈希，不代表后续任意 EXE 已复验。Agent 复用核对后的正式 Release `APIMonitor_x64.dll`，本批未构建主程序、Light、驱动或 Agent。中间夹具修复后重新运行整批包装时也重复执行了增量构建，不能将本批总构建次数表述为一次。
- 构建与实测全程使用统一 `Ksword5.1/x64/Release` 输出与固定验证目录 `Ksword5.1/x64/Release/action-analyze-cli-validation`；每次用例结束核对会话文件身份并删除配置/停止标记，确认自有目标和 CLI 正常退出，最终 `scratch_exists=False`，无本轮残留夹具进程。

#### 实测结果

| 用例 | 结果 |
| --- | --- |
| 持续 `--duration-ms 0` >120 秒后私有 console 定向 `CTRL_BREAK` | `elapsedMs=125453`、`intervalElapsedMs=125110`；`agentReady=true`、`readyCoverageRevision=1`；`completedInterval=false`、`cancelled=true`、`targetExited=false`；`cleanupComplete=true`、`stopMarkerWritten=true`、`hooksRemoved=true`、`cleanPipeEof=true`；停止后目标仍活，退出码 `6`。 |
| 持续分段检查点增长 | 就绪后每 5 秒观测检查点数量 `0 → 4 → … → 117`（25 个采样点，单调增长）；最终 `committedSegments=123`，原包 `ordinaryPackets=16188`、`archivedPackets=16188`，线索 `4047`，Agent 丢包/无效包/漏归档均为 `0`。 |
| 终段与原包回读 | 终段 `#123` 结束回执 `stopReason=cancelled`、`sourceState=pipe-eof`；逐段回读 123 个 raw 段及检查点散列链，原包字节、PID/TID/会话身份和长度全部核对；CLI `analyze api-evidence replay --packet 1` 回读一包与归档 `wire.hex()` 一致，包 SHA-256 `06aeb82604858338539415549d8362a972e281680311ad564920f72ffacc8796`，终段 SHA-256 `9ae452e8538fdf9a792a523a87cad9e572b531e1bf051ff8ed2ab576b8a9a141`，自写偏移 `5..4051` 连续。 |
| 持续 0 目标自然退出 | `completedInterval=false`、`targetExited=true`、`cancelled=false`、`cleanupComplete=true`，退出码 `6`；终段 `#1` `stopReason=target-exited`、`sourceState=pipe-eof`；原包 `139` 条回读通过。 |
| 原有限时正例 `--duration-ms 1000` | `completedInterval=true`、`cancelled=false`、`targetExited=false`、`cleanupComplete=true`；终段 `stopReason=duration-limit`；原包 `139` 条回读通过。`partialHooks=true` 由 Agent 覆盖给出，与原有限时正例历史口径一致，仍为部分退出 `6`。 |
| 负例 | `analyze api-evidence capture --duration-ms 1/999/120001` 均退出 `1` 且 `status=invalid-resident-capture-scope`；普通 `monitor api capture --duration-ms 0`、`--startup-timeout-ms 999`、`--stop-timeout-ms 120001` 均退出 `1`。源码侧核对 `durationMs=0` 仅严格/驻留模式准入、有限时 `100..120000` 及启动/停止超时 `1000..120000` 门禁仍生效。 |

- 新夹具兼容并行接线后的 Agent `AAIP1|` 定长详情与旧 `key=value` 详情，回读仍复用 `decode_raw` 和正式 CLI replay；该兼容只在本批验证脚本内，不改共享夹具。
- Qt／Light 本批只同步默认 `durationMs=0` 的源码与双语提示，未执行 GUI 实测；主协调已由另一 CodeBuddy 完成 i18n 审计（31,997 条、退出 `0`，日志 `.codex-build-logs/continuous-cooperative-i18n.log`），本批未重复审计。
- 首轮 CodeBuddy 长任务只完成源码检查，工具授权拒绝后执行器退出 `1`，未构建、未产生长程实测结论；中间数轮因本批夹具辅助函数问题（终段序列起点、详情格式、源码门禁字符串）退出非 `0`，均在锁内修复后重跑，最终整批命令退出 `0`。该首轮不能计为产品验收通过。
