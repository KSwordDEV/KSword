# 第 11 项：规则内容身份三端集成验证

用户原话：「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。本文记录正式 CLI 规则身份链路（规则 `sourceSha256` → 采集计划 `ruleSourceSha256` → 检查点 `ProjectApiCheckpoint.ruleSourceSha256` → `replay-api-rules` 的 `sourceSha256`／`recordedSourceSha256`／`matchesRecordedRules`）的一条运行命令与判据。与 [规则库独立夹具](rule-profile-identity.md) 分工：该任务负责 `tools/action_analyze_validation/rules/` 的独立编译夹具；本文只覆盖正式 CLI 集成面，两目录互不竞争。

## 授权边界

- 2026-11-26 用户已明确授权本批构建正式 CLI、运行本夹具并完成落盘；执行记录见下方实测回执。GUI、驱动和 Sysmon 仍不在本轮范围。
- 不改产品源码、不提交、不写共享 `validation-results.md`；本轮文本回执以本文为准。
- 测试不使用固定旧 callback 档作为规则身份证据（见判据 5），也不与 `tools/action_analyze_validation/rules/` 的独立夹具共用文件。

## 一条运行命令

前置：正式 `Ksword5.1/x64/Release/KswordCLI.exe` 已按授权构建，`Release/profiles/action_analyze_api_rules.json` 为本次构建部署副本。仓库根目录执行：

```powershell
py -3.12 -B tools/action_analyze_validation/cli/rule_profile_identity.py
```

配套静态门禁（同一次运行内执行）：

```powershell
python tools/i18n_language_pack.py audit --source-root Ksword5.1/Ksword5.1 --zh-pack Ksword5.1/Ksword5.1/languages/zh-CN.json --en-pack Ksword5.1/Ksword5.1/languages/en-US.json
git diff --check -- tools/action_analyze_validation/cli/rule_profile_identity.py docs/CLI使用文档.md docs/action-analyze-planning/rule-profile-integration-validation.md
```

`i18n audit` 与 `git diff --check` 在夹具准备阶段因会话 Bash 权限被拒未能执行，属于待执行项，不冒充已通过。

## 判据（全部通过才算通过）

1. `api-rule-catalog` 的 `sourceSha256` 等于 `Release/profiles/action_analyze_api_rules.json` 实际字节的 SHA-256（原始字节，非重序列化 JSON），`presetSet` 与文件一致。
2. 固定旧 callback 档（`tools/action_analyze_validation/project/x64/Release/callback-project-fixture`）不适用：`replay-api-rules` 对其非零退出并返回 `archive-unsupported`／`archive-unavailable`／`archive-invalid`，且不产生任何 `matches` 或 `matchesRecordedRules` 结论。夹具缺失时显式记 `SKIP`，不冒充通过。
3. 既有被动 JSONL 跟随夹具（`passive_api_session.run`）完成一次新采样：每段冻结计划的 `ruleSourceSha256` 等于基线摘要且各段一致；对同一采样 `replay-api-rules` 返回 `sourceSha256 == recordedSourceSha256 == 采集摘要`、`matchesRecordedRules=true`、`archiveSource=jsonl-follow`。
4. 只替换一条 ASCII `summary`、保持 `presetSet` 与其余字节不变：catalog 与回放 `sourceSha256` 变为新字节摘要；`recordedSourceSha256` 仍为原值；`matchesRecordedRules=false`；恢复原始字节后 `matchesRecordedRules=true`。探针在 `finally` 恢复发布文件并核对原始摘要。
5. 关闭 JSONL 导入样（旧 API 档语义）没有记录摘要：`recordedSourceSha256` 与 `matchesRecordedRules` 均为 `null`，`sourceSha256` 仍显示当前摘要。
6. 坏规则文件（截断 JSON）：catalog 与 `replay-api-rules` 以退出码 4 返回 `rule-profile-unavailable` 且带 `configError`；同一采样的图入口仍可回读跟随档原包，已关闭导入样 `analyze api-evidence replay` 仍 `readback-verified`（原包不依赖规则可用性）；`finally` 恢复后 catalog 摘要回到基线。说明：分段跟随档没有单段结束尾记，`api-evidence replay` 只适用于已关闭导入，不能用它核对跟随档。
7. 测试项目只放在固定 `Ksword5.1/x64/Release/action-analyze-cli-validation/`（`owned_project_path` 拒绝已存在目录并核对非 reparse 身份），导入源文件用独占创建（`xb`）并在结束后删除；结束核对拥有目录已整体清除。

## 固定目录与输入

- 被测规则文件：`Ksword5.1/x64/Release/profiles/action_analyze_api_rules.json`（CLI 从自身映像目录加载，见 `BehaviorPresets.cpp` `LoadApiPresetDatabase()`）。
- 测试根：`Ksword5.1/x64/Release/action-analyze-cli-validation/`；被修改的发布配置只有上述 rules JSON，全部修改点均有 finally 恢复与摘要核对。
- 复用夹具：`passive_api_session.py`（JSONL 跟随采样）、`api_evidence.py`（`packet`／`archive_line`／导入）、`live_etw.decode_raw`（独立解码冻结计划）、`project_v1.owned_project_path`（固定测试根）。无临时编译、无运行时复制。

## 源码检查回执（2026-11-26，本任务完成）

身份链源码核对（相对仓库根）：

- `KswordCLI/ActionAnalyze/Rules/BehaviorPresets.cpp:261`：摘要与解析使用同一份原字节，完整成功后才发布；失败路径返回空摘要与诊断。
- `KswordCLI/ActionAnalyze/Project/CooperativeApiCapture.cpp:44-45,128` 与 `KswordCLI/ActionAnalyze/Cli/PassiveApiCapture.cpp:202-203,382`：两类采集计划写入同一 `database.sourceSha256`。
- `KswordCLI/ActionAnalyze/Project/ProjectApiCheckpoint.cpp:212-216`：可选字段校验 64 位小写十六进制，旧档缺字段仍可读；标记本身不携带摘要，摘要来自逐段冻结计划（`ProjectApiCheckpoint.cpp:349-356`）。
- `KswordCLI/ActionAnalyze/Cli/ApiRuleReplayCommand.cpp:328-334,368`：回放/目录从同一次冻结的 `database` 取值；旧档/导入样后两项为 `null`。
- Qt 同源核对：`Ksword5.1/Ksword5.1/ActionAnalyze/BehaviorPresetReplay.cpp:161,202-203`（一次 `LoadApiPresetDatabase` 同时供 presetSet／ruleSourceSha256 及两个 profile 求值）、`PassiveApiCaptureOwner.cpp:65-66,108-109`（同一回执对象投影）。
- Light 同源核对：`KswordARKLight/Features/ActionAnalyze/ActionAnalyzePage.cpp:267,272-273`（同一冻结 database）、`NativeLiveSession.cpp:93-95,126-128`（同一 rules 回执对象）。
- CLI 文档已同步：`docs/CLI使用文档.md` 目录与回放命令行新增摘要字段说明。

以上仅为源码级核对结论；**本任务不声明 GUI 视觉验收、不声明产品已实测**。

## 本次实测回执（2026-11-26）

- 命令：`python -B tools/action_analyze_validation/cli/rule_profile_identity.py`，在 `Local\KSword.ActionAnalyze.CliValidation` 互斥内运行；正式 CLI 由 `tools/Invoke-KSwordNativeBuildCheck.ps1 -Product CLI` 以 HostX64、BelowNormal、固定 `IntDir=KswordCLI\x64\Release`、统一 `OutDir=Ksword5.1\x64\Release` 构建。
- 主批次受测 CLI SHA-256：`8dad7486c9b5ccc7fd8be07392b9f5f7f69fb07e7ae26db8bca0e5727ac474f0`（本批构建 + 合成跨段 + 规则身份同产物，日志 `.codex-build-logs/action-analyze-transfer-rule-batch-20261126-041029.log`）；并发工作流随后重建为 `6d18cad8…`、`bde6ab63…`、`c2d46be2514446d07ccdeac9aaaca754254c6ec53b58d1c134bf2271dbb87d24`，本夹具在 `c2d46be2…` 上复核退出 `0` 且值一致。
- 退出码 `0`，最终输出 `CLI_RULE_PROFILE_IDENTITY=PASS`。
- 基线/新采样/恢复摘要均为 `45a1438f3ecb31467a5d780502d38f423dbeb2c0865ab5d38b58c78cbe2d27f4`；该值同时等于 `Release/profiles/action_analyze_api_rules.json` 的实际字节 SHA-256。
- 新采样 `86fb6ec5-bbc1-41fb-bc45-424de85fd601`（`8dad…`）、并发复核 `3f18be43-d909-46ad-97be-c611a9dfb2e4`（`c2d4…`）：`sourceSha256 == recordedSourceSha256 == 45a1438f…`，`matchesRecordedRules=true`，`archiveSource=jsonl-follow`。
- 旧关闭导入样 `92db3ac4-fc4a-4fa8-bf12-f5f9a03333e5`（`8dad…`）、并发复核 `f776c7fa-2dbd-43f3-a027-6d03670be125`（`c2d4…`）：`sourceSha256=45a1438f…`，`recordedSourceSha256=null`，`matchesRecordedRules=null`，`archiveKind=closed-api-import`。
- 只替换一条 ASCII `summary` 后：目录/回放摘要变为 `f233b6ac96be73da8d7e6b85d5aa1b3ee25480bbf0564dfe09bc9861ee350334`，`recordedSourceSha256` 仍为 `45a1438f…`，`matchesRecordedRules=false`；`finally` 恢复后回到 `45a1438f…` 且 `matches=true`。
- 坏规则文件：`api-rule-catalog` 与 `replay-api-rules` 均退出 `4`，状态 `rule-profile-unavailable`；同一跟随采样的图入口仍发布原包观察；关闭导入样 `api-evidence replay` 仍 `readback-verified`；恢复后 catalog 摘要回到基线。发布文件实测摘要始终为 `45a1438f…`，未留在测试字节。
- 前置回调档负例：固定旧 callback 档回放退出非零，状态为 `archive-unsupported`/`archive-unavailable`/`archive-invalid` 之一，未产生 `matches`/`matchesRecordedRules` 结论；本机夹具存在，输出 `RULE_IDENTITY_CALLBACK_OUT_OF_SCOPE=PASS`。
- 并行修复（仅测试脚本）：`decode_raw` 逐段解码时改为累计 Stored 序号；坏规则阶段对跟随档改用图入口，对关闭导入样使用 `api-evidence replay`。产品规则身份源码未改。
- 静态门禁：`git diff --check` 退出 `0`。`i18n audit` 在 04:01 批次以 `32149 source strings` 退出 `0`；随后并发工作流持续新增未入语言包的词条（本轮先后观察到 `nativeExecutionActiveOwner`/`nativeExecutionWrite`，以及 `HeldEvent`/`LiveRead`/`NtQueueApcThread`/`线程 TID` 等），最近复核退出 `1`。这些词条均不属于本页规则身份改动，本任务未代改他人语言包。
- 清理：固定测试根 `action-analyze-cli-validation` 已删除；发布规则文件原字节恢复；无遗留夹具进程。

## 未完成与下一步

- 未执行：Qt/Light 外置规则的实际界面显示、完整 GUI 矩阵、驱动和 Sysmon 相关回归（用户要求桌面实测后置）。
- `i18n audit` 当前被并发工作流新增的 4 个无关词条阻塞；待其作者补齐语言包后应复跑为最终门禁。
- 下一可执行步骤：主协调将本页 CLI 身份链回执并入第 11 项；Qt/Light 只在恢复桌面实测时按 AA-08 复用同一采样。
