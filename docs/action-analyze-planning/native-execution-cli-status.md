# 原生执行归档 CLI 旧验收任务登记

## 当前登记

2026-11-26，本次仅只读核对已派发任务的现有状态和产出，没有新派发、续接、重试、构建或替代测试。

- 旧验收会话：`01a216d8-edab-7087-9476-031913a77261`。
- 已授权续跑任务：`sh_216dd33bc001tWS4PttOV7SW9h`。
- 续跑目录标识：`20261126-035845-2803db44`，保存于派发工具的 `codebuddy-stream` 目录。
- 自然完成通知和最终 `status.json` 已确认 `state:failed`、`ok:false`、`exitCode:1`，结束时间为 `2026-11-26T04:47:37.2569117-04:00`，原因为 CodeBuddy 429 额度耗尽。未续接或重试。
- 日志中已出现对 `tools/action_analyze_validation/cli/product_native_execution.py` 的写入，仓库中也存在该脚本；脚本存在不证明已运行或断言通过。本次没有修改、执行或接管该脚本。
- 已接收并只读核对最后一轮日志 `.codex-build-logs/action-analyze-native-execution-cli-20261126-044715.log`：正式 HostX64/BelowNormal 构建成功，`native-save` 用例结束时累计断言为 55；后续 `history-read` 在夹具字符串/整数比较处失败，整批未通过，未生成成功 receipt。具体证据、SHA 和待验范围见 [自然结束登记](native-execution-cli.md)。

首次派发曾被宿主 120 秒时限中止；其旧状态文件未写完成，不能将该文件的 `running` 当作首次任务仍在运行。当前保留所有旧任务及原始日志，不擅自停止或清理。

## 证据适用范围

旧验收任务范围为原生执行保存、历史读取，以及 API 写入/线程创建与原生执行的一致性候选查询。完成结果到达后仅按实际日志登记，不自动续接失败或追加新场景。

旧脚本及旧任务的任何结果都不认证新增 APC 候选或 `apcCandidates` 输出，也不认证新增 `contextCandidates`；源码接入与本次局部运行证据分别记录。

`control.memory.snapshot` 和 `analyze execution memory` 仍按各自交付记录保持待验，不能由旧执行归档回执推断通过。

用户限制继续有效：“从现在开始暂时不允许派发CodeBuddy任务，我会在可用时告诉你”。禁止新增派发、续接、重试或替代测试；已有任务自然结果到达后只登记。
