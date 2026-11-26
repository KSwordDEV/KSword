# 原生执行归档 CLI：旧任务自然结束登记

## 结论

2026-11-26，旧任务 `sh_216dd33bc001tWS4PttOV7SW9h` 自然结束，CodeBuddy 会话 `01a216d8-edab-7087-9476-031913a77261` 最终状态为失败，退出码 1，原因为 429 额度耗尽。整批验收未完成，不能标记产品批次通过。本登记仅回读既有日志；没有新派发、续接、重试、修改夹具、构建或替代测试。

## 可复用的局部证据

原始日志：`.codex-build-logs/action-analyze-native-execution-cli-20261126-044715.log`。

- 该轮日志记录同线程验收互斥 `Local\KSword.ActionAnalyze.CliValidation`，PID 20020，等待 0ms。
- 正式构建记录 `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`；HostX64，BelowNormal。
- 固定 IntDir：`KswordCLI/x64/Release`；OutDir：`Ksword5.1/x64/Release`。
- 该轮受测 `KswordCLI.exe` 的 SHA-256：`EF9451260A31F6608E6A30CE1F1DEFBF967B47454A3BADFBED04D36868061586`。这是日志中的历史受测产物身份，不表示当前磁盘产物仍为同一文件。
- 日志末尾 `CASE=native-save ASSERTIONS_SO_FAR=55`，仅说明执行到该用例结束时的累计断言数，不是全套断言数。
- 局部真实运行记录包括：自有目标 DR0 进入尝试；九种错误会话/参数/停点输入拒绝；原生事件首次保存和重复保存返回相同段坐标；Into 单指令完成保存为第二段；再次命中保存为第三段；显式继续后正常关闭，summary 为退出码 0、`clean:true`、`attached:false`。
- 三次保存的原始 written/flushed 边界及段 SHA 均在日志中保留。第一段末 sequence 为 1，第二段为 2，第三段为 3。

## 中断原因与尚未覆盖范围

最后一轮在 `history_read_case` 第一个段的回读检查中，于夹具 `product_native_execution.py:847` 执行 `document['instructionAddress'] > 0` 报 `TypeError`：归档地址按正式格式为十进制字符串，不能直接与整数比较。该错误是夹具类型处理问题；本次不修复、不重跑。该段之前已有项目/采样、历史标识、段 SHA/端点等检查，但没有 `CASE=history-read` 完成标记，历史读取全用例仍待验。

同一旧任务此前还修正过夹具对错误阶段、Continue expected 形状以及单次命令 JSON data 外壳的假设；并遭遇并发新增文件尚未落盘的构建失败。这些旧重试属于已运行任务的原始记录，不是本次新发起动作。管道工具曾把包含 traceback 的命令显示为退出 0，不能据此认定测试通过；最终派发器状态和实际断言/异常优先。

依本轮脚本顺序，历史读取之后的跨会话复用、REPL 保存、租约冲突、坏链/失败写入阻断、上限边界及 correlate 正反例均未在最后一轮到达，保持待验。未生成 `action-analyze-native-execution-cli-*-receipt.json`，不登记全套成功或完整断言数。

本次没有独立检查或执行清理。局部用例日志已确认 owner 正常清退；脚本虽有 finally 清理路径，但缺少最终目录/进程核对回执，因此不宣称全部临时目录、夹具产物或进程清理通过。保留原始日志和现有文件，不擅自删除。

本回执不认证新增 `control.memory.snapshot`、`analyze execution memory`、APC 或上下文关联，不证明真实共同跨进程 API 触发。构建成功也不替代这些入口的实际测试。

用户限制继续有效：“从现在开始暂时不允许派发CodeBuddy任务，我会在可用时告诉你”。后续仅待明确恢复授权；不得自动续接、重试或自行替代测试。
