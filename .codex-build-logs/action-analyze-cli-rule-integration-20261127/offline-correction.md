# CLI 规则回放后处理离线更正附录

- 原构建回执、原 replay stdout/stderr、原 `readonly-replay/receipt.json` 保持不变；原回执 `BLOCKED_POSTPROCESS` 不改写。原后处理首次错误为在 `PSCustomObject` 上调用不存在的 `.Contains()`，属于回执解析脚本错误，不是 CLI 失败。
- 本附录只读取已经落盘的 `readonly-replay/stdout.json`，没有重新启动 CLI、读取项目归档或执行场景、GUI、Build。原始 stdout SHA256：`58650f5bdc15406fd8390820f33da1c8ff56efaebfd6ca5494c7d4e4fcdd97fd`，259,671 字节；stderr 为空。
- Replay 命令本身退出 `0`，响应 `status=readback-verified`，项目 `18141f17-b514-4526-b9bb-63924ea690bd`，已提交两段、终段完成、`nextAfter=null`；线索数 88，coverage 仍为 `unknown`。
- Typed 字段：88/88 行均包含 `rule.observedFields` 数组，共 440 个字段。离线核对 id 非空且行内唯一；字段类型限于 `bool`、`u64`、`text`；值类型分别匹配 bool、规范无符号十进制字符串（不超过 UINT64_MAX）、字符串。0 个字段错误；每行规则状态均为 evaluated。
- 行为双语：44 条行为行均为 evaluated，`WriteProcessMemory`、状态码 5、证据 `reported-api-return`；英文 `Memory write request returned access denied.` 与中文 `内存写入请求返回访问被拒绝` 均逐条一致。0 个行为释义错误。
- Raw 坐标：88/88 行都有有效正十进制字符串 `rawSegment`、`rawSequence`、`sourceSequence`，三元坐标均唯一；44 条行为行的坐标也均唯一。此离线更正只验证原 replay JSON 中的坐标存在性、格式与唯一性，不重读归档或重新对照 GUI 历史文件。
- Rule profile：当前与记录 preset 均为 `ksword.api.behavior-presets.v3`；当前 source SHA256 `5067c8387c156b56e71de84d1e44877585c9090d4ab3704f745b2ce4675ff41d`，记录 source SHA256 `3f5283bba6ffb656ed691d92b9497ff46d3c41c6fb9c97453fb564ffef0beca8`，`matchesRecordedRules=false`、`configError=null`。身份不匹配如实保留，不当作相同规则版本。
- 实际构建范围：单次 KswordCLI `Release|x64` 增量构建，包装器 `tools/Invoke-KSwordCliBuildCheck.ps1`，HostX64／BelowNormal／固定 IntDir `KswordCLI/x64/Release`、OutDir `Ksword5.1/x64/Release`、`BuildProjectReferences=false`；CLI SHA256 `eabd8bd7d22d3498f6d8927c05b2a125dfd039790bb97a7cf8c16f6e646fa77c`。输入源码提交为 `6ba5fc62a`、`f3a3596f2`、`ba751d80d`；相关编译单元包括 `ApiMonitorEvidenceCommand.cpp`、`ApiRuleReplayCommand.cpp`、`ApiBehaviorObservation.cpp`、`BehaviorPresetFields.cpp`、`BehaviorPresets.cpp`。本次运行基线 HEAD 为 `ed3704e4c`。用户提示的后续 debug 输出不在此 CLI 哈希覆盖范围内。
- GUI 历史回执原状态仍为 FAIL；本次结果仅补充当前 CLI 对保留项目的离线回放及其 JSON 后处理核对，不覆盖 GUI FAIL、不构成原任务干净 PASS，也不扩为规则全量、GUI 或 ActionAnalyze 完整验收。
- 离线核对摘要另保存为 `offline-verification.json`（PASS，来源为上述 stdout 的 SHA256 `58650f5b…4e4fcdd97fd`）。原日志：`build.log`、`build-receipt.json`、`readonly-replay/stdout.json`、`readonly-replay/stderr.txt`、原始 `readonly-replay/receipt.json`；本附录及摘要仅追加更正，不改写原FAIL。
