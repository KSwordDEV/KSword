# 原生停点步进：已有 CodeBuddy 结果登记

## 当前状态

**未通过，未闭合。** 本文件由开发作者登记已有任务返回的失败结果，不是 CodeBuddy 的最终验收回执，也没有补跑测试。用户已暂时禁止 CodeBuddy 新派发、续接、失败重试和替代测试；既有任务自然结束后没有重启。

已有会话 `01a216a4-5132-7708-b33e-673afa8c625f` 最终因 CodeBuddy `429` 额度耗尽结束，派发退出 `1`，无最终模型结果。末尾修改脚本因 `AssertionError: child thread log block` 失败，没有完成该批拟议测试修订。

## 已有构建与运行证据

最后一组已知元数据前缀：

`.codex-build-logs/behavior-planning/action-analyze-native-step-20261126-084542-7683585-41800-`

| 项目 | 已有结果 |
| --- | --- |
| 构建脚本 | `KswordCLI/ActionAnalyze/Control/tests/Invoke-NativeStepValidation.ps1` |
| 执行方式 | CodeBuddy 通过 PowerShell 调用该脚本；脚本直接链接生产控制源和自有目标夹具 |
| 固定 IntDir | `KswordCLI/ActionAnalyze/Control/tests/x64/Release/NativeStep/` |
| 统一产物 | `Ksword5.1/x64/Release/ActionAnalyzeNativeStepValidation.exe` |
| 工具与优先级 | 已有输出记录 MSVC `14.44.35207` HostX64、BelowNormal、`/W4 /WX` |
| 构建退出码 | `0` |
| 运行退出码 | `1` |
| 运行汇总 | `RESULT=FAIL checks=666 failures=2` |
| Watchdog | `False` |
| 当次 EXE SHA-256 | `DF4F52120A84BDF1B4437D963D64F3E0C365F4D16A477673F04D5354A817B4A5` |
| 当次进程检查 | 元数据 `LEFTOVER_FIXTURE_PROCESSES=` 为空；只代表当次检查，不代表另行复查 |

已有失败为：

- `thread-exit`：`existing-peer-thread-scheduled-after-step`。
- `process-exit`：`process-exit-ended-the-target`。

较早运行曾为 `648`／`665`／`666` 项检查、单个线程退出场景失败；不能选择较早数字掩盖最后一组的两项失败。更早夹具编译失败、看门狗运行失败和诊断日志仍按原路径保留。

当前源可能含末次运行后的夹具编辑和并行私有执行开发，未保存该次完整源散列清单。上表 EXE 散列仅属于已有运行元数据，不能据此声称覆盖现在的全部源或私有执行功能。没有清理不明来源的 IntDir 文件或原始证据，也未核实测试配置清理完成。

## 接口与未完成项

`NativeDebugOwner::Step(NativeStepRequest)` 使用完整 `ReleaseRequest`、线程强实例、TID、创建 FILETIME 和模式；内部请求键是严格递增的 `continue/N`，与人工继续共用序列。`QueryStep` 查询原回执，`CancelStep` 只请求中断，完成仍需真实事件和资源回读。新停止组有新授权，普通步进停点不携带旧 `breakpointHit`；提前命中用户 DR0 时保留用户断点语义。

已有 CodeBuddy 针对 TF／DR 原因识别及提前 DR0 命中进行了产品修订，但完整变更和覆盖结论尚无最终回执。后续恢复验收前须核对线程退出路径的同伴挂起债务：失败不得清账，任何恢复辅助函数都必须检查 `ResumeThread` 结果并保留未解责任。当前不能声称取消、关闭、线程／进程退出和全部资源恢复已经验收完成。

待用户明确恢复 CodeBuddy 后，仍由作者派发其完成必要修复、真实原生复测、源与 EXE 身份、断言范围和清理回执。不得将本登记文件、历史 R3 固定 MASM 夹具或编译通过当作正式 CLI、GUI、普通 R0 或私有执行位置绑定验收。
