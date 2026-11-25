# 原生 ETW 控制器回归

此工程编译生产 `EtwSessionController`、`PassiveEtwSource` 和 ActionAnalyze CLI 派发层。仅对原生控制器编译单元替换 `StartTraceW`、`EnableTraceEx2`、`OpenTraceW`、`ProcessTrace`、`CloseTrace` 和 `ControlTraceW`，测试过程只操作夹具的会话与消费者。

从仓库根目录以 `BelowNormal` 优先级启动 64 位 MSBuild，按 `Release|x64` 构建 `tools/native_etw_controller_validation/NativeEtwControllerTests.vcxproj`。使用 `/p:PreferredToolArchitecture=x64`、`/p:PROCESSOR_ARCHITECTURE=AMD64` 和 `/p:PROCESSOR_ARCHITEW6432=AMD64`。工程在编译前输出 `IntDir`、`OutDir` 和 `HostX64`，启用 `/W4 /WX` 和断言。中间产物固定在 `tools/native_etw_controller_validation/x64/Release/`。在统一输出目录运行 `Ksword5.1/x64/Release/NativeEtwControllerTests.exe`，通过时退出 `0`。验收后核对路径、使用状态和 Git 跟踪状态，清理本次创建的夹具产物。

将上述 `IntDir` 的绝对路径作为参数传给 EXE，可额外运行 CLI 派发层测试。它在该目录下分别创建 `full-ledger`、`eof` 和 `shutdown` 三个独立项目，拒绝使用已存在的项目目录。

## 判据

- 在 `OpenTraceW` 替身内阻塞工作线程，等待控制器接受停止请求后放行。打开成功时记录 `BeforeProcessTrace` 并跳过 `ProcessTrace`。同一时序的打开失败保留原生 `87`，启动中止回执为 `None`。如果停止请求在打开提交前就已获受理，控制器记录 `BeforeOpenTrace`。
- `processAttempted` 表示工作线程已提交消费调用。事件回调为已开始消费提供独立证据。同一 `87` 在消费失败分支仍为原生错误。`ERROR_CANCELLED` 也保留；两个结果的来源终态为 `Failed`，现有采样归档据此报告 `partial`。
- 已提交消费且截至停止请求没有收到任何原生回调时，完整交付不可确认。消费者在 logger 清退前被关闭或结束时也保持该标记。即便 `ProcessTrace=0` 且成功取得 STOP 统计，来源仍报告 `Failed`，现有采样归档据此报告 `partial`。正常观察到事件并完成 STOP 和排空的正控仍报告 `Stopped`。
- 在工作线程已消费时让 STOP 和 Close 同时失败，核对两次原生失败、原 logger 名称和两个固定句柄仍归原所有者。对同一实例重试后核对相同句柄得到释放、线程完成、首个 STOP 错误仍在原生回执中。
- 保留现有的注册表所有者重试、单独 Close 失败、消费自然退出和启用失败补偿用例。待完成关闭使用 `ERROR_CTX_CLOSE_PENDING`，最终回执同时要求 `ProcessTrace` 已返回。
- 将 4,092 条回执写入账本，确认新普通请求被拒绝。STOP／Close 首次失败后，用同 ID 重放不得再次触发原生 API。新 ID 和当前修订可重试一次，验证 raw 归档后关闭采样和项目。EOF 和 shutdown 在原生失败仍持续时，派发层保留未清退和待归档状态。夹具会解除替身故障再销毁；此结果不覆盖持续原生失败下的进程退出。

Windows 实际 API 行为及正式 CLI 归档由自有 provider 产品回归另行验证。固定的替身 `87` 和线程门闩用于核对实现分支。

HostX64 替身夹具运行退出 `0`，临时测试 EXE、PDB 和中间生成文件已移除。正式 CLI 用自有 provider 核对 12 条观察与精确载荷，快速 EOF 和快速 REPL 停止报告 `partial`，都已完成原生清退并可重开归档。收到事件后的人工停止报告 `stopped`，目标退出报告 `target-exited`。正式 JSONL 验证通过 71 帧及 10 项请求向量。产物位于 `Ksword5.1/x64/Release/KswordCLI.exe`，构建和运行日志为 `.codex-build-logs/action-analyze-cli-checkpoint-shared-build.log`、`.codex-build-logs/action-analyze-cli-etw-cleanup-contract.log`。真实 Windows 的 STOP／Close 双失败由替身回归提供分支证据，正式 CLI 的满账本清退重试仍待覆盖。

加入 `startupAbort` 和 `tailDeliveryUnconfirmed` 字段后，正式 CLI HostX64 构建退出 `0`。产物 SHA-256 为 `7ED74105E5EE1E3AFFE0055274C9F001E15A9EADAEC36F00DE3AEAF3D519836D`。实际快速 REPL 停止回报 `before-open-trace`，快速 EOF 回报 `ProcessTrace=0` 及 `tailDeliveryUnconfirmed=true`。两条回执均为 `partial`，原生清退完成，终态字段与 Stored 记录一致。已收到 12 条事件的人工停止回报 `stopped`。正式 JSONL 复验通过 72 帧及 10 项请求向量，测试项目已删除。构建与运行日志为 `.codex-build-logs/action-analyze-cli-startup-receipt-build.log` 和 `.codex-build-logs/action-analyze-cli-etw-startup-receipt.log`。

`monitor etw capture` 现读取控制器实际的 `consumerJoined`。原生夹具覆盖没有工作线程、STOP 与 Close 同时失败、同一所有者重试后 join，以及跳过消费调用但工作线程已 join。HostX64 `/W4 /WX` 夹具退出 `0`，本次产物已清理。正式 CLI 用自有 GUID 完成空采样并确认 `consumerJoined=true`、`processCompleted=true`、`sessionStopped=true`。ActionAnalyze JSONL 同批通过 71 帧和 10 项请求向量，测试项目已删除。正式 CLI SHA-256 为 `5AC7327B53C91C4194FA4271F0D6A401D5FC1DA84FB4D1C7FFDA4FC5AD2C976B`，日志位于 `.codex-build-logs/action-analyze-etw-join-fixture-build.log`、`.codex-build-logs/action-analyze-cli-etw-join-build.log`、`.codex-build-logs/action-analyze-cli-etw-join-product.log` 和 `.codex-build-logs/action-analyze-cli-etw-join-contract.log`。

满账本及 EOF／shutdown 派发层夹具通过，固定目录内三个项目及夹具产物已清理。正式 CLI HostX64 增量构建退出 `0`，SHA-256 为 `2E81871A571ABFB2B4C783504B043A0073C1E0922459F1A4041C3BAFD4C14569`。正式被动 ETW 回归再次通过 71 帧和 10 项请求向量，测试项目已删除。日志位于 `.codex-build-logs/action-analyze-etw-ledger-fixture.log`、`.codex-build-logs/action-analyze-cli-etw-ledger-build.log` 和 `.codex-build-logs/action-analyze-cli-etw-ledger-contract.log`。
