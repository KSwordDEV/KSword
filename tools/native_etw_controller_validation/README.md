# 原生 ETW 控制器回归

此工程编译生产 `EtwSessionController` 和 `PassiveEtwSource`。仅对控制器编译单元替换 `StartTraceW`、`EnableTraceEx2`、`OpenTraceW`、`ProcessTrace`、`CloseTrace` 和 `ControlTraceW`，测试过程只操作夹具的会话与消费者。

从仓库根目录以 `BelowNormal` 优先级启动 64 位 MSBuild，按 `Release|x64` 构建 `tools/native_etw_controller_validation/NativeEtwControllerTests.vcxproj`。使用 `/p:PreferredToolArchitecture=x64`、`/p:PROCESSOR_ARCHITECTURE=AMD64` 和 `/p:PROCESSOR_ARCHITEW6432=AMD64`。工程在编译前输出 `IntDir`、`OutDir` 和 `HostX64`，启用 `/W4 /WX` 和断言。中间产物固定在 `tools/native_etw_controller_validation/x64/Release/`。在统一输出目录运行 `Ksword5.1/x64/Release/NativeEtwControllerTests.exe`，通过时退出 `0`。验收后核对路径、使用状态和 Git 跟踪状态，清理本次创建的夹具产物。

## 判据

- 在 `OpenTraceW` 替身内阻塞工作线程，等待控制器接受停止请求后放行。打开成功时记录 `BeforeProcessTrace` 并跳过 `ProcessTrace`。同一时序的打开失败保留原生 `87`，启动中止回执为 `None`。如果停止请求在打开提交前就已获受理，控制器记录 `BeforeOpenTrace`。
- `processAttempted` 表示工作线程已提交消费调用。事件回调为已开始消费提供独立证据。同一 `87` 在消费失败分支仍为原生错误。`ERROR_CANCELLED` 也保留；两个结果的来源终态为 `Failed`，现有采样归档据此报告 `partial`。
- 已提交消费且截至停止请求没有收到任何原生回调时，完整交付不可确认。消费者在 logger 清退前被关闭或结束时也保持该标记。即便 `ProcessTrace=0` 且成功取得 STOP 统计，来源仍报告 `Failed`，现有采样归档据此报告 `partial`。正常观察到事件并完成 STOP 和排空的正控仍报告 `Stopped`。
- 在工作线程已消费时让 STOP 和 Close 同时失败，核对两次原生失败、原 logger 名称和两个固定句柄仍归原所有者。对同一实例重试后核对相同句柄得到释放、线程完成、首个 STOP 错误仍在原生回执中。
- 保留现有的注册表所有者重试、单独 Close 失败、消费自然退出和启用失败补偿用例。待完成关闭使用 `ERROR_CTX_CLOSE_PENDING`，最终回执同时要求 `ProcessTrace` 已返回。

Windows 实际 API 行为及正式 CLI 归档由自有 provider 产品回归另行验证。固定的替身 `87` 和线程门闩用于核对实现分支。

HostX64 替身夹具运行退出 `0`，临时测试 EXE、PDB 和中间生成文件已移除。正式 CLI 用自有 provider 核对 12 条观察与精确载荷，快速 EOF 和快速 REPL 停止报告 `partial`，都已完成原生清退并可重开归档。收到事件后的人工停止报告 `stopped`，目标退出报告 `target-exited`。正式 JSONL 验证通过 71 帧及 10 项请求向量。产物位于 `Ksword5.1/x64/Release/KswordCLI.exe`，构建和运行日志为 `.codex-build-logs/action-analyze-cli-checkpoint-shared-build.log`、`.codex-build-logs/action-analyze-cli-etw-cleanup-contract.log`。真实 Windows 的 STOP／Close 双失败由替身回归提供分支证据，正式 CLI 的满账本清退重试仍待覆盖。
