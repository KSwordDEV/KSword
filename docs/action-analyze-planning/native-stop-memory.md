# 原生停点内存读取最小必要真实无窗口验收回执

本回执只覆盖新增产品 `CaptureNativeStopMemory` 与 `OwnedDataWatchSession::CaptureMemory` 的
最小必要真实无窗口验收。夹具作者负责夹具、构建、运行、失败排查与准确落盘；产品代码由调用者
独立编写，本轮不修改产品源码。格式归档由另一 CodeBuddy 独立测试，本夹具只做单次写回读确认，
不改格式。

## 实际产物与命令

- 夹具目录：`tools/action_analyze_validation/native_stop_memory/`
- 构建入口：`tools/action_analyze_validation/native_stop_memory/Invoke-NativeStopMemoryValidation.ps1`
- 固定 `IntDir=E:\Projects\Ksword5.1\tools\action_analyze_validation\native_stop_memory\x64\Release`
- 统一 `OutDir=E:\Projects\Ksword5.1\Ksword5.1\x64\Release`
- 产物：`E:\Projects\Ksword5.1\Ksword5.1\x64\Release\ActionAnalyzeNativeStopMemoryValidation.exe`
- 构建宿主：`D:\Software\VS\VC\Tools\MSVC\14.44.35207\bin\HostX64\x64\cl.exe`，
  MASM `...\HostX64\x64\ml64.exe`，均经 `where` 回读为 HostX64。
- 宿主优先级：`BelowNormal`，编译/链接子进程沿用。
- 编译标志：`/std:c++20 /permissive- /EHsc /W4 /WX /O2 /MT /utf-8 /DNOMINMAX`，0 警告、0 错误。
- 仅构建本夹具及其复用工程依赖，未构建 CLI、Qt、KswordARKLight，未加载驱动，
  未使用 GUI/Sysmon/第三方，未运行既有 1313 group 或全 step 矩阵。

## 最终证据（以该批次为准）

| 项 | 值 |
| --- | --- |
| 证据前缀 | `.codex-build-logs/behavior-planning/action-analyze-native-stop-memory-20261126-084027-3886180-26236` |
| `BUILD_EXIT_CODE` | `0` |
| `RUN_EXIT_CODE` | `0` |
| `WATCHDOG` | `False` |
| 断言 | `RESULT=PASS checks=87` |
| 可执行体 SHA-256 | `B741DDE4FAA855D12CC34B00C49AD8CA4C05BD1D1BA88DFF2D53869630C8AC32` |
| `SCRATCH_CLEANED` | `yes` |
| `LEFTOVER_FIXTURE_PROCESSES` | 空 |
| 构建日志 | `...-20261126-084027-3886180-26236-build.log` |
| 运行日志 | `...-20261126-084027-3886180-26236-run.log` |
| 元数据 | `...-20261126-084027-3886180-26236-metadata.txt` |

运行日志实测关键行：`HELD eventCode=1 exception=2147483652 hit=1 stage=execution-breakpoint-held tid=42180`
（`0x80000004` = `EXCEPTION_SINGLE_STEP`，`breakpointHit` 有值，真实执行断点），
`STEP_STARTED status=3 stage=continue-debug-event error=0 release=1 receipt=1 result=0 step=step-running stepError=0`
（`result=0` = `ReleaseResult::Continued`，真实 Into 已放行），`DIRECT_SECTION_DONE checks=65`。

## 断言分组（共 87）

直接 `CaptureNativeStopMemory` 段 65 项（`DIRECT_SECTION_DONE checks=65`）：
1. 自有 AMD64 合作子进程在真实硬件执行断点停住；`status=Held`、`attached`、`!clean`、
   `group.state=HeldComplete`、`pending.ledgerOwned`、`responsibility` 齐备，
   `breakpointHit` 非空、`eventCode=EXCEPTION_DEBUG_EVENT`、`exceptionCode=EXCEPTION_SINGLE_STEP`。
2. 从原 `owner.Query()` 提取完整 `ProcessGroupStop`，`CaptureNativeStopMemory` 以同一身份与精确
   令牌逐页读取 16 字节已知模式：`stage=process-memory-read-observed`、`completeRange`、
   单页捕获、逐字节匹配 `KswordNativeStopMemoryBytes`。
3. `before`/`after` 两个原 owner 回读令牌逐字段等于请求 stop，`heldAtBothChecks=true`；
   请求对象未被读取过程改写。
4. 读后 `owner.Query(groupId)` 仍 `Held`、事件相同、`stateRevision` 相同、`release` 为空：
   读取动作没有 Continue、没有让出停点。
5. 负控全部在读取前拒绝且无 `snapshot`、不改变 owner：LiveRead 携带 stop、缺 stop、
   错 sampleId、未授权、错 sessionId、错 epoch、错 backendInstanceId、错目标创建时间、
   旧 event serial、旧 `stateRevision`、旧 `groupId`。阶段分别为
   `process-memory-held-request-required` 与 `process-memory-stale-stop`。
6. 所有负控后 owner 仍持有同一原生事件且没有产生继续回执。
7. 真实 Into 步进得到新组与新停点（`step` 完成、`stopGroupId` 变化、`breakpointHit` 为空），
   在该停点上 `CaptureNativeStopMemory` 再次成功且字节一致；随后释放步进事件、子进程正常退出、
   owner `Close` 回读 clean。

会话段 22 项（87 − 65）：
1. `OwnedDataWatchSession::Start(..., sampleId)` 绑定新 UUID sampleId；`Identity()` 回读一致，
   编译期 `static_assert` 固定 `const OwnerIdentity&` 只读契约。
2. 启动时条件求值计数全 0；真实数据写入停点（`breakpointHit.dataChange` 有值、
   `HeldComplete`、完整令牌绑定本会话身份）上 `CaptureMemory` 读取已知 4 字节写入值。
3. 读取后 `ConditionReport` 计数仍全 0、原生事件不变：读取不触发条件自动继续。
4. 错 epoch 的旧显示快照被 `data-watch-memory-stale-stop` 拒绝且无读取。
5. 单次 `WriteProcessGroupMemorySnapshot` 接受 helper 输出的原请求模式与读前/读后完整令牌；
   `receipt.verified && completeRange && ordinal==1 && capturedBytes==4`，证明同步写回读通过。
6. `session.Close()` 回读 clean；固定 scratch 项目目录由脚本清理。

## 失败排查与夹具稳定性

排查过程中记录并闭合了以下夹具侧问题（均非产品新增缺陷）：
- 早期 owner 身份使用非 UUID 标签，`StopLedger` 构造抛出未捕获异常导致 fastfail `0xC0000409`；
  改用规范 UUID 后消失。
- 首次 C++ 断点函数首指令不被产品步进解码器支持（`step-instruction-unsupported`）；
  改为 MASM NOP 站点后，Into 步进可用。
- `OwnedDataWatchSession::Start` 不接受命令行参数；改用继承环境变量把同一 EXE 切到写入子进程模式。
- 产品将 `CaptureMemory`/`SaveExecution` 拆到 `OwnedDataWatchSessionArchive.cpp`、
  新增 `NativePrivateExecutionSite.cpp`、`NativeDebugOwner.cpp` 后续变更；构建源清单同步补齐。
- Windows `min/max` 宏冲突通过 `/DNOMINMAX` 消除。
- 数据写入子进程需在 owner 武装断点前进入稳定等待态；由对端线程先置 ready 后，
  连续 4 次运行均 `PASS checks=87`，`step-suspend-peer` 竞态不再复现。
- 失败轮证据与最终 PASS 证据均保留在 `.codex-build-logs/behavior-planning/`，未删除历史失败日志。

## 清理

- 自有子进程：由私有 Job（KILL_ON_JOB_CLOSE）与显式退出事件双重约束；
  最终批次 `LEFTOVER_FIXTURE_PROCESSES` 为空。
- 固定 scratch 项目目录 `tools/action_analyze_validation/native_stop_memory/x64/Release/native-stop-memory-archive-scratch`
  在脚本 `finally` 中删除；最终 `SCRATCH_CLEANED=yes`。
- 命名事件 `Local\KSword.NativeStopMemory.DataWatchGate` 由宿主与子进程句柄关闭而释放。
- 产物 EXE/OBJ/PDB 位于固定 `IntDir` 与统一 `OutDir`，无系统临时目录、无 `output/`、
  无随机 `runtime-*`、无运行时副本。未提交、未暂存，未触碰用户 7 项暂存。

## 未验范围

- 未穷尽指令集、架构或全部断点/写入场景；只覆盖单一自有 AMD64 良性目标的
  一个执行断点、一个数据写入停点与一个 Into 步进停点。
- 未验证并发命中、多所有者竞争、所有者死亡恢复、R0 后端、普通 R0 29 项外部判据。
- 未运行完整归档格式矩阵（由另一 CodeBuddy 独立验收）；本夹具仅做一次写回读确认。
- 未做 GUI/HUD/Launcher 或独立桌面实机视觉验收；本机无驱动、无 GUI、无 Sysmon、无第三方参与。
- 未验证跨会话/跨项目重开后旧令牌的归档回放语义。
