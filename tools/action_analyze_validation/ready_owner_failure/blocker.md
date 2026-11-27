# Ready-owner failure 同步触发器

本目录现在包含一个只负责同步和外部释放的自有 x64 触发器。它不链接
`NativeDebugOwner`，不查询或修改产品状态，也不生成 `firstRecoveryFailure`。
触发器创建一个自有目标，目标分配一页私有 `PAGE_EXECUTE_READWRITE` 内存，
把精确的 PID、进程创建时间、分配基址、地址和大小通过 `READY` 发给外部
owner。目标随后等待 `GO`，由外部 owner 在 `ArmBreakpoint` 已经进入
`Armed` 后发送。

## 已接受的屏障

唯一接受的释放屏障是真实的 NX Held 停点。外部调用方必须先确认：

- Agent 已经 Ready，且仍未被停止；
- `NativeDebugOwner::Query` 返回 `Held`；
- `breakpointHit` 命中 `READY` 中的精确私有地址；
- 停止组为 `HeldComplete`，事件、stop、owner、状态修订和线程身份均来自同一份当前回执。

调用方把这些事实通过 `HELD` 发送给触发器。触发器会再次核对目标强身份和
分配身份，然后在目标仍由触发器父进程持有、且没有主动终止的条件下执行：

```text
VirtualFreeEx(targetHandle, allocationBase, 0, MEM_RELEASE)
```

释放前必须由 `VirtualQueryEx` 确认原地址属于精确的已提交区域，且
`AllocationBase`、`BaseAddress`、`RegionSize` 与 `READY` 一致。释放后再次
`VirtualQueryEx`，只有 `State=MEM_FREE` 才会在 `RELEASE` 中报告
`regionVerifiedFree=true`。保护位变化、伪造 Ready、Agent 停止、目标退出和
先释放后补发 Held 都不满足协议。

## 组合步骤

1. 启动 `ActionAnalyzeReadyOwnerFailureTrigger.exe --serve`，读取唯一的
   `READY` 行。不要把其它进程的 PID、地址或重新分配后的地址写入后续命令。
2. 用 `READY` 的 `pid`、`creation`、`address` 和 `bytes` 建立生产 owner 的
   显式私有页断点，使用 `privateAddress=address`、`privateRangeBytes=bytes`。
   先等待真实 `Armed`，再确认同一目标的 Agent Ready 且仍未停止。
3. 向触发器发送 `GO`，收到 `GO_ACCEPTED` 后由生产 owner 查询真实执行结果。
   只有同时满足 `Held`、精确命中和 `HeldComplete` 才能继续；缺少真实 Held
   必须中止，不得继续发送 `HELD`。
4. 发送一行 `HELD`。字段值不能包含空格，布尔值只用 `true` 或 `false`：

```text
HELD mode=continue|step agentReady=true agentUnstopped=true statusHeld=true breakpointHit=true heldComplete=true pid=<READY.pid> creation=<READY.creation> allocationBase=<READY.allocationBase> address=<READY.address> bytes=<READY.bytes> eventPid=<target-pid> eventTid=<real-event-tid> eventSerial=<real-event-serial> stateRevision=<real-revision> ownerSampleId=<owner-sample> ownerSessionId=<owner-session> ownerEpoch=<owner-epoch> ownerBackendId=<owner-backend> groupId=<real-group> stopId=<real-stop> eventBackendId=<real-event-backend>
```

   `mode` 必须与后续正式操作一致。触发器返回 `RELEASE` 后，检查
   `freeSucceeded=true`、`freeError=0` 和 `regionVerifiedFree=true`；任何一个
   不满足都不是目标场景的成功释放。
5. 释放回执确认后，生产 owner 才调用已有的正式 `Continue` 或 `Step` 路径。
   `Step` 必须使用当前 Held 事件构造完整的 `NativeStepRequest`，不能用手工
   `ContinueDebugEvent` 替代；`Continue` 也必须使用当前 owner、group、stop、
   event 和状态修订生成 `ReleaseRequest`。
6. 从生产 owner 的真实 `NativeControlResult.firstRecoveryFailure` 回读结果，
   再发送 `RECOVERY`。触发器只保存并回显这些字段，不接受由释放结果推断的
   替代值：

```text
RECOVERY mode=continue|step status=<real-status> firstRecoveryFailurePresent=true firstRecoveryFailureStage=<real-stage> firstRecoveryFailureError=<real-error> ownerSampleId=<real-owner-sample> ownerSessionId=<real-owner-session> ownerEpoch=<real-owner-epoch> ownerBackendId=<real-owner-backend> pendingEventBackendId=<real-event-backend> pendingEventSerial=<real-event-serial> releaseRequestId=<real-release-request>
```

7. 只有完成正式 Continue/Step、读取实际 `firstRecoveryFailure` 并记录
   `RECOVERY` 后发送 `STOP`。触发器收到 `STOP` 才释放自有停止标记，并输出
   `DONE`；目标必须保持存活到生产 owner 完成清退。若生产 owner 需要在
   `RECOVERY` 前关闭，应记录为协议未完成，不得把 `DONE` 当作恢复成功。

## 输出语义

- `READY`：仅是触发器自有目标和原始分配身份，不是 Agent Ready 证据。
- `GO_ACCEPTED`：目标已允许执行 NX 页，之后的 Held 必须由生产 owner 实际查询。
- `RELEASE`：包含释放结果、释放前区域和释放后 `MEM_FREE` 回读。
- `RECOVERY`：包含调用方原样提交的模式和实际 `firstRecoveryFailure` 字段。
- `DONE`：仅表示触发器目标收到停止标记并观察到退出，不表示生产恢复通过。

后续接入 `live_agent_failure_recovery` 时，A/F/C runner 负责生产 Agent
Ready、owner 查询、正式 Continue/Step、目标恢复和 C 的独立证据；本触发器
只插入 F 的真实 Held 屏障与原始分配释放步骤。不得用 F 的 Agent stopPath
代替 Held 屏障，也不得用 C 的成功代替 F 的 `firstRecoveryFailure`。

## 初始实现边界

夹具初始提交只完成源码、固定 Release x64 工程、工程过滤器和组合协议文档，
当时没有构建、运行或启动 GUI。正式接入仍需按上述协议运行，并保存原始
`READY`、`RELEASE`、`RECOVERY`、`DONE` 行。

## 本轮实际验证

固定 `Release|x64` 增量构建已完成，runner 与 trigger 均使用统一
`Ksword5.1\x64\Release` 输出；runner 编译器为 HostX64，构建宿主为
`BelowNormal`。唯一一次修正版 Continue 场景记录在
`runtime-receipt-continue-canonical-owner.txt`，旧的 owner 身份失败回执
`runtime-receipt-continue.txt` 保留。

本轮已由生产 `NativeDebugOwner` 观测并通过：`Arm -> Armed -> GO ->` 真实
NX `Held`、精确私有地址命中、`HeldComplete`、owner/event 身份一致、外部
精确释放的 `VirtualQueryEx` 前置与释放后 `MEM_FREE` 断言，以及生产
`NativeControlResult.firstRecoveryFailure`。该 fixture 没有加载 Agent，回执
明确标记 `agentLoaded=false` 和 `nativeRecoveryBranch=true`。

场景未形成干净收尾：生产恢复失败为
`private-execution-page-rearm-external-protection`（Win32 `487`），随后
`owner-cleanup-evidence` 失败，未发送 `DONE`。现有回执保留该失败；runner
已补强为在后续运行中原样持久化 `RELEASE`/`RECOVERY`，并在清理断言前写入
`OWNER_CLEAN` 的 `clean`、`attached` 和恢复失败字段。该改动尚未重跑场景，
因此不把新增持久化字段写成已有运行证据。本回执证明了 native
recovery-failure 分支和释放屏障，不证明 `clean && !attached` 或目标自然
清退；不得将本轮写成全通过，也不得以触发器目标清理代替 owner 清理。
