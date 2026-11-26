# A4.3／SB CLI 停止责任账本

`StopLedger` 由 CLI 的单一控制执行者串行调用，接收外部调试 owner 为自有合作目标核验的原生事件证据。当前模型支持每个 owner 一条待处理 Debug Event 和顺序发生的多组停点。事件 owner 保存真实句柄、异常处置、事件序号及调用结果，并负责在错误或拒绝后继续持有实际事件。输入使用采样、后端、进程和线程的强实例 ID。源证据的原生身份核验归事件 owner。

| 接口 | 接入职责 |
| --- | --- |
| `Freeze(FrozenStopGroup)` | 在开启停点路由前预留记录。冻结请求线程、成员修订和上游计算的 SHA-256。规范化线程顺序并检查重复。本地检查 hash 文本格式，成员规范编码和 hash 计算归冻结范围的调用方。 |
| `AdoptNativeStop(groupId, NativeStop)` | 收到已认领的真实事件后导入。owner 实例和单调事件序号构成事件身份。原始站点异常和不同代次由适配器事先区别处置。已确认归属但阶段未知时，`phase` 留空并保留实际事件线程及责任。 |
| `ObserveMember`、`ObserveIncidental`、`SealMembership` | 提交逐项证据。仅同一原生事件进程内、经核验的冻结成员可标记为覆盖。附带线程独立提交集合质量，排除请求成员及独立展示的 origin。多个成员共享同一原生责任和 `stopId`。`SealMembership` 只结束首轮成员收集，后续仍可接受有序证据。 |
| `BeginRelease`、`QueryRelease` | 校验活 owner、epoch、事件身份、`stopId` 和预期状态修订。首次接受返回单次 `effect`。接受过的同 ID 同载荷返回 `Duplicate`，可查询原请求回执。同 ID 异载荷返回冲突。CLI 传输仍负责全局请求 ID 及拒绝回执的幂等。 |
| `RecordReleaseReceipt`、`RecordReleaseReadback` | 保存 exact attempt 的原生结果。成功只确认自身事件责任已释放。`StillPending` 需要核验事件确实未消耗，且旧尝试无法再调用 Continue。确认后可用新命令和当前修订明确重试。超时、结果丢失或未核验的失败保留待确认或恢复责任。 |
| `ObserveOriginExit`、`RecordRetiredOnExit`、`ConfirmNoNativeEvent` | 可单独记录范围外 origin 线程退出。退休需要证实精确原生事件已清退且其进程确实退出。无事件路径先确认路由没有武装或已排空，再结束证据已明确的冻结组。 |
| `Query`、`UnresolvedNativeResponsibility`、`CanRetireLedger` | 读取只读投影及内部仍待处置的事件责任。关闭调用方把后者作为独立门槛，继续核对路由清退、其它资源和真实脱离。 |

`HeldComplete` 适用于当次冻结成员。附带集合处于 `Partial` 或 `NotCollected` 时，真实事件仍保持全部进程级释放责任。附带成员在终态中保留为历史观察。确认继续后，原来未知成员的 `NotHeld` 只描述本账本已无持有，`MemberSnapshot::evidence` 仍保留当时证据。事件与成员状态均无法证明线程已经调度执行。

内部快照的 `nativeEventState` 保留组内原生事件的最后责任状态。相同的成员汇总（如 `Ended`）可对应已确认继续的 `Released`、已核验退出清退的 `RetiredOnExit`，或从未接纳原生事件时的空值。`Retryable` 和 `Indeterminate` 也分别保留。该字段只提供状态，不含原生事件身份或控制令牌。

`StopGroupSnapshot` 为内部类型。全部冻结成员已确认退出且原生 origin 仍持有时，内部投影 `OriginHeld` 对应草案的 `origin-held`。已提交释放和待恢复分别优先投影为 `ReleasePending` 和 `RecoveryRequired`。原生事件仍持有但 origin 已退出，或缺少可投影阶段且没有已核验成员持有时，内部保留 `UnprojectableNativeHold`。调用方使用内部责任查询继续追踪，不能把该状态写成终态。公开 JSON 投影、成员分页和命令注册是后续接入。本增量的释放单位是单个原生事件。指定单个成员继续、显式 Suspend/Resume、多个原生事件待决、其它资源回退、未来线程准入门控和 owner 死亡接管需独立验证。

每个账本保留 64 个组，每组最多 1024 个请求成员、1024 个已知附带成员和 64 条已接受释放命令。达到上限时保留已有账目，并返回 `Capacity`。如发生在恢复路径，仍可提交确切结果、读回或退出清退证据。下一步接入须核对预留失败和重复请求。冻结成员、已接受命令和历史组保留至该账本退休，历史组从未提供继续动作，重启后恢复实时控制不在本增量范围内。

从仓库根目录运行 `pwsh -NoProfile -File KswordCLI/ActionAnalyze/Control/tests/Invoke-Validation.ps1`。隔离工程构建并直接运行 `Ksword5.1/x64/Release/ActionAnalyzeStopLedgerValidation.exe`。测试沿用 [离线协议模型](../../../tools/trace_protocol_validation/test_protocol_model.py) 的重复命令、旧 epoch 和清理责任判据，直接编译并执行此处的 C++。构建和测试证据保存在 `.codex-build-logs/behavior-planning/action-analyze-cli-stop-ledger-*`。

原生接入门槛是同一真实调试 owner 关联 SB02 自有夹具，验证事件采用和 Continue 唯一性、丢失回执后的读回语义、关闭交错、成员及实际目标退出。原始 OS 处置与验证仍由实际适配器提供。

## CLI 的 R3 执行断点 owner

`NativeDebugOwner::ArmBreakpoint` 只接纳当前 CLI 宿主直接创建、显式授权且 PID 与创建时刻匹配的同用户同会话原生 AMD64 子进程。不派生采样对象，只有一个目标实例、一个断点绑定。使用当前已加载映像的完整 DOS 路径和 RVA 或区分大小写的非转发 PE 导出名，不支持 PDB、延迟加载绑定、WOW64 或其它后端。RVA 必须由调用方确认是指令边界。模块卸载触发退役，不自动跟随同址映像。

- `ArmBreakpoint` 的 `Accepted` 只表示已提交附加。以 `Query().breakpoint.state` 回读 `Armed`、`Held` 或退役/失败。初始停点完成武装，新线程在 `CREATE_THREAD_DEBUG_EVENT` 尚未继续时安装并读回同一 DR0 执行断点；有其它活动调试寄存器或 TF 时不接管。
- `Query` 在实际单步异常到达并通过事件、进程、线程、地址、DR6/DR7 复核后提供 `breakpointHit`、停止组和继续义务。组中的线程是本次冻结快照；原生事件暂停目标进程，不暂停其它进程。使用完整 `ReleaseRequest` 继续同一个事件，历史回执可查询，重复命令不会再次放行。断点正常继续后仍保持绑定。
- `Close` 撤销整个绑定。在未继续的工作事件或受到核验的标准调试中断上恢复自有寄存器，再继续并脱离。确认失败则保留相应责任和错误，可用 `Query` 观察；不把请求成功算作清洁脱离，不保证任意 owner 死亡后恢复。最多核验 1024 个活线程，保留 63 次断点命中，继续最后一次命中时退役；不得把容量退役当作持续覆盖。

正式 CLI 已登记 `NativeDebugOwner`、`NativeBreakpointImage` 和 `StopLedger`，实际入口为 `analyze breakpoint session`。HostX64 Release 增量构建已通过。未验证三端一致性、性能或普通 R0。

正式 `KswordCLI.exe` 的 JSONL 和 REPL 合计通过 30 项运行检查。独立确认首次命中前函数体未执行，有效继续后执行，同址再次获得不同停点；停止时退出，回执为 `clean=true`、`attached=false`，原子进程第二次执行后退出 `0`。JSONL 的旧修订和重复继续 ID 均未放行第二次停点。正式运行日志为 `.codex-build-logs/behavior-planning/action-analyze-product-breakpoint-20261125-033030-7079019-run.log`。
