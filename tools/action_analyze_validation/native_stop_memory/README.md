# 原生停点内存读取最小无窗口验收

对应 `CaptureNativeStopMemory` 与 `OwnedDataWatchSession::CaptureMemory` 的新增产品验收。
本目录只构建/运行一个原生自有无窗口夹具；不构建 CLI、Qt、Light，不加载驱动，不使用
Sysmon 或任何第三方组件，不跑既有 1313 group 或全 step 矩阵。

## 夹具结构

- `NativeStopMemoryTests.cpp`：宿主与自有良性 AMD64 子进程同一个 EXE。
- `NativeStopMemoryFixture.asm`：真实执行断点/Into 步进的确定性 NOP 站点。
- `Invoke-NativeStopMemoryValidation.ps1`：BelowNormal、HostX64、`/W4 /WX` 构建及运行。
- 固定 `IntDir=<本目录>/x64/Release`，统一 `OutDir=Ksword5.1/x64/Release`，
  产物 `ActionAnalyzeNativeStopMemoryValidation.exe`。

## 覆盖

1. 直接驱动 `NativeDebugOwner`：在真实执行断点（硬件 DR、`EXCEPTION_SINGLE_STEP`、
   `breakpointHit` 与 `HeldComplete` 完整令牌）上逐页读取 16 字节已知模式；
   核对读前/读后令牌逐字段一致、`target` 仍 Held、未产生任何 Continue 回执。
2. 负控：LiveRead 携带 stop、缺 stop、错 sample、未授权、错 session/epoch/后端身份、
   错目标创建时间、旧 event/revision/groupId——全部在读取前被拒绝且无 `snapshot`；
   所有负控后 owner 仍持有同一原生事件。
3. 真实 Into 步进后的新停点上再次读取仍成功且字节一致（对端线程先进入稳定等待态，
   避免 `SuspendThread` 首帧竞态）。
4. `OwnedDataWatchSession::Start` 绑定新 sampleId；真实数据写入停点上 `CaptureMemory`
   读取已知 4 字节；`ConditionReport` 计数不变证明读取不触发条件自动继续；
   旧 epoch 显示快照被拒绝；`Close` 回读 clean。
5. `Identity()` 的 `const OwnerIdentity&` 只读契约在编译期断言。
6. 单次 `WriteProcessGroupMemorySnapshot` 写回读：helper 输出的请求模式与读前/读后完整
   令牌被归档写入器接受，`receipt.verified` 证明同步回读通过；本夹具不改格式。

## 构建与运行

```powershell
& tools\action_analyze_validation\native_stop_memory\Invoke-NativeStopMemoryValidation.ps1
```

脚本在 `.codex-build-logs/behavior-planning/action-analyze-native-stop-memory-<runId>-*`
保存 build/run/metadata 证据，结束时清理固定 scratch 项目目录与自有子进程进程。
PASS 判据：`BUILD_EXIT_CODE=0`、`RUN_EXIT_CODE=0`、`RESULT=PASS checks=87`、
`SCRATCH_CLEANED=yes`、`LEFTOVER_FIXTURE_PROCESSES` 为空。
