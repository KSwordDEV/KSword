# 原生停点内存 CLI 接入

## 当前交付范围

`analyze breakpoint session --project PATH [--sample UUID]` 的单目标执行会话复用当前项目独占写租约、已提交采样及原 `NativeDebugOwner`，新增：

- JSONL：`control.memory.snapshot`，`params:{"base":"正十进制地址","bytes":"正十进制长度"}`，带当前 `session:{id,epoch}` 和 `expected:{stopId,stateRevision}`。
- REPL：`memory-snapshot BASE BYTES STOP_ID STATE_REVISION`，数值使用规范正十进制。

`Cli/NativeStopMemoryJournal` 借用 `NativeExecutionJournal` 持有的项目，不创建第二个 writer。请求先核对显示的 stopId/stateRevision，再冻结同一 owner 的完整当前令牌；核心 `CaptureNativeStopMemory` 独立执行读前/读后核对，不调用 Continue/Pause，不创建第二个 owner。保存通过 `WriteProcessGroupMemorySnapshot` 保留完整 `readContext`。

启动时核验一次已有 `raw-memory` 完整段链；后续复用段号与前序游标，不重扫全部旧链。同事件内允许新的时间/范围读取，每次形成新段。单次最多 64 页，每采样最多 4096 段。旧内存坏链或新的写入/刷盘/回读失败仅禁用内存追加，原生执行 lane 保持独立。响应保留真实字节数、页元数据/散列、整段 SHA-256、坐标及原始写入/刷盘边界；部分页不补零。响应 `exitCode:6` 表示范围不完整或停止状态改变，不关闭活控制会话。

历史读取和字节导出复用 `analyze memory read/export`。历史停点描述不授予活进程控制权。

## 同停点执行字节回查

正式入口为 `analyze execution memory --project PATH --sample UUID --native-ordinal N --memory-ordinal N [--bytes N] [--json]`。两个段号各自限定为 1..4096，`--bytes` 默认 1，范围 1..15。

`NativeExecutionCommand.cpp` 以只读方式打开项目，各自从首段核验 `raw-native` 与 `raw-memory` 到指定段，随后调用 `Detection/NativeExecutionMemory` 的 `AssociateNativeExecutionMemory`。核心核对项目、采样、进程强身份及 held-event 完整前后停点令牌，取原执行观察 `instructionAddress` 起的归档字节。命令层不按 nextRIP 取值，不回退实时或 changed-held 记录，不访问目标，也不比较 QPC。

成功回执包含 `bytesHex`、原始 `observation`、指令起点，以及两个来源各自的段号、SHA-256、核验状态和归档端点。执行来源保留原记录 sequence 和完整 `document`，内存来源保留参与字节选择的页 sequences 和完整 `plan`。`heldAtBothChecks` 为 true；`bytesAtExecutionVerified/allocationGenerationVerified/sourceAuthenticated/instructionDecoded` 四项保持 false，明确不证明 CPU 取指时字节或已解码完整指令。参数、读链或匹配失败返回退出码 3，不发布部分字节；核心具体失败 stage 原样保留。

核心头文件和实现已登记到 CLI `.vcxproj` 与 `.filters`，没有登记到 Qt/Light。本入口只完成源码接口核对，未构建、未运行、未测试，未修改旧验收脚本或续接旧验收任务。

## 验证状态与暂停边界

2026-11-26：源码、命令帮助、CLI 使用文档及 CLI 工程登记已接入。本入口的构建和真实 CLI 实测尚未完成，不能用源码核对代替运行结论。核心最小原生 helper 验收由主协调独立负责，不在本端重复。

用户最新明确指令为：“从现在开始暂时不允许派发CodeBuddy任务，我会在可用时告诉你”。因此不新派发、不续接、不失败重试、不自行替代运行，也不新增验收子代理。已有执行归档/关联验收任务保留，完成结果只登记。恢复授权后，原作者验收会话只补下列新增命令范围，复用有效目标及既有执行归档/关联回执：

1. 当前真实执行停点读取已知字节，核对 `readContext.before/after`、`heldAtBothChecks`、SHA-256、字节数和归档坐标。
2. 错 stopId/stateRevision 拒绝，且没有读取或新增内存段。
3. 同一停点重复显式读取形成独立内存段，查询仍保持同一个 Held 停点。
4. 正常清退不受内存归档影响；必要时用旧 memory read/export 回查本次真实归档。

所有必要 CLI 增量构建与整批运行仍须在同一线程持有 `Local\KSword.ActionAnalyze.CliValidation`，使用 HostX64、BelowNormal、工程固定 IntDir 和统一 Release，不重复整套 step/Hook/格式矩阵，不运行 GUI 或驱动。
