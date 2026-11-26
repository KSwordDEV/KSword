# 原生执行观测 v1／v2

`native-execution-v1`／`native-execution-v2` 保存 KSword 活原生调试所有者已经接纳的执行观察。新写入采用 v2，增加同一事件线程的完整冻结寄存器；读侧继续接受字段严格匹配的旧 v1。它不把远程写入、线程创建、APC 入队或 API 调用成功转换成执行事实。

## 实际事件与保存时机

`NativeExecutionFromOwnedStop` 只处理当前仍持有、账本已接纳、未进入继续未决状态的第一机会 `EXCEPTION_SINGLE_STEP`，以及原 owner 核验的登记 NX 页执行访问异常。事件 PID、实际线程身份、创建 FILETIME 和原生事件键来自同一份 `NativeDebugOwner` 快照。历史组、已释放组或另一个事件的步进回执不会生成本格式。

- `execution-enter-attempt`：DR0 执行断点命中精确绑定地址，表示尝试在该地址执行。它不证明该指令完成。
- `instruction-completed`：Into 模式的 TF 步进完成；临时步进资源已恢复，回执的新事件、停止组和实际线程与当前停点一致。`instructionAddress` 为此次步进的起始 RIP，`nextInstructionAddress` 为事件时回读的下一 RIP。

步过调用、跳出完成与数据写入停点不按上述 Into 规则生成单指令完成。指令完成不说明该线程之后继续执行，也不反推整条跨进程注入链的因果归属。执行位置与内存的区域分配代次、内容版本仍是不同证据。

## 项目归档

每次显式保存写入 `samples/<sample UUID>/raw-native/` 下一个新 Stored v1 Raw 段。文件名、段头、项目和采样校验沿用 `ProjectRawEvidence`；独立前序不占用 API `raw`、ETW `raw-etw` 或内存 `raw-memory` 的序号。

每段恰好一条 RawRecord v1，内联原字节为空，元数据包含：

| 字段 | 语义 |
| --- | --- |
| `kind` | 新档为 `native-execution-v2`，兼容旧 `native-execution-v1` |
| `projectId`、`sampleId` | 已登记项目与本轮采样 |
| `sessionId`、`epoch` | 保存时仍持有事件的会话与控制代次 |
| `source` | `native-debug-owner` |
| `historical` | 归档后固定为 `true` |
| `observation` | 上述两种执行观察之一 |
| `target` | `processInstanceId`、PID、创建 FILETIME |
| `thread` | 稳定线程 ID、TID、创建 FILETIME |
| `event` | `backendInstanceId`、严格正值原生事件序号 |
| `groupId`、`stopId`、`stateRevision` | 保存时的精确停止组与修订 |
| `instructionAddress` | 尝试进入或完成的指令起始地址 |
| `nextInstructionAddress` | Into 完成后的实际 RIP；进入尝试时为 `null` |
| `observedQpc`、`qpcFrequency` | 外部所有者观察事件的本机时钟；未采到观察时刻时为 `null` |
| `registers` | 仅 v2：未采到为 `null`；成功为同一实际 `threadId` 及 `values` 固定字段对象 |

地址、FILETIME、QPC、序号和修订为无损十进制字符串。PID／TID 为 JSON 无符号整数。线程创建时间不能早于所属进程创建时间。元数据字段严格匹配版本，不忽略未知字段或根据文字摘要补值。

v2 的 `registers.values` 恰好包含 `eflags`、`r10` 至 `r15`、`r8`、`r9`、`rax`、`rbp`、`rbx`、`rcx`、`rdi`、`rdx`、`rip`、`rsi`、`rsp` 这18项，均为无损无符号十进制字符串。`eflags` 是原32位值的零扩展。`rip` 必须等于进入尝试的 `instructionAddress`，或 Into 完成的 `nextInstructionAddress`。这是事件停止时快照，不能把完成后的寄存器解释为指令执行前值。旧 v1 不含该字段，读侧不填零也不从历史地址重建寄存器。三端继续使用既有规范文档和JSON详情展示，历史值不提供活控制资格。新增v2读写及关联接线尚未构建或运行验收。

调用方持项目写租约并在原生会话的串行控制线程保存。写入器核对活所有者的采样、会话、代次及后端事件，写入新段后刷盘，再通过固定项目目录中的只读句柄核对封装、元数据、端点和完整段 SHA-256。写入、刷盘及核验分别保留回执。

## 历史回查边界

读取器只有在完整段、严格元数据、身份和散列通过后才发布历史文档，失败时不交付部分执行文档。读取器不把文档解码成活 `ReleaseRequest` 或可以继续目标的控制对象。

CRC32C 和 SHA-256 用于核对存储内容与读取一致性，不认证导入文件的历史生产者。跨来源关联必须保留每份证据的来源、时钟与区域版本；只有地址相同、时间接近或具有同一文件散列，不足以确认写入导致了执行。

## 同一停点的内存字节回查

`Detection/NativeExecutionMemory` 将已核验的本格式与 `selected-memory-plan-v1` 关联。调用方先各自验证 `raw-native` 和 `raw-memory` 的独立前序链，再核对项目、采样、进程实例标签、PID 和创建 FILETIME。内存必须带 `readContext.source=held-event` 且 `heldAtBothChecks=true`，读前与读后令牌的目标、groupId、stopId、后端实例、事件序号及修订必须分别等于执行观察的同一停点。旧 live 格式、变化后的停点和仅地址相同的记录不形成此关联。

调用方显式选择 `instructionAddress` 起的 1..15 字节。取值复用 `SelectMemorySnapshotBytes`，所选范围内缺页、读取失败或缺口时整次查询失败，不填零；全快照存在其它缺口不妨碍已完整核验的子范围。成功结果保留执行段、内存段和实际覆盖页的原始序号及两段 SHA-256，执行阶段保持原值，不使用 `nextInstructionAddress` 替换原指令起点。

这份结果表示同一停止事件持有期间读取到的字节。Into 完成后的读取发生在指令执行之后；进入尝试停点的读取也不能排除其它进程写入。因此 `bytesAtExecutionVerified`、`allocationGenerationVerified` 和 `sourceAuthenticated` 始终为 false。不比较两份时钟，不由 1..15 字节选择推断完整指令解码，也不授予历史停点活控制权。正式 CLI 源码入口为 `analyze execution memory`；本轮实现尚未构建或运行验收。
