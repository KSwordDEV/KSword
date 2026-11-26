# 显式选中内存采样 v1

本格式对应 `Memory/SelectedMemorySnapshot` 和 `Project/ProjectMemorySnapshot`，属于单轮只读采样。项目存储入口为 `samples/<sample UUID>/raw-memory/<既有 raw 段文件名>`；段头仍使用 Stored v1 `Raw` 类型，项目、采样及段号校验沿用 `ProjectDocument::ReadRawEvidenceSegment`。`raw-memory` 的序号和前序独立于 API `raw` 及混采 `raw-etw`。

每个新段按顺序包含一个计划、零到 64 个已访问页记录及一个结束记录。首段序号从 1 开始，后段必须紧邻上一完整段的最后序号。所有记录均为 RawRecord v1；元数据是严格 JSON，页内原字节放在 `inlineRawData`，计划和结束记录不携带字节。未完成写入的前缀可用于诊断，缺少合法结束记录时不能报告本轮归档完整。

地址、长度、FILETIME、QPC、计数均为无损十进制字符串。PID、状态枚举、Win32 错误和内存保护位为 JSON 整数。不存在的读时钟、区域、散列和返回字节数为 `null`。

## 计划

`kind: selected-memory-plan-v1` 保存以下字段：

- `projectId`、`sampleId`：匹配实际段头及已登记的项目采样。
- `trackingEpoch`：本次显式读取的代次。
- `target`：`machineId`、`bootId`、`processInstanceId`、`pid`、`creationFileTime`。
- `range`：`base` 与 `bytes` 定义非空、无溢出的半开区间。
- `source: read-only-memory-sample`。
- `atomicProcessSnapshot: false`、`allocationGenerationVerified: false`。
- `qpcFrequency`：本机实际采样时钟频率。

集合调查通过 `WriteProcessGroupMemorySnapshot` 保存时，计划另有可选 `readContext`：`source` 为 `live-read` 或 `held-event`，并保留 `stage`、`win32Error`、`before`、`after` 和 `heldAtBothChecks`。旧计划无此字段，表示没有持久化控制上下文，不据此推断读取时是否暂停。

`before`／`after` 为 `null` 或精确停点文档：`pid`（JSON整数）、`creationFileTime`、`groupId`、`stopId`、`backendInstanceId`、`eventSerial`、`stateRevision`。Live 模式不携带停点；Held 模式必须保存匹配请求目标的原读前停点。只有两个停点完整相同且后台确认保持时，`heldAtBothChecks` 才能为真。读后停点变化时仍保留已读字节和两次观察，不能把 `completeRange=true` 解释为整个读取期间都已保持停点。

历史文件中的目标字段为采集时保存的身份。CRC 和 SHA-256 校验文件内容及读取一致性，不能据此认证外来文件的历史生产者，更不能从历史身份重新取得进程控制权。

## 页记录

`kind: selected-memory-page-v1` 保存：

- `pageBase`、`range`：原生页起点及本次真正读取的页内子区间。已访问页按地址组成计划范围的连续前缀，不能重叠、越界或跳过失败页。
- `state`：`sampled`、`not-committed`、`guarded`、`unsafe-read-attributes`、`not-readable`、`query-failed`、`read-failed`、`mapping-unstable` 或 `hash-failed`。
- `mappingBefore`、`mappingAfter`：区域 `region`、`allocationBase`、`state`、`type`、`protection`、`allocationProtection`。未取得时为 `null`。
- `issue`、`additionalIssue`：阶段编号、`win32Error`、可选 `ntStatus`，保留同时发生的读取和读后检查失败。
- `readBeginQpc`、`readEndQpc`、`returnedBytes`、`sha256`。

只有 `sampled` 页可以携带字节；字节数必须等于该页 `range.bytes`，SHA-256 必须对应全部内联原字节。完整页需同时具备相同的前后区域、非空读时窗及成功字节长度。失败页的内联字节必须为空，不能用部分返回值或填零构造完整页。

读取器保留 `PAGE_GUARD`、不可读、未提交和映射变化的真实结果，不为导出修改保护。区域查询无法证明两次观察间没有同地址释放再分配；逐页读取也无法阻止其它进程或内核写入。因此两个完整成功页不构成全进程原子时刻。

## 结束记录

`kind: selected-memory-end-v1` 保存 `completeRange`、`capturedBytes`、`unavailablePages`、`visitedPages`、`allPagesVisited`、观察器终态 `state`、`issue` 及本轮 `beginQpc`／`endQpc`。

只有已访问整个范围、每页均为完整成功、字节总数等于计划长度、采样时钟完整且单轮正常收尾时，`completeRange` 才为真。取消、退出、错误、少访问的页和缺口必须保留部分结果。`completeRange` 描述读取范围；`verified` 是写入器回读全部元数据、原字节、段端点和段散列后的独立回执。

导出连续原字节前需确认所请求范围完整且逐页连续；存在缺口时应输出分段文件及位置清单，或明确拒绝连续导出。不得静默填零、拼掉缺口或将首个成功页当作整个请求成功。

## 活停点读取

`Control/ProcessGroupMemorySnapshot` 允许明确选择 `LiveRead` 或 `HeldEvent`。后者需要原生进程组中同一成员的完整 `ProcessGroupStop`，包括真实 PID／创建时间、groupId、stopId、后端事件键和状态修订；原生组必须为 `HeldComplete`，采样身份须与持有组一致。

调用者在同一串行控制线程读取，前后回查原所有者令牌。若停点已变化，保留实际读到的部分字节及两次回读结果，返回停点变化；不能自动降级到实时模式，也不能由调查代码继续或关闭用户停点。`heldAtBothChecks` 不宣称外部写入者也被冻结。
