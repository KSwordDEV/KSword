# R0 模块与映像映射

`r0 kernel-modules [--base VA] [--cursor INDEX] [--max-rows 1..512] [--json]` 在驱动中调用现有 SystemModuleInformation 快照，输出映像基址、系统报告的映像大小、原始 flags 和有界路径。`--base` 为精确基址查询，满足单模块详情需求；`--cursor` 是上次响应的 nextCursor，分页期间系统可能加载或卸载模块，因此各页并非一个原子快照。此来源与 R3 的 SystemModuleInformation 共享系统数据源，不能当作独立的隐藏模块交叉视图。

`r0 process-modules --pid PID [--creation-time FILETIME] [--base VA] [--cursor VA] [--max-rows 1..512] [--json]` 在持有已引用进程对象及其内核句柄时，使用内核 ZwQueryVirtualMemory 分组 MEM_IMAGE 区域，读取映射名称。`--base` 精确查询一个映像；连续分页必须把首个响应的 `creationTime` 和 `nextCursor` 回传，以避免 PID 复用。它是内存映像映射，不是 PEB loader 链或独立 VAD 视图；`spanBytes` 是观察到的映射跨度，不宣称等于 PE SizeOfImage，也不能据此证明未映射映像不存在。各页是独立采样。

响应包含原始 NTSTATUS、flags、每行路径状态和 `spanComplete`。命中行数／扫描预算、路径不可用、目标退出或查询中断时返回部分结果和必要的续扫位置；首个区域查询即失败时返回不可用。指定 `--base` 而完整快照未找到目标返回 3。驱动未提供该 IOCTL 时返回 5，不自动回退 R3。
