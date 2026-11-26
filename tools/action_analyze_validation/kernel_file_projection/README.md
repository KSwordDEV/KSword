# 被动 ETW 来源验证

`PassiveEtwSource` 使用本端独占的实时 ETW 会话。`start()` 返回是否受理启动，`status()` 从原生回执报告消费是否已经开始。`drain(maxRecords)` 取走队首记录，`stop()` 清退本会话并保留已入队记录供继续排空。每条记录保存采集代次。报头 PID/TID 始终是原生记录上下文，来源序号缺失。`headerPid` 可选，作为采样范围内的报头抑制条件。

默认每条最多保留 4096 字节的 `UserData` 前缀，队列默认 512 条。硬上限为每条 16 KiB、4096 条和总负载预算 32 MiB。队列满时保留已入队记录并累计丢失的新增记录。Windows 事件丢失、日志缓冲区丢失、实时缓冲区丢失以及本地队列丢失分别读取。系统计数只有收到本次 STOP 统计时才可用。Level 和 Keyword 由调用方冻结。Windows 可能接受尚未注册的 GUID，生产者可用性以已观察记录和实际失败回执为依据。

已登记 Kernel-File 的 15、16（Read/Write v0/v1）及 24（OperationEnd v0），核对 provider、ID、版本、头部位宽、级别、channel、opcode、task 和负载长度。输出分别保留请求长度、偏移、完成 NTSTATUS 与 v1 的原生发起线程 ID。该 ID 只提供关联线索。文件对象、键及 IRP 同样以关联线索保存。遇到其它事件、布局变化或截断时仍可保存原始观察，类型化字段保持缺失。关联活动项最多检查 32 项，支持明确的 `RelatedActivityId`。其它扩展负载尚未采集。

夹具默认仅运行投影与原生数据结构的内存向量。增加 `--live` 会注册本进程的测试 provider、写入固定的八字节测试事件，并分别尝试未注册 GUID 和系统 Kernel-File。使用仓库统一 Release 以及此夹具的固定中间目录，以 BelowNormal、HostX64 和 `/W4 /WX` 构建。

2026-11-25，Windows 10 build 19045.7846 通过 56 项投影断言、133 项原生来源断言。自有 provider 收到 3 条，受一条队列限制接纳 1 条、丢弃 2 条。接纳记录包含原始八字节的三字节前缀。Windows STOP 统计为零事件及零实时缓冲区丢失。未注册 GUID 的 Enable 成功，收到 0 条。Kernel-File 的 StartTrace 返回 0，EnableTrace 返回 5（`ERROR_ACCESS_DENIED`），消费未打开。Kernel-File 实际负载、跨 Windows 版本及产品归档接线仍需独立运行验证。
