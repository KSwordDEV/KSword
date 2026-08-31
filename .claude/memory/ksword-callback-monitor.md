---
name: ksword-callback-monitor
description: KSword 内核回调监控的共享协议、R0 ring、Minifilter 双消费者、R3 游标与高频 UI 提交边界
metadata:
  type: project
---

# 内核回调监控通道

- 共享 ABI 唯一落点是 `shared/driver/KswordArkCallbackMonitorIoctl.h`。Callback Monitor v1 使用独立 Control/Query/Read IOCTL，不复用或修改回调规则、AskUser 和旧文件监控队列语义。
- R0 在 callback runtime 内预分配 2048 条固定记录。发布者只读取类别原子掩码、try-lock 单写者并复制到固定槽；争用时计入 dropped，不等待、不分配。Start/Stop 控制线程只做有上限的短自旋等待，超限返回 `STATUS_DEVICE_BUSY`，避免单核或优先级反转时无限占用 CPU。
- Read 使用 `afterSequence`，返回 first/latest/next、lostBeforeFirst、dropped 和 more/snapshot-race。槽位复制前后都要核对 commit sequence；遇到覆盖竞态必须停止本批且不推进该序号，下一轮才能重试或按新 earliest 精确补账。
- 文件监控的 `FltStartFiltering` 是一次性引擎状态，旧 File Monitor 的 STARTED 位只是旧队列采集状态。pre/post 回调分别判断旧队列和 callback monitor 两个消费者；任何一方需要 post 结果都返回 `FLT_PREOP_SUCCESS_WITH_CALLBACK`，停止其中一方不能关闭另一方或规则回调。
- callback monitor 单独采集文件事件时只复制现有 `FileObject->FileName`，不调用会分配名称信息的规范化查询；旧文件监控启用时仍保留其原有规范化路径行为。
- R3 只通过 `ArkDriverClient` 控制和读取，并严格校验 ABI 尺寸、版本、返回字节数、entrySize、游标范围、首条期望序号和后续事件连续性。旧驱动的未知 IOCTL 映射成明确的 unsupported 状态。
- 对象回调遥测必须在进程保护和通用 `STRIP_ACCESS` 规则全部执行后发布；`OriginalAccess` 保存系统最初请求，`DesiredAccess` 保存对象管理器最终采用的权限。
- MonitorDock 页面按 Tab 懒加载，打开不自动采集。高频事件使用追加式 `QAbstractTableModel` + `QSortFilterProxyModel`，后台线程持独立游标；暂停只冻结 100 ms UI 批量提交，后台继续读入有界队列。过滤表达式只在条件变化时重新编译和失效，定时批量提交不得对未变化过滤器做全表重算。读取失败时后台线程应尝试 STOP R0、清除本地 running 状态，并保留可重试的驱动清理状态。右键菜单打开期间不得更新模型。
- 驱动本地 variant-sign 工具可能在编译、链接、Universal ApiValidator 均完成后无输出卡住。复核精确进程树且确认无编译器/链接器/验证器后，只结束该构建的 signer；代码复验可用 `KswordArkSkipAutoVariantSign=true`，签名和实际加载状态必须另行报告。
