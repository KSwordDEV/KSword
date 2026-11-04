# Shadow SSDT 基线检查和恢复

`kernel shadow-ssdt-baseline --index N --json` 获取单个槽位的只读快照，输出表基址、槽位地址、当前字节、归一化磁盘基线、模块路径、磁盘 SHA-256 和缓存签名级别。它同时执行无 FORCE 的 R0 预检；此预检只报告需要 FORCE，不验证旧字节或写入内存。

只有在明确确认预览后，才使用其中返回的字段执行恢复：

```text
KswordCLI.exe kernel shadow-ssdt-restore --index N --expected-table TABLE_BASE --expected-current CURRENT_BYTES --expected-baseline BASELINE_BYTES --expected-sha256 DISK_SHA256 --confirm --confirmation "RESTORE SHADOW SSDT" --json
```

当前字节和基线字节是预览返回的四字节十六进制字符串。命令重采集槽位和映像身份，并将快照与显式参数比较；无 FORCE 预检必须返回 `FORCE_REQUIRED`，在提交前再次采集并比较所有身份和字节。驱动在强制操作中比较当前槽值与预期值，操作后命令读回槽值。`writeAttempted`、`patchStatus`、`bytesPatched` 和 `verified` 分别报告尝试、驱动结果和读回结果；失败或读回不完整时不要假设槽位未改变。

基线要求目标属于唯一的已加载模块，磁盘和已加载 PE 的 machine、timestamp、SizeOfImage、checksum 与模块大小一致，驱动确认匹配的模块路径/基址与文件的 Code Integrity **缓存签名级别**，且目标字节完全位于 `PeImageMap` 的可比较范围。缓存签名证据不表示完成了 embedded/catalog WinTrust 完整链验证；输出明确标记 `diskWinTrustVerified=false`。模块或签名证据不可用、槽值已相同、响应不完整或不受支持时拒绝恢复。恢复系统调用表可能导致图形会话或系统崩溃。
