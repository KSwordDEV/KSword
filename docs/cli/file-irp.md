# 文件系统 IRP 构造

`file irp submit` 使用现有 R0 `IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT`，在从文件路径解析出的设备栈上完成一次打开、目标 IRP 及收尾；不接受任意设备对象指针，也不自动切换 R3。

```powershell
KswordCLI.exe file irp submit --path 'C:\test\sample.bin' --major 3 --layer 0 --access 0x120089 --share 7 --disposition 1 --offset 0 --output-bytes 64 --confirm --json
```

参数：`--major` 为 0..27 的 IRP_MJ 值，`--minor` 为 IRP_MN；`--layer` 的 0/1/2/3 分别表示 related、base filesystem、VPB filesystem、device。`--access`、`--share`、`--disposition`、`--create-options`、`--attributes` 描述打开阶段；`--information-class`、`--control-code`、`--security-information`、`--offset`、`--lock-key`、`--lock-length`、`--pattern` 按目标 major 的协议语义使用。未填数值为 0；内核按具体 major 验证合法组合，不将 0 视作通用的安全默认值。

`--flags` 是协议位掩码，其中 0x2 表示请求跳过清理但内核仍会收尾，0x4/0x8 分别表示打开重解析点/目录意图，0x10/0x20 为目录扫描标志，0x40 只执行 CREATE。确认位及危险位不能直接放进 `--flags`：命令一律要求 `--confirm`，PnP/电源等危险 major 还要求 `--allow-dangerous 1`。所有值、位和允许的 major/minor 组合以 [共享协议](../../shared/driver/KswordArkFileIrpIoctl.h) 和驱动校验为准。

输入用 `--input-hex` 或 `--input-file`，互斥且最多 64 KiB；输出缓冲 `--output-bytes` 最多 256 KiB，超时 `--timeout-ms` 最多 60000（0 为驱动默认）。结果包含传输状态、协议状态、阶段标志、各阶段原始 NTSTATUS、目标设备及驱动、实际 `information`、完整返回字节的 `outputHex`、短读/短写和截断状态。未到达阶段的状态为 null；CREATE-only 不伪称执行了操作阶段。

结果 0 要求实际打开、目标操作和关闭成功；写入短写、输出截断或收尾无法确认返回 6，IRP/打开失败和超时返回 3，设备未打开返回 2，不支持返回 5，协议格式错误返回 4。`shortRead=true` 表示读取少于请求字节，可能是文件结束；仍返回 6 提示请求范围未全部读出。驱动阶段标志中的 output-truncated 位在写入 `IoStatus.Information` 表示写入字节数时可能置位，CLI 保留原始位，但仅在实际请求了输出缓冲时将其解释为输出截断。

超时、失败或收尾异常可能已产生部分效果，不能自动重试。底层路径可能发送影响文件或设备的请求；调用方应使用明确目标，并在后续独立查询中核对效果。
