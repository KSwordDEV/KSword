# R0 事件与流量捕获

以下命令使用 KswordARK 驱动；先确认驱动和 WFP 能力可用。它们不修改网络规则。

```text
KswordCLI.exe r0 traffic-start --confirm [--json]
KswordCLI.exe r0 traffic-stop --confirm [--json]
KswordCLI.exe r0 traffic [--after-sequence N] [--max-rows N] [--json]
KswordCLI.exe r0 wfp-events [--after-sequence N] [--max-rows N] [--json]
KswordCLI.exe r0 hvm-events [--after-sequence N] [--max-rows N] [--json]
KswordCLI.exe r0 piddb [--max-rows N] [--json]
```

`traffic-start` 和 `traffic-stop` 显式改变逐包捕获状态；停止会清空驱动环，因此须在停止之前读取需要保留的数据。回执给出实际 enabled、generation、协议状态和 NTSTATUS。旧驱动或 WFP 不可用不会被表示为成功启停。

`traffic` 返回 IP packet 的序号、时间、方向、协议、PID、地址、端口、总长度和有界报文前缀十六进制；前缀不是保证完整的报文。`wfp-events` 是 ALE 授权事件，仅包含 IPv4 五元组等元数据，不是逐包数据。两者输出 `oldestSequence`、`newestSequence`、`nextSequence`、累计覆盖数 `droppedCount` 和当前游标丢失数 `cursorGapCount`。使用 `nextSequence` 作为下一次 `--after-sequence`；`pageTruncated=true` 表示仍有下一页，正常分页不单独视为采集失败。当前游标发生缺口或重置时返回 6；累计覆盖数不一定发生在当前游标之后，须结合缺口计数判断。捕获关闭时明确返回部分状态，而不将空结果解释为成功采集。

`hvm-events` 返回 HVM 事件序号、处理器、虚拟机退出及地址证据、状态和 watch 标志；`guestLinearAddress` 仅在协议标志有效时显示。结果保留 `availableCount`、`droppedCount`、`newestSequence` 和最后返回行的 `nextSequence`；没有返回行时 `nextSequence` 为 null，调用方保留原游标。此命令只查询已有事件，不启动 HVM 或清空环。

`piddb` 返回名称、时间戳、条目地址和加载状态；动态数据不可用、读取失败或结果截断分别通过状态与非零退出码表示。此查询不删除条目。
