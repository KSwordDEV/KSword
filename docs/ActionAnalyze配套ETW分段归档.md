# ActionAnalyze 配套 Agent ETW 分段归档

实时 API 采集的配套 ETW 复用 `PassiveEtwSource`、项目原写租约与 `raw-etw/records-etw/checkpoints-etw`。来源队列有界，采集期间由原 API worker 排空，不能把全部生命周期事件留到结束时才写入。

`ProjectEtwStream` 只保存本次来源的已提交段号、观察累计数及写入结果，不拥有线程或来源。普通轮询一次至多取出 512 条，在原 `RawEvidenceArchive` 写入段首计划、原观察及段尾，再调用既有 `PublishEtwCheckpoint` 发布；只有检查点成功才推进游标。写入或发布失败后停止追加，已有段及首个错误保留，不尝试跳段。

计划的 `segmented=true` 明确采用分段计数；`durationMs` 仍保留用户要求的采集时长，有限时长也允许分段。旧持续计划 `durationMs=0` 沿用原分段语义，旧有限计划缺少该标志仍按原单段累计计数读取。各段的 `headerPidFilters` 保存当时实际目录，根 PID 和创建时间仍只是根请求身份。

普通段使用 `stopReason="segment-rotated"`、`finalSegment=false` 和本段 `segmentObservations`。停止唯一来源后继续按原序排空尾包，只有最后一段声明 `finalSegment=true`，其来源队列必须为零。所有段保持同一来源代次与采样，各流序号独立连续。API 终段在 ETW 最后一次封段之后发布，配套结果保留实际段号、累计已归档观察、是否已封终段及独立失败状态。

源队列丢失、原生丢失、部分载荷、写入失败和未封终段分别使 ETW 结果不完整。原生接管和 API 已发布前缀继续保留，ETW 失败不撤销调用前接管。

三端实时 API 入口共用的 `CaptureCooperativeApi` 已接入该游标，原轮询触发阈值256条或约一秒，来源停止后才封终段。CLI 结果与原桌面共享 ETW 文档保留相同游标字段。CLI 本机实测、历史回读和尾段计数由 CodeBuddy 执行并独立落盘；Qt／Win32 GUI 验收继续后置。源码接线不构成运行通过。

CLI 原长程 ETW 的持续采集也调用该游标，普通段仍按原阈值封段，停止后完整排空；已有有限时长独立 ETW 保留旧单段格式，读取仍兼容。两入口不维护两套分段写入实现。
