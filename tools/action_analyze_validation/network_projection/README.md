# 行为分析网络投影夹具

`NetworkEvidenceValidation.vcxproj` 使用合成输入测试 TCP／UDP IPv4／IPv6 清单收发、来源时钟、采样边界、PID 复用、已知零与未知丢失，以及原始 IP 报文字节的精确移交。夹具只构造内存中的 `PacketRecord`，无需启动 ETW、抓包、驱动或 socket。

## 采集与归档交接

- 网络输入来自已存在的采样 ETW 所有者。`Microsoft-Windows-Kernel-Network` 关键字 `0x10 | 0x20`，使用 Windows 安装的清单 v0。投影依据载荷 PID 和采样范围接纳。缺少源 PID、范围外 PID 或来源代次错误只产生状态，不移交地址。范围内缺强实例的结果保留为未解析。当前网络归档的流记录要求强实例，此类未解析结果可由所有者记为诊断计数。
- `EtwSessionController` 的原始回调排在事件头 PID 过滤之后。行为分析所有者接线时应确保来源可交付记录，再用本投影的载荷 PID 范围门禁。`ProcessNetworkEtwMonitor` 的旧入口提供累计流量和会话健康。其 PID 聚合和 `start/stop` 例程无需在此另行运行。
- `sourceId`、`clockId`、`bootId` 用 1–64 字节的 `[A-Za-z0-9._:/-]` 标签。`sourceEpoch`、项目和采样使用非空规范 UUID。QPC=1 要求非零频率，FILETIME=2 的频率为空。地址族=4／6、TCP=6／UDP=17、入站=1／出站=2 均与归档枚举一致。`sourceField/destinationField` 保留原生端点字段。只有强实例绑定的发送事件使用 `destinationField` 确认出站目的端点。端口是主机序；该清单支持的收发记录直接提供端口，包括已知零。
- `observedEtwBytes` 对应 `observedBytes`。ETW 流记录使用 `captureLayer=flow-metadata`、`payloadState=metadata-only`、`encoding=null`、`originalLength=null`、`capturedLength=0`、`producerCapturedLength=0`。若采集所有者另行保留 ETW `UserData`，应以明确类型的通用 RawRecord 保存。
- `ProjectExistingRawSocketPacket` 从采集所有者接收 `PacketCollectorRecordView`。当前支持 `RawSocketIp=1`。`sourceId/sourceEpoch/observationOrdinal` 定位报文自身来源。采集者需要提供对应来源、实际包序号、毫秒时间和强进程实例的独立证明。`PacketRecord.sourceText`、界面序号和端口表 PID 属于原界面数据。方向未知或本地双端点时，需要独立方向证据。关联 ETW 流也需要另有证据。ALE 和空字节返回仅元数据状态。当前尚无 ActionAnalyze 实时抓包订阅接线。
- IPv4／IPv6 报文均映射为 `captureLayer=ip-packet`、`encoding=bytes`。原始字节留在 JSON 之外。`originalLength` 来自可验证的 IP 头，`wireLength` 在旧 R3 入口保持为空，`capturedLength` 是实际移交的字节数。旧 R3 入口最多保留 4096 B。归档前裁剪场景需另外保留 `producerCapturedLength`。当前 RawRecord 的 JSON 上限 1536 B，字节内联上限 65,536 B。同采样 `value.bytes` blob slice 留给归档所有者。源截断布尔字段仅标志截断证据，原长为空的捕获状态仍为 `captured`。
- 证据回读关联由归档所有者绑定 `projectId/sampleId/eventOrdinal/rawSegmentOrdinal/rawRecordSequence/checkpointGeneration`。检查点发布前代次保持为空。源事件／实时缓冲丢失、队列丢弃和归档失败分别计数。共享 ETW 会话的丢失计数是该会话的观测，不能派给单进程。

## 独立验收

HostX64 Release，`IntDir=tools/action_analyze_validation/network_projection/x64/Release/`，`OutDir=Ksword5.1/x64/Release/`。运行该目录下的 `NetworkEvidenceValidation.exe`。正式工作台、实时采集接线、持久归档和重开由各自所有者验收。

本次 BelowNormal 构建成功，独立夹具通过 112 项检查。IPv4 UDP、IPv6 TCP 和截断 UDP 前缀均与固定字节逐一比较。夹具没有创建测试配置。
