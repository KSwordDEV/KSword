# 硬件 R3 命令

## 设备枚举与详情（迁移项 31）

```powershell
KswordCLI.exe help hardware
KswordCLI.exe hardware devices help
KswordCLI.exe hardware devices enum --help
KswordCLI.exe hardware devices enum --scope present --json
KswordCLI.exe hardware devices enum --class Net --json
KswordCLI.exe hardware devices query --instance-id 'PCI\VEN_15AD&DEV_0405&SUBSYS_040515AD&REV_00\3&61AAA01&0&78' --json
```

`hardware devices enum` 支持 `--scope all|present`（默认 all：包括非当前连接的已安装设备）、`--class`（不区分大小写的精确类名或 GUID）、`--limit 1..100000`（默认 1000）。`hardware devices query` 必须提供 `--instance-id`。均默认 R3，支持 `--backend r3` 和 `--json`，不要求 KswordARK，不切换 R0，不提供后端未实现的设备启用、禁用或卸载操作。

枚举 data 包含 source（SetupAPI + Configuration Manager）、scope、complete（devnode 枚举是否到达正常末尾）、limited、win32Error、enumeratedCount、matchedCount、returnedCount、truncated 和 devices。query 包含 requestedInstanceId、found、win32Error、device。设备包含 instanceId、parentInstanceId、devInst（十六进制定位值）、displayName、className、classGuid、state、statusFlags、problemCode、properties。displayName 使用友好名称，缺失时使用设备描述。设备编号和状态是瞬时查询，不是后续处置的持久身份保证。

properties 按稳定字段名提供 available、absent、malformed、registryType、win32Error、configRet、values 和 number。字段包括身份／父身份／状态、类、制造商、服务、驱动键、位置／位置路径、硬件／兼容 ID、设备及类 UpperFilters/LowerFilters。REG_SZ／EXPAND_SZ 的 values 为单元素数组；REG_MULTI_SZ 为原始多字符串数组，条目中的分号保持原样；数值使用十进制字符串 number。不可获得的值为 null，不使用 UI 文本推断状态。configRet 是 Configuration Manager 返回码，与 Win32 错误分别保留。

可选注册表属性或过滤器不存在标记 absent，可以成功；访问拒绝、设备已退出、CM 状态不可查询等证据缺失返回 6；畸形长度／终止符／类型返回 4。开始枚举失败、query 无法打开指定实例返回 3；枚举中途失败保留已采集设备并返回 6。有效空列表／类筛选无匹配可以返回 0，输出截断返回 6。devnode 上限 100000，单属性上限 16 MiB，属性扩容最多 4 次。help 不打开设备或执行查询。

## 系统性能采样（迁移项 32）

```powershell
KswordCLI.exe hardware performance help
KswordCLI.exe help hardware performance sample
KswordCLI.exe hardware performance sample --group cpu --json
KswordCLI.exe hardware performance sample --group memory --samples 3 --interval-ms 1000 --json
```

`hardware performance sample` 支持 `--group all|cpu|memory|disk|system|network|gpu`（默认 all）、`--samples 1..30`（默认 1）、`--interval-ms 250..10000`（默认 1000）、`--limit 1..100000`（每次样本最多返回的指标数，默认 1000）、`--backend r3`、`--json`。首次计数器采样等待 1000 ms 预热，后续等待从前次采集完成后开始。预热与请求等待之和不得超过 120 秒；PDH 提供者调用本身不强制中断，因此该值不是执行硬超时。group 选择输出，不改变 System 范围后端打开的计数器集合；纯 R3，无 Qt 或 KswordARK 依赖。

data 提供 source、group、requestedSamples、intervalMilliseconds、warmupMilliseconds、returnedSamples、cancelled、queryClosed、closeEvidence（同一拥有线程的 PdhCloseQuery 原始结果）、samples。每个样本提供 sequence、elapsedMilliseconds、queryOpened、queryStatus、baselineStatus、collectStatus、resolutionDisplay、diagnosticDisplay、matchedCount、returnedCount、truncated、sources、metrics。PDH 状态是其自己的状态码，不当作 Win32 错误翻译。sources 明示 domain（pdh/win32）、路径、调用状态、完整性、空结果和跳过数量。

指标提供稳定 id、group、label、instance、unit、value、valid、display、source、evidence，网络适配器另提供 receivedBytesPerSecond 和 sentBytesPerSecond。无效值为 null，display 仅保留 Light 显示文字，不参与成功判定。计数和整数字节为十进制字符串；吞吐／百分比等为 JSON 数字。静态内存／处理器计数保留精确 64 位整数；PDH 本身提供双精度值，整数字符串不提升原始计数器精度。`memory-available` 单位是原始 mebibytes，其余内存字节项使用 bytes；延续实际查询路径可审计英文／本地化和 Processor 回退来源。

PDH VALID_DATA 和 NEW_DATA 都是有效数据；函数成功不证明 CStatus 有效。数组检查实际长度、项数、名称指针／终止符和有限数值，16 MiB 上限及 4 次扩容重试。计数器缺失／尚未就绪、输出截断或取消为 6；所选组无可用值为 5；畸形数据为 4。PDH 查询失败仍保留已实现的 Win32 静态处理器／内存数据，以部分结果报告。

GPU 是最大活动引擎占用率，不是整卡总占用；没有引擎实例不伪造 0%。网络合计按当前可见接口求和，可能包含虚拟接口、重复流量，不能解释为物理链路利用率；某方向不可读取时保留 null 而非零。Ctrl+C/Break 停止后续采样和等待；已开始的原生调用完成后，由同一工作线程关闭 PDH 查询，并输出一个完整 JSON 文档（返回 6）。help 不创建 PDH 查询或等待采样。
