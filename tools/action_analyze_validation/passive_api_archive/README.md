# ActionAnalyze 被动 WinAPI 归档读取

`PassiveApiArchiveTail` 增量读取授权采集器已经写入 `events.jsonl` 的记录。它复用现有的 1000 字节 WinAPI 包、无损 JSON 解析器和五类线索目录。每次 `Poll()` 最多读取 64 KiB、返回 50 条完整记录，最多跨批保留 8192 字节的半行。读取器自身没有后台线程或队列。

## 调用契约

1. 采样所有者显式选择自有或已授权的本地归档。向 `Open()` 提供已打开的文件句柄，以及从该次授权会话独立取得的 `sessionIdentity`、调用方 PID 和创建时间。源文件须只追加。当前范围为每个文件一个会话、一个进程实例。缺失创建时间、混入其他会话或进程时，读取在首个不匹配的行停止。
2. 所有者在同一个串行后台工作队列调用 `Poll()`，读取 `Status()`。返回行保留连续的归档序号、原包和可空的 `clue`。控制包、覆盖包和普通未命中 API 也可能出现在同一批。调用方可只将 `clue != nullptr` 的记录送入线索面板或现有封装。`Reading` 表示已有积压，`AtTail` 和 `PartialLine` 表示等待追加。单轮失败前的有效记录仍随该轮返回。故障行号可由 `validatedRows + 1` 得到。
3. 归档所有者确认停止追加后提交 `SetWriterReceipt()`。对 `WinAPIDiskArchive`，`finish()` 成功且关闭后使用 `{Flushed, written()}`。写入失败且已关闭时使用 `Failed`，已关闭但缺少成功计数时使用 `UnknownCount`。下一轮读端以同一文件的共享状态验证写入句柄已关闭，再排空剩余记录。成功回执、精确行数和换行结尾全部吻合时才进入 `Sealed`。结束或取消后由所有者销毁读取器并释放句柄。

`reportedAgentDrops` 是同一来源已报告的累计下界，缺失时未知。它与归档连续序号分别计量。归档可滞后于采集，既有写入器按大小或持续写入时的时间条件刷新缓冲。归档前的暂停、前置筛选、未送达的丢失通知与采集覆盖仍取决于原来源。身份比对用于核对已授权来源的归档声明，依赖调用方对文件归属及写入者的信任。目标实例、实际写入、后续执行与因果归属须由独立证据支持。

## 所有者接入位置

- CLI 在 `KswordCLI/ActionAnalyze/Cli` 的采样所有者持有实例，复用现有单写者归档路径。项目与筛选显示应沿用冻结的采样 ID。
- Qt 和 Light 各自的 ActionAnalyze 采样所有者调用同一数据适配器。Qt 将轮询放在后台，一次只允许一个在途批次，按现有会话管理规则登记。Light 沿用其原生工作队列。共享模块无需 UI 或项目服务。
- 接入端在各自 `.vcxproj` 与 `.vcxproj.filters` 的现有 `ApiMonitorClue.h` 附近登记 `shared/evidence/PassiveApiArchiveTail.h`，并在 `EvidenceJson.cpp` 附近登记对应 `.cpp`。三个工程已各自编入所需的 `EvidenceJson.cpp` 和 `LosslessValue.cpp`。适配器通过现有 Windows `Crypt32.lib` 解码 Base64。

## 独立回归

使用 HostX64 和 BelowNormal 构建此目录下的 `PassiveApiArchiveValidation.vcxproj`，配置为 `Release|x64`。给生成的 `Ksword5.1/x64/Release/PassiveApiArchiveValidation.exe` 传入固定中间目录下尚不存在的 `x64/Release/archive-fixture.jsonl` 的完整路径。夹具使用本进程实例身份，按生产写入器的 Windows 共享模式追加合成包，运行后清理它创建的档案。

2026-11-25 夹具以 `/W4 /WX` 成功编译并通过 317 项断言。覆盖空尾及半行、150 行跨块续读、原包逐字节核对、原包分类、会话/PID/创建时间错配、序号缺口、错误 Base64、重复 JSON 键、超长行、累计丢失、源截短、关闭状态和提前回执。正式三端活采样和覆盖率等待产品接入后独立验收。
