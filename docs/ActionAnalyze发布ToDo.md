# ActionAnalyze 发布 ToDo

用户原话：「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。答复进度后续做当前任务，压缩和交接保留原话、未完项目与下一可执行步骤。正式状态以 [11 项产品验收清单](ActionAnalyze产品验收清单.md) 为索引。

交付入口为「监控 → 行为分析」。选定明确的进程实例后，单击开始即启动所选监控来源和预设分析。用户可查看实际覆盖，停止后在同一工作台查看本次结果，再从项目重开。CLI 与 Win32 使用各自的运行所有者，能处理同一份证据。以下按依赖顺序验收，每一阶段保留成功、部分、失败及清退记录。

- [ ] **01 一键运行与预设分析。** Qt 在总览选目标和方案，冻结目标身份及本次配置，单击启动。接入真实 R3 进程活动，显示 CPU 和 I/O 区间。ETW 辅助源独立显示可用性、丢失与清退，失败不覆盖前次有效结果。用正式 Qt 和自有样本核验采样、预设、停止、失败重试和选中记录。
  - [x] 正式 Qt 内存预览验收。`监控 → 行为分析 → 总览` 单击运行，选中同一进程实例的两条记录。详情回读区间 1,016 毫秒、CPU 234.375 毫秒、读写各 3,932,160 字节。手动停止后仍可查看，输入无效 PID 保留原表，改回正确 PID 可重新运行。Kernel-File `EnableTrace=5` 时活动分析继续，并单独报告来源受限及清退结果。构建退出 0，语言包审计通过。运行记录 `.codex-build-logs/action-analyze-qt-live-preview-final.log`，两个进程均退出 0，配置已逐字节恢复，样本已移除。项目内预设和配置冻结随 02、05 项验收。
- [ ] **02 项目及生命周期。** 使用同一项目存储多次采样、冻结规则及断点配置。完成 `session.open/query/stop/close` 与人工 REPL、JSONL，保证请求去重、独立收尾和退出处置。覆盖坏输入、慢输出、取消、目标退出、EOF 和失联。每条活方法有机器 schema、帮助、向量和正式 CLI 回执。
  - [x] CLI 被动 ETW 子项已验收。正式 CLI 在同一项目验证四个会话方法、重复请求、创建时间和状态修订校验、时限、EOF、REPL、目标正常退出和慢输出。目标退出触发 `target-exited`。stdout 背压触发 `output-lost` 并退出 `3`。两者均确认原生会话清退并回读原始段。规则与断点配置冻结仍待验。[CLI 回执](../tools/action_analyze_validation/cli/README.md#passive-etw-session-receipt)
  - [x] 正式 R3 CLI 的方法目录和 JSONL 包络通过 71 帧运行回执与四个会话方法的 10 项请求向量。已覆盖握手、响应、协议错误和终态摘要。[方法目录](../schemas/action_analyze/live-etw-method-catalog.json) · [输出包络](../schemas/action_analyze/live-etw-message.schema.json)
  - [x] 真实 REPL 采样在自有目标产生 12 条观察后停止，按原序核对 8,881 字节归档中的实际载荷。快速 REPL 停止与 EOF 均核对已刷盘的两条记录、原生清退和覆盖状态。[CLI 回执](../tools/action_analyze_validation/cli/README.md#passive-etw-session-receipt)
  - [x] 满回执账本预留一次清退重试。替身验证首次 STOP／Close 失败、旧 ID 重放、新 ID 重试和关档，以及持续失败时 EOF／shutdown 的未清退回执。正式进程在持续原生失败时能否退出仍待验。[原生回执](../tools/native_etw_controller_validation/README.md#判据)
- [ ] **03 来源与证据。** 分别接通 ETW、API、异常、网络、WMI 及脚本，并登记每个来源的可用字段、覆盖范围、时间域与缺口。以真实操作核对阶段、返回值和记录上下文。双栈 TCP／UDP 样本须区分真实捕获的字节、仅元数据、截断和丢失，并核对出站 IP 与进程实例。
- [ ] **04 持久化与重开。** 写完来源依赖、原始记录和 blob 后写规范事件，最后发布覆盖依赖的 checkpoint。Stored 必可读，zstd 有明确能力标记。覆盖坏尾、满盘、断电、锁冲突、索引重建、搬运及三端复读。采样失败与部分结果有明确状态。
  - [x] CLI 已在停止时写入、刷盘并回读 Stored 原始段。重开项目后读回相同字节边界，QtCore 和 Light 生产读取器从同一个段逐条核对 12 条自有 ETW 记录及实际 UserData。跨流 checkpoint、完整项目互读及桌面交互分别验收。[CLI 回执](../tools/action_analyze_validation/cli/README.md#passive-etw-session-receipt)
  - [x] CLI 以 JSONL 和 REPL 在只读项目中回读匹配的采集计划摘要、12 条观察及结束回执。活采样缺段和归档截尾分别报告，冻结配置仍可读取。[CLI 回执](../tools/action_analyze_validation/cli/README.md#passive-etw-session-receipt)
  - [x] 被动 ETW 停止后提交 `raw/1` 与终态覆盖 `records/1` 的两流检查点。正式 CLI 重开复核两段 SHA-256、端点和原始引用。已验未发布、前缀后坏尾、依赖缺失、截短与错采样。规范事件、多代恢复和桌面互读继续验收。[CLI 回执](../tools/action_analyze_validation/cli/README.md#passive-etw-session-receipt)
  - [x] 正式 Qt 从项目回放相同的被动 ETW 双流检查点，验证未提交尾部、覆盖段缺失、错采样、旧档回退和原位重试。[Qt 回执](../tools/action_analyze_validation/qt/ETW-Readback.md#qt-项目检查点)
  - [x] 同一正式 CLI 样本经 CLI、Qt 正式窗口、Light 生产读取器和 Light 正式窗口核对双流提交、14 行及 12 条事件载荷。[三端回读](ActionAnalyze总览交互与验收.md#light-普通权限打开归档)
- [ ] **05 规则与预设交付。** 固化预设版本，登记启用的来源、阶段、字段、范围、预算和缺失语义。完成上游规则许可、类型转换、字段矩阵和等价回放。用真实受控样本核验在线和离线判定、证据引用、覆盖不足时的未知结果。
- [ ] **06 R3 控制和全局下断。** 同一个外部 owner 持有真实调试事件和停止账本，接通 `control.pause/query/continue/recover`。用自有 x64／WOW64 目标核查手动暂停、同步规则或断点命中、原调用保留、停止组冻结、附带冻结、新线程和错误后恢复。调试退出与目标处置使用明确策略，故障及 owner 死亡分别取证。
  - [x] 正式 CLI 的 `analyze breakpoint session` 对自有 AMD64 子进程实测命中、精确继续、再次命中及正常清退。JSONL 的旧修订和已用继续 ID 均不会放行后续停点，REPL 走同一所有者。仍未接三端项目会话、WOW64、普通 R0 或异常退出恢复。
- [ ] **07 脏内存及执行证据。** 把成功写入、映射代次、内容变化、执行进入、执行确认和后续影响关联到强对象身份。验证自有数据页和受控执行样本的有效范围、同址重建、别名、并发变化、重设防及漏采负控。区间快照差异作为独立证据保留。已发布 `c1bd8f56b` 的 R3 只读快照切片和真实样本报告。
  - [x] `analyze memory track` 在正式 CLI 的两页自有样本中核对 3 字节变化、绝对地址、SHA-256、内容版本和不可读负控。不可读页不会抹去前次有效记录，第二页继续采样，旧 `memory watch` 的结果仍兼容。此入口为被动采样，不确认写入者或执行，不写项目。
- [ ] **08 普通 R0 独立验收。** 在指定 VMware 来宾满足原生准入后核查驱动身份、逐项回读、停止和清退责任。当前来宾 build `26100.9711`，Windows OS 门槛为 `26300`，29 项专项均未执行。引用驱动源码和[只读准入回执](../tools/action_analyze_validation/ordinary-r0-readiness-audit.md)，保留 R3 和 R0 各自的支持范围。
- [ ] **09 调试、调查与网络处置。** 按 T01–T11／T14 逐项接通实际所有者与回读。完成独立一键调查、进程和线程菜单及 Dump 导出，持久化内容与证据索引。对所选进程做双栈连接处置并验证非目标连接仍存续。T12 回滚外部操作和 T13 热重载依已确认范围延期。
- [ ] **10 三端工作台。** Qt 和 Win32 真实验证同一实时／归档总览、事件表、左侧纵向瀑布、独立 API／ETW 筛选、右侧动作、底部证据图和固定状态。规则和断点独立页需有项目存取及真实应用回执。覆盖键盘、拖选、恢复实时、窄窗、DPI、主题、首帧、旧结果及稳定选择。CLI 人工和机器会话验证同一次真实采样、报告导出和重开。
  - [x] 正式 Qt 工作台从「监控 → 行为分析 → 总览」打开 CLI 写出的原始段。ETW 筛选使 14 行变为 12 行。清除筛选后恢复 14 行并保留选中详情。首条记录的来源代次、报头 PID 及 8 字节预览与同一段一致。日志 `.codex-build-logs/action-analyze-qt-etw-replay.log`。本次使用 Qt 文件选择器、浅色主题及右侧详情。Light 正式构建及读取器回读通过，实际工作台、DPI 和主题验证待验。
  - [x] 正式 Qt 窗口从「项目与采样」选中已登记采样并打开首个原始段。总览核对项目和采样 ID，保留筛选前的详情。读取器回归确认身份不符时不发布记录。[Qt 回执](../tools/action_analyze_validation/qt/ETW-Readback.md#qt-项目目录回放)
  - [x] 正式 Qt 的原位重读遇到另一采样的原始段时保留原表和详情。恢复文件后，同一按钮重读成功，保持选中详情。[Qt 回执](../tools/action_analyze_validation/qt/ETW-Readback.md#qt-项目目录回放)
  - [x] 复验 Qt 目录路径绑定、回放和同产物实时预览。QtCore 拒绝从另一目录查询同 UUID 的原始段。正式窗口完成直达、筛选、详情保留、错采样重试、进程活动采样、停止及无效 PID 保留结果。[复验回执](../tools/action_analyze_validation/qt/ETW-Readback.md#目录身份绑定复验)
  - [x] 正式 Light 普通权限窗口完成采样选择与取消、ETW 筛选、瀑布键盘选择、坏尾隔离、Coverage 缺失保留详情、旧档回退、原位重读和独立段打开。800×650 控件几何已核对，视觉和跨屏 DPI 待验。[Light 窗口回执](ActionAnalyze总览交互与验收.md#light-普通权限打开归档)
- [ ] **11 可靠性及性能。** 按文档矩阵记录首条事件和暂停延迟、窗口内丢失、磁盘及内存上界、目标扰动和多轮恢复。执行长时间采样、背压、目标快退、新线程、异常退出、故障恢复、休眠和满盘用例。报告测试机器、数据规模与版本。
- [ ] **12 发行。** 对照概念图和 A0–A10 全部 33 项工单，列出实证、已确认延期和支持限制。通过 HostX64 的主程序、Light、CLI 和配套项目构建、语言包和主题审计。用真实自有样本留存可复核报告、产物哈希、清退结果和导航步骤。按验证闭合的切片提交并推送 `ActionAnalyze`，在统一 Release 目录核对组件版本并制作、测试 7z。

验收依据见[成品验收对照](ActionAnalyze成品验收对照.md)、[施工任务与契约落点](ActionAnalyze施工任务与契约落点.md)、[总览交互与验收](ActionAnalyze总览交互与验收.md)和[工具栏逐项功能核对](ActionAnalyze工具栏逐项功能核对.md)。
