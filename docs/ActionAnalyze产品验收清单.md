# ActionAnalyze 11 项产品验收清单

用户原话：「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。进度答复后继续当前工作。压缩上下文和交接时保留原话、未完项目与下一可执行步骤。验收闭合的批次仅推送 `ActionAnalyze`。

以下是 2026-11-25 正式产品进度估计。验收注明产品入口、采样范围和证据来源。未实现项标「无」，夹具只作为其所测机制的独立回执。

待验的开发批次由独立验收会话运行并直接落盘。见 [验收交接](action-analyze-planning/validation-handoff.md) 和 [验收回执](action-analyze-planning/validation-results.md)。

下一阶段的依赖顺序、并发分工和逐项 70% 门槛见 [70% 路线图](action-analyze-planning/roadmap-70.md)。

| 项目 | 进度 | 现有产品证据与缺口 |
| --- | ---: | --- |
| 1. 选择起点后完成注入 | x64／Win32 合作启动；x64 显式非合作 CLI 附加通过 | 两种架构的自有应用均在声明的业务起点主动等待同架构 Agent 就绪。正式 CLI 确认启动覆盖修订 `1`，首个业务调用入档，分别连续回读 98 和 106 次自有调用。既有 Qt、Light 实测核对同一合作会话停止前后的就绪修订、普通包及正常清退。错误创建代次、Agent 未驻留和缺专用目录未发布配置。新增显式非合作 R3 附加：正式 CLI `analyze api-evidence attach` 对自有 x64、启动时未装载 Agent 的目标按精确 PID＋创建 FILETIME 确认后，由 CLI 从自身同目录装载产品 Agent；`attachmentIdentityVerified`／`agentLoadAttempted`／`agentModuleVerified` 与 `agentReady` 分开，就绪为同一管道 SessionReady＋成功 HooksInstalled＋当前完整且含活动观察 Hook 的覆盖。1000ms 正例 `41` 普通包、`2` 段、回读末坐标 `raw/2 #42`，持续 `--duration-ms 0` CtrlBreak `184` 包、`5` 段且 `cancelled=true`；停钩、干净 EOF、清退与目标存活分别核验，不声称 DLL 卸载。缺 confirm、错误 FILETIME 未装载未发配置，`--backend r0`、`--r0-inject` 与普通 `monitor api capture --duration-ms 0` 拒绝。范围仅自有 x64 无预装载目标；一般第三方目标、全活动与全部 API 覆盖、GUI 附加入口为无。[附加回执](action-analyze-planning/attached-api-capture.md#2026-11-26-本机实测回执显式非合作附加) |
| 2. 样本执行时 WinAPI 回传 | 60% | 正式 CLI 自有 x64／WOW64 活采发布检查点。缺第 5 段检查点（`5e94b9ced`）：独立读者退出 `0`，写端退出 `4`，均保留 4 段、526 包、132 条线索。本批新增持续模式定向实测：正式 CLI `--duration-ms 0` 持续 125 秒后定向停止，123 段、16,188 原包、4,047 线索，`completedInterval=false`／`cancelled=true`，目标仍活且清退与终段 `cancelled`、原包回读正确；持续 0 自然退出 `targetExited=true`、有限时 1000ms `completedInterval=true`，时长负例全部拒绝。Qt／Light 仅同步默认 0 源码与双语提示，活水位及 GUI 实测仍待验。[持续采集回执](action-analyze-planning/continuous-cooperative-capture.md#2026-11-26-正式-cli-长程实测通过)、[原有回执](action-analyze-planning/validation-results.md#2026-11-26--正式-cli-定向回执) |
| 3. 归类、规则比对与行为解释 | 70%（原归类展示口径） | 三端同一合成项目验证访问拒绝释义及缺返回位负例。正式 CLI／Light 在同一真实合作采样对账拒绝 `raw/1 #194`（普通包流水号 `483`）及成功 `raw/1 #193`（普通包流水号 `482`）；Light 切到成功记录后不残留释义，合成活跟随也已通过同项检查。Qt 活跟随构建、双语和主题门禁通过，窗口验收因用户主程序在运行而未启动。真实混合来源和注册表环境判断未验，普通注册表读取不证明沙箱判断。[验收回执](action-analyze-planning/validation-results.md#2026-11-25--light-真实合作档规则回放与-qt-活跟随窗口阻塞) |
| 4. 跨进程转移监控 | 30% | 正式 CLI 已验被动 API 候选及五条原包。三端已有 `raw/1 #2`、源序号 `107` 的合成回调回读；新版 CLI 核实通知时间的原始八字节，以及首、续页及空批的读批状态。回调 PID/TID 是来源提示。**正式 CLI 本机活采候选链已实测**：自有父进程加载正式 Agent、对自有子进程在同采样不同检查点执行写入区间内的自有导出线程，`apiTransfers` 得 1 条候选，写入 `raw/2 #39`／线程创建 `raw/3 #44` 与 replay 原包及 `archive.inspect graph` 三处坐标一致；失败写入与区间外合法入口负例不串链，见 [活采候选链回执](action-analyze-planning/live-api-transfer-validation.md)。原生图/链夹具 78/78 覆盖同源、会话、代次、QPC 次序、实际写入半开区间、跨段、坏锚点及 1024 写入窗口淘汰；候选不产生执行或原生角色。正式 CLI 合成两段跟随采样见写入 `raw/1 #2`、创建 `raw/2 #4` 候选 1 条，缺首检查点/首段损坏失败关闭，见 [消费侧回执](action-analyze-planning/api-transfer-consumer-validation.md)。Qt／Light 归档行详情与活采 progress 摘要已接入版本化字段投影源码（Qt `ParameterWorkspace`+`StructuredFieldView`，Light 原生详情文本，无新布局），工程登记、接线与 i18n audit（退出 0，32032 词条）已核对，桌面运行/各状态 GUI 未验；Light 旧摘要矛盾已源码修复、实机仍后置，见 [源码回执](action-analyze-planning/api-transfer-desktop-source.md)。滚动窗口 >32 与发布失败/通知异常边界、真实驱动回调入档、事件时强实例和后续执行证据为无；1024 写入淘汰已由原生夹具覆盖。 |
| 5. 脏内存断点与新线程接续 | 45% | 正式 CLI 已在自有 AMD64 子进程的对齐数据导出实测 1、2、4、8 B。各宽度下，范围外写、同值写自动继续，首次命中后建立的线程写到关注区间末字节时再次命中。两次 TID 和创建 FILETIME 均独立核验，旧令牌被拒绝，新停点仍持有。关闭确认脱离、登记归零，目标继续并正常退出。另完成 8 B 对齐指针数据导出绑定 `MEM_PRIVATE` RW／RWX 区间：CLI 实际地址与目标 `VirtualAlloc` 地址逐项一致；空指针、未对齐、只读、非 `MEM_PRIVATE`、越界均以 Win32 `487` 拒绝；指针、保护或释放后同址映射替换均清退且不重绑；无 Ready 5.031 s、Ready 前退出 0.016 s、武装前 EOF 均按预期取消。Qt／Light 已接入同一绑定方式和区域回执源码，双语审计 32,034 条通过；桌面实测延期。任意私有页、任意长度、跨区范围、新分配传播及异常终止恢复为无。[回执](action-analyze-planning/private-data-watch.md) |
| 6. 全局下断及恢复 | 30% | 正式 CLI 自有 AMD64 单绑定 131 次停点；合作双目标验证部分／完整持有、组继续、旧令牌拒绝，主动关闭两成员均脱离且存活，自然退出两成员均确认退出事件已继续、退出 `0`。清退冲突重试仅由原生夹具验证（1,072 项）。Qt 已验项目定义保存、重开与冻结；所有者死亡恢复为无。本轮新增明确进程集合的正式 CLI 入口 `analyze process-group session`：1–16 个显式 PID＋创建 FILETIME 实例的配置只核对不暂停，全集与子集暂停、精确令牌继续、成员级部分失败保留成功成员、同 ID 同内容重放不可变与同 ID 异内容冲突、128 项票据窗口过期、Recover 按原 continue ID 回读而错误原 ID 一律 `readback-required`、关闭恢复脱离且最终 clean，均以正式 exe 与自有受控子进程实测 530 项断言；错误 creation、重复 PID、系统目标、非 AMD64、缺 `--confirm`／非法 `--input`、错误与缺失 session 均以真实回执拒绝。原生故障注入未执行，Recover 只验证无故障路径的原票据回读，未决清退下的原 owner 保留分支未实测；全局范围、自动后代、新线程门控与所有者死亡恢复仍为无。[回执](action-analyze-planning/validation-results.md#2026-11-26--正式-cli-定向回执)、[进程集合 CLI 回执](action-analyze-planning/process-group-cli.md) |
| 7. 流量抓取与归档 | 30% | 正式 Qt、Light 均通过合成网络归档回读；CLI 核对完整 300 字节，Light 对账 `0 / 7 / 300` B 和三条实际文件位置。正式 CLI 实测本机回环 ETW 启用报 Win32 5，追踪会话已清退且未产生采样。实时归档正例待验。实时通信字节采集和桌面活网络入口为无。 |
| 8. ETW 遥测及归档 | 85% | 本机正式 CLI、Qt、Light 共验一份至少 180 秒的自有源采样：CLI 回读 68 段、13,200 条 ETW，终段原生丢失和队列丢弃为 0；两端窗口均为最近 4,096 条，筛选得 4,053 条，末观察同为 `raw/67 #13333`。两端均已单独通过活采及项目重开。另通过 CLI 同采样归档并由两桌面端分别筛选 12 条真实自有 ETW 与 2 条合成 API，核对两路 `#2` 的不同原始坐标。CLI 分别验证检查点缺失时另一流仍可完整回读。饱和负载、小时级表现、异常清退和真实 Agent 混采仍待实证。 |
| 9. 底部树状图 | 40% | 正式 Qt、Light 已验关系分组和 `raw/3 #9`。Light 经分组入口使用 Enter 定位被筛掉的原始记录；新版 Qt 用树叶 Enter 和双击均定位到该记录、保持筛选，清筛后恢复选中。两端已接入同采样检查点的树增量更新源码，桌面运行待验。归档行详情与树详情共用同一规范文档，本轮新增版本化 API 字段投影与活采 progress 摘要只做源码／语言包检查，视觉与 Enter 定位仍待桌面实测；Light 旧摘要矛盾已源码修复、实机仍后置，见 [源码回执](action-analyze-planning/api-transfer-desktop-source.md)。正式 CLI 侧活采候选与 `archive.inspect graph` 的 `apiTransferCandidates.links` 坐标一致性已实测，见 [活采候选链回执](action-analyze-planning/live-api-transfer-validation.md)。跨事件强关系为无。 |
| 10. C# 语法及复杂条件断点 | 60% | 正式 Qt 已验离线表达式与 UTF-8 错误位置。正式 CLI 用冻结 RIP 和线程创建 FILETIME 的复合条件核对真条件手动继续、假条件自动继续，另验 RAX 未采集的未知分支与启动前语法错误；三轮均正常脱离。正式 CLI 双目标合作条件本轮补齐同组一真一假的聚合：按启动前冻结的线程创建 FILETIME 阈值区分首成员主线程与次成员后建线程，完整组逐成员同表达式求值得 trueCount=1、falseCount=1，按 any-true-holds-group 整组双持有，重复查询不重复计数，显式 continue/1 释放两成员，关闭双脱离且自有目标正常退出。Qt／Light 写入停点已接入冻结条件和真／假／未知三值处理，桌面实测待验。完整 C# 表达式面与产品侧多目标条件绑定为无。[双目标回执](action-analyze-planning/pair-condition-validation.md) |
| 11. 行为规则预置 | 70% | 正式 CLI 合作采集封段与离线回放使用同一规则集 v1，累计 198 条。目录命令在缺失、坏 JSON、共享冲突下均退出 `4`；恢复后退出 `0`、对账 `2 / 5 / 1`。本轮规则内容身份正式集成通过（本批构建 `8dad7486…`；并发重建后 `c2d46be2…` 复核同值）：目录/采集/回放/恢复摘要均为 `45a1438f…`；新采样 `recordedSourceSha256=45a1438f…`、`matches=true`；旧关闭导入 `recorded/matches=null`；只改 `summary` 后摘要变 `f233b6ac…`、`recorded` 保持、`matches=false`，恢复后回到原值；坏规则 catalog/回放退出 `4`，跟随档图入口与关闭导入原包仍可读；发布文件原字节已恢复。重载及版本冻结另有原生夹具回执。Qt／Light 外置规则待实测，KswordSandbox 601 条候选接入为无。[规则身份回执](action-analyze-planning/rule-profile-integration-validation.md) · [历史回执](action-analyze-planning/validation-results.md#2026-11-26--正式-cli-定向回执) |

第 1、5 项已取得合作范围的本机证据。当前优先补齐第 2 项分段归档与第 4、6、9、10、11 项核心链路。第 3、7、8 项在其余项目基本完成后推进。Qt、Win32 后续桌面实测按用户顺序延后，仅在有实际待验场景时启动相应构建。本机继续做正式 CLI 及有必要的无窗口实测。已有桌面回执保留实际测试范围。指定普通 R0 来宾尚未达到 26300 准入门槛，验收 0/29。

第 5 项桌面源码入口为 Qt「监控 → 行为分析 → 写入停点」和 Light「监控 → ActionAnalyze → 写入停点」。Qt 参数页复用 `ParameterWorkspace`、`StructuredFieldView`、`AsyncOperation` 和 `BackgroundTaskRegistry`。Light 使用原生 `WorkspaceHost`、共享控件和后台清退协议。两端以合作程序路径、精确的数据导出名和关注宽度启动本端会话，显示冻结的进程与触发线程身份，继续当前停点或等待清退回执。桌面正式构建与后续实机记录分别见验收回执。

### Qt 项目工作流

- 默认入口为「监控 → 行为分析 → 项目与采样」。目录使用 `ResultTableHost` Compact，样本配置与分类来自同一份 `StructuredFieldView` 文档。「新一轮扫描」进入现有总览参数并聚焦 PID。用户显式开始后，新采样绑定当前项目及修订。
- 正式 Qt HostX64 Release 已验证在默认入口新建项目，同一自有进程连续两轮各创建独立采样，历史文件保留。第一轮正式归档有 21 条观测，其中 12 条 ETW 报头。重启后打开同一项目、按 UUID 回放第一轮，缺终段、坏中段和重试回到原记录通过。窗口均退出 0，配置恢复，固定项目已清理。日志 `.codex-build-logs/action-analyze-qt-live_archive_reopen-project-current.log`。
- 正式 Qt 在独立桌面选中 CLI 导入的五类合成线索样本，直接显示分类。「查看采样记录」定位最新线索，验证其采样 ID、记录序号和源归档行号。分析预览最多读取 32 个连续段，窗口保留最近 4,096 行，采样详情列出最近 32 条敏感 API 线索。本次实机范围为浅色主题与右侧详情，窄窗、高 DPI、深色和背景模式待验。[复跑命令与回执](../tools/action_analyze_validation/qt/ETW-Readback.md#项目工作台与三端同采样)
- 「项目与采样」的证据定位选项来自同一次归档分析，显示类别、API 名称和 raw 坐标。正式 HostX64 Release 在深浅主题的右侧详情布局中选择内存写入线索，直接定位同一采样的 `raw/1 #1`、源行 `2`，并通过筛选、坏尾及恢复。工具带使用共享换行布局和工具控件几何，目录与字段详情沿用原共享组件。发布窗口保持最多 32 条可定位线索，窗口之外通过总览查阅。颜色对比、DPI 和背景模式待验。[复跑命令与回执](../tools/action_analyze_validation/qt/ETW-Readback.md#项目工作台与三端同采样)

### Light 项目工作流

- 「监控 → ActionAnalyze」通过 `WorkspaceHost` 进入原生工程页。新建、打开、扫描参数与采样目录复用原生工具带、`AsyncSnapshotTask` 和 `VirtualListView`，证据列表操作条为 None。选中后预览首段，显式回放读取检查点已发布的后续段。旧单段在 800×650 窗口验证工程选择、取消、回放、ETW 筛选、键盘选中和损坏重读。仍需主题、DPI 和完整键盘路径矩阵。
- 独立桌面已验空工程发起首轮，随后用同一自有进程再次扫描。停止后返回工程自动出现新采样，两个采样独立存储，各提交两段并报告 ETW 丢失和队列丢弃为 0。目标退出后重启 Light，打开同一工程回放第二轮并对账原始字节。窗口正常退出，配置恢复，固定夹具已清理。[复跑命令与回执](../tools/action_analyze_validation/qt/ETW-Readback.md#项目工作台与三端同采样)
- 正式 Light 用键盘选择证据类别并定位。目标行被筛选隐藏时，详情保留真实记录及坐标。清除筛选恢复表格选中，由首段预览进入正式回放后仍是同一条记录。与 Qt 共用采样 `82a181e8-f3f3-473d-b524-ef801b0c7219`，两窗口退出 0，配置恢复，固定夹具已清理。[复跑命令与回执](../tools/action_analyze_validation/qt/ETW-Readback.md#项目工作台与三端同采样)

### CLI 长程 ETW

- 正式 CLI 在 180.078 秒内接收 13,400 条自有 ETW 事件。69 个运行段和 1 个终段逐条核对原始流、覆盖流、检查点及字节。CLI 写端峰值工作集 15.16 MiB，采样私有提交量最高 7.69 MiB，CPU 时间 1.234 秒。生产、写端与读端退出均为 0，固定目录已清理。复跑命令为 `python -B tools/action_analyze_validation/cli/continuous_etw.py --long-seconds 180`。
