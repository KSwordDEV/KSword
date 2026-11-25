# ActionAnalyze 工程推进记录

## 持续推进与交接

用户原话：「严禁在我问一个问题过后就停下来，任务完成之前不能停下来，全部继续推进」。进度答复后继续执行当前任务。该原话、未完成项目及下一可执行步骤须保留在压缩摘要和交接记录。按 [11 项产品验收清单](../../docs/ActionAnalyze产品验收清单.md) 更新状态，正式产品实证明确到入口、产物和测试范围，闭合批次仅推送 `ActionAnalyze`。

## 2026-11-24 首批工程启动

- 用户授权多 agent 并发编码、按功能分批提交和推送。主协调者负责分工、接口对齐、证据审查、集成排序、Git 和工程记录。逻辑闭合的工作包可先提交到 `ActionAnalyze`，适用构建可随后执行。分别记录源码、构建、原生和产品验收状态，产品验收项凭对应产品证据关闭。
- 新增或重构文件每文件上限 2000 行，沿用仓库建议的 1000 行组织目标。按职责拆 `.h`／`.cpp`，驱动用适用 `.h`／`.c`，禁止 `.inc` 堆叠。重构逐项登记受影响的旧功能与入口、行为、端／架构、复测判据、实际结果和待测范围。优先单独提交可验证的结构改动。
- R3 是正式后端，必须在 KSword 驱动未加载或不可访问时独立完成受支持用户态全流程。采样显式选择后端，活采样禁止静默切换。更换时原所有者先完成恢复并确认脱离，之后新建采样与会话代次，旧停点令牌和恢复责任留在原后端。
- 已确认同步下断使用命中线程直接进入已登记原生停点、目标外所有者接管。首个双架构夹具用自有合作目标验证调试所有权、进入／返回阶段和原调用语义。
- 用户指定 Qt 的唯一挂载点为「监控 → 行为分析」。总览、项目与采样、后续规则和断点等均是该工作台的子页。MonitorDock 管理根宿主，实际页签、全局搜索和 Taskbar 共用 `monitor.action_analyze` 导航树。
- 新增桌面工作包覆盖显示筛选、底部进程与线程右键和 Dump 导出、随采样自动归档网络流量元数据、出站 IP 和实际通信字节。网络写入沿用采样内 `raw`、`records`、BlobStore 和检查点。采样身份贯穿筛选、菜单与归档。[桌面交互计划](../../docs/ActionAnalyze总览交互与验收.md#显示筛选对象菜单与网络证据实施计划)
- 停止调试后的目标处置，以及单步时是否扩大依赖线程放行范围，仍由调用方显式决定。发现影响持久格式、恢复语义、采集范围或无驱动承诺的歧义时，先在依赖方之间对齐。产品需求变更写回共享基线并通知全部受影响 owner。

首批分工已启动，状态为开发进行中。A0 类型与 Stored 契约、CLI 离线外壳、Stored 归档与恢复、CLI 项目生命周期、离线规则回放、R3 停点夹具、被动环境入口目录、既有上游目录按行数拆分，各自独立编辑，统一审查提交。CLI `.vcxproj`／`.filters`、入口接线与内置帮助、文档同步在接口交付后统一分配，并串行运行共用构建工程。

## 当前验收决定

全范围完成验收后才能最终关闭。R3 在本机验证。普通 R0 在指定来宾 `E:\VMs\Windows11-24H2` 阻塞。普通 R0 入口要求 `RtlGetVersion` 报告 OS build `26300`，来宾 OS 为 `26100.9711`，SYS 就绪也无法通过。来宾已有 `TESTSIGNING`，KSwordARK 服务未注册、驱动未加载，现有产物来源与验证批次不匹配，配套签名候选产物未暂存。29 项普通 R0 外部判据尚未运行。历史夹具沿用各次授权和原始证据。环境详见本地计划 `docs/ActionAnalyze工程开工基线.md` 的「验收范围与运行环境」。

## 已接收批次与证据

| 提交 | 内容与证据 | 分支状态 |
| --- | --- | --- |
| `69f490db2` | 离线协议模型，本次无写入重跑 31/31 通过。 | 已推送 `origin/ActionAnalyze` |
| `f28f7fd5a` | 自有目标的 R3 原生步进夹具，本批沿用历史 106 项断言通过的证据。 | 已推送 `origin/ActionAnalyze` |
| `f04142e96` | 自有目标的传输夹具，保留历史 37 项 IPC 回归、7 项父进程终止后的子进程清理、TCP 权限负控。实际成功断连待验。 | 已推送 `origin/ActionAnalyze` |
| `f0efdde80` | 固定规则来源目录，共 24 个文件。11 个分片顺序拼接与原索引字节一致，批次内各文件最多 2000 行。 | 与 `10e0f370f` 同批推送至 `origin/ActionAnalyze` |
| `10e0f370f` | 自有目标页面执行探针夹具，沿用历史 21 项检查通过的证据。 | 与 `f0efdde80` 同批推送至 `origin/ActionAnalyze` |
| `055fef531` | SB02 自有目标同步停点夹具。Windows 10 19045，BelowNormal、HostX64 构建 x64 及 Win32 两个 Release，分别运行原生 x64 与 WOW64 目标。386 项断言通过，四个自有子进程，8 次真实停点、8 次旧代次或外来事件正确转交，四个正常退出事件，零测试配置、零残留夹具进程。[SB02 夹具说明](../../tools/action_analyze_sync_stop_validation/README.md) | 已推送 `origin/ActionAnalyze` |
| `6b459325e` | CLI 离线会话外壳和命令帮助。共用正式工程 HostX64 Release 构建退出 0，0 警告、0 错误，产物 `Ksword5.1/x64/Release/KswordCLI.exe`。旧 shell smoke 已独立运行并通过。本机构建日志 `.codex-build-logs/action-analyze-cli-shell-20261124-223330.log`。[旧 shell 回执](../../tools/action_analyze_validation/cli/README.md#first-shell-build-evidence) | 已推送 `origin/ActionAnalyze` |
| `5adc91d33` | A0 基础和 Stored v1 静态契约。66 项基础用例、35 项 Stored 用例及 CRC／UUID 检查通过。[基础契约](../../schemas/action_analyze/base-contract-v1.md) | 已推送 `origin/ActionAnalyze` |
| `a7d40bc27` | A0 离线 CLI 方法静态契约。62 项请求、传输及输出向量通过。[方法契约](../../schemas/action_analyze/method-contract-v1.md) | 已推送 `origin/ActionAnalyze` |
| `121ef3ea2` | Stored v1 分段读写与前缀扫描，覆盖封装范围与 CRC。记录语义解码另验。[归档验证范围](../../tools/action_analyze_validation/archive/README.md) | 已推送 `origin/ActionAnalyze` |
| `d2f246c8e` | 类型化离线规则回放与有界筛选。仓库夹具使用内存事件投影，完整 DSL、真实归档接线和实时策略继续按工单验收。[规则夹具范围](../../tools/action_analyze_validation/rules/README.md) | 已推送 `origin/ActionAnalyze` |
| `9a5449304` | 离线项目、配置修订和采样持久化。HostX64 Release 原生夹具 71 项以及 Python 文件与语义校验通过。最终可达代次链为 `6 → 4 → 3 → 2 → 1`，第 5 代保持未提交。[验证回执](../../tools/action_analyze_validation/project/ValidationReceipt.md) | 已推送 `origin/ActionAnalyze` |
| `96b9f38bd` | 被动环境证据来源索引归档。覆盖资料目录的静态清点，运行覆盖按独立判据验收。[来源索引](../../docs/action-analyze-planning/environment/README.md) | 已推送 `origin/ActionAnalyze` |
| `9c52f1847` | 原生停止责任账本与 C++ 夹具。账本处理单原生事件的释放责任。[账本范围](../../KswordCLI/ActionAnalyze/Control/README.md) | 已推送 `origin/ActionAnalyze` |
| `c0543c4dd` | Qt 普通 R0 回读解析器构建通过。R0 运行未执行。 | 已推送 `origin/ActionAnalyze` |
| `14509b8aa` | A0.2 离线项目／采样方法，62 项基础向量及 47 项项目方法向量通过。 | 已推送 `origin/ActionAnalyze` |
| `221cda4ba` | 正式 CLI 离线项目生命周期接线。HostX64 Release 构建退出 0，0 警告、0 错误。正式 CLI 的 `project_v1` 验证通过，临时验证目录已清理。 | 已推送 `origin/ActionAnalyze` |
| `923e36acc` | 保留 origin 的停止快照契约，96 项离线停止向量通过。 | 已推送 `origin/ActionAnalyze` |
| `59046a957` | 自有合作目标的原生停点与责任账本夹具。集成 495 项、基线 415 项、独立账本 124 项通过，范围限于各自夹具。 | 已推送 `origin/ActionAnalyze` |
| `345472b89` | Stored 格式分类与截断覆盖。469 项截断检查、35 项 A0 封装向量通过。 | 已推送 `origin/ActionAnalyze` |
| `a302d03cc` | 已提交采样的项目归档段解析器。28 项原生检查及 71 项项目生命周期夹具检查通过。 | 已推送 `origin/ActionAnalyze` |
| `a7f117606` | 正式 CLI 接通 `archive.inspect`。HostX64 Release 构建、12 方法的传输回归、项目及归档验收通过，测试目录已清理。[归档回执](../../tools/action_analyze_validation/cli/README.md#archive-v1-build-and-test-receipt) | 已提交 `ActionAnalyze` |

`221cda4ba` 的构建日志为 `.codex-build-logs/action-analyze-cli-project-20261124-224716.log`。受测正式产物 `Ksword5.1/x64/Release/KswordCLI.exe` 的 SHA-256 为 `54569FA5788D53160D1A6B2D37744A839E0B2A5D525E50BA834ECB9B0752710B`。`42c5977e6` 回执记录 `project-v1` smoke 通过 16 项请求、22 项传输向量及回执缓存条数和字节上限检查。[正式 CLI 验证回执](../../tools/action_analyze_validation/cli/README.md#unified-project-v1-build-and-test-receipt)

原 SB02 本机证据为 `.codex-build-logs/behavior-planning/action-analyze-sb02-20261125-022401-3067253-35208-metadata.json`。后续 `59046a957` 已验证自有目标夹具接线。并发命中、控制所有者死亡恢复与产品接入继续待验。

## CLI 接入与待验项

- 2026-11-25 正式 HostX64 CLI `b05abcd310b28515036802d70c5ab8cbbf7b74815ec35f63c7f70b1d8f74e37a` 复验自有 AMD64 子进程 131 次停点、130 次继续、128 条继续回执窗口和正常脱离。持续内存流通过 70 轮及精确 4 字节差异、四类输入收尾、stdout 断开和背压超时，以及退出后的计数对账。日志位于 `.codex-build-logs/action-analyze-cli-product-breakpoint-current.log` 和 `.codex-build-logs/action-analyze-cli-product-memory-current.log`。夹具已清理。全局停止组和故障恢复仍待验。
旧 `KswordCLI/KswordCLI.cpp` 已有 8398 行。ActionAnalyze 沿用它现有的委派入口，经 `KswordCLI/CommandRegistry.cpp` 接入，新增逻辑按职责拆分。上述 smoke 已覆盖实际帮助、旧入口查询及异常参数处理。其余回归按工单记录实际结果。

Qt 和 Win32 总览作者开工前均须读 `design-taste-frontend`。Qt 首版离线项目与采样通过正式 Release 构建，Win32 离线读取单个 Stored 段。实际窗口和旧入口回归另行验收。[当前离线切片](../../docs/ActionAnalyze总览交互与验收.md#当前离线切片)

Light 与独立 Stored 验证器的正式 Release 构建均以 BelowNormal 优先级使用 HostX64 工具链，两项构建均为 0 警告、0 错误。验证器通过 35 项 Stored 向量和 2 项 Win32 文件用例。正式产物为 `Ksword5.1/x64/Release/KswordARKLight.exe` 和 `Ksword5.1/x64/Release/KswordARKLightStoredEvidenceValidation.exe`。签名驱动镜像的 SHA-256 构建前后一致。[Light 构建与验证回执](../../docs/ActionAnalyze总览交互与验收.md#light-构建与验证回执)

## 网络证据的离线验收

网络草案通过 39 项静态向量。原生网络归档夹具在固定 `KswordCLI/x64/Release/ActionAnalyzeNetworkEvidenceValidation` 中构建并从统一 Release 运行，HostX64 `/W4 /WX` 的 539 项断言通过。包含 65,536 字节逐字节往返、队列回绕、源及队列丢失回执、实际截断文件后的已验证前缀。夹具段、对象文件和 EXE 已清理。投影夹具通过 112 项合成检查，包括八个 ETW 双栈收发描述符、IPv4 UDP／IPv6 TCP 原始内容及截断前缀。

旧 R3 `PacketRecord` 交付的实际字节最多 4,096，归档 writer 内联上限 65,536。ETW 计数按仅元数据处理。归档 writer 运行在样本单写者持有的串行通道，段刷新只产生文件前缀回执。实时接线、规范事件引用、BlobStore、检查点及跨端项目重开须单独验收。[网络草案](../../schemas/action_analyze/README.md#网络证据)

阶段依据保存在本地计划 `docs/ActionAnalyze工程开工基线.md`、`docs/ActionAnalyze施工任务与契约落点.md` 和 `docs/ActionAnalyze同步全局断点与性能复查.md`。首次启动时工作区有既有规划、验证夹具和资料目录尚未提交。集成须用限定路径提交，逐批核对来源、文档链接依赖、生成文件和行数。

## 被动 ETW 桌面回放

- 2026-11-25 正式 CLI 与 Light 共用 9 段持续 ETW 项目。CLI 记录 624 条 ETW 观察并查询 4,101 个不同 ID。Light 检查终段、624 条 ETW 筛选结果、跨段末观察的归档坐标和重读选择。移走第 2 段检查点后窗口报告该段尚未发布并只显示第 1 段的 14 条原始记录。截断第 3 段覆盖流后报告核验失败并显示前两段的 28 条。恢复后读回全部 642 条。旧 ETW 单段与五类 API 归档在同一 Light 产物复测通过。窗口正常退出，测试配置恢复，固定目录清理完成。日志 `.codex-build-logs/action-analyze-light-continuous-etw.log`，构建产物位于 `Ksword5.1/x64/Release/`。指定普通 R0 及 Light 实时采集仍待验。
- `3403fe3dc` 已推送至 `origin/ActionAnalyze`。Qt 项目入口重开冻结的项目及采样描述，再复用 CLI 校验 `raw/1` 与 `records/1`。只读句柄验证相同 raw 散列后，仅投影已提交前缀。标记缺失显示旧档回退，缺依赖或错采样保留原表和选择。独立段入口保留诊断式部分预览。
- 正式 Qt HostX64 构建、双语及主题门禁通过。真实 Qt 复验 14／12 行、同一详情、未提交尾部、缺 Coverage、错采样、旧档回退和恢复重读。窗口退出 `0`，测试项目和配置均已清理或恢复。浅色及右侧详情已验，Light 项目回放及完整桌面矩阵继续验收。[Qt 回执](../../tools/action_analyze_validation/qt/ETW-Readback.md#qt-项目检查点)
