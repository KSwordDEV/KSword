# A5 / RAV0 被动环境入口清单

适用范围为 Windows x86、WOW64 和 x64 的 E01–E16 规划入口。清单基于 ActionAnalyze 分支的 898 项 API Monitor 声明、采集器源码、Windows 接口文档和已有自有夹具报告。入口选择优先覆盖方案点名的接口及其常见并行来源。能力审批仍需以每个系统版本、体系结构、来源和阶段的有效证据为准。[E01–E16 方案](../../ActionAnalyze反反虚拟机与环境实验行动方案.md#3-探测面与行动矩阵) · [A5 施工项](../../ActionAnalyze施工任务与契约落点.md)

| 资料 | 用途 |
| --- | --- |
| [environment-entry-catalog.jsonl](environment-entry-catalog.jsonl) | 每个入口一行。包含模块/导出或接口/方法等身份、架构、语义角色、actor 角色、字段类型和适用阶段、源码或官方依据、现有字段缺口与历史证据。 |
| [strong-selection.jsonl](strong-selection.jsonl) | 强类型入口选择和按职责共享的旧采集字段矩阵。具体 API 行保留原声明和实际处理器定位。 |
| [additional-entries.tsv](additional-entries.tsv) | 外部 API 和非导出来源的人工核对输入。字段为调查所需的原生类型摘录。 |
| [historical-api-matches.jsonl](historical-api-matches.jsonl) | 既有 20H2 自有夹具逐接口报告的 16 个架构行，保留原字段名、值、报告 SHA-256 和 JSON Pointer。 |
| [rule-overlap.jsonl](rule-overlap.jsonl) | 7 个本地候选 JSON Pointer 和字段键、4 个固定上游文件身份，以及可关联的入口角色和待核对项。 |
| [inventory-check.json](inventory-check.json) | 清单行数、E 面计数、历史证据计数、Raw 包语义和数据哈希。跨多个 E 面的接口只占一个入口行。 |

## 如何解读字段和证据

- 强类型行的 `declaration` 保留唯一 JSON 定义中的原始对象，包括参数方向、长度、编码、调用约定及返回契约。`contractFields` 记录字段语义及阶段。已发现的方向差异单列为 CoCreateInstance `objectPointer` 输出、注册表 value API `dataSizePointer` 输入/输出、GetThreadContext `contextPointer` 输入/输出。其它从声明继承的方向仍可按 SDK 逐项复核。[唯一声明源](../../../APIMonitor_x64/api_monitor_definitions.json)
- `legacyPhases` 给出现有发包阶段。生成包装先保存至多八个参数位置的值或地址，原调用之后统一发送 `ApiCall`。`detailText` 是 320 个宽字符的有界摘要。标记存在时才读出独立返回位和 100 ns 耗时。`legacy-typed` 表示旧协议中的具体字段，`legacy-summary` 表示源码会产生该摘要，内容仍可能截断、未读取或只记录了指针。共享 `legacyProfileFields` 给出职责组的覆盖边界，个别成员是否实际带该值须回查该行定位的函数。`unknown` 表示该项需逐成员复核，`needs-capture` 表示缺原值，`needs-enrichment` 表示缺身份或关联，`unsupported` 表示当前路径无此资源。契约字段的阶段沿用 A0 的 `entry`、`return`、`complete`、`observation`。只有原来源发出这些阶段时，才在 `legacyPhases` 中记录。[包装生成器](../../../tools/api_monitor/generate_definitions.py#L163) · [旧包协议](../../../shared/WinApiMonitorProtocol.h#L162) · [阶段与字段契约](../../ActionAnalyze事件身份与协议契约.md)
- `absent-from-strong` 表示 898 项中没有同名导出。`owner` 对外部 API 使用文档入口模块。解析后的最终地址、已有强类型别名、加载时机、架构、规则和覆盖快照都需要单独核对。Raw 经过模块名单、默认拒绝名单、分类和地址检查，有效 Raw 事件仅保留 `EntryOnly`。QPC、Tick、Sleep 等默认拒绝项已按源码标明。[Raw 策略](../../../shared/WinApiMonitorProtocol.h#L103) · [Raw 入口处理](../../../APIMonitor_x64/hook/HookTargets.cpp#L1840)
- `historical-return-matched` 记录指定 20H2 快照中的调用/事件配对。两架构各七项匹配。`GetCursorPos` 和 `GetCursorInfo` 的匹配来自失败路径，`GetLastInputInfo` 匹配来自成功路径。两架构的 `GetPhysicalCursorPos` 均报告共享入口冲突。返回配对仍留有结构输出缺口。`unverified-in-inventory` 表示本目录没有该项运行证据。行内 `architectures` 对强类型条目来自声明，对其余条目表示计划审查范围。 [API Monitor 逐接口验证](../../../APIMonitor_x64/README.md#逐接口运行验证) · [原报告摘录](historical-api-matches.jsonl)

## E01–E16 关键待补字段

| E 面 | 待补项 |
| --- | --- |
| E01 | 绑定 WMI namespace、对象身份、属性和实际 `VARIANT.vt` / `CIMTYPE`。COM 激活、目标方法、WMI ETW 和 KSword 自有订阅各有来源。ETW 需提供确切版本和原包。 |
| E02 | 记录注册表 hive、有效 WOW64 view、成功输出字节及 HKEY 代次。区分 pre 尝试、status、输入容量、所需容量和实际值。 |
| E03 | 确认文件对象与路径、返回记录、枚举游标及最终完成。Win32 与 Native 出现相同对象时需要关联证据。 |
| E04 | 取得进程创建身份、完整枚举项、模块装载身份或服务代次。枚举结束状态、版本和截断要保留。 |
| E05 | 区分固件 provider、table ID、容量、返回长度和有界原字节。HardwareDock 的固件读取归 KSword 观察者。 |
| E06 | 补 group/affinity、进程与系统视图、物理/虚拟内存、逻辑卷与物理盘身份和单位。 |
| E07 | 保存实际 IOCTL、设备身份、完成状态、长度和已验证结构。当前通用日志不交付 buffer 正文。 |
| E08 | 保存网卡 LUID/GUID、物理地址及其长度、地址族、DNS 等实际值。同一接口索引的时间有效性待核。 |
| E09 | 需要执行现场、线程和映射版本、leaf/subleaf 和结果寄存器。普通 API 事件没有内联指令现场。 |
| E10 | 区分 QPC、uptime、UTC、TSC 和共享数据。目标读取证据与工具采证时钟分开。 |
| E11 | 保存超时域、原请求期限、完整等待对象、alertable 和精确状态。用独立时钟核对耗时。 |
| E12 | 实际 `POINT` 两坐标、`LASTINPUTINFO.dwTime`、会话、坐标空间、DPI、回绕仍待采。现有摘要仅带输出地址。 |
| E13 | 绑定用户、会话、locale 和路径的来源，明确权限与采集界限。命令行或目录快照只提供各自范围的证据。 |
| E14 | 需要成功后有效的状态输出、被查询对象、实际内存读或异常来源的独立证据。ETW syscall 地址和退出状态只有各自载荷。 |
| E15 | 需要 DNS 结果、连接和请求代次、完成证据、可溯源的响应/握手字段。网络可用性可随环境独立变化。 |
| E16 | 需要强实例、事件覆盖和顺序、可复核的分支及退出证据。连续出现的事件只支持当前明确的关联强度。 |

## 离线复核

```powershell
python -B tools/action_analyze_source_inventory/environment_inventory.py
python -B tools/action_analyze_source_inventory/environment_inventory.py --verify-history
```

第一条使用版本库内的资料，并逐字节比较生成的目录和收据。第二条需要本地存档 `.codex-build-logs/gui-per-api-vm-20261108/per-api-summary.json`，用原始报告验证摘录。修改人工输入后可以加 `--write` 更新目录和收据。本目录的历史摘录绑定当前声明 SHA，换版本需复核历史与新目录的关系。验证器只解析指定文本文件。上游文件交叉核对使用固定文件清单，本地规则源检查使用 JSON Pointer 和字段键。[规则来源锁](../source-lock.json) · [校验器](../../../tools/action_analyze_source_inventory/environment_inventory.py)

可直接复用的规则审查接口是入口身份、阶段、字段类型和既有缺口。W2 后续仍要按原节点检查语法作用域、例外和依赖，尤其是本地候选的 `allDataRegex`、数值范围、命令行条件和排除字段。capa 与 CAPE 行只绑定固定文件，正文及逐规则许可由其各自审查负责。[规则交叉索引](rule-overlap.jsonl) · [W2 施工清单](../../ActionAnalyze规则来源与转换施工清单.md#3-w0w8下一层任务) · [规则阶段与运算语义](../../ActionAnalyze筛选器与规则语言设计.md)
