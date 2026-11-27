# 条件与 API 观察预置

`PreparePredicateExpression(source, phase, catalog)` 用当前 `predicate-expr-v3` 准备新条件。读取冻结配置时使用四参数重载，传入配置保存的 profile；`IsSupportedPredicateExpressionProfile()` 判断版本是否已登记，不能把任意旧版本重标成当前版本再解析。

| Profile | 实际准入 |
| --- | --- |
| `predicate-expr-v1` | 原字段对显式常量比较、布尔组合、括号、文本函数、`isNull/isComplete`。 |
| `predicate-expr-v2` | v1 加 `isKnown` 和 `quality(field) ==/!= "规范质量名"`。 |
| `predicate-expr-v3` | v2 加有限 u64 数值子树、字段对字段比较、类型化 `?:` 和布尔非短路 `& ^ |`。 |

v1/v2 保留原解析路径：拒绝数值算术、位操作、数值括号和字段对字段比较。v1 拒绝 v2 的质量函数。旧 JSON `FieldTest` 继续调用原 `PreparePredicate()`。

v3 数值常量支持十进制、`0x/0X` 十六进制及 `0b/0B` 二进制，后缀为 `u64` 或大小写 `UL/LU`，数字内部可用 `_` 分隔；旧 v1/v2 仍只接受原十进制、`0x` 和 `u64`。所有基数完整检查 u64 范围，不截断溢出。优先级从高到低为 `! ~ +`、`* / %`、`+ -`、`<< >>`、关系比较、相等比较、`&`、`^`、`|`、`&&`、`||`、`?:`。普通二元操作左结合，`?:` 右结合；数值位运算两侧须为 u64，因此 `(mask & 1u64) != 0u64` 必须明确括号。没有赋值、自增自减、用户函数、对象方法、指针读取或正则执行。

`WriteFile` 返回 `FALSE` 且原错误码为 `ERROR_IO_PENDING (997)` 时，预置释义独立标为异步等待，不把调用返回布尔值误写成最终 I/O 失败，也不推测完成字节数。同步成功的零字节、部分和全部完成沿独立计数字段解释。

`condition ? whenTrue : whenFalse` 的条件必须为 bool，两个分支同为 bool 或同为 u64；顶层仍要求 bool。准备阶段检查全部分支的字段和类型，执行时条件为真／假只读取所选分支，未知条件直接返回 Unknown，不读取两个分支或推断相同分支。示例：`(stop.firstChance ? stop.thread.rax : stop.thread.rbx) == 0u64`；`stop.firstChance ? true : stop.thread.rax != 0u64`。未选择的除零分支不产生故障，选中分支沿用 `division-by-zero`。v1/v2拒绝三元语法。缺 `:`、非布尔条件、分支类型不同分别返回 `expression-expected-conditional-colon`、`expression-expected-boolean-condition`、`expression-conditional-branch-type-mismatch` 及源码位置。本次三元扩展仅完成源码，未构建或运行。

加减乘按 unchecked u64 环绕，右移为无符号右移，移位计数只取低六位。不支持一元负号。字面量越界在准备阶段拒绝。未知操作数传播未知；已求值的零除数使结果为 `Unknown + DivisionByZero`，稳定 ID 为 `division-by-zero`。`&&/||` 按三值逻辑从左到右短路，未进入的分支不产生算术故障。所有新数值节点受 512 节点、32 深度和运行计费预算限制。

v3 的 `&`、`^`、`|` 也接受两个 bool 谓词，按 C# 优先级从左到右求值两侧，不使用 `&&/||` 的短路。bool 与 u64 混用在准备阶段拒绝。bool `&` 中假值决定假、bool `|` 中真值决定真，其余未知按三值逻辑保留；异或任一未知即 Unknown。即使左侧已决定真值，右侧发生的除零或预算故障仍使整体为带故障 Unknown。例如 `(stop.pid == 42u64) & isKnown(stop.thread.rax)`；`false & (1u64 / 0u64 == 0u64)` 会求值右侧并报告 `division-by-zero`。数值位运算语义不变，v1/v2继续拒绝这些运算符。该布尔扩展仅源码完成，未构建或运行。

主程序“监控 → 行为分析 → 行为规则草稿”使用相同解析器。草稿顶层可显式设置 `expressionProfile`；未设置时按 v2 读取，新的内置草稿明确使用 v3。字段类型从 `BehaviorRuleFields()` 取得；合成草稿输入和归档预置字段分别列出，不把 API 字段冒充合成事件输入。

v3的 `==`、`!=` 支持两个bool字段或任意bool子树，如 `stop.firstChance == isKnown(stop.thread.rax)`、`(stop.firstChance & isKnown(stop.thread.rip)) != false`。两侧按左到右求值；任一未知即Unknown，包括两个未知值，不把未知当false或彼此相等。bool大小比较及bool/u64混用拒绝；旧 `field == null`／`!= null` 仍是原字段null测试，v1/v2维持字段对显式常量语法。新增源码未构建、未实测。

v3还支持两个已登记文本字段的 `==`／`!=`，例如 `file.path == file.sourcePath`。两字段必须属于当前事件阶段，区分大小写，不归一化路径；文本大小比较、跨类型比较和将文本字段当函数模式均拒绝。双方完整Known时比较原UTF-8值，两个显式Null相等，Null与已知空字符串不等；缺失、截断、拒绝访问及读取失败均为Unknown，同字段未知也不折叠为相等。两侧从左到右读取，沿用原UTF-8、长度及工作预算，坏字段故障不能被布尔短路之外的比较隐藏。Qt草稿、CLI预置及Light回放共用此准备器，不扩大各入口的字段目录；没有文本字段的停点目录仍拒绝该示例。v1/v2与原字段对常量文本比较语义保留。本增量仅源码，未构建或运行。

`profiles/action_analyze_api_rules.json` 保留 `schemaVersion:1`，新增可选 `expressionProfile`；旧文件省略时为 v2。结构见 [API 预置 schema](../../../schemas/action_analyze/api-rule-presets.schema.json)。数据库仍冻结实际读取字节的 SHA-256，修改文件不替换已加载采样的准备结果。

`BehaviorPresetFields.cpp/.h` 是规则专用投影，不建立跨事件候选链。`ReadApiPresetEvidence()` 调用专用协议严格读侧与普通强类型返回读侧；`ProjectApiPresetFields()` 只发布有效位、精确返回或通过严格 formatter 格式核对的字段。全部字段处于归档观察阶段；`evidence.phase == "return"` 只由通过返回核验的协议产生。缺字段为 `NotCollected`，不回填零、不做 raw substring 匹配、不解引用请求指针。API 报告的身份与返回不认证历史生产者，也不授予活控制权。

自有词条包括内存／线程八类、注册表查询／写入、进程枚举、模块／系统查询、进程创建、文件打开／复制／写入、服务管理、名称解析／网络会话／HTTP 请求。具体条件及双语释义以外置配置为准。AAIM1／AAAP1／AACT1／AASM1 仍按独立协议投影；跨进程词条要求双方创建代次、目标稳定和不同 PID，APC/context 还要求目标线程代次。所有词条由 KSword 自行编写，未复制第三方规则或修改原有许可。

目录与加载使用同一配置和字段目录，CLI `api-rule-catalog` 同时给出兼容 `fields` 列表及 `typedFields`；Qt／Light 回放只把既有归档行已核验的协议值交给相同准备结果。无返回证据的包只分类，不生成返回层级释义。

普通强类型参数由 `ApiBehaviorObservation.cpp/.h` 消费已有采集格式，而非执行上游脚本。读侧要求同模块、精确 API、类别、Strong、非零源会话、显式返回标记，并按 API 分别解释 BOOL／HANDLE／LSTATUS／NTSTATUS／GetAddrInfo 返回。`StatusUnknown` 不发布错误码；GetAddrInfo 的错误来自函数返回，不能把包装器残留的 WSA LastError 当成原因。返回字段可独立存在，参数无效不回填假值。

`NtQueryInformationProcess` 独立归类为 `process-query`，由同一 `ReadApiPresetEvidence()` 发布真实 NTSTATUS 返回观察；32位返回位和原包状态必须一致，按 `NT_SUCCESS` 解释。`process.informationClass` 只来自完整 `process/class/size` 数值布局中的请求信息类；末尾 size 可能是输出长度或输入容量，不发布为结果。正式双语谓词只对 ProcessDebugPort（7）、ProcessDebugObjectHandle（30）、ProcessDebugFlags（31）的成功／失败查询解释为调试环境查询线索。生产 Hook 未保存三类输出值，故不提供 `debuggerPresent` 或调试器存在／不存在结论，也不从句柄推断目标身份。

现有生产声明、Hook 与 formatter 没有 `IsDebuggerPresent`／`CheckRemoteDebuggerPresent` 强类型采集，不能为它们创建可触发谓词或伪字段。若后续增加 `IsDebuggerPresent` 的可信返回，FALSE 应解释为查询成功且调试器不存在，不能复用普通 BOOL 的失败约定；本次不增加 Hook 或修改协议。

原通用包的文本没有独立完整性位。本读侧仅接受具名字段完整布局，文本必须有已核验后继字段，生成包装器还须有签名对应的完整 `arg1...argN` 十六进制尾部。满缓冲、无终止符、可见不可读标记、非法 UTF-16、控制字符、文本中的 `=` 等歧义分隔使参数不发布。ANSI formatter 未归档代码页，仅接受 ASCII；W 版用严格 UTF-16 转 UTF-8。配置缩短摘要导致缺尾时，返回事实仍可保留，缺参数的规则为 Unknown。没有把 NUL 结束等同于独立的完整性有效位，也未给末尾无分隔文本创建类型字段。这里的 Known 表示按已登记 formatter 语法解码成功，不是独立采集完整性认证：配置截断可能落在最终数字中；恶意输入若伪造后继布局且真正尾部又被剪掉，旧包无法与完整布局区分。除下述受生产摘要下限保护的 WriteFile 计数外，不发布最终尾数字作为业务字段，也不据此声称采集文本在对抗输入下完整可信；需要独立长度或完整性协议才能关闭该边界。

`file.requestedBytes`／`file.transferredBytes` 只在 WriteFile 成功返回且完整 `handle/request/transferred` 数值布局通过时一起发布，分别是请求及安全读回的完成字节数。布局还必须短于现有 MonitorConfig 的最小摘要限制64字符；达到64字符及更长时均不发布计数，保守拒绝可能截短最终数字的包。现有 HookedWriteFile 仅非 OVERLAPPED 调用成功且安全读取输出时写完成数字；失败、异步成功及输出不可读的 `transferred=unknown` 不补零，也不单独发布请求计数。规则按零完成（包括零请求）、正数部分完成、正数全量完成依次置于原通用返回释义前，缺计数或不符合三种关系时保留原 fallback；这些计数不证明文件路径、内容或持久落盘，不关联后续异步完成包。

`registry.path`/`registry.pathLower` 仅来自 RegOpenKey 的明确 HKLM/HKCU 根，或 RegGetValue／RegSetKeyValue 的预定义根 HKEY 加子键。普通句柄不查当前系统、不做历史映射。`*Lower` 仅折叠 ASCII 大写，不变换斜杠、不展开环境变量、不删除 `..`；目录里的 ASCII 键路径可用精确相等或明确分支前缀匹配。无名默认值当前不投影为已知空字符串。`registry.valueNameLower` 同样按 ASCII 大小写匹配。RegSetValueEx 虽有值名，但没有键路径，不能命中 Run 键规则。

默认行为覆盖虚拟化软件／服务／ACPI 键查询的成功与拒绝、精确隔离模块查询、来宾服务打开、进程／模块枚举，以及 Basic、Process、Module、Firmware、KernelDebugger、Hypervisor、CodeIntegrity、HypervisorDetail、IsolatedUserMode 等指定系统信息类查询；所有环境规则只称探测线索。启动配置包括 Run／RunOnce、Winlogon、AppInit；服务与任务包括服务 ImagePath、TaskCache 分支写入、服务创建／启动请求／配置修改／标记删除，以及应用参数名为 schtasks.exe 的进程创建。后者不证明任务注册；文件规则不把打开句柄称为载荷落地，网络规则不把会话句柄称为 TCP 已连接，也不作数据外传归因。`network.domainLower` 只接受 ASCII DNS 标签并移除一个尾点，不从 IP、URL 或未知 IDN 猜域名。

本次未增加任务 COM 方法采集、注册表值数据、全局 HKEY／文件句柄历史、进程枚举末尾名称、网络响应正文或跨事件链。它们没有伪字段或默认不可触发模板。规则按文件顺序首条命中，特定语义放在同类一般返回之前；缺字段比较保持 Unknown，失败不能被解释为痕迹不存在。
