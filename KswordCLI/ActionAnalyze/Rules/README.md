# 条件与 API 观察预置

`PreparePredicateExpression(source, phase, catalog)` 用当前 `predicate-expr-v3` 准备新条件。读取冻结配置时使用四参数重载，传入配置保存的 profile；`IsSupportedPredicateExpressionProfile()` 判断版本是否已登记，不能把任意旧版本重标成当前版本再解析。

| Profile | 实际准入 |
| --- | --- |
| `predicate-expr-v1` | 原字段对显式常量比较、布尔组合、括号、文本函数、`isNull/isComplete`。 |
| `predicate-expr-v2` | v1 加 `isKnown` 和 `quality(field) ==/!= "规范质量名"`。 |
| `predicate-expr-v3` | v2 加有限 u64 数值子树和字段对字段比较。 |

v1/v2 保留原解析路径：拒绝数值算术、位操作、数值括号和字段对字段比较。v1 拒绝 v2 的质量函数。旧 JSON `FieldTest` 继续调用原 `PreparePredicate()`。

v3 数值常量为十进制或 `0x` 十六进制，必须带 `u64` 后缀。优先级从高到低为 `! ~ +`、`* / %`、`+ -`、`<< >>`、关系比较、相等比较、`&`、`^`、`|`、`&&`、`||`。二元操作左结合；位运算只接受 u64，因此 `(mask & 1u64) != 0u64` 必须明确括号。没有赋值、自增自减、用户函数、对象方法、指针读取或正则执行。

加减乘按 unchecked u64 环绕，右移为无符号右移，移位计数只取低六位。不支持一元负号。字面量越界在准备阶段拒绝。未知操作数传播未知；已求值的零除数使结果为 `Unknown + DivisionByZero`，稳定 ID 为 `division-by-zero`。`&&/||` 按三值逻辑从左到右短路，未进入的分支不产生算术故障。所有新数值节点受 512 节点、32 深度和运行计费预算限制。

主程序“监控 → 行为分析 → 行为规则草稿”使用相同解析器。草稿顶层可显式设置 `expressionProfile`；未设置时按 v2 读取，新的内置草稿明确使用 v3。字段类型从 `BehaviorRuleFields()` 取得；合成草稿输入和归档预置字段分别列出，不把 API 字段冒充合成事件输入。

`profiles/action_analyze_api_rules.json` 保留 `schemaVersion:1`，新增可选 `expressionProfile`；旧文件省略时为 v2。结构见 [API 预置 schema](../../../schemas/action_analyze/api-rule-presets.schema.json)。数据库仍冻结实际读取字节的 SHA-256，修改文件不替换已加载采样的准备结果。

`BehaviorPresetFields.cpp/.h` 是规则专用投影，不建立跨事件候选链。`ReadApiPresetEvidence()` 调用专用协议严格读侧与普通强类型返回读侧；`ProjectApiPresetFields()` 只发布有效位、精确返回或通过严格 formatter 格式核对的字段。全部字段处于归档观察阶段；`evidence.phase == "return"` 只由通过返回核验的协议产生。缺字段为 `NotCollected`，不回填零、不做 raw substring 匹配、不解引用请求指针。API 报告的身份与返回不认证历史生产者，也不授予活控制权。

自有词条包括内存／线程八类、注册表查询／写入、进程枚举、模块／系统查询、进程创建、文件打开／复制／写入、服务管理、名称解析／网络会话／HTTP 请求。具体条件及双语释义以外置配置为准。AAIM1／AAAP1／AACT1／AASM1 仍按独立协议投影；跨进程词条要求双方创建代次、目标稳定和不同 PID，APC/context 还要求目标线程代次。所有词条由 KSword 自行编写，未复制第三方规则或修改原有许可。

目录与加载使用同一配置和字段目录，CLI `api-rule-catalog` 同时给出兼容 `fields` 列表及 `typedFields`；Qt／Light 回放只把既有归档行已核验的协议值交给相同准备结果。无返回证据的包只分类，不生成返回层级释义。

普通强类型参数由 `ApiBehaviorObservation.cpp/.h` 消费已有采集格式，而非执行上游脚本。读侧要求同模块、精确 API、类别、Strong、非零源会话、显式返回标记，并按 API 分别解释 BOOL／HANDLE／LSTATUS／NTSTATUS／GetAddrInfo 返回。`StatusUnknown` 不发布错误码；GetAddrInfo 的错误来自函数返回，不能把包装器残留的 WSA LastError 当成原因。返回字段可独立存在，参数无效不回填假值。

原通用包的文本没有独立完整性位。本读侧仅接受具名字段完整布局，文本必须有已核验后继字段，生成包装器还须有签名对应的完整 `arg1...argN` 十六进制尾部。满缓冲、无终止符、可见不可读标记、非法 UTF-16、控制字符、文本中的 `=` 等歧义分隔使参数不发布。ANSI formatter 未归档代码页，仅接受 ASCII；W 版用严格 UTF-16 转 UTF-8。配置缩短摘要导致缺尾时，返回事实仍可保留，缺参数的规则为 Unknown。没有把 NUL 结束等同于独立的完整性有效位，也未给末尾无分隔文本创建类型字段。这里的 Known 表示按已登记 formatter 语法解码成功，不是独立采集完整性认证：配置截断可能落在最终数字中；恶意输入若伪造后继布局且真正尾部又被剪掉，旧包无法与完整布局区分。当前不发布最终尾数字作为业务字段，也不据此声称采集文本在对抗输入下完整可信；需要独立长度或完整性协议才能关闭该边界。

`registry.path`/`registry.pathLower` 仅来自 RegOpenKey 的明确 HKLM/HKCU 根，或 RegGetValue／RegSetKeyValue 的预定义根 HKEY 加子键。普通句柄不查当前系统、不做历史映射。`*Lower` 仅折叠 ASCII 大写，不变换斜杠、不展开环境变量、不删除 `..`；目录里的 ASCII 键路径可用精确相等或明确分支前缀匹配。无名默认值当前不投影为已知空字符串。`registry.valueNameLower` 同样按 ASCII 大小写匹配。RegSetValueEx 虽有值名，但没有键路径，不能命中 Run 键规则。

默认行为覆盖虚拟化软件／服务／ACPI 键查询的成功与拒绝、精确隔离模块查询、来宾服务打开、进程／模块枚举和指定系统信息类查询；所有环境规则只称探测线索。启动配置包括 Run／RunOnce、Winlogon、AppInit；服务与任务包括服务 ImagePath、TaskCache 分支写入、服务创建／启动请求／配置修改／标记删除，以及应用参数名为 schtasks.exe 的进程创建。后者不证明任务注册；文件规则不把打开句柄称为载荷落地，网络规则不把会话句柄称为 TCP 已连接，也不作数据外传归因。`network.domainLower` 只接受 ASCII DNS 标签并移除一个尾点，不从 IP、URL 或未知 IDN 猜域名。

本次未增加任务 COM 方法采集、注册表值数据、全局 HKEY／文件句柄历史、进程枚举末尾名称、网络响应正文或跨事件链。它们没有伪字段或默认不可触发模板。规则按文件顺序首条命中，特定语义放在同类一般返回之前；缺字段比较保持 Unknown，失败不能被解释为痕迹不存在。
