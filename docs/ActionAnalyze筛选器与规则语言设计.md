# ActionAnalyze 筛选器与规则语言设计

下一层施工索引：[A2.1–A2.3](ActionAnalyze施工任务与契约落点.md)规定typed AST／校验／下推／规则准备／状态执行的owner与正负控；[规则来源转换清单](ActionAnalyze规则来源与转换施工清单.md)逐条件保留上游作用域／窗口／排除。本文语义继续为规范依据，机器schema／解析器／执行器尚未创建。

日期：2026-11-24。状态：首版实施建议，尚无parser、规则运行或性能结果。需求见[主规划](恶意行为单点追踪与调试能力规划.md)，字段与方法见[事件身份与协议](ActionAnalyze事件身份与协议契约.md)，文件封装见[存储设计](ActionAnalyze项目存储格式与恢复设计.md)，依赖排期见[开工总表](ActionAnalyze完整开工审查与实施总表.md)。三端业务独立，共同文档／语义向量不等于公共runtime。

## 1. 源码复用审查与避免的歧义

已核对两类Qt页面及Win32实现：

| 真实入口／源码 | 可复用事实 | 不能直接沿用 |
| --- | --- | --- |
| 监控→WinAPI→API覆盖／API事件；`WinAPIDock.Coverage.cpp`、`.Pipe.cpp`、`WinAPIFilterRules.h`、`WinAPIEventTableModel.cpp` | 模块／函数目录、不可变配置、有界导入／原子保存、后台筛选代次和事件ordinal | 前置是收包后归档前拒收，不改Hook、不等于调用前断点；无typed AST／三值／跨事件依赖 |
| 监控→ETW→简易／详细筛选；`MonitorDock.cpp` | 字段／阶段目录、组内AND／组间OR、原位校验、配置快照 | 缺数值先false后invert可能变true；文本token拆分／自动交换范围不适合严格DSL；接收过滤不等于provider pushdown |
| Light→监控→ETW；`Features/Monitor/EtwMonitorView.cpp`、`Ui/FilterBar.cpp`、`Ui/VirtualListView.cpp` | generation、owner-data、搜索防抖 | 坏正则回退contains不能进入新语言；std::regex与Qt正则不保证同方言／预算 |
| `UI/ParameterWorkspace`、`AsyncOperation`、`TableRowFilterSupport`、`TableSearchFilterSnapshot` | 编辑结构、异步值请求、当前模型增量投影 | 当前显示列文本搜索不能当规范字段规则或完整历史数据库 |

Qt旧模块caseFold与CLI ordinal-ignore-case、NUL及版本宽松解析存在接受域差异；旧配置必须显式转换成草稿并报告差异，不宣称天然全等。详细源码定位保存在 `.codex-build-logs/behavior-planning/action-analyze-preflight-filter-rules.md`；本轮没有改变旧页面行为。

## 2. 六类条件与默认行为

| 条件 | 输入与时机 | 默认／unknown | 可影响范围 |
| --- | --- | --- | --- |
| 显示筛选 | 已形成事件／语义／关系 | 默认全部；高级谓词只列true，unknown另计且可显式查看 | 视图／导出查询，不改变采集／分析／控制 |
| 采集过滤／记录范围 | 来源配置及本端接收记录 | 默认保留允许范围内全部；不能确定可丢则keep | 不可逆减采，标source或receiver实际层 |
| 传播发现策略 | 跨进程操作、生命周期、执行进入 | 必需发现持续，未知TID不关闭探针 | 候选纳入／准备下一跳，不自动恶意归因 |
| 同步断点 | 支持入口的调用前／执行进入快照 | true命中；unknown默认诊断不触发用户动作 | 有能力才停；必要准入unknown仍保持闸门 |
| 语义规则 | 规范原事件及有限窗口 | 新规则默认同线程实例，missing默认unknown＋覆盖提示 | 输出语义和证据；异步结果只申请后续暂停 |
| 输出订阅 | 已生成事件／状态 | 默认response/state/gap/summary，高频raw显式开 | 仅输出量与投影背压，不减采或丢控制状态 |

界面不用单独“前置／后置”称不同副作用。API/ETW可见按钮属于显示筛选，不停止采集。用户硬范围先限定采样的对象和来源；必要发现不授权偷偷扩大到全机。若异步补关联需要全机最小元数据，必须在计划中单列范围与预算并显式选择，默认不开。

记录保留条件为 `硬范围内 && (P || C)`，P是生命周期、句柄链、传播／探针、启用断点／规则依赖及控制／覆盖事实的并集，C是普通用户记录条件。硬排除与P冲突，默认拒绝应用并返回最小受影响闭包；可让用户明确关闭受影响能力后重新校验，不静默忽略排除、停用规则或扩大收集。普通显示条件不能隐藏必要控制错误。

## 3. 字段目录与三值逻辑

字段key、类型、来源、可用phase、单位、完整性、大小写、长度、隐私／采集上限、pushdown能力统一登记。`actor/target/header/observedOn`角色不混；`args.<name>`只使用精确API声明的参数，Raw槽位独立类型。eventId按协议采用sample＋本端ordinal，原source epoch/sequence单列，不凭它强造跨源因果。

基础类型为bool、i32/u32/i64/u64、地址、位掩码、状态域＋原码、时长、UTC／单调时刻、字符串、bytes、有限数组／记录、对象实例、IP／端口。暂不公共开放浮点比较；比例用显式缩放整数。参数／数组／缓冲区均是采集时快照，语言不隐式读目标指针或访问文件／网络。

值状态遵循协议的known/null/notCollected/unsupported/accessDenied/readFailed/truncated/decodeFailed/redacted，另以reason记录notApplicable/ambiguous/stale。未知fieldId在校验阶段报错，不当作普通缺值。

| 运算 | 结果 |
| --- | --- |
| `!U` | U |
| `F && U`／`T && U` | F／U |
| `T \|\| U`／`F \|\| U` | T／U |
| `U && U`／`U \|\| U` | U／U |
| unavailable参与普通比较 | U；不能先转false再invert |
| known零／空串／空数组 | 正常已知值，不是unknown |
| `x == null` | 已知null为T、已知非null为F、未采为U |

`isKnown(x)`、`isNull(x)`、`isComplete(x)`、`quality(x)`为显式总函数；isNull只问是否已知null，对未采为F。known-null为完整值；truncated可含已采前缀但不完整。`&&/||`左到右短路，静态检查所有分支。没有隐式`?? false`。

截断值：在已获前缀找到contains模式可T，没找到为U；完整相等／suffix依赖尾部，不能根据缺尾报F；已获前缀已经矛盾时相等可F。足够长的已获prefix匹配可T。空且完整集合Any=F、All=T；截断集合无匹配为U。计数下界足以达到`>=N`可给正向证据，仍附incomplete；`==N`、`<N`和absence必须完整覆盖／水位。

逐规则missing可选unknown＋notice、skip当前实例并记账、基于已知子证据输出明确候选；不得missing→确定事实。普通断点unknown也停可为显式选项，需停点资源准入，默认关闭；这不改变必要Ready失败时的hold。

## 4. 文本、路径、时间和数值

- 规范文本UTF-8，JSONL无BOM；文档文件导入可接受一个开头BOM后规范化。目标坏编码原bytes保留，decodeFailed，不能拿replacement字符作事实匹配。
- 字符串默认ordinal、区分大小写、不trim、不Unicode归一、不展开变量。支持普通`"..."`转义与C#风格`@"..."`双引号转义；不支持插值、未知escape、隐式多行拼接。字符串内NUL按长度保存，UI转义呈现。
- `Text.Contains/StartsWith/EndsWith/Equals`精确模式；显式`...AsciiIgnoreCase`首版仅ASCII，超域返回unsupported／U并诊断，不由Qt、CRT或OS各自折叠Unicode。后续完整Unicode profile须固定表版本与共同向量。
- `Text.Utf16Length`与`Bytes.Length`／`Text.Utf8ByteLength`明确单位，无含混Length；字符串截断时原始总长未知则长度unknown。
- 路径保留DOS／NT／UNC／长路径／注册表namespace。`Path.LexicalMatch`不访问文件、不解析reparse、不剥ADS／尾点、不擅自合并C盘与device路径。真实文件identity与词法匹配分开；HKCU保存SID、注册表视图保存WOW64。
- API模块裸名可按明确ASCII规则忽略大小写并补`.dll`；函数导出名敏感；有路径或其它扩展不擅自改写。模块文件／映射identity条件优先于文本同名。
- IP为family＋二进制地址＋scope，IPv4-mapped IPv6不默认等同，端口0有效；host规范化另列函数与版本，不套路径规则。
- 十进制默认，十六进制必须`0x`，u64等用显式后缀／构造；当前 `predicate-expr-v3` 另接受数字之间的 `_` 分隔符，以及大小写均可的 `UL`／`LU` 两字符无符号长整型后缀（例如 `1_000UL`、`0xFFFF_FFFFLU`），分隔符不能出现在数字首尾、连续出现或夹在后缀／空白旁。`u64` 旧写法继续保留；v1/v2 不开放新后缀和分隔符。类型不隐式窄化，溢出／除零为evaluation-error→U，常量错误校验即拒绝。地址使用`addr("0x...")`且带目标位宽／对象上下文。
- 时间范围统一`[start,end)`；`last(30s)`创建查询时固定anchor，follow才明确滑动。跨clockId无可靠校准比较为U；UTC展示顺序不替代因果。暂停时主机时间仍走，无事件不能直接得absence。

## 5. 有限C#风格表达式

当前产品实现为 `predicate-expr-v3`，具体范围以 [Rules 模块说明](../KswordCLI/ActionAnalyze/Rules/README.md)为准：有限 u64 算术、位运算、移位和字段间比较；加减乘按 unchecked u64 环绕，除零／余零为 Unknown 并附稳定故障码，未知值不视为零。显式读取 v1/v2 时保留原字段对常量准入，不开放 v3 语法。下方 checked 及扩展类型内容仍为后续设计，不能视为当前能力。

正文是唯一语义源，typed AST为编译产物，保存语义版本及规范AST hash，不同时维护两份可独立编辑的语义。JSON定义event selector／scope／window／actions等结构，`predicate`内放纯表达式。可视编辑器生成同一正文；无法无损回到简易模式时保留高级原文。

首版语法轮廓如下，词法／优先级在A0形成正式EBNF与向量：

```text
predicate := logicalOr
logicalOr := logicalAnd ( '||' logicalAnd )*
logicalAnd := bitOr ( '&&' bitOr )*
bitOr := bitXor ( '|' bitXor )*
bitXor := bitAnd ( '^' bitAnd )*
bitAnd := equality ( '&' equality )*
equality := relational ( ('==' | '!=') relational )*
relational := additive ( ('<' | '<=' | '>' | '>=') additive )*
additive := multiplicative ( ('+' | '-') multiplicative )*
multiplicative := unary ( ('*' | '/' | '%') unary )*
unary := ('!' | '-' | '~') unary | primary
primary := typedLiteral | fieldPath | whitelistCall | '(' predicate ')'
```

bit运算只整数，`&&/||`只bool／三值，不用布尔`&`混替。数值计算checked，时间与地址只开放明确定义且不溢出的组合。函数必须白名单纯函数，类型／工作量可算；`In`、有界`Any/All`可使用受限元素谓词，不允许任意lambda捕获、递归、赋值、循环、new、反射、程序集加载或外部脚本。

bytes literal为`hex"4D 5A 00 FF"`；模式为`hexPattern"48 8B ?? 01"`，仅整字节通配，不猜半字节。`Bytes.Slice(x,offset,length)`检查边界；decode显式UTF-8/UTF-16LE/BE或固定codepage，严格错误策略。字节扫描按实际扫描字节计费，不把任意大输入算一次操作。

### 5.1 正则方案

首版建议采用有界Thompson NFA的`aa-regex-v1`子集，准备阶段编译，运行按解码字节与状态推进计费；三端分别组织实现并验证共同向量，不新增公共runtime。支持字面、`.`、字符集／范围、非捕获分组、选择、绝对头尾锚点、`?*+{m,n}`；显式有界重复的上限256、编译态最多2048，`*`／`+`由有界输入及运行预算约束。拒绝反向引用、lookaround、递归、条件组、捕获结果、任意回溯／平台专有选项；超profile为prepare错误，不能移交系统regex尝试。

模式显式区分Text.Regex与Bytes.Regex：Text严格按Unicode标量、不归一；Bytes按0–255字节，不能把坏UTF-8强转文本。`.`在Text排除CR和LF，在Bytes排除0x0d/0x0a；`^/$`只匹配完整输入头／尾，不隐含多行或尾换行特例。`\d/\w/\s`统一ASCII集合，分别为0–9、A–Z/a–z/0–9/_、HT/LF/VT/FF/CR/空格；大小写默认敏感，显式ASCII-ignore-case仅折叠ASCII。首版拒Unicode属性类和地区化选项，不依赖OS／Qt Unicode表。普通Regex是搜索是否存在匹配，FullRegex才要求整串；布尔结果无贪婪捕获语义。截断输入上找到无需未知尾部的完整匹配可T，未找到或结果依赖`$`则U；空模式可匹配空串，但不能证明未采值。

同步入口首版不开放正则；后台与查询只有能证明确定工作量边界的profile才启用。不得临时调用不限时QRegularExpression/std::wregex代替，不支持的上游pattern保留needs_semantics，不改成contains后称等价。此为选型建议，实际NFA实现及性能尚未存在。

## 6. 阶段分型与两层执行

| 能力 | 同步入口 | 后台语义／查询 |
| --- | --- | --- |
| 已捕获标量／identity／bitmask | 按精确入口能力可用 | 可用 |
| 有界已捕获string/bytes | 校验最坏工作量后可用 | 按预算读归档／快照 |
| return/out/actualWritten | entry禁止；只能对应return/complete阶段 | 依字段实际来源 |
| regex／count／distinct／sequence | 首版禁止 | 有界profile／状态处理 |
| 符号／签名／内容扫描 | 禁止 | 独立任务，附查询时间和版本 |
| pause/dump/network等动作 | 谓词不执行，由协调者按命中请求 | 独立动作计划；历史禁止副作用 |

计划 prepare 把同步白名单编成固定操作、常量和字段绑定，并校验同一入口和阶段的全部候选累计成本。真实执行位置按 API Hook 与所选后端的能力报告。R0 固定入口只接受已验证的形式。未知阶段、字段、读取方式或超预算计划在准备时拒绝。同步命中进入登记站点后交由外部所有者接管。[同步断点专项](ActionAnalyze同步全局断点与性能复查.md)

## 7. 计数、序列、匹配身份与依赖闭包

新stateful规则默认scope=threadInstance、窗口30秒、ordered non-adjacent（允许中间事件），不自动声称因果；上游自带scope/window/order原样保存，不用默认覆盖。规则至少包含selector、predicate、scope key、window、join bindings、order、threshold、missing、evidence policy及budget。

窗口默认使用声明clockId的事件时间；时间不可比较则该实例为U／候选，不能换用收包时间后称原规则命中。一次序列的首末时间满足`last-first<=window`且有独立顺序证据，边界可等；滑动计数由当前锚事件触发，覆盖`[anchor-window,anchor]`并包含该锚事件。这个计数定义与历史时间查询的`[start,end)`分开登记。规则文件须显式存timeBasis/windowBoundary，转换上游时保留原语义。处理超窗／缺口导致不完整的实例记录原因，按已声明事件水位正常过期；水位不推进时仍受容量／年龄预算限制，淘汰只产生incomplete，不产生“没有发生”的结论。

计数明确CountEvents／CountCalls／CountDistinct；entry/return/complete不默认算三次call。相同源重复运输按事件identity去重，跨源无明确operation因果时只叫observation数量。distinct缺键单独unknown，不与null／空串合桶，不凑阈值。

sequence使用明确顺序边，cooccurrence不要求先后；同源发布序号的真实保证先登记，跨源凭call／operation／显式因果或有证明的时间区间，不能按收包排序补造。步骤绑定如`a.target.process == b.actor.process`、实际写区间、mapping/contentVersion必须明定，不能只因同TID／同VA就串起来。

匹配建议all bounded matches：一个事件可参与多候选；同rule/version/scope/步骤eventId元组去重，不隐式greedy消费。每个behavior instance有独立ID、输入引用及analysisRun，按ruleId的显示汇总是投影，不将所有对象／版本合成一条事实。超状态预算标incomplete，不偷偷换匹配算法。

依赖闭包包括引用规则、列表／宏／lookup hash、selector、字段／phase、生命周期、句柄链、结果／完成事件、clock与排除条件；循环／未知引用／未冻结外部表拒绝prepare。先按event type/API/field索引候选，不逐事件扫全部601候选。目录全量可浏览，运行只装启用且满足能力的闭包。

规则包采样时冻结；编辑为项目草稿。本期不提供运行规则包热替换入口；历史／现有输入的独立analysisRun可重算，不能补造过去未采字段或执行原动作。断点显式apply是已有独立需求，不与延期的样本热重载混称。

[缺口G13](ActionAnalyze规划缺口复查与补齐任务.md)补充否定窗口的定案：依赖源没有覆盖证明／有效水位时，absence及尚依赖未知尾部的精确计数结论保留U；source静默、超时、退出或archive sealed均不能独立证明完整。迟到后以新analysisRun或派生修订／supersedes表达变化，原命中与动作历史保留，不能重放控制。三端比较同固定输入／水位／规则／预算的结果及依据集合，不拿随机ID或展示到达顺序充当语义差异。

## 8. 保守源端下推

目标保留集合为硬范围内P∨C；下推Q必须是该集合的保守超集，需要保留的T或U不能被源排掉。本端保留residual做最终精确判断。无法证明则不下推。

- 首版仅对已证明角色／phase等价的source kind、provider/event、精确API、绑定实例集合及有限数值条件下推。ETW header PID不等于target PID，不能自动映射。
- `A&&B`可只下推安全必要条件A；`A||B`若B不可表达，Q=true；NOT、缺值、转换／路径／regex默认不下推。
- 未知字段／版本不当false；协议／身份坏包仍拒绝，keep-unknown不授权接受伪数据。
- 扩范围先部署新超集并回读effectiveRevision／Ready再放行；缩范围先确认在途旧调用和依赖退役再撤旧条件。无法原子变更就保留旧宽集合或拒绝，不能短暂关完再开后称无缝。
- explain输出requested/effective范围、P及消费者、Q/residual、不可下推原因、受影响规则、实际生效层与配置hash。suppression与传输gap分开，没有计数能力报unknown。

发现未知worker、B→C的最小来源不受“只采A PID／已知TID”的完整日志过滤限制；范围仍不超用户明确计划。扩展到正常宿主仅标候选／策略跟随。

## 9. 实时／历史查询、聚合与分页

默认query为单sample固定已提交归档快照，绑定queryHash、sample、analysis/enrichment revision、字段目录、anchor、排序、archive/index水位与indexGeneration。当前内存窗口另标window；包含未落盘尾部时返回archivedThrough/observedThrough及provisional，按eventId合并不双计。

运算顺序：`snapshot → WHERE → 可选GROUP/aggregate → HAVING → stable ORDER → page`。LIMIT是输出页大小，scanLimit是输入预算，两者分开；未扫完返回partial／progress／continuation，不报精确全量total。字段无索引可做显式慢扫描，不把无索引说字段unknown。

语义视图先查已生成behavior instances再做显示条件，不能先筛原事件后重跑语义。时间选区对原事件为落入，对语义默认区间overlap（first<end且last>=start）；选区外依据保留可展开。历史重分析扩读完整前置窗口和依赖，输出范围明确，不将10秒选区静默变成原30秒规则窗口。

稳定keyset cursor包含最后排序键／ID，固定快照跨页不漏不重。默认page500、max2000，与协议统一并受256 KiB输出硬帧限制；宽字段引用／分段，少于pageSize不等于结束，hasMore/nextCursor显式。默认展示时间排序、unknown独立区、eventId tie-breaker，只称展示顺序。

cursor首版采用`aa1.<base64url(aa-cjson-v1正文)>.<base64url(HMAC-SHA256)>`，无padding，总长不超过4 KiB；正文含queryId、固定输入／版本／水位hash、indexGeneration、排序／最后键及本控制器lease代次。HMAC密钥为控制器启动时生成的32字节随机数，只在内存，不写项目／包／日志；使用系统密码API，不自行实现密码算法。它用于拒绝篡改，内容不保密。idle lease60秒、有效读取时续期；使用本控制器单调时钟，控制器重启、租约失效、查询取消、indexGeneration改变后明确staleCursor，不能隐式从当前数据继续。只读查询可另存query定义重新执行，不承诺游标跨端／跨程序续页。

默认比较为known值升序、unknown最后且保留各quality，不在unknown之间造数值大小；降序仍把unknown放末尾。已知null单列在known非null之后、unknown之前，反向排序只反转可比较的known值；必要时用户显式选择unknown-first。默认时序用可比较的校准时间区间及eventId稳定打破平局，仍不作为因果证据。

CountEvents/Calls/Distinct、behavior instanceCount、displayedRows、evidenceCount、suppressed/lost/windowEvicted各自计账。近似聚合首版不开；追加聚合用稳定instanceId＋revision的upsert/retract，不暗改旧快照页。

follow为独立订阅，默认不补全历史；分页→实时交接必须先建tail边界再固定snapshot并去重，否则明示gap。取消query不停止采集，清空显示不删归档，导出明确选中／当前筛选／全部已归档范围与水位。图的上下文祖先不计命中数，隐藏节点不改控制对象。

## 10. 文件、错误与UI一致性

文档kind分别为view-filter/capture-plan/discovery-plan/breakpoint/semantic-rule/subscription，版本含表达式语义／字段目录hash；不能把display条件当同步breakpoint。独立文件建议`.aafilter.json`与`.aarules.json`，扩展名仅选择器，实际按kind/version解析。原文件hash与规范typed AST语义hash分开；规范序列化采用[协议§2.1](ActionAnalyze事件身份与协议契约.md#21-规范序列化与hash)的`aa-cjson-v1`，A0补机器向量，不按pretty-print字节猜语义一致。

顶层和关键语义闭集键，严格UTF-8／重复键／溢出／未知字段／operator／stage校验。错误包含errorId、UTF-8字节范围＋行列、实际／要求类型与phase、affectedRules、能力、desired/effective revision；UI与CLI同标识，不让AI猜本地化文本。

旧WinAPI v1/v2／ETW配置只导入草稿，报告大小写、bool invert／缺失、时间边界、模块例外和token差异；不改原文件、不自动应用。简易编辑、表达式、REPL/JSONL映射相同typed语义；校验失败保留旧effective和新草稿，防抖只读预览不提交采集控制。

编辑器ParameterWorkspace＋CodeEditorWidget，目录／管理表None，结果表Compact＋互补列组，详情同StructuredFieldView。六域编辑不再塞入12项调试工具栏。UI入口／共享结构及后台登记见总表；真实GUI尚未实施／验收。

## 11. 初始资源限制与超限

以下按总表统一为可调原型初值，非实测SLO。预算保存到每采样实际配置；按count/byte/age先到限者执行。

| 项目 | 初值建议 | 达限 |
| --- | --- | --- |
| 单谓词 | UTF-8 8 KiB，AST512节点／深度32 | prepare拒绝，旧版继续 |
| 同步谓词 | AST128节点、4096计费操作、预捕获string/bytes合计4 KiB | 预验最坏工作量；运行超限U＋诊断，必要准入另按hold |
| 后台谓词 | 65536计费操作、单值扫描64 KiB | U＋budget；大内容转job |
| regex | pattern1024 bytes、input64 KiB、NFA2048态，扫描／状态推进计费 | 不支持／超限明确，绝不无界回溯 |
| stateful | 默认30秒、准入上限1小时；每键256、每规则4096部分匹配 | 不缩窗口、不换greedy，受影响incomplete |
| 规则状态 | 单规则4 MiB、启用集合总64 MiB | 先正常过期；容量淘汰与正常过期分账，不影响控制责任 |
| 准备闭包 | 最多4096规则／100000依赖边；编译总8 MiB | 拒绝待应用版本；目录仍可分页浏览 |
| 文件导入 | 单规则1 MiB，单文档4 MiB | 拒绝，不部分应用 |
| 查询／UI | page500/max2000、整工作台每轮4ms目标、150ms只读预览防抖 | 单在途／最新代次；扫描分批／job，不把批次当全量 |
| raw订阅 | 默认关闭，显式开启建议1000条/秒＋1 MiB/秒 | 输出层gap／汇总，不回压恢复或静默减采 |

计费包含扫描字节、容器、key、候选、引用与临时值，不只payload。4096操作不等于固定微秒；性能公开阈值必须三端测量。

## 12. 示例与验收

以下为设计语法，精确字段须按来源目录绑定，不是现有可执行规则：

```csharp
api.id == apiRef("Kernel32.dll", "WriteProcessMemory")
    && args.RequestedLength >= 4_096UL
    && target.process != actor.process
    && Bytes.StartsWith(args.BufferSnapshot, hex"4D 5A")
```

该predicate只适用有真实入口快照的call-enter，禁止引用actualWritten／return。没有BufferSnapshot或目标实例时U，不隐式读内存。动作另配，实际后端能力不足不假称已拦。

```csharp
!Text.Contains(args.PathSnapshot, "sandbox")
```

截断前缀没找到sandbox为U，不确定匹配“没有sandbox”。已获前缀找到则contains=T、否定F。

序列示例：a=write.completed且实际写入>0，b=execution.enter-attempt；显式绑定a.target.process=b.actor.process、实际成功范围、mapping/contentVersion和窗口。线程创建日志不能替代execution.enter；版本缺失仅候选。计数VM注册表线索只表示多项探测尝试，不表示VM存在／规避成功。

实现顺序：字段／阶段／真值向量→parser/validator/explain→单事件evaluator与同步白名单→依赖／pushdown→count/sequence/watermark→历史query→UI/CLI接入。测试必须含全T/F/U表、截断否定、Unicode/NUL/编码、溢出、PID/TID/VA／句柄复用、OR下推负控、快速下一跳、源暂停时absence、count与page不混、历史不触发动作、错误regex不回退、预算失败不改旧effective。

三端用相同黄金向量但分别报告实际能力／结果；当前仅完成设计与源码审阅，没有这些产品测试结果。
