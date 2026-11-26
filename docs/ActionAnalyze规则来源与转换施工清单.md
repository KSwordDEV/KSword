# ActionAnalyze 规则来源与转换施工清单

后续[缺口G09／G11–G14](ActionAnalyze规划缺口复查与补齐任务.md)补齐入口快照／中介执行／CLR版本、absence定案与分析器真实入口。来源目录或规则标题存在不代表这些字段／运行能力存在；转换时逐条件沿用缺字段与不支持状态，禁止借推断扩大同线程作用域或将小型内容扫描子集称完整YARA。

日期：2026-11-24。状态：规划与来源目录资料，未实现转换器、IR解释器或规则运行。本文把[模板来源规划](行为语义规则模板收集与并入规划.md)的W0–W8落实到可逐条审查的输入输出，关联[施工任务A2](ActionAnalyze施工任务与契约落点.md)。不复制执行上游Python、SPL、任意C#或响应脚本。

## 1. 明确来源和更合适的组合方案

建议采用**KSword自有证据语义＋可审查的声明式规则IR＋开发期上游转换**。区域版本、实际执行线程、停止责任和直接传播边来自已验证的采集／控制事实，不能由第三方规则库提供；上游规则主要补行为解释、关联条件、良性排除和内容识别。规则命中后可请求后续控制，不能倒造早先同步拦截。

同步调用前谓词和跨事件语义处理共用有类型字段／有限表达式约定，使用不同阶段白名单和预算。自有语义默认同线程；导入规则保留原关联键、作用域、窗口、顺序及排除。规则包在采样开始时冻结；已提交输入可以新建analysisRun，不热替换活采样。

这比“先移植601条JSON或执行CAPE Python”更适合现有C++三端：能保留字段缺失和证据边界、控制准备与运行资源、逐条件说明非等价处，也不要求三端引入相同语言runtime。但有限IR不保证表达任意上游语言；超出能力的候选保留needs-semantics，不能删条件凑支持数。

| 来源／固定版本入口 | 采用角色及优先级 | 进入转换前必须满足 |
| --- | --- | --- |
| 自有机制语义 | 核心：写入尝试／成功、区域版本、进入／执行、直接／候选传播、真实保护失败 | 真实来源、阶段与身份；不把“脏区”或恶意标签当检测事实 |
| [capa动态规则](https://github.com/mandiant/capa-rules/tree/ffd03fc584e87fed57ddf225c8ab3cd0345dc8cf) | 优先：API／字符串／数值能力、依赖规则；span是无序共现 | dynamic scope可用、完整依赖闭包；不将静态指令特征改成API名文本匹配 |
| [Sigma](https://github.com/SigmaHQ/sigma/tree/7228cccddc63a771924ab585e072f4fbb63690fb) | 优先：Windows事件、路径／命令行、明确排除；correlation单独适配 | logsource和动作等价、字段来源足够、DRL通知；不虚构Sysmon EventID |
| [Fibratus](https://github.com/rabbitstack/fibratus/tree/0d2cb65b379673542da6ff35992f81fa603fe5a1/rules) | 优先关联参考：序列、进程实例、目标绑定、宏列表 | 原window/by与跨事件绑定保留，符号／信任／富化依赖闭合 |
| [Splunk](https://github.com/splunk/security_content/tree/689e177da0c31da9154b51d3dbdd2af40462a03c/detections) | 第二层：端点行为、统计和良性过滤 | SPL／CIM／macro／lookup／基线逐条展开；没有通用SPL执行器 |
| [Elastic端点行为](https://github.com/elastic/protections-artifacts/tree/418cfd9aaa89ffc4b6a55e3d01c384facf4fd548/behavior)与[SIEM规则](https://github.com/elastic/detection-rules/tree/8bbc8b1b5aa674196ff7c7588f311cfac457ee4e/rules) | 直接API与EQL序列的高价值参考；是否复制发行逐条审查ELv2 | 事件时栈、签名、provenance及全部排除真实可采；两个来源／后端类型分开 |
| [CAPE](https://github.com/CAPESandbox/community/tree/1844e971751eddafcab28f42108ee82f39706171/modules/signatures)／[Cuckoo](https://github.com/cuckoosandbox/community/tree/14864b9fa2ba2576ca11887caf37616eaec6d941/modules/signatures) | 沙箱API语义与历史差异参考，人工提炼有限状态 | 逐类／helper／report依赖与逐文件许可；已读7个CAPE文件GPL头不能推广全库；不运行Python |
| [signature-base](https://github.com/Neo23x0/signature-base/tree/fffcaa4d3931d791a2553f01457966144418a316/yara) | 独立内容扫描证据层，不作为API时序规则 | 逐rule／include／module／external变量与许可例外；内容命中不叫实际执行 |
| 本地`../KswordSandbox`，固定`79525023f5c0373a6d31bbca896db2db9b7be5f4` | 601条候选覆盖清单和业务分类参考 | 无LICENSE及逐规则出处，当前阻塞复制发行；组合字符串必须追查真正输入生产链 |

优先级决定转换与字段施工顺序，不删其它候选、不预设30–50条上限。来源许可事实与发行兼容审查分开，开发期研究不等于已获再分发授权；对DRL来源的作者／出处随命中详情和导出保存，对其它来源按实际通知义务保留。

## 2. 本轮可审查资料与未完成部分

`source-lock.json` 固定 9 个上游与本地源。上游索引登记 9 棵固定树的所有 blob，并按路径保守标记候选文件。原 `upstream-files.jsonl` 的等价内容由分片清单和对应 JSONL 文件提供。`local-candidates.jsonl` 按 JSON Pointer 登记 601 条候选的索引，`license-evidence/` 保存已读包级许可原字节及 hash，`inventory-check.json` 保存资料计数与校验。[规划资料](action-analyze-planning/README.md) · [上游文件分片清单](action-analyze-planning/upstream-files/manifest.json)

文件目录特意保留非Windows规则／依赖文件，先标候选，再判平台，不因当前Windows支持丢掉类别。仓库完整树是文件边界，不是规则边界：YAML可多文档、Python可多Signature类、YARA可多rule，目录内也有helper／示例／测试。**上游规则总数、逐规则语义及许可例外仍未完成**；树条目里的Git blob SHA不是文件SHA-256，正文未采时`bodySha256=null`，不虚填。

当前资料不能载入产品作为规则包。9个固定SHA沿用原研究基线，不自动追HEAD；路径选择仅是保守候选分类，全树保留供后续复核漏选。网络失败、API截断、gitlink／symlink、LFS指针及外部依赖必须在采集报告单列，树“完整”也不证明这些外部正文已闭合。

## 3. W0–W8下一层任务

| 任务 | 明确输入 | 独立产物及文件建议 | 错误／恢复与完成条件 |
| --- | --- | --- | --- |
| W0.1 来源锁核验 | 固定repo/commit、包级许可、原研究 | 本轮R:`source-lock.json`、许可原字节／SHA | SHA不可达／license未知保留阻塞；不能换HEAD；源码平台API的license标签不能覆盖正文 |
| W0.2 正文采集 | 每树条目、Git mode、路径及字节预算 | 开发期`source-files.jsonl`：原字节SHA-256、大小、固定URL、采集状态；纯数据缓存 | 短响应／429／404逐文件pending；限额拒绝记录；不开上游安装器／脚本，LFS内容独立核验 |
| W1.1 规则枚举 | 已核hash正文及格式白名单 | `candidate-manifest.jsonl`：每文档／类／rule的稳定candidateId、文件内定位和原身份 | YAML安全模式、重复键拒绝、TOML版本明确；Python只AST／文本、无import/exec；不能识别语法即parse-failed，不以空数组算零规则 |
| W1.2 全类别与去重 | 全候选、helper／宏／include／lookup | `dependency-edges.jsonl`、类别与平台覆盖报告、来源alias | 依赖循环／缺失／动态生成保持unknown；相似标题不合并排除差异，abstract类／helper不计可运行规则 |
| W1.3 逐文件许可 | 原LICENSE/NOTICE、目录覆盖、文件头／元数据 | `license-review.jsonl`：每候选适用依据、例外、署名和发行阻塞 | 无法确认许可不补默认；GPL／ELv2／DRL按具体复制或衍生方式评估，未闭合不发行 |
| W2.1 字段矩阵 | 原始选择条件及当前三端真实来源 | `rule-field-map.jsonl`：规则×字段×端×来源／阶段／质量／依赖 | 每字段available／needs-capture／needs-enrichment／unsupported／unknown；配置已启用不当真实可采 |
| W2.2 采集补齐任务 | 缺字段清单、上游排除／状态依赖 | 映射到A5具体adapter／结构字段／阶段及验证case，不先弱化规则 | 实际返回数据／句柄代次／事件时栈无法取得则阻塞；若另建弱规则，独立KSword ID及差异 |
| W3.1 条件对照 | 完整选择／排除、scope、window、sequence、lookup | `conversion-map.jsonl`：每源节点→IR节点、值类型、转换理由、等价级别 | 精确／有限子集／派生／不可表达分开；未知函数不忽略，源条件不能成为不可回查文本 |
| W3.2 IR与profile | typed AST、三值、正则profile、依赖／预算 | A0产品`rule.schema.json`＋operator profile与正反例索引；本轮未生成 | 正则语义／大小写／路径归一化有差异则报needs-semantics；不改上游窗口以适应内存预算 |
| W4.1 准备及候选索引 | 许可／语义准入的启用规则及闭包 | 各端`RuleCompiler/RuleDependencyIndex`、PreparedRuleSet和逐条拒绝报告 | 全库只读浏览不全编译；prepare取消／超限不替换已冻结集合；缺依赖不部分启用 |
| W4.2 有界执行 | PreparedRuleSet、typed原事件、水位与gap | 各端`SemanticProcessor/RuleStateStore`：命中、证据引用、状态字节及incomplete | 正常窗口过期与资源淘汰分开；unknown不触发肯定动作；同步谓词不等语义／符号／磁盘 |
| W5.1 结果投影 | behavior、原依据、来源署名、analysisRun | 默认语义行、证据分页、缺口／许可／差异详情；沿用A9共享框架 | 图／表／导出同ID；UI聚合不替代原始证据，隐藏不停止采样 |
| W6.1 原事件向量 | 独立已知事实源、同线程／同对象约束及反例 | `rule-tests.jsonl`引用原包／规范事件、预期／禁止结论、真实来源证据 | 预填`api.sequence`只验预计算输入；不得计为原事件关联通过；缺事件／乱序负控不可删 |
| W6.2 真实良性回放 | 自有良性程序与许可允许的固定测试数据 | 逐规则TP／负控／管理软件噪声报告、三端解释一致性 | 误报标签和未支持字段公开；规则上游test状态不等本产品validated |
| W7.1 资源与故障 | 冻结规则集、事件流、预算、慢盘／丢失条件 | A10分位数／状态峰值／淘汰／回落报告，按规则归因高开销 | 预算达限incomplete，不将丢失后无命中算真阴性；不按目录数量许诺吞吐 |
| W8.1 发行包 | 全部通过的候选、许可文本／署名／变更说明 | 产品manifest／包hash／NOTICE、端能力矩阵及完整候选状态索引 | 只打包releasable子集；来源文件更新导致条件／许可变化即重新准入；活采样不热改 |

采集脚本属于开发期工具，文件名在实施时登记，不成为产品自动联网更新器。本轮只实现来源目录资料的生成，不实现W0.2以后的正文全集采集或产品转换流程。

## 4. 每条规则的审查记录

| 记录部分 | 必须可回答的问题 |
| --- | --- |
| 来源与身份 | 来自哪个固定commit、哪个文件、哪文档／类／rule？原正文SHA-256是什么？原始ID与KSword派生ID是什么？ |
| 原义与目的 | 观察尝试、返回成功、静态内容、无序共现、有序行为还是统计异常？允许输出到什么证据强度？ |
| 正向与排除 | 每个选择、not、filter、例外、状态／返回值条件映射到哪里？缺排除字段时是否必须Unknown？ |
| 关联约束 | 同线程／进程／目标／对象／地址／句柄代次怎样绑定？上游窗口、顺序和结束条件是什么？ |
| 依赖与输入 | 引用规则／宏／列表／基线／符号／签名由谁产生？原生、导入、富化或合成？何时有效？ |
| 转换与限制 | 完全等价、受支持子集还是另立派生规则？未表达处和三端能力是什么？ |
| 动作与资源 | 仅输出语义还是允许请求暂停／调查？动作白名单／冷却、状态／证据／耗时预算是多少？ |
| 许可与验证 | 作者、原通知、例外及发行依据？原事件正例／负例／缺失／实例重用／良性回放证据是什么？ |

审查维度独立保存，例如同一规则可同时`license-pending + needs-fields + needs-semantics`；validated及releasable是另外两个维度。转换器成功输出JSON，只能计converted，不能算规则已正确工作。

## 5. 三端字段施工矩阵的首张审查表

以下是**字段施工任务**，不是逐规则全部矩阵，也不表示任一端已接通新引擎。Q/W/C均须从各端真实adapter取证；共用旧低层代码不自动将能力复制到三端。

| 语义族 | 不可省的输入／关联 | 当前已核对缺口 | 对应任务与负控 |
| --- | --- | --- | --- |
| VM注册表线索探测 | open/query、完整路径、hive/view、源线程；尝试与读取成功分开 | R0 Pre事件能提供尝试；R3新HKEY／返回内容链不完整 | A5.1/2、W2；查询不存在键仍可能探测，正常清单软件不直接判恶意 |
| 返回的VM标识／反调试结果 | 精确API／属性、成功状态、输出类型／实际值 | EntryOnly及缓冲区指针不足，WMI方法来源尚为候选 | A5.1/3；失败不读未初始化输出，环境干预值不能当真实硬件 |
| Run等持久化修改 | 实际写、值路径／类型／正文／成功、文件身份 | 现RegSet摘要不复制dataPointer，R0现回调也无正文 | A5.1/2；读取不当写，命令相似但文件不同不拼落地链 |
| 跨进程内存写／执行 | 源目标强实例、句柄代次、实际写范围、区域版本、X证据 | WPM具部分字段，强身份及全路径来源、执行探针待补 | A5/A6/A7；部分写／失败／创建未执行、direct syscall及共享store负控 |
| capa动态能力 | call/span/thread/process、API／值／字符串与依赖规则 | 当前日志不是现成capa动态报告；span精确窗口语义须适配 | A2.2/3；乱序call仍可满足无序规则，不能当有序链 |
| Fibratus注入序列 | 远程线程目标与image-load进程绑定、原1m窗口、符号／信任宏 | 事件时符号、信任来源和跨事件强实例未闭合 | A5/A2；目标不同、窗口超界、缺排除字段均不得照常命中 |
| PowerShell | 解释器身份、ScriptBlockId、正文分片、完成／截断、命令行 | Provider预设不证明正文已采；命令行不替代脚本块 | A5.3；同脚本ID跨进程／重复片段、漏片、只有EncodedCommand线索 |
| WMI持久化 | consumer/filter/binding实例、命名空间、command template及操作结果 | 不能由普通registry路径或ExecQuery字符串补齐对象链 | A5.3；只有查询不得称创建持久化；方法Hook与ETW各列覆盖 |
| DNS／HTTP／网络周期 | DNS结果、连接／请求代次、方向、完成字节及统计覆盖时段 | 现有主机／方法／长度不等于正文或周期／jitter | A5.3/A2.3；短窗口／连接重用／未采握手不当无SNI |
| Elastic API及防护干扰 | 精确目标地址／符号、event时栈、模块签名、provenance、全部排除 | 当前事后最近导出与摘要不足以补成上游条件 | A5/W2；缺字段阻塞等价转换，另派生弱规则须明确差异 |
| 栈／控制流完整性 | 原始异常／子码／保护来源、frame/slot代次、真实转移 | 通用fail-fast不等于栈越界；不是NX已覆盖全部ROP | A7.3；良性展开／切栈／JIT、槽位退休后重用 |
| YARA内容／IOC | 实际blob、范围／版本、扫描器版本、includes/modules/external | 本地14条小型子集不等于完整YARA，产品扫描器能力待定 | A8显式调查；规则命中只叫内容证据，不声称调用或执行 |

上表各端状态初始均为`mapping-pending`，不能填`available`。进入W2.1后，必须拆到实际ruleId／字段／端／来源行，并附源包定位与正反例；只完成上述族表不关闭全量字段矩阵待办。

## 6. 首个规则纵向切片

首个切片不追求数量，而验证“独立原事件→身份与字段→规则IR→证据结果→归档重放→用户解释”的全链。完整候选目录照常保留。

1. **自有探测尝试规则**：两个独立注册表open/query原事件、同线程实例、明确路径集合和窗口；输出“多项VM线索探测尝试”，不输出“VM存在／恶意规避成功”。路径集合须有来源锁，不从名称猜硬件。测试缺TID、正常管理软件、单事件、窗口外及排除Unknown。
2. **自有写入／执行证据组合**：真实成功范围与独立执行进入／确认事件绑定同目标mapping/content版本。离线手写事件只能验关联；真实来源和探针成功后再提升为产品证据。只有写入、只有线程创建、映射重用均不能输出已执行。
3. **一条上游规则的逐条件转换**：优先选动态capa或字段可完整满足的Sigma规则，保留原scope与全部排除。具体规则在W2能力矩阵完成后选择；不得现在虚定某规则必然可运行。测试引用固定源、原条件节点及每项正反例。
4. **状态规则**：再接Fibratus或其它完整可表达的序列，验证目标字段绑定、乱序、到期、水位gap、状态达限和重复输入；不使用聚合字符串预填结果。

切片1/2的自有规则只能说明明确自有语义，不解决本地601条的原授权问题；不能从待授权模板改标题就宣称自有。误报与缺字段仍写覆盖提示，动作默认记录；暂停／调查需独立策略和真实能力。

## 7. 源更新和发布复审

开发期对旧／新固定快照比较新增、删除、改条件、改依赖、改许可与改署名。若仅翻译变化也保留版本，但是否需重新语义验证由实际条件hash决定。schema／adapter／字段来源或正则profile变化同样触发相应规则复审，不能只盯上游文件hash。

发布根manifest包含规范schema/profile、来源清单hash、每条规则及依赖hash、作者通知、转换差异、端能力和验证引用。采样保存最终包hash和启用闭包；离线新analysisRun可用新包，旧结果不被覆盖。发布回退只影响新采样或新analysisRun，不把旧规则自动应用成目标断点。

当前距离规则可用仍差：正文全集／逐规则枚举、逐文件许可例外、三端字段和语义矩阵、转换器及IR执行器、真实原事件正反例和良性回放。来源已经明确，下一步是按表收敛这些具体产物，不能继续用“找一个规则库接上”代替实施。

反VM／反沙箱类别具体对接[环境实验行动方案](ActionAnalyze反反虚拟机与环境实验行动方案.md)的E01–E16／RAV1：规则解释真实探测尝试与实际返回，环境替代由独立显式策略／事务负责。原始硬件值、工具替代值和目标所见必须可区分；被工具改变后的值不能回填成“真实机器不存在VM痕迹”的证据。observed/substituted/seen/path-observed分级也不能由规则标题直接提升。
