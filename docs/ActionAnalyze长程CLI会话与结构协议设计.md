# ActionAnalyze 长程 CLI 会话与结构协议设计

本轮[缺口复查G15](ActionAnalyze规划缺口复查与补齐任务.md)补齐查询kind、项目关闭／采样删除／搬运及受限blob分块；具体方法提案归[事件协议](ActionAnalyze事件身份与协议契约.md)。这些操作仍走本端catalog／同一dispatcher／writer与现有预算，尚未注册产品命令；不可用kind明确unsupported，历史资料操作不自动attach或取得旧stop责任。

日期：2026-11-24。状态：拟实现契约。下文命令、消息和文件名尚未注册或实现，示例不能当作现有可执行命令。本文补充[通信与控制施工设计](ActionAnalyze多通道通信与控制施工设计.md)，三端各自组织会话的边界保持不变。

用户已明确：CLI 应适合人和 AI 清晰调用；长程运行不能只靠启动参数输入。必须按职责组织 `.cpp/.h`，不使用 `.inc` 堆叠，允许有明确回归义务的适度重构。

本轮补齐的具体方法、值类型、字段／版本、分页／水位及初始运输限制见[事件身份与协议契约](ActionAnalyze事件身份与协议契约.md)；过滤与项目文件分别见[筛选器](ActionAnalyze筛选器与规则语言设计.md)和[存储契约](ActionAnalyze项目存储格式与恢复设计.md)。这些是实施建议；正式机器schema、catalog/help和黄金向量归入[开工总表](ActionAnalyze完整开工审查与实施总表.md)的A0工作包，当前仍未注册产品命令。

## 1. 运行形态

建议保留两种用途：有限捕获供一次性脚本，持续控制会话供人工与 AI。持续会话是本能力的主要控制入口，启动参数只选择输入／输出格式、初始预算与保存位置，不把全部操作编码成一次启动参数。

以下是待注册的命令层级建议，不是已支持的命令：

```text
analyze capabilities           查询本端实际能力，不启动监控
analyze capture               明确期限的一次捕获与归档
analyze session               保持本 CLI 进程存活，持续接收命令
```

`session` 建议提供 `--input repl|jsonl` 与 `--output text|jsonl` 的明确组合：终端为 repl/text，机器为 jsonl/jsonl；其它组合暂不声明支持。有限 capture 的 `--json` 保持一个完整文档，不能与长会话多记录输出混用。禁止自动把重定向输入解释成 shell 脚本。机器模式固定 UTF-8 JSONL；终端模式以命令行语法映射同一份有类型请求，不执行任意 C#、PowerShell、Python 或命令拼接。

现有 `DebuggerSession.cpp` 的 stdin 命令与 `KswordCLI.cpp` 中 `mutation session` 已有保持控制所有者的先例，因此本项目并非完全没有长程命令。新设计要补齐其不等价的持续采集、运行时配置、并发输入、消息分型和输出背压，不能复制阻塞循环后就声称完成。

## 2. 一个存活进程拥有一个控制器

```text
调用方 ── stdin 命令 ── 解码线程 ── 有界请求 ── 控制协调者 ── 后端／Agent
                                            ↓ 实际状态
调用方 ←─ stdout 消息 ←─ 独立输出线程 ←─ 有界结果／订阅投影
                                  ↑
                       采集／语义／归档后台工作
```

控制器可拥有一个追踪会话及其多个根／进程／线程，具体多会话需求后续再定。首次版本不为并行会话先造全局管理总线；多根本来就属于同一追踪会话。

持久工作单位按用户补充改为[分析项目](ActionAnalyze分析项目与多次采样设计.md)：项目保存断点及配置，一个项目含多次采样，本端存活控制器只持本次运行会话。打开项目／历史采样不启动目标，新采样继承项目定义并重新绑定；projectId／sampleId 不授权接管旧停点。多次采样横向比较暂列待做。

CLI 进程退出后，该进程的控制线程、句柄、停止账本不继续存活。不能让第一次 `analyze session` 启动后退出，再声称第二个 CLI 可以凭 PID 或字符串 sessionId 接管停点。本轮不引入 daemon、共享 TraceHost、公共追踪 DLL 或跨端 IPC。AI 应保留同一子进程的输入／输出管道，持续收发。

人可以在同一个终端会话继续输入命令；终端提示符与文字说明不混入机器 stdout。自动化无需模拟按键或解析提示符。

## 3. 运行期操作族

下列方法名均为提案；启用前由实际 capabilities 列出支持的方法与参数。人类短命令和结构方法映射同一个请求，不另写两套控制逻辑。

| 结构方法建议 | 人类入口建议 | 职责／结果 |
| --- | --- | --- |
| `controller.hello`／`controller.capabilities` | `help`／`capabilities` | 协议、方法、schema、来源与后端能力；不部署目标 |
| `project.create`／`project.open`／`project.query`／`project.save` | `project create/open/status/save` | 管理项目资料与配置修订，不自动采集／接管目标 |
| `sample.list`／`sample.query` | `sample list/status` | 查询项目中的独立采样与历史结果，明确实时或离线身份 |
| `plan.load`／`plan.validate` | `plan load/validate` | 载入有界草稿，返回修订与 hash；不自动发布到当前会话 |
| `session.open`／`session.query` | `open`／`status` | 在明确项目中创建新采样及本端追踪会话，返回 sampleId／配置快照／真实阶段；按能力完成 Ready |
| `target.add`／`target.remove`／`target.list` | `target add/remove/list` | 运行时增减起点／线程，创建身份冻结；暂停目标删除遵循已定询问／明确策略 |
| `breakpoint.validate`／`breakpoint.apply`／`breakpoint.list` | `break validate/apply/list` | 语法和阶段校验、发布新配置、实际 ACK，不靠编辑文件假定热生效 |
| `rule.validate`／`rule.prepare` | `rule validate/prepare` | 草稿检查及下一采样／独立analysisRun准备；首版不提供活采样规则包替换，不改当前冻结判据 |
| `control.pause`／`control.continue`／`control.step` | `pause`／`continue`／`step` | 绑定真实对象、停止代次和本端所有权，接受与应用分别报告 |
| `control.query` | `stop status` | 原生状态／停止组／恢复责任回读，不以事件流最后一条推断当前状态 |
| `control.recover` | `recover` | 按后端能力重试精确停点的自有恢复责任，不执行盲目 resume-all |
| `investigation.start`／`job.query`／`job.cancel` | `investigate`／`job status/cancel` | 本端直接调查任务，保留采集批次和暂停，不创建页面 |
| `subscription.set` | `events` | 调整输出订阅和速率，不停止实际采集／归档 |
| `evidence.query` | `evidence` | 分页历史／详情引用；与全会话大 JSON 区分 |
| `request.query`／`request.cancel` | `request status/cancel` | 查询未知结果或取消未提交请求，不重发副作用 |
| `session.deadline.set`／`session.deadline.clear` | `deadline set/clear` | 运行期间修改期限；与单请求等待时限分别保存 |
| `session.stop` | `stop` | 停采集并明确 keep／release-owned；keep 时控制器与必要恢复能力继续存活 |
| `session.close`／`controller.shutdown` | `close`／`quit` | 按显式停止策略收尾，查询未决责任；不能把 quit 当杀进程 |

人工命令解析保留带空格路径、Unicode、引号和地址语义；用可测试 tokenizer，不使用简单按空格 split，也不交给 shell eval。`help <命令>` 显示状态前提、必须身份、异步结果和失败恢复方法。

典型交互为：启动外壳 → 查看能力 → 载入／校验草稿 → 显式 open → 等实际 Ready → 运行中增减目标／修改断点 → 命中后持 stopId 调查 → 显式 continue → query 回读 → stop／close → shutdown。调查完成不自动继续；删除仍被持有的目标必须明确停止责任如何处置。有限 capture 只接受可按预定策略收尾的计划，不用一次性进程承载退出后仍需用户控制的停点。

上述草稿和新采样归属明确项目，有限 capture 同样创建项目内采样；projectId／sampleId 在关联的响应、事件、证据与归档中保留。项目配置修订与本次 configRevision 分别报告，运行期断点变更的“应用本次”与“保存到项目”分别执行；新采样重新绑定，不能加载旧 stopId 来继续旧目标。字段与方法建议已经登记在[事件身份与协议契约](ActionAnalyze事件身份与协议契约.md)，机器schema、catalog/help及正反例在A0冻结后才接产品解析器。

PPT 原图的现行范围包括 12 项类型化后台操作。回滚外部操作与热重载延期。网络操作断开选中进程的现有连接并逐项报告实际结果。链条重新启用跟踪，三个箭头依次是逐过程／逐语句／跳出。请求冻结真实对象和停止前提，按采样显式选择后端。[工具栏功能契约](ActionAnalyze工具栏逐项功能核对.md)

## 4. 机器协议的固定规则

R3 在本机独立验证受支持的用户态分析流程，普通 R0 在指定来宾验证。手动暂停与 Agent 同步命中共用本端控制账本，CLI 用既有 `control.query` 读取组状态。[双后端设计](ActionAnalyze双后端独立全流程设计.md) · [同步全局断点契约](ActionAnalyze同步全局断点与性能复查.md) · [验收范围与运行环境](ActionAnalyze工程开工基线.md#验收范围与运行环境)

每行一个完整 JSON 对象，换行分帧；字符串内换行使用 JSON 转义。行长1 MiB、深度32、单对象128键、数组4096项等初始限制及输出／在途预算统一见[协议§7](ActionAnalyze事件身份与协议契约.md#7-运输与-cli-初始边界)，公开阈值再经实测校准。解析器必须在累积超过上限时立即拒收／终止该输入协议，不能无限缓存一个未换行请求。

对象键重复、非法 UTF-8、浮点地址、溢出整数、未知方法、缺必需字段、版本不符分别返回明确错误。未知可选扩展字段与未知控制语义的处理由 schema 明定，不能默默忽略目标／暂停／恢复字段。

首版建议封闭顶层与方法参数键集，未知字段拒绝；只有显式版本化的扩展对象允许未知可选键。复用现有 `shared/evidence/EvidenceJson` 的有界无损解析器并按入口收紧预算，另做严格 UTF-8 与字段类型检查；便利数值转换函数不能替代 schema 校验。坏行无法取得 requestId 时返回 `protocolError`、requestId=null、输入序号和错误位置，不伪造客户端 ID。

建议公共请求包含：

| 字段 | 类型／意义 |
| --- | --- |
| `schemaVersion` | 小整数；版本协商不改变已经接纳请求的语义 |
| `requestId` | 调用方生成的有限字符串，本控制器内唯一；重试同 ID 同参数，不允许复用成另一操作 |
| `method` | capabilities 中精确的方法名 |
| `session` | 需要会话的方法携带 sessionId、epoch；控制器级方法允许缺省 |
| `expected` | 修改所需的 stopId、stateRevision、configRevision 等显式前提 |
| `params` | 方法专有的有类型参数，不放任意可执行代码 |

controller 级请求省略 session，session 级请求必须提供完整身份。`expected` 按方法规定必需项，缺失或 null 均不视为通配；step／continue／停点调查／recover 必须携带真实 stopId。已知无值的响应可用 null 加状态原因；缺字段、null、已知零和空集合不互相替代。版本必须为 JSON 整数，地址和 uint64 必须符合规范字符串格式，不做宽松类型强转。

地址使用规范十六进制字符串，64 位计数／时钟／创建身份使用规范十进制字符串或明确的固定 ID 字符串；不能经 JavaScript Number 读写后丢精度。已知零、未知、未采集、截断、失败分别表达。错误对象包含稳定 errorId、原始 source／code、retryability 和当前真实阶段；不以文本猜测补字段。

同一请求允许先发 `accepted` 再发 `completed`，但阶段独立。同步查询可直接 completed，不强制制造两次消息。异步 job 的启动请求完成只说明 job 已建，job 成功另有状态；控制命令的 completed 也须包含实际 effectPhase，而非默认已运行。

配置分别记录 desiredConfigRevision 和逐来源／目标 effectiveConfigRevision，覆盖修订另存。修改配置的前提比较当前已提交 desired 修订，放行还须核对所要求的 effective 修订、覆盖与探针状态；最新草稿不等于全部路径已生效。controller、capture、control、archive 各有状态，不能合成一个 paused 布尔值。

请求账本同时限制条数和字节，不淘汰未决副作用与恢复责任。若采用任意字符串 requestId，应保留本控制器已接纳变更 ID 的有界身份记录；达到累计上限后拒绝新普通变更，保留查询、恢复和关闭资源，不能淘汰后把旧 ID 当新请求再执行。若后续改用单调请求序号／水位压缩历史，须独立定义协议与反例测试，不能声称普通 LRU 已提供永久去重。

## 5. 消息分型与示例

输出至少有 `hello`、`response`、`state`、`event`、`gap`、`protocolError`、`warning`、`summary`。每种消息都带 schemaVersion、controllerId 和 streamSequence；streamSequence 在实际序列化输出次序分配，不作为行为因果。response 回显 requestId，session 消息带实际 sessionId／epoch，state 带 stateRevision，event 带 eventId／sourceSequence／覆盖状态。gap 明确来源／传输／归档／显示哪一层丢失，不能把同一缺口跨层相加。summary 是本控制器真正准备退出时的最终记录；没有收到它不能推断清理完成。

下面只是拟定的交互示例。`S1`、`E1`、`STOP7` 为可读占位 ID，真实值由本端生成并要求原样回传。

```json
{"schemaVersion":1,"requestId":"q1","method":"controller.hello","params":{"acceptVersions":[1]}}
{"schemaVersion":1,"requestId":"q2","method":"session.query","session":{"id":"S1","epoch":"E1"},"params":{}}
{"schemaVersion":1,"requestId":"q3","method":"control.continue","session":{"id":"S1","epoch":"E1"},"expected":{"stopId":"STOP7","stateRevision":"19"},"params":{"scope":"selected","targetIds":["T4"]}}
```

上例 q2／q3 以调用方已经从 session.open 收到有效 ID 为前提，不表示启动就有默认目标。目标实例 T4 的具体 PID／TID／创建时间可通过 target.list 查询，不能把裸 PID 当作稳定 ID。

拟定结果形态：

```json
{"schemaVersion":1,"type":"response","controllerId":"C1","streamSequence":"11","requestId":"q3","session":{"id":"S1","epoch":"E1"},"phase":"accepted","effectPhase":"pending"}
{"schemaVersion":1,"type":"response","controllerId":"C1","streamSequence":"12","requestId":"q3","session":{"id":"S1","epoch":"E1"},"phase":"completed","effectPhase":"observed","stateRevision":"20","result":{"targetId":"T4","state":"running","releasedOwnHold":true},"error":null}
```

真实多目标结果逐项记录，部分释放不能压成上述单对象成功。若操作已提交但回执丢失，request.query 回答 committed-result-unknown／可取得的状态；不能建议用 q4 再执行一次 continue。

最终 schema 应以独立可校验文档／JSON schema 发布，并带正反例。文档示例、内置 help 与实际解析器使用同一方法元数据源，不能为 AI 维护一套与真实命令漂移的接口。

## 6. 输出背压与调度

输入、控制执行、遥测处理、归档、stdout 输出分别有执行责任。stdout 写阻塞不能持有状态锁，不能阻塞输入线程、外部恢复线程或停止所有者；stderr 的诊断也不能在控制线程同步无限写入。

结果／状态与普通事件使用分开的有界待输出预算，普通事件允许摘要／订阅降采样并显式记录显示丢失。停点事实保存在真实后端与账本，不能只保存于待写 stdout 队列。默认机器订阅优先返回请求结果、状态变化和汇总；高频原始事件需显式订阅／分页或直接读取归档。

优先级只影响尚未写出的消息。某个事件已经进入阻塞的 OS 管道写操作后，不能被后来的控制 ACK 抢占。因此：

- 帧必须小且有限；大 dump／脚本正文通过证据引用与分页，不塞进结果行。
- 输出线程使用可取消 I/O 和有限收尾；取消后的完成／缓冲生命周期单独处理。
- 输出不通时，CLI 可继续执行已接纳控制，但不能承诺回执已经交付。
- 再通后先对请求和当前状态同步，不用补齐海量历史输出来挡住恢复查询。
- 输入洪峰对新普通请求限流；取消／停止／状态查询有保留容量，保留容量也不能无限。

语义事件是否输出不影响其采集与归档。机器调用方应并行读取 stdout、stderr 并保留 stdin；“写完命令再统一读全部结果”可能填满管道。没有持续读者时，程序需要按已声明的 output-lost 策略处理，不以无限内存缓存掩盖问题。

## 7. Ctrl-C、EOF 与关闭

| 输入／故障 | 建议契约与必须验证的边界 |
| --- | --- |
| Ctrl-C／Break | 建议Ctrl-C取消当前前台可取消job，Ctrl-Break提交orderly-close；handler只signal，重复信号合并，不直接做I/O或无条件归还所有挂起 |
| `request.cancel` | 提交前取消赢则无副作用，提交后说明真实执行状态；不能把请求取消当恢复停止组 |
| `session.close` | 停止新准入，处理在途操作，按明确策略恢复／解除本端责任，回读后输出逐项结果 |
| 人类 `quit` | 有暂停对象时显示其身份和可用恢复选择；确认从持续会话中再次输入，不销毁所有者后才询问 |
| 机器 EOF | 表示命令来源关闭，触发预先声明的 orderly-close，不作为 keep-running daemon 请求；不能指望之后仍从同一已关闭 stdin 询问用户 |
| 已登记调用方进程死亡 | bootstrap 明确登记 PID＋创建时间、持真实同步句柄才监视；与控制器自身死亡不同，执行已声明 input-lost 策略；未登记则报告 not-monitored |
| stdout broken／读者消失 | 标记交付失败；按预定策略进入收尾，不能阻塞恢复等待输出；归档和原生控制结果分别记录 |
| 关闭中恢复失败 | 保留恢复责任及原始错误，不报告 clean；若控制器继续存活则是 recovering／unresolved，必须有可达恢复或预先约定的有限故障处置，不用无限无人值守等待冒充恢复 |
| 进程被强杀 | 依真实后端 owner-death 能力处理；普通 R3 suspend 不保证自动恢复，同进程线程已不能执行清理 |

机器模式不能临时弹窗或等待终端确认。会话 open 时提供明确关闭／输入丢失策略及后端可实现性，不支持的保证在产生副作用前报告。正常超时由存活用户控制器继续保持闸门，与输入彻底丢失／进程死亡分开。

“保留目标暂停并退出”只有后端可以将责任交给已存在且合法持有的所有者、并有真实 ACK 时才允许；本轮不为此新建守护进程。用户请求保持停点也不意味着允许 CLI 随意丢掉唯一恢复句柄。

进程退出码是控制器最终结果，不作为每个请求的结果。单个请求失败可以继续会话；最终 summary 给出原生清理、归档写入／刷盘、交付状态、未决责任和退出原因。

### 7.1 沿用现有退出码与流边界

已核对 `docs/CLI使用文档.md` 和 `CommandRegistry`，拟定新命令遵循现有 0–6 约定，不改变旧命令：

| 退出码 | 新控制器最终含义 |
| --- | --- |
| 0 | 本次目标完成且要求的清理已确认；query 成功本身不证明会话健康 |
| 1 | 启动参数／计划／请求用法错误；会话内单次错误不强制结束进程 |
| 2 | 必要驱动设备打开失败，有对应原始证据 |
| 3 | I/O／操作失败或明确失败的等待超时；另存副作用未知阶段 |
| 4 | 后端响应长度／版本／格式错误；客户端坏 JSON 与之区分 |
| 5 | 明确不支持或所需证据不可用；未探测的 unknown 不冒充不支持 |
| 6 | 部分证据、取消、归档不完整或要求的清理尚未确认 |

若多个条件并存，先按 6 呈现部分副作用／未决清理，再按必要后端失败分类；用法错误须在副作用前拒绝。summary 另列原始错误和退出原因，不由一个数字覆盖材料化责任。不要新增 130 来代替 Ctrl-C 的取消原因。新会话边界捕获运行异常并尽可能给出最终结构结果；控制器被强杀、输出失联时不保证 summary 交付。

现有 `dispatchR3` 在 `run` 返回后调用 `emit`，且普通选项解析只将既有少数选项视为 flag。接入时必须增加明确输出所有权／选项类型，使长会话由唯一 writer 输出完整协议，返回时不再追加旧 Result 文档；有限命令保留现有单文档路径。当前主入口将 CRT stdout／stderr 设为 `_O_U8TEXT`，新原生 UTF-8 字节 writer 必须独占相应句柄，不与原 `wcout`／窄字符输出混写。

现有 `R3Cancellation` 用同一个进程级 atomic 处理 Ctrl-C 与 Break；新会话的本地生命周期接入须分别表达取消、关闭、EOF 和期限，不直接复用该单标志作为全部状态机。暂不改旧命令取消约定。机器输入真正关闭、又没有可达恢复入口时，准入前必须确认已选择且后端支持的失联处置；不能接受自动 held 计划后以无人可操作的无限存活作为恢复方案。

R0 审计确认现有批量附加恢复、R3 原页保护及临时挂起还有丢账边界；不能在 CLI capabilities 中预先公告 owner-death 完整恢复。后端修复门槛见[通信施工 §7.4](ActionAnalyze多通道通信与控制施工设计.md#74-普通-r0-后端的静态审计门槛)。新配置修订不授权新的执行动作，但精确处理旧责任仍需可达入口，不能只因 configRevision 变旧便拒绝恢复。

按后续双后端要求，R3原生和普通R0各自是正式后端；session.open明确选择，正式字段归A0冻结。挂起／上下文／TF／DR／保护及异常继续由所选后端记责，调查不绕账本。R3不以驱动在线或私有内核ABI作为全流程前置；缺少R0专用字段的规则／调查逐项阻塞，不把整个R3会话判为不可用。hello／capabilities与逐项结果报告所选／实际后端、来源缺口、协议及恢复能力；超时／坏包不自动切换，更换须清退旧责任后新建采样／epoch。原生NX在途控制器死亡恢复失败仍未解决，不能通过CLI封装宣称安全。

## 8. 文件组织与回归义务

以下均为建议新文件，位于 `KswordCLI/ActionAnalyze/`，不把主命令大段添加到 `KswordCLI.cpp` 或 `R3MonitorApi.cpp`：

| 文件 | 唯一职责／接口 |
| --- | --- |
| `Commands.h/.cpp` | 注册命令族／help 元数据，解析 bootstrap；启动本端控制器 |
| `Request.h` | 有限值类型、身份、方法和预算；无流／GUI／后端句柄 |
| `RequestDecoder.h/.cpp` | 有界 UTF-8／JSONL 解析与 schema 校验，不执行方法 |
| `InputReader.h/.cpp` | console／重定向输入、分片缓冲与可取消读寿命，不执行控制 |
| `ReplParser.h/.cpp` | 人类命令 tokenizer，转同一 Request；不调用 shell |
| `Session.h/.cpp` | 本端长程会话、各工作者生命周期与关闭策略 |
| `ControlCoordinator.h/.cpp` | 接纳／提交／取消仲裁、原生状态和停止账本 |
| `MethodDispatcher.h/.cpp` | 依据能力和状态派发有限方法，查询不启动副作用 |
| `MethodCatalog.h/.cpp` | 方法、参数类型、状态前提、能力与 help 同源元数据，不另持业务状态 |
| `OutputWriter.h/.cpp` | 有界结果／订阅队列、唯一 stdout 写者、可取消写入 |
| `DiagnosticWriter.h/.cpp` | 有界 stderr 诊断，不阻塞控制／stdout |
| `LifecycleSupervisor.h/.cpp` | 信号、登记父身份、I/O 失联和期限，向同一协调者提交生命周期意图 |
| `ProtocolJson.h/.cpp` | 请求／结果／事件类型的序列化，64 位无损／未知语义 |
| `SourceAdapters.h/.cpp` 等按来源拆分 | 复用已有低层采集入口，本端编排，不通过 Qt 宿主 |

状态与后端拥有者尽量复用本端已规划模块，不额外建立两套 Session／停止账本。若 `MethodDispatcher` 已能由固定命令表完成，不为形式再引入继承树。需要拆分时以职责和生命周期为准；所有新源码登记项目和 filters，并包含中文注释及正常排版。

旧 JSON builder、全局命令 registry、一次性 dispatch 只做必要扩展；不得为了这一条长程命令整体重写所有旧输出。旧 debugger／mutation 命令保持原行为，若抽取其公共能力，分别记录接口差异和回归结果。

回归分别覆盖 registry 的旧输出／错误单文档及 flag 解析、debugger 同进程控制与 detach、mutation 失败 commit 后 rollback 所有者存活、API capture 双架构／子进程／租约／取消及 ETW 既有捕获。现有 `tools/test_ksword_cli.py` 使用临时编译目录和直接 cl，执行前须适配固定产物与 BelowNormal 规则；本轮未运行该旧入口，不能将它列为已通过。

必须验证：

1. 同一进程运行时添加目标、修改断点、查询、暂停／继续／调查，不重启 CLI。
2. 两个并发 request 的乱序完成能按 ID 匹配，旧 epoch／stopId 拒绝，重复 ID 不重复副作用。
3. UTF-8／引号／空格路径、分片输入／多行一次输入、坏 JSON、重复键、超长未换行、未知方法及 64 位边界。
4. 事件洪峰／输入洪峰／stdout 不读／stderr 不读时，控制执行和取消不死锁；结果交付缺口如实报告。
5. Ctrl-C、EOF、父进程死亡、输出断开、正常 close 与恢复失败，逐项核对所有者、句柄和真实暂停责任。
6. 机器 stdout 每行可解析且类型稳定，无提示符／诊断混入；最终 summary／退出码与 help 一致。
7. 有限 capture 与旧命令的 JSON／文本／取消／help 不回归；长程协议通过不代替实际驱动／Agent 运行验证。

## 9. 当前状态

本轮先落契约与源码审阅，尚未新增 CLI 命令或结构输入解析器，没有产品长程会话运行结果。独立协议模型与 Windows IPC 夹具只能验证其声明的机制，不替代这里的真实 CLI 收发、语法与关闭验收。

后续实施顺序：核对现有 registry／取消／输出约定 → 固定请求与结果 schema → 自有假后端验证长程 I/O／取消／背压 → 接入本端真实控制 → 三端能力与产品回归。实现任何命令／别名／参数时，同步更新内置 help、`docs/CLI使用文档.md` 和对应专题，而非仅更新此草案。

下一层任务为[施工清单A3.1–A3.3／A9.3](ActionAnalyze施工任务与契约落点.md)，首条离线纵向链和假后端I/O与真实控制分别验收。环境实验如后续接CLI，依[反反虚拟机方案](ActionAnalyze反反虚拟机与环境实验行动方案.md)使用显式profile／required集合及新采样，不直接接受任意“改返回值”脚本，也不把机器请求接到Qt宿主。
