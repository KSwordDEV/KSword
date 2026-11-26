# 显式多进程执行断点集合

正式命令为 `KswordCLI.exe analyze execution-group session`。一次配置 1–16 个不同 PID 的明确实例，每个实例冻结一份执行站点和可选条件，逐项真实附加。每个成员使用独立的 `OwnedDataWatchSession` 和 `NativeDebugOwner`，可共享采样 ID，成员的 session、epoch、backend ID 与原生停止组独立。

```powershell
KswordCLI.exe analyze execution-group session --sites C:\Work\execution-sites.json --confirm --disposition resume-detach --input jsonl --backend r3
```

`--confirm` 与 `--disposition resume-detach` 必须明确提供。`--input` 可选 `repl`（默认）或 `jsonl`，只支持 R3。不会自动扫描系统、接纳所有后代、按历史关系图附加或在同一 PID 上为第二个站点创建另一个 owner。

可选 `--project PATH` 在附加前新建项目并创建本轮独立采样；`--project PATH --open-project` 打开已有项目并创建新采样，不复用旧停止票据。不提供目录时仍可控制集合，但不能保存执行观察。项目准备失败会阻止附加；项目被其它会话占用时不另开 writer。Qt 和 Light 的执行集合页提供相同目录及打开方式草稿，Start 时冻结，由原 worker 持有写租约，全部原成员 clean 后才归还。

模块 RVA 站点可再指定可选 `definitionId`（规范 UUID）。必须同时配置项目；启动时读取本轮新采样冻结配置中的同 ID 启用 RVA 定义，并核对模块文件名及填写的 RVA。定义中的映像 SHA256 自动继承；手填散列与冻结散列冲突时拒绝。全部成员解析成功才开始附加，任一失败不附加任何成员，详情保留 `executionArchive.setupError`，可清退空集合后修改草稿重试。精确导出和私有站点不接受定义 ID；此入口不解析 PDB、不自动枚举全系统实例。

## 配置文件

集合的 `recovery-required` 同时保留成员原回执中的断点、步进、主动暂停、范围回滚与不确定事件继续责任；不能只看顶层状态而把完整 Held 数量当作已可恢复运行。首次恢复失败在成功清退后仍保留为历史诊断，`clean=true` 后不因此阻止集合进入 Closed。集合只呈现责任，实际恢复仍由各成员原 owner 的 Close 执行。

单成员 `control.step` 与 `control.step.cancel` 的前置回读使用无条件查询，不会顺带处理其它成员的假条件并自动继续；错误或过期票据拒绝也不释放其它成员。条件自动处理仍在明确的集合查询路径执行。

`--sites PATH` 读入 1–131072 字节的普通磁盘文件。文件必须为严格 UTF-8、无 BOM，JSON 不接受重复键、浮点、超限深度或多余字段。读取期间不允许其他写入或替换；文件读取和所有条件编译在任何附加前完成。根对象只含 `schemaVersion` 与 `sites`。

```json
{
  "schemaVersion": 1,
  "sites": [
    {
      "pid": 4120,
      "creationFileTime": "134085245678901234",
      "module": "C:\\Work\\TargetA.exe",
      "exactExport": "ExecutionEntry",
      "condition": "stop.pid == 4120 && isKnown(stop.thread.rip)"
    },
    {
      "pid": 5188,
      "creationFileTime": "134085245678901235",
      "module": "C:\\Work\\TargetB.dll",
      "rva": 8192
    },
    {
      "pid": 6324,
      "creationFileTime": "134085245678901236",
      "address": "140698833649664",
      "rangeBytes": "4096"
    }
  ]
}
```

所有示例 PID、创建时间及地址均为格式示例，使用时须由用户替换为实际选定实例。

| 字段 | 格式及含义 |
| --- | --- |
| `pid` | 必填，正的 uint32 JSON 整数；集合中每个 PID 只能出现一次。 |
| `creationFileTime` | 必填，正 uint64 的规范十进制字符串，无前导零；与 PID 一起冻结真实进程实例。 |
| `module` | 映像站点必填，绝对 DOS 模块路径，例如 `C:\Work\Target.dll`；与私有地址形式互斥。 |
| `exactExport` | 与 `rva` 二选一，区分大小写的精确 PE 导出名，不解析 PDB 名称或转发导出。 |
| `rva` | 与 `exactExport` 二选一，正 uint32 JSON 整数；调用者确认该 RVA 是指令边界。 |
| `imageSha256` | 映像站点可选，64 个小写十六进制字符。原成员 owner 对实际模块基址对应调试装载事件文件计算散列，相符后才武装 DR0；私有地址站点拒绝此字段。 |
| `address` | 私有站点必填，正 uint64 规范十进制字符串；与模块、RVA、导出互斥。 |
| `rangeBytes` | 私有站点必填，uint64 规范十进制字符串；`"0"` 表示单地址 DR0 执行停点。非零为 4096 的倍数，最多 64 页，地址也须 4096 对齐；实际区域与保护由原 owner 核对。 |
| `condition` | 可选、非空 UTF-8 条件表达式，最多 8192 字节；复用 `PrepareDataWatchCondition` 的字段、类型、三值及预算规则。 |

启动只冻结上述明确输入，实际模块、进程架构、访问权、用户/会话和执行位置的准入以成员原生回执为准。部分附加失败时保留已成功成员，继续处理余下目标；不以回滚整组的方式丢掉成功附加者。`attachAccepted` 表示初次接纳，武装进度和真实命中请看 `control`。条件只处理该成员真实执行进入事件，假或未知值沿原会话自动继续并保留求值报告；普通步进停点沿原会话独立处理。

可选文件约束对模块导出和 RVA 均适用。`site.imageSha256` 保存请求时冻结的期望值，`control.breakpoint.imageSha256` 只保存原 owner 实测成功值；不能取得原装载文件、散列不符或文件读取失败时由该成员原 owner 拒绝并清退，不影响其它已成功成员。不按当前同名路径重开文件替代事件文件，不认证进程映像页的运行时内容。完整控制票据保留实测散列；旧无散列票据只兼容无约束绑定，不能给带散列绑定补值。Qt／Light 的成员草稿使用相同约束，新增源码尚未构建或运行。

## 状态与身份

输出始终使用 UTF-8 JSON 行；REPL 的命令输入是文本。`hello.session` 是本 CLI 活会话的 `id/epoch`，控制请求必须原样携带。`hello.result.control.collectionId` 只标识本次执行集合，不能代替任一成员的原生 `groupId`。本命令不从项目、索引、历史停止档案或另一个 CLI 实例恢复活控制权。

`control.members` 按启动配置顺序给出：

- `site`：冻结配置及条件原文。
- `owner`：成员原 `sampleId/sessionId/epoch/backendInstanceId`。
- `control`：成员原生状态、绑定、命中、步进、继续与清退诊断；`nativeSnapshot` 保留停止投影。
- `condition`：该成员真、假、未知计数及最近实际求值和自动继续结果。
- `pauseToken`：原执行 owner 的活绑定满足 `CanPauseDataWatchSession` 时提供完整显示快照，不要求已有停点。
- `stopToken`：仅在成员实际持有可控停止事件时给出完整当前票据。
- `stepToken`：原会话存在步进请求时给出完整票据，取消仍由原会话核对精确请求。
- `control.armedPause`：主动暂停的原 owner、`pause/N`、Pending/Held/Preempted 等状态、停止组、事件和错误，与继续/步进回执分列。
- `replToken`：仅 REPL 输出；与完整票据 JSON 等价的 UTF-8 小写十六进制字节。
- `sessionToken`：`{owner,control}` 完整成员表项，其中 control 是同一原始显示快照；Held、Armed 运行以及失败状态分别保留，不从裸 PID 补票。
- `canPause`／`canContinue`：该成员在混合批次中的显示资格，包含 `already-held`／`already-running`；不代表原生动作已经执行。
- `canAddRange`：该成员持有完整 NX 停点且符合本事件条件，可显式追加范围；ManualPause 同样允许。
- `control.breakpoint.totalRangeBytes/totalRangePages`：实际成功范围目录的总量，与保留初始站点身份的 `rangeBytes` 分开；失败回滚中的页不作为已纳入范围。`control.executionRange.owner/event/groupId/stopId/expectedStateRevision` 是提交时的原停点坐标，`stateRevision` 是本次实际核验修订。
- `replSessionToken`：仅 REPL 输出，完整 `sessionToken` 的 UTF-8 小写十六进制字节。顶层 `control.sessions` 是固定全集同顺序的完整表，可直接作为混合 all 请求输入。

`held-complete` 仅表示逐成员查询时每个固定成员都持有停止事件。集合明示 `simultaneousFreeze:false` 与 `observation:"sequential-member-readback"`，不证明所有进程在同一时刻冻结。组当前 `state/members` 与最近 `operation` 分开：操作的 `outcomes` 保存全部请求成员，每项有 `actionAttempted` 和 `disposition`。实际调用原 session 时为 `true`／`action-attempted`，不等于原生动作成功；无动作项分别为 `false`／`already-held` 或 `false`／`already-running`，control 保留原停点或运行快照，不生成新释放回执。后续查询不改写原操作结论。拒绝批次没有原生调用，`admitted:false` 且 `outcomes:[]`。

## JSONL 请求

复用正式 `Cli/Transport` 的请求包络及 LF/CRLF 分帧、UTF-8、输入与输出限制。所有修改操作必须携带当前 hello 的会话身份。暂停、继续、步进和取消共用单调递增的 `execution/N` 请求 ID（从任意正数起、后续必须更大），保留最近 128 份回执。同 ID 相同参数只返回首次结果，不重做原生动作；同 ID 不同参数拒绝，过期 ID 不执行。已进入组准入的失败操作也占用该 ID，修正参数后使用更大的 ID。协议形状错误尚未进入组准入时不消费 ID。

查询：

```json
{"schemaVersion":1,"requestId":"status-1","method":"control.query","params":{}}
```

选中继续的结构如下。尖括号内容必须替换为当前 `hello`、`collectionId` 和完整 `member.stopToken` 对象；不要把尖括号示意直接作为请求发送。

主动暂停使用 `method:"control.pause"`、`params:{"scope":"all"|"selected"}` 和相同 `session/expected` 包络。混合集合推荐 `expected:{collectionId,sessions:[完整 member.sessionToken, ...]}`；`all` 传顶层 `control.sessions` 的完整固定全集，`selected` 传明确非空子表。兼容旧 `expected:{collectionId,stops:[完整 control token, ...]}`，可混合原 `pauseToken` 与 Held 的 `stopToken`，但不能把原owner表项与裸control token混在同一数组。暂停不要求运行成员拥有旧 stop，也不接受裸 PID、索引、空数组或服务端补选。全部目标先匹配原活 owner、PID/创建时间、进程实例和 `breakpoint.requestId`；精确Held者保留原stop并记 `already-held`，可暂停运行者才调用原 `session.Pause`。任何重复、外来、陈旧停点、恢复失败、未决或未知状态都拒绝整个批次，不调用任一原动作，不清账；核验回读使用 `QueryWithoutCondition`，不触发条件自动Continue。实际调用仍可能部分失败，分别保留原回执，不创建第二个 owner 或重新绑定断点。

暂停准入后的 Pending 不等于 Held，也不保证跨进程同时停止。只有原 `ManualPause`、Held 回执及精确事件/停止组一致才可 Continue，Query 不应用原执行条件；本批拒绝从 ManualPause 步进。暂停被真实执行命中抢先时按原 owner 的 Preempted 和实际停点报告，不伪造主动中断成功。完整 token 额外保留 `clean`、`stopReason`、`armedPause`、`stepState` 和绑定 `requestId`，各操作只接受本次输出的新完整形状。

```text
{
  "schemaVersion": 1,
  "requestId": "execution/1",
  "method": "control.continue",
  "params": {"scope": "selected"},
  "session": {"id": "<hello.session.id>", "epoch": "<hello.session.epoch>"},
  "expected": {
    "collectionId": "<current collectionId>",
    "stops": [<complete current member.stopToken>, <another selected member.stopToken>]
  }
}
```

混合 Continue 同样接受 `expected:{collectionId,sessions:[完整 member.sessionToken, ...]}`，兼容旧完整 `stops` 列表。`scope:"all"` 必须明确携带固定全集每一份完整成员快照，`selected` 是非空明确子集，不能省略运行成员后让服务端补票。先核对全部原owner和绑定；对精确Held成员再核对停止组、事件、来源线程、完整成员构成、修订和本事件条件资格，随后才调用各原会话的 Continue。明确 Armed 运行者记 `already-running`，`actionAttempted:false`，不伪造释放或调用 Continue。原owner、停止或状态预核验失败时整批拒绝；通过后实际调用阶段仍可能部分失败，失败不清账。单成员Step仍要求真正Held，本批不能对ManualPause或already-running步进。

混合全局操作包络示例（把占位内容替换为原样完整对象）：

```text
method: "control.pause"          // 或 "control.continue"
requestId: "execution/10"
params: {"scope":"all"}
session: {"id":"<hello.session.id>","epoch":"<hello.session.epoch>"}
expected: {"collectionId":"<current collectionId>","sessions":<完整 control.sessions 数组>}
```

单成员步进使用相同 `session/expected` 包络，`stops` 必须只有一个完整当前停止票据：

```text
method: "control.step"
requestId: "execution/2"
params: {"mode":"into"}        // 或 "over-call"、"out"
expected: {"collectionId":"...", "stops":[<complete current stopToken>]}
```

原会话从精确事件冻结的强线程身份发起步进，不从裸 TID 或当前页面索引选择线程。取消使用同一成员原步进请求的完整 `stepToken`：

```text
method: "control.step.cancel"
requestId: "execution/3"
params: {}
expected: {"collectionId":"...", "stops":[<complete current stepToken>]}
```

取消核对完整原 `NativeStepRequest`，不会把旧取消请求迁移到成员后来发起的步进。

单成员追加私有执行范围复用同一 `execution/N` 修改流水，必须提供一个完整当前 `stopToken`：

```text
method: "control.execution.range.add"
requestId: "execution/4"
params: {"address":"140698833657856","bytes":"4096"}
session: {"id":"<hello.session.id>","epoch":"<hello.session.epoch>"}
expected: {"collectionId":"<current collectionId>","stops":[<complete current NX Held stopToken>]}
```

`address/bytes` 为规范正十进制字符串，起点与长度均须 4096 对齐，不溢出，长度最多64页。原 owner 核验实际私有页、同一分配及所有范围合计64页预算。追加在成员原 `OwnedDataWatchSession` 内分配独立 `range/N`，不调用 Continue，不改变原停止事件、初始地址或 `site`。完整 ManualPause 可追加；运行、步进在途、恢复未决及旧范围快照均拒绝。核验采用无条件回读，不触发其它成员条件自动继续。实际范围见 `control.breakpoint.executionRanges`，该次范围与回滚结果见 `control.executionRange` 和 `operation.outcomes`；失败不能用请求已受理冒充范围已纳入。同ID重放沿原128回执窗口返回原结果，不重复追加。

### 保存成员执行观察

配置项目后，选择一个当前执行进入或用户 Into 完成事件，沿同一修改流水显式保存：

```text
method: "control.execution.save"
requestId: "execution/5"
params: {}
session: {"id":"<hello.session.id>","epoch":"<hello.session.epoch>"}
expected: {"collectionId":"<current collectionId>","stops":[<complete current member.stopToken>]}
```

保存先无条件回读原成员及完整事件/修订；不求值同伴条件，不调用 Continue，不因有请求而声称实际执行。ManualPause、普通数据写入或不完整旧停点不构成执行观察。实际段沿 `native-execution-v3` 保存同一事件的寄存器、原绑定、已纳入 NX 范围和实测映像散列。全部成员共用本轮采样的 `raw-native` 顺序流，但每条记录保留原成员 owner，不能用集合 ID 替代。

每次控制响应中的 `executionArchive` 独立给出项目/采样、写租约、最近保存、首次追加失败及 `appendBlocked`。`saved` 包含实际事件、段号、written/flushed 边界、段散列和 `segmentVerified`，写成功不代表目标已继续或全流程采集完成。相同 backend/serial 再次保存返回原段坐标及 `duplicate:true`；保存日志最多4096个事件。真实追加失败后保留原失败并阻止越过坏尾；可以继续控制和清退，不能以旧成功重放掩盖 `firstFailure`。Qt 字段详情和 Light 完整正文消费同一规范文档，搜索/复制/导出保留这些字段。本批仅源码接线，尚未构建或实测。

### 同采样 API 来源采集

配置项目后，可为一个仍附加的成员选择集合以外的来源实例，复用当前 sample 的冻结修订和原 writer：

```text
method: "control.api.capture"
requestId: "execution/6"
params: {"sourcePid":6132,"sourceCreationFileTime":"134085000000000000","durationMs":3000,"confirm":true,"startupProgress":true}
session: {"id":"<hello.session.id>","epoch":"<hello.session.epoch>"}
expected: {"collectionId":"<current collectionId>","sessions":[<one complete member.sessionToken>]}
```

REPL 为 `api-capture execution/N PID FILETIME DURATION confirm REPLSESSIONTOKEN [progress]`，最后的目标票据来自 `member.replSessionToken`，不同于执行保存的 stopToken。全部参数及目标身份进入原 `execution/N` 重放签名，同 ID 返回原结果，不再装载 Agent。

来源 PID 不得是集合任何成员，实际装载前由共享采集器核对来源 PID＋创建 FILETIME。采集区间为 Ready 后 1000–10000 毫秒，启动与清退另计；CLI 在同步采集返回后处理排队控制，不承诺在途命令取消。Qt／Light 复用原参数区、worker 及展示周期，关闭入口立即取消在途 API，原采集排空后才清退原调试成员和归还项目 writer。原调试事件仍由各成员自身 debug owner 持有。

`apiCapture` 独立给出来源、准入、启动阶段、覆盖、普通包、段坐标、规则、清退及目标前后状态；`apiOwner` 给出本次冻结的原成员身份。可选进度只写 stderr JSONL；stdout 保留原响应。服务前后采用无条件查询，不求同伴条件、不调用 Continue、不自动保存执行事件，也不自动将 API 候选归因为真实执行。已有 `raw/checkpoints` 时沿原采集链拒绝重写；`raw-native` 执行段仍是独立流。本批只有源码，未构建或实测。

退出：

```text
method: "controller.shutdown"
requestId: "quit-1"
params: {}
session: {"id":"<hello.session.id>","epoch":"<hello.session.epoch>"}
```

退出不接受 `expected`。若尚未 clean，返回真实状态并只接受查询和再次退出；保持进程及所有原 owner，直到恢复完成。

## REPL 命令

```text
help
status
pause execution/1 selected TOKENHEX,TOKENHEX
pause execution/2 all TOKENHEX,TOKENHEX,TOKENHEX
continue execution/3 selected TOKENHEX,TOKENHEX
continue execution/4 all TOKENHEX,TOKENHEX,TOKENHEX
step execution/5 into TOKENHEX
step execution/6 over-call TOKENHEX
step execution/7 out TOKENHEX
step-cancel execution/8 TOKENHEX
execution-range-add execution/9 ADDRESS BYTES TOKENHEX
execution-save execution/10 TOKENHEX
api-capture execution/11 SOURCE_PID SOURCE_FILETIME 3000 confirm REPLSESSIONTOKEN progress
quit
```

Save 使用唯一当前执行成员的完整 `replToken`；它与 JSONL 的 `stopToken` 保存请求等价。无项目时只控制，不产生执行段。

Pause/Continue 的 `TOKENHEX` 推荐复制同次当前成员输出的完整 `replSessionToken`，也兼容旧 `replToken` 列表；同一批次不能混用两种形状。多个票据使用逗号连接，不加空格。Step/Cancel/Range仍复制完整 `replToken`。Range的ADDRESS/BYTES与JSONL相同，使用规范正十进制整页范围。它们是完整 JSON 票据的 UTF-8 字节编码，不是历史索引；CLI 解码后核对与 JSONL 相同字段。旧 epoch、外来owner或旧事件不会因REPL位于当前CLI内而获得控制权。

## 清退与限制

`quit`、EOF、Ctrl-Break、输入/输出断开或处理异常均先关闭全组新操作准入，再逐成员调用原 `Close`，由原 owner 取消步进、恢复断点资源并恢复/脱离目标。未确认 clean 时不销毁成员，不将 summary 当作清退证明；仍存活的输入可查询或重试清退。无法确定的原生责任可能使 CLI 长期保留，强杀控制器不属于已提供的恢复机制。

单条输出保持正式 256 KiB 硬上限；完整线程/停止投影过大时输出明确超限诊断并进入原 owner 清退，不截断票据继续授控制。该限制与 16 进程上限同时存在。

本功能不提供跨进程原子继续、同刻冻结保证、自动系统/后代跟踪、同 PID 多站点或控制器死亡恢复。本命令的状态及票据只属于当前活会话，不能从历史 JSON 或停止文件重建 native owner。

## 双端 backend 接口

共享声明位于 `KswordCLI/ActionAnalyze/Control/OwnedExecutionGroup.h`，CLI、Qt、Light 正式工程均登记该 backend。调用方在已有串行 worker 持有整个对象：

```cpp
OwnedExecutionGroup group;
auto started = group.Start(std::move(explicitSites), true,
    NativeTargetDisposition::ResumeAndDetach, frozenSampleId);
auto current = group.Query();
std::vector<ExecutionGroupSessionEntry> sessions;
for (const auto& member : current.members) sessions.push_back({member.owner, member.control}); // 点击时冻结完整原成员表。
auto paused = group.Pause(sessions, true); // 精确Held记already-held，只对可暂停运行者动作。
// 后续Continue使用用户当时显示的新完整成员表，不复用Pause之前的旧停点。
auto result = group.Continue(displayedSessions, true); // Held才继续，明确运行者记already-running。
auto stepped = group.Step(displayedFullStop, NativeStepMode::Into);
auto cancelled = group.CancelStep(displayedFullStep);
auto added = group.AddRange(displayedFullNxStop, explicitAddress, explicitBytes); // 原成员原owner，不继续。
auto closing = group.Close(); // !closing.clean 时保留 group，继续 Query/Close。
```

双端推荐按值传递 `ExecutionGroupSessionEntry{owner,control}`；原 `span<const NativeControlResult>` 重载仍兼容完整旧列表，不按裸PID补票。`CanPauseMember`／`CanContinueMember` 用于混合范围按钮资格，须遍历全部明确成员；`Matches`／`MatchesStep`／`MatchesPause` 分别用于精确停点、步进和可暂停运行绑定，不用首行代表全体。页面草稿、当前选择与冻结 `site/condition` 分开，结果及操作回执以真实实例归属展示。

Qt「监控→行为分析→执行断点集合」在参数正文复用 `PrivateExecutionRangePane`，独立显示追加目标实例与停点；管理列表仍为 None 操作条，详情复用 `StructuredFieldView`。Light 同一集合页复用私有地址／范围字节草稿，由固定底栏“追加选中NX范围”提交；该动作只使用单选原成员control，不使用PID／模块／条件草稿来找目标。两端均走原串行worker，选择或查询不提交追加，失败保留草稿。新增集合范围追加当前为源码接线，未构建、运行或GUI验收。
