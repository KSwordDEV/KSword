# 第 10 项双目标条件：本机验收记录

日期：2026-11-26。本批只做测试夹具维护、构建、执行与落盘，不改产品源码，不做 GUI、驱动和 git 提交。验收对象是正式 `KswordCLI.exe` 的 `--cooperative-pair` 双目标条件路径：部分持有不求值、完整组按同一表达式逐成员求值、真条件保持整组、假/未知条件整组自动继续，以及自动继续与客户端继续序号、旧组令牌的关系。

## 1. 命令、退出码与产物身份

| 步骤 | 命令 | 退出码 | 结果 |
| --- | --- | --- | --- |
| 正式 CLI 增量构建 | `pwsh -NoProfile -File tools/Invoke-KSwordNativeBuildCheck.ps1 -Product CLI` | 0 | `BUILD_RESULT=SUCCESS` / `EXIT_CODE=0` |
| 新增定向模式 | `python -B tools/action_analyze_validation/cli/product_breakpoint_long_run.py --pair-condition --expected-cli-sha256 22f4046a402d504edd9220ba502c7999da103742776db85895d6f0958146d7e3` | 0 | `PAIR_CONDITION=PASS TRUTHS=true,false,unknown` |
| 既有条件寄存器回归 | 同上脚本 `--condition-registers --expected-cli-sha256 <同上>` | 0 | `CONDITION_REGISTERS=PASS` |
| 既有双目标回归 | 同上脚本 `--cooperative-pair --expected-cli-sha256 <同上>` | 0 | `COOPERATIVE_PAIR=PASS` |

构建读回的实际路径与主机（脚本在编译前打印并校验）：

```
IntDir=E:\Projects\Ksword5.1\KswordCLI\x64\Release
OutDir=E:\Projects\Ksword5.1\Ksword5.1\x64\Release
VC_ExecutablePath_x64=D:\Software\VS\VC\Tools\MSVC\14.44.35207\bin\HostX64\x64
Priority=BelowNormal
SHA256=22F4046A402D504EDD9220BA502C7999DA103742776DB85895D6F0958146D7E3
```

正式 CLI：`Ksword5.1\x64\Release\KswordCLI.exe`，SHA-256 `22f4046a402d504edd9220ba502c7999da103742776db85895d6f0958146d7e3`（小写同值）。三轮验收前后各读一次摘要，验收过程中该文件未被改写；测试脚本以 `--expected-cli-sha256` 在任何夹具启动前强制核对。

## 2. 首错记录

第一次运行 `--pair-condition` 退出码为 1，首错在**测试脚本自身**，不是产品行为：

```
RuntimeError: {'pid': 3488, ..., 'held': False, 'control': {'state': 'released', 'stage': 'continue-debug-event',
 'hit': {'address': '0x00007ff700b61000', 'tid': None}, 'stopGroup': {'state': 'released', 'historical': True},
 'release': {'result': 'continued'}}}
  at check_pair_condition_members (tools/action_analyze_validation/cli/product_breakpoint_long_run.py)
```

原因：脚本原先对三种真值共用“成员仍处于持有态”的断言。假条件与 RAX 未知条件由 CLI 自动继续整组后，原生待决事件已归还，客户端再读到成员快照时 `held=false`、`hit.tid=null`，断言因此误报。首错发生前真条件场景已完整通过（`PAIR_CONDITION_HOLD=PASS`、`PAIR_CLOSE=PASS`）。修正方式：持有态才核对命中线程 TID 与创建时间，自动继续后改为核对两份真实释放回执（`release.result=continued`）与逐成员原生组标识；未改产品源码。修正后同一正式 CLI 连续三轮全部通过。

## 3. 定向覆盖结果

夹具：`tools/action_analyze_validation/cli/product_breakpoint_child.c` 编译出的自有合作 EXE，两实例各跑 3 轮 `ExportedTick`。条件表达式随会话启动交给正式 CLI，`--cooperative-pair` 与 `--condition` 同时生效。

| # | 覆盖项 | 观察到的产品行为 | 结论 |
| --- | --- | --- | --- |
| 1 | 部分持有不求值、无令牌 | 仅触发一个成员时组状态 `held-partial`，成员持有集合 `[true,false]`；报告无 `stop`、无 `release`，`condition.last=null`，`trueCount/falseCount/unknownCount=0/0/0`，两个业务完成事件均未触发 | 通过（三个真值场景各一次） |
| 2 | 真条件双持有 | 两成员都命中后组状态 `held-complete`，`stop` 与 `condition.last` 同时发布，`action=hold`，逐成员 `truth=true`，`trueCount=2`（`falseCount=0`、`unknownCount=0`），`continued=false` | 通过 |
| 3 | 重复查询计数不变 | 保持期连续三次 `control.query`，三次 `trueCount/falseCount/unknownCount` 与 `condition.last` 完全一致（含 `stopId`、`stateRevision`、逐成员 `eventSerial`） | 通过 |
| 4 | 真条件继续 | `continue/1` 提交冻结组令牌，释放回执 `continued=true`、`stopId`/`stateRevision` 与判定一致、含 2 份成员回执；两份成员业务完成事件随后触发 | 通过 |
| 5 | 真条件旧令牌 | 用同一旧组令牌发 `continue/2`，返回 `errorId=stale-stop`（不是 `invalid-continue-sequence`，也不是 `release-replay-expired`） | 通过 |
| 6 | 假条件双自动继续 | 表达式 `stop.thread.rip > 0xffffffffu64 && stop.thread.creationFileTime < <会话前FILETIME>u64` 使两成员同为假：整组自动继续，`action=auto-continue`、`continued=true`，逐成员 `truth=false`，`falseCount=2`，两份成员释放回执 `continued`，成员自行执行并触发业务完成事件（无需客户端继续请求） | 通过 |
| 7 | RAX 未知双自动继续 | 表达式 `stop.thread.rip > 0xffffffffu64 && stop.thread.rax == 0u64`：本切片不采集 RAX，逐成员 `truth=unknown` 且 `evaluationFault=null`，`unknownCount=2`，整组同样自动继续并释放两份 | 通过 |
| 8 | 自动继续后客户端 `continue/1` 仍合法 | 自动继续后客户端首个 `continue/1` 序号校验通过（旧组令牌返回 `errorId=stale-stop`，不是序号错误），`true/false/unknown` 三个场景一致；再次查询时组已释放、报告无 `stop`、计数保持不变 | 通过 |
| 9 | 关闭双脱离、自有目标正常退出 | `controller.shutdown` 后 `reason=requested`、`endReason=requested`、`state=closed`、`clean=true`、无 `stop`、释放回执 `continued=true`；两名成员清退均为 `detached`（各自独立后端实例）、`breakpoint.state=retired`、`enrolledThreads=0`；脱离后自有目标仍能跑完剩余两轮并以退出码 0 正常结束 | 通过（三个真值场景各一次） |

各场景使用的表达式（`u64` 字面量与本次会话的真实 FILETIME 绑定）：

```
真值   stop.thread.rip > 0xffffffffu64 && stop.thread.creationFileTime >= 134401481602866506u64 && stop.thread.creationFileTime <= 134401482202866506u64
假值   stop.thread.rip > 0xffffffffu64 && stop.thread.creationFileTime < 134401481607129044u64
未知   stop.thread.rip > 0xffffffffu64 && stop.thread.rax == 0u64
```

真值场景额外用 `OpenThread`＋`GetThreadTimes` 独立核对命中线程的创建 FILETIME 落在表达式窗口内，确认 `stop.thread.creationFileTime` 是真实原生线程身份而不是补零。

## 4. 既有模式回归

- `--condition-registers` 退出码 0：非法表达式仍在启动前以 `expression-expected-literal at UTF-8 byte 18 ...` 拒绝；单目标真/假/未知三条件各自成立。
- `--cooperative-pair` 退出码 0：部分持有→完整持有→精确释放、旧令牌 `stale-stop`、关闭后双脱离，以及成员自然退出路径均未回归。

## 5. 证据日志

| 用途 | 路径 |
| --- | --- |
| 正式 CLI 构建输出 | `.codex-build-logs/behavior-planning/pair-condition-cli-build.log` |
| 首错（夹具断言误报）一轮 | `.codex-build-logs/behavior-planning/action-analyze-product-breakpoint-long-20261126-062823-422071-36688.log` |
| 新增 `--pair-condition` 通过轮 | `.codex-build-logs/behavior-planning/action-analyze-product-breakpoint-long-20261126-062918-132407-16176.log` |
| 既有 `--condition-registers` 轮 | `.codex-build-logs/behavior-planning/action-analyze-product-breakpoint-long-20261126-062931-673814-33844.log` |
| 既有 `--cooperative-pair` 轮 | `.codex-build-logs/behavior-planning/action-analyze-product-breakpoint-long-20261126-062937-674047-16736.log` |

日志逐帧记录 `TX`/`RX` 原文，含完整 JSONL 帧、组状态、逐成员原生快照、条件计数与判定，可直接复核上表每一行。

## 6. 清理

- 夹具 EXE `Ksword5.1\x64\Release\ActionAnalyzeProductBreakpointLongRun.exe`：每轮结束由 `installed_fixture` 删除，验收后确认不存在。
- 夹具中间目录 `KswordCLI\ActionAnalyze\Control\tests\x64\Release\ProductBreakpointLongRun`：每轮结束删除，验收后确认不存在。同级 `x64\Release` 下其余内容属于仓库既有其它测试工程产物，未改动。
- 自有目标进程：`ActionAnalyzeProductBreakpointLongRun` 与 `KswordCLI` 残留进程数为 0。
- 未写入系统临时目录、`output/`、随机 `runtime-*` 目录；编译与运行产物只落在工程固定 `IntDir`/`OutDir` 与统一 `Release`。
- 未做 git 提交，未修改产品源码；本批唯一改动的仓库文件是 `tools/action_analyze_validation/cli/product_breakpoint_long_run.py` 与本记录。

## 7. 未覆盖项

- ~~**混合真假（同一完整组内一真一假）的 `any-true-holds-group` 聚合**：本切片只有一条条件表达式，且必须在 CLI 启动前确定；两个成员的 PID 只在会话 `hello` 之后才可知，无法在启动前构造按成员区分的表达式。按任务授权明确记为未覆盖，未耗时追求。若后续需要覆盖，需要产品侧提供启动前可知的成员判别字段或按成员表达式入口。~~ 已由第 8 节的混合真假补测覆盖：条件表达式虽然仍只有一条且必须在启动前确定，但 `stop.thread.creationFileTime` 的取值是命中线程的真实创建时间，阈值只要落在两个命中线程的创建时间之间即可按成员区分，无需产品侧新增字段。
- 条件表达式非法、预算超限等输入侧行为由既有 `--condition-registers` 覆盖，本批未重复。
- 驱动、GUI 与真机视觉相关项不在本批授权范围，未执行。

## 8. 混合真假聚合补测（2026-11-26 第二轮）

本轮只补第 7 节第一条未覆盖项：同一冻结组内两个成员的真值恰为一真一假，验证 `any-true-holds-group` 的聚合语义。只用现有正式 CLI（不构建 CLI），产品源码一行未改。

### 8.1 命令、退出码与产物身份

| 步骤 | 命令 | 退出码 | 结果 |
| --- | --- | --- | --- |
| 混合真假定向模式 | `python -B tools/action_analyze_validation/cli/product_breakpoint_long_run.py --pair-condition-mixed --expected-cli-sha256 22f4046a402d504edd9220ba502c7999da103742776db85895d6f0958146d7e3` | 0 | `PAIR_CONDITION_MIXED=PASS TRUTHS=true,false AGGREGATION=any-true-holds-group` |

本轮只为该分支构建一次自有夹具；既有 `--pair-condition`、`--cooperative-pair`、`--condition-registers` 模式按要求未重跑。

夹具构建读回（脚本在编译前打印并校验）：

```
IntDir=E:\Projects\Ksword5.1\KswordCLI\ActionAnalyze\Control\tests\x64\Release\ProductBreakpointLongRun
OutDir=E:\Projects\Ksword5.1\Ksword5.1\x64\Release
HOSTX64=D:\Software\VS\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe
Priority=BelowNormal
```

正式 CLI：`Ksword5.1\x64\Release\KswordCLI.exe`，SHA-256 `22f4046a402d504edd9220ba502c7999da103742776db85895d6f0958146d7e3`，与首轮同一文件。脚本在夹具启动前强制核对该摘要，并在验收结束再次读回确认未被改写。

### 8.2 首错记录

第一次运行 `--pair-condition-mixed` 退出码为 1，首错在**测试脚本自身的断言**，不是产品行为：

```
RuntimeError: ({'address': '0x00007ff78c3c1000', 'tid': 27700},
                134401487478278618, 134401487478069671, 134401487578069671)
  at pair_condition_mixed_regression (tools/action_analyze_validation/cli/product_breakpoint_long_run.py)
```

原因：脚本原先用「初始线程 TID 等于进程 PID」这一常见假设确认首成员命中的是主线程，而本机该成员的 PID 为 35464、命中线程 TID 为 27700，两者并不相等；脚本自己的 `OpenThread`＋`GetProcessIdOfThread` 已确认该命中线程确实属于该成员（PID 35464），且其创建 FILETIME 与进程创建时间仅差 10 个 tick。修正方式：改用「命中线程创建时间与进程创建时间的量级关系」判定初始线程与后建线程，不再依赖 TID 与 PID 相等；产品源码未改。首错发生前第一成员已按预期停在原生事件上，组仍处于 `held-partial`、尚未求值。

### 8.3 该分支的实现方式

条件表达式仍只有一条，且必须在 CLI 启动前交给正式 CLI；可用的按成员区分来自 `stop.thread.creationFileTime` 取的是**命中线程的真实创建时间**：

- 阈值在会话启动前冻结：`THRESHOLD = 启动时刻 FILETIME + 10 s`。
- 第一成员由**进程初始线程**命中：其创建时间与进程创建时间同量级（实测相差 9 tick），必然早于阈值 → 判真。
- 第二成员由**阈值之后新建的线程**命中：夹具新增仅测试模式，本成员存在 `spawn` 事件时每轮命中点由新建线程执行；测试在越过阈值加 2 s 余量后才触发该成员，因此命中线程创建时间必然晚于阈值 → 判假。
- 规则表达式：`stop.thread.rip > 0xffffffffu64 && stop.thread.creationFileTime < <阈值>u64`。

夹具改动只在自有测试源 `tools/action_analyze_validation/cli/product_breakpoint_child.c`：新增 `TickFromNewThread` 与「存在本成员 `spawn` 事件时由新建线程执行命中点」的分支。没有新增产品字段，没有硬编码 PID，没有改正式 CLI。

### 8.4 覆盖结果

实测身份与判定（本次运行的真实数值）：

| 项 | 值 |
| --- | --- |
| 启动时刻 | `134401488007009635` |
| 冻结阈值 | `134401488107009635`（启动后 10 s） |
| 第一成员 | PID 23312，进程创建 `134401488007173338`，命中 TID 23880，命中线程创建 `134401488007173347` |
| 第二成员 | PID 36360，进程创建 `134401488007187928`，命中 TID 36076，命中线程创建 `134401488127390489`（启动后约 12.04 s） |

| # | 覆盖项 | 观察到的产品行为 | 结论 |
| --- | --- | --- | --- |
| 1 | 部分持有不求值 | 只触发第一成员时组状态 `held-partial`，成员持有集合 `[true,false]`；报告无 `stop`、无 `release`，`condition.last=null`，`trueCount/falseCount/unknownCount=0/0/0`，两个业务完成事件均未触发 | 通过 |
| 2 | 同一冻结组一真一假 | 第二成员命中后组状态 `held-complete`，`condition.last` 发布，逐成员 `truth` 为 `["true","false"]`（第一成员主线程真、第二成员新线程假），`trueCount=1`、`falseCount=1`、`unknownCount=0`，`action=hold`、`continued=false`，`aggregation=any-true-holds-group`，`evaluationFault` 均为 `null` | 通过 |
| 3 | 组仍双持有 | 假成员没有让整组自动继续：两个成员的 `held` 仍为 `true`，各自原生 `stopGroup.state=held-complete`，组令牌 `stop` 与判定同时发布 | 通过 |
| 4 | 重复查询计数不变 | 保持期连续三次 `control.query`，三次 `trueCount/falseCount/unknownCount` 与 `condition.last` 完全一致（含 `stopId`、`stateRevision`、逐成员 `eventSerial`） | 通过 |
| 5 | 显式继续释放两成员 | `continue/1` 提交冻结组令牌，释放回执 `continued=true`、`stopId`/`stateRevision` 与判定一致、含 2 份成员回执且两份均为 `continued`；两份成员业务完成事件随后触发 | 通过 |
| 6 | 旧组令牌 | 用同一旧组令牌发 `continue/2`，返回 `errorId=stale-stop`（不是 `invalid-continue-sequence`，也不是 `release-replay-expired`） | 通过 |
| 7 | 关闭双脱离、自有目标正常退出 | `controller.shutdown` 后 `reason=requested`、`endReason=requested`、`state=closed`、`clean=true`、无 `stop`；两名成员清退均为 `detached`（各自独立后端实例）、`breakpoint.state=retired`、`enrolledThreads=0`；脱离后自有目标仍能跑完剩余两轮并以退出码 0 正常结束 | 通过 |

独立复核：脚本用 `OpenThread`＋`GetThreadTimes` 读取两个命中线程的真实创建 FILETIME，并要求第一成员与进程创建时间相差小于 1 s、第二成员比进程创建时间晚 1 s 以上且晚于阈值，阈值两侧的真实线程身份与产品给出的 `true`/`false` 逐成员一致。第二成员释放回执帧中 `enrolledThreads=2`，说明后建线程确由原生所有者登记后命中。

### 8.5 证据日志

| 用途 | 路径 |
| --- | --- |
| 首错（夹具断言误报）一轮 | `.codex-build-logs/behavior-planning/action-analyze-product-breakpoint-long-20261126-063905-593945-33932.log` |
| 混合真假通过轮 | `.codex-build-logs/behavior-planning/action-analyze-product-breakpoint-long-20261126-063958-687239-34276.log` |

日志逐帧记录 `TX`/`RX` 原文，含完整 JSONL 帧、组状态、逐成员原生快照、条件计数与判定，可直接复核上表每一行。

### 8.6 清理

- 夹具 EXE `Ksword5.1\x64\Release\ActionAnalyzeProductBreakpointLongRun.exe`：每轮结束由 `installed_fixture` 删除，验收后确认不存在。
- 夹具中间目录 `KswordCLI\ActionAnalyze\Control\tests\x64\Release\ProductBreakpointLongRun`：每轮结束删除，验收后确认不存在；首错轮同样已清理。
- 自有目标进程：`ActionAnalyzeProductBreakpointLongRun` 与 `KswordCLI` 残留进程数为 0；系统临时目录无相关残留。
- 未写入系统临时目录、`output/`、随机 `runtime-*` 目录；编译与运行产物只落在工程固定 `IntDir`/`OutDir` 与统一 `Release`。
- 未做 git 提交，未修改产品源码；本轮改动的仓库文件是 `tools/action_analyze_validation/cli/product_breakpoint_child.c`、`tools/action_analyze_validation/cli/product_breakpoint_long_run.py` 与本记录。

### 8.7 本分支结论

第 10 项的混合真假聚合已在正式 CLI 上实测通过：同一冻结组内逐成员求值得到恰为一真一假，`any-true-holds-group` 保持整组双持有，重复查询不重复计数，显式 `continue/1` 释放两成员，关闭后两成员正常脱离且自有目标以退出码 0 结束。产品侧未新增任何字段或按成员表达式入口：按成员区分只依赖既有 `stop.thread.creationFileTime` 与启动前冻结的阈值，阈值两侧分别是进程初始线程与阈值之后新建的线程。

仍未覆盖：产品侧（Qt／Light）尚无多目标条件绑定入口，本轮结论只覆盖正式 CLI 的 `--cooperative-pair` 条件路径；GUI 实测与完整 C# 表达式面仍按验收清单第 10 行的边界保留。

