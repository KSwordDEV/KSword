# 第4、5、6项：失败验收缩减边界

## 2026-11-26 用户纠偏

用户指出 CodeBuddy 验收重复、任务可超过100分钟，批准当前失败任务继续，但要求核实探针必要性并减少约70%的非必要门禁。此授权替代先前暂停指令的范围仅为**已有失败任务**；不是所有新增功能、新专项或GUI验收的恢复授权。

不以删失败断言取得通过，不以改纯用户态夹具避开系统调用崩溃，不把429当作产品结论。主协调继续写产品，不接管测试执行。

## 本轮执行量

旧入口默认集合：原生步进16个场景、CLI步进7个、执行归档11个、内存CLI7个，再加独立执行核心整套，共42个顶层场景/套件。它们包含跨层重复验证；断言数不作为工作量或完成度。

缩减为12个顶层场景，计划减少约71%的默认场景执行量。**这是任务范围缩减，不是已经达到的耗时结果。** 保留旧测试源码供明确需要时选用，取消默认全跑及通过后重复整批。

| 范围 | 本轮保留 | 不再默认执行 |
| --- | --- | --- |
| 原生步进 | 线程退出、进程退出、运行中关闭、新线程资源恢复，共4项 | 其余12项已有路径；授权/未知指令/基本Into/Over/Out不跨层重复 |
| CLI步进 | fast、运行中cancel，共2项 | 已有条件、REPL、pair/data拒绝及另一个慢速正常完成场景；fast的真实0x80000004失败必须保留，cancel不能靠纯自旋绕开已知系统调用问题 |
| 执行归档CLI | native-save、history-read、failed-write，共3项 | 租约/帮助/重复身份形状/4096上限造档/第二套核心整批；在保留场景内核对真实DR0/Into、重放不执行及坏尾拒绝，合成correlate沿用已有对应范围证据，不认证新增协议 |
| 内存CLI | 字节往返、缺页部分结果、坏段导出拒绝，共3项 | 再跑311/359/87核心套件，帮助/文档逐条运行、相同类型输入负控遍历；保留一次错代次无读取检查和原raw不覆盖检查，不另开整套 |

## CodeBuddy 执行约束

- 同一持久会话只能一个运行实例；停止两路续跑同一会话、互相覆盖夹具。三个CLI验收串行复用同一正式CLI构建。
- 第一阶段仅定点裁剪现有入口和修正明确夹具类型错误；不新建总控框架、门禁清单、散列清单生成器或大型测试工程。
- 产品控制源仍在开发时不构建。主协调明确本批源码可验后，才进行一次适用增量构建；不得睡眠等待文件落稳、反复试编、修改TargetName或另复制运行时。
- 原生必要测试工程至多一次构建；正式CLI至多一次构建并由后续场景复用。明确编译缺陷或失败修复后只允许一次相关增量重试，不做无变化复验。
- 命名互斥只作真实串行化；等待最多30秒，忙则记录阻塞返回，不占用十几分钟等待。不新增探针、后台巡检或逐轮环境扫描。
- 每个场景执行一次。失败后只定位该失败；不重新跑所有已过场景。真实修复后只重跑失败场景，保留前后结果；无法定位则交付准确阻塞，不无限循环。
- 不读取整个巨大派发日志，不重复审查全部AGENTS、全部主题、全仓语言包或全部工程。沿用现有规范；仅处理所编辑入口的直接依赖。
- 每份最终回执只保留：本轮修改、实际命令、结果、适用产物身份、未通过项和本次创建内容的清理结果。不得因没有总结而重跑已经有完整日志的测试。
- 每次任务目标15分钟内给出结果或具体阻塞；不能为凑通过延长到100分钟。超过预算没有权限扩任务或自动派后续。
- 不运行Qt/Light GUI、驱动、Sysmon或用户进程；本次不涵盖新增私有执行/写转执行/同采样API协议的运行验收。

## 实际进度

本文件只确定缩减责任与默认范围。裁剪、构建和执行是否完成，分别由原CodeBuddy失败任务的续跑回执记录；未取得实际回执的项目保持待验。

### 2026-11-26 源码裁剪结果（仅改验收源码，未构建、未执行）

四个入口默认改为 `focused`，顶层场景共12个；旧场景函数与断言全部保留，改由 `--suite full` 显式执行。

| 入口 | 默认 focused 场景 | 数量 | 旧全量 |
| --- | --- | --- | --- |
| `KswordCLI/ActionAnalyze/Control/tests/NativeStepTests.cpp` | thread-exit、process-exit、close-while-running、new-thread-restoration | 4 | `--suite full`（16） |
| `tools/action_analyze_validation/cli/product_step_validation.py` | fast、slow-cancel | 2 | `--suite full`（7） |
| `tools/action_analyze_validation/cli/product_native_execution.py` | native-save、history-read、failed-write | 3 | `--suite full`（11） |
| `tools/action_analyze_validation/cli/memory_snapshot_cli.py` | roundtrip（含一次错代次无读取检查与一次原 raw 不覆盖检查）、gap、corruption | 3 | `--suite full`（7） |

- 三个 Python 入口新增 `--suite focused|full`（默认 focused）与 `--skip-build`（复用同一批次构建，仍报实际 CLI SHA）；命名互斥等待上限 30 秒，忙则直接返回阻塞。
- `NativeStepTests.cpp` 新增 `--suite` 与可重复 `--scenario`；`Invoke-NativeStepValidation.ps1` 转发 `-Suite`/`-Scenario`、一次构建一次执行，并移除重复传入的 `NativePrivateExecutionSite.cpp` 链接输入。
- 修正 `product_native_execution.py` 的 `history_read_case` 夹具类型错误：`document['instructionAddress']` 为十进制字符串，改为 `int(...)` 比较。
- slow-cancel 保留夹具原有良性系统调用等待（`g_block` 事件句柄），放行改用 `Set/ResetEvent`；纯用户态自旋不再是默认，只能用 `KSWORD_PRODUCT_STEP_SPIN=1` 显式选择。fast 的真实 0x80000004 未处理单步死亡场景未删除。
- 回执只写实际执行场景；失败不计入 PASS。

待 READY 后执行的 focused 命令（主协调确认 NativeDebugOwner 并行编辑完成后再构建并真测）：

```powershell
pwsh -File KswordCLI/ActionAnalyze/Control/tests/Invoke-NativeStepValidation.ps1 -Suite focused
py -3.12 tools/action_analyze_validation/cli/product_step_validation.py --suite focused
py -3.12 tools/action_analyze_validation/cli/product_native_execution.py --suite focused --skip-build
py -3.12 tools/action_analyze_validation/cli/memory_snapshot_cli.py --suite focused --skip-build
```

本阶段只完成入口裁剪与夹具修正，未构建、未运行，无通过结论。

### 2026-11-26 缩减批次实际执行（产品作者 READY 后）

旧全量场景数为原生 16 + CLI 步进 7 + 执行归档 11 + 内存 7 = 41；本轮计划执行 14 个顶层调用（原生 4 + CLI 步进 2 + 执行归档 3 + 内存 5），按 41→14 计约削减 66%（约 70%）。内存 focused 实际调用 5 个函数（roundtrip、错代次无读取、原 raw 不保留、gap、corruption），其中两个为 roundtrip 内保留的附加检查。第一轮实际执行 13 个（执行归档在 history-read 处中断，failed-write 未执行），补齐后计划内 14 个全部覆盖。

上一 CodeBuddy 本轮 dispatch 按日志登记为 04:00–04:05、约 261 秒。

| 入口 | 结果 | 实际场景 / 失败点 |
| --- | --- | --- |
| `Invoke-NativeStepValidation.ps1 -Suite focused` | 构建成功、运行 FAIL（checks=160 failures=2） | close-while-running、thread-exit、process-exit、new-thread-restoration 全部执行；失败集中在 thread-exit |
| `product_step_validation.py --suite focused` | 构建成功、fast 通过、slow-cancel 失败 | fast 通过；slow-cancel 在取消+放行后被调方崩溃 |
| `product_native_execution.py --suite focused --skip-build` | 第一轮失败（夹具错误）→ 修正夹具后通过，assertions=117 | 夹具错误两处：跨 ordinal 的 endOffset 单调断言、零 ordinal 拒绝要求 stdout 为空；修正后 native-save、history-read、failed-write 全部执行并通过 |
| `memory_snapshot_cli.py --suite focused --skip-build` | 通过（CHECKS=70 FAILURES=0） | roundtrip、错代次无读取、原 raw 不覆盖、gap、corruption |

产物身份：正式 CLI `SHA256=1531438135f3ad233f30c10f3dc7e8378db9e406741d47734228cc0a972f81d7`（本批次由入口 2 唯一增量构建，入口 3/4 以 `--skip-build` 复用）；原生步进验证 exe `SHA256=43E235181BF0E2576226525B309444B9AC061D94AA728F388F3FF487628E473A`。HostX64、BelowNormal、固定 IntDir/OutDir 与统一 Release 均沿用既有 wrapper。

失败项（保留，未删断言、未延长超时、未改夹具规避）：

1. **原生 thread-exit 的同伴线程未恢复**：`NativeStepTests.cpp::TestThreadExit`（第 844 行）在步进线程退出、原生事件释放（`!state.pending` 成立）后，`CountPeerTicks()` 为 0，`RequirePeerResumed` 以 `existing-peer-thread-scheduled-after-step`（win32=32）失败；同伴在调试前已确认在跑。属 owner 侧同伴恢复语义，需产品作者定位。
2. **CLI slow-cancel 在真实系统调用等待路径上崩溃**：被调方按原 `g_block` 事件阻塞于系统调用等待（非纯自旋）；`control.step.cancel` 生效（step 收据 cancelled、`resourcesRestored=true`），`control.continue` 放行后被调方线程恢复时跳到 `rip=0x0`，退出码 `0xC0000005`（marker：`EXCEPTION code=0xc0000005 rip=0x0 rsp=0xaba5eff630 slot-16=0x7ff7070319b1`，slot-16 即该步 destination）。CLI 侧干净退役（exit-event-continued、clean=true）。属取消路径的上下文恢复语义，需产品作者定位。
3. **执行归档 history-read 的两处夹具错误（非产品失败，已按产品契约修正）**：raw-native 每个 ordinal 是独立段文件，`endOffset` 是本文件字节位置，跨 ordinal 递增的是 `lastSequence`，文件长度不要求递增——已删除 `previous_offset` 与跨文件 `endOffset > previous_offset` 断言，保留 `endOffset == 段长度`、`sha256` 与段字节一致、`lastSequence` 严格递增、默认 ordinal=1 读取。零 ordinal 拒绝按 CLI 自身错误信封约定校验（退出码非零＋信封 `status=failed` 且诊断说明 `--ordinal must be a positive uint64`），不再要求 stdout 为空。

执行归档补齐运行（仅该入口一次，复用本批次正式 CLI `SHA256=1531438135f3ad233f30c10f3dc7e8378db9e406741d47734228cc0a972f81d7`，`--skip-build` 故 `build.skipped=true`、`exitCode=null`）：`py -3.12 -B tools/action_analyze_validation/cli/product_native_execution.py --suite focused --skip-build` → PASS，assertions=117，实际场景 native-save、history-read、failed-write，回执 `.codex-build-logs/action-analyze-native-execution-cli-20261126-050757-receipt.json`。本次只关闭夹具错误并执行此前未执行的 failed-write，未构建任何工程、未跑其它入口、未复验新增 follow/API 协议；复用当前产品源不等于新源码已验，本轮范围仍为旧验收范围。

本轮清理：删除本次运行创建并核对过的固定测试目录 `KswordCLI/x64/Release/MemorySnapshotCliValidation/`；未删除取证日志（`.codex-build-logs/` 本轮日志与原生步进 build/run/metadata 日志全部保留），未清理不明旧文件，未改动用户暂存，未提交版本库。

新增 follow/API 协议（`Control/NativeWriteExecutionTransition.cpp`，已由作者登记进 vcxproj）本轮不适用：原生 owner/步进仍按旧范围验收，仅在原生步进验证工程中补齐该源文件的链接输入。


