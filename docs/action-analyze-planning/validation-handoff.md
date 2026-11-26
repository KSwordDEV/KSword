# ActionAnalyze 验收交接

在 `E:/Projects/Ksword5.1` 的当前 `ActionAnalyze` 工作树运行。桌面改动在工作树里，验收从现有改动构建。先读根目录 `AGENTS.md` 和共享记忆。使用自有夹具和正式 Release。保留现有源码、暂存内容及用户配置。

**验收模型将结论直接追加到 [`validation-results.md`](validation-results.md)**。开始时在结果文件新建本轮记录，完成或遇到阻塞时填写相应项目。聊天只需回复写入的文件路径。验收以读源码、构建、运行和落盘回执为范围。源码修复、提交、推送及产品进度变更交回开发方。

后续按交付批次指定待验项目编号和正式门槛。转交提示词见 [70% 路线图](roadmap-70.md#转给验收模型的提示词)。

## AA-03M 自有 API 与 ETW 同采样

本机只采一次：正式 CLI 打开自有目标和其显式授权的本地 API 归档，同时订阅 KSword 私有 ETW 提供程序，然后停止并重开同一个采样。记录 `raw` 与 `raw-etw` 各自的首条观察、段摘要、记录数与来源丢失分项。分别用 `archive.inspect` 图视图回查，不按段号或序号把两路事件关联。API 声明不等于实时连接；若 API 包由夹具生成，登记为合成输入，不能记为真实 Agent 混采。

Qt「监控 → 行为分析 → 总览」和 Light「监控 → ActionAnalyze」只读重开该 CLI 项目，在独立非输入桌面分别使用 API、ETW 筛选核对两条坐标和同一采样 ID。不得重跑已有单来源矩阵。桌面只读通过不代表桌面也能启动混采。

## AA-01 桌面归档证据区

入口为 Qt「监控 → 行为分析 → 总览」和 Light「监控 → ActionAnalyze」。代码复用原有的底部证据区、选中行和详情，两端按类型化原始记录显示候选或上下文。

1. 通过 `tools/Invoke-KSwordBuildCheck.ps1` 构建 Qt 主程序。按根 `AGENTS.md` 的规范，以 HostX64、Release/x64 和 BelowNormal 构建 `KswordARKLight/KswordARKLight.vcxproj`。记录实际 `IntDir`、`OutDir`、退出码和受测 EXE SHA-256。主程序构建中的语言包与主题门禁分别记录。
2. 通过独立非输入桌面运行下列命令。API 跟随脚本检查 Qt 底部标签和 Light 详情标签。跨客户端 ETW 脚本检查 Light 详情中的来源上下文。Qt 的 ETW 标签使用同一项目和隔离桌面桥观察。

   ```powershell
   python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/archive_api_follow_preview.py
   python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/archive_etw_preview.py --cross-client
   ```

3. 两端在正式项目中用鼠标和键盘选中 API 线索。预期底部出现 `未解析候选 · raw/3 #9`，详情原始段号、记录序号和源行 `6` 与同一行一致。缺失第 2 段或第 3 段损坏时，只允许显示各自已核验的前缀。修复后重新定位。切换采样时检查旧坐标消失，筛掉已选记录时检查详情仍指向原记录。
4. 在 ETW 项目选中一条可解码的归档 ETW 记录。预期显示 `来源上下文 · raw/<段号> #<序号>`，坐标与详情一致。可选取网络档的已解码流验证相同标签。检查普通不透明记录、无选择和实时窗口的证据状态。检查已有规范事件的对象引用、菜单和详情操作。
5. Qt 覆盖浅色、深色、窄窗、DPI 和长文字。Light 窄窗底图收起时，从可聚焦详情验证同一标签。报告实测组合、范围和环境限制。窗口退出后记录配置恢复和本轮夹具清理。

## AA-02 CLI 网络完整字节查询

已有 HostX64 Release 及正式 JSONL、REPL 回执。若在本轮改动上需要连带复验，先按根规则构建 `KswordCLI/KswordCLI.vcxproj`，然后运行以下命令。隔离桌面脚本依赖统一 Release 中现有的 `KswordARKLightStoredEvidenceValidation.exe`，缺少时按同样的 HostX64 规范构建 `KswordARKLight/Features/ActionAnalyze/tests/StoredEvidenceValidation.vcxproj`。

```powershell
python -B schemas/action_analyze/vectors/validate-request.py
python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/qt/archive_network_preview.py
```

预期有 58 项归档请求与响应向量通过，JSONL 和 REPL 同样返回 300 字节，保留 IPv6 入站元数据。元数据档的字节串为空，坏块前仍可读至 5922 字节。错误坐标、缺记录和损坏目标块应分别返回对应错误。Qt 独立归档回放依次显示 9、7、7 行。既有回执在 `.codex-build-logs/action-analyze-qt-cli-network-project-current.log`。

## AA-03 CLI 合作目标入口与来源就绪

以 HostX64、Release/x64 和 BelowNormal 构建 `KswordCLI/KswordCLI.vcxproj`。使用统一 `Release` 中的正式产品 Agent。验收对象为自行装载产品 Agent 的自有合作目标，采集期间由该目标执行可计数的普通本地 API 调用。例如让目标调用 `WriteProcessMemory`，只写其进程里预先分配的自有缓冲区，并记录实际调用次数。用现有项目命令创建验收项目，使用 `process detail basic query --pid PID --json` 核对目标的创建 FILETIME。

```text
KswordCLI.exe help analyze api-evidence capture
KswordCLI.exe analyze api-evidence capture --project PROJECT --title TITLE --pid PID --creation-filetime FILETIME --confirm --duration-ms 3000 --json
KswordCLI.exe analyze api-evidence replay --project PROJECT --sample SAMPLE_ID --packet 1 --json
```

1. 记录 `residentVerified`、`connected`、`agentReady`、`sourceSessionIdentity`、`completedInterval`、`cleanupComplete` 和覆盖状态。按已安装的目标 API 钩子对账指定调用及留存线索，比较首条已回读的段号、记录序号、源序号和完整原包。按退出回执记录部分覆盖或来源丢失。
2. 用未装载 Agent 的自有目标和错误创建 FILETIME 验证拒绝。再对持有正式 Agent 的自有目标分别在采集中取消和正常退出，核对回执、已录下的证据和可观测的清退状态。记录进程、配置及测试目录清理结果。
3. 定向复跑 `python -B tools/action_analyze_validation/cli/passive_api_session.py` 的被动跟随路径。在同一冻结身份的输入中核对 `HooksInstalled` 声明、普通 API 包与 `firstRaw`。补查无匹配的完整截止和截断边界，核对 `attached`、`observed`、`stopped-no-match`、`source-interrupted` 及独立的 `producerConnection=unknown`。使用现有夹具生成器构造输入，按所测范围登记结论。
4. REPL 通过 `help open` 和 `open PID CREATION_FILETIME api=SESSION_ID "ARCHIVE" authorized "TITLE"` 打开同一输入，再用 `status`、`stop`、`close` 查回执。核对 JSONL 与 REPL 的计数、首条原始坐标及停止语义。缺少授权字面量时拒绝打开。

本机 AMD64 合作目标通过 `py -3.12 -B tools/action_analyze_validation/cli/cooperative_api_capture.py` 完成就绪与有界采集。`--identity-negative` 通过错误进程代次及未装载 Agent 拒绝回执。两个模式共享固定夹具目录，须串行。该入口不做自动注入或修改系统共享目录 ACL；部分 Hook 的覆盖范围以原回执为准。

同一脚本 `--behavior` 核对真实访问拒绝：目标仅请求自己进程的查询权限，确认写操作返回 `FALSE`／Win32 `5`、缓冲区不变。运行中只读 CLI 核对已提交前缀；停采后同时核对累计规则、规则回放、归档图及完整原包坐标。成功调用无拒绝释义。这个模式也占用同一固定夹具目录。

正常退出和取消：本机 `python` 已指向 3.12，分别串行运行 `python -B tools/action_analyze_validation/cli/cooperative_capture_lifecycle.py --case target-exit` 与 `python -B tools/action_analyze_validation/cli/cooperative_capture_lifecycle.py --case cancel`。两例须先看到安装成功和至少两条已读普通包；停止后逐字节回读这些原包。取消只向已确认的独立控制台内自有 CLI 进程组发信号，并验证目标仍存活。

新版 CLI 由验收子代理通过 CodeBuddy 调用 `pwsh -NoProfile -File tools/Invoke-KSwordCliBuildCheck.ps1`。取消用例同时检查配置发布、`SessionReady`、安装、停止标记、停钩、包边界 EOF 及实际采集时长。归档 `archiveSource=cooperative-pipe` 时，源序号是普通包流水号；和旧档的回放坐标分别记录。

同一正式 CLI 的只读线程前置：运行 `python -B tools/action_analyze_validation/cli/memory_stream.py --observe-threads`。定向模式复用现有自有目标，发送 `stop` 前观察同一 TID 与创建时间由 `newly-observed` 到 `exited`。核对实际字节轮的 `threadObservation`、`previousThreadObservationRound`、终态和目标正常清理。枚举失败的续持逻辑不在此用例的成功路径内；不计入实际断点验收。

同一样本三端正式回读：`py -3.12 -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/cooperative_archive_replay.py`。CLI 核对完整自写原包，再让 Qt 与 Light 重开同一项目并核对各自可见的原包前缀。该脚本也使用上述固定目录，须串行；不验桌面实时接入、取消或混采。

归档来源改动不新增页面。入口是 Qt「监控 → 行为分析 → 总览／项目与采样」的 `StructuredFieldView`、「行为规则」的 `CodeEditorWidget` 回执，以及 Light「监控 → ActionAnalyze」的原生记录详情。合作档仅在整段通过后显示归档来源和合作流水号；规则报告使用同一流水号。关闭 JSONL 仍用文件行号，旧档无新来源标签。只更新合作正例的既有夹具断言。坏尾重读须保留此前已核验的详情；Qt 主程序仍在运行时，不启动窗口、不结束现有进程。

Light 正式增量入口为 `pwsh -NoProfile -File tools/Invoke-KSwordNativeBuildCheck.ps1 -Product Light`。仅从统一 `Release` 读取现有内嵌资源，不构建、签名或加载驱动。

### 桌面直连合作 Agent

Qt 从「监控 → 行为分析 → 总览 → API 采样」显式选择「合作 Agent」。此入口是原参数执行页，继续复用 `ParameterWorkspace`、固定图标动作、共享分段控件及 `StructuredFieldView`。默认仍为 JSONL，切换来源保留文件草稿，不启动任务。Light 使用现有「监控 → ActionAnalyze」实时 API 入口与原生状态区。两端各持本端工作线程和项目租约，输入冻结到实际 PID、创建 FILETIME 与项目修订。只从同用户专用目录连接已主动加载的 Agent，就绪后最多 120 秒；手动停止只停止本轮。

按用户顺序开放桌面实测后，将两个桌面端的相关改动各做一次正式构建，并在独立非输入桌面复用 `cooperative_api_capture.py --behavior-target` 的自有样本。确认显式开始、同会话就绪、采集中首段和后续段水位、累计规则、停止及归档。回读同一采样的失败和成功原包，核对树增量、筛选后定位和切换采样。停钩、干净 EOF、目标退出与清退分别核对；停止后自有目标仍活。复用已有启动与旧归档验收，不重跑 ETW 长档。存在用户窗口时保留原进程。

Qt 定向入口：`python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/qt/live_cooperative_api.py`。在新版正式 Qt 构建成功、旧主程序退出且无活动驱动服务后由 CodeBuddy 运行。检查 `QT_LIVE_COOPERATIVE_API=PASS`：Qt 采样与停止、CLI 完整原包及规则、Light 只读回放须对上同一 UUID 和停止前原包，最后确认窗口／目标退出、设置恢复和固定夹具清理。不重复采集旧的 Light 或 CLI 正例。

Light 定向入口：`python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/live_cooperative_api.py`。上述正式 Light 的 `LIGHT_COOPERATIVE_API=PASS` 已登记；Qt 验收无需重跑这一轮。

## AA-04 Qt 与 Light 同采样归档关系浏览

沿用 AA-01 的正式构建、隔离桌面和两套已知归档。项目内至少保留两次采样，用来核对切样行为。每端独立记录构建和实际 GUI 结果。

1. 在 Qt 总览底部展开「归档关系」。用方向键移动到 `raw/3 #9`，分别用 Enter 和双击打开。表格、瀑布及详情应定位同一条记录，源行是 `6`。Light 依次使用「关系分组」「组内记录」「定位」。用键盘和鼠标分别定位相同坐标及组内一条非最新记录。用 ETW 样本核对来源上下文到原始记录的对应关系。
2. 筛掉目标原始行，先选中另一条可见行，再激活被筛掉的关系记录。详情应切到目标原始坐标，旧高亮应清除，筛选应保留。清除筛选后，同一坐标重新成为可见选中行。Light 用 AA-01 的四段跟随脚本复验，关键字 `8` 只保留 `raw/3 #8`（源行 `5`），再定位组内的 `raw/3 #9`（源行 `6`）。Qt 的桥可读分组和叶项，但 `select_row` 不会激活树叶；Qt 的 Enter／双击和筛后关系定位仍需在真实窗口验证。
3. 切换采样、读入缺检查点或坏尾、再修复重读。新的读取应按实际核验范围呈现。Qt 重读同一完整快照失败时沿用上一次完整结果，同时显示本次失败范围。用另一采样或首次打开坏档验证较短前缀。核对旧标签、对象引用及菜单仍可用。Qt 检查深浅主题、双语、窄窗与实际缩放。Light 检查窄窗可用性和键盘焦点。

已有四段同采样基线：`718d8a79-eefd-42a5-acdc-1deffbef3378` 在非输入桌面通过 `QT_RELATION_GROUP`、`LIGHT_RELATION_LOCATE` 和两端 `2/4/6` 归档回放。两端均退出 `0`，配置恢复，固定夹具已清理。日志：`.codex-build-logs/action-analyze-aa04-codebuddy.json`。基线中的 Qt 原始坐标由表格选行对账，不计为关系树定位。

筛后定位补验：通过 CodeBuddy 精确授权执行 AA-01 第一条命令一次，新采样 `be2657c6-c502-40e5-93df-896190fafa50`。非输入桌面回执 `LIGHT_RELATION_FILTERED_LOCATE=PASS`：从可见的 `raw/3 #8` 切到隐藏的 `raw/3 #9`，筛选保持且旧高亮清除；清空关键字后六条 API 恢复，`#9` 再次选中。此次 `QT_RELATION_GROUP`、`LIGHT_RELATION_LOCATE` 和两端 `2/4/6` 也通过；两端退出 `0`，配置恢复，固定夹具已清理。Qt 关系激活未覆盖。

## AA-05 CLI 项目行为规则回放

复用 AA-03 的 CLI 产物，或按同一固定输出构建。使用当前验收项目的完整 API 导入样本和多段跟随样本。

```text
KswordCLI.exe help analyze replay-api-rules
KswordCLI.exe analyze replay-api-rules --project PROJECT --sample SAMPLE_ID --json
KswordCLI.exe analyze replay-api-rules --project PROJECT --sample SAMPLE_ID --profile by-category --limit 1 --json
```

1. 检查汇总及五类细分的规则 ID 和原始坐标。用 `nextOffset` 遍历细分页，并和 CLI `api-evidence replay` 或归档图的同一原包对账，确认无重复和漏项。
2. 对多段跟随样本检查跨段命中。移走一个中段检查点，再单独损坏中段，预期 `verified-prefix-only`、退出码 `6`、首个未核验段和之前的有效命中。恢复后应与原结果一致。
3. 首段缺失、错采样、导入尾记损坏或非 API 档应报告具体错误。已核验的空输入应保留归档范围并返回空命中。采集覆盖使用 `unknown`。

三端同一合成样本的行为正负例使用 `py -3.12 -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/behavior_rule_replay.py`。只在带明确失败返回标记的 `raw/3 #9`（源行 `6`）显示访问拒绝释义；状态同为 `5` 的 `raw/2 #5`（源行 `3`）缺返回标记，只保留分类。窗口从现有规则回放和详情入口核对，不使用合成数据证明实际写入、调用意图或活采。

## AA-06 CLI 实时回环网络元数据归档

复用 AA-03 的 CLI 产物，或按同一固定输出构建。准备自有回环通信目标、回环服务和另一自有进程。目标在采样期间分别经过 IPv4 和 IPv6 回环发送并接收数据，另一进程提供对照流量。

```text
KswordCLI.exe process identity query --pid PID --json
KswordCLI.exe analyze network-capture --project PROJECT --pid PID --create-time FILETIME --duration-ms 5000 --authorize-loopback yes --json
```

1. 核对原生启动、停止和关闭回执。支持的环境应得到新采样、`segmentVerified:true` 及非空记录。若本机不能生成或启用指定 PID 和事件筛选，记录失败阶段和 Win32 错误，确认项目未新增采样。
2. 在正式 CLI 重开项目，使用回执中的坐标调用 `archive inspect SAMPLE_ID raw 1 network SEQUENCE RECORD_OFFSET`。比对当前目标的 PID、创建时间、双栈端点、收发方向和计数。核对另一进程的流量未进入结果。`payloadState=metadata-only`、`capturedLength="0"`、`bytesHex=""`。
3. 重试错误创建时间、缺授权和取消，记录是否产生采样、已保留前缀、清退结果及日志。验收范围为回环流元数据。

## AA-07 CLI 合作目标条件断点

复用 AA-03 的 CLI 产物，或按同一固定输出构建。使用 `tools/action_analyze_validation/cli/product_breakpoint_long_run.py` 所用的自有 `ExportedTick` 合作子进程，每个条件各起一轮。等待夹具就绪和 `breakpoint.state=armed` 后触发一次调用。

| 参数 | 通过条件 |
| --- | --- |
| `--condition 'stop.tid > 0u64'` | 核对 `condition.last.truth=true` 和真实 `stop`。夹具尚未完成该次调用。用 `continue/1` 及原停止 ID 和修订继续，观察释放及夹具完成。 |
| `--condition 'stop.tid == 0u64'` | 触发后先等待夹具完成，再发查询。应读到 `false`、`release=continued`、无活动停点。 |
| `--condition 'stop.thread.rax == 0u64'` | 同样先等夹具完成。应读到 `unknown`、`evaluationFault=null`、`release=continued`、无活动停点。 |
| 省略条件 | 核对原来的停止令牌和人工继续，回执省略 `condition`。 |
| `--condition 'stop.tid =='` | 验证启动子进程前退出，退出码 `1` 并输出 UTF-8 字节诊断。 |

每轮正常退出后核对 `control.clean=true`、`control.attached=false`，记录夹具和配置清理结果。保留 JSONL 状态、一次 REPL 查询及退出回执。

冻结 RIP 的回归使用 `py -3.12 -B tools/action_analyze_validation/cli/product_breakpoint_long_run.py --condition-registers`。它用高 32 位非零的地址区分正、负条件，验证缺失 RAX 的未知结果及启动前字节位置。正式本机结果已登记，后续只有相关源码变化才复跑。

## AA-08 三端项目规则回放

使用 AA-05 的四段跟随夹具。Qt 在「监控 → 行为分析 → 项目与采样」选择同一采样，点击「回放采样规则」，在「行为规则」查看报告。Light 在「监控 → ActionAnalyze」打开该项目、回放该采样并选中 API 记录。两个窗口均在独立非输入桌面。

1. 对账 `raw/3 #9`、源行 `6` 的 `WriteProcessMemory`。Qt 报告及 Light 原有详情应显示 `ksword.api.memory-operation-observed.v1` 和 `ksword.api.memory-write-observed.v1`。与 CLI `replay-api-rules` 的两种预置比较。采集覆盖仍为未知。
2. 用另一个采样或先移走第 2 段检查点再首次打开，确认结果只包含首段。单独截断第 3 段应只包含前两段。修复后重新读取并对账 6 条。核对 Qt 规则草稿和上次成功报告在无可用输入或取消后仍在，Light 筛掉选择时保留该记录详情，切样则引用新采样。

## AA-09 CLI 已提交分段的实时规则回执

使用 AA-03 的被动归档输入与 AA-05 的规则回放对账。通过原有跟随夹具逐批追加，等检查点发布才读取 `rules`。冻结的版本应为 `ksword.api.behavior-presets.v1`。三批各两条线索应得到累计 `2 / 4 / 6` 条，终段保持末次 `raw/3 #9`、源行 `6` 和细分规则 ID。暂停追加时重复 `session.query`，确认累计数不变。用读取失败用例确认已提交命中仍在。REPL `status` 与 JSONL `session.query` 同字段。结束后用 AA-05 回读末次命中。

## 三端同一 180 秒 ETW 档

通过 CodeBuddy 在正式产物空闲后执行 `python -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/archive_etw_preview.py --cross-client-long`。复用 CLI 的 180 秒自有 ETW 生产、逐段回读和测量，再让 Qt 和 Light 串行打开同一项目。两端对账终段水位、最近 4,096 条窗口的首尾坐标、窗口内实际 ETW 行数和同一末观察；不要求把完整归档加载到可见窗口，不重复短档故障用例。`CROSS_CLIENT_LONG_ETW=PASS` 在两端退出、配置恢复及固定项目清理后才输出。该用例核对正式 CLI 哈希，运行期间不重新链接共享产物。

## AA-10 KSword 自有线程创建证据

原 Sysmon 方案取消。历史回执只记录当时实验，不作为产品验收；不安装、不查询、不订阅 Sysmon，不将其归档作为三端产品数据。移除后用现有合成项目确认旧格式不会作为普通记录显示，且原档未改动。

自有路线复用 KSwordARK Callback Monitor 的线程创建记录与现有 `ArkDriverClient`，普通 R0 仍只在指定且通过准入的来宾运行。v1 核对回调序号、原始位置、创建上下文与目标的 PID/TID、漏失及覆盖；它没有实例创建时间，不产生强实例、写入或执行结论。R3 路线独立验证 KSword 用户态采集，不以外部日志补齐缺失身份。完成归档接线后，再由三端回读同一份自有样本。

已通过的合成回读：先用 `py -3.12 -B tools/action_analyze_validation/cli/callback_archive_graph.py --create-fixture` 生成固定项目并验 CLI，随后用 `py -3.12 -B tools/action_analyze_validation/isolated_desktop.py tools/action_analyze_validation/light/callback_archive_gui.py` 验同一项目的 Qt 和 Light。三端均完成非空、完整空及计数冲突判别。本轮固定项目已清理；重跑时重新生成。真实驱动回调采集仍待验。

## 报告写法

每个项目填写通过、失败、阻塞或未执行。附实际命令、退出码、日志相对路径、受测源码差异范围、产物哈希、采样和原始坐标。失败时保留首个有用错误和复现条件。下一轮采用同一文件追加记录。

## 本轮转交提示词

> 在当前 `ActionAnalyze` 工作树验证 AA-03、AA-04、AA-08 及 AA-09 尚未覆盖的项目。使用统一 Release 与自有夹具。AA-04、AA-08 在独立非输入桌面复用同一个项目和采样。复用已通过的 AA-05、AA-07 和 AA-09 定向结果。AA-06 正例仅在具备原生 ETW 权限时运行；AA-10 只验 KSword 自有来源，不执行旧 Sysmon 方案。将退出码、日志路径、产物 SHA-256、采样坐标和清理结果追加到 `validation-results.md`。
