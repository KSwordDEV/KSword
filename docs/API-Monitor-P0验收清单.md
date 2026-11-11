# API Monitor P0 验收清单

本清单记录本会话确定的 P0 范围，以及 2026-11-02 开始本轮工作时可见的证据和缺口。**下列历史证据不等于本轮通过**；执行完成后必须逐项补充构建身份、实际命令、数据和结论。所有系统进程实验仅在指定 Windows10-20H2 来宾中进行，禁止附加宿主机 DWM。

## 证据记录要求

- 记录源码提交及未提交差异、构建时间、exe 与两种位数 Agent 的 SHA-256，记录来宾系统版本、机器名、目标 PID、创建时间、位数与配置。每项区分未测、通过、失败、受限及不适用，保留原始输出；不能用旧构建结果证明新构建。
- 以可控 x64/x86 自有进程为首轮目标，随后才在来宾验证真实系统进程。对 DWM 记录附加前后进程创建身份、Hook 安装/恢复、目标状态和应用错误事件；一次短时成功不代表长期稳定。避免新建带内存快照造成宿主机卡顿。
- 统计各层丢失口径和时间窗口：Agent 队列/发送丢失、连接或管道丢失、主程序接收与过滤、归档写入、界面淘汰/显示隐藏分别记录；未知计数标记未知。Hook 失败和未加载模块不等于零调用。
- 停止监控要求确认入口恢复、末次覆盖快照和目标正常继续执行；当前 Agent 的 DLL/退役代码可能保留至进程退出，不能描述为完全卸载。

## 逐项验收

### 1. 函数声明与参数自动解析

- [ ] 项目自有定义与外部转换结果按模块（不区分大小写）和导出名（区分大小写）确定身份，覆盖 A/W、重复声明与冲突；保留来源、版本和未核验状态。保持既有强类型 Hook ID 和生成绑定稳定。
- [ ] 对各类型声明核对参数个数、次序、类型、方向、返回类型和调用约定；未支持、含糊或冲突的 ABI 不能被当成已核验。分别验证 x64 整数/浮点、x86 stdcall/cdecl、双字宽及超出采集槽位的情况；不得把未知寄存器、结构返回或栈槽解释成已知值。
- [ ] 确认 Release 实际加载的声明文件与构建产物一致，程序无需依赖临时 XML 目录；记录定义数量、冲突/未核验数量、文件大小和首用加载耗时。外部定义的转换来源和发行授权状态单独记录。
- 起始状态：`APIMonitor_x64/api_monitor_definitions.json` 含 641 项强类型定义；`WinAPISignatureCatalog.h` 用自有目录作保守 Raw 映射。原候选中有未核验和未转换的内容；本轮最终合入范围及验证结果待填。

### 2. 调用前后参数、返回值和错误码

- [ ] 用可控目标对照调用前输入、调用后输出、真实返回值与实际错误来源，覆盖成功、失败、空/不可读指针、输出未写入、异步未完成和截断；无有效结果时显示未知，不将状态码冒充函数返回值。
- [ ] x86/x64 的寄存器/栈、返回宽度、字符串编码、错误码保存与恢复均核对；多线程、递归与嵌套调用不能错误配对或影响被测应用语义。
- [ ] 记录哪些函数/调用方式支持、哪些不支持；未实现的 Raw 退出事件、结构体或浮点返回不得以入口快照推断。
- 起始状态：`tools/api_monitor/test_file_return_values.py` 仅针对 CreateFileA/W/2 的真实句柄和错误语义；`WinAPIEventColumns.h` 的耗时列起始时固定为“未采集”。这不证明通用函数的调用前后采集。

### 3. 调用者地址和调用栈

- [ ] 可控目标从 EXE、已加载 DLL 和私有可执行内存分别发起调用，记录入口返回地址及预期调用链；检查有界栈帧、模块、模块内偏移和可用符号，以及无符号、截断/展开失败、跳板与尾调用。
- [ ] x86/x64 多线程、递归、异常展开和模块卸载场景下，不可把当前映射冒充历史映射；采集失败、非完整栈和资源预算耗尽应明确显示。
- 起始状态：`RawAbiSnapshot.h` 采集入口返回地址和部分参数栈槽，不是完整调用栈；详情中按选择时刻解析是后验快照。完整栈与符号支持待验收。

### 4. 地址归属与可疑内存线索

- [ ] 分别验证 MEM_IMAGE、MEM_MAPPED、MEM_PRIVATE 的可执行/非可执行及 RX/RWX、释放或重用区域，展示保护属性、区域范围、路径/模块及查询时刻；不可访问、进程退出、PID 重用等明确标为未知或失败。
- [ ] 区分调用时记录和之后的查询时快照，不能从私人可执行页直接推断恶意；表格、详情和导出如声明提供同一字段，须使用一致数据与状态。
- 起始状态：`shared/ApiMonitorCallerSnapshot.h` 使用进程创建时间校验和异步有界查询；`WinAPIDock.Actions.cpp` 在详情展示查询时快照。起始版本的表格调用者模块和内存类型列未填充。

### 5. 稳定性与丢失可见性

- [ ] 在来宾自有 x86/x64 目标验证高频、多线程、跨位数子进程、重复启停、目标退出、接收端中断和达到队列/归档预算的场景；与目标侧产生总数核对接收、过滤、淘汰和已报告丢失。
- [ ] 在来宾 DWM 与其他经选择的进程记录实际 Hook 覆盖、失败原因、安装与停止耗时、事件吞吐、内存变化、响应性以及停止后的进程存活。若业务事件为零、覆盖不完整或连接提前关闭，结论为受限/失败，不算完整通过。
- [ ] 分别核对已知与未知丢失计数，过滤不混作丢包，磁盘归档淘汰和表格窗口淘汰分开统计；重复会话记录留存代码增长。
- 起始状态：历史 Win10 来宾 CLI 测试与早前 DWM 实验见 `.claude/memory/ksword-api-monitor.md`，但后续源码已有变化，本轮尚无相应 VM 证据。

### 6. 密度时间轴

- [ ] 用确定时间间隔与不同类别产生事件，核对点/桶按事件实际时间错落分布；同一时间桶聚合允许重叠，不能因时间单位/轴范围错误全部压到一点。分别覆盖跨秒、长时段、乱序、时间回拨和缺失时间。
- [ ] 统计类别及桶计数与纳入口径一致；既不要求每条事件画点，也不以图上未显示推断无事件。验证百万级事件、高频实时更新、内存与 UI 延迟；显示桶宽和丢失/不纳入原因。
- [ ] 缩放、改变时间范围、拖动选区与列表过滤保留正确行为；清除选区能恢复；窄窗、深浅主题和真实主程序绘制分别核对，构建通过不代替视觉验收。
- 起始状态：`WinAPITimelineDensity.h`、`WinAPIEventTimeline.cpp` 实现有界聚合，`test_timeline_density.py` 覆盖合成事件；用户截图显示时间分布异常，本轮修复和真实来宾/GUI 结果待验证。

## 已有执行入口与覆盖边界

所有命令须在仓库根目录、可用的 HostX64 MSVC 开发环境中执行；Python 测试会生成临时测试可执行文件。部分脚本依赖本机 Qt 和真实 Agent，执行前检查脚本中的依赖路径及二进制位数。

```powershell
# 主程序按项目构建门禁，Agent x64/x86 分别按其工程 Release 平台构建。
& tools\Invoke-KSwordBuildCheck.ps1 -RepositoryRoot (Get-Location).Path -Action Build

# 仅声明目录、调用者快照、密度模型及 CreateFile 返回的专项验证。
python tools/api_monitor/test_signature_catalog.py
python tools/api_monitor/test_caller_snapshot.py
python tools/api_monitor/test_timeline_density.py
python tools/api_monitor/test_file_return_values.py

# 不含 UI 的 Agent/协议回归；分别在可调用对应位数编译器的环境运行。
python tools/api_monitor/run_regressions.py --architecture x64 --no-ui
python tools/api_monitor/run_regressions.py --architecture x86 --no-ui
```

`test_timeline_density.py` 优先使用仓库 Qt，缺失时回退 `D:/Software/Qt/6.9.3/msvc2022_64`；可传入 CLI 采集 JSON，将实采 API 时间戳重放到主程序的密度模型和投影逻辑。`run_regressions.py` 自动发现同目录所有 `test_*.py`，并非独立于各脚本环境；x86 需核实每个被纳入的测试是否真正支持该位数。`test_file_return_values.py` 启动自有测试进程并实际加载 Agent，需核对它加载的 Agent 路径和哈希。

来宾中的 `tools/Test-KSwordCliApiMonitor.ps1` 需要 `-Cli`、`-Fixture64`、`-Fixture32`、`-ReportRoot` 四个参数；它针对自有目标执行真实采集，生成 `summary.json` 和各次 JSON，覆盖部分安装、停止、重复及截断路径。它不验证 GUI、完整调用栈、所有 P0 或 DWM。所有产物、脚本与两位数 DLL 先确认是本轮构建后再复制到来宾；逐项对照机器名及 PID 创建身份，禁止指向宿主机。

## 本轮结果

- 2026-11-03 用户确认修改前版本的时间轴显示和交互正常。之后根据反馈调整列、详情和时间轴布局；新 Release 构建日志 `.codex-build-logs/ksword-build-check-20261103-004108.raw.log`，EXE SHA-256 `7C4172157A20367336C74417FE7F65CE73910AC3F40E4C5E889E42006FF5E4CC`，语言包及主题门禁通过。用户禁止 computer use，调整后的真实 GUI 未实机视觉验收。
- 主程序 Release 构建成功：`.codex-build-logs/ksword-build-check-20261102-222645.raw.log`，EXE SHA-256 `BF1A60EE16B5B92490AC566B53A4EFED7F79E1B4A8BF22294230E3B8598E8E27`；该构建通过双语门禁。当前 x64/x86 Agent SHA-256 分别为 `0591835E8B3756429010B5B18280393D70ADB6A3BEA0A12D7CEFA76D5E195702`、`D0456F6208CC5C678EC9FC3D84F6AFF5DE79AC5AE89304F4AB886032C512A6E7`。
- 构建脚本报告 EXE 测试签名已写入，但 `signtool verify /pa` 返回 `0x80096019`（basic constraint extension），签名状态为 `UnknownError`。构建成功不代表本机或其他机器已信任该签名；本次未更改证书信任配置。
- 按用户要求暂不合入第三方候选；当前源码和 Release 声明文件只含 641 条自有定义，SHA-256 均为 `F963FFD995036E2070D37811E3D0239C9DCD8EC461CC54418144CE46F25A4BEB`。隔离候选 `.codex-build-logs/api-monitor-user32-batch-candidate.json` 中 227 条 User32 参考声明通过 SDK 双位数原型检查，额外 19 条未通过并隔离；参数方向和运行时语义仍未验证。
- 包含候选声明的较早版本在来宾自有 x64/x86 目标分别核对 `GetSystemMetrics(42)` 的 Raw 槽位、声明哈希和停钩：匹配事件分别为 61、58，Agent 与 CLI 缓冲丢弃均为 0，两个结果均 partial。见 `.codex-build-logs/sdk-raw-227-final-vm-20261102/results/summary.json`；这不是当前发行声明的验证。
- 异步等待语义修复前的自有声明版本在来宾自有双位数目标完成 142 项 R3 检查及 R0 注入/停钩检查，均为 partial；R0 的 Agent/CLI 缓冲丢弃为 0，驱动恢复停止。分别见 `.codex-build-logs/cli-parity-owned-catalog-vm-20261102/results/`、`.codex-build-logs/api-p0-r0-owned-catalog-vm-20261102/results/summary.json`。
- 当前双位数 Agent 在来宾自有目标的 R0 注入和停钩检查通过，分别捕获 45/41 条 WriteFile，Agent/CLI 缓冲丢弃均为 0，覆盖仍为 partial；驱动测试前后均为手动启动、停止状态。见 `.codex-build-logs/api-p0-r0-pending-vm-20261102/results/summary.json`。
- 当前双位数 Agent 的自有目标对照测试验证 `VirtualProtect`、`DuplicateHandle` 的成功和失败：返回值、成功输出参数、失败错误码与目标进程的实际结果一致；`ReadFileEx` 的等待阶段状态未知、字节数未知，完成阶段的字节数和回调结果匹配。Agent/CLI 缓冲丢弃均为 0，已停钩，覆盖仍为 partial。见 `.codex-build-logs/semantic-pending-vm-20261102/results/summary.json`；不能推广到所有 API 或所有异步情形。
- 来宾自有目标高频对照 9600 次通过，记录在 `.codex-build-logs/api-p0-vm-metrics-reconnect-20261102/`；该轮早于最终 Agent，不用于证明最终二进制。CLI 对等功能来宾 140 项检查记录在 `.codex-build-logs/cli-parity-vm-20261102-final/`，随后 CLI 又增加 R0 选项，故不能把该轮认作最终 CLI 全量验证。
- 较早 Agent 和 CLI 的 R0 路径在来宾自有 x86/x64 目标收到事件并完成停钩，见 `.codex-build-logs/api-p0-r0-vm-20261102/results/summary.json`；两次均为 partial，测试后驱动恢复原停止状态。先前 DWM/Explorer 短测也为 partial，且不是最终 Agent 的验证。
- 较早 CLI 与双位数 Agent 的 R0 路径在来宾自有 x64/x86 目标验证，分别捕获 50/48 条 WriteFile，Agent 和 CLI 缓冲丢弃均为 0，确认停钩及进程正常退出；两次覆盖均为 partial。现有驱动测试前后均为手动启动、停止状态，见 `.codex-build-logs/api-p0-r0-current-vm-20261102/results/summary.json`。
- 较早 CLI 与双位数 Agent 在来宾自有目标完成 140 项检查（`CLI_PARITY_GUEST_PASS checks=140`），涉及前后置筛选和例外、调用栈开关、有界时间桶计数、声明哈希和停钩；每次均报告 partial，见 `.codex-build-logs/cli-parity-current-vm-20261102/results/`。这是有界自有目标验证，不证明全部调用栈或真实 GUI 表现。
- 双位数夹具复测新增调用栈来源检查：先核对目标进程可执行路径，再用运行时主映像基址和大小检查 `WriteFile` 的已采集栈帧；x64、x86 均至少有一帧属于夹具映像，合计 `CLI_PARITY_GUEST_PASS checks=142`，原始采集见 `.codex-build-logs/cli-stack-provenance-vm-20261102/results/`。不能由此推断每个调用的完整栈、符号或历史映射。
- 使用上述真实采集的 x64/x86 baseline JSON 重放主程序密度和 1200 列投影：594/700 条事件分别投影到 54/51 个不同列，投影总数与输入一致，时间跨度约 2.23 秒；同时原有百万事件模型检查通过。重放命令为 `python tools/api_monitor/test_timeline_density.py <baseline.json>`，这不代替 GUI 的视觉、缩放与拖选验收。
- 使用较早版本的来宾 DWM/Explorer 采集 JSON 重放同一模型，19998/19999 条带时间的业务事件分别投影到 31/33 个不同列，计数守恒，时间跨度约 1.69/1.73 秒。两类事件在捕获中多次具有相同时间戳，对应轨道可能纵向对齐；Agent 使用 `GetSystemTimeAsFileTime`，不能将时间戳解释为高精度调用顺序。本次只重放 CLI 缓冲保留的数据，前述被淘汰事件不在此范围内。
- 较早声明目录含 53 条经过 SDK x86/x64 原型检查的 User32 参考项；来宾自有目标中 GetSystemMetrics 的两位数 Raw 槽位及声明哈希核对通过，见 `.codex-build-logs/sdk-raw-vm-20261102/results/summary.json`，这不代表其余声明已逐项实测。
- 较早 x64 Agent 在来宾 DWM（PID 7248）与 Explorer（PID 4908）各进行三秒短测，原进程身份保持、HooksInstalled/Removed 和清理确认，未发现对应崩溃事件，Agent 报告丢包为 0。两轮均 partial，CLI 各保留最近 20000 条并分别淘汰 5240/6068 条；这是有界缓冲淘汰，不能宣称完整无损采集。证据见 `.codex-build-logs/api-p0-final-system-20261102/final-system-results/summary.json`。
- 同一较早 Agent 复用驻留会话，将 CLI 上限提高至 100000 后再各测三秒：DWM 25632 条、Explorer 22880 条，Agent 报告丢包及 CLI 缓冲淘汰均为 0，原进程存活且停钩确认，两轮仍为 partial。见 `.codex-build-logs/api-p0-final-system-100k-20261102/final-system-100k/summary.json`；这是短时间场景，不证明长时间无丢失。
- 包含候选哈希的较早 x64 Agent（SHA-256 `EBE234F24ECD957798BA11B8C764633767044889EA82BC75188BCF9A68F63371`）在来宾 DWM PID 7248 和 Explorer PID 4908 各短测三秒：目标创建身份保持、安装和停钩确认、未发现匹配的应用崩溃事件，Agent 报告丢失均为 0；每轮均为 partial。CLI 缓冲各保留 20000 条并分别淘汰 10341/10357 条，故不能称完整无损。结果见 `.codex-build-logs/api-p0-current-system-vm-20261102/results/summary.json`；停钩后 Agent 保持驻留，短测不证明长期稳定。
- 异步等待语义修复前的自有声明版本 x64 Agent（SHA-256 `E9368B110130D487CE2C4A87186C0E2DCE3E9B114F365D92ADEC802EF7E60A05`）在来宾 DWM PID 7248 和 Explorer PID 4908 各短测三秒，进程身份保持、停钩确认、未发现匹配的应用崩溃事件；两轮 partial，Agent 报告丢失为 0。CLI 各保留 20000 条并淘汰 19146/20972 条，结果见 `.codex-build-logs/api-p0-owned-system-vm-20261102/results/summary.json`。各自保留的 19999 条有效业务事件重放到 1200 列密度模型后分别落入 37/35 列，计数守恒；这不证明当前 Agent 系统进程行为、GUI 视觉、长期稳定或无损。
- 读取上述两次完整覆盖快照，DWM 和 Explorer 各有 372 条 Unsupported：202 条补丁区间与不兼容处理器冲突、113 条入口过短、42 条指令不支持或截断、15 条入口不可读或不可执行；这些是记录数，存在别名共用地址。各有 1 条强类型项，即 `Kernel32.dll!GetProcAddress`；此前同一来宾采集的入口字节为 `4c 8b 04 24 48 ff 25 b5 5b 06 00 ...`，当前拒绝其中的 RIP 相对间接跳转。现有引擎已有邻近中继与 5 字节补丁，不应将该失败简单归因于固定 14 字节补丁；需要另行验证间接跳转重定位及终止控制流。不能通过忽略短入口、冲突或不支持指令来宣称安装成功。
- 隔离夹具中，精确 `48 ff 25 disp32` 的重定位及停钩通过，但真实 `GetProcAddress` 前置指令读取调用者返回地址作为参数；现有 C++ wrapper 经 trampoline 调用会改变该地址。因此该解码候选未合入，不能仅凭跳转重定位成功宣称保留真实 API 语义。
- 在来宾自有进程中确认该跳转槽当前指向 `KERNELBASE!GetProcAddressForCaller`；隔离 fixture 捕获原调用者、直接传递后，真实函数的名称、序号、失败和 LastError 对照通过。该目标未在本机 SDK 中声明，其调用约定基于当前来宾机器码推断；fixture 不是生产 wrapper，且尚未验证调用者敏感路径、CFG/CET 等，因此候选仍未合入。
- 后续隔离候选对实测系统版本的内部入口和未知版本拒绝路径进行了自有目标验证，但该内部接口仍未公开，无法据一个映像版本推断其他系统兼容性；为了稳定性未合入生产，也不改变 `Kernel32!GetProcAddress` 的覆盖状态。
- 未完成项：最终 Agent 的长时稳定性、真实 GUI 的时间轴/交互、所有第三方声明 ABI 与语义、完整调用栈以及跨版本组合仍无充分证据。用户要求不使用 computer use，不能以离屏模型测试或编译成功代替真实 GUI 验收。

## 本轮时间轴与详情：源码级 UI 核对

本节是 2026-11-02 的静态核对记录；并行修改可能改变细节，最终交付时须以最终源码再次核对。没有使用 computer use，也没有据静态检查声称真实主程序视觉已通过。

### 入口与共享组件

| 导航入口 | 页面类型 | 源码中的宿主与组成 |
| --- | --- | --- |
| 主窗口“监控” → “WinAPI” → “API 事件”（默认结果页） | 参数/执行 + 监控时间线 + 主列表 + 对象详情 | `MonitorDock::ensureWinApiTabInitialized` 惰性创建 `WinAPIDock`，并使用 `ScopedWidgetThemePreparation`；`ParameterWorkspace` 分离参数/结果，`StyleJoinedResultTabs` 连接筛选行与结果 Tab；表格 `TableActionTableView` 选 Full；`DetailLayoutRegistry::registerStructuredHost` 登记详情 splitter；共享 `ProcessTraceTimelineWidget` 绘制时间轴。 |
| 主窗口“监控” → “WinAPI” → “API 覆盖” | 覆盖表与前后置筛选 | 同一结果 Tab 宿主；覆盖表 `TableActionTableView` 显式 Compact；覆盖表和规则面板由垂直 splitter 分配空间。 |
| 设置中的详情方案 → WinAPI 选中事件 | 字段详情/专业 HEX | 共享 `DetailLayoutHost` 管理下方、右侧、行内和独立窗口方案；下方/右侧的事件详情使用属性树、参数树与共享只读 `HexView`；Raw 分配编辑为事件页上的独立专业控件。 |

对照的相近页面：`MonitorDock.cpp` 的 ETW 监控以及 `ProcessTraceMonitorWidget.Ui.cpp` 的进程定向页，两者都复用 `ProcessTraceTimelineWidget` 和 Full 事件表操作条。共享实现检查了 `VisibleTableWidget.h` 的 `TableActionTableView`、`DetailLayoutRegistry.cpp`/`DetailLayoutHost.cpp`、`ProcessTraceTimelineWidget.cpp`/`.Render.cpp`。API 事件页源码未直接显式调用 `ResultTableHost`；表格宿主的其它统一接入由运行时确认，不能仅凭类名断定不合规或已合规。

### 逐项源码观察与待验收

- **页面和导航**：WinAPI 根布局为 8px 边距及间距，参数区交由 `ParameterWorkspace`；结果页在连体结果 Tab 后依次放时间轴和事件表/详情 splitter。实际外层是否再叠加留白、6px 的 Tab 与表格组间距，以及参数区/结果区在窄窗的可用高度，静态无法确认。
- **图表与交互**：时间轴共七类轨道，主题色通过 `KswordTheme::TimelineRole`，图表绘制背景/边界取共享主题色；按时间桶的类别密度投影在后台完成，选区变更经 200ms 合并后设置模型时间范围，“显示全部时间”清除范围。轴与选区交互沿用 `ProcessTraceTimelineWidget`；点形状、错落位置、缩放/拖动手感、数据与列表时间身份仍需真实运行验收。高频更新的实际响应和帧耗时未测。
- **列组与详情开关**：A 为调用视图，B 为来源视图，共有列包括时间、序号、API、PID、TID；表头右键支持逐列切换，自定义列后清除 A/B 选中态。“显示详情”默认不勾选，仅控制表格详情列，与详情窗方案独立。实际列标题、横向滚动、排序/过滤、复制与所见记录一致性待运行核对。
- **导出**：事件工具行另设业务 TSV 导出，`MonitorCanonicalExport` 使用可见事件快照、当前时间范围及筛选状态，导出说明写明并非完整调用轨迹；表格同时为 Full 操作条。须实际核对两种入口的列范围、筛选和排序、快照/冻结及后台导出的结果和差异，静态不能证明导出的字段或行完整。
- **详情数据与布局**：`updateEventDetails` 先构造一份 `FieldDocument`，设置 `StructuredFieldView` 后据同一文档投影属性、参数树，HEX 用当前未分配字节；无选中事件时清空。该三栏专业布局显式放在共享详情 pane，行内/独立方案使用共享字段镜像，是否保留同样的三栏、参数操作和 HEX 体验需逐方案核对，不能称四种方案的视觉与交互一致。
- **主题和状态**：轨道、表格前景、状态标签、搜索和工具行有共享主题入口；参数分配条自绘使用共享表面色与文字对比函数。事件过滤输入也设置局部 `blueInputStyle`，深浅主题和热切换是否被覆盖、各种选中/悬停/禁用/焦点对比是否达标需实测。源码静态检查不等于 4.5:1/3:1 对比验收。
- **尺寸修正和剩余风险**：`WinAPIDock.Ui.cpp::configureIconButton` 原来显式设定 34px 宽度，之后的 `NormalizeToolbarControl` 还会按字体重设高度和宽度，因此不能断言运行时实际是 34px；现改为共享 `ApplyCompactIconButtonMetrics` 初始化，并设置与 tooltip 一致的无障碍名称，再由工具行做自适应对齐。主题 token 门禁自测及全量 1268 文件检查通过，真实几何仍待验收。表格上方过滤/状态/按钮为单个 `QHBoxLayout`，未见换行设计，窄窗及长翻译存在挤压风险，需通过真实尺寸确认；现有 `FlowLayout` 可用于独立控件流，但其扩展项会占满当前行，直接替换会改变搜索框伸缩和 A/B 分组关系，因此本次未未经实测重排。分配类型按钮使用 `FlowLayout`，分配条内部有按需水平滚动；三栏 pane 最小宽度设为零，但不足以证明长文本、HEX 和分隔条在窄窗可用。
- **必须另行验证**：设置四种详情模式的切换和选中状态保留、搜索/复制/导出使用同一文档、列组与表头菜单、浮窗/行内模式、深浅主题及背景图/透明背景、100%/高 DPI、长中英文文本、首帧及惰性页激活；无数据/等待/失败状态以及键盘焦点、快捷键和颜色对比。未观察到实际 GUI 前，这些均为未验收。
