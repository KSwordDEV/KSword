# ActionAnalyze NX 页数与集合成员额度调整

本说明对应 NX 执行范围原 64 页、执行集合及进程集合原 16 成员额度的源码调整，供三端集成及文本同步使用。

## 行为与协议

- NX 初始范围、运行中追加、历史执行范围转草稿和 API 实际范围候选不设固定页数额度；每段仍须非空、4KiB 对齐、地址加长度不溢出。
- 每段实际范围仍由原所有者核验同一私有分配、提交状态、保护、重叠和完整当前停点。追加不隐式继续目标。
- 执行集合首次配置及追加、进程集合配置、批量选择与完整票据解析不再按 16 个成员拒绝；重复 PID、授权和真实实例核验继续适用。
- 容器剩余容量比较先于数量相加。NX 页目录和范围目录在更改保护前取得存储；分配失败报告 `ERROR_NOT_ENOUGH_MEMORY`。
- Qt 三个 NX 页数入口使用 `QLineEdit` 和同一 `ParsePrivateExecutionPageBytes`，逐位解析 ASCII 正十进制 uint64，并检查乘 4096；回填完整页数不经过 `int`。
- Light 候选页使用原生 EDIT，按 `EN_CHANGE` 绑定草稿，使用编辑框自然行高；先核对正十进制和乘法再交共享范围核验。
- CLI、Qt、Light 的实际范围总字节统计均检查加法溢出；无法表示时 CLI 的 `totalRangeBytes/totalRangePages` 为 `null`，界面显示“不可用”。
- 单目标 `hello.result.rangeProtocol.maximumTotalPages`、执行集合 `hello.result.protocol.maxMembers`、进程集合 `hello.result.groupProtocol.maxMembers` 均为 `null`，表示无固定业务额度。
- 原 JSON、配置文件、输入输出字节预算继续独立适用；没有改成更大的人为页数或成员数。
- `PassiveDirtyMemory`、`ProjectMemorySnapshot`、`MemorySnapshotReader` 及执行集合内存读取的独立 64 页限制继续适用。

## 源码落点

以下均为仓库相对路径；只列本项负责的文件。并行作者在同文件的改动不归本项。

- `KswordCLI/ActionAnalyze/Control/`：`NativePrivateExecutionPage.cpp/.h`、`NativeDebugOwner.cpp/.h`、`NativeDebugAdmission.cpp`、`OwnedExecutionGroup.cpp/.h`、`OwnedProcessGroup.cpp/.h`。
- `KswordCLI/ActionAnalyze/Cli/`：`BreakpointCommand.cpp`、`BreakpointRangeProtocol.cpp`、`ExecutionGroupCommand.cpp`、`ExecutionGroupProtocol.cpp`、`ExecutionGroupReport.cpp`、`ProcessGroupCommand.cpp`、`PrivateExecutionCandidateCommand.cpp`。
- `KswordCLI/ActionAnalyze/Detection/`：`PrivateExecutionCandidates.cpp/.h`。
- `KswordCLI/ActionAnalyze/Project/ExecutionGroupArchive.h`：最近自动批次注释不再描述 16 个成员；实现原本按实际批次保留。
- `shared/evidence/ApiNativeExecutionProjection.cpp`：历史执行范围转草稿。
- `Ksword5.1/Ksword5.1/ActionAnalyze/`：`PrivateAddressWatchFields.cpp/.h`、`PrivateExecutionRangePane.cpp/.h`、`PrivateExecutionCandidatesPane.cpp/.h`、`PrivateExecutionCandidatesLayout.cpp`、`ExecutionGroupPage.cpp/.h`、`ExecutionGroupPageControl.cpp`、`ExecutionGroupSession.h`、`ExecutionGroupFields.cpp`、`ProcessGroupPage.cpp`、`OfflineSegmentOverview.Objects.cpp`。
- `KswordARKLight/Features/ActionAnalyze/`：`ExecutionGroupPage.cpp`、`ExecutionGroupPageCommands.cpp`、`ExecutionGroupPageLayout.cpp`、`ExecutionGroupPagePresentation.cpp`、`ExecutionGroupPageState.h`、`ProcessGroupPage.cpp`、`ProcessGroupPageLayout.cpp`、`LightPrivateExecutionCandidatesPane.cpp`、`ActionAnalyzePage.cpp`。

## 页面接入范围

| 导航入口 | 页面职责 | 共享入口 |
| --- | --- | --- |
| 监控 → 行为分析 → 写入停点 → 整页执行关注、追加范围及 API 范围候选 | 参数、显式执行及候选结果 | Qt `ParameterWorkspace`、`StyleParameterSection`、标准输入主题；Light 原生 `ParameterWorkspace` 与主题输入 |
| 监控 → 行为分析 → 执行断点集合 | 站点草稿、追加及原成员控制 | 既有 `ParameterWorkspace`、站点结果表及同源字段详情 |
| 监控 → 行为分析 → 进程集合控制 | 显式实例配置及控制 | 既有 `ParameterWorkspace` 和结果表 |
| 行为分析归档总览 → 执行范围草稿 | 历史对象转草稿 | 既有总览对象选择与草稿接收入口，仅修正拒绝原因文字 |

本项保留原布局、操作条、列组、详情源和显式执行流程，仅替换 NX 页数字段及额度判断。未对全部旧页面作视觉合规声明。

## 待主协调同步的语言包源文本

语言包由主协调统一定点同步。以下列出本项全部替换后的 Qt 源文本；旧词条可按同文件差异定位，不要整体重写语言包。

| 源文件 | 新源文本 |
| --- | --- |
| `ExecutionGroupPage.cpp` | 为明确选择的进程实例各配置一个执行站点。开始冻结目录和条件；各成员独立命中，逐项回读，不保证同时冻结。 |
| `ExecutionGroupPage.cpp` | 冻结当前表单中的新进程实例与条件，沿同一采样追加成员；保留已有停点，不替换原成员。同一 PID 只能登记一次。 |
| `ProcessGroupPage.cpp` | 仅控制本会话显式选择的进程实例。配置只核对身份；暂停与继续需另行执行。 |
| `OfflineSegmentOverview.Objects.cpp` | 执行集合未接收草稿：请先清退并返回草稿，检查重复 PID。 |
| `PrivateAddressWatchFields.cpp` | 每页4096字节，页数填写正十进制整数。范围必须属于同一私有分配且不溢出；保留各页原保护，拒绝空洞。 |
| `PrivateExecutionRangePane.cpp` | 在当前完整执行停点下显式纳入另一段私有执行页，不继续目标。单段必须来自同一分配，范围须为整页且地址不能溢出。 |
| `PrivateExecutionRangePane.cpp` | 请输入非零、4KiB对齐的起点及正十进制页数，页数字节换算和地址范围均不能溢出。 |
| `PrivateExecutionCandidatesLayout.cpp` | 页数（4KiB，正十进制） |
| `PrivateExecutionCandidatesLayout.cpp` | 仅将符合整页且地址不溢出的实际整段填入草稿；不裁剪、不扩大范围。 |
| `PrivateExecutionCandidatesPane.cpp` | 请输入实际输出范围内部的 4KiB 对齐子范围和正十进制页数，换算不能溢出；不自动扩大或裁剪。 |

`ExecutionGroupFields.cpp` 新增使用既有源词条“不可用”；主协调审计时一并核对两种语言已有映射。

Light 的新增/替换文字位于上述负责文件中：页数标签及释义、NX 参数错误、集合说明和原拒绝原因同步取消固定额度。

## 待主协调同步的总 CLI 文档

`docs/CLI使用文档.md` 由主协调持有，本项未编辑。需调整以下段落：

1. `analyze process-group session` 命令表：将“固定 1–16 个”改为“一个或多个明确选择的”，并说明无固定成员额度。
2. 活执行集合 `members-append` 段：取消“追加后最多16个不同PID”，保留重复 PID、部分失败和原 writer 规则。
3. 执行集合 `control.execution.range.add` 段：取消“总64页预算”，说明整页、地址溢出、真实容器及系统失败。
4. 单目标 NX `execution-range-add` 段：取消“全部范围合计最多64页”，补 `rangeProtocol.maximumTotalPages:null`。
5. 进程集合、执行集合能力段补 `maxMembers:null`；明确传输预算和独立内存快照限制仍存在。

内置 CLI help 已同步；`docs/cli/action-analyze-execution-group.md` 和 `docs/cli/action-analyze-execution-candidates.md` 已同步本项行为。

## 集成边界

本项未编辑语言包、总 CLI 文档或共享 memory；未执行构建、测试、GUI、CodeBuddy、提交或推送，也未生成验收回执。已进行源码检索及差异阅读；运行、视觉和性能结论待后续授权验收。

Light 单目标 `DataWatchPage.cpp`、`LightDataWatchSession.cpp/.h` 由挂起启动作者处理；自动接管 `ApiTransferHandoff`、`CooperativeApiCapture` 及 Agent Hook 由主协调处理。它们须在最终整合时继续核对，不能以本项源码完成代替全范围验收。
