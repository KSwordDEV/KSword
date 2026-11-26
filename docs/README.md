# KSword 文档中心

本文以当前仓库代码为准，最近核对日期：**2026-10-05**。发行包可能早于当前源码；功能入口、协议版本和能力状态应以实际运行版本为准。

ActionAnalyze 专题索引于 2026-11-24 补充。首批工作包已并行开工，产品验收仍待完成。各验证记录标明夹具、环境与实测范围。

## 开始使用

| 需要做什么 | 文档 |
| --- | --- |
| 安装、选择完整/轻量版、核对驱动与偏移、排查不可用 | [使用与兼容性](使用与兼容性.md) |
| 了解产品能力 | [中文介绍](readme_zh.md) · [English overview](../README.md) |
| 按模块查实现、入口与限制 | [功能技术文档](功能技术文档.md) |
| 使用命令行、核对命令和参数 | [CLI 使用文档](CLI使用文档.md) |
| 编译、制作发行包、接入 Launcher 报告 | [构建与发布](构建与发布.md) |

## 常用调查与分析

| 主题 | 文档与用途 |
| --- | --- |
| 内存查看、暂存、汇编、对比与显式写回 | [内存编辑器组件清单](内存编辑器组件清单.md)，包括 R3/R0/R-1/DDMA 的集成边界 |
| 系统内存与物理页归因 | [系统内存审计](系统内存审计.md) · [PFN 物理内存归因](PFN物理内存归因.md) |
| 进程注入痕迹 | [功能技术文档第 4 章](功能技术文档.md#4-进程模块)，区分现场异常、采集缺口与历史注入归因 |
| ETW、Syscall 与 WinAPI 监控 | [功能技术文档第 10 章](功能技术文档.md#10-监控模块) · [API Monitor x64](../APIMonitor_x64/README.md) · [API Monitor x86](../APIMonitor_x86/README.md) · [Syscall 工具](../tools/syscall_monitor/README.md) |
| 文件结构扫描、元数据、删除与恢复 | [功能技术文档第 7 章](功能技术文档.md#7-文件模块)，写入与删除结果以回读/复核为准 |
| 内核知识与现场证据 | [内核知识中心](内核知识中心.md)，71 个双语专题及只读业务页路由 |
| 窗口、输入与 DWM 排序 | [窗口输入控制](窗口输入控制.md) · [DWM 窗口序列注入](DWM窗口序列注入.md) · [独立 DWM 工具](../DwmZOrderStandalone/README.md) |
| SOS 救援桌面 | [SOS 救援桌面](SOS救援桌面.md)，高权限新实例、返回操作与输入保护边界 |

| 调试器与插件 | [共享调试后端](../DebuggerBackend/README.md) · [x64dbg 后端](ksword-x64dbg-backend.md) · [x96dbg 集成](../X96dbgIntegration/README.md) · [CE 插件](../CheatEnginePlugin/README.md) · [TitanEngine 插件](../TitanEnginePlugin/README.md) |

## 虚拟化与实验后端

虚拟化工作区包含 Intel VMX/EPT 与实验性 AMD SVM/NPT 路径。入口存在、编译通过、离线回归通过和实机验收是不同状态；不能把某台机器的成功结果推广到全部硬件和内层系统。

| 主题 | 文档 |
| --- | --- |
| 当前能力与历史设计边界 | [虚拟化能力路线图](虚拟化能力路线图.md) · [虚拟化规范要点](虚拟化规范要点.md) |
| Intel 嵌套 VMX/EPT 架构 | [嵌套虚拟化架构](next/嵌套虚拟化架构.md) · [嵌套虚拟化实现设计](next/嵌套虚拟化实现设计.md) |
| 多核与内存视图 | [嵌套下的跨核 TLB 失效](next/嵌套下的跨核TLB失效.md) · [EPT 切换后端设计](next/EPT切换后端设计.md) |
| AMD 实现与尚待验收的限制 | [AMD 嵌套 SVM 实现](next/amd-nested-svm-implementation.md) · [AMD 入口进展](next/amd-nested-entry-progress.md) |
| 使用、测试与证据判据 | [使用与限制说明](next/使用与限制说明.md) · [自动化测试](next/自动化测试.md) · [实验工具](../tools/hvm_lab/README.md) · [VTL1 证明报告判据](next/VTL1证明报告判据.md) |
| DDMA、RXPF 与其他后端 | [高级取证与实验后端设计](高级取证与实验后端设计.md) · [RXPF 实验机制](RXPF实验机制.md) · [CLI 使用文档](CLI使用文档.md) |

## 开发与维护

| 主题 | 文档 |
| --- | --- |
| 协作、模块边界和许可证 | [贡献指南](../CONTRIBUTING.md) · [AGENTS.md](../AGENTS.md) · [LICENSE](../LICENSE) |
| 协议注册、权限与覆盖 | [驱动 IOCTL 审计](driver_ioctl_audit.md) · [共享协议源码](../shared/driver/) |
| PDB/DynData 数据与接入 | [动态偏移功能接入步骤](动态偏移功能接入步骤.md) · [PDB 工具](../tools/pdb_offset_generator/README.md) · [多模块审计准备](pdb_r0_audit_prep/) |
| 插件与多语言 | [插件系统规范](插件系统规范.md) · [多语言语言包规范](多语言语言包规范.md) |
| 功能对照与规划 | [OpenArk 对照](OpenArk功能对照与TODO.md) · [SKT64 对照](SKT64旧版功能对照.md) · [第二规划验收矩阵](第二规划R0R3验收矩阵.md) |
| 恶意行为监控能力规划 | [恶意行为单点追踪与调试能力规划](恶意行为单点追踪与调试能力规划.md)，保存非虚拟化、线程传播、调试取证、规则与 UI／内存预算要求；产品引擎未实施 |
| ActionAnalyze 完整开工审查 | [不确定项总账与实施总表](ActionAnalyze完整开工审查与实施总表.md)：29项总账、A0–A10依赖、来源／控制／调查／UI／预算与交付门槛，区分可独立施工和待R0实测范围 |
| ActionAnalyze 工程开工 | 首批工单、同步停点、放行条件、E01–E16 环境探测范围和普通 R0 来宾阻塞项。[工程开工基线](ActionAnalyze工程开工基线.md) · [同步全局断点与性能复查](ActionAnalyze同步全局断点与性能复查.md) · [已发布的 A0 基础契约](../schemas/action_analyze/base-contract-v1.md) |
| ActionAnalyze 下一层施工 | 33 项任务逐项列文件／所有者、输入输出、依赖、失败恢复和独立验收。12 类接口、5 条纵向切片，逐项待验。[施工任务与契约落点](ActionAnalyze施工任务与契约落点.md) |
| ActionAnalyze 成品验收 | 概念图逐区、12 项动作、33 项工单和真实自有 CLI 样本回执。[成品验收对照](ActionAnalyze成品验收对照.md) |
| ActionAnalyze 发布 ToDo | 从一键启动、预设分析到三端验收和发行的依赖顺序。[发布 ToDo](ActionAnalyze发布ToDo.md) |
| ActionAnalyze 桌面总览 | 当前 Qt 项目与采样、Win32 归档段的离线验收，以及完整工作台的瀑布框选、证据图、12 项调试动作和键盘／DPI 要求。[总览交互与验收](ActionAnalyze总览交互与验收.md) |
| ActionAnalyze 双后端与启动期 | R3 是正式后端，须在无 KSword 驱动时完成受支持的用户态全流程。普通 R0 独立验收，活采样禁止静默切换。启动记录含 x64/x86 六例共 68 项，覆盖原始挂起 299、入口安装漏 TLS 和独立早期原型的 EXE TLS 结果。[R3／普通 R0 独立全流程](ActionAnalyze双后端独立全流程设计.md) · [挂起创建与最早窗口验证](ActionAnalyze启动挂起注入与最早窗口验证-20261124.md) |
| ActionAnalyze 执行覆盖 | [执行覆盖与逐路径验收](ActionAnalyze执行覆盖与逐路径验收.md)：已设防区域的执行入口发现不依赖注入手法，D/X/P/A四轴、16路径与完整屏障判据；自动发现新区域仍待验证 |
| ActionAnalyze 反反虚拟机 | [反反虚拟机与环境实验行动方案](ActionAnalyze反反虚拟机与环境实验行动方案.md)：16探测面、15项任务、7组实验，WMI／注册表／固件一致性、有限指令站点／多时钟研究、原值／替代／目标所见与恢复；未实施、默认不干预 |
| ActionAnalyze 规划遗漏复查 | [规划缺口复查与补齐任务](ActionAnalyze规划缺口复查与补齐任务.md)：16项具体缺口，修正规范根与旧状态，补线程门控、普通store发现、异常／断点资源、准入启动／失效、中介执行／托管代码及CLI／CI契约；关键机制仍待实测 |
| ActionAnalyze 规则施工 | [规则来源与转换施工清单](ActionAnalyze规则来源与转换施工清单.md)及[规划资料](action-analyze-planning/README.md)：固定9源、21468个blob／12810候选文件、本地601条索引和7份许可hash；未枚举上游规则总数、未实现转换／执行 |
| ActionAnalyze 事件与结构协议 | 无损类型、强实例、阶段／字段、来源、方法和水位。A0 已发布基础、Stored 及离线方法子集。[事件身份与协议契约](ActionAnalyze事件身份与协议契约.md) |
| ActionAnalyze 筛选与规则语言 | 六域隔离、三值、有限表达式、序列与历史分页。离线类型化规则回放已合入，完整 DSL 和实时接入待验。[筛选器与规则语言设计](ActionAnalyze筛选器与规则语言设计.md) |
| ActionAnalyze 文件与恢复 | [项目存储格式与恢复设计](ActionAnalyze项目存储格式与恢复设计.md)：目录项目、分段字节布局、blob／索引、提交／恢复／锁、单文件搬运与配额；三端互读和故障验收待实施 |
| ActionAnalyze 栈与控制流 | [栈破坏与控制流劫持发现设计](ActionAnalyze栈破坏与控制流劫持发现设计.md)：区分栈耗尽／缓冲区越界／保护失败／pivot／代码复用，补同进程写入、有限槽位watch及证据／负控，未实现通用检测器 |
| Action Scope功能研究 | [功能与实现核查](ActionAnalyze对ActionScope功能与实现核查.md)：官方历史包版本／文件身份，配置与真实代码路径分层，分路静态审查Hook／检测／WMI环境干预／网络／主控；借鉴候选与运行未知分开 |
| 页面执行探针机制验证 | [2026-11-24 验证记录](非虚拟化页面执行探针验证-20261124.md)：自有线程池首次发现、Guard／NX 负控、统一停止后按需放行与重设防；受控夹具通过，不代表任意目标完整覆盖 |
| Explorer 复杂环境验证 | [2026-11-24 实测记录](ActionAnalyzeExplorer复杂环境验证-20261124.md)：目标外原生调试接收异常，多线程Explorer五类正常场景79项通过；持有NX异常时杀控制器造成桌面功能失效，已重启恢复，故障恢复仍失败，未验普通R0 |
| 行为语义规则模板 | [收集与并入规划](行为语义规则模板收集与并入规划.md)：本地沙箱及公开上游来源、字段与许可证、语义关联和性能约束；候选目录不等于已导入规则 |
| ActionAnalyze 通信与控制设计 | [多通道通信与控制施工设计](ActionAnalyze多通道通信与控制施工设计.md)：目标外控制、就绪屏障、命令阶段、停止恢复与容量；离线模型／自有 IPC 与产品端到端验收分别记录 |
| ActionAnalyze 长程 CLI | 已提交离线会话外壳及项目生命周期接线。正式 CLI 的 `project_v1` 通过。旧入口 smoke 修复、真实控制接线及产品验收待完成。[会话与结构协议设计](ActionAnalyze长程CLI会话与结构协议设计.md) |
| ActionAnalyze 分析项目 | [分析项目与多次采样设计](ActionAnalyze分析项目与多次采样设计.md)：项目统一保存断点／配置／多次采样，采样独立快照与结果，重新绑定目标；横向比较暂列待做 |
| ActionAnalyze 工具栏核对 | 原图 14 项保留 12 项，回滚与热重载延期。网络作用于选中进程。两后端按开工基线分别验收。[工具栏逐项功能核对](ActionAnalyze工具栏逐项功能核对.md) |
| ActionAnalyze 通信验证 | [2026-11-24 验证记录](ActionAnalyze通信机制验证-20261124.md)：31 项离线模型与 37 项自有 Windows IPC，分别记录证据边界；后续故障与步进另见 R3 补充，不是生产 Agent 或长程 CLI 验收 |
| ActionAnalyze R3 补充 | 历史实测包括 37 项 IPC 正常回归、7 项杀父 Job 清理和 106 项真实步进。TCP 权限负控 12 项通过，成功断连未验收。[R3 机制补充验证](ActionAnalyzeR3机制补充验证-20261124.md) |
| 单点追踪工程与 CLI 设计（历史备选） | [原共享采集架构与 CLI 设计](单点追踪共享采集架构与CLI设计.md)，2026-11-24 已改为 Qt/Win32/CLI 各自组织实现，不推进共享宿主或公共追踪 DLL；历史命令草案尚未实现 |

`docs/next/logs/`、`docs/next/paper-data/` 与 `docs/next/evidence/` 保存带环境和日期的实验记录。这些历史文件保留原始事实，不作为当前全部功能的支持声明。

官网源码独立维护在 [Felix3322/KSwordWebsite](https://github.com/Felix3322/KSwordWebsite)。产品文案引用此文档中心及对应专题；更新流程见 [文档与官网维护](文档与官网维护.md)。
