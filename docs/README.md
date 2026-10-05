# KSword 文档中心

本文以当前仓库代码为准，最近核对日期：**2026-10-05**。发行包可能早于当前源码；功能入口、协议版本和能力状态应以实际运行版本为准。

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

`docs/next/logs/`、`docs/next/paper-data/` 与 `docs/next/evidence/` 保存带环境和日期的实验记录。这些历史文件保留原始事实，不作为当前全部功能的支持声明。

官网源码独立维护在 [Felix3322/KSwordWebsite](https://github.com/Felix3322/KSwordWebsite)。产品文案引用此文档中心及对应专题；更新流程见 [文档与官网维护](文档与官网维护.md)。
