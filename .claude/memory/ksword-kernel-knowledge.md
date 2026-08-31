---
name: ksword-kernel-knowledge
description: KernelDock 内核知识中心的 71 专题目录、双语文章、R3/R0 现场证据协议、只读路由与完整性校验约束
metadata:
  type: project
---

# KernelDock 内核知识中心

- 需求基线是仓库根目录 `第二规划.md`。它列出 12 类、71 个 Windows 内核知识专题，并要求每篇同时具备关系图、生命周期、公开/私有边界、只读观察路径、版本/权限/IRQL、错误处理、Ksword 字段解释和证据限制。
- 目录定义集中在 `Ksword5.1/Ksword5.1/KernelDock/KernelKnowledgeCatalog.*`；文章 UI 位于 `KernelKnowledgeTab.*`。新增文件必须继续同步 `.vcxproj` 和 `.vcxproj.filters`。
- 可见文章只存放在 `languages/zh-CN.json` 与 `languages/en-US.json` 的 `context_translations` 中，键格式为 `kernel.knowledge.topic.<id>.(title|summary|body)`。语言包只能定点编辑。
- 动态语义键必须调用 `ks::i18n::text(key)`，不能调用 `text(key, key)`：中文是历史源语言，非空 fallback 会优先返回 fallback，从而把键名直接显示给用户。验证器会拒绝这一回归。
- 71 个专题 ID 还与 `shared/driver/KswordArkResearchIoctl.h` 及 `research_topic_ioctl.c` 严格同序。`IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC` 只采集本次 R3→WDF→WDM 上下文并用中央表核实 1..4 个业务 IOCTL，不串行调用业务 handler，不触发扫描或 mutation。
- R3 只能通过 `ArkDriverClient/ArkDriverResearch.cpp` 调用专题协议，并必须校验版本、固定头、字节数、标志、保留字段、行数量/类型/状态和 NUL 终止。知识 UI 不得直接调用 `DeviceIoControl`；异步展示必须用 generation 丢弃切题后的旧结果。
- Catalog 的 71 项均为 `Coverage::Available` 且有业务页路由。“Available”表示共享协议、R0 handler、中央注册、R3 wrapper、UI 与至少一个真实业务入口闭环，不表示每台机器都拥有 PDB、硬件、权限或完整业务结果；运行态的 unsupported/partial/truncated/budget/unavailable 必须保留。
- `KernelDock::openKnowledgeRoute` 只做现有页签切换和惰性初始化，不模拟按钮点击，也不触发修复、摘除或写入；目标页仍可按自身生命周期执行首次只读加载。新增 routeId 必须同时加入白名单验证器并保持这一边界。
- 分类外部链接只允许 Microsoft Learn 官方驱动文档；私有布局仍需在正文中标明 PDB/DynData/推断来源。
- 改动后运行 `python tools/validate_kernel_knowledge.py`，再运行仓库要求的 `tools/i18n_language_pack.py audit` 和 IOCTL audit。验证器固定检查 12 类、71 专题、共享 ID/R0 映射/中央注册/R3 与工程条目、双语三键、八标题顺序、关系图和只读路由；Windows MSVC/Qt/WDK 编译由 CI 证明，未签名驱动实际加载需另行验证。
