# Memory Index

- [KSword UI/主题架构](ksword-ui-architecture.md) — theme.h token 体系、全局样式块链路、WindowChrome 标题栏染色、周期后台刷新与全局进度通知边界
- [标题栏全局搜索/双模式输入](ksword-global-ui-search.md) — GlobalUiSearch 架构、页面路径/高亮跳转链路、i18n 审计恒等词条与语言包定点插入约定
- [MSVC/WDK 构建恢复](ksword-build-recovery.md) — `LNK1000 IMAGE::BuildImage` 的一次性 WPO 禁用重建，以及驱动 x64 `ApiValidator` 后置校验边界
- [驱动候选地址安全读取](ksword-driver-safe-read.md) — 不可信内核地址统一使用 `KswordARKRuntimeReadMemory`，以及 Release 同构函数符号归因注意事项
- [蓝屏 BGP、截图基线与崩溃前解析缓存](ksword-bugcheck-bgp.md) — `BPP=1` 延迟探测、24/32 BPP 预生成、四区截图布局、进程/模块缓存、Stop Code 白名单归因与 fail-closed 边界
- [蓝屏 Shield PatchGuard 安全缓冲](ksword-bugcheck-shield.md) — 只走公共 BugCheck reason 回调、多阶段有界 stall、KSHL 确认令牌、绝不写私有 ntoskrnl 状态
- [CI 合并回归恢复](ksword-ci-merge-recovery.md) — Actions 日志收敛顺序、共享 IOCTL 编号兼容、WDK 令牌声明与 `/WX` 协议头约束
- [FileDock 文件元数据编辑](ksword-file-metadata-editor.md) — FILE_BASIC_INFO 零值写入、重解析点句柄、文件身份复核、结构性属性保留与异步回读
- [Win32k 消息 Hook 筛选](ksword-message-hook-filtering.md) — 同侧原子筛选、目标/所有者 UI 范围、异步旧结果抑制、Hook 独立预算与诊断
- [R0-only 进程身份校验](ksword-process-r0-identity.md) — 内核枚举创建时间、驱动对象校验、普通进程与仅 R0 可见进程的动作分流
- [KernelDock 内核知识中心](ksword-kernel-knowledge.md) — 71 专题双语目录、R3/R0 现场证据协议、业务 IOCTL 映射、只读站内路由与验证器约束
- [内核回调监控通道](ksword-callback-monitor.md) — Callback Monitor v1 多游标 ring、回调 try-lock 发布、Minifilter 双消费者与高频 Qt 模型提交边界
- [HVM 常驻生命周期保护](ksword-hvm-resident-lifecycle.md) — Intel-only 能力门、S0 电源回调、处理器拓扑冻结、DriverUnload 互锁与全核 VMXOFF 发布边界
- [KswordARKLight 调查工作台骨架](ksword-arklight-investigation-workbench.md) — 跨进程驱动租约、二级页懒加载、EntityRef 路由、证据会话与独立测试/CI 门禁
