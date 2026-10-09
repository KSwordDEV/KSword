# Memory Index

- [CLI 崩溃报告与 VMware 验收](ksword-cli-crash-report.md) — Unicode CRT 日志 fastfail、旧 OS build 门禁归因、参数/状态诊断、VIX 自动通道与只读回归

- [ETW 解析与进程归属](ksword-etw-decoding.md) — 事件头与关联身份、映像枚举、数组/结构体布局、网络端口和 TraceLogging 缓存

- [API Monitor 生命周期与事件协议](ksword-api-monitor.md) — x86/x64 工程与自动注入、JSON 定义、异步/覆盖协议、会话互斥、退役 Hook 保留与回归证据
- [Syscall 监控与 SysWhispers 兼容形态](ksword-syscall-monitor.md) — QPC 栈关联、进入/退出布局、系统映像信任、静态调用号边界与有界离线回归

- [欢迎页采样与 GPU 遥测蓝屏](ksword-welcome-gpu-telemetry.md) — 首页采样范围、GetNodePerfData 空指针现场、17763 系列禁用与 WDDM 2.4 门槛
- [KSword UI/主题架构](ksword-ui-architecture.md) — theme.h 动态/静态 token 边界与构建期门禁、全局样式块链路、WindowChrome 标题栏染色、周期后台刷新与全局进度通知边界
- [窗口控件检查](ksword-control-inspection.md) — UIA/Win32 独立树、悬停与选中分离、一次性拾取配对、透明覆盖裁剪及隐藏桌面 UIA 回归边界
- [内存工作台重写（进行中）](ksword-memory-workbench-rewrite.md) — 用户拍板的 D1–D4 决策、Phase 0 七个 Qt-free 逻辑类与 2587 条断言已落地登记、后续阶段与暂定参数、等价变异体的坑；设计文档在 docs/内存工作台重写设计.md
- [内存工作台夹具并行变异的四个坑](ksword-memwb-parallel-mutation-pitfalls.md) — 环境变量进程级会互相覆盖、并行构建写满系统盘、/W4 /WX 下常量条件变异编不过、NO_SUMMARY 不算被抓到
- [QTimer 戳阻塞 exec() 的两个坑](ksword-qtimer-popup-race-crash.md) — 嵌套第二层 singleShot 按引用捕获局部变量会在栈销毁后写入（整进程崩溃）；固定毫秒数在机器忙时会错过弹窗窗口，改 0ms 单层定时器 + 之后显式排空事件循环
- [统一内存编辑器与汇编](ksword-memory-editor.md) — Tab4/Tab6/R-1 共用快照编辑器、Intel 汇编语法、暂存与后端绑定、写前比对和最终回读
- [标题栏全局搜索/双模式输入](ksword-global-ui-search.md) — GlobalUiSearch 架构、页面路径/高亮跳转链路、i18n 审计恒等词条与语言包定点插入约定
- [MSVC/WDK 构建恢复](ksword-build-recovery.md) — `LNK1000 IMAGE::BuildImage` 的一次性 WPO 禁用重建，以及驱动 x64 `ApiValidator` 后置校验边界
- [驱动候选地址安全读取](ksword-driver-safe-read.md) — 不可信内核地址统一使用 `KswordARKRuntimeReadMemory`，以及 Release 同构函数符号归因注意事项
- [已卸载驱动来源布局](ksword-unloaded-driver-layout.md) — NtosActive 与单项可用性的区别、精确全局 RVA 的局部运行时布局补全、离线回归与实机边界
- [驱动 OS build 上限策略](ksword-driver-os-build-gate.md) — 2026-10-03 按用户要求注释 R0/Launcher 上限拦截与 runtime fallback build 防护，保留最低版本及逐功能校验；附历史 fail-closed 策略
- [蓝屏 BGP、截图基线与崩溃前解析缓存](ksword-bugcheck-bgp.md) — `BPP=1` 延迟探测、24/32 BPP 预生成、四区截图布局、进程/模块缓存、Stop Code 白名单归因与 fail-closed 边界
- [蓝屏 Shield PatchGuard 安全缓冲](ksword-bugcheck-shield.md) — 只走公共 BugCheck reason 回调、多阶段有界 stall、KSHL 确认令牌、绝不写私有 ntoskrnl 状态
- [CI 合并回归恢复](ksword-ci-merge-recovery.md) — Actions 日志收敛顺序、共享 IOCTL 编号兼容、WDK 令牌声明与 `/WX` 协议头约束
- [FileDock 文件元数据编辑](ksword-file-metadata-editor.md) — FILE_BASIC_INFO 零值写入、重解析点句柄、文件身份复核、结构性属性保留与异步回读
- [文件占用扫描与解锁](ksword-file-handle-usage.md) — 模块映射无可关闭句柄、自身进程保护、R3 35% 阶段、路径查询等待上限与不完整结果
- [句柄页 R3/R0 关闭](ksword-handle-close.md) — 行快照菜单、内核创建时间、独立关闭 IOCTL、挂起/恢复回执与旧枚举布局兼容
- [FileDock 右键菜单与特殊权限启动](ksword-file-context-menu.md) — 不可用动作隐藏、菜单顺序、System/TI/管理员/普通用户令牌启动及验收边界
- [FileDock 大目录响应性](ksword-filedock-latency.md) — 快照模型、缓存排序、后台重解析标记与状态查询、十万项全选回归
- [R0 文件删除边界](ksword-file-delete.md) — POSIX 路径移除、共享检查高风险模式、回执兼容与 Win10 动态入口
- [Win32k 消息 Hook 筛选](ksword-message-hook-filtering.md) — 同侧原子筛选、目标/所有者 UI 范围、异步旧结果抑制、Hook 独立预算与诊断
- [Win32k 窗口 Band 事务](ksword-window-band-control.md) — 跨 UIAccess 原生顺序、精确版本 ABI、GUI 调用线程、恢复及未完成的实机验收
- [R0-only 进程身份校验](ksword-process-r0-identity.md) — 内核枚举创建时间、驱动对象校验、普通进程与仅 R0 可见进程的动作分流
- [进程列表 R0 字段显示](ksword-process-list-fields.md) — 保护来源提示、PS_PROTECTION 名称解码与 HandleTable 空值/不可用区别
- [KernelDock 内核知识中心](ksword-kernel-knowledge.md) — 71 专题双语目录、R3/R0 现场证据协议、业务 IOCTL 映射、只读站内路由与验证器约束
- [内核回调监控通道](ksword-callback-monitor.md) — Callback Monitor v1 多游标 ring、回调 try-lock 发布、Minifilter 双消费者与高频 Qt 模型提交边界
- [Object Callback 安全注销](ksword-object-callback-remove.md) — PDB RegistrationHandle 语义、EX 行身份/代次重验证、ObUnRegisterCallbacks 与移除后复核边界
- [扩展回调注销研究](ksword-callback-remove-research.md) — OpenArk/WinObjEx64 源码、Registry Cookie 校准、特殊类别真实参数、Image Verification 包装器计数与 ETW/EMP 句柄缺口
- [HVM 常驻生命周期保护](ksword-hvm-resident-lifecycle.md) — Intel/AMD 准入与 UI 状态发布、S0 电源回调、处理器拓扑冻结、DriverUnload 互锁与全核退出边界
- [调试器共享后端与 x64dbg 适配](ksword-debugger-backend.md) — 原生会话借用、64 导出 ABI、真实 Windows 停止事件、HVM 执行断点、独立调试器与控制日志 Tab
- [AMD SVM/NPT 实验与重启续接](ksword-hvm-amd-lab.md) — 待硬件验收实现、双启动脚本、VMware 克隆、构建证据与未完成的多核验证
- [KswordARKLight 调查工作台骨架](ksword-arklight-investigation-workbench.md) — 跨进程驱动租约、二级页懒加载、EntityRef 路由、证据会话与独立测试/CI 门禁
- [内核池分配分析](ksword-pool-allocation-analysis.md) — PoolTrace v2 真实布局、会话隔离、未知位置丢失配对、历史栈来源、共享 DbgHelp 锁与 Qt 6.9 窄窗
- [剪贴板保护会话生命周期](ksword-clipboard-guard.md) — Agent 配置热更新、停止标记、管道整包读取与 Hook 就绪状态
- [UAC 安全桌面助手生命周期](ksword-uacdesk-lifecycle.md) — 父进程阻塞等待与取消、ETW 清理、所有配置禁用文件/调试日志及验证边界
- [驱动功能矩阵 CI](ksword-driver-functional-ci.md) — 185 IOCTL 全量处置门禁、危险操作模式排除、targetGuard 目标校验、PatchGuard 延迟崩溃的归因降级
- [进程注入痕迹检查](ksword-injection-trace-check.md) — InjectionSurvey 判据层分层与不变式、能力限制与覆盖缺口的分界、交叉视图矛盾分档、两项需按能力单独提权的采集

- [Light R3 shared backend migration](ksword-r3-backend-migration.md) — 逐功能迁移至 shared、保留行为、HostX64 编译与测试后独立提交
