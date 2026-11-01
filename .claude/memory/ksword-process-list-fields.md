# 进程列表 R0 字段显示

## 2026-11-01 历史进程树

- 入口：进程 Dock → 进程列表 → 时间轴历史点；开关统一命名“友好视图”：勾选按应用/后台/系统分组，取消后按该时刻的进程树显示。此前实际文案误写为“进程树视图”，导致名称与勾选行为相反，现已同步修正中英文及提示。保留既有 TablePresentation、FlatTableModel、GPU 表格视口与工具行，没有新增页面或窗口。
- `ProcessActivityProcessPoint` 记录原始 `parentPid` 和同一采样中确认的 `parentCreationTime100ns`；父 PID 不存在、父实例比子进程更新、创建时间缺失/合成或自引用时不建立关系。历史回放保留 PPID，但不能借用实时缓存补父节点。
- 实时树和历史树共用 `buildProcessTreeDisplayOrder`；历史路径严格核对父 PID＋创建时间。迭代遍历处理长父链，环断开后所有节点仍只出现一次。历史搜索保持扁平，清空搜索恢复树；点表头可切到该时刻的扁平排序。
- 切换友好/树状显示或列预设不再丢弃当前历史快照。每轮另保存可见窗口归属、隐藏标记和 kernel-only 状态，历史记录与实时共用列表、树及友好分组投影器；历史友好分组只从冻结的窗口归属和已确认父实例推导，不枚举当前窗口。已淘汰的选中样本继续由独立记录保有父子身份及分组依据；恢复实时后才显示当前树。
- 定向入口 `python tools/process_activity_tree_tests.py` 编译生产采样身份、回放和树投影方法，覆盖 PID 复用、缺父、未知身份、搜索/扁平/树切换、冻结样本淘汰、环和 2 万节点父链。产品构建与用户实际 GUI 验收状态按当次交付报告。

- 保护状态列只显示原始字节；`Runtime pattern`、PDB 等字段来源保留在悬停提示中，用于诊断偏移来源。
- PPL 列按 `shared/driver/KswordArkProcessIoctl.h` 的 PS_PROTECTION 位域解码：Type 位 0–2、Audit 位 3、Signer 位 4–7。Type=0 显示 `-`；2026-10-05 按用户要求改为仅显示 signer 名称（如 `Antimalware` / `WinTCB`），完整原始代码在前面的保护状态列显示；未知类型或 signer 显示 `Unknown`，不能误报无保护。保护状态、PPL、HandleTable、SectionObject 未采集时均显示 `-`，字段来源保留在悬停提示中。
- HandleTable、SectionObject 只显示实际地址，移除 `Available:` 与来源括号；字段不可用或地址为空都显示 `-`，字段来源放在提示中。
- 显示入口在 `ProcessDock.cpp` 的 `formatColumnText` 与 `processTableData`。新增提示同时定点补充双语包的 `context_translations` 和 `source_translations`，两者缺一会使 i18n 审计失败。

## 2026-10-05 内存列拆分

- 复用既有 `WorkingSet` 与 `CommitSize` 列取代合并 RAM，名称分别为“内存使用”与“内存申请”，单元格及表头汇总均以 MB 显示。使用取 `rawWorkingSetBytes`，申请取 `commitSizeBytes`；申请未采集时显示 `-`，不纳入申请表头汇总。
- 两列移动到旧 RAM 的视觉位置；旧 `Ram` 逻辑索引保留但不再出现在列选择入口。旧 RAM 显隐覆盖与自定义视图载入时迁移到两列，已保存的独立列覆盖优先，不能删除枚举项导致后续保存索引整体漂移。
- 内存使用包含共享页，跨进程汇总可能重复统计共享页；表头是当前筛选进程的列汇总，不是系统物理内存利用率。

## SectionObject 实机核查（2026-10-03）

- 本机内核 `10.0.19041.7725`，RSDS `63950D24-7362-0017-E1FC-214544590A77/1`，PE SHA256 `b3de5c162d582e0e3cbb27977fd82c2d8212d18fbc3f70bb8bf7e0c4a5925960`。精确 PDB 与导出访问器均给出 `_EPROCESS.SectionObject=0x518`。
- 已加载服务使用 `Ksword5.1/x64/Ksword-nice/KswordARK.sys`，该运行目录的旧压缩配置包只有 2405 项且没有当前内核匹配项。驱动现场的 `EpSectionObject` 为 `0xFFFFFFFF` / Unavailable，进程枚举因此未读取该字段。已备份并同步新版 2406 项包，原有 2405 项逐项完全一致。
- `process_resolver.c` 的运行时回退在驱动初始化期间取 `PsGetCurrentProcess()` 校验候选对象；加载阶段的 System 样本在 `0x518` 处实测为 0，普通进程则为非零。只用该样本校验会把正确偏移拒绝为不可用。此回退代码尚未修改；不能把“全不可用”认定为所有进程都没有 SectionObject。
- 通过现有 `dyn apply-profile` 接口只合入精确字段 item 2 后，驱动回读为 `0x518` / PDB profile，独立 PowerShell 枚举返回有效 Section 指针；前 30 条记录中 25 条非零。System、Secure System、Registry 等可能真实为空。此验证没有写 EPROCESS、替换或重新装载驱动。
- 进程列表指针可读不代表完整 Section 映射枚举可用：`section query-process` 仍受 `_SECTION.ControlArea` 与映射链布局依赖约束，本次仍仅由公共文件对象路径获得 ControlArea。
- 现场日志与旧配置备份位于 `.codex-build-logs/process-columns-20261002/`。管理员只读诊断可用隐藏窗口的独立 PowerShell 进程执行 CLI 并落盘；普通会话的 Win32 5 仅代表访问被拒，不能据此推断驱动功能失败。

## 2026-10-03 内存采集口径诊断

- 当前进程列表策略默认为 `NtQuerySystemInformation(SystemProcessInformation)`（策略下拉框 index=1），并非默认 Toolhelp。NtQuery 已填充动态计数器时，刷新缓存路径不会再用 PSAPI 覆盖内存字段。
- RAM 单元格的“使用”是 `WorkingSetSize`（含共享页的总工作集），“申请”是 `PrivatePageCount` / PSAPI `PrivateUsage`（私有提交量，不是虚拟地址保留量）。任务管理器的默认内存列通常采用专用或活动专用工作集，不能直接比较上述两项；应按 PID 在两边选择同名指标。
- 内存视图已有“工作集”“内存(专用工作集)”“内存(活动的专用工作集)”等独立列；NtQuery 专用工作集来自 `WorkingSetPrivateSize`，按字节使用，不乘页大小。
- `updateUsageSummaryInHeader` 的 RAM 表头汇总 `ramMB`（私有提交），RAM 行排序却按 `workingSetMB`（总工作集）；表头不是全系统物理内存利用率，且受搜索/隐藏筛选影响。即使汇总总工作集，也会重复计算共享页，不能作为系统物理用量。
- 默认采样间隔 1 秒，列表显示间隔 2 秒；历史时间轴还可切换到旧样本。比较必须对齐指标、进程身份和采样时刻。
- 活动专用工作集目前只是“全部线程 Waiting 且 Suspended/WrSuspended 则清零，否则等于专用工作集”的派生值。这不是单独采到的系统活动内存计数，不能仅依据现有代码注释宣称所有 Windows 版本及挂起场景均与任务管理器一致。
- Toolhelp 补采使用 `PROCESS_MEMORY_COUNTERS_EX`，没有专用工作集；还把 `PROCESS_VM_READ` 和受限查询权限绑定打开，失败后只补句柄数。现代 Windows 的 `GetProcessMemoryInfo` 只要求查询权限，可改为独立采集；支持的系统可用 `PROCESS_MEMORY_COUNTERS_EX2.PrivateWorkingSetSize`，旧系统保留明确回退/不可用状态。EX2 官方最低版本为 Windows 10/11 22H2 加 2023 年 9 月累积更新。
- 本机一次只读 x64 对照（非任务管理器 UI 验收）：explorer PID 14456 总工作集 216.06 MiB、专用工作集 91.04 MiB、私有提交 252.87 MiB；KSword PID 33216 分别 384.71/326.37/362.07 MiB。两者的 NtQuery 与 PSAPI EX2 同指标在 0.01 MiB 显示精度内一致；部分 svchost 拒绝 OpenProcess，但 NtQuery 仍返回内存计数。该证据支持统计口径差异及系统级快照的覆盖优势，不证明任意时刻/目标/API 均完全一致。
- 官方定义参考：[GetProcessMemoryInfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo)、[PROCESS_MEMORY_COUNTERS_EX2](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex2)。后续修改优先统一列名、字段与汇总口径，保留 NtQuery 批量采集；切换 API 本身不能消除不同指标的差异。
