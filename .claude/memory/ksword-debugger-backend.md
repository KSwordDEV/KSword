# 调试器共享后端与 x64dbg 适配

- CE 与 x64dbg 共用 `DebuggerBackend/`；R0 协议仍只定义在 `shared/driver/`，设备访问仍通过 `ArkDriverClient/`。
- `TitanEnginePlugin/` 的规范 ABI 是 x64dbg `f107330b6563da3c38d60a3ad6e629057b7cf5d0` 的 64 个导出，原生 TitanEngine 固定 `21ef77f31fd42d17f785802c36b2ca4ca44c43d7`。源头、检查器及声明见 `third_party/x64dbg_abi/`。
- 代理放在运行目录 `KSword/TitanEngine.dll`，原生依赖保留在上一级 `TitanEngine.dll`。两者均校验 AMD64/导出并固定进程生命周期；初始化不放在 DllMain。保留原生成功/失败 LastError。
- x64dbg 核心只增加 `DebugEngineKSword=4`，沿现有 checked loader 加载；补丁及基线在 `X96dbgIntegration/`。启动器使用真实 `-userdir` 和每会话 INI，不能发明 GUI 不接受的 `--engine` 参数。
- `X96dbgExecutablePlugin/` 的 ID 是 `x96dbg`，仅发行 x64dbg AMD64。KSword Tab 为配色/等宽控制日志页，调试器保持独立窗口。页面关闭不应终止调试器或目标。
- 默认原生模式不依赖驱动。HVM 控制使用 SESSION/REVISION 文件请求和实际状态确认；活动目标必须持有真实 Windows 调试事件且清空已有硬件绑定后，才允许切换模式。
- `DebuggerBackend` 原生会话 API 只借用前端会话，不能二次 attach，也不能抢 Wait/Continue。保留进程/线程句柄身份及代次，防止 PID/TID 重用和旧回调。
- HVM 硬件执行断点通过驱动精确线程/RIP 筛选和 guest #DB，交给原生 Windows `EXCEPTION_SINGLE_STEP` / Titan DebugLoop。历史 ring 事件不能伪装成当前停止，也不能由轮询线程调用前端断点回调。
- 代理仅改原生 DLL 内六个 IAT 槽：GetThreadContext、SetThreadContext、WaitForDebugEvent、ContinueDebugEvent、ReadProcessMemory、WriteProcessMemory。完整 GPR/SIMD/XSTATE 留给 Windows；内部断点读取见逻辑 INT3，公开内存读取见原字节。常规 EPT 保留 Windows DR6；CE ShadowPage 停止只在匹配的真实持有事件中叠加命中槽/RIP。DR7 先于地址的短序列必须暂存，未完成或失败时不能继续。
- Titan HVM 下通用硬件写/读写断点返回 ERROR_NOT_SUPPORTED，不能将 4 KiB EPT 数据页语义冒充字节范围。软件断点保留原生循环并支持隐藏 INT3，通用内存断点仍原生；显式 Watch 和完整 HVM 命令通过版本化 KSwordDebuggerCall。
- 常规 HVM 执行断点不可用时，公共后端自动尝试 EPTP 切换的 ShadowPage 隐藏 INT3（不要求 MTF）。原生协议操作 8/9 管理目标页 MDL、owner/target 进程引用、同页偏移合并及进程退出清理。不能接管外部准备/常驻；目标映射更换仍要重装。
- CE 标题是 KSword HVM / KSword R0 / KSword Connected；Connected 表示桥接已连接但驱动不可用，保留 CE 原函数表。VM 中 R0 上下文错误 31、挂起计数导出缺失会明确记录并用 Windows 接口，策略/身份拒绝不回退。进程内 Lua 缓冲区自读写不得送往目标驱动内存接口。
- 控制/确认文件读取必须允许 FILE_SHARE_READ/WRITE/DELETE，并在解析/等待前关闭句柄。否则第二次原子替换会因共享冲突失败。普通原生 StepInto/StepOver 不能套用硬件停止的延迟回调；只对真实匹配的自有硬件停止采用事件代次保护。
- 单步完成先在策略锁内退休私有回调记录，再释放锁调用前端回调。真实 x64dbg 暂停回调会等 Run；持锁调用会使另一线程的上下文查询死锁。实际命令层 HVM attach/bphws/mov/sti/run/bphwc/detach 已验证，DLL 回调 fixture 不能替代这个检查。
- 清理仅处理自动适配记录的私有 ID；外部已准备/常驻状态会阻止自动准备。原生出口、线程退出、模块卸载及内存释放需要清理。Decommit 按 Windows 实际页舍入处理，并检查地址溢出；模块通过 PID/AllocationBase 匹配。原始规则由调用者负责，不能混入自动持有的准备。
- 构建脚本 `tools/Build-X96dbgPayload.ps1` 必须使 CMake 探测进程也使用 AMD64 环境及 64 位 MSBuild；仅 `-T host=x64` 在本机可能仍探测 HostX86。MSBuild 始终传三项架构属性并读回 HostX64。
- `tools/export_x96dbg_source.py` 导出可构建源码及固定上游源码 ZIP，`tools/package_x96dbg_plugin.ps1` 校验 64 位 PE、64 导出与实际 bridge 标记，保留源代码/原始许可证并生成哈希清单。插件 ZIP 根直接为 plugin.json，解压到 plugin/x96dbg。
- 2026-09-30 后续在 KSword-HVM-Target（Win11 22621.4317、2 vCPU）加载匹配驱动，真实 GUI、CE R0/HVM 扫描、三态标题、CE 硬件/软件隐藏 INT3、Titan 完整上下文修改/单步/重复命中、ShadowPage owner/target 死亡清理均通过。最终全量原生回归 85/85 PASS、2 回放 SKIP；实际两个 Tab 连续开关与关闭保持独立调试器也通过。此 VM 缺 MTF，原始 MTF/EPT #DB 路由不支持；已验收自动 ShadowPage 执行回退。16 项 HVM 通路/布局检查不代表所有变更操作实测。准确产物哈希和边界见 `docs/ksword-debugger-vm-validation.md`。

## 2026-09-30 后续策略与 Shadow 代码补丁

- 公共 C ABI 命令 4/5/6/7 为 GET_OPTIONS / SET_OPTIONS / QUERY_POLICY / RESTORE_SHADOW_WRITES。选项 v1 为 48 字节（mode、shadowMemoryWrites、allowFallback、强制开启 logFallback、nativeContextFallback、nativeSuspendFallback、maxShadowPages=1..32），策略为 72 字节；路径 Native=0、EPT=1、Shadow=2。旧调用/默认行为保留；离线选项不初始化驱动，失败 ACK 返回实际选项，有自有绑定/补丁时不能更改策略。
- 常规 HVM 保留自动执行回退，隐蔽模式优先 Shadow，不允许真实代码/可见 INT3/真实执行 DR 回退。非可执行数据在 allowFallback=1 时可普通写入，隐蔽模式也允许该明确数据回退；每次记录原因及实际完成/失败、字节数。上下文/挂起还受对应自定义开关约束。
- CE Shadow 代码写入默认关闭，显式启用后修改可执行页执行视图，普通数据读取保持原字节。RX/RWX 不能判定代码意图，RWX 可能包含冻结数据；不能宣称通用数据冻结隐身。代码 Shadow 需要 HVM，失败不会普通写回原代码。单次同页最多 1232 字节；跨页、超限或代码/数据混合范围修改前拒绝。
- 代码补丁和隐藏 INT3 均接受 MEM_PRIVATE 或已 COW 私有化的 MEM_IMAGE / MEM_MAPPED；锁页后必须 working-set Valid=1、Shared=0，并复查当前 VA/PFN。COW 后 Windows 仍报告映像/映射类型，不能按类型误拒绝。仍共享的页面错误 50 明确提示 requires Windows COW-private backing，不自动向运行目标同字节写入来触发 COW。视图按物理页生效，不保证 PID/CR3 隔离；映射替换仍需重新安装。
- 驱动原生操作 10/11 写入/恢复 PatchMask，INT3 层优先，恢复内存补丁保留断点。旧补丁回放失败用操作 12 标记 owner/target 内容隔离；适配器 start/continue 和驱动直接 START 都拒绝，只有完整成功恢复清除，部分恢复不清除。完整恢复、进程退出、驱动卸载清理引用。
- START 先取得 Shadow 共享锁租约、验证所有 owner 视图/隔离，再取得 HVM 锁，统一出口先释放 HVM 再释放租约，防止检查到启动间视图被改。Shadow 变更及退出清理按 Shadow→HVM 顺序；Shadow 内不调用 START。租约的临界区进入/退出包括失败出口均平衡。
- 本轮模型 PASS（包括第二段旧字节回放失败的隔离/完整恢复）；驱动完整 WDK Build、x64 ApiValidator、CAT PASS；CE/Titan Release/x64 构建 PASS，均 0 警告/错误。安装布局 8 例及实际 VM 受控市场安装 PASS，主程序构建退出码 0、i18n 26697 条通过（`ksword-build-check-20260930-205354.raw.log`）；用户运行目录新版已部署并核对哈希，该目录市场操作仍待最终复测。本轮策略 offline、memory、normal-native、normal-hvm 实时 PASS：执行补丁 `0xff`、普通读原始、恢复执行 `0x101`，数据回退和无半写入拒绝通过。
- 本轮最终六阶段实时全部 PASS（offline、memory、normal-native、normal-hvm、stealth-hvm、stealth-no-hvm），证据 `.codex-build-logs/debugger-vm/policy-final-run.log` 的 `FINAL PASS policy regression`。首轮隐蔽模式问题已修复：原生 Titan 回调前暂时移除物理 INT3，状态必须按已安装的逻辑绑定报告，不能按当前物理字节或所选模式推断。恢复最后内存补丁后路径 Shadow=2、逻辑断点 1，恢复后的第二次真实隐藏 INT3 命中已通过；HVM 关闭的隐蔽模式明确拒绝可见 DR 回退。修复后构建见 `x96-policy-titan-route-build.log`，0 警告/错误。
- 最终策略复验前显式恢复 KswordARK 服务；服务不存在时 readiness 错误 2 不属于功能验收。之前 85/85 属于前一轮基线，本轮六阶段有独立实时证据；新插件在用户运行目录的实际部署和界面验证尚未包含在该后端测试内。保留首轮失败证据 `debugger-vm/policy-result-first.json`、`policy-stealth-first.log`，准确状态与范围见 `docs/ksword-debugger-vm-validation.md` 的后续策略章节。
- 后续 COW/上下文准备修正模型通过：prepared/resident 外部所有权在修改前拒绝，不 STOP/TEARDOWN/写上下文或假回滚；真实修改失败仍恢复。重复诊断按独立原因最多 64 键合并，首次和累计 10/100/1000 次输出；回退计数和实际错误 31 每次保留，日志不改调用方 LastError。证据 `.codex-build-logs/debugger-image-cow-model-results.log`。
- 新七阶段实际 VM 合计 490 PASS：offline 29、memory 130、image-cow 109、normal-native 55、normal-hvm 59、stealth-hvm 82、stealth-no-hvm 26。模块页先 Shared=1 拒绝 50；受控 Windows 同原字节 COW 后仍 MEM_IMAGE/Shared=0，Shadow 使目标执行 102，双方普通读及另一进程执行保持 101，恢复执行 101。证据 `.codex-build-logs/debugger-vm/policy-cow-ready-run.log` / `policy-cow-result.json`（passed=true）。驱动 65545A14...、CE 6A5B25F8...、Titan D85AA8C9...、目标 DC85BF56... 的完整中间身份见验收文档；该轮早于最后常规 HVM 仅数据 DR 上下文修正。
- 最后仅数据 DR 修正已通过 BackendTests：常规允许回退时原生 DR 设置、替换、清零、继续、线程/会话退休都不修改外部 prepared/resident，清零/退休解除策略占用；隐蔽或禁用回退明确拒绝可见 DR。证据 `.codex-build-logs/debugger-final-model-results.log`；实际 CE 验收另见后条。
- 最终 CE `1C569800FF2F472D5660B7840C5C47DA8C7A9A5483576EDDBEC95C93D9750600`、Titan `36CC7773A4EFBA33AB6AFDB4ECF3D0F703D69C2BF489EA2A37F9A15F2BEDD6C1`（驱动/目标不变）生产 VM 再跑七阶段 490 PASS，日志 `debugger-vm/policy-final-cow-data-run.log` FINAL PASS，已取回 `policy-final-cow-data-result.json` passed=true。真实原生代理兼容/依赖拒绝也通过 `debugger-final-proxy-results.log`，不打开驱动。后续独立生产 GUI 也通过，见后条。
- 实际 CE 数据观察断点独立通过 147 项（`debugger-vm/ce-data-live.log` FINAL PASS）：8 字节写断点真实 Windows #DB/DR6 数据槽命中，store 后 RIP/RAX/数据=0x101；清除后原始 Windows DR0–DR3=0、DR6=0、DR7=0，backend bindings=0/canChange=true；第二次 store counter=2 且回调 hits=1。外部 HVM generation81、prepared2、resident2/2 全程不变且无自有 EPT/Shadow；测试所有者最后 STOP/TEARDOWN 成功，generation83、prepared/resident0（`ce-data-hvm.log`）。该路径是可见原生数据 DR，不宣称隐藏数据断点。
- CE debug_getBreakpointList 可包含已禁用/markedfordeletion 的条目：getBreakpointAddresses 不过滤，RemoveBreakpoint 先禁用再由 idle cleanup 删除。即时列表非空不能证明仍活动；验收必须看原始 Windows DR、后端绑定/策略占用、再次真实写入无命中。上述实际 CE 测试确认此残留只是内部记账，未修改 CE 删除逻辑。
- 最终真实生产 GUI 315 PASS（`debugger-vm/gui-tabs-final.log` FINAL PASS）：用户目录 KSword 与两页 PluginHost 选项、六切换项/页预算、出站新 revision 和实际 ACK、错误选项不改当前/保存配置、独立 CE/x64dbg 顶层窗口、Consolas 与真实转发日志。真实新会话重新加载已保存自定义选项且 HVM off，最终无绑定/补丁页；`gui-tabs-owned-processes.json` Outcome=PASS、FreshSessionReload=true、OriginalPreferencesRestored=true，任务返回 0。
- GUI 首次失败属于 fixture 顺序：CE action1 只修改 options，不关闭已保存的 HVM 选择；必须先 action0 关闭 HVM 并 ACK，再 action1 设置选项。初始化/结束步骤已修，产品/DLL 身份未变。上述验收与之前 85/85 和早期 GUI 基线分别保留。
- 最终源码 ZIP 已重生成，CE 2.1.0 / x96dbg 1.1.0 根清单包校验通过并部署到用户运行目录；安装后的 338 / 125 个清单文件全部 SHA256 一致。用户 Main/CE/x64dbg 已重新打开，六个策略控件存在，实际加载的 CE/Titan DLL 与最终构建相同；CE 可见主窗为 `Cheat Engine (Admin) [KSword HVM]`。测试 HVM prepared/resident=0，7 个已完成的自有测试任务已移除。汇总证据 `dist/KSword-debugger-final-validation.json`；本轮新修改/插件包尚未提交或推送。
- Lazarus 的 `Get-Process.MainWindowTitle` 可能返回辅助应用窗 `Cheat Engine`，而可见 CE 主窗已有 KSword 三态标题。标题验收需按精确 CE PID 枚举可见顶层窗，不能把该辅助窗标题当作主窗标题更新失败。
- 2026-10-01 修复 x64dbg 硬件 / 内存安装失败的 `BpNew` 残留，及 Enable all 硬件失败后的错误 Enabled / 槽位状态；保留 LastError。Titan 内部重复恢复已匹配的单字节不再误建 Shadow 写入页。共享后端 / Titan 记录物理安装、临时撤销与真实命中。用户指定 PS Direct 光标控制后，真实 UI 已通过 x64dbg 的隐藏 / 常规 / 原生执行、软件断点、数据 DR、PAGE_GUARD、失败清理重试、Enable all 拒绝及最终隐藏执行单步 / 删除无再命中。最终 x64dbg `98627DE5...`、Titan `DDD39FC6...` 已部署并验证实际加载；候选尚未发布。截图序号 / 哈希 / 各候选验证边界见 `docs/ksword-debugger-vm-validation.md`；GUI 目标在 `tools/breakpoint_demo/breakpoint_demo_gui.c`。按用户顺序完成 x64dbg 后继续了 CE；两者独立证据见该文档，旧 315 项配置页测试不能代替本轮前端实际场景。
- 2026-10-01 CE 真实 UI 暴露 SetValue / freeze 临时把普通数据页改为 RWX，导致旧策略误装执行 Shadow 补丁、数值修改 / 冻结无效。适配器现在验证同线程单次保护事务，DuplicateHandle 保留原进程对象，确认原始非执行区域及当前映射后传入内部数据意图；允许回退才真正写数据并记录结果，严格模式拒绝。完整 CE 候选 `BCBDF20E...` 已实测扫描、改值 / 冻结 / 解冻、Shadow inc→dec / 恢复、隐藏执行断点重复命中 / F7 / 删除、Find what writes 两次记录 / Stop、严格数据拒绝。最终 `5F44E66B...` 再测改值 / 冻结 / 解冻、严格 HVM 失败日志；目标未解析页可读 ??，实际按钮访问后读取恢复，不能宣称所有非驻留页可读。最终无冻结 / 绑定 / Shadow 页，原偏好恢复、标题 R0，worker 601 正常退出 / 任务移除。原 RX / RWX 混合页仍需要显式写入意图；最终 CE 新日志尚未编入当前 Titan 候选。源码与包未发布。
- 2026-10-01 Issue #3983 指向 PR #3974 的 API 形态；PR 最新 head `de6fc34df7cb01edea28f40c8b5c49d37bc1c0fb` 的头 / 64 导出与当前固定 `f107330b...` 一致，仍 open。已有内存 / 线程 / Pause / Session API 足够常规接入与 GUI 失败回滚；后续建议可选的断点实际机制 / 范围查询、Original / Execution / DebuggerLogical 视图及版本化配置扩展。当前 GetSessionInfo 仍转发原生，前端缓存会话能力；模式改变需配套刷新。64 导出齐备不证明所有操作走 HVM，保留原生 Titan 循环仍需要内部六 IAT 适配；详见 `docs/ksword-x64dbg-api-review.md`。

## 2026-10-07 内存视图地址导航桥接

- `UI/X64DbgNavigation.*` 经现有 launcher 的 `navigate` 命令异步接入；目标包含 PID、创建时间、VA 与 CPU/Dump 视图。快照必须在读取时冻结创建时间，不能在稍后菜单打开时给旧 PID 补查新进程身份。
- 新 `X96dbgIntegration/NavigationBridge/` 是 x64dbg 的 `.dp64/.dp32` SDK 插件；固定宽度管道只提供 Query/Navigate，不提供命令执行、附加、运行、暂停、分离、断点或写内存。GUI 线程内复核目标身份并读回实际选择地址才 ACK；客户端核对管道服务器 PID、保留调试器句柄及创建时间。
- 官方 attach 实现会先 Stop 或 Detach 旧目标，因此绝不能给忙实例发 attach。同 PID/创建时间才复用既有桥接实例；未知调试器占用返回错误。新目标只启动独立实例，等待 `CB_SYSTEMBREAKPOINT` 后的 `CB_PAUSEDEBUG` 再定位，默认保留附加暂停。标准安装需有匹配位数桥接插件，缺件明确报错；随包仍为 AMD64，Win32 插件可单独构建。
- 既有会话导航不调用运行控制、不修改引擎/策略；新标准安装使用独立 native userdir，随包使用 Engine=4。关闭页面、launcher 或 KSword 不终止独立调试器/目标。异步超时不触发二次附加；GUI 任务取消且排队 DLL 回调未消费时拒绝卸载。
- `GetCurrentProcess()` 的合法伪句柄是 -1，与文件 API 的 INVALID_HANDLE_VALUE 相同。读取进程创建时间时不能按文件句柄规则拒绝它，否则自身管道端点创建时间错误为 0。
- Win32 真管道假 SDK 夹具（`NavigationBridge/tests/`）已通过 PID/创建时间拒绝、精确地址 ACK、暂停/运行保持、协议拒绝、系统断点→暂停就绪、超时取消和 DLL 卸载生命周期；目标是夹具自身，没有真实 debug attach。受限沙箱的本地管道返回 Win32=5，正常本机权限下通过。Qt helper/launcher 源码与 PowerShell 脚本语法检查通过；本轮没有生产 HostX64 MSVC 构建、真实 x64dbg GUI/附加或 x32 运行验证，不能将夹具 PASS 当作这些验收。

- **2026-10-07 x64dbg 地址导航**：新增 `X96dbgIntegration/NavigationBridge` 窄插件（dp64/dp32）与 `NavigationProtocol/NavigationClient`，`X96dbgExecutablePlugin` 增加 navigate，主程序统一 `UI/X64DbgNavigation` 入口。按目标 PID+创建时间查询已有桥接会话，同目标仅 GUI CPU/Dump 导航并回 ACK；不同目标开独立实例，未知调试器占用不抢占。桥接没有运行控制/attach API；新实例由 launcher `-p` 附加并等本次系统断点暂停后定位，保持暂停。原版安装需加载同桥接。ACK 不能用进程启动成功或命令入队成功替代。
- 自有假 SDK 的真实 named-pipe 测试覆盖身份错配、非法协议/操作、运行/暂停保持、回调超时取消后不延迟定位，以及 pending 回调禁止卸载。未操作用户调试进程，未实测真实 x64dbg GUI/首次系统断点附加。普通进程伪句柄 `GetCurrentProcess()` 为 -1，不能按文件 `INVALID_HANDLE_VALUE` 判断为无效；创建时间查询需要允许这个伪句柄。
- **2026-10-07 中断恢复后对抗审查**：回调入口检查取消不足以保护慢 snapshot/CIP；所有前置查询结束后、第一条 GUI 副作用前用 Pending/Committed/Cancelled/Finished 原子阶段仲裁。取消赢则不跳转；已提交超时返回 ERROR_IO_PENDING，UI 明示结果未确认且不自动重试。CIP 一次冻结于提交前。服务端 WriteFile 完成不代表客户端消费，立即 DisconnectNamedPipe 实测 2000 次中丢 5 次回复；协议升至 v2，客户端完整核验回复后发带 requestId 的 typed Receipt，服务端只用有界 I/O 等待再断开，不使用可能无界阻塞的 FlushFileBuffers。修复后独立压力 2000/2000，删除回执及把 CIP 移到提交后两种变异均被持久测试抓到；launcher 工程/filter 同步登记两个导航头。工作台菜单拒绝无创建时间的弱会话，不给缓存 PID 补授新进程身份。

## 2026-10-17 不附加内存调试

- “内存 → 内存调试”的运行控制独立于原 `DebuggerBackend` 和 Titan/CE 原生调试循环。R3 线程检查只增加、归还自己的一次线程挂起计数；PID/TID 都绑定创建时间并保留对象句柄。原生自有进程 47 项、故障转发 66 项通过，不代表主程序 GUI 或 HVM 硬件验收。
- `shared/debug/CooperativeDebugClient.*` 与 `tools/cooperative_debug/` 提供目标主动静态链接的 VEH 调试组件，使用真实检查点与自有 TF 异常单步，不自动注入。关闭取消 I/O 并断连，服务端按 owner/租约释放；TF 在途时不能卸载异常消费者或把线程所有权交给新会话。真实 50 项断言通过，步进前后 DebugPort=0、DebugObject=STATUS_PORT_NOT_SET/null；不据此宣称任意第三方进程无需组件可调试。
- 实验 HVM 路径使用独立 `KswordArkHvmNoAttachIoctl.h` 与 `ArkHvmNoAttachClient`，通过预建的 MBEC 三根表、当前 ETHREAD/TEB/CPL 核验、MTF 和独立 sessionId/stopId 控制一个用户态线程。只支持满足条件的 Intel 独占生命周期；已有外部 HVM 状态不接管。查询或选择模式不启动 HVM。
- VMX root 不等待 GUI、不分配；通用 fault 退出也必须先撤销停止发布。快照与状态同代读取，Step/Continue 消费停点后仍需复核真实现场；CONTINUE_PENDING 不得当成已运行。当前 GPR 显示不包含 XSTATE，运行路径仍须遵守既有 FXSAVE/legacy SIMD 保护。退出失败保留映射、引用与恢复身份，文件 Cleanup、owner/目标死亡和电源通知各有撤销责任。
- 页面离开先询问暂存守卫，取消不能先释放暂停；确认后关闭运行控制期间冻结工作台输入。HVM OPEN 回执丢失时先用同一持有设备文件查询自己会话，再尝试 Close，不能换句柄接管别的页面。
- 独立内存目标换代时要清退旧 `WorkbenchStatusBar::m_readResultText`；反汇编读取未必产生 HEX baseline/`onProviderJobLanded`，不能等它覆盖旧退出警告。同一已退出目标只换通道仍保留真实警告，不清暂存区脏锁存，也不把空状态写成读取成功。
- 使用说明与准确验证边界见 `docs/内存调试模式.md`，一手研究及旧 HVM 仍依赖 Windows #DB 的边界见 `docs/不附加单步调试研究.md`。实验 HVM 的源码/编译结果不能替代 MBEC/MTF 实机运行证据；本轮未自动加载新驱动或操作测试 VM。

## 2026-11-13 两套独立执行通道

- HVM 无附加 v2（命令 33 / IOCTL 0x924）与普通驱动 v1（命令 34 / IOCTL 0x938）共用 232/480 字节停止文档，使用独占设备文件、对象创建时间及 sessionId/stopId；跨后端预约禁止互相接管。GUI 入口为内存 → 内存调试，CE `noAttach.useBackend` 与独立 x64dbg `ksna_backend` 选择同一规范 API；它们不进入原生 Titan Windows 调试循环。
- 普通后端只对精确匹配的 OS 26300 / ntoskrnl 26100.9711、26100.9974 开放私有 ABI。9974 的入口及被调函数完整差分、Resume 唯一被调关系均单独核对，不能把旧 RVA 当作新版本地址。KernelMode 缓冲区与 UserMode 现场分开传入五参 PspGet/SetContextThreadInternal；PsGetContextThread 包装会把同一 mode 同时用于两者，曾实际返回 C0000001。
- 纯 TF、无地址槽时 Windows 不投影 DR6，连活动陷阱帧中也可能为零；实际分发入口硬件 DR6=FFFF4FF0、帧 DR6=0 已取证。消费者使用同一目标线程入口读取的硬件状态；退休自有 BS 时保留外部原因，由当前异常线程回写，不能靠猜 BS 或私有陷阱帧偏移。
- 普通异常入口用已验证填充区和一个完整两字节原子入口建立转接。Close 恢复入口与本会话 TF/DR，转接器及模块留驻到重启以保护晚到调用；不实现 PatchGuard 绕过，测试签名和 HVCI 关闭不代表长期稳定性。只支持四个 DR 执行槽、native AMD64 单线程，不修改目标代码。
- 指定 26H2-11-Pro、内核 9974 实测：CE 完整流程 52 PASS、真实 DR 停止中 Close 28 PASS、Titan 独立命令 34 完整流程 52 PASS。三轮 DebugPort=0、无 Debug Object、其它线程运行、目标字节不变、退出码 0。候选 0CD2F89A195A7CD461896135AF8F486EEFF366A3079C5ADD3846BADFD6462D70，证据 `.codex-build-logs/kernel-noattach-hardware-acceptance.log`；9711 最终修复未再硬件复验。
- 主程序 CD8777FC... 已在真实窗口检查两种模式浅色宽窗及断点/寄存器工具窗；完整深浅、窄窗、DPI、背景矩阵仍未覆盖。构建/源码/模型不能代替这些项目。
- 用户明确禁止创建 Hyper-V 检查点；此前本任务创建的两个检查点已删除并合并。测试仅在唯一 Windows VM，不改宿主安全设置；来宾临时策略在后续验收结束后恢复，准确备份在本任务日志中。

- **2026-11-13 最终 HVM 备用边界**：保留 MTF 优先；缺 MTF 的 Intel MBEC 来宾通过明确 `CAP_VMX_TF=0x20` 使用 VMX 拦截 TF/#DB。只读/NX MDL 系统映射在普通控制面建立；root 只检查固定 backing 的保守指令类别。同步异常/IRQ/NMI 投递前恢复 TF，真实故障保留 CR2/错误码；特殊指令、可写代码与并发自修改不在支持范围。
- **实测 IRQ/RF**：第一次 TF STEP 被 IRQ 打断，trace arm=204、exit=1、完整边界字段已保存；仅在原 RIP/RSP、全部 GPR、CR3 与普通 flags 匹配时，给同一次已消费 STEP 最多 64 次重试。CPU 会在 EPT fault/retry 修改 RF，不能因此将已经发布的 STEP 再覆盖成 FETCH；RF 仅从身份比较排除，其它 flags/GPR 仍严格核对。
- **首轮 HVM 7F/8**：匹配驱动 PDB 的转储明确落在 hvm_entry.asm native-return 换到用户 RSP 后的 push。独立恢复现在归还拦截并保留资源，实际 VMXOFF 交给内核控制面 Close；正常继续也仅在当前物理页被监视时逐指令旁路。后续 HVM 停止中关闭、重复开启和普通留驻后重开均通过。
- **最终同一 SYS 实机**：签名副本 `0BEDB0407F525BBF9FBEB16C4CFDC639FCB12E687FEB53CE37808C2DA76B7C60`，HVM/CE 48、HVM/Titan 48、HVM 停止中 Close 26、普通 CE 52、普通留驻后 HVM 48 PASS；DebugPort=0、无 Debug Object、字节不变、目标退出 0、最后 VMX processors=0/0。HVM 实际为 VMX_TF_EPT，不应宣称物理 MTF 已在此 VM 验收。生产 VMCS 夹具 119、普通事件夹具 23、离线 ABI 16 均通过。
- **最终恢复**：原 Windows BCD、Secure Boot On、VBS 状态 2、内存完整性服务运行、测试签名 Off；测试服务/BCD/暂存目录已移除，VM 正常关机、启动 4 GB、nested False、Checkpoint Disabled/Automatic False/Count 0。准确字段见 `.codex-build-logs/noattach-vm-restored-guest.json` 与 `noattach-vm-restored-hyperv.json`。宿主安全设置未变。
- **最终主程序**：Release/x64 811510712AADEF50BD3B2AF26085DBF3C61B6FA4E540337DDA9C56CEB173E125，Build/双语门禁 PASS，真实页面机制说明已查看；完整深浅/窄窗/DPI/背景矩阵未覆盖，不应将基本 GUI 验收扩大为全矩阵通过。独立 x64dbg 命令插件未接管原生 CPU/F7/F9 事件投影。
