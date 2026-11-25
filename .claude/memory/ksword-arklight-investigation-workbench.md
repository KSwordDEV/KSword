# KswordARKLight 调查工作台骨架

## 驱动生命周期

- `Core/DriverLease` 用命名 mutex + file mapping 维护跨进程租约，租约身份是 PID + 进程创建时间，读取时清理死亡或 PID 复用条目。
- 只有观测到 `未运行 -> 运行` 的 Light 实例把驱动标记为 Light 所有；退出时仅在“Light 所有且最后一个租约释放”时请求停驱动。预先运行的驱动必须保留。
- 手工卸载会清除所有权；租约注册失败时采取 fail-safe，自动退出不得停驱动。纯决策放在 `DriverLeasePolicy`，供无窗口测试复用。

## 通用懒加载工作区

- `Ui/WorkspaceHost` 是二级 tab 的统一宿主：稳定 tab id、placeholder、异步首次物化、同步命令路由物化、失败重试、布局和激活回调都由宿主维护。
- “已投递”和“正在创建”必须是两个状态；同步导航可越过已投递但尚未执行的消息，不能把 placeholder 错当成真实页面。
- Hardware、Driver、Network、Window、SysTools 使用该宿主。重采样或重枚举动作应放在真实页面 factory 或首次激活回调，不放在外层模块创建阶段。
- `WM_COMMAND` 只在 `wParam` 低 16 位交付控件 ID。ActionAnalyze 从 `683xx` 移到 `583xx` 后，打开、筛选和采样选择恢复响应。仅走生产读取器的测试不会覆盖这类控件通知问题。正式窗口回归从「监控 → ActionAnalyze」操作原生控件。

## 实体导航和命令框

- `Core/EntityRef`/`Ui/EntityNavigation` 统一进程、线程、文件、注册表、窗口等实体。进程身份优先保留 PID + creation time；只有 PID 的外部请求在进程页再次解析当前创建时间，拒绝无法确认的实例。
- Lite 命令框默认解释为模块/实体导航：`pid`、`tid`、`hwnd`、`file`、`reg`、`net`、`handle`、`etw`。只有前导 `!` 显式进入 `cmd.exe /k`，避免普通搜索文本被执行。
- 跨模块调查动作通过根窗口同步路由；未物化模块先保存 pending request，真实页面挂载后再应用。进程页可跳文件、网络、句柄、ETW、窗口；网络连接可反向打开进程详情。

## 证据与验证

- `Ui/EvidenceSession` 记录成功的通用剪贴板/文件导出，支持 session snapshot、最近两次行级 diff、JSON/TSV 和 `C:\Users\<name>` 隐私脱敏。
- `KswordARKLightTests` 只测试纯策略/解析/证据逻辑，Release 使用 `/W4 /WX`；CI 在 Light Release 构建后构建并执行测试。
- 主 Light 项目使用 `/W4` 但暂不全局 `/WX`，避免历史第三方/旧模块警告一次性阻断；新增纯逻辑必须进入独立 `/WX` 测试项目。

## 兼容性护栏

- Lite 保持原生 Win32 x64、静态 CRT 与单 EXE/系统 DLL 部署；不要直接搬入 Qt、ADS、插件或额外运行时。
- 高版本 Windows API 必须按现有 `GetProcAddress` 范式延迟绑定；页面级 `Unsupported`/`Partial` 是正常结果，不能把一个可选诊断字段升级为进程启动前置条件。
- 新驱动能力必须 capability-gated：旧驱动、未加载驱动或无管理员权限时，R3 浏览、导出、证据会话和原有管理入口继续可用。
- 内存读取快照只来自已经成功的既有虚拟内存读 IOCTL；快照前进/后退只重放本地不可变字节，不重新读取目标或要求新协议。

## 单独构建 Light 时跳过驱动与签名

- 只构建 `KswordARKLight.vcxproj` 仍可能运行其 `BuildKswordArkDriverBeforeLightEmbed` 目标。需要显式传入 `/p:KswordArkLightEnsureDriverBuilt=false /p:KswordArkLightSkipDriverSign=true /p:KswordArkLightReuseSignedDriver=true`。
- Light 的嵌入驱动准备步骤仍需要现有 `KswordARK.sys`；可把 `/p:OutDir=` 指向已有该文件的临时输出目录，避免占用中的仓库 Release EXE 阻止链接。
- 每次构建后检查日志不含 `KswordARKDriver.vcxproj`、`signing`、`CSignTool`、`Sign-Ksword`，并确认 Light 构建退出码为 0。用户要求按功能分别编译、分别提交时，每次仅暂存本功能修改的文件。

## 进程列采集与刷新（2026-10-02）

- 进程页默认 `ProcessViewPreset::Detail`；初始化下拉框从实际 preset 同步选中项，不能只改默认列后仍显示“监视”。
- `ProcessDetails` 是需求位图和纯文本映射层；`ProcessExtraQueries` 只读延迟绑定 WIP/效率模式；`ProcessTelemetry` 由页面独占，在串行刷新工作线程中维护 I/O 与网络基线。工作任务捕获共享所有权，页面关闭后仍在执行的任务不会使用悬空缓存。
- 扩展字段按 PID + creation time 合并；静态查询之后再次核验创建时间。启动时间直接格式化 NtQuery 快照中的 FILETIME，专用工作集来自 `WorkingSetPrivateSize`，不能拿 `PrivatePageCount`（私有提交量）代替。
- 自动定时器在 refreshTask 正运行时跳过本轮，不增加任务代次。否则签名/R0 查询耗时超过周期时，`AsyncSnapshotTask` 会一直丢弃已完成快照，导致扩展字段永远无法展示。手动请求和列切换仍可合并到下一轮。
- 签名每轮最多验证 24 个尚无缓存的实例，结果按稳定身份保存并清理死亡实例；已经验证的行不能在下一轮重新变成 Pending。
- GPU 沿用公共 R3 PDH 后端，接收 `PDH_CSTATUS_VALID_DATA` 和 `PDH_CSTATUS_NEW_DATA`；增加 `gpuUsageKnown`，实测 0 与预热/失败分开。显存两类计数器都成功才标记已知，零值仍是有效样本。该路径不使用 D3DKMT 节点性能查询。
- 网络列按需启动既有 `ProcessNetworkEtwMonitor` 的独立私有会话，覆盖 TCP/UDP IPv4/IPv6；隐藏网络列后的下一轮停止会话。未提权/丢事件明确显示原因；实例复用、会话重启和计数器回退都重建基线。磁盘列显示进程读写 I/O 字节差值速率（该 R3 计数包含非磁盘 I/O，不能声称是物理磁盘吞吐）。
- 企业上下文使用系统目录 `edputil.dll` 的 `EdpGetContextForProcess` + `EdpFreeContext`，依微软公开 ABI 解码 WIP 状态和 UI 企业身份；不要把共享后端的固定 Personal 当成实测证据。效率模式在 Win32 查询失败时只读回退到 `NtQueryInformationProcess(ProcessPowerThrottlingState=77)`，不修改目标状态。
- 管理员列使用 `isAdminKnown` 区分 TokenElevation 读取失败与真实未提升。策略/DPI 枚举转换成中文状态，Unknown 不能按已禁用显示。
- 内核列保留枚举返回的真实对象表/映像节地址，不用“句柄数”覆盖对象表地址；驱动缺字段时不能宣称无保护。R0-only 行保留驱动创建时间，未返回的用户态统计不能伪造为 0；失败 CrossView 也不能标记“已审计”。
- 验证：Light Release/x64 完整链接通过；独立 `/W4 /WX` 进程回归涵盖元数据、PID 复用、策略状态、GPU 空闲/失败、专用工作集与 I/O 基线；整套 LightTests 通过。用生产对象链接的隐藏窗口探针验证默认详细列组、671 行真实枚举、用户/GPU/安全视图回填；读取实际 worker 函数的探针验证 WIP、效率模式及真实文件 I/O。未提权探针的网络提供者启用返回 Win32 5，已验证权限降级，没有完成管理员会话实际流量验收；没有执行驱动装载或修改目标进程。

## 进程页状态行与内存输入（2026-10-02）

- 进程页移除常驻状态控件及其 20px 占位，不再拼接每轮同步数量与 R0 原始错误。操作诊断送到 `OutputDebugStringW`，既有操作失败弹窗继续保留。
- 内存页初始地址和进程导航后的地址均留空，明确提示十六进制；无前缀地址复用 `NumericTextParse` 的十六进制模式，PID/长度仍按十进制（支持显式 `0x`）解析。读取/写入本地拒绝空地址、地址范围溢出和超过共享协议限制的长度；区域查询显式允许 `0x0`，不可与读取校验混淆。
- 读取结果先显示实际完成情况，随后保留原始 IOCTL/NT 字段。`transport OK + PARTIAL_COPY + 0 bytes` 是读取失败；只有真实返回的非空字节才能创建快照，不以通信成功或补零代替读取成功。
- 本轮 Release、完整 LightTests 和生产对象链接的隐藏窗口验证通过；窗口探针验证状态控件不存在、列表紧接工具栏、空地址不发起读取或新增操作历史。只读自身有效缓冲区的 R0 探针仍返回 Win32 2，未装载驱动，实际成功读取未验收。

## 回调遍历同步（2026-10-02）

- 核对 10 月 1 日 `75ab8a61` 与 `696774c1`：前者补充 13 个扩展注销类别并移除主程序实验 unlink 入口，后者修复 Process Ex2 配对注销与 Minifilter owner unload。共享头增加注销类别常量、明确 Minifilter EX 字段语义；IOCTL 编号、协议版本、结构布局未变，Callback Monitor 通道也未变。
- Light 直接复用共享协议及 `ArkDriverClient`，纯逻辑集中在 `Features/Kernel/CallbackEnumeration`：展示注册子类型、按数值协议字段判断 verified/candidate/unavailable，菜单与 facade 使用同一身份解析与 EX 封包，缺 V3 generation/identity hash 不执行注销。Object 的实际 RegistrationHandle 与诊断节点不能互换；Registry Cookie 是值。
- Minifilter 子行保持显示的 operation record，EX 请求的 `registrationAddress` 携带 `contextAddress` 中的所属 FilterObject，`rawStorageValue` 携带子行的 `registrationAddress`；父行用 IDENTIFIER 回退。私有发现的子行仍为候选，公开卸载 API 不提升来源可信度。菜单和确认说明卸载所属过滤器的全部回调及实例，并可能被过滤器拒绝。
- Light 移除实验 unlink 菜单与执行路径；内部旧 action 枚举保留编号并本地拒绝。枚举不再自行截断到 256 行。注册类型列必须映射 `RegistrationTypeText`，不能误把列别名加到 IAT/EAT 页面。
- 注销响应先验证长度/size/version，再判断 NTSTATUS；失败保留当前枚举表并展示原始驱动错误，成功重新枚举，不能把注销响应当成枚举表渲染。
- 验证：Light Release/x64 构建、整套 LightTests、44 项回调策略/封包/列映射回归，以及 `tools/callback_remove_tests/run.py --cc cl` 的生产 R0 模拟测试通过。未实际注销回调、卸载过滤器或装载驱动。

## 表格快照收尾（2026-10-24）

- 本轮按用户确认仅提交 Light；UI CPU 采样工具、动态偏移调查笔记和 `.tmp/` 原有内容保留未提交。用户随后明确停止 Computer Use，无需评估 UI 合规性；后续不要自动继续 GUI 验收。
- 进程主表通过 `TableCompareRows` 接入共享采集/比对/清除菜单，回调保留当前展示快照与筛选映射的共享所有权。跨列组必须使用 `ProcessColumnId`，不能把显示位置当稳定列身份；否则切换列组后会错配不同字段。
- `TableCompareRows::sourceColumns` 是与表头平行的可选稳定 ID；单元格回调仍接收当前位置，生产适配器负责转换。空 ID 向量保留旧位置编号；长度不匹配、重复/负 ID 拒绝采集且不覆盖快照。生产适配移至 `Ui/TableCompareRowSource.cpp`，同时进入 Light 与独立 `/W4 /WX` 测试工程，两个工程及 filters 均登记。
- 进程表未配置稳定行键，仍明确使用共享引擎的整行回退，不能声称已经按 PID + 创建时间作字段级身份比对。七个其他页面调用补充比对窗口/导出表名，其中杂项审计沿用每个子页的 `state.title`。
- `CreateCaptureProtectionView` 当前仅有声明/定义，未挂入窗口模块工厂；保留代码的构建不等于导航可达。完整入口记录见 `docs/audit/arklight-closeout-20261024.md`。
- HostX64 Light Release Build 成功（退出 0，约 35 秒，17 条既有 KernelPage/ArkDriverKernel 路径警告）；测试工程 Release `/W4 /WX` 构建成功，0 警告。完整测试及清单 43/43 通过，快照压力/适配套件 151/151。该套件此前漏登必跑清单，本轮补齐。
- 日志位于 `.codex-build-logs/light-closeout-20261024/`。复用现有驱动，不执行驱动构建、签名或装载；不构建主程序 Qt 工程、不推送或重写历史。真实窗口曾启动，但捕获接口连续超时，未完成视觉验证；之后按用户要求停止。
