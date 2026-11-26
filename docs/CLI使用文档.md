# KswordCLI 使用文档

本文档按当前命令分发器、内置 help 元数据和 `shared/driver/` 协议核对，覆盖既有 R0 命令及逐项接入的 R3 命令（2026-10-10）。R0 命令通常需要管理员权限及已加载的 KswordARK 驱动；纯 R3 命令按各项文档说明所需权限，不要求驱动。构建与发行目录见 [构建与发布](构建与发布.md)。

## Help 查询

设备打开返回 `win32=2` 或 `3` 时会提示启动已安装的 `KswordARK` 服务（`sc start KswordARK`），或以管理员身份运行配套 `Launcher.exe` / `Ksword5.1.exe` 加载驱动；原始错误码保留。仅复制 CLI 文件并不自动安装驱动服务。

```powershell
KswordCLI.exe help
KswordCLI.exe help <family>
KswordCLI.exe help <family> <subcommand>
KswordCLI.exe <family> help
KswordCLI.exe <family> <subcommand> --help
```

维护要求：每新增、删除或调整一个 `KswordCLI` 命令、别名或参数，必须同步更新该命令注册处的内置 help 元数据和本文档。`analyze` 的入口在命令注册表中登记，REPL 帮助与会话能力列表使用同一组方法定义。

顶层 `help` 只展示命令族和简介；业务层只展示直接子节点；具体叶子帮助展示完整参数、输出和限制。已有叶子同时增加子命令时，父级仅展示旧调用入口和直接子节点，不展开叶子的长篇字段说明。
原来的 `help <family> <subcommand>`、`<family> help`、`<command> --help`、`-h`、`/?` 继续有效，新增任意深度路径，例如：

```powershell
KswordCLI.exe help network
KswordCLI.exe help network connections
KswordCLI.exe help network connections close
KswordCLI.exe network connections help
```

## R3 功能与输出

已接入迁移项：01 TCP/UDP 枚举与 IPv4 TCP 关闭；02 Ping；03 路由跟踪；04 DNS 查询；05 防火墙规则读取；06 AFD/NSI 公开端点审计。07 服务枚举、详情和控制；08 注册表浏览和读取；09 注册表搜索；10 注册表修改；11 启动项枚举；12 启动项控制和位置查询；13 当前进程权限查询和作用域执行；14 目录浏览；15 文件操作；16 文件所有权和占用者；17 文件哈希、签名和熵；18 十六进制和 PE 分析；19 R3 进程枚举；20 进程扩展字段；21 进程遥测采样；22 R3 进程控制；23 进程基本信息；24 线程查询和控制；25 模块枚举、卸载和关联线程控制；26 令牌查询与编辑；27 令牌开关；28 PEB、环境／内存区域查询和进程亲和性；29 进程热键候选；30 驱动 R3 枚举与模块元数据；31 硬件设备枚举与详情；32 系统性能采样；33 物理磁盘活动采样；34 USB 拓扑；35 总线设备与资源；36 窗口枚举与管理；37 剪贴板格式与文本读取；38 窗口显示亲和性；39 窗口层级诊断；40 全局热键占用探测；41 ETW 限时采集与筛选；42 系统文件句柄占用；43 事件日志读取；44 Shell 右键菜单注册及启用／禁用；45 系统时间与 W32Time 配置；46 IOCTL 编码解析；47 内核对象命名空间；48 对象目录递归；49 内核符号链接；50 Device／Driver 对象注册；51 全局与会话命名对象；52 命名通信端点；53 R3 对象类型矩阵；54 命名管道枚举与打开验证；55 Atom 与注册剪贴板格式名称；56 安全 NtQuery 预设与导出清单；57 磁盘 PE Hook 基线读取与字节比较；58 CI／WDAC 公开证据；59 VBS／HVCI／SKCI 公开证据；60 Hyper-V／VMBus／HvSocket 公开证据；61 AppLocker／AppID 公开证据；62 BAM／ahcache／Amcache 摘要；63 Bugcheck／VMware 环境证据；64 窗口列表捕获保护适配；65 剪贴板清空与实时所有者；66 进程身份采样。详细语法见 [网络 R3 命令](cli/network.md)、[服务 R3 命令](cli/service.md)、[注册表 R3 命令](cli/registry.md)、[启动项 R3 命令](cli/startup.md)、[权限 R3 命令](cli/privilege.md)、[文件 R3 命令](cli/file.md)、[进程 R3 命令](cli/process.md)、[驱动 R3 命令](cli/driver.md)、[硬件 R3 命令](cli/hardware.md)、[窗口 R3 命令](cli/window.md)、[监控 R3 命令](cli/monitor.md)、[系统工具 R3 命令](cli/system.md)、[内核对象 R3 命令](cli/kernel.md)、[安全证据 R3 命令](cli/security.md)。
66 项对应关系与边界见 [迁移覆盖清单](cli/coverage.md)，可用 `tools/Test-KSwordCliR3Coverage.ps1` 核对全部帮助层级。
网络关闭的 API 状态与回读存在性分别输出；错误 317 不推导为目标消失，详见 [网络文档](cli/network.md)。
`network connections enum [--pid PID] [--protocol all|tcp4|tcp6|udp4|udp6] [--offset N] [--limit N] [--backend r3] [--json]` 支持显示偏移与下一页位置；不同调用是各自的网络快照。
`process memory regions page --pid PID [--creation-time FILETIME] [--start-address ADDRESS] [--limit N] [--json]` 以地址游标分页读取进程的已提交区域；正常页大小限制不代表采集失败。分页快照可能随进程映射变化，详见 [进程文档](cli/process.md)。
`process memory dump` 与 `process module dump` 支持 R3/R0 分块转储并报告来源、身份与完整性；`process thread stack query` 默认捕获受验证线程的用户调用栈，`--backend r0` 仅返回未验证的 KTHREAD 栈线索、不产生调用帧，详见 [进程文档](cli/process.md)。
`process thread layout query [--image PATH] [--profiles DIR] [--json]` 与 `process layout query [--image PATH] [--profiles DIR] [--json]` 按磁盘 PE/RSDS 精确身份读取 `_ETHREAD`／`_EPROCESS` PDB 布局元数据，不读取实时对象。默认使用系统 `ntoskrnl.exe` 和 CLI 同目录下的 `profiles/ark_dyndata_pack_v4.json.qz`；完整布局及版本索引均已内嵌 v4，不再依赖外置 TSV。`--profiles` 仍指定包含该文件的目录，详见 [进程文档](cli/process.md#线程与进程类型布局)。

`process layout sample --pid PID [--creation-time FILETIME] [--profiles DIR] [--json]` 和
`process thread layout sample --pid PID --tid TID [--creation-time FILETIME] [--thread-creation-time FILETIME] [--profiles DIR] [--json]`
通过只读 R0 `0x941` 获取精确内核身份限定的 EPROCESS/ETHREAD 对象体快照。JSON 明确
`source=live_object_body`、`live=true`、`atomic=false`，保留逐字节有效位和全部符号行。
覆盖率分母不删行，严格分子排除 union 解释并去重存储别名；只有现场身份通过且严格覆盖
超过一半才退出 `0`。此处不包含内核栈展开，详见 [实时字段采样](cli/process.md#线程与进程实时字段采样)。

`process thread stack dump --dump PATH --pid PID --tid TID [--creation-time FILETIME] [--thread-creation-time FILETIME] [--symbols PATH] [--limit N] [--json]` 通过本机 x64 Windows 调试工具从指定内核转储展开目标线程的内核栈。PID/TID 指转储内对象；输出不代表实时内核状态。

`process thread stack capture --pid PID --tid TID --creation-time FILETIME --thread-creation-time FILETIME [--limit N] [--timeout-ms N] [--method auto|saved|apc] [--backend r0] [--json]` 通过GUI/CLI共用客户端采集在线目标内核栈。默认 `auto` 首选保存上下文；只有新端点明确不支持才回退至旧APC诊断，不拼接两种来源。保存上下文确实展开到用户态机器帧边界才退出 `0`；部分帧退出 `6`，不支持退出 `5`。当前保存上下文只允许两份精确VM内核，其他版本和跨模块展开限制详见进程文档。
`thread r0` 与 `thread driver` 提供独立的驱动线程控制入口，详见 [R0 线程命令](cli/thread-r0.md)。
`handle close` 对同一目标提供 R3/R0 关闭及独立状态回执，详见 [句柄命令](cli/handle.md)。
`network policy` 提供按各自后端实现的 R0 托管策略与 R3 防火墙策略操作；`network qos` 提供 R3 QoS 操作，详见 [网络命令](cli/network.md)。
`network firewall rule` 提供单项详情与规则增改、启停和删除，按名称和指纹重验；详见 [网络命令](cli/network.md)。
`file metadata` 提供文件属性、时间、命名流、扩展属性和安全描述符的 R3 查询与操作，详见 [文件元数据命令](cli/file-metadata.md)。
`service config set`、`service recovery set`、`service delete` 提供服务配置及删除操作，详见 [服务命令](cli/service.md)。
`startup location query --id` 直接返回对应单项的详细字段，详见 [启动项命令](cli/startup.md)。
`r0 traffic-start`、`r0 traffic-stop` 和事件记录读取的行为与清理语义见 [R0 事件命令](cli/r0-events.md)；PiDDB 单项详情与删除见 [PiDDB 命令](cli/piddb.md)。
`r0 kernel-modules` 和 `r0 process-modules` 提供驱动模块快照与进程映像映射视图，详情与来源边界见 [R0 模块命令](cli/r0-modules.md)；窗口热键与 Band 入口见 [窗口命令](cli/window.md)。
`r0 io-timer`、`r0 platform-edit`、`r0 debug-output-control`、`r0 research-topic`、`r0 token-privilege` 和 `r0 process-protect` 控制及查询说明见 [R0 底层命令](../KswordCLI/R0LowlevelCommands.md)。
`file irp submit` 提交文件 IRP，参数和状态见 [文件 IRP 命令](cli/file-irp.md)；`pfn` 提供物理页查询，详见 [PFN 命令](cli/pfn.md)。
虚拟位置与应用控制操作分别见 [虚拟位置命令](cli/location.md) 和 [应用控制命令](cli/application-control.md)；Shadow SSDT 基线和恢复见 [Shadow SSDT 命令](cli/shadow-ssdt.md)。
`debugger session --pid PID --creation-time FILETIME --confirm [--backend r3|r0] --json` 启动逐行交互会话。输入 `wait`、`continue`、`threads`、`context`、`read`、`write`、`break` 或 `detach`；完整参数见 `help debugger session`。仅支持原生 x64 目标和按线程设置的硬件执行断点，不支持 HVM 或软件断点。
`system health [--json]` 只读汇总驱动服务、能力、动态数据和跨视图字段证据；各查询独立报告状态与限制，详见 [系统工具文档](cli/system.md)。
`system time speed` 提供 R0 时间倍率查询、设置与恢复，`system time resync` 使用 R3 时间服务重同步，详见 [时间控制命令](cli/system-time-control.md)。
新增纯 R3 命令默认使用 R3，支持显式 `--backend r3`，不自动切换 R0；既有命令的默认后端和输出保持兼容。

默认输出可读 UTF-8 文本，`--json` 在 stdout 输出一个 JSON 文档：`schemaVersion`（1）、`command`、
`backend`、`status`（success/partial/unsupported/failed）、`data`、`diagnostics`。
参数错误仍返回 1 并提供语法；已识别的 R3 命令在 JSON 模式下同时输出结构化失败。

R3 文件创建可使用 `file create --path PATH [--text TEXT | --hex HEX | --data-file PATH] --confirm` 或 `file directory create --path PATH --confirm` 指定最终名称；原有 `--directory` 自动命名仍可用。R3 注册表 `--type` 支持 `REG_SZ`、`REG_DWORD` 等名称，详见 [文件](cli/file.md)与[注册表](cli/registry.md)命令。
`file signature query` 分别检查嵌入式签名和已安装驱动子系统目录的 SHA256/SHA1 目录签名；来源、验证状态、搜索边界和错误各自输出，详见 [文件命令](cli/file.md)。
`file pe query --path PATH --json` 的 `exportSymbols` 覆盖非零 EAT 槽，包括仅序号导出、多个名称和转发目标；损坏或超过 4096 槽／名称上限时标记 partial，详见 [文件命令](cli/file.md)。

既有 R0 `registry` 命令的 `--key` 使用原生路径，例如 `\Registry\Machine\SOFTWARE`；当前用户配置单元使用 `\Registry\User\<调用者 SID>\...`，可用同一调用者的 `whoami /user` 获取 SID。R3 命令支持 `HKLM`、`HKCU` 等简称；R0 的 `set-value --type` 仍使用数字类型和原始 `--data-file`。
地址和句柄为十六进制字符串，大于安全整数范围的计数为十进制字符串。部分完成返回 6。

## API Monitor 注入监控

`monitor api capture --pid PID --confirm [--duration-ms N] [--json]` 已接入主程序同源的 API Monitor Agent、位数选择、原生注入、会话租约、子进程注入 broker 和覆盖快照协议，默认使用 R3 注入，无需加载 R0 驱动。可显式使用 `--r0-inject 1` 选择现有 R0 注入后端；开启自动子进程时子进程同样使用 R0 注入，失败不会自动回退 R3。目标创建时间在驱动调用前后校验，但现有 PID 协议仍有查找前复用窗口。`injectionBackendRequested` 记录选择，常驻 Agent 复用时不再次注入。默认从 CLI 同目录选择 `APIMonitor_x64.dll`／`APIMonitor_x86.dll`；限时采集结束或 Ctrl+C 后写停止标记，并等待 Hook 移除和管道排空。DLL 保持常驻，可对同一目标再次采集。

通过 `--call-stack 0|1` 或 `--options-file` 导入 `[monitor]` 节中的 `capture_call_stack=1` 可选采集强类型调用栈；事件 JSON 的 `callStackAvailable` 与 `callStack` 分别表示是否采到和最多 8 个地址。该栈可能包含监控内部帧，Raw 调用或详情空间不足时可能缺失；命令行选项优先于 INI。

可用 `--filter-file PATH` 导入界面的前后置筛选配置；`--pre-exclude-modules`、`--pre-exclude-apis`、`--post-exclude-modules`、`--post-exclude-apis` 按分号分隔的模块或 `模块!函数` 身份追加排除，优先于导入配置中的允许例外。前置在接收后入缓冲前拒收，后置只隐藏已保留结果；控制和覆盖事件不受影响。模块名不区分大小写，无路径且无扩展名时按 `.dll` 匹配；函数名区分大小写。`--timeline 1` 输出最多 2048 个自适应时间桶，计入前置保留的普通调用（含后置隐藏和缓冲淘汰），不包含丢失或前置拒收事件；详见 [监控命令](cli/monitor.md)。

`monitor etw capture --decode 1` 可按 TDH 读取有界的顶层载荷与原始前缀；`--target-pid` 只匹配明确载荷目标字段，未知目标单独计数，不把事件头 PID 当作目标。解码不完整和事件丢失会返回部分结果；边界和性能说明见 [监控命令](cli/monitor.md)。

事件中的 `rawAbi` 列出实际采集的 Raw 寄存器和栈槽，不推断参数类型。`--signatures 1` 读取同目录的项目声明文件，只有文件 SHA-256 与 Agent 事件定义哈希一致时才附加声明，并标识项目、SDK 已核对或未核验参考来源；不读取目标指针。

支持 `--agent PATH`、`--duration-ms 100..120000`（1000，从 HooksInstalled 后计时）、`--limit 1..100000`（5000，保留最近事件）、`--categories file,registry,network,process,loader,clipboard,memory,thread,service,security,crypto,com,window,gui`（逗号分隔；gui 默认关闭，包含 GDI、绘图及 DC 调用；窗口生命周期、消息和菜单属于 window）、`--raw 0|1`、`--raw-modules LIST`、`--raw-exclude LIST`、`--raw-default-denylist 0|1`、`--auto-children 0|1`、`--r0-inject 0|1`、`--options-file PATH`、`--startup-timeout-ms 1000..120000`（30000）和 `--stop-timeout-ms 1000..120000`（15000）。Raw 列表以分号分隔；INI 仅导入 `[monitor]` 业务选项，包含主程序 Fake Success／剪贴板规则，拒绝跨行选项，不导入控制端路径、SID、会话或 broker 身份；显式命令行选项覆盖 INI。支持 `--backend r3` 和 `--json`，x64 CLI 为监控宿主。

采集事件的 `returnValueAvailable`、`durationAvailable` 分别表示是否实际采到返回位模式和调用耗时；对应的 `returnValue` 是十六进制字符串、`duration100ns` 是以 100 纳秒为单位的十进制字符串，缺失时为 `null`。旧 Agent 和 Raw 入口不会推断未采集值。详见 [monitor 命令](cli/monitor.md)。

输出事件、异步 operationId、每个 PID 的完整覆盖快照、Hook 安装／移除、Agent 丢包、输出缓冲截断、进程创建身份及清理结果。Raw 的未知返回值为 null。完整无损采集返回 0；部分 Hook、丢包、截断、取消、提前退出或未确认停止返回 6；启动失败 3，参数错误 1，非 x64 宿主 5。仅加载 DLL 不算监控成功，只有 HooksInstalled 才开始计时；只有 HooksRemoved／原目标退出才确认停止。停止标记保留，以防迟到的加载线程重启旧会话。详见 [监控命令](cli/monitor.md)。

`processes.finalCoverageRevision` 声明停止时应收齐的最终覆盖修订；管道正常 EOF 不再误报错误233，缺失最终快照或半包仍标记过期／错误。安装中取消会停止后续 Hook 准备并执行移除。高覆盖量的安装／移除采用批处理，仍逐入口检查真实字节和暂停期间的线程指令指针。

## 原始 IOCTL 调用

`system ioctl call --code N [--input-hex HEX | --input-file PATH] [--output-bytes N] --confirm [--allow-unregistered] [--json]` 通过现有 `ArkDriverClient` 向固定 KSword 控制设备发送一次原始请求。默认先查询驱动 IOCTL 注册表并拒绝未登记的控制码；`--allow-unregistered` 仅用于明确受信的兼容性探测。输入／输出各上限 1 MiB；输出默认 4096 字节，原始内容采用十六进制回执，只保留实际返回长度。所有调用都必须确认，不自动加载驱动、提权或重试。编码及缓冲区 ABI 由配套共享协议定义；传输成功不代替响应中的业务状态。详见 [系统工具命令](cli/system.md)。内置帮助入口为 `help system ioctl call`。

## 参数约定

`r0` 和 Callback Monitor 的 `nt_status=n/a` 表示传输失败且没有返回 NTSTATUS；它不代表内核执行成功。响应解析器取得的实际非零 NTSTATUS 仍按十六进制显示。

IOCTL 失败的 `error:` 原因和其后的 `unsupported / unavailable:` 审计结论统一写入 stderr，保证合并重定向时先原因、后结论；成功数据继续写入 stdout。

退出码沿用既有约定：`0` 成功，`1` 用法/参数错误，`2` 设备打开失败，`3` I/O 调用或响应中的操作失败（包括等待超时），`4` 响应格式错误，`5` 不支持或证据不可用，`6` 部分结果或完整动作尚未确认。即使 DeviceIoControl 成功，响应中的失败 NTSTATUS 也会返回非零退出码；输出保留原始状态。未支持的 IOCTL 传输错误（Win32 1/50/120/127）和响应中的不支持状态返回 `5`。`file hex query`、`driver modules enum` 和 `process module enum` 的 `complete` 表示请求的采集证据完整，`displayTruncated` 表示有意限制的显示内容；仅显示受限返回 0，采集缺失仍返回 6。其他命令的限制与退出码见各自 help，不能假定已全部统一。

若所有只读命令连同 `capability query-driver-capabilities` 都返回 `win32=50`，不能仅凭 IOCTL 名称判断驱动缺少实现。请运行 `preflight query` 和 `r0 ioctl-registry`，核对 `sc qc KswordARK` 的实际加载路径及配套版本。2026-10-01 的旧驱动会在 OS build 高于 26100 时拦截包括能力查询在内的请求；该上限已于 2026-10-03 移除，仍须使用匹配的内核 profile。

- 数值参数支持十进制或 `0x` 前缀十六进制。
- 缺少必填参数会指出参数名，例如 `missing option --pid`；有参数但无值会显示 `missing value for option --pid`。参数错误同时显示该命令的语法及内置 help 的参数说明。
- 未知选项在发送请求前报 `unknown option --name`；`driver detail` 使用 `--driver`，不接受 `--name`。允许的选项与该命令的 help 语法一致。
- `--flags 0xN` 是按位标志；具体含义以 `shared/driver/` 中对应协议头为准。
- `--limit N` 通常限制 CLI 显示行数；`--max-*` 通常控制查询预算。各命令的限制与退出码以对应 help 为准。
- `--hex`/`--*-hex` 接收十六进制字节串；`--data-file`/`--*-file` 从文件读取原始字节；同一 payload 的 hex 和 file 形式互斥。
- `--hexdump` 会把返回字节按十六进制展开打印。

## 命令族总览

| 命令族 | 用途 |
| --- | --- |
| `log` | Read bounded frames from the KswordARK log device. |
| `process` | Inspect and control process visibility, PPL, DKOM, and cross-view state. |
| `memory` | Query, read, write, translate, and audit virtual/physical memory. |
| `file` | Inspect files, filters, storage evidence, and file-monitor runtime state. |
| `kernel` | Inspect SSDT, hooks, driver objects, CPU, physical layout, CID, and IPC state. |
| `security` | Query public R3 security configuration and availability evidence. |
| `system` | Read bounded R3 system tools and configuration evidence. |
| `callback` | Manage callback rules, pending decisions, callback inventory, and bypass PIDs. |
| `dyn` | Query or apply dynamic kernel symbol/profile data. |
| `thread` | Enumerate threads and compare R0/R3 thread evidence. |
| `handle` | Enumerate process handles and inspect object metadata. |
| `driver` | Driver integrity, device stack, and optional global evidence aliases. |
| `hardware` | Device, input, USB, and PnP stack audit views. |
| `hwid` | HWID Dispatch query and guarded control operations. |
| `window` | Win32k、GUI、GPU 审计及 R3 窗口／剪贴板查询与管理。 |
| `clipboard` | `window clipboard` 的 R3 格式／文本读取别名。 |
| `misc` | Security, CI/VBS, Hyper-V, AppLocker/BAM, and driver trust posture. |
| `alpc` | ALPC port diagnostics for a process handle. |
| `section` | Process and file section mapping diagnostics. |
| `trust` | Image trust and signing diagnostics. |
| `safety` | Safety policy query and update controls. |
| `preflight` | Release-readiness and driver capability preflight checks. |
| `registry` | Registry read, enumeration, and mutation helpers. |
| `redirect` | File/registry redirect rules and runtime status. |
| `network` | Network rules, endpoints, WFP/NDIS evidence, and R3 fallbacks. |
| `keyboard` | Keyboard hotkey and hook inventory. |
| `mutation` | Prepare, commit, rollback, and audit bounded mutation transactions. |
| `analyze` | 管理 ActionAnalyze 项目，进行限时 R3 ETW 采集或只读内存采样。 |
| `capability` | Unified driver feature capability query. |
| `wsl` | WSL silo and Linux PID/TID diagnostics. |
| `ddma` | 磁盘 DMA 能力探测、拒绝路径自检与物理内存读取。读取过程会临时写入指定暂存扇区。 |
| `r0` | 复用桌面端的 R0 取证查询、证据读取与剪贴板规则控制。 |

## 具体命令语法

### `analyze`

| 命令 | 语法 | 用途 |
| --- | --- | --- |
| `analyze capabilities` | `KswordCLI.exe analyze capabilities [--json] [--backend offline\|r3]` | 查询所选控制器的方法和限制。`--json` 的 `data` 字段为能力对象。 |
| `analyze session` | `KswordCLI.exe analyze session [--input REPL_OR_JSONL] [--output TEXT_OR_JSONL] [--backend offline\|r3]` | 在同一个 CLI 进程内连续收发请求。默认使用 `--input repl --output text --backend offline`。 |
| `analyze memory watch` | `KswordCLI.exe analyze memory watch --pid PID --creation-time FILETIME --address ADDRESS --size BYTES [--samples N] [--interval-ms N] [--backend r3] [--json]` | 对明确内存范围读取有限快照，报告相邻快照的差异区间和读取时段。 |
| `analyze memory track` | `KswordCLI.exe analyze memory track --pid PID --creation-time FILETIME --address ADDRESS --size BYTES --confirm [--samples N] [--interval-ms N] [--observe-threads] [--backend r3] [--json]` | 对明确授权的自有进程逐页追踪映射及内容变化，可选附加只读线程观察。 |
| `analyze memory stream` | `KswordCLI.exe analyze memory stream --pid PID --creation-time FILETIME --address ADDRESS --size BYTES --confirm [--interval-ms N] [--observe-threads] [--output text 或 jsonl] [--backend r3]` | 持续逐轮跟踪明确授权的自有进程，可选附加只读线程观察，接受 `stop`。 |
| `analyze memory snapshot` | `KswordCLI.exe analyze memory snapshot --project PATH [--sample UUID] --pid PID --creation-filetime N --base ADDR --bytes N --confirm [--title TEXT] [--json]` | 对选中范围执行单轮真实字节采样，在项目采样的独立 `raw-memory/N` 归档成功页、失败页及收尾。 |
| `analyze memory read` | `KswordCLI.exe analyze memory read --project PATH --sample UUID --ordinal N [--json]` | 核对内存段链、页字节散列和收尾，显示实际坐标、有效长度、采样时钟及缺口。 |
| `analyze memory export` | `KswordCLI.exe analyze memory export --project PATH --sample UUID --ordinal N --out PATH [--base ADDR --bytes N] [--json]` | 导出已核验内存档的全部范围或完整子范围，缺口、坏段和已有输出文件均拒绝。 |
| `analyze breakpoint session` | `KswordCLI.exe analyze breakpoint session (--exe PATH [--module PATH] (--export NAME 或 --rva RVA) 或 --pid PID --creation-filetime N --address ADDR [--range-bytes N]) --confirm --disposition resume-detach [--input repl\|jsonl] [--condition EXPR] [--project PATH [--sample UUID]] [--watch-write-bytes N [--watch-pointer-export] 或 --execute-pointer-export 或 --cooperative-pair]` | 控制本 CLI 启动的自有 AMD64 子进程，或显式附加到已有实例的私有地址。单目标执行、写入停点共用停止、继续、步进及项目内存归档；真实执行观测可显式保存。 |
| `analyze execution read` | `KswordCLI.exe analyze execution read --project PATH --sample UUID [--ordinal N] [--json]` | 从第 1 段依次核验至指定 `raw-native` 段，返回历史执行文档、SHA-256 和归档端点；段号默认 1，须为正 uint64。 |
| `analyze execution history` | `KswordCLI.exe analyze execution history --project PATH --sample UUID [--after N --limit N] [--json]` | 不依赖 API 流列出原生历史摘要；先核验连续链（最多4096段），`after` 为已消费段号、默认0，`limit` 默认32、最多128。返回原坐标、散列、观察阶段、进程／线程代次、实际IP及 `nextAfter/hasMore/historyLimited/firstUnreadOrdinal`。完整文档使用 `execution read`。 |
| `analyze execution correlate` | `KswordCLI.exe analyze execution correlate --project PATH --sample UUID --api-ordinal N --native-ordinal N [--after N --limit N] [--json]` | 核验 API 图页与原生段链，按目标进程、线程代次及实际写入半开范围输出一致性候选；APC 另要求实际指令起点等于请求例程入口。API 段号最多 128，原生最多 4096；分页默认 100、最多 4096 行。 |
| `analyze execution memory` | `KswordCLI.exe analyze execution memory --project PATH --sample UUID --native-ordinal N --memory-ordinal N [--bytes N] [--json]` | 分别核验原生执行与内存段链，匹配同一历史停点后，取执行指令起点处已归档的字节。两个段号均为 1..4096，字节数默认 1、范围 1..15。 |
| `analyze execution map` | `KswordCLI.exe analyze execution map --project PATH --sample UUID --api-ordinal N --native-ordinal N [--after N --limit N] [--json]` | 核验 API 与原生两路链，按目标 PID＋创建 FILETIME 及实际映射半开范围输出指令一致性候选，不要求写入。API 段最多 128、原生段最多 4096；分页默认 100、最多 4096 条 API 观察。 |
| `analyze process-group session` | `KswordCLI.exe analyze process-group session --targets PID:CREATION,PID:CREATION --confirm --disposition resume-detach [--input repl\|jsonl] [--project PATH [--sample UUID]]` | 固定 1–16 个明确授权的 AMD64 进程实例，按全集或明确子集控制；可绑定项目，显式读取并保存已显示的内存快照。 |
| `analyze api-evidence import` | `KswordCLI.exe analyze api-evidence import --archive EVENTS_JSONL --project PATH --title TITLE [--json]` | 从已关闭的 WinAPI 原始归档筛选线索，写入已存在项目的新采样。 |
| `analyze api-evidence capture` | `KswordCLI.exe analyze api-evidence capture --project PATH --title TITLE --pid PID --creation-filetime VALUE --confirm [--duration-ms MS] [--json]` | 从自有合作目标进程中已经装载的产品 Agent 采集普通 WinAPI 原包，分段写入已存在项目的新采样。 |
| `analyze api-evidence attach` | `KswordCLI.exe analyze api-evidence attach --project PATH --title TITLE --pid PID --creation-filetime VALUE --confirm [--duration-ms MS] [--json]` | 显式为精确进程实例装载或复用同目录正式 Agent，并复用项目分段归档。只支持 R3。 |
| `analyze api-evidence replay` | `KswordCLI.exe analyze api-evidence replay --project PATH --sample UUID [--after SEQUENCE] [--limit N] [--packet 1] [--json]` | 重开采样并核对原始段与收尾记录。按原始序号分页并可选返回原包。 |
| `analyze api-rule-catalog` | `KswordCLI.exe analyze api-rule-catalog [--json]` | 列出 `profiles/action_analyze_api_rules.json` 中的 API 行为预置、条件、字段及证据口径，并给出本次实际解析文件原始字节的 `sourceSha256`。 |
| `analyze replay-api-rules` | `KswordCLI.exe analyze replay-api-rules --project PATH --sample UUID [--profile grouped\|by-category] [--offset N] [--limit N] [--json]` | 对指定项目和采样的已核验 API 线索应用外置规则文件中的预置，返回规则 ID 和原包坐标；`sourceSha256` 为当前规则字节摘要，`recordedSourceSha256` 为采集计划摘要，`matchesRecordedRules` 表明两者是否一致，旧档没有记录摘要时后两者为 `null`。 |
| `analyze network-capture` | `KswordCLI.exe analyze network-capture --project PATH --pid PID --create-time FILETIME --duration-ms MS --authorize-loopback yes [--json]` | 采集一个授权进程的回环网络元数据，写入项目的新采样并回查记录坐标。 |

入口帮助可用 `KswordCLI.exe help analyze`、`KswordCLI.exe help analyze session` 或 `KswordCLI.exe analyze session --help`。两个后端均支持协议协商、项目读写、采样描述和 Stored 归档段检查。`--backend r3` 另提供持续或显式限时的被动 ETW 采样。调用方进程监视状态为 `not-monitored`。

`api-evidence import` 接受主程序「监控 → WinAPI」生成的 `events.jsonl`，输入上限 32 MiB。导入从 `packetBase64` 重新判定五类线索：内存写、线程创建、APC 排队、线程上下文和节映射。原始行号与 Stored 记录序号分别保存。文件完整、线索非空时创建新采样。源文件损坏退出 `4`，项目或写入错误退出 `3`，输入没有匹配项时返回 `no-clues`。`replay` 仅在完整段和导入收尾记录均通过校验后输出结果。把 `nextAfter` 传给下一次的 `--after`。每页默认 25 条，上限 100 条。`--packet 1` 返回完整原包的十六进制。源覆盖、目标进程身份、实际写入范围、执行与归因保持未知。

`api-evidence attach` 不要求目标预先合作装载 Agent。先核对 PID 与创建 FILETIME，再用 `--confirm` 明确确认本轮附加；控制器只从正式 CLI 同目录选择匹配位数的 `APIMonitor_x64.dll`／`APIMonitor_x86.dll`。只观察原 API 调用，不启用 Fake Success、剪贴板改写或自动附加后代。`--backend r0`、R0 注入参数均拒绝，不回退后端。`attachmentIdentityVerified`、`agentLoadAttempted`、`agentModuleVerified` 分别报告实例准入、装载尝试和模块核验；`agentReady` 还要求同会话的 `SessionReady`、成功 `HooksInstalled` 以及对应或更新的完整覆盖快照内存在活动观察 Hook。完整快照不表示所有 API 均已安装，实际缺口由 `partialHooks`、覆盖及丢失字段分别报告。时长、持续模式、分段回放和清退与合作入口相同。`hooksRemoved`、`cleanPipeEof`、`cleanupComplete` 独立报告；Agent 使用既有 PIN 常驻策略，停止不等于 DLL 卸载。归档仍使用既有 `cooperative-pipe` 管道封装，冻结计划另存 `captureMode=explicit-r3-attachment` 区分准入方式。

导入后的采样可在 Qt「监控 → 行为分析 → 项目与采样」和 Light「监控 → ActionAnalyze」中打开。Qt 总览可勾选 `API` 筛选并查看来源坐标。CLI 的 `--packet 1` 可取回完整包，桌面详情提供有界前缀。

`api-evidence capture` 要求自有目标主动装载正式 Agent，并用 `--confirm` 确认本轮授权。用 `process detail basic query --pid PID --json` 核对创建 FILETIME。命令核对已装载的产品模块、进程实例和本次回传管道，分别报告 `residentVerified`、`connected`、`agentReady` 和 `cleanupComplete`。采集时长从就绪后计，默认 3,000 毫秒，可设 1,000–120,000 毫秒；`--duration-ms 0` 持续到控制台取消（Ctrl+C／Ctrl+Break）或该目标实例退出，启动就绪及停止清退仍受各自超时约束。持续模式的 `completedInterval` 始终为 `false`，明确停止或目标退出沿用部分采样退出码 `6`，分别以 `cancelled`、`targetExited` 和独立清退回执说明实际结果。普通 `monitor api capture` 仍只接受原有有限时范围。普通 API 原包在采集中分段写入，每段核验后发布检查点。`ordinaryPackets` 为收到的普通包数，`archivedPackets` 为已提交的普通包数，`omittedClues` 为收到但未提交的分类线索数。`archive` 给出已核验段数和最多一条已回查线索；零线索也可有归档回执。归档失败时返回 `archiveError`，已有检查点仍可按原采样回读。

目标和 CLI 须通过 `KSWORD_APIMON_COOPERATIVE_SESSION_V1` 使用同一个绝对路径，目录名为 `KswordApiMonCooperative`。该目录由本轮发起者准备，访问仅限当前用户和 SYSTEM；目录不合格时拒绝发布配置，不回退到共享目录。`configPublished`、`sessionReady`、`hooksInstalled` 分别表示配置已发布、收到同会话就绪回执、收到安装回执。收到安装回执不代表全部 Hook 成功，仍须看 `partialHooks`。

CLI 收到同一会话的安装回执后，会等待读回完整且有效的覆盖快照。快照修订达到或超过 Agent 声明的安装修订，且至少包含一个已生效的观测 Hook 时，`agentReady` 才为 `true`，采集时长从此刻起算。`readyCoverageRevision` 记录启动时实际核验的修订，未就绪时为 `null`。旧 Agent 的安装回执缺少覆盖修订时，命令以 `capture-failed` 和退出码 `3` 返回，并尝试清退本轮会话。

`elapsedMs` 包含启动、采集和清退。`readyAfterMs` 为等待就绪时长，`intervalElapsedMs` 只计就绪后的采集。未就绪时后二者为 `null`。

`api-evidence attach` 与 `capture` 可加 `--startup-progress 1`，在 stderr 按实际前进阶段输出 JSON 行，stdout 仍只输出最终结果。阶段依次为 `identity-verified`、`agent-resolved`、`config-published`、按需出现的 `agent-load-started`、`agent-module-verified`、`pipe-connected`、`session-ready`、`hooks-installed`、`ready`。复用已驻留模块时不产生装载开始阶段。每行保留原 PID、创建 FILETIME、阶段耗时及当时已确认的事实；会话仅在管道服务端核验后提供，覆盖修订仅在完整 Ready 核验后提供。

最终 `startup` 保存最后真实到达阶段及其 `elapsedMs`，失败或取消不把最后阶段改成 Ready，清退期晚到的安装包也不追认启动成功。原生同采样 `control.api.capture` 的 `capture.startup` 使用同一投影。已连接采样的终段保存 `startup` 供历史回查，不授予新控制资格。Qt／Light 在原采样回执刷新内显示同一启动事实；本次扩展尚未构建或运行。

重开归档后，`sample status SAMPLE_ID capture ORDINAL` 或 `sample.query` 启用 `includeCapture` 并选择终段时，`captureArchive.terminal.startup` 返回已核验终段里的原快照；旧档没有该字段时为 `null`。Qt 的归档记录详情和 Light 原有详情文本保留同一历史启动回执，复制与导出沿原详情来源。快照只随完整终段发布，缺标记或坏尾不能从未提交内容补出启动成功；回放不查询当前同PID进程，也不恢复控制权。

清退时，`stopMarkerWritten` 表示控制端已发布停止标记。`hooksRemoved` 表示收到本会话的停钩回执，`cleanPipeEof` 表示管道在原包边界正常结束。未建立连接时后两项为 `null`。目标退出后，CLI 仍会在清退时限内读取已连接的管道，并保留异常读取或截断末包的 `pipeError`。不能单凭 `cleanupComplete` 判定 Agent 确认停钩。`coverageRevision` 是最近完整读回的覆盖快照修订，`requiredFinalCoverageRevision` 仅在停钩回执声明时有值；`coverageSnapshotCurrent` 为真也不意味着所有 Hook 均安装成功。

`api-evidence replay` 和 `replay-api-rules` 的 `archiveSource` 区分关闭文件导入（`closed-jsonl`）、合作管道采集（`cooperative-pipe`）及未记录来源的旧档（`legacy-unspecified`）；规则回放的文件跟随为 `jsonl-follow`。合作管道的 `sourceSequence` 是普通 API 包流水号。合作分段归档按全采样的 `rawSequence` 分页，每条线索另有 `rawSegment`。未见终段时返回 `readback-prefix`；后续段损坏时保留此前已核验的页，退出 `4` 并返回 `failedSegment`。来源字段来自已核验的归档声明，覆盖范围仍为 `unknown`。

合作采集在每段检查点发布后运行五类基础预置。`capture` 结束回执的 `rules` 给出预置版本、累计 `matchedRows` 和最近命中的 `segmentOrdinal`、`rawSequence`、`sourceSequence`。没有检查点时 `rules` 为空；规则求值失败时保留此前的匹配和已提交原包。`replay-api-rules` 的 `presetSet` 是实际回放版本，`recordedPresetSet` 是已核验的采集计划版本，旧档未声明时为空。规则命中只解释同一已核验原包的字段，来源覆盖仍为 `unknown`。

合作采集同时持续计算 `apiTransfers`，仅消费逐字节回读并发布检查点后的原包。四种专用 API 的结构字段用于关联同一来源会话、源/目标创建代次、稳定目标句柄身份及严格先写后创建的 QPC 顺序；请求线程入口须落在来源报告的实际成功写入半开区间内。`candidateCount` 为累计候选数，`recent` 保留最近 32 条、各自的写入与创建请求 `raw` 坐标及普通包流水号。`windowTruncated` 表示候选显示窗口已滚动，`evictedWrites` 独立报告至多 1,024 次最近写入的状态淘汰数。失败归档批次不产生候选，规则配置失败不影响此独立关联。`execution` 保持 `unknown`，创建请求和范围重合不证明实际执行或跨事件因果归因。Qt、Light 活采详情使用同一已提交回执，归档重开通过 `archive inspect ... graph` 回查各段的 `apiTransferCandidates`。

`apiApcTransfers` 使用同一已提交写入窗口，独立累计 `QueueUserAPC`／`NtQueueApcThread` 的 AAAP1 请求返回。只有同来源会话、源／目标创建代次、稳定目标线程代次一致、写入返回 QPC 严格早于入队调用，且请求例程落在实际完成写入的半开范围，才保留候选。其 `recent` 同样最多 32 条，不挤占线程创建候选；`queueOutcome=accepted` 仅表示原接口接受入队，`delivery`、`execution` 均为 `null`。归档图页以 `apiApc` 显示原字段，以 `apiApcTransferCandidates` 显示分页中的候选及双方 raw 坐标；该新增源码尚未构建或实测。

`apiContextTransfers` 同样只消费已提交原包，并与前两类共用 1,024 次实际写入状态，独立保留最近 32 条上下文请求候选。`SetThreadContext`／`NtSetContextThread` 的 AACT1 必须报告完整目标线程代次、安全读取的 CONTROL 请求和接受返回；同来源写入严格早于设置请求，且请求 IP 落在实际完成写入范围，才记录双方 raw 坐标。`contextApplied`、`execution` 均为 `null`。归档图页的 `apiContext` 保留请求 IP／SP／flags／ABI，以 `apiContextTransferCandidates` 输出独立候选窗口；`apiSectionMap` 则分列请求与实际映射范围、原节偏移和输入句柄，不以句柄原位关联共享别名。新增部分均仅源码接入，待构建与实测。

规则目录、合作采集和 JSONL 跟随的规则回执另有 `sourceSha256`，对应本轮实际解析的文件原始字节。采集计划保存 `ruleSourceSha256`，后续各段沿用同一冻结计划。`replay-api-rules` 返回当前 `sourceSha256`、归档中的 `recordedSourceSha256` 和 `matchesRecordedRules`；相同版本名但内容改变时匹配值为 `false`，旧档没有摘要时后两者为 `null`。规则加载失败时摘要为空，不中止独立的原包归档；文件修改仅影响下一轮加载。

`api-rule-catalog --json` 不需要项目。程序从自身目录下的 `profiles/action_analyze_api_rules.json` 加载规则，`profiles` 分别列出 `grouped` 和 `by-category` 的分类预置，`behaviorRules` 列出两种回放配置共用的附加释义。目录同时给出 `expressionProfile`、兼容字段名列表 `fields` 及字段类型、来源、缺值质量的 `typedFields`。缺失、超限、JSON 损坏、版本不符或表达式字段不匹配时返回 `rule-profile-unavailable`，不会使用程序内置的替代规则。自有规则包括虚拟化相关注册表查询线索、环境查询、启动配置写入、服务／任务相关请求、文件操作、进程创建、域名解析与 HTTP 请求；精确字段和证据限制见[规则模块说明](../KswordCLI/ActionAnalyze/Rules/README.md)。KswordSandbox 的 601 条候选索引见[规则规划资料](action-analyze-planning/README.md)，仍未转换为可发行规则。

文件为 UTF-8 JSON。每套分类须为一条已核验 API 观测给出唯一命中；返回释义按文件顺序取第一条匹配。修改条件时更新 `presetSet`，新版在下一次采集或回放生效。正在进行的采集继续使用启动时读入的版本。规则配置加载失败时，合作采集和 JSONL 跟随仍归档原包，并在 `rules.configError` 报告诊断。源码构建会将发布配置复制到目标目录。

`replay-api-rules` 支持单段导入及最多 128 个连续已提交的 API 跟随段。默认使用 `grouped` 两组预置，可用 `by-category` 切为五类细分。`--offset` 是从零开始的线索偏移，`--limit` 默认为 25，范围 1–100。使用上一页的 `nextOffset` 继续。返回段号、块号、原始序号、记录及原包偏移。后续段无法核验时返回 `verified-prefix-only` 和退出码 `6`。报告将采集覆盖标为 `unknown`。

匹配行可附带 `behavior`（规则 ID、证据级别和释义），沿用该行原包坐标。例如明确记录 `WriteProcessMemory` 返回失败且状态为 `ERROR_ACCESS_DENIED` 时，证据级别为 `reported-api-return`，仅解释 API 报告的访问拒绝，不确认目标实例、写入量或调用意图。缺返回字段或状态不匹配时省略 `behavior`。

`network-capture` 用 `process identity query --pid PID --json` 返回的创建 FILETIME 锁定已授权的本机进程。采样时长为 100–60,000 毫秒，最多保存 256 条回环流元数据。系统必须接受指定 PID 和事件的 ETW 筛选。归档核验完成后，用 `records` 返回的 `recordSequence`、`recordOffset` 及采样 ID 调用 `archive inspect SAMPLE_ID raw 1 network SEQUENCE RECORD_OFFSET`。记录的 `payloadState` 为 `metadata-only`，`bytesHex` 为空，采集覆盖为 `unknown`。

`memory watch` 单次运行只持有目标进程的查询、读取和等待权限。请用 `process detail basic query --pid PID --json` 核对 `creation-time`。单次可读 1–65536 字节、2–64 份快照。相邻读取至少间隔 10–1000 毫秒，默认采样 20 次、间隔 100 毫秒。身份不匹配、读取失败或发现映射变化时结束观测。返回的区间为相对起始地址的字节偏移，未显示的区间另计数量。写入来源与执行状态为未知。同属性重建或在两次读取之间写入并复原的内容可能漏过。命令无需驱动或目标 Agent。

每轮的 `threadObservation` 单独记录线程枚举时间窗。可核对身份时保留 TID 和线程创建时间；`newly-observed` 指首次观察到该实例，只有原线程句柄确认终止才报告 `exited`。身份无法确认报告 `unknown`；每轮最多检查 64 个线程，超出时标记 `limited`。这不是停点，线程观测和字节差异不构成写入归因。

`memory track` 与 `memory watch` 的长度、轮数及间隔参数相同，但按页返回映射观测代次、实际读取的范围和 SHA-256、QPC 读取窗口、绝对地址差异区间和覆盖缺口。`--confirm` 确认目标为明确授权的自有进程；后端拒绝跨用户或会话。无法读到的页不作为零或无变化；完整读取退出 `0`，有部分观测退出 `6`，原生失败且无观测退出 `3`。这是一条独立 CLI 命令，不修改项目或目标；执行未采集，写入者未知。两次采样之间短暂变化或相同属性重映射可能漏过。

`memory stream` 使用同一只读范围和身份检查持续交付结果。`stop`、输入结束、目标退出或来源错误都会结束采样。`summary.inputIssue` 保存输入诊断和可用的字节偏移。输出暂时阻塞时保留一帧，并继续接收停止指令。stdout 断开或写入超时会停止采样，并在 stderr 输出 `memory-stream-output-unavailable`，进程退出码为 `3`。`--interval-ms` 设定两轮之间的最短等待，归档由调用方负责。

`memory snapshot` 要求已有项目，使用 PID 与 `--creation-filetime` 冻结同一真实进程句柄，最多覆盖 64 页，只读一次，不暂停目标。没有 `--sample` 时按项目当前修订新建采样；指定已有采样时只追加新的 `raw-memory` 段，不覆盖 API/ETW 的 `raw` 主流。`--title` 只用于新采样。各页保存读前后映射、QPC 窗口、实际成功原字节及 SHA-256；失败或取消保留部分结果，缺失范围不填零。完整范围退出 `0`，部分范围退出 `6`，身份或存储错误退出 `3`。`plan.target.machineId/bootId` 为单次采集 UUID 作用域标签，不表示跨采集验证的系统身份。读取属于 live 非原子快照，不表示停点或完整进程 Dump。

`memory read` 在安全项目路径内从第一段到指定段核对连续序号、完整段封装、计划、页次序、字节散列及尾记，返回 `raw-memory` 段号与每页 `recordSequence/recordOffset`、`validLength`、失败页数量、QPC、整段 `sha256` 和 `completeRange`。`memory export` 只从同样已核验的归档取字节；默认导出完整所选范围，也可同时提供 `--base/--bytes` 导出被完整覆盖的子范围。跨不可读页或尚未访问页的范围直接拒绝，且不创建输出。输出父目录必须已存在，文件以新建方式打开，已有文件不覆盖；结果给出有效长度、导出文件 SHA-256 及来源段 SHA-256。

这里的 CRC／SHA-256 核验只证明归档内容完整及本次读取一致，不能认证外来文件的历史生产者。历史 `plan` 中的身份仅作证据说明，不能据此取得活进程句柄、停点令牌或控制权。存储格式见 [显式选中内存采样 v1](../schemas/action_analyze/selected-memory-v1.md)。

回读同时兼容原始计划与带可选 `readContext` 的计划，原样保留读取来源、阶段、错误及前后停点历史身份。`heldAtBothChecks` 与字节范围的 `completeRange` 分别报告；历史持有停点失效不会被改写成实时读取。带上下文的实时读取不允许携带停点令牌；声明两次均持有时，前后完整令牌必须相同且目标匹配计划。

两条命令的 `--observe-threads` 默认关闭。`track` 的 `data` 以及 `stream` 的 `start.data`、`summary.data` 用 `threadObservationEnabled` 报告是否启用。启用后，一轮内至少有一个页产生已核验的 `content`，才会使用原进程句柄附加 `round.threadObservation`（JSONL 中为 `round` 帧的 `data.threadObservation`）。部分读取、读后映射变化或散列失败时，`returnedBytes` 仍可用于诊断，不能代替 `content`。线程观察字段与 `watch` 相同。关闭、无已核验内容或轮次被终止时该字段为 `null`；正常完成的末轮仍按采样处理。停止、取消、退出和背压期间仅检查状态时，不补采线程。线程快照有独立时间窗，可能漏掉短命线程；不装载驱动、不修改或挂起目标，也不证明谁写入、哪个线程曾执行或命中停点。

`round.previousThreadObservationRound` 是前一次实际尝试线程快照的内存轮号，与 `ordinal` 编码一致。首次、关闭或本轮未尝试时为 `null`。前一次快照可能有读取缺口，须查看所指轮次的 `snapshotStatus`；跳过的内存轮不更新这个编号。枚举失败而目标仍在运行时，保留已有线程句柄供后续确认退出，但失败轮不作为判断新线程的完整基准。

`breakpoint session` 是独立活会话。启动模式接受明确授权的 EXE 和可选已加载模块的完整路径；默认模块是 EXE，只接受一个区分大小写的非转发导出名或由调用方确认的指令边界 RVA。子进程不继承 CLI 的输入输出。附加模式接受已运行目标的精确 PID、创建 FILETIME 与明确私有地址。最初的 `hello` 只报告启动或附加提交回执；用 `status` 等待 `breakpoint.state=armed`，或读取 `held`、命中线程和停止令牌。`continue STOP_ID STATE_REVISION` 继续该原生事件并保留断点，`quit` 或 EOF 先清退自有断点再解除附加，不代为终止目标。武装前的执行不在覆盖内。均不支持 WOW64、PDB 或 R0，异常退出后不保证恢复。

已有进程的私有地址及模块执行入口：

多实例执行集合的正式命令、站点格式和完整成员票据见[执行断点集合](cli/action-analyze-execution-group.md)。AAIM1 内存生命周期的只读范围目录、分页和显式草稿见[私有执行范围候选](cli/action-analyze-execution-candidates.md)。

执行集合可用 `--project PATH` 新建项目，或 `--project PATH --open-project` 打开已有项目；两者都在附加前创建本轮新采样。REPL `execution-save execution/N TOKENHEX`、JSONL `control.execution.save`（空 params，expected 携 collectionId 和唯一完整 stopToken）显式保存当前成员执行观察到同采样 `raw-native`，不继续任何成员。`executionArchive` 分别报告真实项目/采样、事件、段号、written/flushed/verified、去重和首次追加失败；ManualPause 不构成执行证据。Qt 和 Light 执行集合入口同步提供项目草稿、保存动作及同源详情。新增接线尚未构建或实测。

执行集合的模块 RVA 站点支持可选 `definitionId`。它引用本轮采样冻结的启用 RVA 定义，要求项目、模块名及 RVA 一致，并继承定义的映像 SHA256；冲突或缺失在任何附加前拒绝。Qt/Light 提供相同字段；手工导出和私有站点不发送隐藏定义草稿。完整全局定义自动激活及 PDB 符号解析仍未实现。

执行集合的同采样API入口为 REPL `api-capture execution/N PID FILETIME DURATION confirm REPLSESSIONTOKEN [progress]` 或 JSONL `control.api.capture`。JSONL params沿用明确 `sourcePid/sourceCreationFileTime/durationMs/confirm` 及可选 `startupProgress`；expected为 `{collectionId,sessions:[唯一完整sessionToken]}`。来源必须在集合全部成员以外，复用原项目writer和sample，Ready后采集1000–10000毫秒，CLI返回后再处理排队控制。`apiCapture/apiOwner` 保留采集、归档、清退及原目标前后回读；不Continue同伴、不自动保存执行事件。Qt/Light同步提供参数、确认、阶段、完整详情及关闭取消。新增接线未构建、未实测。

执行集合内存入口为 `memory-read execution/N ADDRESS BYTES TOKENHEX`／`control.memory.read`（params含十进制字符串address/bytes，expected含collectionId及唯一完整stopToken），以及 `memory-save execution/N TRACKING_EPOCH`／`control.memory.save`（空params，expected含collectionId/trackingEpoch）。读取沿原成员会话核对读前后停点，允许主动暂停；保存冻结原字节到本轮sample独立raw-memory，切换选择不改来源。结果独立保留逐页诊断、字节预览、savedSource及写入/刷盘/核验，同读取重复保存返回原段，真实追加失败停止后续写入。Qt/Light原参数页和worker同步接入，新增源码未构建、未实测。

执行集合的模块站点可选 `imageSha256`（64个小写十六进制字符），支持精确导出及RVA。每个原成员owner对实际模块基址对应的调试装载事件文件核验后才武装DR0；期望值在 `site.imageSha256`，实测成功值在 `control.breakpoint.imageSha256`，私有地址禁止该字段。不能取得原事件文件或散列不符只清退对应成员，成功成员继续保留。该新增集合约束仍待构建和运行。

执行集合也支持单成员 `control.execution.range.add`：`params:{address,bytes}` 用规范正十进制字符串，`expected:{collectionId,stops:[完整当前NX停点票据]}`。REPL为 `execution-range-add execution/N ADDRESS BYTES TOKENHEX`。它沿原成员owner追加明确整页范围，保留原停点、初始站点和总64页预算，不继续目标；ManualPause允许追加。`canAddRange`、实际 `executionRanges` 和独立 `executionRange` 回执分列。该新增入口尚未构建或实测。

执行集合另支持 `pause execution/N all|selected TOKENHEX[,TOKENHEX...]`／JSONL `control.pause`：在各成员原执行 owner 内主动暂停，冻结完整 `pauseToken`，全部预核对后逐项提交；独立保留暂停回执。精确 `ManualPause` Held 可继续，本批拒绝步进，不能以创建执行绑定冒充主动暂停。参数及完整包络见上述执行集合文档。

执行集合的全体／所选暂停和继续支持 Held／Armed 混合状态。新 JSONL `expected.sessions` 携带完整 `{owner,control}` 成员表，兼容旧 `expected.stops` 完整令牌列表；REPL新增可回传的 `replSessionToken`。全批身份先核验，Pause保留精确Held并记`already-held`，Continue跳过明确运行成员并记`already-running`；每项单列 `actionAttempted`／`disposition` 和原回执，未知或恢复失败拒绝且不清账。

```text
KswordCLI.exe analyze breakpoint session --pid PID --creation-filetime FILETIME --address 0xADDRESS --confirm --disposition resume-detach --input repl
KswordCLI.exe analyze breakpoint session --pid PID --creation-filetime FILETIME --address 0xPAGEBASE --range-bytes 4096 --confirm --disposition resume-detach --input repl
KswordCLI.exe analyze breakpoint session --pid PID --creation-filetime FILETIME --attach-image --module C:\Target\module.dll --rva 0xRVA --confirm --disposition resume-detach --input repl
KswordCLI.exe analyze breakpoint session --pid PID --creation-filetime FILETIME --address 0xADDRESS --watch-write-bytes 8 --project PROJECT --confirm --disposition resume-detach --input jsonl
```

`--attach-image` 用于已有进程的普通模块执行断点：提供绝对 `--module` 路径，以及二选一的 `--export` 精确PE导出或非零 `--rva`。该模式核验实际实例和已加载映像位置，不创建目标或合作Gate，不修改页保护，不能与私有地址、NX范围或写关注混用。命中后沿原owner执行条件、继续、步进、内存及执行归档，`targetMode=attached-image-execution`；没有PDB符号解析。Qt／Light写入停点页的“已有模块导出执行关注／已有模块RVA执行关注”使用同一路径。

已保存定义可使用 `--attach-image --module PATH --definition UUID --project PATH`，与 `--rva`、`--export` 互斥。定义来自本轮真实采样的冻结配置，须已启用、使用非零 RVA，且模块文件名匹配。可选 `imageSha256` 传给原生owner，在DR0武装前核对实际解析模块基址对应的 `CREATE_PROCESS`／`LOAD_DLL` 调试事件文件；缺文件、不能完整读取或散列不符均拒绝。新回执 `control.breakpoint.imageSha256` 是实测文件散列，不能据此证明目标映像内存页未被改写。当前仍不接PDB调试符号。`hello.executionArchive.breakpointDefinitionId` 保留实际定义来源。Qt与Light同样从原sample解析约束，并显示实测散列；读取旧项目定义只准备新活会话，不导入历史停止令牌。固定映像散列新增接线尚未构建或实测。

已经武装且正在运行的单目标会话支持 `pause PID CREATION_FILETIME`；JSONL 使用 `control.pause`，带当前 `session`、独立连续 `pause/1` 起的 `requestId` 和 `params:{"targetPid":123,"targetCreationFileTime":"..."}`，不带 `expected`。沿同一个原生 owner 请求中断，不创建第二个调试附加。接受请求只表示等待事件；`armedPause.state` 区分 `pending`、`held`、`preempted`、拒绝和恢复失败。`pause-status pause/N` 或 `control.pause.query` 的 `params:{"requestId":"pause/N"}` 查询原暂停回执。该查询使用普通查询ID，不占 `pause/` 空间。

实际主动停止显示 `stopReason=manual-pause`，保留当前停止组和完整票据，用原 `continue STOP_ID STATE_REVISION` 恢复。手动暂停不应用断点条件、不生成执行证据，本批不提供在中断线程上的单步；完整 Held 可读内存，关闭仍清退原绑定。真实断点抢先时保留真实命中及暂停请求的独立状态，不将它改名为手动暂停。该新增链路未构建、未实测。

NX执行会话持有当前完整停点后，可用 `execution-range-add ADDRESS BYTES STOP_ID STATE_REVISION` 显式纳入新范围。四项均冻结于请求，地址、长度及修订使用规范正十进制；地址与长度按4096字节对齐，单段来自同一已提交私有分配，允许多段不连续或属于不同分配，全部范围合计最多64页，重叠拒绝。操作保留原停点，不自动继续，也不改写初始 `binding.address/rangeBytes`。`binding.executionRanges` 列出成功范围，`control.executionRange` 保留新增、回滚、阶段和错误回执。

JSONL方法为 `control.execution.range.add`，请求带当前session、独立连续 `range/1` 起的requestId、`params:{"address":"...","bytes":"..."}` 与 `expected:{"stopId":"...","stateRevision":"..."}`。重放窗口128条，冲突及过期请求拒绝，不占Continue或Step序号。新增失败只回滚新增页，恢复未确认仍由原Close保留责任。

数值条件使用 `predicate-expr-v3`，旧v1/v2仍可读取。支持字段间比较、括号、`~`、一元 `+`、`* / % + - << >> & ^ |`，按C#优先级解析。例：`(stop.thread.rax & 0xffu64) == 0u64`、`stop.thread.rip >= stop.address`。位运算与比较请明确加括号；无符号加减乘溢出环绕，移位计数取低6位，除零或余零产生 `Unknown` 及 `division-by-zero`，未知寄存器不视为零。原条件假或未知自动继续的策略保持一致。

v3新增 `condition ? whenTrue : whenFalse`，优先级低于 `||`、右结合。条件为bool，两分支必须同为bool或同为u64，最终断点谓词仍须bool；例：`(stop.firstChance ? stop.thread.rax : stop.thread.rbx) == 0u64`。准备时检查全部分支类型，求值时只进入选中分支；未知条件直接Unknown，未选分支不读取字段、不产生除零故障。显式v1/v2拒绝三元语法，字段白名单不扩张。Qt／Light走同一准备及求值路径；三元扩展仅源码完成，尚未构建或运行。

v3的 `& ^ |` 另支持同为bool的两侧谓词，按原C#优先级从左到右求值两侧，bool/u64混合在准备阶段拒绝。与 `&&/||` 不同，右侧不会因左侧真值而省略；例如 `false & (1u64 / 0u64 == 0u64)` 返回带 `division-by-zero` 的Unknown。未知值保持三值逻辑，异或遇未知仍为Unknown。三端复用共享解析器和预算，该新增布尔语法仍待构建和运行。

v3还允许两个bool字段或谓词的 `==`／`!=`，例如 `stop.firstChance == isKnown(stop.thread.rax)` 或 `(stop.firstChance & isKnown(stop.thread.rip)) != false`。仍按C#比较优先级从左到右计算，两侧必须都是bool，任一未知即Unknown；bool不支持大小比较或与u64混合比较。原字段对null测试及v1/v2语法保留。Qt／Light说明和CLI帮助同步，新增仅源码待验。

原生 Into 与 NX 跨页取指复用同一有界 AMD64 解码器，按已登记编码支持普通内存读写、算术、分支、near CALL／RET 和部分 SSE／AVX 指令。只读取当前一条指令，最多15字节；执行完成仍须来自精确原线程的真实 TF 事件。未知编码、POPF、SS 修改、特权转换和竞争调试状态拒绝。REP 字符串的一次 BS 可能只代表一轮，因此当前拒绝这种单指令完成请求；不会把一轮当成整条指令完成。Over 遇 CALL 仍按 DR1 返回边界停止，遇其它受支持指令则沿原owner执行一次真实TF，保留 `mode:over-call` 和 `destination:null`；不预测下一IP。非CALL的单条TF完成可形成 `instruction-completed`，CALL返回边界不形成此证据。Qt／Light及CLI执行集合共用此行为。Out 仍要求真实 RET 或 owner 已证明的入口帧。本增量尚未构建或运行验证。

省略 `--watch-write-bytes` 时设执行关注，地址必须位于已提交的私有 EXECUTE／RX／RWX 区域；提供 1／2／4／8 时设对应宽度的写入关注，地址必须自然对齐且完全落在同一私有 RW／RWX 区域。附加不依赖导出符号、目标握手或父子关系；`--exe`、`--module`、`--export`、`--rva`、两种指针导出参数和双目标模式不能与附加选择器混用。回执 `targetMode=attached-private-address`，默认单地址绑定 `siteKind=private-address-execution` 或 `private-address-write`，冻结地址与区域属性。两种单目标模式均支持原条件和单步；写入模式可在真实停点读取、保存内存并采集同采样 API，Into 真正完成后的执行观测也可保存。新线程通过同一原生 owner 登记，关闭使用原恢复账本；默认单地址DR0不修改区域保护，检测到映射属性变化会清退，不自动重绑；同址同属性的分配代次仍未知。此新增入口尚未实测。

`--range-bytes` 显式选择私有NX执行范围，与写关注互斥；起点及长度必须按4096字节对齐，并由原生owner接纳实际范围。示例4096表示整页关注。该机制临时撤去执行权限，保留原读写权限，关闭时恢复原保护；不占用DR0。绑定返回 `siteKind=private-page-execution`、`rangeBytes` 与范围起点，命中返回实际页内RIP，二者不必相等。Continue沿原生TF推进并重新设防后再释放同伴；推进不支持或恢复失败时保留真实停止责任及诊断。NX命中可保存为执行进入尝试，内部重新设防TF不会冒充用户单条指令完成。新增范围入口未构建、未实测。

单目标写入关注也接受 `--condition`，例如 `stop.data.changedByteMask != 0u64 && stop.thread.rax == 0u64`。写入字段仅在实际写入观测中存在；`stop.thread` 下的 `rip`、`rax`、`rbx`、`rcx`、`rdx`、`rbp`、`rsi`、`rdi`、`rsp`、`r8` 至 `r15` 及 `eflags` 均为 `u64`，来自原生 owner 在该事件暂停时采集的同一命中线程快照。`control.registers` 保留同一线程身份；RIP／RSP 沿用地址表示，其余为无符号十进制字符串。示例：`(stop.thread.eflags & 0x40u64) != 0u64 && stop.thread.rcx == stop.thread.rdx`。采集失败为未知，已采集的零值仍为已知。假或未知走原自动继续，普通单步停点不重新求值；执行入口条件引用写入字段时也保持未知。主动暂停不采寄存器、不套断点条件。新增寄存器与写入条件接线尚未实测，旧“RAX 未采集”的用例不代表本次采集行为。

单目标执行或写入停点可带 `--project PATH` 打开已有项目，整个会话持有独占项目写租约。没有 `--sample` 时从当前已提交配置新建真实采样；指定 `--sample UUID` 时复用项目内已登记的采样，该采样成为原生 owner 的 `sampleId`。启动或附加前核对 `raw-native` 实际目录和全部已有段，缺段、坏尾、散列或序号失败均拒绝启动，不能抢占其他 writer。`hello.executionArchive` 返回项目、采样、下一段号和上限。写入停点可读写内存归档，但只有实际执行观测才能执行 `execution-save`；合作双目标模式暂不接受此参数。不带项目时继续保留一次性会话行为。

REPL 使用 `execution-save STOP_ID STATE_REVISION` 显式保存当前仍持有的原生执行观测，不自动继续。JSONL 使用 `control.execution.save`，`params` 必须为空对象，并携带当前会话 `session:{id,epoch}` 和精确 `expected:{stopId,stateRevision}`；修订以规范正十进制字符串表示。保存时在同一 CLI 串行控制线程重新查询活 owner，仅接当前执行进入尝试或原生 Into TF 单指令完成观测。相同原生事件重复保存返回原归档坐标，不新建段。每会话最多保存 4096 个事件，去重内存保持有界，后续会话可核验旧段后继续追加；失败返回原始 `raw.written/raw.flushed`、状态和错误，阻止该会话后续追加，不跳段掩盖部分写失败。

新原生执行文档为 `native-execution-v2`，额外保存同一事件实际线程的 `registers:{threadId,values}`；`values` 含完整18项通用寄存器／RIP／EFlags 的无损十进制字符串，采集失败时整个 `registers` 为 `null`。Into 完成档中的值为指令执行之后的停止现场。`analyze execution read` 以及内存／线程转移／APC／上下文／节映射关联继续接受旧 `native-execution-v1`，旧档缺寄存器不填零。Qt／Light 的原生历史详情消费同一规范文档，不重新查询目标。新增v2读写尚未构建或实测。

当前新写入升级为 `native-execution-v3`，在v2寄存器之外增加 `binding`：同一事件时的原请求ID、绑定地址、初始范围、模块基址、RVA、关注宽度、实测文件 `imageSha256` 及已纳入 `executionRanges`。动态NX追加后保存实际范围列表，旧事件保持旧范围；进入尝试必须落在当时已纳入范围或精确DR0地址，Into完成可已离开初始站点。v1/v2仍按原字段读取，不用当前绑定补旧档；历史绑定不授予活控制权，也不证明区域代次、因果或运行时页面散列。三端复用原历史文档消费；新增v3尚未构建或运行。

项目单目标会话提供 REPL `api-capture PID FILETIME DURATION confirm [progress]`，或 JSONL `control.api.capture`：携带当前 `session`，不带 `expected`，`params` 必须含 `sourcePid`（UInt）、`sourceCreationFileTime`（规范正十进制字符串）、`durationMs`（UInt，1000..10000）、`confirm:true`，另外可含 `startupProgress`（bool）。显式来源必须是另一进程实例，不得使用当前原生目标；调用前从原 owner 的 Query 实读目标 PID，来源 PID＋FILETIME 再由既有显式 R3 附加控制器核对。不从关联候选自动选进程，也不默换采样。

REPL 末尾加 `progress` 或 JSONL 指定 `startupProgress:true` 时，原采集线程在阶段实际前进后向 stderr 输出一行 JSON，字段为 `projectId`、`sampleId`、`nativeTarget:{pid,creationFileTime}` 和 `startup`。`startup` 沿用九阶段及原来源身份投影；stdout 仍只返回原命令响应，不产生额外控制事件或ACK。Qt／Light 同采样API沿同一回调更新现有字段详情，保留本次来源与原采样；原最终回执保留至新结果返回，Ready不代表完整采集或归档成功。仅源码接入，尚未构建或实测。

该命令在原 CLI 控制线程同步完成有限采集，**采集区间最长 10 秒，启动与停止排空超时另计**，期间其他控制指令等待完成后处理；不支持 duration=0。原 debug 线程独立保留已有停点，API 清退只停止 API，不 Continue/Close 原生 owner。复用同一个项目 writer 和实际 sample 的冻结修订，不创建第二 writer、项目、采样或 owner，不订阅 Agent ETW。只允许首次使用 primary API lane：`raw` 或 `checkpoints` 目录已存在时（含空目录、坏尾、缺标记）由核心以 `apiCaptureLaneAlreadyUsed` 拒绝，不覆盖、补写或跳段。

实际采集尝试用 response 返回独立 `exitCode/status`、来源与原 capture、`archive.archivedPackets/committedSegments`、已提交前缀、规则文件 SHA、三类 transfer 累计计数和清退状态；参数/会话拒绝为 error。归档前缀成功不代表原采集完整，部分结果保留真实原码，错误不锁死 native/memory lane。API 回调不隐式保存原生证据，完成后需另显式 `execution-save`。同采样只表示存储作用域一致，四项来源/区域版本/因果/共同钟保证仍为 false；本入口仅完成源码接入，旧验收不覆盖，未构建、未测试。

Qt／Light 的同采样 API 在途时，原会话关闭入口立即置位 API 取消标记。尚未启动的采集不装载 Agent、不发布配置、不创建 API 流；已经启动的采集仍由原采集器停钩、排空并保存可提交前缀，再由原串行 worker 关闭调试会话。取消回执保留 `cancelled`，不补成完整区间；启动前取消也不冒充 Agent 路径缺失。Qt 的关闭动作在 API 在途时可用，关闭优先于尚未执行的排队动作。此变更尚未构建或实测；CLI 的同步命令仍按上述串行区间约定处理。

`analyze execution read` 返回核验后的历史 `document`、`sha256`、`endOffset/blockOrdinal/lastSequence` 和 `raw-native` 段坐标；按链从第 1 段读至请求段。不将历史文档反序列化成活控制对象，归档中的停止 ID 不授予继续或步进权限。

`analyze execution history` 不要求同采样存在 API 归档，按独立 `raw-native` 段号分页列出已核验观察。`after` 是上页 `nextAfter`，`hasMore` 只表示本次最多4096段的已核验范围还有后页；`historyLimited=true` 时 `firstUnreadOrdinal` 标识扫描上限，不代表后续段已验证。坏段使列表查询失败，不发布部分成功列表；已登记但没有原生历史的采样返回成功空列表。Qt／Light 归档关系树分别保留最近512条独立历史和原API一致性候选，独立历史也能查看完整寄存器和原绑定；仅含原生流的采样从项目与采样入口打开，普通raw缺失不会伪报API或ETW终段。此批为源码接入，未构建或运行。

`analyze execution map` 分别从首段核验 API 与原生链，只接受精确 `NtMapViewOfSection` 的 Accepted 记录，要求 Actor/Target/Stable/MappedBase/MappedBytes 有效且实际范围无溢出；实际 `instructionAddress` 必须落在同目标进程代次的 `[mappedBase, mappedBase+mappedBytes)` 中。输出 `mapping/native` 原坐标、两段 SHA、原 observation、实际/请求范围、可选 sectionOffset、句柄原位及各自原时钟；缺失请求有效位时对应值为 null，不用请求范围代替实际输出。`sourceAuthenticated/regionVersionVerified/causalityConfirmed/commonClockVerified/writeObserved/aliasPropagationVerified` 均为 false：不要求写入、不凭节句柄推定别名身份、不跨 QPC 排序、不建立强执行因果，也不访问进程。零匹配为成功空页，`nextAfter` 仍沿 API 观察分页；任一链读取失败整个查询失败，不发布部分候选。

上述项目单目标会话还支持 `memory-snapshot BASE BYTES STOP_ID STATE_REVISION`；JSONL 为 `control.memory.snapshot`，`params:{base,bytes}` 两值均为规范正十进制字符串，携带当前 `session` 与精确 `expected:{stopId,stateRevision}`。先核对界面显示的停止 ID 和修订，再冻结该活 owner 的完整事件令牌，读取核心在读前/读后再次查询同一个 owner，要求完整停止组；不创建第二个 owner，不继续或暂停目标。复用当前项目独占写租约和实际采样，不创建第二个 project writer。

启动时同步核验一次完整 `raw-memory` 前链，后续每次显式读取用已核验游标追加新段，最多每采样 4096 段、每次范围最多覆盖 64 页。同一原生事件内可重复读取不同时间或范围，不按执行事件去重。响应保留完整 `readContext`、实际归档字节数、页元数据/散列、整段 SHA-256、原始写入/刷盘回执及页坐标；缺页不填零，结果 `exitCode:6` 表示范围不完整或停止状态改变，会话继续保留，等待调用方决定下一步。写入、刷盘或回读失败保留首次回执并只阻断 `raw-memory`，不误阻断 `raw-native` 保存。历史字节读取和导出复用 `analyze memory read/export`，停点上下文仍只是历史证据。

`analyze execution correlate` 复用已核验的 API 图页及指定原生历史段，逐个把创建候选的原始坐标对应到该页创建记录，再比较目标 PID＋创建 FILETIME、创建返回线程 TID＋创建 FILETIME，以及原生实际指令地址是否位于实际完成写入的 `[writtenAddress, writtenAddress+writtenBytes)` 范围。返回 `candidates`、写入/创建/原生三份原坐标、原生与 API SHA-256、原生实际观测种类、各自原始时钟及截断/淘汰限制；`nextAfter` 沿用 API 原始观察分页游标，空候选页也可能有下一页。任一链核验失败时整个查询失败，不发布部分成功关联。`sourceAuthenticated/regionVersionVerified/causalityConfirmed/commonClockVerified` 均保持 `false`：没有共同启动期时钟证明，不比较两路 QPC 的先后，也不据此反推整条注入已确认；此命令只读归档，不访问进程。

APC 对应的输出单列为 `apcCandidates`／`apcCandidateCount`，输入窗口用 `apcTransferCandidateCount`、`retainedApcTransferCandidates`、`apcTransferCandidatesTruncated` 报告。核对请求目标线程 TID＋创建 FILETIME，并额外要求实际 `instructionAddress` 等于 `requestedRoutineAddress`；进入尝试和 Into 完成观测保持原阶段，不用下一 RIP 代替例程入口。每项保留写入／入队／原生三份坐标、原生 SHA 和两路原时钟。`queueOutcome` 仍只为接受，`delivery=null`，上述四项声明仍为 `false`；即使同线程在例程入口实际停住，也不能据此确认通过 APC 投递到达。新增关联尚未构建或实测。

上下文一致性结果独立输出为 `contextCandidates`／`contextCandidateCount`，窗口计数使用 `contextTransferCandidateCount`、`retainedContextTransferCandidates`、`contextTransferCandidatesTruncated`，沿用同一 API 页的 `after/limit/nextAfter`。请求端按原始坐标精确定位本页已核验上下文记录，再交核心匹配；每项保留 write/context/native 三份原坐标、原生 SHA、请求 IP/SP/架构及两路原时钟，四项声明仍为 `false`，`contextApplied=null`。请求 IP 和 API 接受结果不自动代表实际执行、上下文已应用或活控制资格；不访问目标、不比较跨源 QPC，任何读链失败均不发布部分候选。新增上下文关联仅源码接入，未构建、未测试。

`analyze execution memory` 分别从第 1 段核验 `raw-native` 和 `raw-memory` 到请求段号，再由共享核心核对项目/采样、进程 PID＋创建 FILETIME＋processInstanceId，以及内存 `readContext` 的 held-event 读前/读后完整令牌与原生执行的 event/group/stop/revision。只取 `instructionAddress` 起请求字节，不使用 `nextInstructionAddress`；不回退到旧 live-read 或 changed-held 结果，不访问目标进程。

成功回执包含 `observation`、`instructionAddress`、`bytesHex`，以及两条 lane 的段号、段 SHA-256、端点、执行记录 sequence 和参与字节提取的内存页 sequences；保留原始执行 `document` 和内存 `plan` 身份。`heldAtBothChecks` 为 true，`bytesAtExecutionVerified/allocationGenerationVerified/sourceAuthenticated/instructionDecoded` 均为 false。这仅说明同一历史停点持有期间读取到了这些内存字节，不证明 CPU 取指当时的字节，也不表示已解码完整指令；两路 QPC 不比较。任一链或匹配失败均退出 3，不返回部分 `bytesHex`。

`--cooperative-pair` 启动同一合作 AMD64 控制台程序的两个实例，使用同一命名执行导出，和 `--module`、`--rva`、`--watch-write-bytes` 互斥。每个实例主动就绪，两端武装后才允许进入正常业务。`status` 返回两个独立的 `members`；只有 `held-complete` 才返回组 `stop`。`held-partial` 表示仅部分持有。继续使用组令牌，逐个成员确认 `release.members`，只有两项均确认才返回 `release.continued:true`。组关闭报告实际 `clean`，保留原始 `endReason`（`requested`、`failed` 或 `member-ended`）和已经取得的继续回执。`members[].exitCode` 来自启动时取得的进程句柄；未观察到退出时为 `null`，即使调试清退已确认。

双目标可同时提供 `--condition EXPR`。表达式在启动前冻结，仅在两成员均真实持有时，按启动顺序分别对冻结字段求值。任一成员为 `true` 就保留整个组；两成员均为 `false` 或 `unknown` 时使用当轮组令牌自动继续全部成员。部分持有不求值或释放。`condition.aggregation` 为 `any-true-holds-group`，`condition.last.members` 保留每个成员的 PID、创建 FILETIME、原生组修订、事件序号、三值与求值错误；计数按成员累计。同一组代次查询不重复计数，自动继续不消耗客户端 `continue/N` 序号。

单目标和组内成员均在取得原生凭据时返回 `retirement`：`detached` 表示已脱离，`exit-event-continued` 表示已继续进程退出事件，后者附带 `exitEvent` 和事件报告的退出码。`firstRecoveryFailure` 独立保存首次未清退阶段、Win32 错误、原生所有者及当时已知的事件和继续请求 ID，后续清退成功仍保留。事件凭据由 `backendInstanceId` 和十进制字符串 `serial` 共同定位，无凭据时对应字段为空。

JSONL 输入沿用 `schemaVersion`、`requestId`、`method`、`params` 包络，支持 `control.query`、`control.continue`、`controller.shutdown`，三者的 `params` 均为空对象。继续须提供 `hello` 的 `session` 和 `expected` 中的 `stopId`、`stateRevision`，后者为十进制字符串。继续请求 ID 从 `continue/1` 逐次递增，最近 128 个继续 ID 可重放，窗口外返回 `release-replay-expired`。后端滚动保留至多 64 个停点，不淘汰未清退责任。两种输入均输出独立的 JSON 行，`hello`、`response`、`error` 或 `summary` 保存会话和传输序号；有原生清退责任时不会报告 `clean=true`。

单目标执行停点会话另提供原生步进。`originThread` 给出当前冻结触发线程的 `threadId`、数值 `tid` 和十进制字符串 `creationFileTime`。REPL 使用 `step into|over-call|out STOP_ID STATE_REVISION THREAD_ID TID CREATION_FILETIME`；原停点被继续后，由原生所有者在完成或中断处登记新停止组。必须查询新令牌后才能再次步进或继续。原执行断点的条件不自动放行普通步进停点；若提前再次命中原断点，则仍按该断点条件判断。合作双目标组和数据写入停点不提供本轮步进入口。

单目标 `--watch-write-bytes`＋`--watch-pointer-export` 会话另提供显式同址转执行：REPL `execution-follow ADDRESS STOP_ID STATE_REVISION`，地址与修订均为规范正十进制；JSONL `control.execution.follow` 携带当前 `session`、仅有 `address`（规范正十进制字符串）的 `params` 和精确 `expected:{stopId,stateRevision}`。请求 ID 从 `follow/1` 连续递增，与 `continue/N`、`step/N` 分开，最近 128 条可重放；同 ID 改参数拒绝，窗口外不重新执行，通过形状和序号核验的过期停点请求也消费该 follow 序号。`hello.followProtocol` 说明协议，其他单目标模式该项为空。

先 Query 核对 `breakpoint.privateExecutionFollowAvailable`、实际原地址与当前完整写入停点。协议重新核验同一活 owner、sample/session/epoch、HeldComplete 和精确 stop/revision/address，核心再核验最初冻结的 RWX 私有区域起点、各活线程强身份及 DR 状态并处理失败回滚；不从历史或候选补目标。操作只将同址硬件写关注改为执行关注，不改变页保护，不 Continue 或 Step，原写入命中和停止组仍保留写入语义。`control.executionFollow` 分别报告 `converted`、`rollbackComplete`、原 stop/revision、阶段和 Win32 错误，`continued` 固定 false；核对结果及当前停止令牌后由用户另显式继续，后续真实执行命中才属于执行观测。`executePointerExport` 沿用实际绑定字段，不因提交 follow 就将旧写入证据改成执行证据。本入口仅源码接入，旧 step/写关注验收不覆盖；本端未构建、未测试。

JSONL 使用 `control.step`，`params` 必须正好包含 `mode`（`into`、`over-call` 或 `out`）、`threadId`、数值 `tid`、十进制字符串 `threadCreationFileTime`，并携带同一活会话 `session` 与 `expected:{stopId,stateRevision}`。请求 ID 从 `step/1` 连续递增，与人工继续的 `continue/N` 序列独立。相同 ID、相同参数返回原提交回执，参数冲突被拒绝；最近 128 次请求可重放，窗口外返回 `step-replay-expired`，不会重新执行。通过形状和序号校验后的过期停点请求也消耗该次 step 序号。查询与取消使用 `control.step.query`、`control.step.cancel`，均携带 `session` 和 `params:{requestId:"step/N"}`，不提供 `expected`；本次包络的请求 ID 使用普通独立 ID。REPL 对应 `step-status step/N`、`step-cancel step/N`。

`control.step` 的提交响应不代表执行已完成。随后通过查询读取 `step.state`、`stage`、原生错误、起始和观察到的 IP/SP、目标地址、强线程身份、新停止组及 `resourcesRestored`。取消请求异步交给同一原生所有者，待 `cancelled` 或其他终态及新停点回执后再决定继续；退出和关闭同样先归还本次步进的寄存器及挂起责任。当前模式只接受原生实现支持的已知指令和帧：调用步过针对已识别的调用指令，跳出限可核验返回位置；未知指令或无法证明的帧会被拒绝并保留原停止责任，不作猜测式运行。`hello.stepProtocol` 为该入口的协议说明，数据写入模式为空。

`status` 与 `control.query` 在真实持有原生事件时另给出 `execution` 执行观测，只能由同一原生所有者回读适配器生成。`kind=execution-enter-attempt` 表示 DR0 执行断点的进入尝试，`instructionAddress` 为该断点地址；`kind=instruction-completed` 表示一次 `into` 模式的单指令 TF 已完成，`instructionAddress` 是真实完成的那条指令起点，`nextInstructionAddress` 是回读到的下一 RIP。仅 `into` 完成、且 `resourcesRestored`、观测事件、新停止组和强线程身份与当前停点一致时才给出该结论；调用步过、跳出、取消、数据写入停点、线程创建 API 入口和旧步进票据都不产生该字段。`observedQpc` 是所有者观察到该事件的时刻，`qpcFrequency` 为其频率；该时刻不是 CPU 精确取指时刻。

显式 `quit` 或 `controller.shutdown` 会停止自动条件求值，等待原生清退。当账本确认上次释放尚未调用 `ContinueDebugEvent` 时，本次关闭最多自动重试一次。清退成功后输出 `summary`。若责任仍未解除，CLI 返回带本次请求 ID 的 `response`，保留会话，可用 `status`／`control.query` 读取状态或重新请求关闭。

写入停点使用 `--watch-write-bytes 1`、`2`、`4` 或 `8`，配合 `--export` 选择 EXE 中同宽对齐的可写数据导出。`breakpoint.watchedBytes` 给出已请求的硬件关注宽度。绑定时读取基线，收到原生写入事件后比较同一地址区间，存在实际变化时保留停点。`hit.changedByteMask` 第 0 位对应导出地址的首字节，表示本次快照与基线的差异。`hit.tid`、`threadId` 和 `threadCreationFileTime` 来自冻结的触发线程，继续后仍可核对。`enrolledAfterStop=0` 表示首次停点前已登记，大于 0 表示在相应停点之后登记。继续和关闭沿用同一原生账本。写入模式与 `--module`、`--rva`、`--condition` 互斥。

追加 `--watch-pointer-export` 后，`--export` 指定完整、8 字节对齐的 AMD64 指针数据导出，实际关注其指向的 1／2／4／8 字节私有可写区间。目标先初始化指针，对继承参数 `--ksword-breakpoint-ready HANDLE` 调用 `SetEvent`，随后从 `--ksword-breakpoint-gate HANDLE` 读取一个字节；只在收到 `'1'` 后进入业务，EOF 表示启动已取消。宿主观察实际硬件绑定为 Armed 后才写入许可。Ready 只表示目标已初始化，不代表停点已武装。此模式与直接数据导出模式分别选择，不自动等待一个未声明的动态地址。

间接绑定的 `breakpoint.siteKind` 为 `private-pointer-export`，`address` 为实际关注地址；另列 `pointerExportAddress`、`allocationBase`、`regionBase`、`regionBytes`、`regionProtection`。收到写入停点时核对指针、提交状态和区域属性；观察到改变便清退旧绑定，不静默重绑。`allocationGenerationVerified:false` 表示 Windows 区域查询不提供分配代次，不能排除同一地址在两次观察间释放后原样重用。当前仍是单个对齐硬件区间，不表示整页、任意长度、跨区范围或新分配自动传播已经完成。Qt／Light 写入停点页提供同一绑定方式选择，当前仅源码接入，桌面实测后置。

`--execute-pointer-export` 显式选择私有可执行位置。`--export` 指定 EXE 的完整、8 字节对齐 AMD64 指针数据导出，指针目的地址必须位于已提交的 `MEM_PRIVATE` EXECUTE／RX／RWX 区域。目标沿用上述 Ready／Gate 初始化协议，宿主确认实际 Armed 后放行；不修改页保护。此开关与写入模式、`--module`、`--rva`、`--cooperative-pair` 互斥。回执 `siteKind=private-execution-pointer-export`、`executePointerExport=true`，`address` 是实际 DR0 执行位置，`pointerExportAddress` 是选择器。命中表示 `execution-enter-attempt`，不能直接当作该指令已完成；显式 Into 的完成回执另行记录。指针或冻结区域属性变化时清退，不自动重绑、不确认分配代次。单目标条件、步进及 `--project` 的原生执行／内存归档入口沿用同一 owner。此新增入口目前仅源码接入，尚未构建和运行验收。

回执的 `stopGroup` 提供冻结成员的修订和散列、持有与待恢复状态、线程计数及附带集合质量。`held-complete` 表示当前合作子进程中已知的冻结成员均受本次停点覆盖。继续仍使用活 `stop` 中的 ID 和修订，已结束的组保留为历史回执。

`--condition EXPR` 在启动子进程前编译 C# 风格表达式。整数常量使用 `u64` 后缀，例如 `--condition 'stop.tid > 0u64 && stop.thread.creationFileTime > 0u64'`。条件匹配后保留真实停点及原继续令牌。结果为 `false` 或 `unknown` 时自动继续。可用字段包括 `stop.address`、`stop.exceptionCode`、`stop.firstChance`、`stop.pid`、`stop.tid`、`stop.thread.creationFileTime`，以及前文列出的完整通用寄存器和 `eflags` 字段。异常信息取决于停点快照；寄存器和创建 FILETIME 来自同一冻结停点，类型均为 `u64`。无法核验或采集失败保持未知。`status`、`control.query` 和结束回执提供表达式、判定计数及最近一次判定和释放结果。自动继续不消耗调用方的 `continue/N` 请求序号。

ActionAnalyze 不使用 Sysmon 作为数据源。原 `analyze sysmon-thread-create` 及其 `follow`、`archive`、`replay` 子命令已移除，不再查询、订阅、归档或专用回放 Sysmon 事件。旧项目文件按原样保留，可查看通用项目描述和 Stored 封装；对完整的旧 Sysmon 段执行 `archive inspect SAMPLE_ID raw ORDINAL graph` 返回 `project-unsupported`（`graphArchiveSource`），不返回证据行。

#### 进程集合活会话

`process-group session` 使用现有的精确 PID 和创建 FILETIME，以 `--confirm --disposition resume-detach` 确认本轮授权；创建时间取 `process detail basic query --pid PID --json`。仅支持 R3 的原生 AMD64 自有目标，不自动加入子进程或系统目标。配置阶段只核对并固定真实存活实例，不暂停；每次实际 Pause 再由原生所有者检查 AMD64、同用户／会话和其它原生准入条件。配置成功不代表后续附加一定获准。暂停按成员依次提交，集合状态不表示原子同时停止；查询实际 `members[].control` 与可继续的 `members[].stop`。

可选启动参数 `--project PATH [--sample UUID]` 在创建原生控制组前打开已有项目并取得项目单写租约。指定 `--sample` 时固定该项目中已有采样及其原配置快照；省略时按项目当前已提交修订新建采样。仅提供 `--sample` 而没有项目会拒绝，不在活会话中切换项目或采样。`hello.result.sampleId` 是控制组与内存读取共用的真实采样 ID；`memoryArchive` 显示项目、采样、配置修订、归档通道及可保存 capture 的身份。不提供项目时，原控制与内存读取功能保留，但保存返回 `memory-project-not-bound`。

REPL 支持 `status`／`query`、`pause group/N [all|PID:CREATION,...]`、`continue group/N PID:CREATION:GROUP_ID:STOP_ID:BACKEND_ID:SERIAL:REVISION,...`、`recover group/N`、`close`／`quit`。暂停省略选择或写 `all` 时使用配置全集；显式子集仍须提供原 PID 和创建时间。继续只提交明确列出的完整令牌，不以当前状态补齐字段。令牌的七项依次对应 `target.pid`、`target.creationFileTime`、`groupId`、`stopId`、`event.backendInstanceId`、`event.serial`、`stateRevision`。

JSONL 复用活会话包络，变更须携带 `hello.session`。`control.pause` 的 `params:{}` 选择固定全集；明确子集使用 `params:{"targets":[{"pid":1234,"creationFileTime":"134000000000000000"}]}`。`control.continue` 使用 `params:{}`，并将查询到的完整 `members[].stop` 原值放入 `expected:{"stops":[...]}`；列表可为全集或明确子集。每个令牌包含 `target:{pid,creationFileTime}`、`groupId`、`stopId`、`event:{backendInstanceId,serial}`、`stateRevision`。PID 为 JSON 无符号数，其余 64 位字段为规范正十进制字符串。

暂停和继续共享严格递增的 `requestId:"group/N"`；首个可用 ID 为 `group/1`，保留最近 128 个操作票据。格式合法并到达组层准入的 Pause／Continue 请求，即使因旧令牌、目标不符或状态不允许而拒绝，也固定原请求内容并占用 ID；纠正参数必须使用更大的新 `group/N`。相同 ID、相同动作及同顺序内容返回 `duplicate` 和原始 `operation`，同 ID 换内容返回 `conflict`，窗口外重放不会重新执行。`operation.ledgerResult`、`operation.stage`、`operation.win32Error` 保留首次准入结论，独立于顶层本次重放结论和当前集合状态。`members` 为本次独立回读，`operation.outcomes` 为原始不可变成员回执，两者可以不同；查询不产生动作票据。`control.recover` 用普通独立包络 ID、`params:{"requestId":"group/N"}` 指定原继续票据，不提交新停止令牌或新继续 ID；原 Continue 若被准入拒绝，Recover 返回原拒绝票据和 `readback-required`，不执行恢复。`control.query` 和 `controller.shutdown`／`control.close` 的 `params` 为空对象，无 `expected`。

部分失败保留成功成员的持有状态和失败回执。Continue 在释放任何成员前核验全部所选令牌，旧令牌不会释放新代次。普通暂停的继续会恢复并脱离；下一次暂停使用新的原生所有者和令牌。显式关闭先停止新动作准入，只有 `clean:true` 才输出最终结束回执；未决时保留原会话，只接受查询、按原继续 ID 恢复或再次关闭。EOF、取消或输出断开同样先清退，未决责任仍保留原所有者和项目租约；输入仍可用时继续处理 Query／Recover／Close，实际 EOF 后不凭空建立新输入或所有者。不凭旧会话 ID 在新 CLI 中接管，不承诺所有者死亡恢复。实际验收范围见[进程集合 CLI 回执](action-analyze-planning/process-group-cli.md)，本批项目绑定与显式保存仅源码接入、待验，不扩展原回执范围。

集合活会话另提供 `control.memory.snapshot`。请求必须带当前 `session`，并用普通独立请求 ID（不能使用暂停／继续专用的 `group/N`）：

```json
{"schemaVersion":1,"requestId":"memory-1","method":"control.memory.snapshot","session":{"id":"HELLO_ID","epoch":"HELLO_EPOCH"},"params":{"source":"live-read","target":{"pid":1234,"creationFileTime":"134000000000000000"},"range":{"base":"0x10000000","length":"4096"}}}
```

`source` 必须明确为 `live-read` 或 `held-event`。`target` 只能选择配置中的精确 PID／创建时间，`range.base` 接受正十进制或 `0x` 十六进制字符串，`range.length` 为正十进制字符串，单次范围最多涉及 64 页。可选 `params.sampleId` 只用于确认 `hello` 冻结的采样，传入其它采样拒绝，不能借此更换样本。`live-read` 不接受 `expected`；`held-event` 须额外提供 `expected:{"stops":[完整成员令牌]}`，数组恰好一项且目标相同。令牌必须仍是该成员完整持有事件的当前令牌；失败不会回退为实时读取。REPL 对应 `memory-snapshot live-read|held-event PID:CREATION BASE LENGTH [EXACT_STOP_TOKEN]`，令牌格式沿用上述七字段格式。

读取与 Continue／Close 在同一个串行分发线程执行，持有事件方式在读取前后回读原停点，不释放或重建停点。响应保留冻结的 `target`、`range`、`source`、`sampleId` 与读取 `trackingEpoch`；`captureId` 等于本次 `trackingEpoch`，`captureAvailable:true` 表示存在可冻结的实际读取结果。`before`／`after`、`heldAtBothChecks` 和读取状态分别呈现。`snapshot` 返回实际核验的 `capturedBytes`、逐页 `validLength`、系统读取的 `returnedBytes`、失败阶段与错误、映射、SHA-256 及 QPC 时间窗。失败页不填零，不丢弃其它成功页；没有内容时散列为空。`bytesIncluded:false` 表示响应不回显原字节；读取不自动归档。`atomicProcessSnapshot:false` 始终说明这是逐页采样，前后持有停点也不证明外部写入者被冻结。

绑定项目后，显式 `control.memory.save` 保存最近一次已输出的实际 capture。请求带当前 `session`，使用普通非 `group/N` 请求 ID，`params` 严格为 `captureId` 和 `sampleId` 两项，不接受 `expected` 或新的读取范围：

```json
{"schemaVersion":1,"requestId":"save-1","method":"control.memory.save","session":{"id":"HELLO_ID","epoch":"HELLO_EPOCH"},"params":{"captureId":"DISPLAYED_CAPTURE_UUID","sampleId":"HELLO_SAMPLE_UUID"}}
```

REPL 为 `memory-save CAPTURE_UUID SAMPLE_UUID`。两项须复制本次已显示读取结果的身份；错采样、旧 captureId 或未读取均拒绝。仅保留最近一次实际读取结果，被准入拒绝的旧令牌读取、参数草稿和 Query 不替换旧结果；成功输出下一次实际读取结果后，旧 captureId 不再可保存。输出进入有界传输队列不代表接收端 ACK；只有明确指认已输出 captureId 的保存请求才触发归档。

保存复用 `WriteProcessGroupMemorySnapshot` 向独立 `raw-memory/N` 追加，完整保留读取时的 Live／Held `readContext`、原始 before／after、失败页和实际成功字节；随后由 `MemorySnapshotReader` 回读核验。保存只消费已冻结字节，不重新读取进程、不使用现在的参数／停点覆盖历史上下文，也不隐式 Continue。同一当前 capture 重复保存返回首次成功回执，不追加第二段；响应提供项目／采样、段号、SHA-256、端点及实际字节长度。写入或回读失败后，`memoryArchive.laneBlocked:true` 阻断本会话通道续写，并保留实际写入／刷盘端点，不覆盖坏尾；启动时发现既有坏尾同样只封锁内存归档，控制与清退仍可用。离线回查／导出继续使用独立 `analyze memory read`／`export` 命令，不能把历史停点当作活控制凭据。本批新增源码尚未构建或实测。

#### 人工会话

运行 `KswordCLI.exe analyze session` 后输入 `help` 查看命令，也可用 `help capabilities` 查询单项帮助。`hello` 查看协议版本，`capabilities` 查看当前能力和限制，`quit` 关闭控制器。REPL 支持用双引号引用参数和用两个相邻的双引号表示引号内的字面双引号。背斜杠按原字面保留。命令由本端派发器解析，输入只用于该会话的命令。

以下命令在同一会话中新建项目，分别按两个已保存的修订创建采样，然后重新打开查看。创建路径应为尚不存在的专用目录。`sample status SAMPLE_ID` 可查看给定采样的冻结设置。`help project`、`help sample list` 也可在会话内使用。

```text
project create "C:\Cases\Offline Review" "First revision" "Initial scope"
sample create "First sample"
project save "Second revision" "Updated scope"
sample create "Second sample"
project close
project open "C:\Cases\Offline Review"
project status
sample list
quit
```

`project open PATH [read-only|read-write]` 接受项目目录或其中的 `project.ksaproj`，默认只读。写入已有项目时明确指定 `read-write`。当前会话只持有一个项目，打开另一个项目前先执行 `project close`。REPL 的项目身份和写入预期修订取自当前已打开的项目。需要按页查看时，使用 `sample list START GENERATION [LIMIT]` 并传回上页的 `nextStart` 与 `generation`。

#### R3 被动 ETW 会话

运行 `KswordCLI.exe analyze session --backend r3`，创建项目或按 `read-write` 打开已有项目。用 `process detail basic query --pid PID --json` 核对目标进程的创建 FILETIME。采集范围为一个明确指定的 ETW Provider 和该进程的 ETW 记录头 PID。记录头字段表示记录上下文，实际操作对象和线程实例需另有证据。

| REPL | JSONL 方法 | 参数和前提 |
| --- | --- | --- |
| `open PID CREATION_FILETIME PROVIDER_UUID [DURATION_MS] TITLE` | `session.open` | `params` 含 `projectId`、`pid`、`creationFileTime`、`providerId`、`title`，可选 `durationMs`。顶层填写 `expected.revisionId`，省略 `session`。 |
| `open PID CREATION_FILETIME api=SESSION_ID ARCHIVE authorized [DURATION_MS] TITLE` | `session.open` | 跟随显式确认授权的本地 API 归档。路径或标题包含空白时用双引号引用。JSONL 通过 `params.apiArchive` 提供路径、源会话及授权。 |
| `open PID CREATION_FILETIME api+etw=SESSION_ID ARCHIVE authorized [DURATION_MS] TITLE` | `session.open` | 在同一个新采样中跟随授权的 API 归档，并按同一 PID 和创建时间订阅 KSword 自有 ETW 提供程序。JSONL 同时提供 `apiArchive` 和 `providerId:"d4a71ada-81b0-4b15-a173-417f33bc8107"`。 |
| `status` | `session.query` | 传入 `open` 返回的顶层 `session`（`id`、`epoch`），`params:{}`。用新请求 ID 查询最新状态。 |
| `findings` | `session.findings` | 使用与 `session.query` 相同的会话包络。含 API 归档的会话只读返回已提交原包的规则累计匹配数及最近坐标（`source:"api-archive-follow"`）；纯 ETW 仍返回 `state:"not-configured"`，不代表检查后未发现。 |
| `stop` | `session.stop` | 传入顶层 `session`、`expected.stateRevision` 和 `params:{}`。停止 ETW，写入并读回核对原始段。 |
| `close` | `session.close` | 传入终态的顶层 `session`、`expected.stateRevision` 和 `params:{}`。释放会话，之后可开启新采样或关闭项目。 |

`pid` 与显式 `durationMs` 是 JSON 整数。**不传 `durationMs` 时持续记录**，无须发送查询驱动采集，回执的计划用 `durationMs:0` 表示没有期限。传入期限时沿用 1,000–120,000 毫秒的有限抓取。`creationFileTime` 和 `stateRevision` 是十进制字符串，Provider 使用不带花括号的规范小写 UUID。`session.open` 冻结本次项目修订并创建新样本。对 stop 和 close 的比较依据是上次报告的 `stateRevision`。机器会话按方法、参数、会话身份和 `expected` 去重。普通请求占满账本后，有效的停止、会话关闭和项目关闭可用预留额度。持续模式的 `session.query` 是不占累计账本的只读状态查询，调用方仍应为每条请求分配新 ID。`controller.shutdown` 可用新请求 ID 直接发起收尾。

`r3` 的 REPL 和 JSONL 均可跟随已授权的本地 WinAPI 归档。JSONL 使用 `apiArchive` 对象代替 `providerId`，提供 `path`（现有 `.jsonl` 的绝对路径）、`sessionIdentity`（非零十进制字符串）和 `authorized:true`。继续传入 `projectId`、`title`、`pid`、`creationFileTime` 和 `expected.revisionId`。可选的 `durationMs` 沿用相同范围。该来源仅提供文件与归档声明的一致性证据。`source.validatedRows` 是已校验的完整归档行数，`archive.recordedRows` 是已提交并回读的原包数，`source.coverage` 为 `unknown`。停止时固定可见文件边界，报告是否到达截止位置和未完成的尾部。 [方法契约](../schemas/action_analyze/live-etw-session.schema.json)

混采的 `source`、`archive` 和 `rules` 仍描述 API；`etw.source`、`etw.archive` 单独报告原生统计、队列丢弃与已提交水位。API 保留 `raw`，ETW 写入 `raw-etw`、`records-etw` 和 `checkpoints-etw`，两路段号和原始序号各自递增。历史 `sample status SAMPLE_ID capture ORDINAL` 一次返回该段号在两路的独立校验结果，并不表示同号段覆盖同一时间。用 `archive inspect SAMPLE_ID raw-etw ORDINAL graph` 回查已提交的混采 ETW 观察；API 仍使用 `raw`。历史 API 行可能早于 ETW 订阅，两路共同归档不证明全量覆盖、时序对齐或因果关系。ETW 只有目标实际发出该提供程序的事件时才会有观察。

被动 API 会话的 `readiness.state=attached` 对应同一冻结身份下的历史 `HooksInstalled` 声明。`observed` 对应至少一个匹配的普通 API 原包已经通过归档回读及检查点发布。`firstRaw` 给出段号、原始记录序号和源行号。`stopped-no-match` 表示正常读完停止边界且无匹配。读取或存储中断时分别报告 `source-interrupted` 和 `archive-interrupted`，保留此前发布的坐标。生产连接仍由 `source.diagnosis.producerConnection` 表示，被动来源为 `unknown`。

开始跟随时，`plan.rulePresetSet` 冻结细分预置版本。每段回读并发布检查点后，自动对本段分类线索求值。`rules` 返回累计命中、末次命中的规则 ID 和原始坐标，采集覆盖为 `unknown`。求值失败单独报告 `evaluation-failed`，此前命中和已提交原包仍可回查。停止后使用 `analyze replay-api-rules --profile by-category` 对账。

`source.state=running` 表示工作线程已提交 `ProcessTrace` 调用。`source.startupAbort` 记录快速停止时明确跳过的调用阶段。`source.tailDeliveryUnconfirmed=true` 表示无法确认收尾阶段的完整交付，采样状态为 `partial`。原生错误码、系统丢失和本地队列丢失分别报告。最多保留 512 条记录，每条最多保留 4,096 字节 ETW `UserData` 前缀。手动停止、目标退出、到达期限、输入 EOF 和输出交付失败会触发收尾。`cleanup-pending` 表示原生清退未确认，可用新的请求 ID 和当前修订重试 `session.stop`。正常 EOF 或主动退出时，如果本次仍持有部分采样，退出码为 `6`，`summary.clean` 独立报告清退状态。

R3 账本为首次停止、一次新的清退重试、关闭采样和关闭项目预留回执空间。重放原停止 ID 不会再次调用原生 API。如果重试后仍无法清退，可能没有空间继续接受新的停止 ID；应保留最后一份清退回执，不将待归档状态当作成功。

持续模式约每秒或队列达到排空阈值时封存一段，每段最多 512 条。所有段沿用同一采样、来源代次及冻结目标，刷盘读回后才发布相同段号的 `raw`、`records` 检查点。`archive.segmentOrdinal` 和 `archive.recordedObservations` 报告最近已提交段及累计已提交条数；磁盘故障会明确收尾，保留之前已提交的段。停止后封存终段；`sample status SAMPLE_ID capture ORDINAL` 或带 `captureOrdinal` 十进制字符串的 `sample.query` 逐段回读，持续档的 `finalSegment` 区分普通段与终段。显式有限抓取仍写单段。采样创建描述中的 `not-collected` 不随采集回读修改。用 `archive inspect SAMPLE_ID raw ORDINAL` 核对封装。[被动 ETW 会话 schema](../schemas/action_analyze/live-etw-session.schema.json) · [检查点 schema](../schemas/action_analyze/etw-terminal-checkpoint.schema.json)

旧的 REPL `sysmon=GUID`、JSONL `sysmonTargetGuid` 以及在本会话中直接指定 Sysmon Provider UUID 均返回 `invalid-params`，不会创建采样、启动来源或自动切换到其他来源。

#### JSONL 会话

以 `KswordCLI.exe analyze session --input jsonl --output jsonl` 启动，使用管道或文件作为 stdin、stdout 的字节流。启动选项允许的组合是 `repl/text` 和 `jsonl/jsonl`。`session` 的输出选项为 `--output`，`--json` 适用于一次性的 `capabilities`。长程客户端应保持 stdin 可写并持续读取 stdout。启动参数失败的诊断来自 stderr，会话内错误通过 stdout 的协议记录返回。

每条请求是一个对象，包含整数 `schemaVersion:1`、`requestId`、`method` 和对象 `params`。下列三行可依次发送给同一进程。协商是可选步骤，`acceptVersions` 接收 1–16 个正的 uint32 整数，含 `1` 即可协商成功。`controller.capabilities` 和 `controller.shutdown` 的 `params` 必须为空对象。

```jsonl
{"schemaVersion":1,"requestId":"q1","method":"controller.hello","params":{"acceptVersions":[1]}}
{"schemaVersion":1,"requestId":"q2","method":"controller.capabilities","params":{}}
{"schemaVersion":1,"requestId":"q3","method":"controller.shutdown","params":{}}
```

- 输入使用无 BOM 的严格 UTF-8，每行以 LF 或 CRLF 终止。正文上限为 1 MiB，容器最多 32 层（根容器计第 1 层），对象最多 128 键，数组最多 4096 项，JSON 值最多 65,536 个。`requestId` 和 `method` 各最多 128 个 UTF-8 字节且不能为空，禁止 ASCII 控制字符。重复键、浮点、溢出整数、非法 UTF-8 及未知字段会拒绝。超长行或 EOF 前的非空残帧会结束输入协议。
- 第一条 stdout 记录为 `hello`，其中包含能力。每条记录都有相同的 `controllerId` 和递增的十进制字符串 `streamSequence`。具有有效 ID 的已解码请求返回 `response`，该阶段使用 `phase:"completed"`。无法解码有效 ID 时返回 `protocolError`，其中 `requestId` 为 `null`，另有 `inputSequence` 和可用的字节偏移。成功关闭时 `summary` 为最后一条记录。每条输出正文最大 256 KiB，输出队列包含最多 16 条记录（含正在写入的记录），最早待写记录达到 5 秒上限时终止交付。
- 本进程的回执账本最多 4096 项、32 MiB，以 ID、方法、规范化参数、序列化结果和每项固定开销计费。成功查询及项目状态变更方法进入派发后的成功或失败回执都会保留。同一 `requestId`、方法和等值参数重放原回执，对象键顺序不影响等值判断。重放在当前项目和修订校验之前完成。复用已登记 ID 进行另一请求时，返回 `request-id-conflict`。账本满时返回 `request-ledger-full`，仍可重放既有回执，并为当前项目的有效 `project.close` 保留一项及 2 KiB，亦可用新 ID 直接关闭控制器。账本随进程退出而销毁。
- `quit`／`controller.shutdown` 和正常 EOF 触发收尾。Ctrl-Break 请求有序关闭，Ctrl-C 在当前无前台任务的会话中保持会话可用。调用方以最终 `summary` 确认收尾。stdout 断开或停止读取时可能收不到该记录。

| 会话退出码 | 条件 |
| --- | --- |
| `0` | 主动关闭或正常 EOF，最终 `summary` 已写出。 |
| `1` | 启动用法错误，或输入协议因超长行、EOF 残帧而终止。 |
| `3` | 流 I/O、输出交付或内部执行失败。 |
| `6` | Ctrl-Break 请求有序关闭，最终 `summary` 已写出。 |

单次请求的失败由记录中的 `error.errorId` 表达。会话退出码只表示最终会话结果。完整字段见 [A0.2 离线 CLI 协议](../schemas/action_analyze/method-contract-v1.md)。

#### 项目方法

| 方法 | `params` 字段 | REPL | `result` |
| --- | --- | --- | --- |
| `project.create` | `path`、`settings` | `project create PATH TITLE [NOTES]` | 项目信息 |
| `project.open` | `path`，可选 `access` 为 `read-only` 或 `read-write` | `project open PATH [read-only\|read-write]` | 项目信息 |
| `project.query` | `projectId` | `project status` | 项目信息及已保存的断点定义 |
| `project.save` | `projectId`、`expectedRevisionId`、`settings` | `project save TITLE [NOTES]` 或 `project save settings EXPECTED_REVISION QUOTED_JSON` | 保存后的项目信息 |
| `project.close` | `projectId` | `project close` | `projectId`、`closed:true` |
| `sample.create` | `projectId`、`expectedRevisionId`、`title` | `sample create TITLE` | 采样详情 |
| `sample.list` | `projectId`，可选 `generation`、`start`、`limit` | `sample list [START GENERATION [LIMIT]]` | `projectId`、`generation`、`start`、`sampleCount`、`nextStart`、`samples` |
| `sample.query` | `projectId`、`sampleId`，可选布尔值 `includeCapture`，启用时可选 `captureOrdinal` | `sample status SAMPLE_ID [capture [ORDINAL]]` | 采样详情，可按需核验 ETW 或被动 API 跟随归档 |
| `api.detail` | `projectId`、`sampleId`、`ordinal`、`recordSequence`，可选 `expectedSha256` | `api detail SAMPLE_ID ORDINAL RECORD_SEQUENCE [EXPECTED_SHA256]` | 同一已核验原始段中的精确 API 记录详情 |

`settings` 包含 `title` 和 `notes`。标题为 1–1024 个 UTF-8 字节。备注最多 64 KiB，可以为空，允许制表符和 LF。项目、修订及采样身份使用规范小写 UUID。`project.save` 与 `sample.create` 在写入前核对项目身份和已保存修订。身份不符返回 `project-id-mismatch`，修订过期返回 `stale-revision`。只读打开后写入返回 `project-read-only`。关闭当前项目、重新打开后使用新请求 ID 查询新快照。

`project.save` 可在完整 `settings` 中携带 `breakpointDefinitions`。字段最多 64 条，显式 `[]` 表示清空。已有定义携带 `project status` 返回的 ID 和逐项修订，新增项携带 `"breakpointDefinitionId":""` 和 `"definitionRevision":"0"`。项目写入器为新项分配 ID，保存后通过 `result.settings` 返回已提交定义。升级后的项目每次保存都要提供完整定义集合。历史采样通过 `frozenSettings` 返回创建时采用的版本。定义在项目中保存声明式配置意图。 [定义字段与约束](action-analyze-planning/project-breakpoint-definitions.md)

REPL 的完整配置写法使用 `project status` 返回的 `revisionId`。把整个 JSON 对象放入一个双引号参数，内部双引号按 REPL 规则写两次。以下示例提交空定义集合，执行前把修订 UUID 换成所选项目的基准修订。

```text
project save settings 20000000-0000-4000-8000-000000000001 "{""title"":""调查项目"",""notes"":"""",""breakpointDefinitions"":[]}"
```

项目信息包含 `projectId`、`createdUtc`、`settings`、`revisionId`、`revisionHash`、`configSemanticHash`、`generation`、`sampleCount`、`access`、`recoveredPrevious`、`primaryFailure`。列表中的采样行包含 `sampleId`、`title`、`createdUtc`、`revisionId`、`snapshotId`、`descriptionHash`、`status`。采样详情在采样行基础上还返回 `projectId`、`generation`、`frozenSettings`、`revisionHash`、`configSemanticHash`。`createdUtc` 为 FILETIME 纪元的 100ns 值。时间、计数和代次使用规范十进制字符串。

`sample.list` 默认从 `"0"` 开始，`limit` 为 1–256 的 JSON 整数，默认 256。显式 `start` 需要指定 `generation`，两者均使用规范十进制字符串。超出输出帧预算时返回放得下的完整行，`nextStart` 等于本页起点加实际返回行数。到末尾时 `nextStart` 为 `null`。代次不符返回 `stale-generation`，从新快照第一页重新查询即可。

`sample status SAMPLE_ID capture` 或 `sample.query` 的 `"includeCapture": true` 会从同一采样的首个 Stored 原始段读取 `captureArchive`。`readback-verified` 提供校验字节范围、观察条数、目标与来源摘要，以及归档中的停止原因和原生清退标志。段须通过项目、采样与配置身份、记录顺序、校验和、来源一致性及结束计数检查。读取上限为 4 MiB。`missing` 表示段未生成或找不到，`unavailable` 表示文件不可读，`limit-exceeded` 表示段超过限额，`unrecognized` 表示首条记录使用其它格式，`invalid` 表示内容或身份核对失败。采样顶层 `status` 保留创建描述。历史查询只读归档，当前活会话用 `session.query` 查询。重试读取使用新的请求 ID。

被动 API 跟随档的 `captureArchive.kind` 为 `api-archive-follow`。查询指定段时从首段开始连续核验，每次最多 128 段，每段最多 512 KiB。成功返回本段的 Stored 坐标、SHA-256、源行范围和本端终段回执。源行范围的下界 `previousSourceSequence` 为排他端点，`lastSourceSequence` 为包含端点，两者相等表示本段没有原包。`pending` 表示所需检查点尚未找到，`invalid` 表示标记或已提交端点内的内容核验失败，两种情况都携带最后连续核验的段号。无提交标记的旧跟随档报告 `legacy-unpublished`。`archive.inspect` 仍可检查原始段的封装及标记端点以外的字节。历史查询直接读项目归档，源覆盖保持 `unknown`。[API 跟随检查点](../schemas/action_analyze/api-archive-checkpoint.schema.json)

历史采样有终态检查点时，`captureArchive.checkpoint=verified` 表示两个流的 SHA-256 及精确前缀端点已复核。端点之后的尾部留给恢复流程。检查点或引用缺失时，已有检查点的采样会返回 `captureArchive.status=invalid` 及 `checkpoint=invalid`。旧项目和未发布检查点的采样仍可读取完整原始段，回执省略 `checkpoint` 字段。

#### 归档段封装检查

`archive inspect SAMPLE_ID STREAM ORDINAL [END_OFFSET]` 检查当前打开项目中的一段 Stored 归档。会话内可用 `help archive inspect`。JSONL 方法 `archive.inspect` 接收当前的 `projectId`、该项目已经登记并验证的 `sampleId`、`stream`、`ordinal`，以及可选的 `endOffset`。`stream` 只能为 `raw`、`records` 或 `control`。`ordinal` 是大于零的规范十进制 `u64` 字符串。`endOffset` 是 `"0"` 至 `"1073741824"` 的规范十进制字符串，指定段内检查范围的排他字节端点。省略时按开始检查时观测到的文件大小扫描，仍受 1 GiB 段大小限制。项目解析器只用采样、流和段号定位文件。

结果包含 `projectId`、`sampleId`、`generation`、`stream`、`ordinal`、`createdUtc100ns` 和 `framingStatus`。`framingCoverage` 提供 `requestedEndOffset`、`fileBytes`、`scanLimitBytes`、`framedBytes`、`blockCount`、`lastBlockOrdinal`、`lastSequence`。时间、偏移和计数以规范十进制字符串返回，无法确认的可选值为 `null`。`requiredRecordCount`、`unsupportedOptionalRecords` 和 `unsupportedRequiredRecords` 只统计已通过封装校验的块。`interpretedBytes` 与 `durableBytes` 均为 `null`，分别表示尚无记录正文解释和归档持久化水位证据。

`framing-complete` 表示本次检查范围通过封装校验。`truncated`、`corrupt`、`unsupported` 和 `io-error` 仍返回读到的检查结果和已验证前缀。`framingError` 为 `null` 或包含稳定的 `reason`、十进制字符串 `offset`、整数或 `null` 的 `win32Error`。例如 `identity` 指段头身份与所选段不符，`end-of-file` 指检查端点超出文件大小或可读范围未覆盖完整封装，`codec` 指当前扫描器不支持的编码。无效参数（包括流名）返回 `invalid-params`，当前项目中找不到采样返回 `project-data-not-found`，缺少所选流目录或段文件分别返回 `archive-stream-unavailable` 和 `archive-segment-unavailable`。JSONL 以相同请求 ID 和参数重放已保存的检查结果，请求错误可重试。使用新的 ID 检查当前归档字节。

#### 归档证据图

打开项目后，用 `archive inspect SAMPLE_ID raw ORDINAL graph [LIMIT [AFTER_SEQUENCE EXPECTED_SHA256]]` 读取指定段的一页证据。JSONL 使用 `archive.inspect`，参数为 `projectId`、`sampleId`、`stream:"raw"`、`ordinal` 和 `view:"graph"`。`limit` 是可选整数，范围 1–100，默认 100。`afterSequence` 默认 `"0"`。翻页时保留同一采样与段号，将 `nextAfterSequence` 和 `prefix.sha256` 分别传为 `afterSequence` 和 `expectedSha256`，并使用新的请求 ID。`nextAfterSequence:null` 表示本段没有剩余观察。前缀散列变化返回 `stale-revision`。图视图的读取端点由归档校验确定。

API 图页用 `apiInputKind` 解释 `sourceSequence`：`cooperative-pipe` 是普通包流水号，`closed-jsonl` 和 `jsonl-follow` 是文件行号，`legacy-unspecified` 表示旧档未声明。此字段只在整段或检查点核验后公布，不认证历史生产者。`archiveSource` 的原有分组保持不变；ETW 和回调图页不返回此字段。

`api detail SAMPLE_ID ORDINAL RECORD_SEQUENCE [EXPECTED_SHA256]` 精确读取 `raw` 通道中的一条 API 记录，复用图视图的来源和归档核验。段号与 `recordSequence` 使用正数十进制字符串；记录号来自 Stored 坐标，不能使用普通包流水号或 JSONL 行号替代。JSONL 方法为 `api.detail`，参数见项目方法表。返回 `record`、所选项目和采样、段号及实际前缀 `sha256`；指定 `expectedSha256` 后摘要变化返回 `stale-revision`，指定位置没有 API 记录返回 `project-data-not-found`。此命令只读历史记录。

`api.detail` 的 `record.apiMemoryLifecycle`、`archive.inspect` 图页对应行的 `apiMemoryLifecycle`、API 归档回放和普通 monitor 输出共用 AAIM1 投影。`kind` 区分 `allocate`、`protect`、`free-request`；`eventType` 区分成功分配、成功可执行保护变更、普通保护变更和释放请求的真实返回结果。字段保留原 `sourceSessionIdentity`、源 ABI、源/目标创建 FILETIME、独立有效位、输入范围、Allocate/Protect 成功后的实际输出范围、原类型/保护参数、`oldProtectionValid`、`status` 与 `returnValid`。缺有效位的值为 `null`，不会从当前进程或输入范围回填。Free 不读回输出范围，`actualReleasedRange` 和 `allocationGeneration` 保持 `null`，不因 size=0 推断整区释放；执行和因果仍未知。旧摘要或损坏 AAIM1 不产生这些结构字段，原包继续保留。

支持通过段尾计数校验的 API 导入段、通过连续检查点校验的被动 API 跟随段，以及通过双流检查点校验的 ETW 段。被动跟随读取从第 1 段校验至请求段，最多 128 段。`archiveSource` 为 `api-follow-checkpoint` 时，`finalSegment` 标记当前段是否为终段。`prefix` 标明已核验字节端点、末块、末序号和 SHA-256。每条 `observations[]` 保留来源标识、代次、原生序号及 `raw` 坐标。`recordOffset` 和 `inlineOffset` 分别指向记录头与内联数据。`tree.unresolvedCandidates` 与 `tree.contextObservations` 保存本页候选和上下文各自的 `raw.recordSequence`。`headerPid` 和 `headerTid` 是来源报头提示。实例、执行和 `finding` 为 `null`，`nodes` 与 `relations` 为空，`sourceCoverage` 为 `unknown`。`observationCount` 统计本段核验范围内的全部来源观察。损坏或缺失证据返回请求错误。[方法 schema](../schemas/action_analyze/archive-inspect-method.schema.json)

`archiveSource:"ksword-callback-batch"` 表示已核验 KSword 自有线程创建通知的完整 `raw/1`。`callbackHints` 区分通知上下文和目标 PID/TID；`notificationUtc100ns` 是归档中的原始通知采时，值为正时以十进制字符串返回，其余为 `null`，不作为线程创建时间。`sourceSequence` 是驱动源序号，`raw.recordSequence` 是归档记录号，`raw.recordOffset` 和 `raw.inlineOffset` 分别指向记录头和原包。回调只作为上下文，实例、结果和执行未知，`finalSegment` 为 `null`。该入口只读回放。

`callbackBatch` 在首页、续页和完整空批次均返回同一份批次回执。`afterSequence`、`nextSequence`、`latestSequence` 是本次源游标，`returnedCount` 包含该批未归档的非线程创建记录。`lostBeforeFirst` 是源报告的覆盖数，`droppedCount` 是环的累计丢弃数；源未报告时为 `null`。即使状态为 `caught-up`，`sourceCoverage` 仍为 `unknown`。缺失或损坏的批次返回错误，完整空批次的 `observationCount` 为 `"0"`。

#### 网络归档完整字节

用 `archive inspect SAMPLE_ID raw ORDINAL network SEQUENCE RECORD_OFFSET` 回查指定网络流。JSONL 使用 `archive.inspect` 和 `view:"network"`，传入 `projectId`、`sampleId`、`stream:"raw"`、`ordinal`、`recordSequence`、`recordOffset`。段号、序号及记录头偏移使用十进制字符串。Qt 总览详情的「文件偏移（字节）」指向记录头。查询只接受项目已登记采样，读取上限为 64 MiB。

`metadata` 保留归档的端点、方向、捕获层和各长度。`bytesHex` 包含全部已保存的内联字节，最多 65,536 字节。`verifiedBlockEnd` 是记录所在完整块的结束位置，`sourceTrust` 为 `recorded-declaration`。元数据档的 `bytesHex` 为空串。序号与偏移不对应时返回 `invalid-params`。目标块或前序块损坏时返回 `project-corrupt`。位于坏块之前的完整记录仍可读取。 [方法 schema](../schemas/action_analyze/archive-inspect-method.schema.json)

### `log`

Read bounded frames from the KswordARK log device.

日志与其他命令统一输出 UTF-8，可直接重定向到文件。日志帧先按 UTF-8 解码；旧版 ANSI 日志按系统代码页解码。默认最多读取 64 帧，`--max-frames 0` 不读取帧。

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `log` | `KswordCLI.exe log [--max-frames N]` | Read up to N log frames from the shared log device. | --max-frames defaults to 64. | No subcommand is used for the log family. |

### `process`

Inspect and control process visibility, PPL, DKOM, and cross-view state.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `process terminate` | `KswordCLI.exe process terminate --pid PID [--exit-status NTSTATUS]` | Terminate one process through the driver. | Required: --pid. Optional: --exit-status defaults to 0xC000013A. |  |
| `process suspend` | `KswordCLI.exe process suspend --pid PID` | Suspend one process. | Required: --pid. |  |
| `process resume` | `KswordCLI.exe process resume --pid PID` | 恢复已挂起的进程。 | 必填：--pid。 | 与 `process suspend` 配对；驱动优先调用 `PsResumeProcess`，不可用时尝试 `Zw/NtResumeProcess`。 |
| `process set-ppl` | `KswordCLI.exe process set-ppl --pid PID --level LEVEL` | Set the process protection level byte. | Required: --pid, --level. |  |
| `process set-integrity` | `KswordCLI.exe process set-integrity --pid PID (--rid RID \| --level untrusted\|low\|medium\|medium-plus\|high\|system) [--flags 0xN] [--confirm]` | Set a process mandatory integrity label through R0. | Required: --pid and one integrity selector. Optional: --flags, --confirm. | Uses `IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY`. |
| `process inject-dll` | `KswordCLI.exe process inject-dll --pid PID --dll PATH [--flags 0xN] [--wait-thread] --confirm` | Inject a DLL path through the R0 process injection protocol. | Required: --pid, --dll, --confirm. Optional: --flags, --wait-thread. | Uses `IOCTL_KSWORD_ARK_INJECT_PROCESS` with `LoadLibraryW`. |
| `process inject-shellcode` | `KswordCLI.exe process inject-shellcode --pid PID --blob PATH [--flags 0xN] --confirm` | Inject a raw shellcode blob through the R0 process injection protocol. | Required: --pid, --blob, --confirm. Optional: --flags. | Uses `IOCTL_KSWORD_ARK_INJECT_PROCESS`; payload is capped by shared protocol. |
| `process enum` | `KswordCLI.exe process enum [--flags 0xN] [--start-pid PID] [--end-pid PID] [--limit N]` | Enumerate processes from R0 evidence. | Optional: --flags, --start-pid, --end-pid, --limit. |  |
| `process set-visibility` | `KswordCLI.exe process set-visibility --action ACTION [--pid PID] [--flags 0xN]` | Apply a process visibility action. | Required: --action. Optional: --pid defaults to 0, --flags. |  |
| `process set-special-flags` | `KswordCLI.exe process set-special-flags --pid PID --action ACTION [--flags 0xN]` | Apply special process flags. | Required: --pid, --action. Optional: --flags. |  |
| `process dkom` | `KswordCLI.exe process dkom --pid PID [--action ACTION] [--flags 0xN]` | Run the configured process DKOM action. | Required: --pid. Optional: --action, --flags. |  |
| `process crossview` | `KswordCLI.exe process crossview [--flags 0xN] [--start-pid PID] [--end-pid PID] [--max-nodes N] [--limit N] [--json]` | Compare process evidence across supported sources. | Optional: --flags, --start-pid, --end-pid, --max-nodes, --limit, --json. | Anomaly flags are raw candidates; missing sources make comparisons incomplete. See source states and DynData diagnostics. |
| `process detail` | `KswordCLI.exe process detail --pid PID [--flags 0xN]` | Query fixed R0 EPROCESS runtime detail. | Required: --pid. Optional: --flags defaults to include-all. | Uses `IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL`. |
| `process runtime-fields` | `KswordCLI.exe process runtime-fields --pid PID --items id:offset:size[:flags][,id:offset:size[:flags]...] [--flags 0xN] [--hexdump] [--limit N]` | Sample bounded EPROCESS runtime fields by checked offsets. | Required: --pid, --items. Optional: --flags, --hexdump, --limit. | Uses `IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS`; each sample is capped by the shared protocol. |

### `memory`

Query, read, write, translate, and audit virtual/physical memory.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `memory query-va` | `KswordCLI.exe memory query-va --pid PID --address VA [--flags 0xN]` | Query virtual memory metadata for one address. | Required: --pid, --address. Optional: --flags. |  |
| `memory read-va` | `KswordCLI.exe memory read-va --pid PID --address VA --bytes N [--flags 0xN] [--hexdump]` | Read virtual memory bytes. | Required: --pid, --address, --bytes. Optional: --flags, --hexdump. | With the kernel-address read flag, --pid may be omitted. |
| `memory write-va` | `KswordCLI.exe memory write-va --pid PID --address VA (--hex HEX \| --data-file PATH) [--flags 0xN]` | Write virtual memory bytes. | Required: --pid, --address, and exactly one payload option. Optional: --flags. | With the kernel-address write flag, --pid may be omitted. |
| `memory read-phys` | `KswordCLI.exe memory read-phys --address PA --bytes N [--hexdump]` | Read physical memory bytes. | Required: --address, --bytes. Optional: --hexdump. |  |
| `memory write-phys` | `KswordCLI.exe memory write-phys --address PA (--hex HEX \| --data-file PATH) [--flags 0xN]` | Write physical memory bytes. | Required: --address and exactly one payload option. Optional: --flags. |  |
| `memory translate-va` | `KswordCLI.exe memory translate-va --pid PID --address VA [--flags 0xN]` | Translate a virtual address to page-table evidence. | Required: --pid, --address. Optional: --flags. |  |
| `memory query-pte` | `KswordCLI.exe memory query-pte --pid PID --address VA [--flags 0xN]` | Query page-table entries for one virtual address. | Required: --pid, --address. Optional: --flags. |  |
| `memory enum-vad` | `KswordCLI.exe memory enum-vad --pid PID [--start VA] [--end VA] [--cursor-vpn VPN] [--max-entries N] [--flags 0xN] [--limit N]` | Enumerate the target process VAD tree as an independent region view. | Required: --pid. Optional: --start, --end, --cursor-vpn, --max-entries, --flags, --limit. | Backed by IOCTL_KSWORD_ARK_ENUMERATE_PROCESS_VAD; profileVerified=0 means the DynData VadRoot offset is not validated for this build and the result cannot support absence inference. |
| `memory scan-exec-pte` | `KswordCLI.exe memory scan-exec-pte --pid PID [--start VA] [--end VA] [--cursor VA] [--max-entries N] [--max-table-reads N] [--flags 0xN] [--limit N]` | Scan the target process page tables for user-space executable leaves. | Required: --pid. Optional: --start, --end, --cursor, --max-entries, --max-table-reads, --flags, --limit. | Backed by IOCTL_KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE; reports what the processor treats as executable, independent of VAD protection. |
| `memory read-section-pages` | `KswordCLI.exe memory read-section-pages --pid PID --start VA --end VA [--cursor VA] [--max-pages N] [--flags 0xN] [--limit N]` | Read the image section object's clean reference pages for a mapped range. | Required: --pid, --start, --end. Optional: --cursor, --max-pages, --flags, --limit. | Backed by IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES; a second reference source independent of the file on disk. Only prototype PTEs in the architectural valid form are resolved - transition and pagefile encodings are version specific and are reported as not resident rather than decoded, and pages are never faulted in. Set --flags 0x1 to also return the page bytes. |
| `memory scan-kexec` | `KswordCLI.exe memory scan-kexec [--flags 0xN] [--max-entries N] [--start VA] [--end VA] [--limit N]` | Scan executable kernel memory evidence. | Optional: --flags, --max-entries, --start, --end, --limit. |  |
| `memory scan-evidence` | `KswordCLI.exe memory scan-evidence [--flags 0xN] [--max-rows N] [--start VA] [--end VA] [--max-bytes N] [--max-bigpool-rows N] [--sample-bytes N] [--limit N]` | Scan kernel memory evidence rows. | Optional: --flags, --max-rows, --start, --end, --max-bytes, --max-bigpool-rows, --sample-bytes, --limit. |  |
| `memory change-mapped-protection` | `KswordCLI.exe memory change-mapped-protection --address VA [--protection 0xN] [--flags 0xN]` | MDL-based page protection change (HVCI research). | Required: --address. Optional: --protection (default PAGE_READWRITE=0x04), --flags (0x1=write test). | Returns per-stage NTSTATUS; exit code 1 if a required/requested stage fails or remains pending, and 4 for an incompatible response. Unrequested stages do not cause failure. |
| `memory change-image-protection` | `KswordCLI.exe memory change-image-protection --address VA [--operation N] [--flags 0xN] [--func-addr VA]` | MmChangeImageProtection on kernel image page (HVCI research). | Required: --address. Optional: --operation (1=RX, 2=READONLY_NX, default 2), --flags (0x1=write test, 0x2=restore), --func-addr (manual MmChangeImageProtection VA). | Returns per-stage NTSTATUS; exit code 1 if a required/requested stage fails or remains pending, and 4 for an incompatible response. Unrequested stages do not cause failure. |

### `file`

Inspect files, filters, storage evidence, and file-monitor runtime state.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `file delete-path` | `KswordCLI.exe file delete-path --path PATH [--flags 0xN]` | Delete one path through the driver. | Required: --path. Optional: --flags. |  |
| `file query-info` | `KswordCLI.exe file query-info --path PATH [--flags 0xN]` | Query file object and basic file metadata. | Required: --path. Optional: --flags. | Accepts Win32, UNC and native NT paths. |
| `file set-integrity` | `KswordCLI.exe file set-integrity --path PATH (--rid RID \| --level untrusted\|low\|medium\|medium-plus\|high\|system) [--directory] [--flags 0xN] [--confirm]` | Set a file or directory mandatory integrity label through R0. | Required: --path and one integrity selector. Optional: --directory, --flags, --confirm. | Win32/UNC paths are normalized to driver NT paths before `IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY`. |
| `file fileobject` | `KswordCLI.exe file fileobject --path PATH [--flags 0xN]` | Alias for file query-info. | Required: --path. Optional: --flags. | Accepts Win32, UNC and native NT paths; prints an alias banner. |
| `file minifilter` | `KswordCLI.exe file minifilter [--flags 0xN] [--max-rows N] [--limit N]` | Enumerate minifilter inventory rows. | Optional: --flags, --max-rows, --limit. |  |
| `file section` | `KswordCLI.exe file section --path PATH [--flags 0xN] [--max-mappings N] [--limit N]` | Alias for section query-file-mappings. | Required: --path. Optional: --flags, --max-mappings, --limit. | Uses the same read-only protocol and unverified mapping evidence semantics. |
| `file bitlocker` | `KswordCLI.exe file bitlocker [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]` | Query BitLocker/FVE storage audit rows. | Optional: --flags, --max-rows, --max-depth, --volume, --limit. | Volume accepts a drive such as C: or an NT device path. |
| `file storage` | `KswordCLI.exe file storage [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]` | Query volume stack audit rows. | Optional: --flags, --max-rows, --max-depth, --volume, --limit. | Volume accepts a drive such as C: or an NT device path. |
| `file mountmgr` | `KswordCLI.exe file mountmgr [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]` | Query MountMgr mapping audit rows. | Optional: --flags, --max-rows, --max-depth, --volume, --limit. | Volume accepts a drive such as C: or an NT device path. |
| `file filesystem` | `KswordCLI.exe file filesystem [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]` | Query filesystem integrity audit rows. | Optional: --flags, --max-rows, --max-depth, --volume, --limit. | Volume accepts a drive such as C: or an NT device path. |
| `file monitor-control` | `KswordCLI.exe file monitor-control --action ACTION [--operation-mask 0xN] [--pid PID] [--flags 0xN]` | Control file monitor runtime state. | Required: --action. Optional: --operation-mask, --pid, --flags. |  |
| `file monitor-drain` | `KswordCLI.exe file monitor-drain [--max-events N] [--flags 0xN]` | Drain file monitor events. | Optional: --max-events, --flags. |  |
| `file monitor-status` | `KswordCLI.exe file monitor-status` | Query file monitor runtime status. | No options. |  |

### `kernel`

Inspect SSDT, hooks, driver objects, CPU, physical layout, CID, and IPC state.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `kernel ssdt` | `KswordCLI.exe kernel ssdt [--flags 0xN] [--limit N]` | Inspect export-derived SSDT entries. | Optional: --flags, --limit. | Totals count matching exports, not all table entries. Missing service targets return 5 (unavailable) or 6 (partial); no hook verdict is made. |
| `kernel shadow-ssdt` | `KswordCLI.exe kernel shadow-ssdt [--flags 0xN] [--limit N]` | Inspect export-derived shadow SSDT entries. | Optional: --flags, --limit. | Totals count matching exports, not all table entries. Missing service targets return 5 (unavailable) or 6 (partial); no hook verdict is made. |
| `kernel scan-inline-hooks` | `KswordCLI.exe kernel scan-inline-hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]` | Scan inline hook evidence. | Optional: --flags, --max-entries, --module, --limit. |  |
| `kernel enum-iat-eat-hooks` | `KswordCLI.exe kernel enum-iat-eat-hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]` | Enumerate IAT/EAT hook evidence. | Optional: --flags, --max-entries, --module, --limit. |  |
| `kernel patch-inline-hook` | `KswordCLI.exe kernel patch-inline-hook --mode MODE --function VA (--expected-hex HEX \| --expected-file PATH) [--restore-hex HEX \| --restore-file PATH] [--flags 0xN]` | Patch or restore an inline hook using bounded byte evidence. | Required: --mode, --function, and expected payload. Optional: restore payload, --flags. | Hex and file payload forms are mutually exclusive per payload. |
| `kernel rxpf-atomic-commit` | `KswordCLI.exe kernel rxpf-atomic-commit --address VA --offset N --hex HEX --confirm [--json]` | Run the existing RXPF register, change, write and unregister sequence in one IOCTL. | Required: --address kernel VA in a loaded image, --offset page offset, --hex payload bytes (1..64), --confirm. Optional: --json. | One IOCTL reduces user-mode round trips but does not isolate other CPUs from the temporary NX state. No backup is retained for later rollback; the caller remains responsible for restoration. Exit 0 requires a successful reported restore status. |
| `kernel rxpf-exec-proof` | `KswordCLI.exe kernel rxpf-exec-proof --hex HEX --expected 0xN --confirm [--json]` | Test the existing driver-owned page emulation path with one inline worker. | Required: --hex payload bytes (1..64), --expected return value, --confirm. Optional: --json. | The Microsoft Hv preflight may report unsupported. Exit 0 requires the expected RAX and a nonzero managed fault count; it does not prove native execution of modified external image code. |
| `kernel query-driver-object` | `KswordCLI.exe kernel query-driver-object --driver NAME [--flags 0xN] [--max-devices N] [--max-attached N] [--limit N]` | Query one DriverObject and device chain. | Required: --driver. Optional: --flags, --max-devices, --max-attached, --limit. |  |
| `kernel query-driver-integrity` | `KswordCLI.exe kernel query-driver-integrity [--driver NAME] [--module-base VA] [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--limit N]` | Query driver integrity evidence rows. | Optional: --driver, --module-base, --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --limit. |  |
| `kernel force-unload-driver` | `KswordCLI.exe kernel force-unload-driver --driver NAME [--module-base VA] [--timeout-ms N] [--flags 0xN]` | Force an unload path for one driver. | Required: --driver. Optional: --module-base, --timeout-ms, --flags. | Exit 0 requires UNLOADED; routine-called/cleanup-only returns 6 and queries DriverObject presence. Print requested/effective flags and preflight evidence; detailed step statuses are in driver log. |
| `kernel query-cpu` | `KswordCLI.exe kernel query-cpu` | Query CPU hardware summary. | No options. |  |
| `kernel query-phys-layout` | `KswordCLI.exe kernel query-phys-layout` | Query physical memory layout summary. | No options. |  |
| `kernel cid` | `KswordCLI.exe kernel cid [--flags 0xN] [--max-entries N] [--max-visits N] [--start-cid CID] [--end-cid CID] [--limit N]` | Enumerate CID table evidence. | Optional: --flags, --max-entries, --max-visits, --start-cid, --end-cid, --limit. |  |
| `kernel object-summary` | `KswordCLI.exe kernel object-summary --target-kind KIND [--cid CID] [--object ADDRESS] [--flags 0xN]` | Query object header/type/counter summary for CID or object evidence. | Required: --target-kind. Optional: --cid, --object, --flags. | Uses `IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY`. |
| `kernel ipc` | `KswordCLI.exe kernel ipc [--flags 0xN] [--pid PID] [--handle HANDLE] [--max-entries N]` | Query IPC summary for a process/handle context. | Optional: --flags, --pid, --handle, --max-entries. |  |
| `kernel callbacks` | `KswordCLI.exe kernel callbacks [--flags 0xN] [--max-entries N] [--limit N]` | Alias for callback inventory. | Optional: --flags, --max-entries, --limit. | Uses callback protocol v3 snapshot validation. |
| `kernel hooks` | `KswordCLI.exe kernel hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]` | Alias-style inline hook scan. | Optional: --flags, --max-entries, --module, --limit. |  |

### `callback`

Manage callback rules, pending decisions, callback inventory, and bypass PIDs.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `callback set-rules` | `KswordCLI.exe callback set-rules --blob PATH` | Load callback rule bytes. | Required: --blob. |  |
| `callback runtime-state` | `KswordCLI.exe callback runtime-state` | Query callback runtime state. | No options. |  |
| `callback monitor-start` | `KswordCLI.exe callback monitor-start [--categories LIST]` | 按具名类别启动 Callback Monitor 采集。 | 可选：--categories，逗号分隔 `process,thread,image,registry,object,minifilter,core,all`，默认 `core`。 | `IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL`；`core` 是前五类，`minifilter` 高频且须显式启用。 |
| `callback monitor-stop` | `KswordCLI.exe callback monitor-stop` | 停止 Callback Monitor 采集，不改变既有回调规则。 | 无。 | `IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL`。 |
| `callback monitor-status` | `KswordCLI.exe callback monitor-status` | 查询 Callback Monitor 采集状态和环形缓冲区计数器。 | 无。 | `IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY`；旧驱动会显示 unsupported。 |
| `callback monitor-read` | `KswordCLI.exe callback monitor-read [--after-sequence N] [--max-records N] [--limit N]` | 使用独立游标读取 Callback Monitor 事件。 | 可选：--after-sequence、--max-records、--limit。 | `IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ`；使用输出的 `next_sequence` 发起增量读取。 |
| `callback wait-event` | `KswordCLI.exe callback wait-event [--waiter-tag N]` | Wait for one callback event packet. | Optional: --waiter-tag. |  |
| `callback answer-event` | `KswordCLI.exe callback answer-event --event-guid GUID --decision N --source-session-id N [--answered-at UTC100NS]` | Answer one pending callback event. | Required: --event-guid, --decision, --source-session-id. Optional: --answered-at. |  |
| `callback cancel-pending` | `KswordCLI.exe callback cancel-pending` | Cancel all pending callback decisions. | No options. |  |
| `callback remove` | `KswordCLI.exe callback remove --class CLASS --callback VA [--flags 0xN] --confirm` | Remove a callback through an address-based public API path. | Required: --class, --callback, --confirm. Object, Registry, and ETW classes are not supported by this legacy command. | CLASS accepts a removal type number or name. |
| `callback remove-ex` | `KswordCLI.exe callback remove-ex --class CLASS --callback VA [--registration VA] [--raw-storage VA] [--generation N] [--identity-hash N] [--source N] [--operation-mask 0xN] [--object-type-mask 0xN] [--trust-flags 0xN] [--remove-behavior N] [--flags 0xN] --confirm` | Remove an external callback with extended row identity. | Use the complete V3 row identity. Registry requires a calibrated cookie; ETW removal is unsupported. | CLASS accepts a removal type number or name. |
| `callback remove-row` | `KswordCLI.exe callback remove-row --identity-hash N --confirm [--json]` | Re-enumerate and remove a uniquely identified current row. | Required: --identity-hash, --confirm. Optional: --json. | Minifilter child removal unloads its entire owning filter; thread/image/WFP may use legacy public API removal. |
| `callback set-minifilter-bypass-pids` | `KswordCLI.exe callback set-minifilter-bypass-pids --pids PID[,PID...] [--flags 0xN]` | Set minifilter bypass PID list. | Required: --pids. Optional: --flags. |  |
| `callback query-minifilter-bypass-pids` | `KswordCLI.exe callback query-minifilter-bypass-pids` | Query minifilter bypass PID list. | No options. |  |
| `callback enum` | `KswordCLI.exe callback enum [--flags 0xN] [--max-entries N] [--limit N] [--json]` | Enumerate callback inventory. | Optional: --flags, --max-entries, --limit, --json. | Includes row identity, trustFlags and removeBehavior; enum and removal class numbers differ. |

### `dyn`

Query or apply dynamic kernel symbol/profile data.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `dyn status` | `KswordCLI.exe dyn status` | Query DynData status. | No options. |  |
| `dyn fields` | `KswordCLI.exe dyn fields [--limit N]` | List DynData fields. | Optional: --limit. |  |
| `dyn capabilities` | `KswordCLI.exe dyn capabilities` | Query DynData capability mask. | No options. |  |
| `dyn profile` | `KswordCLI.exe dyn profile [--limit N]` | List v4 DynData module profile rows. | Optional: --limit. | Alias: dyn v4-modules. |
| `dyn v4-modules` | `KswordCLI.exe dyn v4-modules [--limit N]` | List v4 DynData module profile rows. | Optional: --limit. | Alias: dyn profile. |
| `dyn v4-capabilities` | `KswordCLI.exe dyn v4-capabilities [--limit N]` | List v4 DynData capability groups. | Optional: --limit. | Alias: dyn capability-groups. |
| `dyn capability-groups` | `KswordCLI.exe dyn capability-groups [--limit N]` | List v4 DynData capability groups. | Optional: --limit. | Alias: dyn v4-capabilities. |
| `dyn v4-missing` | `KswordCLI.exe dyn v4-missing [--limit N]` | List missing v4 DynData items. | Optional: --limit. | Alias: dyn missing-items. |
| `dyn missing-items` | `KswordCLI.exe dyn missing-items [--limit N]` | List missing v4 DynData items. | Optional: --limit. | Alias: dyn v4-missing. |
| `dyn v4-items` | `KswordCLI.exe dyn v4-items [--limit N]` | List every applied v4 DynData item status row. | Optional: --limit. | Uses `IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS`. |
| `dyn apply-profile-v4` | `KswordCLI.exe dyn apply-profile-v4 --blob PATH` | Apply a raw v4 DynData profile packet. | Required: --blob. |  |
| `dyn apply-profile` | `KswordCLI.exe dyn apply-profile --blob PATH` | Apply a raw legacy DynData profile packet. | Required: --blob. |  |
| `dyn apply-profile-ex` | `KswordCLI.exe dyn apply-profile-ex --blob PATH` | Apply a raw extended DynData profile packet. | Required: --blob. |  |

### `thread`

Enumerate threads and compare R0/R3 thread evidence.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `thread enum` | `KswordCLI.exe thread enum [--flags 0xN] [--pid PID] [--limit N]` | Enumerate threads. | Optional: --flags, --pid, --limit. |  |
| `thread crossview` | `KswordCLI.exe thread crossview [--flags 0xN] [--pid PID] [--start-tid TID] [--end-tid TID] [--max-nodes N] [--limit N] [--json]` | Compare thread evidence across supported sources. | Optional: --flags, --pid, --start-tid, --end-tid, --max-nodes, --limit, --json. | Anomaly flags are raw candidates; missing sources make comparisons incomplete. See source states and DynData diagnostics. |
| `thread detail` | `KswordCLI.exe thread detail --tid TID [--pid PID] [--flags 0xN]` | Query fixed R0 ETHREAD/KTHREAD runtime detail. | Required: --tid. Optional: --pid, --flags defaults to include-all. | Uses `IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL`. |
| `thread runtime-fields` | `KswordCLI.exe thread runtime-fields --tid TID [--pid PID] --items id:offset:size[:flags][,id:offset:size[:flags]...] [--flags 0xN] [--hexdump] [--limit N]` | Sample bounded ETHREAD/KTHREAD runtime fields by checked offsets. | Required: --tid, --items. Optional: --pid, --flags, --hexdump, --limit. | Uses `IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS`; each sample is capped by the shared protocol. |

### `handle`

Enumerate process handles and inspect object metadata.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `handle enum` | `KswordCLI.exe handle enum --pid PID [--flags 0xN] [--limit N]` | Enumerate handles in one process. | Required: --pid. Optional: --flags, --limit. | Alias: handle object-table. |
| `handle object-table` | `KswordCLI.exe handle object-table --pid PID [--flags 0xN] [--limit N]` | Enumerate handles in one process. | Required: --pid. Optional: --flags, --limit. | Alias: handle enum. |
| `handle query-object` | `KswordCLI.exe handle query-object --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]` | Query one handle object. | Required: --pid, --handle. Optional: --access, --flags. | Aliases: handle object-header, handle type-matrix. |
| `handle object-header` | `KswordCLI.exe handle object-header --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]` | Query one handle object header projection. | Required: --pid, --handle. Optional: --access, --flags. | Alias: handle query-object. |
| `handle type-matrix` | `KswordCLI.exe handle type-matrix --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]` | Query one handle object type projection. | Required: --pid, --handle. Optional: --access, --flags. | Alias: handle query-object. |

### `driver`

`major` 和 `fastio` 共用 `device` 审计请求。输出先明确 `alias: driver major -> driver device` 或 `alias: driver fastio -> driver device`，不可用诊断保留用户输入的别名。

Driver integrity, device stack, and optional global evidence aliases.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `driver integrity` | `KswordCLI.exe driver integrity [--driver NAME] [--module-base VA] [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--limit N]` | Query driver integrity evidence. | Optional: --driver, --module-base, --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --limit. |  |
| `driver detail` | `KswordCLI.exe driver detail --driver NAME [--flags 0xN] [--max-devices N] [--max-attached N] [--limit N]` | Query one DriverObject detail projection. | Required: --driver. Optional: --flags, --max-devices, --max-attached, --limit. |  |
| `driver device` | `KswordCLI.exe driver device [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Query driver device stack audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Aliases: driver major, driver fastio. |
| `driver major` | `KswordCLI.exe driver major [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Alias for driver device audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: driver device. |
| `driver fastio` | `KswordCLI.exe driver fastio [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Alias for driver device audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: driver device. |
| `driver unloaded` | `KswordCLI.exe driver unloaded [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--module-base VA] [--limit N]` | Project MmUnloadedDrivers optional-global evidence. | Optional: --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --module-base, --limit. |  |
| `driver piddb` | `KswordCLI.exe driver piddb [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--module-base VA] [--limit N]` | Project PiDDBCacheTable optional-global evidence. | Optional: --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --module-base, --limit. |  |

### `hardware`

Device, input, USB, and PnP stack audit views.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `hardware audit` | `KswordCLI.exe hardware audit [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Query generic hardware device stack audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: hardware pnp. |
| `hardware pnp` | `KswordCLI.exe hardware pnp [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Alias for hardware audit. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: hardware audit. |
| `hardware input` | `KswordCLI.exe hardware input [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Query input stack audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. |  |
| `hardware usb` | `KswordCLI.exe hardware usb [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Query USB topology audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. |  |

### `hwid`

HWID Dispatch query and guarded control operations.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `hwid dispatch-query` | `KswordCLI.exe hwid dispatch-query` | Query HWID Dispatch hook state. | No options. | Uses `IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY`. |
| `hwid dispatch-control` | `KswordCLI.exe hwid dispatch-control --action query\|enable\|disable\|disable-all [--targets LIST] [--dry-run] [--flags 0xN] [--disk-mode custom\|random\|null] [--mac-mode random\|custom] [--disk-serial TEXT] [--disk-product TEXT] [--disk-revision TEXT] [--gpu-serial TEXT] [--permanent-mac TEXT] [--current-mac TEXT] --confirm` | Control HWID Dispatch hook targets with explicit confirmation. | Required: --action; --confirm is required for non-query actions. Optional: targets/profile/dry-run/flags. | Targets: disk, partmgr, mountmgr, nvidia, nsiproxy, storage, network, all. Uses `IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL`. |

### `window`

Win32k, GUI, GPU, display, and watchdog audit views.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `window win32k` | `KswordCLI.exe window win32k [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]` | Query win32k profile/session status. | Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit. |  |
| `window gui` | `KswordCLI.exe window gui [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]` | Query GUI window snapshot rows. | Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit. |  |
| `window gui-threads` | `KswordCLI.exe window gui-threads [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]` | Query GUI thread snapshot rows. | Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit. |  |
| `window hotkeys-pdb` | `KswordCLI.exe window hotkeys-pdb [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]` | Query PDB-backed win32k hotkey chain rows. | Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit. | Uses `IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB`. |
| `window hooks-pdb` | `KswordCLI.exe window hooks-pdb [--flags 0xN] [--match legacy\|owner\|target\|both] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]` | Query PDB-backed win32k hook chain rows. | Optional: --flags (default 0x3), --match (overrides only owner/target selector bits in --flags; default legacy), --session-id, --pid, --tid, --max-entries (default 4096; hard maximum 8192), --limit. | Uses `IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB`; legacy/both require the complete Session/PID/TID filter to match one side; prints the effective mode and traversal diagnostics. |
| `window detail` | `KswordCLI.exe window detail --hwnd HWND [--pid PID] [--tid TID] [--flags 0xN]` | Query one HWND/tagWND runtime detail packet. | Required: --hwnd. Optional: --pid, --tid, --flags. | Uses `IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL`. |
| `window gpu` | `KswordCLI.exe window gpu [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Query GPU/display/watchdog audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Aliases: window display, window watchdog. |
| `window display` | `KswordCLI.exe window display [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Alias for window gpu audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: window gpu. |
| `window watchdog` | `KswordCLI.exe window watchdog [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]` | Alias for window gpu audit rows. | Optional: --profile-flags, --max-rows, --max-attached, --target, --limit. | Alias: window gpu. |

### `misc`

Security, CI/VBS, Hyper-V, AppLocker/BAM, and driver trust posture.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `misc security` | `KswordCLI.exe misc security [--flags 0xN]` | Query security/CI/VBS posture. | Optional: --flags. | Aliases: misc ci, misc vbs. |
| `misc ci` | `KswordCLI.exe misc ci [--flags 0xN]` | Alias for misc security. | Optional: --flags. | Alias: misc security. |
| `misc vbs` | `KswordCLI.exe misc vbs [--flags 0xN]` | Alias for misc security. | Optional: --flags. | Alias: misc security. |
| `misc hyperv` | `KswordCLI.exe misc hyperv` | Query Hyper-V summary posture. | No options. |  |
| `misc applocker` | `KswordCLI.exe misc applocker` | Query AppLocker/BAM posture. | No options. | Alias: misc bam. |
| `misc bam` | `KswordCLI.exe misc bam` | Alias for misc applocker. | No options. | Alias: misc applocker. |
| `misc driver-trust` | `KswordCLI.exe misc driver-trust [--flags 0xN] [--max-entries N] [--limit N]` | Query loaded-driver trust rows. | Optional: --flags, --max-entries, --limit. |  |

### `alpc`

ALPC port diagnostics for a process handle.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `alpc query-port` | `KswordCLI.exe alpc query-port --pid PID --handle HANDLE [--flags 0xN]` | Query ALPC port information for one handle. | Required: --pid, --handle. Optional: --flags. |  |

### `section`

Process and file section mapping diagnostics.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `section query-process` | `KswordCLI.exe section query-process --pid PID [--flags 0xN] [--max-mappings N] [--limit N]` | Query section mappings for one process. | Required: --pid. Optional: --flags, --max-mappings, --limit. |  |
| `section query-file-mappings` | `KswordCLI.exe section query-file-mappings --path PATH [--flags 0xN] [--max-mappings N] [--limit N]` | Query section mappings for one file path. | Required: --path. Optional: --flags, --max-mappings, --limit. |  |

### `trust`

Image trust and signing diagnostics.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `trust query-image` | `KswordCLI.exe trust query-image --path PATH [--flags 0xN]` | Query image trust and signing evidence. | Required: --path. Optional: --flags. |  |

### `safety`

Safety policy query and update controls.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `safety query-policy` | `KswordCLI.exe safety query-policy [--flags 0xN]` | Query safety policy state. | Optional: --flags. |  |
| `safety set-policy` | `KswordCLI.exe safety set-policy [--set-flags 0xN] [--clear-flags 0xN] [--expected-generation N]` | Update safety policy flags. | Optional: --set-flags, --clear-flags, --expected-generation. |  |

### `preflight`

Release-readiness and driver capability preflight checks.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `preflight query` | `KswordCLI.exe preflight query [--flags 0xN] [--limit N]` | Run release-readiness preflight checks. | Optional: --flags, --limit. |  |

### `registry`

Registry read, enumeration, and mutation helpers.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `registry read-value` | `KswordCLI.exe registry read-value --key KEY [--value NAME] [--max-data-bytes N] [--flags 0xN] [--hexdump]` | Read one registry value or default value. | Required: --key. Optional: --value, --max-data-bytes, --flags, --hexdump. |  |
| `registry enum-key` | `KswordCLI.exe registry enum-key --key KEY [--flags 0xN] [--max-subkeys N] [--max-values N] [--max-value-data-bytes N] [--limit N]` | Enumerate registry subkeys and values. | Required: --key. Optional: --flags, --max-subkeys, --max-values, --max-value-data-bytes, --limit. |  |
| `registry set-value` | `KswordCLI.exe registry set-value --key KEY --type TYPE --data-file PATH [--value NAME] [--flags 0xN]` | Set one registry value. | Required: --key, --type, --data-file. Optional: --value, --flags. |  |
| `registry delete-value` | `KswordCLI.exe registry delete-value --key KEY [--value NAME] [--flags 0xN]` | Delete one registry value or default value. | Required: --key. Optional: --value, --flags. |  |
| `registry create-key` | `KswordCLI.exe registry create-key --key KEY [--flags 0xN]` | Create one registry key. | Required: --key. Optional: --flags. |  |
| `registry delete-key` | `KswordCLI.exe registry delete-key --key KEY [--flags 0xN]` | Delete one registry key. | Required: --key. Optional: --flags. |  |
| `registry rename-value` | `KswordCLI.exe registry rename-value --key KEY --old-value NAME --new-value NAME [--flags 0xN]` | Rename one registry value. | Required: --key, --old-value, --new-value. Optional: --flags. |  |
| `registry rename-key` | `KswordCLI.exe registry rename-key --key KEY --new-name NAME [--flags 0xN]` | Rename one registry key. | Required: --key, --new-name. Optional: --flags. |  |

### `redirect`

File/registry redirect rules and runtime status.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `redirect set-rules` | `KswordCLI.exe redirect set-rules --blob PATH` | Load file/registry redirect rules. | Required: --blob. |  |
| `redirect query-status` | `KswordCLI.exe redirect query-status [--limit N]` | Query redirect runtime state and rules. | Optional: --limit. |  |

### `network`

Network rules, endpoints, WFP/NDIS evidence, and R3 fallbacks.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `network set-rules` | `KswordCLI.exe network set-rules --blob PATH` | Load network rule bytes. | Required: --blob. |  |
| `network query-status` | `KswordCLI.exe network query-status [--limit N]` | Query network runtime state and rules. | Optional: --limit. |  |
| `network managed-policies` | `KswordCLI.exe network managed-policies [--limit N]` | Read managed R0 host and process-instance network policies. | Optional: --limit (default 16; 0 prints summary only). | Read-only. Backed by `IOCTL_KSWORD_ARK_NETWORK_QUERY_MANAGED_POLICIES`; does not apply, toggle or remove policies. |
| `network audit` | `KswordCLI.exe network audit [--flags 0xN] [--max-rows N] [--limit N]` | Query TCP endpoint audit as the default network audit view. | Optional: --flags, --max-rows, --limit. | Use network wfp or network ndis for chain-specific views. |
| `network tcp` | `KswordCLI.exe network tcp [--flags 0xN] [--max-rows N] [--limit N]` | Query TCP endpoint audit rows. | Optional: --flags, --max-rows, --limit. |  |
| `network udp` | `KswordCLI.exe network udp [--flags 0xN] [--max-rows N] [--limit N]` | Query UDP endpoint audit rows. | Optional: --flags, --max-rows, --limit. |  |
| `network wfp` | `KswordCLI.exe network wfp [--flags 0xN] [--max-rows N] [--limit N]` | Query WFP inventory rows. | Optional: --flags, --max-rows, --limit. |  |
| `network ndis` | `KswordCLI.exe network ndis [--flags 0xN] [--max-rows N] [--limit N]` | Query NDIS chain rows. | Optional: --flags, --max-rows, --limit. |  |
| `network afd` | `KswordCLI.exe network afd [--limit N]` | Print degraded R3 AFD endpoint fallback evidence. | Optional: --limit. | No dedicated R0 AFD audit IOCTL is used. |
| `network nsi` | `KswordCLI.exe network nsi [--limit N]` | Print degraded R3 NSI adapter/address fallback evidence. | Optional: --limit. | No dedicated R0 NSI audit IOCTL is used. |

### `keyboard`

Keyboard hotkey and hook inventory.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `keyboard enum-hotkeys` | `KswordCLI.exe keyboard enum-hotkeys [--flags 0xN] [--pid PID] [--max-entries N] [--limit N]` | Enumerate keyboard hotkeys. | Optional: --flags, --pid, --max-entries, --limit. |  |
| `keyboard enum-hooks` | `KswordCLI.exe keyboard enum-hooks [--flags 0xN] [--pid PID] [--max-entries N] [--limit N]` | Enumerate keyboard hooks. | Optional: --flags, --pid, --max-entries, --limit. |  |

### `mutation`

Prepare, commit, rollback, and audit bounded mutation transactions.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `mutation prepare` | `KswordCLI.exe mutation prepare --target-kind N (--after-hex HEX \| --after-file PATH) [--before-hex HEX \| --before-file PATH] [--pid PID] [--address VA] [--context N] [--flags 0xN]` | Prepare a bounded mutation transaction. | Required: --target-kind and after payload. Optional: before payload, --pid, --address, --context, --flags. | Hex and file payload forms are mutually exclusive per payload. |
| `mutation session` | `KswordCLI.exe mutation session --target-kind N (--after-hex HEX \| --after-file PATH) [--before-hex HEX \| --before-file PATH] [--pid PID] [--address VA] [--context N] [--flags 0xN]` | 在同一 CLI 进程中 prepare，并从标准输入接收 commit、rollback、quit。 | 参数与 prepare 相同；flags 同时用于后续 commit/rollback。 | 保留驱动事务归属校验；独立 CLI 进程不能接管 prepare 的事务。 |
| `mutation commit` | `KswordCLI.exe mutation commit --transaction-id ID [--flags 0xN]` | Commit a prepared mutation transaction. | Required: --transaction-id. Optional: --flags. |  |
| `mutation rollback` | `KswordCLI.exe mutation rollback --transaction-id ID [--flags 0xN]` | Rollback a prepared mutation transaction. | Required: --transaction-id. Optional: --flags. |  |
| `mutation query-audit` | `KswordCLI.exe mutation query-audit [--flags 0xN] [--max-entries N] [--start-sequence N] [--limit N] [--hexdump]` | Query mutation audit ring entries. | Optional: --flags, --max-entries, --start-sequence, --limit, --hexdump. |  |

完整流程使用 `mutation session`：收到 `session_ready=true` 后，在同一进程的标准输入写入一行 `commit`；需要还原时再写入一行 `rollback`。成功 rollback 会结束会话；`quit` 或输入 EOF 只结束会话，不自动还原已提交的改动。commit 失败后会话继续等待，仍可请求 rollback，最终退出码保留本次会话的失败。`--flags` 同时用于 prepare、commit 和 rollback，实际写入仍须满足驱动原有 FORCE、确认及安全策略约束。不要分别启动 prepare、commit、rollback 三个 CLI 进程：事务绑定创建它的进程对象，后续进程的事务 ID 不能改变归属。

### `capability`

Unified driver feature capability query.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `capability query-driver-capabilities` | `KswordCLI.exe capability query-driver-capabilities [--limit N]` | Query unified driver feature capability rows. | Optional: --limit. |  |

### `wsl`

WSL silo and Linux PID/TID diagnostics.

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `wsl query-silo` | `KswordCLI.exe wsl query-silo [--pid PID] [--tid TID] [--flags 0xN]` | Query WSL silo process/thread evidence. | Optional: --pid, --tid, --flags. |  |

### `ddma`

DDMA 借助磁盘控制器的 DMA 通道传输物理页；后端有 ATA 与 SCSI 直通分支，是否可用取决于实际设备探测。`probe` 不带 `--lba` 时只枚举；带 `--lba` 会在所枚举磁盘上发出真实的读取探测。`selftest` 检查协议、设备、跨页和确认标志的拒绝路径，不写磁盘扇区；带 `--lba` 时也会做读取探测，输出 `PASS` / `FAIL` / `NOT_APPLICABLE`。当前 CLI 的探测文案仍称 ATA，`readyDisks` 实际可能来自 SCSI 分支。

`read` 的“读”指物理内存读取：它先备份磁盘暂存区，再临时写入目标物理页内容，读回后还原。必须指定可以临时覆盖的专用磁盘暂存区；`--bytes` 默认 64，最多 4096 且不能跨物理页。当前 CLI 自动设置协议确认位，没有额外的 `--confirm` 参数或交互确认。应核对返回的 `readStatus`、各阶段状态和 `SCRATCH_RESTORED` 标志，不能只凭进程退出码或 `bytesRead` 判断磁盘已还原。能力标志报告内核调试已启用时，当前 `MmMapIoSpace` 通路有触发 `MiShowBadMapper` 的蓝屏风险，勿执行物理内存传输。

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `ddma selftest` | `KswordCLI.exe ddma selftest [--lba N]` | 检查 DDMA 协议和拒绝路径。 | 可选：--lba。 | 不写磁盘扇区；提供 LBA 会做真实读取探测。环境不具备传输通道时可为 `NOT_APPLICABLE`。 |
| `ddma probe` | `KswordCLI.exe ddma probe [--lba N] [--max-disks N]` | 枚举磁盘并查询 DMA 能力。 | 可选：--lba、--max-disks（默认 8，上限 32）。 | `IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY`；不带 LBA 不发传输命令。 |
| `ddma read` | `KswordCLI.exe ddma read --disk N --pa ADDR --lba N [--bytes N]` | 通过磁盘 DMA 读取物理内存。 | 必填：--disk、--pa、--lba。可选：--bytes。 | `IOCTL_KSWORD_ARK_DDMA_READ_PHYSICAL`；会临时写磁盘暂存区。当前 CLI 没有公开 `ddma write` 命令。 |

### `r0`

复用桌面端 `ArkDriverClient` 的 R0 取证与控制接口。多数命令为查询；`clipboard-policy-set-rules` 会替换规则表。命令共享桌面端的协议版本、边界校验与旧驱动降级处理，输出中会给出 `io_ok`、Win32/NT 状态及已返回的行数。`traffic` 只读取驱动中现有的捕获环，不会启动捕获；`raw-disk-read` 只读，默认最多显示 256 字节。

| 命令 | 语法 | 用途 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| `r0 workqueue` | `KswordCLI.exe r0 workqueue [--flags 0xN] [--max-entries N] [--limit N]` | 枚举内核工作队列。 | 可选：--flags、--max-entries、--limit。 | `IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE`。 |
| `r0 directory` | `KswordCLI.exe r0 directory --path PATH [--max-entries N] [--limit N]` | 通过 R0 `ZwQueryDirectoryFile` 枚举目录。 | 必填：--path。可选：--max-entries、--limit。 | Win32/UNC 路径会规范化为 NT 路径。 |
| `r0 directory-irp` | `KswordCLI.exe r0 directory-irp --path PATH [--layer N] [--max-entries N] [--limit N]` | 在选定文件系统栈层枚举目录。 | 必填：--path。可选：--layer、--max-entries、--limit。 | 输出实际接收层及驱动名。 |
| `r0 image-signature` | `KswordCLI.exe r0 image-signature --path PATH [--module-base VA] [--flags 0xN]` | 读取 Authenticode 证书表和 CI 证据。 | 必填：--path。可选：--module-base、--flags。 | `IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE`。 |
| `r0 debug-output` | `KswordCLI.exe r0 debug-output [--after-sequence N] [--max-records N] [--limit N]` | 读取内核调试输出环。 | 可选：--after-sequence、--max-records、--limit。 | `IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN`，不改变捕获状态。 |
| `r0 hvm-status` | `KswordCLI.exe r0 hvm-status` | 查询 HVM v6 的 VMX/EPT 或实验性 SVM/NPT 生命周期与能力状态。 | 无。 | `IOCTL_KSWORD_ARK_QUERY_HVM`。 |
| `r0 debugger-status` | `KswordCLI.exe r0 debugger-status` | 查询原生调试后端协议和线程/内存能力。 | 无。 | `IOCTL_KSWORD_ARK_DEBUGGER` 的只读 QUERY；不启动 HVM 或修改目标。 |
| `r0 hvm-metrics` | `KswordCLI.exe r0 hvm-metrics` | 查询转换计时有效性及 INVEPT、替换页资源计数。 | 无。 | `IOCTL_KSWORD_ARK_HVM_METRICS` v10；完整逐核 JSON：`hvm_ctl --json metrics`，包括 Intel 影子 EPT 与 AMD NPT 缓存计数。 |
| `r0 hvm-events` | `KswordCLI.exe r0 hvm-events [--after-sequence N] [--max-rows N]` | 读取 HVM 事件环，不清空事件。 | 可选：--after-sequence、--max-rows。 | `IOCTL_KSWORD_ARK_HVM_EVENTS`。 |
| `r0 hvm-platform` | `KswordCLI.exe r0 hvm-platform` | 查询 CR4、CPUID 与 CET MSR 平台校准证据。 | 无。 | `IOCTL_KSWORD_ARK_HVM_PLATFORM`；不进入 VMX。 |
| `r0 ioctl-registry` | `KswordCLI.exe r0 ioctl-registry [--flags 0xN] [--max-entries N] [--json]` | 查询驱动已注册的 IOCTL 分发表。 | 可选：--flags、--max-entries。 | `IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY`。 |
| `r0 timer-dpc` | `KswordCLI.exe r0 timer-dpc [--max-entries N] [--max-per-bucket N] [--json]` | 枚举内核定时器与 DPC 证据。 | 可选：--max-entries、--max-per-bucket。 | `IOCTL_KSWORD_ARK_ENUM_TIMER_DPC`。 |
| `r0 unloaded` | `KswordCLI.exe r0 unloaded [--source mm\|piddb\|hash] [--max-rows N] [--json]` | 查询已卸载驱动、PiDDB 或哈希桶证据。 | 可选：--source 默认 `mm`，--max-rows。 | `IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS`。 |
| `r0 wfp-events` | `KswordCLI.exe r0 wfp-events [--after-sequence N] [--max-rows N]` | 读取 WFP 事件环元数据。 | 可选：--after-sequence、--max-rows。 | `IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS`。 |
| `r0 traffic` | `KswordCLI.exe r0 traffic [--after-sequence N] [--max-rows N]` | 读取现有流量捕获环的元数据。 | 可选：--after-sequence、--max-rows。 | `IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS`，不启动捕获。 |
| `r0 piddb` | `KswordCLI.exe r0 piddb [--max-rows N]` | 枚举 PiDDBCacheTable 证据。 | 可选：--max-rows。 | `IOCTL_KSWORD_ARK_QUERY_PIDDB`，不删除条目。 |
| `r0 cpu-power` | `KswordCLI.exe r0 cpu-power` | 查询 CPU 电源管理状态及原始能力证据。 | 无。 | `IOCTL_KSWORD_ARK_QUERY_CPU_POWER`。 |
| `r0 process-protect` | `KswordCLI.exe r0 process-protect` | 查询进程保护配置和计数器。 | 无。 | `IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE`。 |
| `r0 clipboard-policy` | `KswordCLI.exe r0 clipboard-policy` | 查询驱动当前存储的剪贴板访问策略规则表。 | 无。 | `IOCTL_KSWORD_ARK_QUERY_CLIPBOARD_POLICY`；驱动只存表/回显，真正拦截判定在被注入目标进程的 Agent DLL 里。 |
| `r0 clipboard-policy-set-rules` | `KswordCLI.exe r0 clipboard-policy-set-rules --blob PATH` | 加载一份原始剪贴板策略配置包并整体替换规则表。 | 必填：`--blob`。 | `IOCTL_KSWORD_ARK_SET_CLIPBOARD_POLICY`。 |
| `r0 raw-disk-backend` | `KswordCLI.exe r0 raw-disk-backend [--disk N] [--backend N] [--flags 0xN]` | 查询指定原始磁盘读取后端。 | 可选：--disk 默认 0，--backend 默认 Windows stack，--flags。 | `IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND`。 |
| `r0 raw-disk-read` | `KswordCLI.exe r0 raw-disk-read --length N [--disk N] [--backend N] [--offset N] [--flags 0xN] [--hexdump]` | 读取受协议长度上限约束的原始磁盘范围。 | 必填：--length。可选：--disk、--backend、--offset、--flags、--hexdump。 | `IOCTL_KSWORD_ARK_READ_RAW_DISK`。 |
| `r0 system-time` | `KswordCLI.exe r0 system-time` | 查询系统时间虚拟化和冲突状态。 | 无。 | `IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME`。 |
| `r0 slat-iommu` | `KswordCLI.exe r0 slat-iommu [--include-mmio]` | 查询 SLAT、IOMMU 固件及运行时证据。 | 可选：--include-mmio。 | `IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT`。 |
| `r0 platform` | `KswordCLI.exe r0 platform [--scope 0xN] [--max-rows N] [--json]` | 查询 HAL 和 WDF 平台审计证据。 | 可选：--scope 默认全量，--max-rows。 | `IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT`。 |
| `r0 i8042` | `KswordCLI.exe r0 i8042 [--max-rows N]` | 查询 i8042prt 回调和栈证据，不读取输入数据。 | 可选：--max-rows。 | `IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT`。 |
| `r0 object-types` | `KswordCLI.exe r0 object-types [--flags 0xN] [--max-entries N] [--start-index N] [--json]` | 枚举内核对象类型表。 | 可选：--flags、--max-entries、--start-index。 | `IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE`。 |
| `r0 object-type-procedures` | `KswordCLI.exe r0 object-type-procedures [--start-index N] [--max-entries N]` | 逐个对象类型核对 Dump/Open/Close/Delete/Parse/Security/QueryName/OkayToClose 八个方法指针的归属模块；方法指针块布局在运行时自验证，验证不过如实报告 UNVERIFIED 而不给结论。核心类型（Process/Thread/Driver/File）按地址范围硬判；非核心类型另有一条"类型内一致性"判据：同一类型里 >=3 个槽落在 ntoskrnl 内、又恰好 1 个槽落在别处时判隐藏行为，汇总行的 `judged_types=N/M` 说明这条判据能覆盖 70 个类型里的多少个——不在这个数里的类型不代表"干净"，只是本版本给不出硬判据。退出码：0=已验证且干净，5=布局未验证，6=已验证但扫描不完整。 | 可选：--start-index、--max-entries。 | `IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES`。 |
| `r0 win32k-timers` | `KswordCLI.exe r0 win32k-timers [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--json]` | 查询基于 PDB 的 win32k 定时器证据。 | 可选：--flags、--session-id、--pid、--tid、--max-entries。 | `IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS`。 |
| `r0 win32k-events` | `KswordCLI.exe r0 win32k-events [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--json]` | 查询基于 PDB 的 WinEvent Hook 证据。 | 可选：--flags、--session-id、--pid、--tid、--max-entries。 | `IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS`。 |

`r0 ioctl-registry`、`unloaded`、`platform`、`object-types`、`win32k-timers`、`win32k-events` 和 `timer-dpc` 输出已解析的逐行文本及响应状态，也支持 `--json`。JSON 使用 `schemaVersion`、`command`、`backend`、`status`、`data` 和 `diagnostics`；`data` 包含传输状态、协议状态、总数、返回行和截断信息，地址与位掩码使用十六进制字符串。`complete=false` 表示已知不完整，`null` 表示无法仅凭这些回执确认采集完整。结合总数、状态和标志判断结果；`--max-rows` 或 `--max-entries` 设置上限不意味着结果完整。`object-types` 的 `next_index`（JSON 为 `nextIndex`）可用于后续 `--start-index` 查询。字段有效性以各协议定义的 `field_flags` 或 `flags` 为准，未标记的值不应被解释成已确认的证据。已解析响应若返回 `STATUS_BUFFER_OVERFLOW`，退出码为 6（部分结果）。

`r0 timer-dpc` 的 `query_state` 将缺少动态数据、无效布局和不支持与成功空结果区分开：上述不可用状态返回 5，部分或截断返回 6，完整结果返回 0；传输错误保留对应错误退出码。


### 通用调试后端能力查询

`KswordCLI.exe r0 debugger-status` 通过 `IOCTL_KSWORD_ARK_DEBUGGER` 的只读 QUERY 操作查询
协议版本、NTSTATUS 与 capability 位图：`0x1` 为原生 x64 线程上下文，`0x2` 为保留原
计数的线程挂起/恢复，`0x4` 为用户进程内存分配/释放。保护操作若缺少 Windows 导出会
明确返回不支持。该命令不修改目标，不启动 HVM；驱动与调试器适配层需使用相同协议。

### HVM 后代页控制（探针工具 `hvm_ctl`）

`hvm_ctl.exe` 是独立探针工具，不随主程序发布，也**不再**与主程序共用命令目录——
主程序那个“完整操作”子页、`--ksword-hvm-command` 入口与 `HvmCommandPanel` 都已删除
（见 `docs/next/hvm-gui-command-parity.md`），`HvmCommandCatalog.c` / `HvmCommandEngine.c`
现在只由 `tools/hvm_ctl/` 编译。`hvm_ctl --json commands`
是命令、参数、默认值和范围的权威目录；`--parse-only` 验证参数且不打开驱动。

| 命令 | 参数与结果 |
| --- | --- |
| `hvm_ctl --json nested-page-map <EPT12> <GPA> <fill> [ownerPID]` | 前三项为十六进制；可选 VMM PID 是十进制，默认 `0` 自动要求恰好一个 `vmware-vmx.exe`。内核校验 PID 和创建时间，拒绝已退出或被复用的进程身份。 |
| `hvm_ctl --json nested-page-query` | 映射 ABI v4 返回进程身份、`leaseRevocationReason`、`sourcePhysicalPage`、源表路径、叶粒度与区间大小。进程退出或原 EPT 路径发生翻译变化后撤销规则；替换页仍保留到显式移除完成全核失效。 |
| `hvm_ctl --json nested-page-map-region <EPT12> <GPA> [leafShift] [ownerPID]` | EPT12/GPA 为十六进制，后两项为十进制，默认 `leafShift=21`、`ownerPID=0`。叶粒度 12/21/30 对应 4 KiB/2 MiB/1 GiB，基址必须按粒度对齐；源 EPT12 叶粒度不够时整体拒绝。映射先克隆原内容，再通过 stage 改指定页。 |
| `hvm_ctl --json nested-page-map-region-scan <EPT12> <GPA> [leafShift] [ownerPID]` | 参数同上；逐项扫描源映射，权限及内存类型一致时才接受。此模式只对首页路径即时检测漂移，其余表项的改变可能延迟发现；它不会提供与普通 region 模式相同的租约保证。 |
| `hvm_ctl --json nested-page-stage <pageIndex> <fill>` | 索引从 0 起、十进制；fill 为十六进制字节。改写已发布区间中的一个 4 KiB 替换页，越界拒绝。更新不是原子的，并发读取可能看到混合字节。 |
| `hvm_ctl --json nested-page-digest` | 返回已发布区间与源区间的内容摘要；会读取整个区间两次，适合按需核验。只给摘要，不返回任意物理内存字节。 |
| `hvm_ctl --json resident-nested-fullsnapshot` | 与 `resident-nested-hidehv` 相同的嵌套和身份策略，但保留 CPUID 的完整诊断 VMREAD，供同一驱动二进制内的性能对照。普通模式省略无关的 qualification 和 instruction-error 字段读取。 |
| `hvm_ctl --json nested-page-remove` | 取消发布、全核失效、回收；失败时保留 backing，不能仅凭 `active=0` 判断已经释放。 |
| `hvm_ctl --json metrics` | 当前 metrics ABI v11 返回 Intel 的 `shadowEpt` 与 AMD 的 `svmProcessors` 等逐核证据。计数在资源重建时清零，查询是时间区间内的观察值，不是所有 CPU 的同时快照。 |

旧 page v1/v2/v3 或旧 metrics 客户端不能搭配此驱动使用；同时更新主程序、
`KswordCLI.exe` 和 `hvm_ctl.exe`。普通 HVM 状态查询 ABI 不变。
进程租约不能检测同一 VMM 进程内的来宾重启、快照恢复或 GPA 重用；
调用者须在这些操作前移除映射，并在控制期间保留目标页。


### AMD SVM/NPT 实验后端（HVM v6 / metrics v11）

HVM v6 在 `status.svmProbe` 增加 `rejectReason`/`rejectReasonName`、`stateValidMask`、`cpuid1Ecx`、`xsaveFeatures`、`cr4`、`xcr0`、`xss`。状态有效位 1/2/4/8/16 分别对应 CR4、CPUID.1、CPUID.D.1、XCR0、XSS；无有效位的零值不代表状态关闭。拒绝码 7 是非零 HSAVE、8 是 CR4 中未支持的状态、9 是 XSAVE/OSXSAVE 不可用、10 是扩展状态读取异常、11 是非零 XSS、12 是物理地址宽度不支持。该查询不修改寄存器、不进入 SVM；SYS、主程序与 CLI 必须同步更新，旧 v5 请求拒绝。

`status` 增加 backend（0 无、1 VMX、2 SVM）、slatType、slatReady、backendStatus、powerGeneration 及带独立 MSR 有效位的 svmProbe。
逐核 executionStage 和 svmExitCode 独立于 Intel VMX 指令结果；AMD 不设置 VMXON_SUCCEEDED。
`metrics` 的 svmProcessors 记录原始 64 位 EXITCODE/EXITINFO1/2、RIP/RSP/CR3/NRIP、事件、ASID、页表/HSAVE/VMCB 身份、full-flush 请求及保留的失败阶段。
64 位原始值采用 JSON 字符串；valid=0 的退出快照不得解释为已观测到零退出码。

执行顺序为 `hvm_ctl --json prepare` → `self-test` → `resident` → `stop` → `teardown`。
现有命令目录为前三条显式附加 ALLOW_NESTED；AMD 仅接受 VMware 外层，仍需全 CPU 实际 VMRUN 自检。
AMD 的 self-test 包含已知 CPUID 退出和完整原生返回；`selfcheck` 只读，不替代它。
`stop`、`teardown` 不要求重新提供进入许可。生命周期 generation 每次控制递增，powerGeneration 才是跨电源检查使用的代次。
AMD 的普通模式不暴露嵌套 SVM；通用嵌套实验另有专用命令，见下文。AMD 不支持 Intel EPTP switch、local EPT、VMREAD benchmark、一次性 Intel guest 或驱动内置 Intel soak；由实验采集脚本执行多核循环和压力。
旧 HVM/metrics 协议版本明确拒绝。
新增 `prepare-svm-probe`、`self-test-svm-nested` 专用命令：前者分配每核嵌套探针资源，后者执行驱动拥有的固定内层 VMRUN→CPUID→退出反射→原生返回序列。两者只能用于 AMD；先从已释放状态准备，完成后使用 `teardown`。该准备配置禁止 `resident`，不会向正常 Windows 宣传可运行任意内层 VMM。

实验性通用 AMD 路径使用独立命令 `prepare-svm-general → self-test → resident-svm-general → stop → teardown`，共享标志 `ENABLE_NESTED_SVM=0x00010000`，HVM v6 结构不变。准备与启动模式必须一致；普通 `prepare/resident` 仍隐藏 SVM，探针准备不能通过省略标志改为常驻。Intel 明确拒绝该 AMD 标志。通用模式逐核绑定当前 Windows 状态和退出协调器，采用相同全核启动/回滚和停止互锁；有虚拟 SVM 所有权、L2 执行或未完成事件时停止返回忙，不能直接卸载。嵌套实现报告 PARTIAL；这些命令是后续实验入口，**没有完整 L2 OS/内层并发通过证据**，不应在日常实体机上直接试运行。
以下 v4～v11 是 metrics 结构的演进记录，当前请求统一使用共享头声明的 v11，不应逐节切换客户端。metrics v4 在每条 `svmProcessors` 中增加 `nestedProbe`：valid、sequence、status、entries、reflections、faults、64 位 exit/marker。仅 valid=1、偶数且递增 sequence、status=0、entries/reflections=1、faults>0、exit=0x72、marker=0x4B534E31 才算该核完整探针通过。此结果不等于内层操作系统启动或两小时压力通过。驱动、主程序与 CLI 必须一起更新。
环境脚本、克隆与调试步骤见 [AMD 实验工具](../tools/hvm_lab/README.md)。硬件验收仍以该目录记录为准。

AMD metrics v5 的 `svmProcessors[].general` 使用独立64位序列校验。`valid=1` 只表示整个诊断快照一致；`preparedEntries` 是软件进入准备次数，`hardwareExits` 才是该通用入口收到的物理VMEXIT次数，两者都不证明完整内层操作系统启动。`nestedProbe` 仍只记录有界探针。`phase/action/gif/pending/nmiCaptured/leaseToken/armedToken/retryToken` 用于解释停止/事件窗口；无通用绑定时 general.valid=0。旧metrics客户端必须重编译，不与v5结构混用。


AMD metrics v6 在 `svmProcessors[].flight` 增加独立首故障记录：`coherent=1` 才能使用；`latched=1` 表示首个 SHUTDOWN（reason=1）、INVALID（2）或内部失败（3）已冻结，后续退出/stop/start不覆盖，teardown释放后才消失。`captureTiming=1` 是退出分派前，`2` 是失败处理后。最近32条L2进入/退出摘要按时间排序输出，`kind=1`为进入前、`2`为退出分派前；进入记录的exit字段仍是前一次退出值，不能解释为新退出。只记录已有拦截，不新增异常拦截，不能保证保留首条异常。

锁存时还导出4096字节VMCB的完整十六进制字符串 `vmcb12Hex`、`currentVmcbHex`；`vmcb12Valid=0`时前者不可解释，current是否为VMCB02由故障行的phase决定（1=L2）。`generation`绑定事件发生时的代次，`total`只在本次资源生命周期单调计数。数据不代表跨CPU同时快照，也不保证跨重启保留。旧v5 metrics客户端明确拒绝，必须同步驱动与CLI/主程序。

故障后可运行 `tools/hvm_lab/Export-SvmIncident.ps1 -Ctl <配套hvm_ctl.exe> -EvidenceDirectory <新目录> -Vmx <克隆vmx路径>`。脚本只执行status/metrics及文件复制，导出原始JSON、VMCB二进制、VMware日志和SHA256；不加载/停止驱动、不重置VM、不清除记录。`latchedCpus=0`不是通过，`incoherentCpus>0`表示部分现场不可用。超时保留进程和日志，不推断回滚。


AMD metrics v7 增加 `svmProcessors[].hotspots`，按原始硬件退出时的 L1/L2 分开计数。
`valid=1` 且 `saturated=0` 才可用于同一次启动、同一运行代次的差值；不能用无效快照的零值计算增长。
`levels[].codes` 保留 0x00～0xff 的精确退出编号，NPF、INVALID 和未知扩展分别计入 `npf`、`invalid`、`other`。
每层保留最先出现的16个 MSR 编号及读写次数，满表后未知编号计入 `msrOverflow`，不会伪装成完整排名。
`lastMsr` 仅指最近一次 MSR 退出；`lastRip/lastInfo1/lastInfo2` 属于该层最近一次任意退出，两者未必是同一次。
该记录使用独立短序列，不依赖 `general.valid` 或 `flight.coherent`，也不等于 L2 已成功启动。
v7驱动必须配套重新构建的CLI/主程序；导出脚本继续支持历史v6，不能用v7 CLI向v6驱动查询metrics。

AMD metrics v10 增加 `svmProcessors[].nptCache`，与 `general` 共用有效位和序列。
`lookups/hits/resets/resetFailures` 分别统计进入阶段的缓存检查、命中、成功清空和清空失败；`ownerTransitions/ownerCpuTransitions` 分别统计重复接手和跨 Windows group:number 接手；`tlbRequests` 统计硬件 TLB_CONTROL 请求，它不会单独清空稳定的 NPT02 页表。
`reasons` 区分未启用复用、冷缓存、epoch、所有权令牌、TLB 请求及 13 个配置键变化。
同一次未命中可能包含多个原因，不能把原因次数相加当作清空总数。`ownerChanged` 不直接证明 Windows 线程迁移。
`invlpgaCount/poolRecycles` 分别统计虚拟 INVLPGA 和页表池回收；它们可能同时造成下一次检查的 `epochChanged`。
只有同一运行代次、`valid=1`、稳定偶数序列且 `saturated=0` 的成对记录可计算差值；无效记录不当作零增长。
`python tools/hvm_lab/analyze_npt_cache.py first/metrics.json second/metrics.json --output delta.json` 会报告有效 CPU 覆盖率和排除原因。
v10 驱动需配套重新构建的 v10 CLI 与主程序；旧客户端明确拒绝版本不匹配。源码中的协议版本不能证明已下载或已发布二进制同步完成。


AMD metrics v10 增加可选 `perf`。命令 `prepare-svm-profile → self-test → resident-svm-profile → stop → teardown` 在通用嵌套模式上添加 `SVM_PROFILE=0x00020000`；普通 general 命令不采样。每 64 次硬件退出选择一次，分别统计原始 L1/L2 和 MSR、XSETBV、VMLOAD、VMSAVE、STGI、CLGI、VMRUN、CPUID、NPF、IO、IRQ、other 十二种退出桶。每桶包含样本数、根态周期总和/最大值及五段周期：扩展状态保存、宿主状态恢复、退出分派、进入协调、来宾状态恢复。分派内部七个 details 依次为取指、VMCB 捕获、权限图、NPT12 同步、写回、页表遍历、影子发布；它们已包含在分派周期内，不能再次加到总周期。其余分派周期包含事件协调、路由、诊断及计时开销，不能称为纯事件处理成本。

计时不含纯硬件 VMEXIT/VMRUN 延迟、来宾执行、最前面的 GPR 保存和最终 guest VMLOAD。`valid=1`、偶数 sequence 且 saturated=0 才可使用；只能比较同一资源代次、CPU/ASID/VMCB 身份和 sampleMask。`tlbIssued[0..3]` 是全部成功硬件进入的 TLB_CONTROL=0/1/3/7 次数，不是采样次数，也不是虚拟 L1 请求数。异常 INVALID 不证明请求已消费。客户端与驱动必须同步重新构建。


`prepare-svm-fast → self-test → resident-svm-fast → stop → teardown` 在采样模式上增加 `SVM_FAST_MSR=0x00040000`。仅无 L2/租约/事件/注入/窗口且 GIF 遮罩、物理 CR8、完整 INT_CTL 不变时，EFER/HSAVE/XSS 的读取和同值写入通过纯整数叶完成；XSS 仍要求 XSAVES。变值写入、状态不符、IRQ/NMI/NPF/SVM 指令及 stop 请求使用完整状态桥。快路不取消 MSRPM 拦截、不转发真实 HSAVE。它跳过 XSAVE/XRSTOR、XCR0/XSS 切换及 host/guest VMLOAD/VMSAVE 配对（来宾非自动状态全程未被 host 修改），同时保留全量 hotspot 和生命周期计数；诊断 ring 只记录慢路。`perf.fastMsr[3][2]` 是 EFER/HSAVE/XSS 读取/同值写入的快路子集，不能再加到 hotspot 总数。构建在 Link 前检查完整叶机器码，无 call/SIMD/x87/FS/GS 或间接跳转，否则拒绝链接；硬件 XSTATE 和事件验证仍需单独完成。


### AMD 架构优化实验入口（metrics v11，尚未实机验收）

`hvm prepare-svm-accel → hvm self-test → hvm resident-svm-accel` 单独选择物理 VLS 和私有 clean 控制；硬件缺少对应能力时继续软件执行。vGIF 不能屏蔽物理中断，本模式保留 CLGI/STGI 截获与物理 INTR/NMI 软件协调；`vgifSelected/vgifEntries` 保持零。
`hvm prepare-svm-opt → hvm self-test → hvm resident-svm-opt` 另外启用 CPU 写入跟踪、VMCB 身份共享 NPT02 缓存和整数 MSR 快路。`hvm_ctl` 直接使用同名命令，不加 `hvm` 前缀。两种准备/启动模式必须匹配；结束仍使用 `stop → teardown`，不能从 CLI 退出推断驱动已经停止。

metrics 升为 v11，主协议仍 v6；旧 metrics 请求明确版本不匹配。`svmProcessors[].optimization` 报告请求标志、VLS/vGIF 选择、clean mask、共享根/迁移计数、写跟踪代次/逐核确认与源依赖撤销。`stableVmcb01Pa/stableVmcb02Pa` 是固定资源身份，`vmcbPa` 仍为当前选择的物理执行页，跨窗口统计不能把正常切层当成资源更换。选择次数不是被消除的退出次数，也不是完整 L2 OS 通过。

`watchState=1` 表示跟踪器可用，`2` 表示已经撤销；只有源页保护和所有 CPU 刷新确认一致时才可跳过源读取。CPU 私有 `watchProofHits` 可分核统计，其他 `watchArms/watchWrites/watchDeclines` 是共享计数，仅索引零且 `watchGlobalValid=1` 时可用。依赖撤销是当前共享根的计数，根更换时不能直接做差。CPU 写故障永久撤销该页的复用证明，直到完整退出后的下一次受控 start 重置；DMA 写入不属于这项 CPU 写入证明。写跟踪未覆盖或预算不足的源不会获得缓存证明；准备分配失败明确报错，不启动部分配置。

本轮仅编译；源证明、DPC确认、VLS/vGIF、中断、XSTATE、原生停止和多核迁移的真实行为尚未测试。不要把该候选覆盖到运行中的驱动目录。

### 回调 WFP 解析诊断

`callback enum` 的 WFP 导出解析失败行会显示本次 `fwpkclnt.sys` 的模块定位状态、基址、大小，以及每个失败的枚举必需导出名称和原始状态。`log --max-frames 256` 中的 `WFP resolve module` / `WFP resolve export` 记录全部八个导出的状态和地址，可用于比较处置前后；日志读取会消费共享日志帧，应及时保存输出。枚举只依赖六个枚举必需导出；缺少 GetById/DeleteById 时仍枚举，但不提供候选移除标记。

复测时先保存新加载驱动的枚举和日志，再逐条执行原处置序列，每条后立即保存同样的枚举和日志，以第一条出现解析差异的操作缩小范围。增加 `--max-entries` 只能改变返回页大小，不能修复导出解析失败。

### 强制卸载诊断与成功对照

`kernel force-unload-driver` 的退出码 `0` 表示响应为 `status=1`（UNLOADED），且主操作/等待状态成功，即驱动后端已确认完整卸载。`status=9`（UNLOAD_ROUTINE_CALLED）只证明卸载例程调用完成，返回 `6`，输出 `unloadOutcome=unload-routine-called fullUnloadConfirmed=0 commandExitCode=6`。`status=7`（FORCED_CLEANUP）表示完成清理，但完整卸载未由该状态确认，同样返回 `6`。失败或超时仍返回 `3`，不支持仍返回 `5`，原始响应状态保持不变。

返回 `6` 时 CLI 自动进行一次只读 DriverObject 查询，打印 `driverObjectPresent=yes/no/unknown` 和查询诊断：`yes` 明确表示查询时该名字的 DriverObject 仍可引用；`no` 仅表示对象查询未找到，不能单独证明内核模块已消失；查询传输、版本、长度或引用证据不可用时显示 `unknown`。这个后置查询不改写原始操作回执，也不把退出码升级为 `0`。需要对比实际驻留模块时，另行保存内核模块枚举结果。

`kernel force-unload-driver` 额外打印 `requestedFlags`、`droppedFlags`、`diagnosticFlags`、`reached` 和 `evidence`。`reached` 列出已经到达的引用、预检、ZwUnloadDriver、直接调用以及验证步骤；`evidence` 列出观察到的阻塞条件，例如 `device-reference`、`resident-threads`、`module-callbacks` 或三类尚未恢复的编辑记录。多项证据可以同时存在，不应把每项都理解成当前路径的决定原因。

诊断复用 V2 响应的 `reserved2`，不改变 IOCTL 编号、结构大小或版本。旧驱动没有 VALID 位时显示 `diagnostics=unavailable`。GUI/Light 的共享客户端保留原始 flags 和可选诊断字段，原有功能仍可使用旧驱动。

失败后立即保存 `log --max-frames 256`，查找 `R0 unload diag summary`、`flags`、`gates`、`thread-evidence`、`callback-evidence`、`loader-image`、`zw` 和 `direct`，这些日志保留各步骤原始状态和计数。`--flags 0x290` 包含直接调用和清理授权，但预检不允许清理时仍可能降为 `0x200`；应比较 requested/effective/dropped，不能把被移除的 flags 当成已经执行的清理。

Beep 返回 DEVICE_BUSY 本身不能证明通路错误，也不能作为成功对照。专用构建夹具与后续来宾对照步骤见 [unload_probe](../KswordARKDriver/tests/unload_probe/README.md)。用户提供的探针回执证明默认 flags 的完整卸载路径可用；显式 `0x200` 仅调用卸载例程后对象和模块仍存在。Beep 的新回执定位到 device-reference，属于当前保护条件下的拒绝。本次 CLI 修改仅构建，未新增运行实测。
