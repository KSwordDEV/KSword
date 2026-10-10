# CLI 崩溃报告与 VMware 验收（2026-10-08）

- `log` 在 `_O_U8TEXT` 下用 `std::cout` 写字节：偶数字节被当作 UTF-16 产生乱码，奇数字节触发 CRT invalid-parameter fastfail `0xC0000409`。不是栈缓冲溢出。统一先解码 UTF-8（旧 ANSI 帧回退系统代码页），再用 `std::wcout`。不要在宽字符 CRT 模式下恢复任何窄字符 stdout/stderr 写入。
- `tools/test_ksword_cli.py` 直接包含生产 CLI，并用 Windows 传输夹具验证真实 CRT 重定向、日志边界、参数诊断、退出码、别名、帮助和失败顺序；扩展结果打印/退出码函数也来自生产源文件。需在 HostX64 VS 环境运行。
- 旧报告在 26200 系统上使用 2026-10-01 驱动，所有只读请求连能力查询都返回 50，与已于 2026-10-03 删除的 OS build 上限分发门禁一致。IOCTL 名称打印正确不证明驱动未注册。查 `preflight query`、`r0 ioctl-registry` 与实际服务映像路径；不得因旧报告重新关闭现有处理器或绕过逐功能布局校验。
- 内置帮助的当前顶层 `driver` 子树已完整；用回归测试保证与 family help 一致。缺必填项和未知选项分开诊断，命令参数错误带语法/参数元数据；允许的选项按具体命令 help 语法检查，不能依赖以前被静默忽略的拼错参数（例如 `r0 object-types --limit`，应使用 `--max-entries`）。
- 退出码保留既有语义：0 成功、1 参数、2 打开设备失败、3 I/O 失败、4 响应格式、5 不支持/证据不可用；扩展和固定/变长响应的同类传输失败保持一致。失败且默认 NTSTATUS=0 时显示 `n/a`，实际返回的非零状态保留。
- 缺驱动现场验收发现 Callback Monitor 和内核枚举封装会覆盖 `IoResult.message`，因此不能依赖 `CreateFileW` 字符串判断阶段。`DriverClient::deviceIoControl` 在打开失败时设置 `IoResult.deviceOpenFailed`，后续复制保留；CLI 用该标志判断退出码和启动提示，不能将真正 IOCTL 内部的文件不存在误归为驱动没加载。
- `tools/ksword_cli_vm.py` 通过安装的 VMware VIX x64 DLL 进程内登录、传文件和运行程序，不在命令行传密码。`tools/Invoke-KSwordCliReportCases.ps1` 在 VMware 来宾执行报告涉及的只读命令、保留 stdout/stderr、退出码、超时、OS/服务/文件 SHA256。`-EnsureDriverLoaded` 只加载 Release 中已有驱动并保留运行供后续复用，不替换驱动或修改签名策略。
- 本次 Win10 20H2 来宾原 CLI 真实复现日志乱码及 1/2/100 帧 fastfail；仅替换 CLI 的候选版本全部正常。当前同目录原 SYS 下进程/SSDT/回调/能力等查询可返回，PiDDB/卸载驱动全局证据仍可如实 unavailable。服务最初未安装，验收创建正常 SCM 测试服务，保留用于复用。
- 来宾 Administrator 无密码，VIX 返回 3033 时由用户设置 `LimitBlankPasswordUse=0`；用户明确要求保持此测试环境设置，不再恢复。来宾通道不需要网络 WinRM/SSH。
- 用户原有七个未提交 UI/语言包/记忆改动应保留；CLI 提交不得顺带提交它们。

## 2026-10-09 动作修复（仅构建）

- CLI 固定/变长响应的主要 NTSTATUS 失败现在传递到进程退出码：操作失败/等待超时为 3，不支持为 5；扩展客户端显式 unsupported 也为 5，传输成功不再掩盖响应失败。
- mutation 的所有者仍为创建事务的进程对象。新增 `mutation session` 在一个 CLI 进程内 prepare，并通过标准输入接收 commit/rollback/quit，失败 commit 后仍保留 rollback 的会话入口。独立 CLI 进程不能接管事务；help 和 CLI 文档已同步。
- 注入后端在没有 ZwCreateThreadEx 导出时解析真实内核 RtlCreateUserThread，保留 R0 分配/写入；本机内核导出与包装器反汇编证实 RTL 路径，参数对照 phnt 声明。不改 IOCTL ABI；短写与正值 STATUS_TIMEOUT 都不当作成功。
- 网络 WFP 最小 ABI 原来在 FWPS_INCOMING_VALUE0 前多放一个 fieldId，破坏了数组步长。正式 WDK 项仅包含 FWP_VALUE0；已删字段并加大小/偏移断言，协议、端口保留正确的类型及主机序。
- 文件重定向发布启用规则前启动共享 minifilter；失败保留旧规则。DOS 盘符规则解析成设备路径；pre-create 按 FltMgr opened 全名/卷内后缀匹配，目标名字替换后完成 STATUS_REPARSE/IO_REPARSE，命中后改写失败完成真实错误，不能继续写入源文件。注册表规则的后端未改。
- APC 控制不再依赖未导出的 PsGetNextProcessThread，复用有界真实 TID 快照并以对象引用复核进程归属。原位掩码错误，ApcQueueable 是 KTHREAD.MiscFlags bit 14；仅在本机 KeInsertQueueApc 的线程字段测试指令校准通过后清位，未知代码形态返回不支持。
- 强卸载预检缺线程私有偏移/非导出枚举器时，改用 System TID 快照、精确线程对象句柄和 ZwQueryInformationThread 查询入口。仍保留占用、核心模块、loader、回调和未完成证据约束，真实 DEVICE_BUSY 不是应绕过的参数错误。
- 对象回调真实句柄校准见 ksword-object-callback-remove.md。本次 VMware 日志没有证明来宾崩溃具体原因。
- CLI、驱动、Qt 主程序、Light 的 Release/x64 构建通过；驱动 ApiValidator 与 Inf2Cat 通过。主程序构建脚本明确 BUILD_RESULT=SUCCESS、EXIT_CODE=0，i18n/主题门禁通过。Light 复用相同 ABI 并嵌入当前驱动，原有编译警告仍存在；其自动 variant 签名工具卡住后停止该单独子进程，原脚本回退测试签名，信任校验仍失败，不声明可加载/发行签名通过。未运行 CLI 动作、GUI/Light 或加载驱动，也未做 VMware 实测。

## 2026-10-09 WFP 枚举复查（仅构建）

- 单页 560 行的回执仍返回 C00000BB，且 WFP 行明确来自 ResolveApi 失败；分页不是这份证据中的原因。
- fwpkclnt PE 解析原用 MmIsAddressValid 判断候选 header/export/name 的可读性并直接访问，分页被换出可能误报不支持。改为 KswordARKRuntimeReadMemory 完整读取本地字段，不使用有效地址探测或 SEH 代替读取；这修复具体代码缺陷，不证明它就是现场处置后的唯一原因。
- 解析现在使用单次模块快照，记录模块定位及八个导出的独立状态/地址。失败回执行显示模块与每个枚举必需导出；全部解析记录进入 WFP resolve 日志。枚举和移除能力分开，缺少移除专用导出不阻断枚举，也不发布移除候选。
- 驱动 Release/x64、ApiValidator Universal、Inf2Cat 通过且零警告；未加载或执行处置。后续需要逐条保存处置后的枚举与日志才能确定触发操作。

## 2026-10-09 强卸载诊断复查（仅构建）

- 默认 Beep 回执 last=80000011、wait=0，直接参数回执 last/wait=80000011、有效 flags=200；原回执没有具体预检字段，不能确定设备引用、线程或回调哪个阻塞。已有 R0 unload diag 日志输出每步状态和门禁证据，但报告目录中未找到这些日志。
- V2 response reserved2 现在提供 VALID + 到达步骤 + 观察到的阻塞证据；没有修改大小、版本或 IOCTL。原始 requestedFlags 已存在于 reserved，CLI 同步打印 requested/effective/dropped 和可读步骤/证据。旧驱动无 VALID 时仍可调用并明确诊断不可用。
- 前置 communication/dispatch/image 三类未恢复记录分别记录，不再由短路 OR 合并隐藏来源；预检构建失败也捕获已经得到的证据。保留原忙设备、附加链、线程、回调、动态数据和核心模块判定，不强行放行 Beep。
- 共享 ArkDriverClient 两个卸载封装保存 requestedFlags/diagnosticFlags 并进入现有 IoResult.message，GUI/Light 消费同一结构。新增技术诊断字串已定点同步两份语言包。
- 新增 tests/unload_probe 独立 WDM 构建夹具，无设备/回调/线程，只设置自身 DriverUnload；项目与 filters 完整，不进入生产工程。Release/x64、Universal 校验通过，未签名/加载/运行，不声称已有卸载成功样本。
- 生产驱动与 CLI 最终 Release/x64 完整构建通过；驱动零警告、ApiValidator Universal、Inf2Cat 通过。主程序构建脚本 BUILD_RESULT=SUCCESS / EXIT_CODE=0（154 秒），i18n 29269 字串与主题门禁通过。Light 构建通过，保留已有非本次修改的警告；显式跳过驱动签名与驱动重复构建，未执行运行测试。
- 分页读取依据微软 DDI 文档：MmIsAddressValid 要求不可分页地址，MmCopyMemory 会尝试使不驻留的虚拟内存驻留。https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmcopymemory 。当前现场缺少逐导出解析日志，仍需复测确认触发操作。

## 2026-10-09 卸载例程调用与完整卸载语义

- 用户提供 sample2-probe-direct 回执：flags=200 / status=9 / last=0，操作后同一 DriverObject 仍存在；用户报告内核模块也仍在。默认 flags 返回 status=1 并使对象和模块消失，已有完整卸载成功对照。不能把这两种结果都解释为驱动已卸载。
- CLI 的 force-unload-driver 现在只对 status=1 且主操作/等待成功返回 0；status=9 或清理完成 status=7 返回 6（完整卸载未确认）。其他响应失败状态即使 last=0 也返回 3，NTSTATUS 不支持仍为 5。驱动响应、保护策略和 ABI 未修改。
- 对 incomplete 结果自动进行一次只读 QUERY_DRIVER_OBJECT，输出 yes/no/unknown 与查询状态。存在按 BASIC_PRESENT 和非零对象地址确认，缺失仅按明确名称/路径不存在；失效长度/版本/传输或引用错误为 unknown。对象缺失不能替代模块消失证据，也不把 incomplete 升为成功。
- 用户 Beep 新回执 direct 在预检阶段拒绝，evidence=device-reference,preflight-denied；用户报告默认路径到达 zw-verify。此为保护条件拒绝，不能归为卸载通路缺陷，不绕过引用保护。
- 本次只修改 CLI 结果解释、help、文档与共享记忆；CLI Release/x64 完整构建通过，无运行实测。GUI/Light 及生产驱动代码、共享客户端/协议未变化，沿用上次通过的构建与兼容性证据。

## 2026-10-10 R3 接入与 VMware 运行库

- R3 CLI 自动来宾测试必须同时复制统一 Release 中的 `MSVCP140.dll`、`VCRUNTIME140.dll`、`VCRUNTIME140_1.dll`，并核对 EXE 和 DLL 哈希；`tools/test_ksword_cli_r3_vm.py` 已落实。旧 Win10 来宾系统库 14.28.29913 与 HostX64 14.44.35211 构建的 `std::mutex` 不匹配，曾发生 C0000005；本地 dump 的栈和已加载模块确认来源，应用目录使用匹配运行库后消失，不应通过改写锁实现掩盖部署错误。
- 测试脚本与可复现夹具随功能提交；运行报告、dump、编译日志与临时生成的夹具产物放在仓库之外。生产构建不可并行写同一 CLI 工程；曾因重叠构建出现 C1041，正确恢复是串行构建，不是加 `/FS` 隐藏调度问题。
- 令牌后端原始报告可包含查询失败后仍显示“刷新完成”的情况；CLI 使用逐信息类结构化状态。`TokenLinkedToken` 查询返回的句柄由调用方拥有，记录数值后必须关闭；不能把其原始数值当作后续有效操作句柄。
