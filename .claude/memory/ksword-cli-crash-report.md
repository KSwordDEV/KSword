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
