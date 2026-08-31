# KswordARKLight 调查工作台骨架

## 驱动生命周期

- `Core/DriverLease` 用命名 mutex + file mapping 维护跨进程租约，租约身份是 PID + 进程创建时间，读取时清理死亡或 PID 复用条目。
- 只有观测到 `未运行 -> 运行` 的 Light 实例把驱动标记为 Light 所有；退出时仅在“Light 所有且最后一个租约释放”时请求停驱动。预先运行的驱动必须保留。
- 手工卸载会清除所有权；租约注册失败时采取 fail-safe，自动退出不得停驱动。纯决策放在 `DriverLeasePolicy`，供无窗口测试复用。

## 通用懒加载工作区

- `Ui/WorkspaceHost` 是二级 tab 的统一宿主：稳定 tab id、placeholder、异步首次物化、同步命令路由物化、失败重试、布局和激活回调都由宿主维护。
- “已投递”和“正在创建”必须是两个状态；同步导航可越过已投递但尚未执行的消息，不能把 placeholder 错当成真实页面。
- Hardware、Driver、Network、Window、SysTools 使用该宿主。重采样或重枚举动作应放在真实页面 factory 或首次激活回调，不放在外层模块创建阶段。

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
