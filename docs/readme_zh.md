<div align="right">
  <a href="../README.md">English</a> |
  <strong>简体中文</strong>
</div>

<div align="center">

  <img
    src="../Ksword5.1/Ksword5.1/Resource/Logo/KswordHome-ZH.png"
    alt="KSword ARK Logo"
    width="520"
  />

  <a href="https://github.com/user-attachments/assets/25a3b2e2-4ee0-49aa-bd90-ee6e3ba01fe4">
    <img
      src="https://github.com/user-attachments/assets/25a3b2e2-4ee0-49aa-bd90-ee6e3ba01fe4"
      alt="KSword ARK Dark Interface"
      width="49%"
    />
  </a>
  <a href="https://github.com/user-attachments/assets/217769a2-0521-41f9-9933-ca7c2fbb1d13">
    <img
      src="https://github.com/user-attachments/assets/217769a2-0521-41f9-9933-ca7c2fbb1d13"
      alt="KSword ARK Light Interface"
      width="49%"
    />
  </a>

  <br>

  <sub>深色模式 · Dark Mode　｜　浅色模式 · Light Mode</sub>

</div>

<h1 align="center">Ksword5.1</h1>
<p align="center"><strong>源码公开（非 OSI 认证开源许可证）Windows ARK / 内核调试工具集</strong></p>
<p align="center">
  <a href="https://github.com/KSwordDEV/KSword/stargazers">
    <img alt="GitHub stars" src="https://img.shields.io/github/stars/KSwordDEV/KSword.svg?style=for-the-badge" />
  </a>
  <a href="https://github.com/KSwordDEV/KSword/network/members">
    <img alt="GitHub forks" src="https://img.shields.io/github/forks/KSwordDEV/KSword.svg?style=for-the-badge" />
  </a>
  <a href="https://github.com/KSwordDEV/KSword/issues">
    <img alt="GitHub issues" src="https://img.shields.io/github/issues/KSwordDEV/KSword.svg?style=for-the-badge" />
  </a>
  <a href="https://github.com/KSwordDEV/KSword/blob/main/LICENSE">
    <img alt="License" src="https://img.shields.io/github/license/KSwordDEV/KSword.svg?style=for-the-badge" />
  </a>
</p>

---

## 中文

### 项目简介
Ksword5.1 是面向 Windows 的源码公开（“开源”仅表示源码可见）ARK、内核调试与系统取证分析工具集。项目由完整 Qt/ADS 主程序、轻量原生 Win32 版本 `KswordARKLight`、R0 驱动 `KswordARKDriver`、命令行工具、辅助 Taskbar/HUD 和可选安装器组成，覆盖进程、线程、句柄、内存、网络、文件、驱动、内核对象、窗口、注册表、启动项、服务、硬件设备和安全策略等场景。

当前主线重点是 R3/R0 cross-view、PDB/DynData 动态偏移、只读审计证据页和明确的 mutation/safety gate。大量审计页默认只读，涉及驱动卸载、回调移除、磁盘写入、进程保护位修改等高风险操作时，应通过单独入口、显式确认和能力门禁执行。

### 近期更新
- KernelDock 新增双语“内核知识”中心：按 `第二规划.md` 收录 12 类、71 个可全文检索专题；每篇均包含完整八段正文、版本化 R3/R0 现场查询、经中央表核实的业务 IOCTL 来源及对应证据页路由。运行时 unsupported、partial、截断、DynData、权限和硬件限制会继续如实显示。
- 新增独立“扫描器” Dock，可在后台结构化扫描 PE、ELF 和 Mach-O 文件。其可选字节编辑器只允许等长修改，会复核源文件快照、使用原子替换，并在明确确认风险后可保留备份。
- 内核与存储取证新增干净已加载镜像和 IDT 基线、描述符表与 IOCTL 解码工具、内核反汇编、扩展的 R0 网络清单，以及原始文件系统浏览和已删除条目分析。
- HVM 页提供需确认的 VMX 自检、一次性测试来宾与受生命周期保护的 Intel VT-x/EPT 常驻监控，并记录 VM-exit 遥测；AMD、已有 Hypervisor 或电源/拓扑/卸载保护不完整时会由驱动拒绝，仅适用于已获授权的实验和诊断场景。
- 发行包 DynData profile 不匹配时，完整主程序和轻量版可在后台解析精确运行时 PDB profile；只有 PE/PDB 身份校验通过的结果才会被下发。
- 新增表格冻结、平滑滚动和可取消的 UI 卡顿检测器；启动项与网络配置修改也加强了目标校验、恢复和事务处理。

### 组件定位
- `Ksword5.1`：完整 Qt 主程序，使用 ADS Dock 布局，适合完整 ARK/调试/审计工作流。
- `KswordARKLight`：轻量 ARK 工具，面向更早系统和低资源场景；使用原生 Win32/C++ 与手写 Dock/UI，不依赖 Qt，提供精简功能、更快启动和更简洁界面。
- `Launcher`：纯 Win32 启动器与兼容性检查助手，读取发布包中的支持清单后再启动主程序或 Light，并可在发现缺少偏移时准备离线上报文件夹。
- `KswordARKDriver`：R0 驱动，承载进程/线程/句柄/内存/网络/内核对象/设备/安全等协议能力。
- `KswordCLI`：面向自动化、验收和排障的命令行入口。
- `KswordSetup`：可选安装程序，只负责释放发行包文件、创建快捷方式和可选系统集成；直接解压完整 `Release\` 目录可以达到同样运行效果。
- `Taskbar` / `KswordHUD` / `APIMonitor_x64`：桌面辅助、HUD 与 API Monitor 组件。

### 主要能力
- 进程、线程、CID 与句柄 cross-view：R3/R0 枚举对照、隐藏嫌疑标记、线程栈、进程详情、PDB 字段诊断和热键/键盘相关审计。
- 内存与页表取证：进程区域、搜索、Hex、书签/断点、R0 读写路径、内核可执行内存扫描、Kernel/Process memory evidence、PTE/VA 翻译。
- 二进制扫描与受控编辑：PE/ELF/Mach-O 结构化扫描；等长字节修改会复核源快照、原子替换目标，并可选保留备份。
- 网络审计与流量工具：抓包/过滤/连接管理/限速/请求构造/HTTPS 解析、WFP 防火墙事件与规则、NIDS、分段下载，以及 TCP/UDP/AFD/NSI/NDIS/WFP 的 R0 清单和审计视图。
- 驱动与内核对象：驱动服务与模块、DriverObject/DeviceObject/MajorFunction/FastIo、MajorFunction 与 DriverObject/KLDR 镜像/加载链事务编辑器、Driver Integrity、Module Cross-View、Unloaded/PiDDB、干净已加载镜像与 IDT 基线、描述符表/IOCTL 解码、内核反汇编、对象命名空间、SSDT/SSSDT、Inline Hook、IAT/EAT、回调遍历。
- 内核知识中心：71 篇中英文专题、全文检索、R3/R0 请求/CPU/时间/WDF-WDM 现场证据、经中央表核实的业务 IOCTL 映射、Microsoft Learn 官方参考，以及通往现有 KernelDock 证据页的只读导航。
- 文件、存储与设备：双面板文件管理、属性/哈希/签名/PE/字符串/Hex、文件解锁与恢复、Minifilter/FileObject/Section/Storage/BitLocker 证据、原始文件系统和已删除条目取证、硬盘 IO 监控、SetupAPI/CfgMgr 设备树和 R0 设备栈审计。
- 系统安全姿态：AppLocker、WDAC/Code Integrity、Defender/ASR、VBS/Hyper-V、驱动信任、平台安全和事件日志诊断。
- UI 与辅助体验：ADS 布局保存/恢复、可见 Dock 惰性初始化、表格冻结、平滑滚动、可取消的 UI 卡顿检测、顶部菜单设置、UIAccess/置顶策略、日志与任务进度面板、Taskbar 顶部 AppBar 与 `S O S Enter` 快速拉起。

### ARK 功能（按主程序 Dock 分类）
> 以下内容基于近期代码、注释、Dock 初始化逻辑与 R0/R3 协议整理。OpenArk 覆盖对照与缺口 TODO 见：`docs/OpenArk功能对照与TODO.md`。

#### 主工作区 Dock（17 个）
> “设置”已从主 Dock 移到顶部菜单，主工作区包括“扫描器”和“杂项”。

| 一级 Dock | 二级页 / 关键区 | 主要功能 |
|---|---|---|
| 欢迎 | 欢迎页主体 | 展示版本、编译时间、用户信息、头像和项目入口。 |
| 进程 | 进程列表、创建进程、详情窗口、线程、模块、令牌、Cross-View、PDB Catalog | 进程树/列表、图标与差异高亮、结束/挂起/恢复/优先级/关键进程/R0 可恢复隐藏、R3/R0 进程线程对照、线程栈、PPL/Signature/CID 等高风险操作提示。 |
| 网络 | 流量监控、进程限速、连接管理、请求构造、HTTPS、ARP/DNS、存活主机、防火墙、NIDS、下载、网络审计 | 抓包过滤、TCP/UDP 连接管理、WFP 防火墙事件与规则、实时检测、分段 HTTP/HTTPS 下载，以及 TCP/UDP/AFD/NSI/NDIS/WFP 的只读 R0 清单和 cross-view。 |
| 内存 | 进程与模块、区域、搜索、查看器、断点/书签、R0 读写、Kernel Exec Scan、Memory Evidence、PTE | R3 内存浏览与搜索、R0 区域读取、内核可执行内存扫描、内核/进程内存证据、页表项与虚拟地址翻译。 |
| 文件 | 文件管理、文件恢复、属性、解锁、Minifilter、FileObject、Section、Storage/BitLocker | 双面板管理、权限接管、哈希/签名/PE/字符串/Hex、NTFS 恢复、文件占用与 Section 映射、存储栈与 BitLocker 只读证据。 |
| 扫描器 | 结构化扫描、安全字节编辑 | 在后台结构化扫描 PE、ELF 与 Mach-O。可选编辑器只允许等长修改，需明确确认风险；它会复核原始快照、原子替换目标，并可保留备份。 |
| 驱动 | 驱动概览、驱动操作、调试输出、对象信息、完整性、模块 Cross-View、Unloaded/PiDDB | 驱动服务注册/加载/卸载/删除、已加载模块、DBWIN 输出、DriverObject/DeviceObject/MajorFunction/FastIo、MajorFunction/镜像字段原子事务、加载链摘除与恢复、Driver Integrity、Unloaded/PiDDB 证据和只告警、显式确认的操作入口。 |
| 内核 | 对象命名空间、原子表、NtQuery、SSDT、SSSDT、Inline Hook、IAT/EAT、CID、IPC、DynData、驱动状态、回调、基线、HVM、内核知识 | 对象目录递归、BaseNamedObjects、NamedPipe、符号链接、设备/驱动对象、对象类型矩阵、CID/cross-view、ALPC/IPC、动态偏移、能力矩阵、干净已加载镜像与 IDT 基线、描述符表/IOCTL 解码、内核反汇编和回调遍历/管理。“内核知识”新增 71 篇双语可搜索文章、版本化 R0 现场上下文/来源查询、官方参考和通往现有证据页的只读路由，并保留运行态降级。回调清单覆盖 Notify、注册表、对象、过滤器、BugCheck、Shutdown、文件系统、登录会话、CallbackObject、镜像验证与 NMI 来源，并展示模块归属及 v3 快照/逐行身份诊断。HVM 流程对 VMX 自检、一次性测试来宾和受保护的 Intel VT-x/EPT 常驻监控设有显式确认。 |
| 监控 | 进程定向、直接内核调用、WinAPI、WMI、ETW、Risk Center | 目标进程树 ETW、syscall 采集、WinAPI Agent、WMI 订阅、ETW Provider/Session 管理、ARK 风险聚合。 |
| 硬件 | 利用率、概览、CPU、GPU、内存、硬盘监控、设备管理、R0 设备审计 | 任务管理器风格性能页、磁盘/网络/GPU 动态卡片、进程 IO 与 ETW 文件活动、SetupAPI/CfgMgr 设备树、DevNode/USB/HID/PCI/ACPI/GPU/display/watchdog 审计。 |
| 权限 | 账号、权限 | 本地用户、创建用户/重置密码、组信息和当前进程权限快照。 |
| 窗口 | 窗口列表、桌面/窗口详情、Win32k/GUI、热键/Hook、剪贴板、GPU/Display | 窗口枚举、筛选、预览、拾取、控制、桌面管理、消息监控、win32k GUI/session 与热键/Hook 结构化审计。 |
| 注册表 | 树、值列表、搜索结果 | 注册表浏览、键值增删改查、导入/导出 `.reg`、异步搜索和跳转。 |
| 句柄 | 句柄列表、对象类型、对象详情 | 按 PID/关键字/类型过滤，命名对象解析，对象类型统计，HandleTable/ObjectHeader/ObjectType 证据。 |
| 启动项 | 总览、登录、服务、驱动、计划任务、高级注册表、WMI | 启动项分类汇总、图标渲染、过滤/导出、定位文件和注册表位置；所有真实来源取消只读保护，改为展示风险等级、影响、恢复能力后由用户确认修改。注册表值和启动文件夹使用备份/暂存恢复，计划任务启停后复核，服务与驱动修改 SCM 启动类型；WMI 禁用和 Winsock/整子键删除属于明确标记的不可恢复操作。 |
| 服务 | 服务主表、常规、登录、恢复、依存关系、审计 | 服务筛选排序、启动类型调整、启动/停止/暂停/继续、属性编辑、依赖和审计信息、TSV/JSON 导出。 |
| 杂项 | 引导、声音来源、系统变速、Shell 关联管理、磁盘编辑、原始文件系统取证、应用控制 | BCD/引导相关入口；Core Audio 声音来源归因；带永久警告、双重确认和恢复路径的 R0 系统全局加速/减速；右键菜单、URL 绑定、文件打开方式、按格式右键菜单及资源管理器主页第三方程序管理；默认只读的磁盘编辑、原始文件系统浏览和已删除条目分析（写入需解锁）；AppLocker/WDAC/Defender/ASR/平台安全/事件日志诊断。 |

#### 辅助面板 Dock
| 面板 | 关键区 | 主要功能 |
|---|---|---|
| 当前操作 | 任务卡片 | 展示后台任务步骤和进度，完成后自动隐藏。 |
| 日志输出 | 级别过滤、日志表格、右键菜单 | 日志过滤、复制、导出、双重确认清空、GUID 调用链追踪。 |
| 即时窗口 | 代码/文本编辑器 | 快速验证、临时记录和即时输出。 |
| 监视面板 | CPU/内存/磁盘/网络图 | 底部实时性能监视，显示多曲线吞吐趋势。 |

### KswordARKLight 轻量版
`KswordARKLight` 是为更早系统、低资源环境和快速处置场景准备的轻量 ARK：

- 原生 Win32/C++ 实现，入口、Dock、控件、主题和占位页均不依赖 Qt。
- 模块按需加载：启动时先创建廉价占位页，Dock 激活后再物化真实页面，降低启动卡顿。
- 当前模块包括：进程、内存、注册表、文件、驱动、内核、监控、硬件、窗口、启动项、网络、句柄、杂项安全。
- 复用 `shared/driver/` 协议和 `ArkDriverClient` 风格封装，已经接入真实 KswordARK 驱动调用。
- `DriverService` 可在需要时从 EXE 资源恢复 `KswordARK.sys`，并通过 SCM 安装、启动、停止和查询服务状态。
- 已完成轻量版内核 UI 分层、监控/窗口/启动项/文件/进程图标、进程差异高亮、驱动页详情和卸载 IOCTL 等更新。

### KswordSetup 安装器说明
`KswordSetup` 只是发行包便利安装器，不是运行时必需组件：

- 构建脚本会把 `Release\` payload 作为 RCDATA 嵌入安装器。
- 安装时释放文件、可选写入外观/启动配置、创建桌面/开始菜单快捷方式。
- 需要时可触发 UAC，用于任务管理器替换、测试签名等系统级选项。
- 如果已经拿到完整 `Release\` 目录，直接解压到目标目录并运行主程序即可，效果等同于安装器释放文件。

### ARK 协作架构约定
- R0/R3 共享协议统一位于 `shared/driver/`；新增 IOCTL 头、结构体和版本字段不要散落在 UI 或驱动私有目录。
- 驱动 IOCTL 分发通过 `KswordARKDriver/src/dispatch/ioctl_registry.c` 注册 handler；`ioctl_dispatch.c` 只负责查表、校验、调用、日志和完成请求。
- 用户态访问 KswordARK 驱动统一通过 `Ksword5.1/Ksword5.1/ArkDriverClient/` 或轻量版对应封装，Dock/UI 不直接打开设备或调用 `DeviceIoControl`。
- PDB/DynData 当前以 `tools/pdb_offset_generator/` 生成的 v4 profile pack 为基础；发行包只携带压缩后的 `ark_dyndata_pack_v4.json.qz`。旧 v1/v2/v3 偏移矩阵不再发布，v4 core item 在 R3 内存中投影到 EX 请求以保持现有功能。
- 依赖未公开字段的 R0 功能必须声明所需 capability，dispatch 层在 handler 前执行 gate；DynData 缺失或 profile 不匹配时应降级或 fail closed。
- 默认审计页应只读；卸载、删除、patch、bypass、磁盘写入等 mutation 类能力必须走独立入口、风险提示和回滚/审计策略。
- DynData 第一阶段使用 `third_party/systeminformer_dyn/` 中 vendored System Informer 动态偏移数据；Ksword 只接入 `KphDynConfig` 数据和轻量解析器，不引入 KPH 通信层、对象系统或 session token。
- DynData R0/R3 协议集中在 `shared/driver/KswordArkDynDataIoctl.h`，KernelDock 的“动态偏移”页通过 `ArkDriverClient` 展示 profile 命中、字段来源和 capability gating；KswordARK 驱动装载后主窗口会立即触发 DynData profile 自动刷新与下发。
- 当发行包 profile 未命中时，完整主程序和轻量版可在串行后台 DbgHelp 会话中解析精确运行时 PDB profile。只有 PE/PDB 身份校验通过时才会下发；不支持或不匹配的数据不会跨版本猜测偏移。
- 进程扩展信息使用 `shared/driver/KswordArkProcessIoctl.h` v2 协议传递 Session、完整镜像路径、Protection/SignatureLevel、ObjectTable/SectionObject 可用性、字段来源和 DynData capability；ProcessDock/ProcessDetail 只展示可用性，不在 DynData 缺失时直接枚举句柄表或 Section。
- R0 可恢复进程隐藏使用 `IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY`，驱动同时修改 `_EPROCESS.UniqueProcessId` 并摘除 `ActiveProcessLinks`，保留 PspCidTable 记录以便按原 PID 恢复。
- 驱动统一状态/能力协议集中在 `shared/driver/KswordArkCapabilityIoctl.h`；KernelDock 的“驱动状态”页展示 Driver Loaded/Missing、Protocol Mismatch、DynData Missing、Limited、安全策略、最近 R0 错误和功能能力矩阵。
- R0 PPL 修改必须依赖 `KSW_CAP_PROCESS_PROTECTION_PATCH`，并在用户态确认框展示当前/目标 Protection、SignatureLevel 影响、字段来源和回滚风险。
- 新增源码必须同步更新对应 `.vcxproj` 和 `.vcxproj.filters`；第三方代码接入必须保留上游许可证文本。


### 工程结构
- `Ksword5.1/`：主解决方案与 Qt/ADS 主程序源码。
- `KswordARKLight/`：轻量原生 Win32 ARK。
- `KswordARKDriver/`：KswordARK R0 驱动。
- `shared/driver/`：R0/R3 共享 IOCTL 协议头。
- `KswordCLI/`：命令行工具与自动化验收入口。
- `KswordSetup/`：可选安装器与 payload 资源生成脚本。
- `Taskbar/`：顶部 AppBar、状态展示和 SOS 快速拉起主程序。
- `KswordHUD/`：HUD 辅助程序。
- `APIMonitor_x64/`：API Monitor 注入/监控组件。
- `tools/pdb_offset_generator/`：PDB offset/profile pack 生成与校验工具。
- `docs/pdb_r0_audit_prep/`：PDB/R0 审计能力准备、接入和验收文档。
- `third_party/systeminformer_dyn/`：System Informer DynData 快照、LICENSE/NOTICE 和 Ksword 包装头。
- [KSwordDEV/Website](https://github.com/KSwordDEV/Website)：独立维护的项目官网和模块介绍页面。

### 构建环境
- Windows 10/11 x64。
- Visual Studio 2022 / MSVC / MSBuild。
- Qt 6.9.3 `msvc2022_64`（主程序、Taskbar、HUD 需要；`KswordARKLight` 不依赖 Qt）。
- 驱动构建需要匹配 WDK；用户态组件可单独构建。

### 快速构建
建议先用仓库脚本发现并写入本机 Qt 路径，避免把个人路径写进各 `.vcxproj`：

```powershell
# 在仓库根目录执行；路径按本机安装位置替换
.\Setup-QtPaths.ps1 -QtDir 'C:\Qt\6.9.3\msvc2022_64'

# MSBuild 路径按本机 VS 安装位置替换；本机也可直接使用 Developer PowerShell 中的 msbuild
$msbuild = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'

# 构建完整解决方案（主程序、Taskbar、HUD、驱动、CLI、安装器、轻量版等项目均在解决方案内）
& $msbuild '.\Ksword5.1\Ksword5.1.sln' /t:Build /p:Configuration=Debug /p:Platform=x64 /m
```

只构建轻量版：

```powershell
& $msbuild '.\KswordARKLight\KswordARKLight.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /m
```

构建原生 Launcher 并生成可直接阅读的支持清单：

```powershell
& $msbuild '.\Launcher\Launcher.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /m
```

如当前机器没有 WDK 或驱动签名环境，可以先构建用户态项目；发行包制作时可沿用已有未签名 R0 Release 产物。

### 发行与运行
- 发行包根目录应为 `Release\`，包含 `Launcher.exe`、主程序、轻量版/辅助程序、驱动、`profiles\launcher_support_manifest.json`、DynData packs、Qt 依赖和插件目录。
- `KswordSetup.exe` 是可选安装体验；直接解压 `Release\` 后应运行 `Launcher.exe`，由它选择并启动主程序或 Light。
- R0 功能需要管理员权限、驱动服务和匹配的系统安全策略；测试签名/驱动签名要求取决于当前系统配置。

### 项目网站
[KSwordDEV/Website](https://github.com/KSwordDEV/Website) 独立维护项目官网和模块介绍页面。

### 声明
本项目包含系统级调试、审计和管理能力，请仅在合法授权和合规场景下使用。

---

### 许可证

Ksword 按 [KSword Community Source License v1.6](../LICENSE) 发布。这里的“开源”仅表示源码公开，不代表本项目使用 OSI 认证的开源许可证类型。许可边界请以 `LICENSE` 为准；第三方组件继续使用它们自己的许可证。

除另有文件说明外，Ksword 自有代码均按 `LICENSE` 所载许可约束发布。
`COMMUNITY_COVENANT.md` 是关于诚实、署名、负责任使用，以及不要把非官方 fork
冒充官方的社区约定，不是另一层许可限制。贡献规则见 `CONTRIBUTING.md`。
