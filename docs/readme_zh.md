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
<p align="center"><strong>源码公开的 Windows ARK（反内核隐藏）与内核分析工具集</strong></p>

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

KSword 是 Windows 10/11 x64 上的 ARK（Anti-Rootkit）和系统分析工具。它自带一个内核驱动——桌面程序从用户态枚举进程、驱动、连接等，驱动从 Ring 0 做同样的事，然后两边对照。对不上的东西就是在藏。

除了 cross-view，还有一整套系统工具：内存搜索和 Hex 编辑、PE/ELF/Mach-O 扫描、抓包、原始 NTFS 取证、SSDT/回调/Hook 检查、注册表和启动项审计、设备栈追踪、安全策略检查——大概相当于把十来个工具合到一个窗口里。

所有审计页默认只读。修改系统的操作（卸载驱动、写磁盘、改保护等级之类的）走单独的按钮，有确认对话框，能撤销的都能撤销。当前系统缺某个内核偏移或功能时，界面直接报"不支持"，不会猜。

按 [KSword Community Source License v1.6](../LICENSE) 源码公开（不是 OSI 认证的开源许可证——见[许可证](#许可证)）。

## 快速开始

解压发行包，管理员运行 `Launcher.exe`。它会读支持清单然后启动对应的版本。

`KswordSetup.exe` 是可选的安装器，多了快捷方式创建之类的功能。

> [!IMPORTANT]
> R0 功能需要 KswordARK 驱动已加载。没驱动程序照常能用，内核侧的页面会显示"不可用"。

## 两个版本

|  | Ksword5.1 | KswordARKLight |
|---|---|---|
| 技术栈 | Qt 6 / ADS 可停靠工作区 | 原生 Win32，零运行时依赖 |
| 场景 | 完整工作流 | 老机器、快速应急、极简部署 |

两者用同一个驱动和同一套 `shared/driver/` 协议。Launcher 自动选。

## 功能

**进程 / 线程 / 句柄** — 树和列表视图，R3/R0 cross-view 查隐藏对象，线程栈、模块、令牌、PDB 诊断。结束、挂起、R0 隐藏（可恢复）、PPL 修改等操作有门禁。

**内存** — 区域浏览、特征搜索、Hex 查看、书签、R0 读取、内核可执行内存扫描、PTE 翻译。

**扫描器** — PE / ELF / Mach-O 结构分析。字节编辑只允许等长修改，写之前校验源快照，原子替换，可选备份。

**网络** — 抓包过滤、连接管理、按进程限速、请求构造、HTTPS 检查、WFP 防火墙、NIDS、分段下载。R0 清单：TCP / UDP / AFD / NSI / NDIS / WFP。

**驱动 / 内核** — 服务管理，DriverObject / DeviceObject / MajorFunction 检查，事务式派发表编辑器，加载链摘除（可恢复），完整性和 cross-view 检查，已卸载驱动 / PiDDB 证据。对象命名空间、SSDT/SSSDT、IAT/EAT/inline Hook、回调（notify、注册表、对象、filter、bugcheck、shutdown、FS、logon、NMI……）、IDT 基线、描述符表和 IOCTL 解码、反汇编。

**文件 / 存储** — 双面板管理器、哈希、签名、PE/字符串/Hex、解锁、NTFS 恢复、minifilter 和 Section 证据、原始文件系统浏览和已删除条目分析（默认只读，写入需解锁）、设备树和 R0 设备栈审计。

**监控** — 按进程 ETW、syscall 采集、WinAPI agent、WMI 订阅、ETW session 管理、风险中心。类任务管理器的实时图表。

**窗口 / 注册表 / 句柄 / 启动项 / 服务 / 权限** — 该有的都有，外加 Win32k GUI 审计、启动项风险门禁（带恢复）、服务 TSV/JSON 导出。

**安全** — AppLocker、WDAC、Defender/ASR、VBS/Hyper-V、驱动信任、事件日志。

**内核知识** — 71 篇中英双语可搜索文章，每篇链接到 R3/R0 实时证据页。

**HVM** — VMX 自检、一次性来宾、受保护的 Intel VT-x/EPT 常驻监控，支持多核。EPT 分离视图（execute-only 影子页）由 EPTP 切换后端服务，因此在不提供 monitor-trap flag 的嵌套 hypervisor 上也能装 Hook。带引导的 EPT Hook 向导。R-1 层的进程冻结与结束。AMD 或不兼容配置下拒绝启动。仅限实验用途。

<details>
<summary>这一层在哪里，以及"常驻"是什么</summary>

<br>

KSword HVM **不启动第二个 Windows**。它对**已经在跑的**那个系统做一次后期虚拟化接管：
`VMLAUNCH` 之后，原本的执行上下文原地继续往下跑，只是从此运行在 VMX non-root 模式，
而 KSword HVM 在 VMX root 模式处理它的 VM exit。没有重启，桌面上什么都不会发生 ——
所以"看不出变化"是正确表现，不是没生效。

```text
CPU
└─ Intel VT-x / EPT
   └─ Hyper-V (L0)              ← 拥有物理虚拟化层
      ├─ 根分区
      │  ├─ 宿主 Windows
      │  └─ VBS / HVCI          ← 可以继续开着，它属于 L0
      │
      └─ 子分区
         └─ KSword HVM (L1, VMX root)
            └─ 同一个来宾 Windows
               （L2, VMX non-root）
```

裸机上没有 `Hyper-V (L0)` 这一层，KSword HVM 自己就是 L0。两种情形下，接管前后
都是**同一个**操作系统。

**常驻**就是这一层存在与否本身。一次性来宾只证明 VMX 能进能出；常驻把正在运行的
Windows 放进 non-root 并保持在那里。停掉常驻，硬件不再查我们的 EPT，所有基于 EPT
的能力 —— 隐蔽 Hook、分离视图、执行域、R-1 进程处置 —— **在同一瞬间全部失效**，
不是降级，是那一层不在了。这也解释了为什么安装这些能力都要求先停常驻，以及为什么
`sc stop` 在常驻期间返回 1052。

完整说明见[嵌套虚拟化架构](next/嵌套虚拟化架构.md)。

</details>

<details>
<summary>按 Dock 展开的完整清单（17 主 + 4 辅助）</summary>

<br>

另见 [docs/OpenArk功能对照与TODO.md](OpenArk功能对照与TODO.md)。

| Dock | 内容 |
|---|---|
| **欢迎** | 版本、构建信息、项目链接。 |
| **进程** | 树/列表 + 图标和差异高亮。结束/挂起/恢复/优先级。线程栈、模块、令牌。R3/R0 cross-view。可恢复 R0 隐藏（有门禁）。PPL/签名操作有风险提示。 |
| **网络** | 抓包过滤。TCP/UDP 管理。按进程限速。请求构造器。HTTPS。ARP/DNS。存活主机。WFP 事件和规则。NIDS。分段下载。R0 网络栈清单。 |
| **内存** | 区域浏览和搜索。Hex + 书签/断点。R0 读取。内核可执行扫描。内存证据。PTE/VA 翻译。 |
| **文件** | 双面板管理。哈希/签名/PE/字符串/Hex。解锁。NTFS 恢复。Minifilter/FileObject/Section 证据。存储和 BitLocker。 |
| **扫描器** | PE/ELF/Mach-O 结构化扫描。安全字节编辑（等长、原子、可选备份）。 |
| **驱动** | 服务增删改查。已加载模块。DBWIN。DriverObj/DeviceObj/MajorFunction/FastIo。事务式编辑器。可恢复加载链摘除。完整性。Module cross-view。Unloaded/PiDDB 证据。 |
| **内核** | 对象命名空间。原子表。SSDT/SSSDT。Inline/IAT/EAT Hook。CID cross-view。ALPC/IPC。DynData。能力矩阵。已加载镜像和 IDT 基线。描述符/IOCTL 解码。反汇编。回调清单。内核知识（71 篇）。HVM。 |
| **监控** | 进程 ETW。Syscall 采集。WinAPI agent。WMI 订阅。ETW session 管理。风险中心。 |
| **硬件** | CPU/GPU/内存/磁盘/网络图表。进程 I/O 和 ETW 文件活动。SetupAPI/CfgMgr 树。R0 设备审计。 |
| **权限** | 本地账号、组、当前进程权限。 |
| **窗口** | 窗口枚举/筛选/预览/拾取/控制。桌面管理。消息监控。Win32k GUI/session 审计。热键/Hook 审计。 |
| **注册表** | 树浏览。键值增删改查。.reg 导入导出。异步搜索。 |
| **句柄** | 按 PID/关键字/类型过滤。命名对象解析。类型统计。HandleTable/ObjectHeader 证据。 |
| **启动项** | 分类覆盖 logon/服务/驱动/任务/注册表/WMI。修改有风险门禁和恢复。 |
| **服务** | 筛选排序。启停。启动类型。属性编辑。依赖关系。TSV/JSON 导出。 |
| **杂项** | BCD/引导。声音来源归因。系统变速（有警告）。Shell 关联管理。只读磁盘编辑和原始 FS 取证（写入要解锁）。AppLocker/WDAC/Defender/ASR 诊断。 |

辅助面板：任务进度、带 GUID 调用链追踪的日志输出、即时窗口、实时性能监视。

</details>

## 仓库结构

```
Ksword5.1/              完整 Qt 主程序
KswordARKLight/          轻量 Win32 版
KswordARKDriver/         内核驱动
Launcher/                启动助手
KswordCLI/               命令行工具 (文档: docs/CLI使用文档.md)
KswordSetup/             可选安装器
Taskbar/                 顶部 AppBar (S O S Enter 快速拉起)
KswordHUD/               HUD 覆盖
APIMonitor_x64/          API 监控辅助
shared/driver/           共享 IOCTL 协议头
tools/                   PDB 偏移生成器等构建工具
docs/                    技术文档
```

项目网站：[KSwordDEV/Website](https://github.com/KSwordDEV/Website)

## 构建

需要：Windows 10/11、VS 2022 (MSVC)、Qt 6.9.3 msvc2022_64（轻量版/Launcher 不需要）、WDK（只有驱动需要）。

```powershell
.\Setup-QtPaths.ps1 -QtDir 'C:\Qt\6.9.3\msvc2022_64'

$msbuild = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
& $msbuild '.\Ksword5.1\Ksword5.1.sln' /t:Build /p:Configuration=Debug /p:Platform=x64 /m
```

只要轻量版：`& $msbuild '.\KswordARKLight\KswordARKLight.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /m`

没 WDK？先构建用户态项目，驱动复用已有的二进制。

<details>
<summary>构建排障</summary>

<br>

**主程序 LNK1000 / IMAGE::BuildImage** — 关 WPO 和 LTCG 做一次干净重建（不要改项目文件）。确认退出码和 `Ksword5.1\x64\Release\Ksword5.1.exe` 非零。

**驱动 ApiValidator 在链接后失败** — 一般是架构选错。单独跑：

```powershell
$solutionDir = (Resolve-Path '.\Ksword5.1').Path + '\'
$apiValidatorX64 = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64'
& $msbuild '.\KswordARKDriver\KswordARKDriver.vcxproj' /t:ApiValidator `
  /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=$solutionDir `
  /p:ApiValidator_ApiExtractorExePath=$apiValidatorX64 /m:1 /v:minimal
```

</details>

## 贡献

协议头放 `shared/driver/`，UI 只通过 `ArkDriverClient` 访问驱动，内核偏移来自经过验证的 PDB/DynData profile（不硬编码），新文件要加 `.vcxproj` + `.vcxproj.filters`。

详见：[CONTRIBUTING.md](../CONTRIBUTING.md) · [AGENTS.md](../AGENTS.md)

<details>
<summary>协议索引</summary>

<br>

头文件都在 `shared/driver/` 下。

| 领域 | 头文件 | 说明 |
|---|---|---|
| 驱动状态 / 能力 | `KswordArkCapabilityIoctl.h` | 驱动状态页的数据来源。 |
| 动态偏移 | `KswordArkDynDataIoctl.h` | Profile 匹配、字段来源、能力门禁。 |
| 进程扩展信息 | `KswordArkProcessIoctl.h` (v2) | Session、镜像路径、保护级别、字段可用性。 |
| 进程隐藏 | `IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY` | 从链表摘除，保留 CID 记录可恢复。 |
| PPL 修改 | `KSW_CAP_PROCESS_PROTECTION_PATCH` | 有门禁，对话框展示影响和回滚风险。 |
| vendored 偏移 | `third_party/systeminformer_dyn/` | 只用了 System Informer 的偏移数据，没引 KPH 通信。 |

</details>

## 文档

[CLI使用文档](CLI使用文档.md) · [功能技术文档](功能技术文档.md) · [内核知识中心](内核知识中心.md) · [IOCTL 审计](driver_ioctl_audit.md) · [OpenArk对照](OpenArk功能对照与TODO.md) · [动态偏移接入](动态偏移功能接入步骤.md) · [PDB/R0 审计准备](pdb_r0_audit_prep/) · [插件系统](插件系统规范.md) · [多语言规范](多语言语言包规范.md)

虚拟化（HVM）：[嵌套虚拟化架构](next/嵌套虚拟化架构.md) · [EPT切换后端设计](next/EPT切换后端设计.md) · [嵌套下的跨核TLB失效](next/嵌套下的跨核TLB失效.md) · [隐蔽Hook安全边界决策](next/隐蔽Hook安全边界决策.md) · [自动化测试](next/自动化测试.md) · [VM测试机搭建](next/VM测试机搭建.md)

## 声明

本项目包含系统级调试、审计和管理能力，仅限在合法授权的环境中使用。

## 许可证

按 [KSword Community Source License v1.6](../LICENSE) 源码公开。这里说的"开源"指源码可见，不是 OSI 认证的开源许可证。再分发和商用条款以 `LICENSE` 为准。

[社区公约](../COMMUNITY_COVENANT.md) 是关于署名和负责任使用的约定，不是额外的许可限制。贡献规则见 [CONTRIBUTING.md](../CONTRIBUTING.md)。
