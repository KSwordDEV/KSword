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

KSword 是 Windows 10/11 x64 上的 ARK（Anti-Rootkit）和系统分析工具。桌面程序与内核驱动对照用户态和 Ring 0 的进程、驱动、连接等视图。差异是调查线索，需要结合采集能力、采样时序和正常系统行为判断，不能仅凭差异认定隐藏。

除了 cross-view，还有一整套系统工具：内存搜索和 Hex 编辑、PE/ELF/Mach-O 扫描、抓包、原始 NTFS 取证、SSDT/回调/Hook 检查、注册表和启动项审计、设备栈追踪、安全策略检查——大概相当于把十来个工具合到一个窗口里。

检查与修改系统的操作使用独立入口。卸载驱动、原始磁盘写入、保护级别修改等敏感操作有各自的能力检查和确认流程，支持恢复的操作提供恢复入口；缺少偏移或功能时明确显示不可用原因。

按 [KSword Community Source License v1.6](../LICENSE) 源码公开（不是 OSI 认证的开源许可证——见[许可证](#许可证)）。

## 快速开始

解压发行包，管理员运行 `Launcher.exe`。它会读支持清单然后启动对应的版本。

`KswordSetup.exe` 是可选的安装器，多了快捷方式创建之类的功能。

> [!IMPORTANT]
> R0 功能需要 KswordARK 驱动已加载。没驱动程序照常能用，内核侧的页面会显示"不可用"。

驱动最低要求 OS build 16299。Launcher 与驱动已取消 OS build 上限拦截；内核功能仍取决于精确 PE/PDB profile 和逐功能校验，更高 Windows build 不等于已验证配置。

## 两个版本

|  | Ksword5.1 | KswordARKLight |
|---|---|---|
| 技术栈 | Qt 6 / ADS 可停靠工作区 | 原生 Win32，零运行时依赖 |
| 场景 | 完整工作流、HVM 工作区、插件集成 | 快速应急、证据工作区、极简部署 |

两者使用同一个驱动和同一套 `shared/driver/` 协议，由 Launcher 根据支持清单选择版本。Light 已加入二级页懒加载、进程/实体导航、证据快照与行级差异、可选用户路径脱敏的 JSON/TSV 导出，以及跨进程驱动租约；Light 退出时保留启动前已经运行的驱动。Qt 插件和统一 Qt 内存编辑器属于完整版本。

## 功能

**进程 / 线程 / 句柄** — 树和列表视图、R3/R0 cross-view、线程栈、模块、令牌、PDB 诊断，以及区分异常证据与采集缺口的注入痕迹检查。结束、挂起、R0 隐藏（可恢复）、PPL 修改等操作有门禁。

**内存** — 区域浏览、特征搜索、书签、内核可执行内存扫描和 PTE/VA 翻译。完整版本共用 Hex/反汇编/文本/字节对比快照编辑器，支持 x86/x64 Intel 汇编、补丁预览、本地撤销/重做与显式应用。写回绑定读取时的目标和后端，写前比对原字节，完成后以实际回读核验；本地撤销不撤销已提交写入。按页面与能力选择 R3、标准 R0、私有页表窗口或 **DDMA**，常驻 R-1 访问使用独立流程。见[内存编辑器组件清单](内存编辑器组件清单.md)。

<details>
<summary>DDMA 条件与边界</summary>

<br>

DDMA 使用磁盘控制器的 `ATA_PASS_THROUGH_DIRECT` / `SCSI_PASS_THROUGH_DIRECT` 通道访问物理页，并可与 CPU 通道读取同一地址进行比较。真实硬件上的 DMA 可采用与 CPU 不同的地址翻译路径，但仍受 IOMMU、控制器和存储驱动栈限制；虚拟机内模拟 DMA 不能保证绕过外层地址翻译。NVMe、SAS/SATA、合成 SCSI 的兼容性需按实际驱动栈确认。

必须显式选择暂存 LBA 并确认风险，没有默认扇区。LBA 0 是合法目标，也可能包含 MBR。每次操作备份、使用并恢复暂存区，恢复失败会明确报告。启用内核调试时通道拒绝执行；非整页写入使用读改写，存在同页并发更新窗口。

`KswordCLI.exe ddma selftest` 默认只检查能力和拒绝路径，不写磁盘扇区；添加 `--lba N` 会在指定 LBA 发起真实 ATA/SCSI 磁盘读取探测，仍不写扇区。这与 `ddma read` 的物理内存读取不同，后者会备份、写入并恢复暂存扇区。仅限实验用途。技术来源：[btbd/ddma](https://github.com/btbd/ddma)。

</details>

**扫描器** — PE / ELF / Mach-O 结构分析。字节编辑只允许等长修改，写之前校验源快照，原子替换，可选备份。

**网络** — 抓包过滤、连接管理、按进程限速、请求构造、HTTPS 检查、WFP 防火墙、NIDS、分段下载。R0 清单：TCP / UDP / AFD / NSI / NDIS / WFP。

**驱动 / 内核** — 服务管理，DriverObject / DeviceObject / MajorFunction 检查，事务式派发表编辑器，加载链摘除（可恢复），完整性和 cross-view 检查，已卸载驱动 / PiDDB 证据。对象命名空间、SSDT/SSSDT、IAT/EAT/inline Hook、回调（notify、注册表、对象、filter、bugcheck、shutdown、FS、logon、NMI……）、IDT 基线、描述符表和 IOCTL 解码、反汇编。

**文件 / 存储** — 双面板管理器、哈希、签名、PE/字符串/Hex、解锁、NTFS 恢复、minifilter 和 Section 证据、原始文件系统浏览和已删除条目分析（默认只读，写入需解锁）、设备树和 R0 设备栈审计。

**监控** — 按进程 ETW、syscall 采集、WinAPI agent、WMI 订阅、ETW session 管理、风险中心。类任务管理器的实时图表。

**调试器 / 插件** — 可执行插件、UI 插件、插件市场，以及可选的独立 64 位 Cheat Engine / x64dbg 集成，共用 KSword 调试后端。KSword Tab 提供控制和日志，调试器保留自己的窗口；原生调试不依赖驱动。R0/HVM 通路、隐藏执行断点及可选 Shadow 执行页写入取决于策略与能力，不支持的数据断点和回退路径会明确报告。见[调试器验证与边界](ksword-debugger-vm-validation.md)。

**窗口 / 注册表 / 句柄 / 启动项 / 服务 / 权限** — 该有的都有，外加 Win32k GUI 审计、启动项风险门禁（带恢复）、服务 TSV/JSON 导出。

**安全** — AppLocker、WDAC、Defender/ASR、VBS/Hyper-V、驱动信任、事件日志。

**剪贴板保护** — 进程/全局规则分别控制读取、写入和枚举的允许、记录、阻止动作。匹配 x86/x64 架构的 Agent 上报 Hook 就绪与访问事件；实际覆盖取决于注入和会话访问成功。

**崩溃分析** — 转储检查、BugCheck 证据，以及截图与崩溃前缓存归因。可选 Shield 通过公共 BugCheck 回调提供有界诊断缓冲，不保证防止蓝屏或从任意内核错误恢复。

**内核知识** — 71 篇中英双语可搜索文章，每篇链接到 R3/R0 实时证据页。

**HVM / KVM 工作区** — 受保护的多核 Intel VT-x/EPT 常驻、嵌套 VMX 分派与 shadow EPT 合成、EPT 分离视图、EPTP 切换 Hook、执行域、R-1 内存/进程操作与引导式 Hook 向导。AMD SVM/VMCB/NPT 与嵌套 SVM 已实现并接入独立实验路径。准入检查硬件、外层虚拟机监控程序、准备资源、全 CPU 自检及生命周期状态；Intel EPT 扩展不直接适用于 AMD，完整内层系统启动与广泛的 AMD 性能验收仍未完成。仅限实验用途。

<details>
<summary>HVM 位于哪一层，以及已保留实验的范围</summary>

<br>

KSword HVM 接管的是**已经运行的同一个 Windows**。Intel 在 `VMLAUNCH` 后进入 VMX non-root，AMD 使用实验性 SVM 路径，监控器在该系统下面处理退出事件。后续虚拟机监控程序可通过嵌套 VMX/SVM 分派运行，前提是后端和配置通过准入。

```text
物理 CPU / 可选外层虚拟机监控程序
└─ KSword HVM：Intel VMX/EPT 或实验性 AMD SVM/NPT
   └─ 原有 Windows 实例
      └─ 通过嵌套 VMX/SVM 接入的后续虚拟机监控程序
         └─ 子来宾，按对应后端的验收范围使用
```

常驻维持这一层，停止常驻会结束依赖其 EPT/NPT 映射的能力。普通 EPT 视图/执行域修改使用停止状态流程；调试器自有 Shadow 规则另有生命周期。仍有 CPU 常驻时不能卸载驱动；退出不完整时保留资源和卸载保护。

Intel 已保留 Hyper-V → Windows → KSword → VMware → TinyCore 链路、受控 4×2 换页恢复/故障试验，以及独立的同二进制计时跟进。旧 2×2 长时观察、新 4×2 试验与性能测量是不同证据集，不证明任意来宾兼容，也不替代后续版本的长期稳定性验收。见[4×2 结果](next/hvm-4x2-results.md)、[计时跟进](next/hvm-followup-results.md)与[早期补测记录](next/hvm-paper-gap-closure.md)。

AMD 保留有限时长的裸机常驻/清理，以及 VMware 来宾中的 1/2/4/8-vCPU 嵌套 SVM 探针和重复启停记录。这些是受控探针结果，完整内层系统启动、持续性能与更广硬件验收仍属实验范围。见[AMD 实验状态](next/ksword-amd-lab-status.md)。

架构与生命周期见[嵌套虚拟化架构](next/嵌套虚拟化架构.md)。

</details>

<details>
<summary>按 Dock 展开的完整清单（17 主 + 3 辅助）</summary>

<br>

另见 [docs/OpenArk功能对照与TODO.md](OpenArk功能对照与TODO.md)。

| Dock | 内容 |
|---|---|
| **欢迎** | 版本、构建信息、项目链接。 |
| **进程** | 树/列表 + 图标和差异高亮。结束/挂起/恢复/优先级。线程栈、模块、令牌。R3/R0 cross-view。可恢复 R0 隐藏（有门禁）。PPL/签名操作有风险提示。 |
| **网络** | 抓包过滤。TCP/UDP 管理。按进程限速。请求构造器。HTTPS。ARP/DNS。存活主机。WFP 事件和规则。NIDS。分段下载。R0 网络栈清单。 |
| **内存** | 区域浏览和搜索。共用快照/汇编编辑器、书签/断点。R3/R0/私有页表/DDMA 后端。内核可执行扫描。内存证据。PTE/VA 翻译。 |
| **文件** | 双面板管理。哈希/签名/PE/字符串/Hex。PE/ELF/Mach-O 扫描器与安全文件字节编辑。解锁。NTFS 恢复。Minifilter/FileObject/Section 证据。存储和 BitLocker。 |
| **驱动** | 服务增删改查。已加载模块。DBWIN。DriverObj/DeviceObj/MajorFunction/FastIo。事务式编辑器。可恢复加载链摘除。完整性。Module cross-view。Unloaded/PiDDB 证据。 |
| **内核** | 对象命名空间。原子表。SSDT/SSSDT。Inline/IAT/EAT Hook。CID cross-view。ALPC/IPC。DynData。能力矩阵。已加载镜像和 IDT 基线。描述符/IOCTL 解码。反汇编。回调清单/监控。内核知识（71 篇）。 |
| **虚拟化（KVM）** | HVM 准入、自检与常驻。嵌套 VMX / 实验性 SVM、EPT 视图/Hook/执行域、R-1 内存/进程控制、SLAT/IOMMU 证据与诊断。 |
| **监控** | 进程 ETW。Syscall 采集。WinAPI agent。WMI 订阅。ETW session 管理。风险中心。 |
| **硬件** | CPU/GPU/内存/磁盘/网络图表。进程 I/O 和 ETW 文件活动。SetupAPI/CfgMgr 树。R0 设备审计。 |
| **权限** | 本地账号、组、当前进程权限。 |
| **窗口** | 窗口枚举/筛选/预览/拾取/控制。桌面管理。消息监控。Win32k GUI/session 审计。热键/Hook 审计。 |
| **注册表** | 树浏览。键值增删改查。.reg 导入导出。异步搜索。 |
| **句柄** | 按 PID/关键字/类型过滤。命名对象解析。类型统计。HandleTable/ObjectHeader 证据。 |
| **启动项** | 分类覆盖 logon/服务/驱动/任务/注册表/WMI。修改有风险门禁和恢复。 |
| **服务** | 筛选排序。启停。启动类型。属性编辑。依赖关系。TSV/JSON 导出。 |
| **杂项** | BCD/引导。声音来源归因。系统变速（有警告）。Shell 关联管理。剪贴板保护。崩溃分析。磁盘编辑和原始 FS 取证（写入要解锁）。AppLocker/WDAC/Defender/ASR 诊断。 |

辅助面板：任务进度、带 GUID 调用链追踪的日志输出、实时性能监视。设置使用独立对话框；文件扫描属于文件工作流。

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
APIMonitor_x64/          64 位 API/剪贴板 Agent
APIMonitor_x86/          32 位 API/剪贴板 Agent
DebuggerBackend/        CE/x64dbg 共享后端
CheatEngineExecutablePlugin/  可选 CE 集成
X96dbgExecutablePlugin/       可选 x64dbg 集成
shared/driver/           共享 IOCTL 协议头
tools/                   PDB 偏移生成器等构建工具
docs/                    技术文档
```

官网源码：[Felix3322/KSwordWebsite](https://github.com/Felix3322/KSwordWebsite)

## 构建

需要 Windows 10/11、VS 2022 的 MSVC x64 工具；完整版本另需 Qt 6.9.3
`msvc2022_64` 与 QtMsBuild，驱动另需 WDK。Light/Launcher 不依赖 Qt。
构建宿主统一使用 64 位 MSBuild、HostX64 编译器与链接器，不降级到 32 位入口。

主程序 Release/x64 使用仓库脚本。它优先读取
`.deps/Qt/6.9.3/msvc2022_64` 和 `.deps/QtVsTools/msbuild`，
检查约定的 64 位工具链，并在构建前读回 HostX64：

```powershell
& .\tools\Invoke-KSwordBuildCheck.ps1 -RepositoryRoot (Get-Location).Path -Action Build
```

单独构建 Light 并复用输出目录中**已有的** `KswordARK.sys` 时，需明确跳过驱动构建和签名目标：

```powershell
$msbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
if (!(Test-Path -LiteralPath $msbuild)) { $msbuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe' }
if (!(Test-Path -LiteralPath $msbuild)) { throw '64-bit MSBuild is required.' }
$hostToolArgs = @('/p:PreferredToolArchitecture=x64', '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64')
& $msbuild '.\KswordARKLight\KswordARKLight.vcxproj' /t:Build `
  /p:Configuration=Release /p:Platform=x64 @hostToolArgs `
  /p:KswordArkLightEnsureDriverBuilt=false /p:KswordArkLightSkipDriverSign=true `
  /p:KswordArkLightReuseSignedDriver=true /m:1 /v:minimal
```

所有手工 MSBuild 命令均传入上述三项宿主架构属性。复用驱动仍须符合预期协议与能力；跳过构建不证明签名或加载有效。发行包与辅助项目流程见 [AGENTS.md](../AGENTS.md)。

<details>
<summary>构建排障</summary>

<br>

**主程序 `LNK1000` / `IMAGE::BuildImage` / `.iobj`** — 仅执行一次干净重建，在本次构建临时关闭 WPO/LTCG：

```powershell
& .\tools\Invoke-KSwordBuildCheck.ps1 -RepositoryRoot (Get-Location).Path `
  -Action Rebuild -DisableWholeProgramOptimization
```

成功须同时满足 `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0` 和
`Ksword5.1/x64/Release/Ksword5.1.exe` 非零。恢复后需要检查产物时使用
`-VerifyArtifactOnly`，不紧接着重复普通 Build 使兼容构建缓存失效。

**驱动已成功链接、WDK 后置校验失败** — 先确认实际失败阶段，再以 x64 ApiValidator 单独验证刚链接的驱动。下例版本号需替换为本机已安装的 WDK：

```powershell
$solutionDir = (Resolve-Path '.\Ksword5.1').Path + '\'
$apiValidatorX64 = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64'
& $msbuild '.\KswordARKDriver\KswordARKDriver.vcxproj' /t:ApiValidator `
  /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=$solutionDir @hostToolArgs `
  /p:ApiValidator_ApiExtractorExePath=$apiValidatorX64 /m:1 /v:minimal
```

`Driver is 'Universal'.` 只证明此校验阶段通过；完整 Build、INF/CAT、签名、实际加载须分别验证，不能把中止的 Build 报成成功。

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

[文档索引](README.md) — 当前功能指南、构建与开发参考、验收记录和历史研究。

[CLI使用文档](CLI使用文档.md) · [功能技术文档](功能技术文档.md) · [内核知识中心](内核知识中心.md) · [IOCTL 审计](driver_ioctl_audit.md) · [OpenArk对照](OpenArk功能对照与TODO.md) · [动态偏移接入](动态偏移功能接入步骤.md) · [PDB/R0 审计准备](pdb_r0_audit_prep/) · [插件系统](插件系统规范.md) · [多语言规范](多语言语言包规范.md)

虚拟化（HVM）：[嵌套虚拟化架构](next/嵌套虚拟化架构.md) · [EPT切换后端设计](next/EPT切换后端设计.md) · [嵌套下的跨核TLB失效](next/嵌套下的跨核TLB失效.md) · [隐蔽Hook安全边界决策](next/隐蔽Hook安全边界决策.md) · [自动化测试](next/自动化测试.md) · [VM测试机搭建](next/VM测试机搭建.md)

## 声明

本项目包含系统级调试、审计和管理能力，仅限在合法授权的环境中使用。

## 许可证

按 [KSword Community Source License v1.6](../LICENSE) 源码公开。这里说的"开源"指源码可见，不是 OSI 认证的开源许可证。再分发和商用条款以 `LICENSE` 为准。

[社区公约](../COMMUNITY_COVENANT.md) 是关于署名和负责任使用的约定，不是额外的许可限制。贡献规则见 [CONTRIBUTING.md](../CONTRIBUTING.md)。

## 开发状态

嵌套 VMX 分派与 shadow EPT 合成已经实现，不再列为未来功能。AMD SVM/NPT、更广的来宾/硬件兼容性与 HVM 性能仍处于实验范围，按各自证据跟进。BugCheck 诊断与 Shield 也已有边界明确的实现，不是通用的防蓝屏保证。当前指南和历史实验在[文档索引](README.md)中分开说明。
