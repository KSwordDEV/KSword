# Hyper-V 嵌套虚拟化测试机（KSword HVM / EPT HOOK 开发环境）

**目标**：让 KSword 的 HVM 能作为 L1 hypervisor 跑在虚拟机里，从而可以在不重启物理机、
不冒蓝屏风险的前提下开发和验证 EPT HOOK。顺带解开验收记录里的 E2 / E5 / E6 三类环境。

---

## 1. 为什么从 VMware 换到 Hyper-V（这是实测结论，不是偏好）

原计划是在 VMware 里做。实测发现一条死链：

```
宿主 VBS + HVCI 正在运行（实测 VirtualizationBasedSecurityStatus = 2）
   → Hyper-V 的 hypervisor 已加载并独占 VT-x（实测 HypervisorPresent = True）
      → VMware 被迫走 WHP/ULM 兼容模式（实测 vmware.log: "Monitor Mode: ULM"）
         → vhv.enable 无效，guest 里看不到 VT-x（实测日志中 VHV 各项开销分配均为 0）
            → KSword HVM 无法 VMXON，EPT HOOK 无从谈起
```

要在 VMware 下打通，**必须关掉宿主的 VBS/HVCI** —— 那是实打实的安全降级。

而 Hyper-V 的嵌套虚拟化用的就是宿主那个已经在跑的 hypervisor，**VBS 可以原样保留**。
所以换 Hyper-V 不只是省事，是能同时保住宿主安全配置。

另外，VMware 在宿主内核里跑着 7 个驱动（`vmx86` `vmci` `VMnetAdapter` `VMnetBridge`
`VMnetuserif` `hcmon`）。本次开发期间宿主发生过**两次内核级挂死**（CapsLock 灯无反应、
只能硬断电；事件日志只有 `Kernel-Power 41` + `6008`，没有 BugCheck 也没有转储，
符合硬挂而非蓝屏的特征）。第二次挂死发生在 `kd -b` 通过 **VMware NAT** 连 KDNET 的瞬间 ——
那条链路正好穿过上面这几个宿主内核驱动。卸载 VMware 会一并移除它们。

> 顺带记一条：KDNET 走 NAT 本来就是最差的选择，多一层 `vmnat` 地址转换。
> 虚拟机内核调试的常规做法是 host-only 或桥接。当时选 NAT 只是因为 guest 网卡已经在 NAT 上。

## 2. 层级关系（先想清楚谁在哪一层）

```
L0   宿主 Hyper-V hypervisor            ← 宿主 VBS/HVCI 也用它，保持开启
L1   KSword-HVM-Target 这台虚拟机        ← 要透传 VT-x/EPT 给它
     └─ KSword 的 HVM 在这里 VMXON      ← 它自己是个 hypervisor
L2        被 KSword HVM 管理的 guest     ← EPT HOOK 作用在这一层
```

**关键约束**：L1 里**不能**再开 Windows 自己的 VBS / 内存完整性 / Hyper-V，
否则 L1 的 hypervisor 会抢走 VT-x，KSword HVM 就 VMXON 不了。装完系统必须确认关闭。

## 3. 已核实的宿主状态（2026-09-05）

| 项 | 值 |
|---|---|
| 宿主系统 | Windows 11 **Pro for Workstations** Insider build 26300 → Hyper-V 角色可用 |
| CPU | 13th Gen Intel Core i7-13700F（Intel VT-x + EPT，符合 HVM 的 Intel-only 能力门） |
| VBS / HVCI | **正在运行**（换 Hyper-V 后无需关闭） |
| `HypervisorPresent` | `True`；`hvhost` 服务 Running |
| Hyper-V 角色 | **未安装**（无 `vmms`、无 PowerShell 模块）→ 需要启用 |
| 可用空间 | C: 103.5 GB，D: 67.8 GB |
| 安装 ISO | `D:\Users\felix\Downloads\Windows11_InsiderPreview_Client_x64_en-us_22621.iso`（4.69 GB） |
| 宿主调试器 | `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\{windbg,kd}.exe` 10.0.26100.6584 |
| 宿主 Defender 实时保护 | 已关闭（此前会锁住刚构建的 exe，造成反复 `LNK1104`） |

## 4. 步骤

### 4.1 卸载 VMware（管理员，你执行）

从"应用和功能"里卸载 **VMware Workstation 17.6.4**，或用它自己的卸载程序。
目的是移除那 7 个宿主内核驱动。剩下的虚拟机文件（`Arch Linux` 15.4 GB）按需自行删除。

> `Windows 11 x64` 那台已经被删掉了，无需处理。

### 4.2 启用 Hyper-V 角色（管理员，你执行，需重启）

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All
```

重启。重启后判据：`Get-Module -ListAvailable Hyper-V` 有输出，`Get-Service vmms` 存在。

### 4.3 建虚拟交换机（管理员，一次性）

```powershell
New-VMSwitch -Name 'External' -NetAdapterName (Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty Name) -AllowManagementOS $true
```

### 4.4 创建测试机（脚本已写好）

```powershell
cd C:\Users\Felix\CLionProjects\KSword
.\scripts\New-KswordHyperVTarget.ps1 -IsoPath 'D:\Users\felix\Downloads\Windows11_InsiderPreview_Client_x64_en-us_22621.iso'
```

脚本把嵌套虚拟化的每条硬要求都固化并**逐项回读校验**：

| 设置 | 为什么是硬要求 |
|---|---|
| `ExposeVirtualizationExtensions = $true` | 把 VT-x/EPT 透传给 L1。只能在关机时设 |
| **动态内存必须关闭** | Hyper-V 明确规定：开着动态内存时不允许暴露虚拟化扩展 |
| **MAC 地址欺骗打开** | L2 guest 的源 MAC 与 L1 网卡不同，不开会被虚拟交换机直接丢包 |
| 标准型检查点 + 关自动检查点 | 生产检查点走 guest 内 VSS，与正在运行的 hypervisor 冲突 |
| 第 2 代（UEFI） | Windows 11 需要 |
| vTPM | Windows 11 安装检查需要。**与 VMware 不同，Hyper-V 的 vTPM 不会加密整机配置**，不会出现"忘了口令就再也打不开"的局面 |

### 4.5 装系统，然后配置 guest

装完**关机**，关掉 Secure Boot（`testsigning` 的前提）：

```powershell
Set-VMFirmware -VMName 'KSword-HVM-Target' -EnableSecureBoot Off
Checkpoint-VM  -VMName 'KSword-HVM-Target' -SnapshotName 'clean-install'
```

在 guest 内（管理员）：

```powershell
bcdedit /set testsigning on
bcdedit /set hypervisorlaunchtype off
```

并在 `设置 → 隐私和安全性 → Windows 安全中心 → 设备安全性 → 内核隔离` 里
**关闭"内存完整性"**，然后重启。

回读确认（别只看"操作成功完成"）：

```powershell
bcdedit /enum "{current}" | Select-String 'testsigning|hypervisorlaunchtype'
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus
```

要的结果：`testsigning Yes`、`hypervisorlaunchtype Off`、VBS 状态 `0`。
最后一项如果不是 0，KSword HVM 一定 VMXON 失败 —— 这是最容易漏的一步。

## 5. 之后能解开哪些验收项

| 环境 | 可跑的编号 |
|---|---|
| **E2** 授权测试机 + 驱动真实加载 | I-12 现场部分、M-12、X-09、T-07、T-11、S-08、Q-05、Q-08，以及 F 系列的"目标环境实测"层 |
| **E5** 隔离环境（Verifier / 临时规则 / 故障注入） | Q-09、Q-10、Q-11、N-07 |
| **E6** 真实 dump + 调试引擎 | C-01、C-03、C-05、C-06、C-07、C-10 的"真实 dump 对照"层 |
| **E3** VBS/HVCI 实际运行 | S 模块的现场层 —— 注意开了 HVCI 后测试签名驱动会被挡，那本身是 S-06/S-08 的有效负向用例 |

**活体内核调试器不是必需的。** E2 只要 `testsigning`；E5 的 Verifier bugcheck 由 guest
自己写转储；E6 要的本来就是**离线**转储分析 —— 在 guest 里产生 dump、拷到宿主、用宿主的
WinDbg 离线分析即可。要活体调试再上串口（命名管道走用户态，不碰宿主内核网络栈）。

## 6. 纪律

- **Driver Verifier 只在这台虚拟机上开，且只对 `KswordARK.sys` 开**（Q-10 要求），
  绝不在宿主开：`verifier /standard /driver KswordARK.sys`，用完 `verifier /reset`。
- 宿主不开 `testsigning`、不导入测试证书到 LocalMachine 信任区、不加载驱动。
- 每次破坏性实验（Verifier、强制蓝屏取 dump）前先 `Checkpoint-VM`。
- 真实 dump 样本要在验收记录里写明来源与取得方式（C-10 要求）；
  自己在虚拟机里产生的 dump 属于"已知来源样本"，可用。
- 本文件不覆盖原虚拟化 roadmap 的 AMD P3 真机要求（Q-16）：
  **嵌套环境能跑通不等于真机验收通过**，两者必须分别记录。
