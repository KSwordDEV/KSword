# KSwordVM 宿主根分区嵌套研究

研究日期：2026-09-08。源码基线：`e3d8106e2bdb5bba2421627b52b9491c5c3fdebb`。

目标是：在当前正在运行的 Windows 宿主根分区内，让 KSwordVM 获得嵌套 VMX 并接管当前 Windows 的执行，同时保持宿主 HVCI/VBS 运行。另开 Hyper-V 子虚拟机、WSL2 中运行 Linux KVM，以及把操作对象换成测试机，都不算完成这个目标。本文的 KVM 按钮指 KSwordVM，不是 Linux KVM。

**结论：当前代码和本机提供的能力不能直接实现这个目标；没有找到已验证可用的宿主根分区开启办法。** 微软明确把嵌套虚拟化的支持范围限定在来宾分区，并排除 Windows 根分区。这个结论说明现有接口的支持边界，不能扩展成对未知实现、未来版本或改变 hypervisor 实现的数学不可能性证明。[Microsoft TLFS：Nested Virtualization](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/nested-virtualization)

宿主确实已经被虚拟化。关键在于：**处于 VMX non-root，和获得一个可再次使用的虚拟 VMX 接口，是两件事。** 根分区负责管理子分区，也不因此拥有物理 VMX root。Hyper-V 的根分区身份与 Intel 的 VMX root 模式不能混用。[Microsoft：Hyper-V Architecture](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/architecture)

目标拓扑可以表示为下面的逻辑关系，其中 KSwordVM 的位置是期望状态，尚未成立：

```text
物理 CPU
└─ Microsoft Hyper-V，L0
   └─ 当前 Windows 根分区
      ├─ VTL1：安全内核与 HVCI 的隔离部分
      └─ VTL0：期望由 KSwordVM 作为嵌套 hypervisor
               接管同一个 Windows 的普通内核及用户态执行
```

即使未来打通嵌套入口，KSwordVM 的虚拟 VMX root 也仍受外层 Hyper-V 约束。VTL 隔离和上层内存访问权限不会因为增加一个 L1 而自动交给它；HVCI/VBS 共存还需要单独验证。[Microsoft TLFS：Virtual Secure Mode](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm)

**本机实测证据**

下面是本次直接查询的结果，不是对旧项目记录的复述。

| 项目 | 结果 | 含义 |
|---|---|---|
| CPU | Intel Core i7-13700F，16 核、24 逻辑处理器 | 本机是 Intel 平台 |
| Windows | Windows 11 Pro for Workstations Insider Preview，26H2，26300.9022 | 结论限定于该现场 |
| HypervisorPresent | `true` | 外层 hypervisor 在运行 |
| VirtualizationBasedSecurityStatus | `2` | VBS 正在运行 |
| SecurityServicesRunning | `[2]` | 内存完整性正在运行 |
| CPUID.1 ECX | `0xFFFAF38B` | bit31=1，bit5（VMX）=0 |
| CPUID.40000000 | 最大叶 `0x4000000C`，`Microsoft Hv` | 外层为 Hyper-V |
| CPUID.40000001 EAX | `0x31237648` | `Hv#1` 接口 |
| CPUID.40000003 EBX | `0x002BB9FF` | 包含 CreatePartitions 权限，与根分区身份一致 |
| CPUID.40000004 EAX | `0x00960E14` | eVMCS 建议位 bit14=0 |
| CPUID.4000000A | EAX/EBX/ECX/EDX 全为零 | 当前上下文没有通告嵌套增强能力 |

Hyper-V 合成 CPUID 叶的解释依据：[Microsoft TLFS：Feature and Interface Discovery](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery)。本机 WMI 的部分 CPU 虚拟化字段也返回 false，但在 hypervisor 已经运行时，不能据此断言 BIOS 没开 VT-x；应以实际执行上下文的能力查询判断。

**KSwordVM 当前卡在哪里**

| 源码位置 | 当前行为 | 对根分区目标的影响 |
|---|---|---|
| `KswordARKDriver/src/features/hvm/hvm_runtime.c:529` | 没有 `FEATURE_VMX` 就返回 `STATUS_NOT_SUPPORTED` | 本机已经在这里失败，尚未进入 VMX MSR 探测 |
| `hvm_runtime.c:672` | 同时存在 Hypervisor 和 VMX 才设置 `NESTED_VMX_EXPOSED` | 开关不能制造外层没有暴露的 VMX |
| `hvm_runtime.c:1513` | PREPARE 要求 `ALLOW_NESTED` 与能力条件成立 | 允许使用能力，不负责开启 Hyper-V 的能力 |
| `hvm_resident.c:1860` | 常驻再次检查 `ALLOW_NESTED` 和 `NESTED_VMX_EXPOSED` | 删掉一处门禁仍不能建立嵌套执行 |
| `hvm_evmcs.c:207` | eVMCS 校验保留 PARTIAL，返回 `STATUS_NOT_IMPLEMENTED` | 该实现不完整，但补完它也不能替根分区申请嵌套授权 |
| `hvm_nested.c:238` | 处理 KSwordVM 下层 hypervisor 的 VMLAUNCH，并保留未完成状态 | 这是向下提供嵌套，与作为 Hyper-V 的 L1 运行方向不同 |

源码链接：[能力探测](../KswordARKDriver/src/features/hvm/hvm_runtime.c)、[常驻入口](../KswordARKDriver/src/features/hvm/hvm_resident.c)、[eVMCS](../KswordARKDriver/src/features/hvm/hvm_evmcs.c)、[向下提供嵌套](../KswordARKDriver/src/features/hvm/hvm_nested.c)。

界面还有一处容易误导研究方向的表述：`MainWindow.Kvm.cpp:653` 将“虚拟机内”和“开着 VBS/HVCI 的机器”并列描述为可以作为 L1 运行；`UI/KvmControl.cpp:360` 也暗示开启菜单即可。对当前 Windows 根分区，这个承诺缺少“外层已经暴露 VMX”的前提。本次只记录问题，没有改动界面或语言包。[菜单实现](../Ksword5.1/Ksword5.1/MainWindow.Kvm.cpp)、[能力说明](../Ksword5.1/Ksword5.1/UI/KvmControl.cpp)

**逐条评估的路线**

| 路线 | 能否完成本次目标 | 依据或缺口 |
|---|---|---|
| KVM 菜单开启嵌套、传 `ALLOW_NESTED` | 当前不能 | 本机 VMX=0；该标志只改变 KSword 自身策略 |
| 删除 Hypervisor/VMX 检测，强行执行 VMX 指令 | 没有成立依据 | 改检测不会改变 L0 对 VMX 指令的处理；本次没有执行这种实验 |
| 修改 CPUID 返回值、伪装 vendor、换更高 Windows 权限 | 不能作为开启机制 | 可见标志与 L0 提供的执行语义不同；管理员或 R0 身份不等于嵌套 VMX 能力 |
| 补全 eVMCS、VP-assist page | 不能独立解决 | eVMCS 是已获嵌套能力后可用的接口优化，本机未通告该能力 |
| `Set-VMProcessor -ExposeVirtualizationExtensions` | 不满足目标 | 配置的是被管理的子 VM，没有把当前 Windows 根分区转换成该 VM 的接口 |
| WHP/WHPX、HCS、WinHv 管理入口 | 不满足目标 | 创建、配置和运行另一个分区，不能据此原地接管当前根分区 |
| 直接研究 Hyper-V 分区属性 hypercall | **本机静态分析未发现开启入口** | `0x80000` 写入拒绝根分区，且该属性与实际嵌套创建标志分离；详见后续静态分析 |
| Hyper-V intercept 接口代替自建 VMX | 未找到满足目标的入口 | 公开用途是父分区监控子分区，或更高 VTL 处理低 VTL；不是普通根分区驱动接管自己 |
| BCD、调整 hypervisor/根分区 CPU 数量、切换调度器 | 未找到开启依据 | 文档中的参数调整启动、调度和 VP 拓扑，没有授予根分区 nested VMX 的语义 |
| 把 KSwordARK 驱动改成更早加载 | 不能凭驱动加载顺序完成 | 普通内核驱动加载时，Hyper-V 已在其下面运行 |
| 启动前由 KSwordVM 成为物理 L0，再运行 Hyper-V | 改变架构，不能作为当前模式的开关 | 需完整嵌套 hypervisor 和启动集成；现有 KSwordVM 的向下嵌套还未实现完整执行 |
| 给两个 hypervisor 分配不同物理核 | 不是同一宿主的嵌套常驻 | 根分区 VP 数量配置不等于将物理核和全系统执行控制权交给另一个驱动 |
| 停 Hyper-V、关闭 VBS/HVCI、换启动项 | 不满足保持保护运行的条件 | 会改变问题的约束 |
| WSL2、Linux KVM、VMware/VirtualBox 子 VM、软件模拟、远端虚拟机 | 不满足宿主原地目标 | 即使可运行，执行对象已变成另一个虚拟机或环境 |

逐 VM 透传的范围见 [Microsoft：Enable Nested Virtualization](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization)。WHP 的创建接口明确返回新分区对象，之后 Setup 才建立 hypervisor 分区：[WHvCreatePartition](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatepartition)。Intercept 的公开作用域见 [Virtualization Host](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/virtualization-host) 和 [HV_INTERCEPT_TYPE](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_intercept_type)。CPU 与启动选项的定义见 [BCDEdit /set](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set)。

这里没有把“所有理论方法”宣布为已穷尽：公开文档不披露当前 hvix64 的全部实现。上表区分了已被目标条件排除的办法、当前能力不成立的办法，以及仍缺实现证据的办法。

**根分区属性：后续静态分析已取得的结果**

微软公开了以下真实接口和属性，不应因文档写“不支持”就假装这些接口不存在：

| 接口或属性 | 定义 |
|---|---|
| `HvCallGetPartitionProperty` | hypercall code `0x0044` |
| `HvCallSetPartitionProperty` | hypercall code `0x0045` |
| `HvPartitionPropertyProcessorVirtualizationFeatures` | property code `0x00080000` |

来源：[GetPartitionProperty](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallgetpartitionproperty)、[SetPartitionProperty](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallsetpartitionproperty)、[HV_PARTITION_PROPERTY_CODE](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_property_code)。Microsoft OpenVMM 的 [hvdef](https://github.com/microsoft/openvmm/blob/main/vm/hv1/hvdef/src/lib.rs) 也包含此属性及一组 NestedVmx 属性定义。

继续分析同一版本的磁盘映像后，已建立入口到属性分支、创建标志和 VP 校验的调用链，详见 [根分区属性静态分析](KSwordVM根分区属性静态分析.md)。关键结果为：

1. `SetPartitionProperty` 和 `SetPartitionPropertyEx` 使用同一写入核心，`0x80000` 的专用写入分支明确拒绝根分区。
2. `0x80000` 的值参与 CPUID 的 Hypervisor Present 呈现；真正控制 VMX 暴露的内部嵌套标志来自 CreatePartition 的 `NestedVirtualizationCapable` 创建条件。
3. 已追踪的根分区初始化不设置嵌套标志，后续重校验也要求新旧该位一致。
4. 根分区可通过属性查询分支获得合成的 `NestedVmx*` 能力，VP 寄存器和嵌套状态校验仍独立检查执行条件。能查询能力不等于可执行 VMX。

这些是精确磁盘映像的静态结果，尚未做运行期根分区属性采样、VMX 指令实验和 HVCI/VBS 共存验证。本次未向当前根分区发送属性写入，也未改动 Hyper-V 映像。

为这条研究线读取了本机系统目录中的 Hyper-V 映像身份：

```text
hvix64.exe 文件版本：10.0.26100.9022
文件大小：2058384 bytes
SHA256：9140DDF9D4C1DB25F665DC73591B75A5D73A82894B1083901383DB1F143A9584
RSDS PDB：hvix64.pdb
GUID：A714D350-3B8A-8177-D0BA-27A4819D2928
Age：1
```

按精确 GUID/Age 查询微软符号服务器的未压缩 PDB 路径，返回 HTTP 404。后续通过 IDA 对同哈希副本建立了静态调用链，RVA、相关对象字段与证据索引记录在上面的专项分析中。功能标签来自分析而非私有符号；该文件身份仍不替代对实际已加载 hypervisor 映像身份的运行期核验。

**WHP 实测为何不能证明宿主可以嵌套**

本机 `WinHvPlatform.dll` 文件版本为 `10.0.26100.8941`。使用本机 SDK 中的公开函数原型运行了进程内探针：能力查询，并分别创建一个不运行 guest 的临时分区对象，设置 1 个处理器、NestedVirtualization=false/true，调用 Setup，最后 Delete。没有创建 VP、映射 guest 内存或运行 guest 指令。

| 探针操作 | HRESULT / 结果 |
|---|---|
| `WHvGetCapability(HypervisorPresent)` | `S_OK`，true |
| `WHvGetCapability(VmxBasic)` | `S_OK`，`0x01D8100000000001` |
| `WHvGetCapability(VmxProcbasedCtls)` | `S_OK`，`0xF7F9FFFE2401E5F2` |
| `WHvGetCapability(VmxProcbasedCtls2)` | `S_OK`，`0x065018AE00000000` |
| `WHvGetCapability(VmxEptVpidCap)` | `S_OK`，`0x00000F0106F34041` |
| Nested=false：Create / Set / Get / Setup / Delete | 均 `S_OK`，属性回读 0 |
| Nested=true：Create / Set / Get | 均 `S_OK`，属性回读 1 |
| Nested=true：Setup | `0xC0350005`，`ERROR_HV_INVALID_PARAMETER` |
| Nested=true：Delete | `S_OK` |

这证明了两件不同的事：WHP 可以查询其能够提供的虚拟化能力；当前最小配置的嵌套分区 Setup 没有通过。**它没有证明 WHP 的所有嵌套配置都不可能，也没有测试 Windows 根分区的属性设置。** 设置属性成功只意味着对象接受了配置，不能当作成功运行嵌套 guest 的证据。[WHP 分区属性定义](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvpartitionpropertydatatypes)

尤其不能把“WHP 返回 VmxBasic”与“当前 Windows CPUID.VMX=0”视为矛盾：前者是在查询虚拟化平台的能力，后者是在查询调用线程当前所处环境的 CPU 接口。WHP 新建对象不是当前根分区的接管句柄。

**子虚拟机只作为对照，不作为交付方案**

- 现有 `KSword-HVM-Target`：Generation 2、配置版本 12.0、2 vCPU、固定 8 GiB、`ExposeVirtualizationExtensions=true`；检查前后都是 Off，本次未启动。
- 已在运行的 Ubuntu WSL2：内核 `6.6.87.2-microsoft-standard-WSL2`，VMX=true、EPT=true，存在 `/dev/kvm` 和已加载的 `kvm_intel`。
- 普通 WSL 用户打开 `/dev/kvm` 返回 PermissionError；没有继续提权，没有取得 KVM API 版本或执行 guest。设备存在不是完整 KVM 运行验证。

这些对照足以反驳“看到宿主 VBS 就可一概否定所有子分区的 VMX 暴露”，但都不能完成当前根分区原地嵌套。网上旧版限制、VMware 的 WHP 模式限制，以及本机 Hyper-V 根分区限制必须分别解释，不能混成同一结论。Broadcom 目前也仍将 Workstation 上宿主 Hyper-V 与 guest 嵌套的组合列为限制：[Broadcom 313547](https://knowledge.broadcom.com/external/article/313547/support-for-running-esxi-as-a-nested-vir.html)。

**对项目下一步的判断**

目前不应通过放宽 KSwordVM 门禁、补一个菜单开关或只补 eVMCS 来宣称支持 HVCI/VBS 宿主。软件本身能够改进的是根分区识别和失败说明；真正的功能前提必须来自外层 Hyper-V。

继续沿用户指定拓扑研究时，剩余验证点是运行期只读能力采样、已加载映像身份和完整的嵌套执行生命周期。本版本已追踪的正常属性与初始化路径没有提供根分区开启机制。真正改变这一结果需要外层 hypervisor 支持根分区的嵌套创建与执行；启动前自建 L0 则是另一种架构，不是现有 KSwordVM 嵌套开关的补丁。当前没有足够证据承诺上述任一路线能在本机落地。

研究结束时重新查询，VBS 仍为运行状态，内存完整性仍在运行。所有临时 WHP 对象都已删除；没有修改 KSword 源码、BCD、驱动服务或安全设置，没有重启宿主，没有运行 KSwordVM 常驻实验。
