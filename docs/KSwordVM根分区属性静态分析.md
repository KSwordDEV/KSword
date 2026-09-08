# KSwordVM 根分区虚拟化属性静态分析

研究日期：2026-09-08。承接 [宿主根分区嵌套研究](KSwordVM宿主根分区嵌套研究.md)。目标仍是在当前 Windows 根分区内运行 KSwordVM 嵌套模式，并保持 HVCI/VBS 运行。

**本轮结论：在本机磁盘上的 Hyper-V 版本中，`0x80000` 不是开启根分区 VMX 的入口。它的写入处理明确拒绝根分区；实际嵌套能力由创建标志转成另一处内部标志，根分区初始化不设置该标志，后续寄存器和嵌套状态校验仍要求它存在。**

本轮建立了静态调用链，没有向运行中的根分区发送属性写入，没有执行 VMXON、加载探针驱动、修改 Hyper-V 映像或改变 HVCI/VBS 配置。静态分析不能冒充运行期 hypercall 返回值，也不构成对整个 Hyper-V 所有未分析路径的穷尽证明。

## 样本与证据范围

| 项目 | 值 |
|---|---|
| 原始文件 | Windows 系统目录中的 `hvix64.exe` |
| 文件版本 | `10.0.26100.9022` |
| 文件大小 | `2058384` bytes |
| SHA256 | `9140DDF9D4C1DB25F665DC73591B75A5D73A82894B1083901383DB1F143A9584` |
| RSDS | `hvix64.pdb`，GUID `A714D350-3B8A-8177-D0BA-27A4819D2928`，Age `1` |
| 分析方式 | 对仓库 `dist/` 中的同哈希副本进行 IDA 离线反汇编与交叉引用分析 |
| 地址表示 | 下文全部使用 RVA，映像首选基址为 `0xFFFFF80000000000` |
| 字节修改 | IDA patched-bytes 枚举为空；原文件未修改 |

精确未压缩 PDB 下载路径此前返回 404；本轮没有依赖私有 PDB。`sub_XXXXXX` 是分析数据库的地址标签，文中的功能名是分析结论，不是已恢复的微软内部符号。反编译器把部分 GS 相对访问误标为 `NtCurrentTeb()`，还有跨函数寄存器传播造成的参数类型失真；关键结论均回看了指令。样本身份尚未通过运行中的 hypervisor 调试会话再次核验。

规范化证据位于本机的 [分析目录](../dist/hv-root-properties-20260908-02/)；其中 [functions.json](../dist/hv-root-properties-20260908-02/functions.json) 索引 22 个函数的完整伪代码和带字节的汇编，`sub_<RVA>.c/.asm` 为引用依据。较早按功能猜测命名的文件只作过程记录，不应据其文件名推断内部函数语义。该目录为本机研究产物，不随本文自动进入版本控制。

## 1. 普通接口和 Ex 接口的实际入口

从 `.rdata` 中识别出每项 24 bytes 的分发表。表项中的调用编号、输入大小、输出大小，与公开 ABI 对应：

| Hypercall | 编号 | 表项 RVA | 处理入口 RVA | 已确认的关系 |
|---|---|---|---|---|
| GetPartitionProperty | `0x44` | `0x2660` | `0x283A20` | 输入 16 bytes，输出 8 bytes；核心读取函数 `0x282A10` |
| SetPartitionProperty | `0x45` | `0x2678` | `0x2843F0` | 输入 24 bytes；把值整理到内部扩展输入，再调用 `0x284450` |
| SetPartitionPropertyEx | `0x10A` | `0x38F0` | `0x284450` | 表项直接指向同一写入核心 |

因此，针对本文的 `0x80000` 属性，改用 Ex 调用仍会到达同一项根分区判断。Ex 核心也会检查属性参数和载荷大小，不能把修改输入布局视为另一种授权机制。[Microsoft：GetPartitionProperty](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallgetpartitionproperty)、[SetPartitionProperty](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallsetpartitionproperty)、[SetPartitionPropertyEx](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallsetpartitionpropertyex)

普通 Get/Set 均经过分区查找及关系校验函数 `0x2A55F0`。其中 `HV_PARTITION_ID_SELF` 对应当前分区；这是分区 ID 语义，不是 WHP 的进程内 handle。目标根分区也不能凭经验填成 ID 0。[Hyper-V 公共类型定义](https://github.com/torvalds/linux/blob/master/include/hyperv/hvgdk_mini.h)

## 2. `0x80000` 的含义与根分区拒绝

微软把 `HvPartitionPropertyProcessorVirtualizationFeatures = 0x00080000` 列在虚拟化属性组，但该组名不等于某个 bit 就是 VMX 开启位。[Microsoft：属性编号](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_property_code)

本样本中的路径如下：

| 操作 | RVA | 静态行为 |
|---|---|---|
| Get `0x80000` | `0x282DCA` | 读取目标分区对象 `+0x6130` 的 64-bit 值；该属性分支没有额外的根分区拒绝 |
| Set `0x80000` | `0x284934` | 先检查对象 `+0x1A0` 的 bit0，置位则跳到拒绝分支 |
| 拒绝分支 | `0x2848F3` | 返回状态值 `6`，即 `HV_STATUS_ACCESS_DENIED` |
| 值校验与写入 | `0x284941`、`0x284947` | 只接受 `0/1`，大于等于 2 返回 `HV_STATUS_INVALID_PARAMETER`；通过后写入 `+0x6130` |

这里的状态值来自属性专用分支。完整 hypercall 还可能在更早的参数、对象、关系或状态检查失败，不能预测任何现场调用都必然返回 6。[状态码定义](https://github.com/torvalds/linux/blob/master/include/hyperv/hvgdk_mini.h)

根分区 bit0 的识别有两条交叉证据：根对象初始化把它置位并把 parent 指针设为 null；`RootProcessorFeatures0/1` 的读取分支只接受这一位已置位的对象。没有只靠一次 `test ..., 1` 就给该字段命名。

该值的消费者还说明了其作用方向：

- 在 CPUID leaf 1 构造函数 `0x2ABB18` 中，`0x2ABC2D` 检查 `+0x6130` 的 bit0；在已追踪的非 Exo 分支中，该位可以清除 ECX bit31，即 Hypervisor Present。
- 在 Hyper-V 最大 CPUID 叶计算函数 `0x2B28EC` 中，普通非根分区的相应分支会据该位把最大叶限制到 `0x40000001`。
- 同一 leaf 1 构造函数的 `0x2ABB8A` 则用 **`+0x1A0` 的 bit2** 选择 ECX bit5（VMX）的值。它不读取 `+0x6130` 来开启 VMX。

因此，本版本已确认的 `0x80000` 行为涉及虚拟化身份的呈现。不能把向它写 1 解释为“申请嵌套 VMX”，也不能把清除 Hypervisor Present 解释为移走外层 Hyper-V。这里描述的是观察到的行为，尚未取得该属性 bit0 的微软正式字段名称。

## 3. 真正的嵌套能力来自创建标志

Linux 主线的 Hyper-V 头文件明确把 `HV_PARTITION_CREATION_FLAG_NESTED_VIRTUALIZATION_CAPABLE` 定义为创建输入 flags 的 bit1。处理器特征 bank 1 中还有独立的 `nested_virt_support` bit6。两者不是同一个字段。[Linux 主线 Hyper-V 定义](https://github.com/torvalds/linux/blob/master/include/hyperv/hvhdk.h)、[Microsoft OpenVMM hvdef](https://github.com/microsoft/openvmm/blob/main/vm/hv1/hvdef/src/lib.rs)

本机样本的静态链条为：

```text
HvCallCreatePartition (0x40，入口 RVA 0x2834E0)
  → 创建参数校验 0x2A32C0
  → 创建标志校验 0x275008
      输入 flags bit1
      + 平台及目标处理器特征 bank 1 bit6
      + 兼容版本及隔离模式等约束
      → 内部 flags bit2
  → 分区分配 0x272BD0
      将内部 flags 的指定部分写入对象 +0x1A0
  → CPUID 构造 / VP 寄存器校验 / 嵌套状态处理
```

`0x275008` 的嵌套分支检查平台能力、兼容版本，以及部分版本中目标处理器特征是否仍保留嵌套支持；通过后才执行内部标志 `|= 4`。它还检查从创建参数导出的内部隔离模式等条件。这些隔离模式字段不能直接等同于“宿主是否开启 VBS”，本轮不作这种替换。

这也解释了属性名的层次：处理器能力 bank 描述能力集合，创建标志申请分区实例所需的执行机制，内部 bit2 决定已建立的实例是否具备相应条件。读取一个能力值不能替代后两个步骤。

## 4. 根分区的独立初始化路径

`0x274754` 使用预留的全局根对象，清空 parent 指针，调用 `0x27395C` 生成根分区标志，再把标志的低位部分存入 `+0x1A0`。`0x2A2688` 和另一条初始化路径 `0x2A2798` 都调用它；它们没有通过普通 CreatePartition 的输入 bit1 申请嵌套。

对 `0x27395C` 的掩码和移位逐项传播后，可得到所有输入变化下可能被置位的保守集合 `0xD0E9206233`：**其中 bit0 可置位且由常量保证，bit2 始终不在集合内。** 这是针对该函数的位传播结论，不是读取运行期分区内存得到的值。

初始化后的创建参数重校验也没有提供补设这位的入口：`0x2A41AC` 调用 `0x2748A8`，比较新旧内部标志；其比较掩码保留 bit2，因此新旧 bit2 不一致会被拒绝。对本次已确认的路径，嵌套能力属于创建时要匹配的分区条件。

因此，现有根分区走的是一条没有设置嵌套标志的初始化路径，普通属性 Set 和 Ex Set 不负责把它重新创建成 nested-capable 分区。本轮未发现可以改变这一结果的 BCD 或注册表输入；这不等于已经反汇编了所有启动选项。

## 5. 根分区能力查询为何会产生“似乎能开”的印象

| 属性 | 本机 Getter 的静态行为 | 本机 Setter 的静态行为 |
|---|---|---|
| `ProcessorFeatures0/1`：`0x6000A/0x6000B` | 对根分区返回全局能力 bank；非根分区读取实例能力 bank | 本核心未实现这些固定属性的写入分支 |
| `RootProcessorFeatures0/1`：`0x60010/0x60011` | 要求根分区 bit0，返回根对象自身的 `+0x60E0/+0x60E8` | 本核心未实现这些固定属性的写入分支 |
| `ProcessorVirtualizationFeatures`：`0x80000` | 读取 `+0x6130` | 根分区拒绝；其他前置检查通过后，非根目标可接受 0/1 |
| `NestedVmxBasic` 至 `NestedVmxTrueEntryCtls`：`0x80003..0x80013` | 调用 `0x34AAB8`；根分区可从全局能力合成结果，非根分区要求内部嵌套 bit2 | 到达这些属性的专用分支时拒绝写入 |

属性名称对应 [Microsoft OpenVMM 的枚举](https://github.com/microsoft/openvmm/blob/main/vm/hv1/hvdef/src/lib.rs)。上表只覆盖这个样本实际处理的编号；该项目中更新的其他编号不自动意味着本样本也实现了。

最有价值的细节是 `0x34AAB8` 的分支顺序：先接受根分区并选择全局能力；只有非根分区才继续要求内部嵌套 bit2。因此，**根分区能够查询虚拟 VMX 控制值，与根分区不能执行嵌套 VMX 可以同时成立。** 本轮没有执行根分区 Get hypercall；这里确认的是静态实现具备该查询分支。

这与此前 WHP 返回 VmxBasic、而当前 Windows 的 CPUID.VMX=0 在逻辑上相容。尚未逆向 `WinHvPlatform.dll` 到这个具体函数的调用链，不能进一步宣称此前 WHP 查询就是由该函数返回的。

## 6. 限制不止于 CPUID

在 VP 寄存器设置校验链 `0x2B7650 → 0x34B86C` 中，CR4/嵌套 CR4 分支会再次检查分区 `+0x1A0` 的 bit2。该位没有置位时，待写值包含 CR4.VMXE（bit13）会返回 `HV_STATUS_INVALID_PARAMETER`。同一分支还检查当前 VP 的上下文字段，说明已有嵌套标志也不是所有上下文都能直接通过。

此外，嵌套状态处理函数 `0x34B5B4` 在缺少 bit2 时直接返回 `HV_STATUS_INVALID_PARTITION_STATE`，随后还有控制寄存器、页对齐和状态检查。其他初始化函数也依据这位建立相应状态。

这些证据足以排除“仅修改 CPUID 呈现就完成嵌套授权”的判断。它们没有替代对所有 VMX 指令 VM-exit 处理函数的审计；本轮没有实测 VMXON 异常，也不承诺它在根分区的具体异常或崩溃表现。

## 7. 对 KSwordVM 的具体结论与剩余边界

- 当前 `ALLOW_NESTED` 仍只表示 KSwordVM 愿意使用外层已有的嵌套能力；本轮找到的根分区属性不能替它建立该能力。
- 不能用写 `0x80000=1`、更换普通/Ex hypercall、改读 `RootProcessorFeatures*` 或查询 `NestedVmx*` 作为可落地的开启步骤。它们分别涉及呈现、相同的处理入口和能力读取。
- 要让当前根分区具备真正嵌套能力，需要外层 Hyper-V 为其提供完整的创建、VP 状态和执行支持。本版本已追踪的正常路径没有建立这套条件；本轮没有找到保持当前 HVCI/VBS 环境的现成开启方法。

尚未完成的是运行期只读属性采样、实际已加载 hypervisor 身份核验，以及完整 VMX 指令/每 VP 生命周期的审计。若后续增加只读采样，值得同时比较 SELF 的 `0x6000B`、`0x60011`、`0x80000`、`0x80003`、`0x8000F`，并原样记录 HV_STATUS；成功读到能力值仍不能当作执行授权。这里列出的是后续验证目标，不是已执行的实验。

本轮没有找到可供 KSwordVM 原地开启的配置方案，也没有把未知路径宣布为不存在。新的进展是：已把“属性编号存在”收敛为可复核的分区身份判断、位语义、创建路径和运行校验四层证据。
