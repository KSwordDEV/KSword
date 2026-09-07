# 虚拟化规范要点

这份文档记的是**架构规范**，不是我们的实现。它存在的理由：实现 VMFUNC / #VE /
多 EPTP / 嵌套时，反复要查的是"SDM 到底要求什么"，而不是"某个开源项目怎么写的"。
参考实现只能说明一种做法是否可行，说明不了它是否正确——两者混淆过一次就会付出
蓝屏的代价。

来源以 Intel SDM 卷与章节号为准，第三方资料只作补充并注明出处。
每一节的"失败模式"是本文最该先读的部分：它们描述的是配置看起来对、
但功能不生效或直接三重故障的那些情况。


---

## Intel VT-x VM Functions / VMFUNC 指令与 EPTP switching (function 0)

VMFUNC（NP 0F 01 D4，无操作数）让 VMX non-root 中的软件直接调用一项 VM function 而不产生 VM exit；EAX 选功能号，指令本身不修改任何寄存器与标志，成功后 RIP 前进到下一条指令。目前架构只定义 function 0 = EPTP switching：以 ECX 为下标从 EPTP list（4KB 物理页、512 项、每项 8 字节 EPTP）取值写入当前 VMCS 的 EPT pointer 字段，之后所有 guest-physical 翻译改走新的 EPT 层级；若处理器支持 “EPT-violation #VE”，同时把 ECX[15:0] 写入 EPTP index 字段。启用需要三级串联开关：primary proc-based bit31 → secondary proc-based bit13 → VM-function controls bit0，并且 EPTP switching 强制要求 enable EPT=1。VMFUNC 不做 CPL 检查，guest ring3 代码也能切换 EPT 视图。


### 能力探测

| 探测什么 | 在哪读 |
|---|---|
| 处理器是否支持 secondary processor-based controls（VMFUNC 的前置条件，因为 enable VM functions 是 secondary 控制位） | `IA32_VMX_PROCBASED_CTLS (MSR 0x482) bit 63 == 1，即 allowed-1 高 32 位的 bit 31（'activate secondary controls'）。带 TRUE 变体时同样看 IA32_VMX_TRUE_PROCBASED_CTLS (MSR 0x48E) bit 63` |
| 处理器是否支持 'enable VM functions'（即 VMFUNC 指令本身） | `IA32_VMX_PROCBASED_CTLS2 (MSR 0x48B) bit 45 == 1，即 allowed-1 高 dword 的 bit 13。SDM Vol.3D Appendix A.11 明确用 'bit 45 of IA32_VMX_PROCBASED_CTLS2' 表述` |
| 具体哪一个 VM function 被支持（哪些 VM-function controls 位允许置 1） | `IA32_VMX_VMFUNC (MSR 0x491)，bit X = 允许 VM-function controls 的 bit X 置 1；bit 0 = EPTP switching。该 MSR 仅在上面两条同时成立时才存在，否则 RDMSR 会 #GP —— 必须先探测再读` |
| enable EPT（EPTP switching 的硬性前置） | `IA32_VMX_PROCBASED_CTLS2 (MSR 0x48B) bit 33，即 allowed-1 高 dword 的 bit 1` |
| EPTP 各字段的合法取值（决定 list 里哪些 EPTP 会被接受） | `IA32_VMX_EPT_VPID_CAP (MSR 0x48C)：bit 8 = 支持 UC memory type(EPTP[2:0]=0)，bit 14 = 支持 WB(=6)，bit 6 = 支持 4 级页遍历(EPTP[5:3]=3)，bit 7 = 支持 5 级页遍历(EPTP[5:3]=4)，bit 21 = 支持 EPT accessed/dirty(EPTP bit 6)。新版 SDM 另有 bit 22 对应 EPTP bit 7 的 supervisor-shadow-stack 控制` |
| 是否存在 EPTP index 字段（决定 VMFUNC 0 会不会顺带写 ECX[15:0]） | `IA32_VMX_PROCBASED_CTLS2 (MSR 0x48B) bit 50，即 allowed-1 高 dword 的 bit 18（'EPT-violation #VE'）。Appendix B Table B-1 注 3 明确该字段只在支持该控制的处理器上存在` |
| VMCS 字段地址的宽度限制（影响 EPTP-list address 高 32 位） | `IA32_VMX_BASIC (MSR 0x480) bit 48 == 1 时，所有此类物理地址不得设置 bits 63:32` |
| 物理地址宽度 MAXPHYADDR（用于校验 EPTP-list address 与每个 EPTP 的保留高位） | `CPUID.80000008H:EAX[7:0]` |
| 注意：没有任何 CPUID 特性位直接报告 VMFUNC/EPTP switching | `只能走上述 VMX capability MSR 链（Vol.3D Appendix A）。第一代支持的硬件是 Haswell（4th-gen Core）及之后` |


### 相关 VMCS 字段

| 字段 | 编码 | 含义 |
|---|---|---|
| VM-function controls (full / high) | `0x00002018 / 0x00002019` | 64-bit 控制字段，Table 25-11（旧版 Table 24-9）：bit 0 = EPTP switching，其余全部保留为 0。仅在同时支持 'activate secondary controls' 与 'enable VM functions' 的处理器上存在。VMFUNC 执行时用 bit EAX 判断该功能是否已启用 |
| EPTP-list address (full / high) | `0x00002024 / 0x00002025` | 64-bit 控制字段，EPTP list 的 4KB 对齐物理（host-physical）地址。EPTP list = 一个 4KB 页 = 512 个 8 字节 EPTP 项。仅在支持 'EPTP switching' VM-function 控制的处理器上存在 |
| EPT pointer (EPTP) (full / high) | `0x0000201A / 0x0000201B` | 64-bit 控制字段。EPTP-switching VMFUNC 成功时由硬件把选中的 list 项直接写入此字段（VMM 无需 VM exit 也无需 VMWRITE），此后地址翻译使用新值的 bits 51:12 |
| EPTP index | `0x00000004` | 16-bit 控制字段（Table B-1，index 000000010B）。EPTP-switching VMFUNC 会把 ECX[15:0] 写入该字段；后续 EPT-violation 引发的 #VE 会把它保存进 virtualization-exception information area。仅在支持 'EPT-violation #VE' 的处理器上存在 |
| Primary processor-based VM-execution controls | `0x00004002` | bit 31 = 'activate secondary controls'。为 0 时 VMX non-root 的行为等同于所有 secondary 控制位都是 0，包括 'enable VM functions' |
| Secondary processor-based VM-execution controls | `0x0000401E` | bit 13 = 'enable VM functions'（Table 25-7 / 旧版 Table 24-7）；bit 1 = 'enable EPT'；bit 18 = 'EPT-violation #VE' |
| Virtualization-exception information address (full / high) | `0x0000202A / 0x0000202B` | 与 EPTP index 配套：#VE 发生时硬件把 EPTP index 等信息写到这里，是 VMFUNC+#VE 组合方案（如 Xen altp2m）必须设置的字段 |
| Exit reason | `0x00004402` | VMFUNC 引发 VM exit 时 basic exit reason = 59 (0x3B)，名为 'VMFUNC'。SDM 明确 'No additional VM-exit information is provided'，即 exit qualification 不携带 EAX/ECX 信息，handler 必须自行读 guest 寄存器 |
| VM-exit instruction length | `0x0000440C` | VMFUNC 引发 VM exit 时，VMFUNC 指令长度（3 字节）保存于此，VMM 需要据此推进 guest RIP |


### 架构约束

- 三级串联使能（SDM §26.5.6.1，旧版 §25.5.5.1）：必须同时置 1 —— primary proc-based controls bit 31 'activate secondary controls'、secondary proc-based controls bit 13 'enable VM functions'、VM-function controls bit 0 'EPTP switching'。缺任何一级都不成立
- 如果 primary bit 31 = 0，VMX non-root 的行为等同于 'enable VM functions' = 0（脚注明确说明），此时 guest 的 VMFUNC 直接 #UD，而不是 VM exit
- VM-entry 检查（§27.2.1.1，旧版 §26.2.1.1）：若 'enable VM functions' = 1，则 VM-function controls 的保留位必须清零，可读 IA32_VMX_VMFUNC (0x491) 判定哪些位保留
- VM-entry 检查：若 'EPTP switching' VM-function 控制 = 1，则 'enable EPT' VM-execution 控制必须也为 1；且 EPTP-list address 必须满足 bits 11:0 = 0（4KB 对齐）且不得设置超出 MAXPHYADDR 的位（IA32_VMX_BASIC[48]=1 时还不得设置 bits 63:32）
- 若 'enable VM functions' = 0，VM entry 完全不检查 VM-function controls —— 里面的垃圾值不会被发现
- EPTP list 结构：正好一个 4KB 物理页，512 个 8 字节小端 EPTP 值，索引 = ECX，取址 = EPTP-list address + 8*ECX。地址是 host-physical，不是 guest-physical，也不是虚拟地址
- list 中被选中的项必须是一个 'valid EPTP value'，判据完全等同于 VM entry 对 EPTP 字段的检查：memory type (bits 2:0) 必须被 IA32_VMX_EPT_VPID_CAP 支持（0=UC 需 bit 8，6=WB 需 bit 14）；bits 5:3（页遍历级数减一）必须为 3（4 级，需 cap bit 6），新版 SDM 允许 4（5 级，需 cap bit 7）；bit 6（EPT A/D）为 1 时需 cap bit 21；保留位 bits 11:7（新版因 bit 7 被定义为 supervisor-shadow-stack 控制而收窄为 11:8，需 cap bit 22）以及 bits 63:MAXPHYADDR 必须全 0
- 推论：一个全 0 的 list 项永远非法（页遍历级数为 0），所以未使用的槽位不能留空，必须填成合法 EPTP（常见做法：填与当前 EPTP 相同的值），否则 guest 用该索引就会 VM exit
- EAX 必须 ≤ 63（架构只允许 VM function 0–63）；ECX 必须 < 512
- VMFUNC 只在 VMX non-root operation 中有意义；在 VMX root（VMM 自身）或非 VMX 环境执行是 #UD
- VMFUNC 不检查 CPL —— SDM 只说 '个别 VM function 可能做额外的错误检查（例如 CPL > 0 时 #GP）'，而 EPTP switching 的规范里没有任何 CPL 检查。因此 guest 的 ring 3 用户态代码可以直接切换 EPT 视图
- EPTP-switching VMFUNC 不修改任何通用寄存器，不修改任何标志位；VPID 与 PCID 不变
- TLB 语义：若 'enable VPID' = 0，切换会失效 VPID 0000H 的所有 combined mappings（对所有 PCID、所有 EP4TA）；若 'enable VPID' = 1，硬件不做额外失效，VMM 必须自己保证 EP4TA 与页表内容一致
- PAE 分页（CR4.PAE=1 且 IA32_EFER.LMA=0）下，EPTP-switching VMFUNC 不重新加载 4 个 PDPTE，继续沿用已有的 guest-physical 值
- VMFUNC 指令本身不会因为 CR3 / PDPTE 中 guest-physical 地址在新 EPT 下的翻译而产生 EPT violation 或 EPT misconfiguration —— 这类退出被推迟到 VMFUNC 之后的第一次内存访问


### 失败模式

- 只置了 secondary controls bit 13 而忘了 primary controls bit 31（activate secondary controls）：VM entry 不会报错（bit 31=0 时 secondary controls 根本不被检查），但 guest 执行 VMFUNC 收到 #UD。表现为“配置看起来对但功能不生效”。避免方法：写 secondary controls 前先 assert primary bit 31 已置，且用 IA32_VMX_PROCBASED_CTLS bit 63 确认支持
- VM-function controls 写入了 IA32_VMX_VMFUNC 未报告的保留位 / EPTP switching=1 但 enable EPT=0 / EPTP-list address 未 4KB 对齐或超出 MAXPHYADDR：VM entry 直接失败，VMLAUNCH/VMRESUME 走 VMfailValid 路径，VM-instruction error = 7 'VM entry with invalid control field(s)'。避免方法：所有控制位用 allowed-0/allowed-1 掩码 (val &= hi; val |= lo) 规整，EPTP-list 页用专门的连续物理页分配器并断言低 12 位为 0
- EPTP list 中留了全 0 的空槽，或填了 memory type / 页遍历级数不被本机支持的 EPTP：guest 一旦用该索引就得到 exit reason 59，而不是切换成功。这类退出没有 exit qualification，VMM 很难区分“ECX 越界”“EPTP 非法”“功能未启用”三种原因。避免方法：初始化时把 512 项全部填成合法 EPTP，并且用与 VM-entry 完全相同的判据在 VMM 侧自检一遍每一项
- 忘了在 VM-exit dispatcher 里实现 exit reason 59 的处理分支：VMFUNC 失败时 VMM 走 default 分支，通常是不推进 RIP 直接 VMRESUME → guest 无限重复执行同一条 VMFUNC 而活锁，或 VMM 注入 #UD 导致 guest 三重故障。避免方法：显式实现 case 59，读 VM-exit instruction length 推进 RIP，并向 guest 注入 #UD 或按策略处理
- 安全模型误判：因为 VMFUNC 不检查 CPL，guest 里任何 ring 3 进程都能任意切换到 list 中的任意 EPT 视图。如果某个视图被设计成“只有内核受信任代码才能看到的隐藏页”，这个假设是错的。避免方法：要么让 list 中所有视图对不受信任代码都同样安全（受保护视图里把入口页设为 execute-only 且入口后立刻校验），要么干脆不启用 'enable VM functions'，让 guest 的 VMFUNC 变成 #UD，改由 VMM 拦截触发点
- 把 EPTP-list 页映射进了 guest 的 EPT（guest 可写）：guest 自己就能往 list 里填任意 EPTP，等于把 EPT 配置权交给了 guest。避免方法：EPTP-list 所在物理页在所有 EPT 视图中都必须不可访问
- 把 guest-physical 地址（或内核虚拟地址）写进 EPTP-list address / list 项的 PFN：VM entry 可能因为对齐和 MAXPHYADDR 都合法而通过，运行期表现为 EPT misconfiguration 或访问到错误内存。避免方法：所有写入这些字段的值一律经过 MmGetPhysicalAddress / virt_to_maddr 之类的显式转换，并断言页对齐
- 切换到一个 bit 6（EPT A/D）为 1 的 EPTP，但自上次使用同样 bits 51:12（EP4TA）且 bit 6 为 0 的 EPTP 以来没有执行过 INVEPT：SDM 明确说明后续内存访问可能不按预期设置 A/D 位。避免方法：改变同一 EP4TA 的 A/D 语义前必须 INVEPT（single-context 或 global）
- 修改了某个视图的 EPT 页表内容后不 INVEPT 就依赖 VMFUNC 切过去：VMFUNC 在 VPID 启用时不做任何刷新，会命中陈旧的 guest-physical / combined mapping，表现为“钩子时有时无”的偶发性 bug。避免方法：任何 EPT PTE 写入后对相应 EPTP 做 INVEPT，多核场景要 IPI 到所有已用过该 EPTP 的 LP
- 配了 #VE 但没写 EPTP index 或没写 virtualization-exception information address：#VE 处理程序拿不到当前视图号，或写 VIRT_EXCEPTION_INFO 缺失导致行为异常。避免方法：参照 Xen 的做法，在开启 SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS 的同时把 EPTP_INDEX 和 VIRT_EXCEPTION_INFO 一起写好并保持同步
- PAE guest 下假设 VMFUNC 会重新加载 PDPTE：不会。切换后 guest 仍用旧的 4 个 guest-physical PDPTE 值，视图设计如果依赖 CR3 页表在新视图下被重定向就会失效
- 在多处理器上只在一个 LP 上配置了 VMCS 的 VM-function controls / EPTP-list address：VMCS 是 per-LP 的，其他核上 VMFUNC 直接 #UD。避免方法：把这些字段的写入放进每核统一的 VMCS 初始化路径并加自检


### 来源

- Intel® 64 and IA-32 Architectures Software Developer's Manual, Vol. 3C, §26.5.6 “VM Functions”（含 §26.5.6.1 Enabling VM Functions、§26.5.6.2 General Operation of the VMFUNC Instruction、§26.5.6.3 EPTP Switching）—— 旧版编号为 §25.5.5 / 25.5.5.1 / 25.5.5.2 / 25.5.5.3
- SDM Vol. 3C, §25.6.14 “VM-Function Controls” 与 Table 25-11 “Definitions of VM-Function Controls”（旧版 §24.6.14 / Table 24-9）—— EPTP list 为 512 个 8 字节项、EPTP-list address 字段的定义出处
- SDM Vol. 3C, §25.6.2 与 Table 25-7 “Definitions of Secondary Processor-Based VM-Execution Controls”，bit 13 = Enable VM functions（旧版 §24.6.2 / Table 24-7）
- SDM Vol. 3C, §27.2.1.1 “VM-Execution Control Fields”（VM entry 对控制字段的检查：VM-function 保留位、EPTP switching ⇒ enable EPT、EPTP-list address 对齐与 MAXPHYADDR、EPTP 合法性判据）—— 旧版 §26.2.1.1
- SDM Vol. 3C, Ch. 31 “VMX Instruction Reference”：VMFUNC—Invoke VM Function（§31.3）；§31.2 Conventions；VM-Instruction Error Numbers（error 7 = VM entry with invalid control field(s)）。旧版为 Ch. 30
- SDM Vol. 3C, Ch. 29 “VMX Support for Address Translation”（EPT 机制、EPTP 字段布局、INVEPT 语义）—— 旧版 Ch. 28，EPT 主体在 §28.2
- SDM Vol. 3D, Appendix A “VMX Capability Reporting Facility”：A.3.2/A.3.3（IA32_VMX_PROCBASED_CTLS / PROCBASED_CTLS2）、A.10（IA32_VMX_EPT_VPID_CAP）、A.11 “VM Functions”（IA32_VMX_VMFUNC, MSR 491H，及其存在条件 = PROCBASED_CTLS bit 63 且 PROCBASED_CTLS2 bit 45）
- SDM Vol. 3D, Appendix B “Field Encoding in VMCS”：Table B-1（16-bit 控制字段，EPTP index = 00000004H）、Table B-4（64-bit 控制字段，VM-function controls = 00002018H/19H，EPT pointer = 0000201AH/1BH，EPTP-list address = 00002024H/25H）
- SDM Vol. 3C, Appendix C “VMX Basic Exit Reasons”：59 (3BH) = VMFUNC
- https://www.felixcloutier.com/x86/vmfunc （SDM 2023-12 抽取版：NP 0F 01 D4；#UD if executed outside VMX non-root operation / if “enable VM functions” is 0 / if EAX ≥ 64；正文引用 Section 26.5.6）
- https://www.felixcloutier.com/x86/invept （用于交叉确认当前版 SDM 的章号：Chapter 29 “VMX Support for Address Translation”、Figure 31-1、Section 31.2）
- SDM Vol.3 全文镜像（较旧版本，章号 -1，用于逐字核对 §25.5.5.x / §24.6.14 / §26.2.1.1 / Appendix A.11 / Appendix B 原文）：https://xem.github.io/minix86/manual/intel-x86-and-64-manual-vol3/o_fe12b1e2a880e0ce-1087.html、-1088.html、-1089.html、-1062.html、-1096.html、-1097.html、-1950.html、-1951.html、-1953.html、-1057.html
- Linux KVM 源码（第三方实现交叉验证）：arch/x86/include/asm/vmx.h —— VM_FUNCTION_CONTROL=0x2018/0x2019、EPTP_LIST_ADDRESS=0x2024/0x2025、VMFUNC_EPTP_ENTRIES=512、VMX_EPTP_PWL_4=0x18/PWL_5=0x20、VMX_EPT_PAGE_WALK_4_BIT=1<<6 / 5_BIT=1<<7 / VMX_EPT_AD_BIT=1<<21、VMX_EPTP_UC_BIT=1<<8 / WB_BIT=1<<14、VMXERR_ENTRY_INVALID_CONTROL_FIELD=7；arch/x86/include/uapi/asm/vmx.h —— EXIT_REASON_VMFUNC=59；arch/x86/include/asm/msr-index.h —— MSR 0x482/0x48B/0x48C/0x48E/0x491
- Linux KVM arch/x86/kvm/vmx/nested.c —— handle_vmfunc()/nested_vmx_eptp_switching()/nested_vmx_check_eptp()：#UD 优先于 VM exit、function>63 → #UD、ECX ≥ 512 → exit、EPTP 合法性检查与保留位 (eptp>>7)&0x1f，以及 VM entry 侧 “EPTP switching ⇒ nested_cpu_has_ept + page_address_valid(eptp_list_address)”
- Xen Project 源码（第三方生产实现，altp2m 即基于 EPTP switching）：xen/arch/x86/hvm/vmx/vmx.c —— vmx_vcpu_update_vmfunc_ve() 写 VM_FUNCTION_CONTROL=VMX_VMFUNC_EPTP_SWITCHING、EPTP_LIST_ADDR=virt_to_maddr(altp2m_visible_eptp)、EPTP_INDEX 与 VIRT_EXCEPTION_INFO 的联动，以及 EXIT_REASON_VMFUNC 的拦截处理 vmx_vmfunc_intercept()


---

## Intel VMX 虚拟化异常 (#VE, vector 20) 与 EPT-violation #VE 转换机制

#VE 是向量 20 的处理器异常（fault，不压错误码），只可能在 VMX non-root 操作中产生。当二级处理器执行控制位 "EPT-violation #VE"（bit 18）为 1 时，部分 EPT violation 不再产生 VM exit，而是在 guest 内部直接投递 #VE。是否可转换（convertible）由该次转换中"恰好一个"EPT 表项的 bit 63（suppress-#VE）决定：bit 63=0 才可转换；对非 present 项看该项的 bit 63，对映射页的叶项看叶项的 bit 63，对指向下级 EPT 结构的中间项 bit 63 被忽略。EPT misconfiguration 永远只产生 VM exit，不可转换。可转换的 EPT violation 还必须同时满足 CR0.PE=1、逻辑处理器当前不在投递事件、非 shadow stack 过早置忙、非 Intel PT 输出、非 PEBS，且虚拟化异常信息区偏移 4 处的 32 位为全 0，才真正变成 #VE；否则仍是 VM exit（exit reason 48）。投递 #VE 时处理器把 exit reason/qualification/GLA/GPA/EPTP index 写进虚拟化异常信息区，并把偏移 4 写成 FFFFFFFFH（busy/in-use 标志），因此下一次 #VE 必须由 guest 软件自己清零该字段才可能发生——这是硬件层面的重入防护。信息区物理地址由 VMCS 字段 Virtualization-exception information address（0202AH/0202BH）给出，EPTP index 由 16 位控制字段 00000004H 给出（VMFUNC 0 会更新它）。若 VMCS 异常位图 bit 20 为 1，#VE 仍然直接 VM exit。


### 能力探测

| 探测什么 | 在哪读 |
|---|---|
| CPU 是否支持 VMX | `CPUID.01H:ECX.VMX[bit 5]` |
| 是否支持 "activate secondary controls"（主控制位 31）；不支持则二级控制整体不可用，PROCBASED_CTLS2 MSR 也不存在 | `IA32_VMX_PROCBASED_CTLS (MSR 482H) bit 63 = 1（即 allowed-1 of primary bit 31）；SDM Appendix A.3.2 / A.3.3` |
| 是否支持 1-setting of "EPT-violation #VE"（二级控制位 18）——这是 #VE 的总开关能力位 | `IA32_VMX_PROCBASED_CTLS2 (MSR 48BH) bit 50（= bit 32+18，allowed-1 半区）；SDM Appendix A.3.3` |
| 是否支持 EPT（#VE 只在 EPT 打开时才有意义） | `IA32_VMX_PROCBASED_CTLS2 (MSR 48BH) bit 33（= 32+1，"enable EPT"）` |
| VMCS 中 VE 信息地址字段 / EPTP index 字段是否存在 | `与上面的 bit 50 同一判据：SDM Table B-1 注 3 与 Table B-4 注 11 都写明「该字段仅在支持 EPT-violation #VE 1-setting 的处理器上存在」。也可用 VMWRITE 探测：不支持时 VMfailValid，VM-instruction error 12 (VMWRITE to unsupported VMCS component)` |
| EPTP switching（VMFUNC 0，会写 EPTP index，从而影响 ve_info 偏移 32） | `IA32_VMX_VMFUNC (MSR 491H) bit 0；二级控制位 13 "enable VM functions" 由 IA32_VMX_PROCBASED_CTLS2 bit 45 报告` |
| execute-only EPT 等叶项能力（影响 misconfiguration 判定，misconfig 不可转换） | `IA32_VMX_EPT_VPID_CAP (MSR 48CH)；SDM Appendix A.10` |


### 相关 VMCS 字段

| 字段 | 编码 | 含义 |
|---|---|---|
| Virtualization-exception information address (full) | `0000202AH` | 虚拟化异常信息区的物理地址（64 位控制字段）。处理器直接用该物理地址写入，不经过 guest 分页/EPT 翻译。SDM Table B-4 / Section 27.6.19 |
| Virtualization-exception information address (high) | `0000202BH` | 同上字段的高 32 位半访问编码（32 位模式下用） |
| EPTP index | `00000004H` | 16 位控制字段（index 000000010B）。EPT violation 转成 #VE 时，处理器把该字段当前值写到 ve_info 偏移 32；EPTP-switching VMFUNC (VMFUNC 0) 会把 ECX[15:0] 装载进该字段。SDM Table B-1 / Section 27.6.19 / 28.5.7.3 |
| Secondary processor-based VM-execution controls | `0000401EH` | bit 18 = "EPT-violation #VE"：置 1 时 EPT violation 可能产生 #VE 而非 VM exit。SDM Table 27-7 / Section 27.6.2 |
| Primary processor-based VM-execution controls | `00004002H` | bit 31 = "activate secondary controls"，必须为 1，否则二级控制（含 bit 18）一律按 0 处理 |
| Exception bitmap | `00004004H` | bit 20 对应 #VE。若为 1，虚拟化异常直接产生 VM exit（按 vector 20、无错误码的 hardware exception 记录），而不是投递给 guest。SDM Section 27.6.3 / 28.5.8.3 |
| Exit reason | `00004402H` | EPT violation 的 basic exit reason = 48 (00000030H)；转成 #VE 时该值被写进 ve_info 偏移 0 而不是 VMCS |
| Exit qualification | `00006400H` | EPT violation 的访问权限/类型限定；转成 #VE 时写进 ve_info 偏移 8 |
| Guest-linear address | `0000640AH` | 转成 #VE 时写进 ve_info 偏移 16 |
| Guest-physical address | `00002400H` | 转成 #VE 时写进 ve_info 偏移 24 |
| EPT pointer (EPTP) | `0000201AH` | EPT 根指针；EPT 叶项 bit 63 的 suppress-#VE 语义只在 "EPT-violation #VE" = 1 时生效。SDM Section 27.6.11 |


### 架构约束

- 虚拟化异常信息区（ve_info）结构 —— SDM Vol.3C Table 28-23：偏移 0 (32 位) = 若发生 VM exit 本应写入 VMCS 的 exit reason，对 EPT violation 恒为 48 (00000030H)；偏移 4 (32 位) = 投递 #VE 时被处理器写成 FFFFFFFFH，即 busy / in-use 标志；偏移 8 (64 位) = 本应写入的 exit qualification；偏移 16 (64 位) = 本应写入的 guest-linear address；偏移 24 (64 位) = 本应写入的 guest-physical address；偏移 32 (16 位) = 当前 EPTP index 控制字段值。共占用 34 字节，其余部分未定义。Linux 内核 struct vmx_ve_information（arch/x86/include/asm/vmx.h）与此逐字段一致。
- 可转换性判据（SDM 28.5.8.1）：控制位为 0 时 EPT violation 一律 VM exit；控制位为 1 时，由该次翻译中恰好一个 EPT 表项的 bit 63 决定 —— 若 GPA 翻译不出物理地址，用那个 not-present 项（bits 2:0 全 0，或在 mode-based execute control 下 bits 2:0 与 bit 10 全 0）的 bit 63；若翻译成功，用映射页的那个叶项（bit 7=1 的 PDPTE/PDE，或任意 EPT PTE）的 bit 63。bit 63 = 0 → convertible；bit 63 = 1 (suppress #VE) → 不可转换，仍 VM exit。
- 指向下一级 EPT 分页结构的中间项（bit 7=0 且非 PTE），其 bit 63 不参与判定，被处理器忽略。所以不能靠在 PML4E/PDPTE 上置位来批量抑制 #VE。
- EPT misconfiguration 永远产生 VM exit，绝不转换成 #VE。
- convertible 之后真正投递 #VE 还需同时满足（SDM 28.5.8.1）：CR0.PE = 1；逻辑处理器当前不处于投递某个事件的过程中；该 EPT violation 未导致 shadow stack 过早置忙（Section 28.4.3）；不是 Intel PT 输出过程引发（28.5.4）；不是 PEBS 引发（28.5.5）；且 ve_info 偏移 4 处的 32 位全为 0。任一不满足 → 退化为普通 EPT violation VM exit。
- busy 字段语义：投递 #VE 时处理器把 FFFFFFFFH 写入偏移 4。此后除非软件把它清零，否则不会再有第二次 #VE（后续可转换的 EPT violation 全部变成 VM exit）。这是硬件级的 #VE 重入防护，也解释了为什么「#VE 不可能在投递另一个异常的过程中被遇到」。
- 因为 guest 需要清零 busy 字段，VMM 必须允许 guest 写 ve_info 页 —— SDM 28.5.8.2 明确把这一点列为 Section 27.11.4（不应让 guest 访问 VMX 相关结构）的例外。
- VM entry 检查（SDM 29.2.1.1）：当 "EPT-violation #VE" = 1 时，virtualization-exception information address 的 bits 11:0 必须为 0（4-KByte 对齐），且必须满足物理地址宽度检查（不得置位超过 MAXPHYADDR 的位）。不满足则 VM entry 失败。
- 若 VMCS 异常位图 bit 20 = 1，#VE 不投递给 guest，而是直接 VM exit，事件按「hardware exception, vector 20, 无错误码」记录在 exiting-event identification 字段（30.2.2）；若 bit 20 = 0 而投递过程中又触发了导致 VM exit 的事件，则记录在 original-event identification 字段（30.2.4）。
- #VE 是 fault 类，不压错误码（SDM Vol.3A Table 7-1；Vol.3C 28.5.8.3）。
- 双重故障严重性：#VE 与 #PF 同级 —— 投递 #VE 期间再遇到 contributory 异常或 page fault 会升级为 #DF。注入侧同理：vector 20 的 hardware exception 在支持该控制位的处理器上不再被视为 benign，而是按 page fault 级别参与 #DF 判定（SDM 29 章脚注）。
- 处理器用物理地址直接访问 ve_info 区，不经 EPT/分页；该页应当 per-vCPU（per-logical-processor）独立分配。
- EPTP index 只有在支持该控制位时才存在；VMFUNC 0（EPTP switching）会用 ECX[15:0] 更新它，从而让后续 #VE 的 ve_info 偏移 32 反映当前 EPTP 视图（SDM 28.5.7.3）。


### 失败模式

- 【最常见】默认语义搞反：EPT 叶项 bit 63 = 0 表示「可转换」。一旦把 "EPT-violation #VE" 置 1，所有 bit 63 为 0 的页的 EPT violation 都会被反射进 guest。对不感知 #VE 的 guest，IDT[20] 通常不存在或指向保留处理，直接 #GP → #DF → triple fault，虚拟机瞬间挂死。设计上：启用该控制位的同时，必须先把所有 EPT 叶项与 not-present 项的 bit 63 批量置 1，再对确实要走 #VE 的页逐个清零。
- guest 的 #VE handler 忘记把 ve_info 偏移 4 清零：之后所有可转换的 EPT violation 静默退化成 VM exit（exit reason 48）。表现为「#VE 只触发一次然后再也不来」、性能与语义都变了却没有任何报错。handler 必须在返回前（且在重新使能可能再次触发的访问之前）写 0。
- ve_info 页跨 vCPU 共享：多个逻辑处理器并发写同一区域，busy 字段和 exit qualification 互相踩踏，读到的是别的 vCPU 的故障信息。必须每个 vCPU 一页，并在每次 VMCS 切换时确保 0202AH 指向本 vCPU 的页。
- ve_info 页自身在 EPT 里没有映射成可写、或它自己的 EPT 叶项 bit 63 没有置 1：guest 访问该页去清 busy 时又触发一次 EPT violation → 递归；虽然 busy 已置位不会真的递归投递 #VE，但会变成一次意料之外的 VM exit，逻辑上死循环。ve_info 页必须始终可写且 suppress-#VE 置 1。
- VMCS 0202AH 未 4KB 对齐或超出 MAXPHYADDR：VM entry 直接失败（VM-instruction error 7, VM entry with invalid control fields），且失败点在 VMLAUNCH/VMRESUME，排查时容易误判成 guest 状态问题。
- 未检查能力位就 VMWRITE 0202AH / 00000004H / 置二级控制位 18：在不支持的处理器上 VMWRITE 失败（error 12）或 VM entry 失败（PROCBASED_CTLS2 bit 50 = 0）。必须先读 MSR 482H bit 63 与 MSR 48BH bit 50。
- 只置了二级控制位 18 却忘了主控制位 31（activate secondary controls）：整个二级控制被当作全 0，#VE 静默不生效，看起来像「CPU 不支持」。
- 忘了异常位图 bit 20：如果因为别的原因（比如通用异常拦截）把 bit 20 置成了 1，所有 #VE 都变回 VM exit，#VE 的性能收益完全消失且难以察觉。
- 信任 ve_info 内容：guest 对该页有写权限，可以任意伪造 exit reason / GPA / qualification。VMM 侧（以及 guest 内的安全逻辑）绝不能把 ve_info 的内容当作可信输入用于权限判定，必须用 VMCS 里的真实退出信息或重新校验。
- 用 #VE 做隐蔽性/内省时忽略 guest ring 3：#VE 可以在任意 CPL 投递（判据里只要求 CR0.PE=1），用户态代码也能触发并观察到，从而探测到 hypervisor 的存在；同样，实模式（CR0.PE=0）guest 永远不会收到 #VE，相关路径要有 VM exit 兜底。
- 依赖「EPT misconfiguration 也能转 #VE」：不会。用 misconfig 做的隐藏页方案必须保留 VM exit 处理路径。
- EPTP switching 后忘记同步 EPTP index 字段的语义假设：VMFUNC 0 会改写该字段，若 VMM 自己也 VMWRITE 该字段，两者会互相覆盖，导致 ve_info 偏移 32 指向错误的 EPT 视图，多视图（如 #VE + EPTP switching 组合的隐藏内存方案）会解错页表。


### 来源

- Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3 (3A/3B/3C/3D), Order Number 325384-092US, June 2026 — 本次直接下载原始 PDF 逐节核对（https://cdrdv2.intel.com/v1/dl/getContent/671447）
- SDM Vol. 3C, Section 28.5.8 "Virtualization Exceptions" — #VE 使用向量 20、只在 VMX non-root 中发生
- SDM Vol. 3C, Section 28.5.8.1 "Convertible EPT Violations" — suppress-#VE (bit 63) 判定规则 + 转换成 #VE 的全部前置条件 + 偏移 4 全 0 与写 FFFFFFFFH 的 busy 语义
- SDM Vol. 3C, Section 28.5.8.2 "Virtualization-Exception Information" 与 Table 28-23 "Format of the Virtualization-Exception Information Area" — 偏移 0/4/8/16/24/32 完整字段表；并注明这是 Section 27.11.4 的例外（允许 guest 写）
- SDM Vol. 3C, Section 28.5.8.3 "Delivery of Virtualization Exceptions" — 异常位图 bit 20、不压错误码、与 #PF 同级的 #DF 严重性、30.2.2/30.2.4 事件记录
- SDM Vol. 3C, Section 27.6.19 "Controls for Virtualization Exceptions" — virtualization-exception information address (64 位) 与 EPTP index (16 位) 两个控制字段的定义
- SDM Vol. 3C, Section 27.6.2 与 Table 27-7 "Definitions of Secondary Processor-Based VM-Execution Controls" — bit 18 "EPT-violation #VE"
- SDM Vol. 3C, Section 27.6.3 "Exception Bitmap"
- SDM Vol. 3C, Section 29.2.1.1 "VM-Execution Control Fields"（VM entry 检查）— 当 "EPT-violation #VE" = 1 时 VE 信息地址 bits 11:0 必须为 0 并受物理地址宽度检查约束
- SDM Vol. 3C, Chapter 31 "VMX Support for Address Translation", Section 31.3.2 表项格式：Table 31-3 (PDPTE 映射 1GB)、Table 31-5 (PDE 映射 2MB)、Table 31-7 (PTE 映射 4KB) 中 bit 63 = "Suppress #VE"；以及 not-present 项 bit 63 的说明（31.3.2 正文）与 Section 31.3.3 / 31.3.3.1 (EPT misconfiguration 只产生 VM exit)
- SDM Vol. 3C, Section 28.5.7.3 (EPTP switching VMFUNC) — VMFUNC 0 用 ECX[15:0] 更新 EPTP index 字段，后续 #VE 会把它存进 ve_info
- SDM Vol. 3C, Appendix A.3.3 "Secondary Processor-Based VM-Execution Controls" — IA32_VMX_PROCBASED_CTLS2 (48BH)，控制位 X 的 allowed-1 在 bit 32+X（故 bit 18 → bit 50）
- SDM Vol. 3C/3D, Appendix B.1.1 Table B-1 "Encoding for 16-Bit Control Fields"（EPTP index，index 000000010B → 00000004H）；Appendix B.2.1 Table B-4 "Encodings for 64-Bit Control Fields"（Virtualization-exception information address full/high = 0000202AH / 0000202BH，index 000010101B）；Appendix B.3.1 Table B-8（Exception bitmap 00004004H、Secondary controls 0000401EH）
- SDM Vol. 3A, Chapter 7 "Interrupt and Exception Handling", Table 7-1 "Protected-Mode Exceptions and Interrupts" — 向量 20 = #VE, Virtualization Exception, Fault, 无 Error Code, 来源 EPT violations（脚注：仅在支持 "EPT-violation #VE" 1-setting 的处理器上产生）
- 第三方交叉验证 — Linux 内核 arch/x86/include/asm/vmx.h：VE_INFORMATION_ADDRESS = 0x0000202A / _HIGH = 0x0000202B、VMX_EPT_SUPPRESS_VE_BIT = (1ull << 63)、struct vmx_ve_information {u32 exit_reason; u32 delivery; u64 exit_qualification; u64 guest_linear_address; u64 guest_physical_address; u16 eptp_index;}（https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/vmx.h）
- 第三方交叉验证 — Linux 内核 arch/x86/include/asm/vmxfeatures.h：VMX_FEATURE_EPT_VIOLATION_VE = (2*32 + 18)，即二级控制字第 18 位（https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/vmxfeatures.h）


---

## Intel VT-x EPT：多个 EPTP 并存时的架构约束（EPTP 字段格式、INVEPT single/all-context 语义、per-CPU TLB 与 paging-structure cache 失效要求、execute-only 叶项能力探测）

EPTP 只有 bits 51:12（SDM 称 EPTRTA）参与缓存 tag，低位（memory type / walk length / A/D / shadow-stack）不参与。所有 guest-physical 与 combined mapping 按 EPTRTA 打标，因此"换 EPTP"只有换根表物理地址才换 tag。INVEPT type 1 只失效指定 EPTRTA 的 guest-physical + combined mapping（跨所有 VPID/PCID），type 2 失效全部 EPTRTA。缓存是 per-logical-processor 的，改 EPT 项必须对所有用过该 EPTRTA 的 LP 逐个 INVEPT。EPTP 各位与 execute-only 叶项都必须先读 IA32_VMX_EPT_VPID_CAP(48CH) 探测，否则 VM-entry 失败或 EPT misconfiguration。


### 能力探测

| 探测什么 | 在哪读 |
|---|---|
| EPT 特性本身可用（"enable EPT" 次级控制 bit 1 允许置 1） | `IA32_VMX_PROCBASED_CTLS2 (MSR 48CH 之前的 48BH) bit 33；前置条件是 IA32_VMX_PROCBASED_CTLS (MSR 482H) bit 63 = 1，即支持 "activate secondary controls"。SDM Vol 3C 表 27-7、Vol 3D A.3.3` |
| IA32_VMX_EPT_VPID_CAP MSR 本身是否存在 | `MSR index 48CH；仅当支持 "activate secondary controls"（IA32_VMX_PROCBASED_CTLS bit 63 = 1）且支持 enable EPT（CTLS2 bit 33）或 enable VPID（CTLS2 bit 37）时才存在。Vol 3D A.10` |
| EPT 叶项支持 execute-only 翻译（bits 1:0 = 0 且 bit 2 = 1 合法） | `IA32_VMX_EPT_VPID_CAP bit 0。若 MBEC 为 1，此位同时表示允许 bits 1:0 = 0 且 bit 10 = 1。Vol 3D A.10，Vol 3C 31.3.3.1` |
| EPT page-walk length = 4（4 级 EPT，EPTP[5:3] = 3） | `IA32_VMX_EPT_VPID_CAP bit 6` |
| EPT page-walk length = 5（5 级 EPT，EPTP[5:3] = 4） | `IA32_VMX_EPT_VPID_CAP bit 7` |
| EPTP[2:0] 可配置为 UC（值 0） | `IA32_VMX_EPT_VPID_CAP bit 8` |
| EPTP[2:0] 可配置为 WB（值 6） | `IA32_VMX_EPT_VPID_CAP bit 14` |
| EPT PDE 可映射 2MB 大页（PDE bit 7 = 1） | `IA32_VMX_EPT_VPID_CAP bit 16` |
| EPT PDPTE 可映射 1GB 大页（PDPTE bit 7 = 1） | `IA32_VMX_EPT_VPID_CAP bit 17` |
| INVEPT 指令存在（否则执行 INVEPT 触发 #UD） | `IA32_VMX_EPT_VPID_CAP bit 20` |
| INVEPT single-context 型（type 1）可用 | `IA32_VMX_EPT_VPID_CAP bit 25` |
| INVEPT all-context / global 型（type 2）可用 | `IA32_VMX_EPT_VPID_CAP bit 26` |
| EPT 的 accessed/dirty flags（EPTP[6] 可置 1；叶项 bit 8/9 生效） | `IA32_VMX_EPT_VPID_CAP bit 21` |
| EPT violation 的 advanced VM-exit information（exit qualification 扩展位） | `IA32_VMX_EPT_VPID_CAP bit 22（注意：不是 shadow stack 位）` |
| supervisor shadow-stack control：EPTP[7] 可置 1，叶项 bit 60 生效 | `IA32_VMX_EPT_VPID_CAP bit 23。Vol 3D A.10；语义见 Vol 3C 31.3.3.2、Figure 31-1 note 8` |
| INVVPID 指令与其四种类型（0 individual-address / 1 single-context / 2 all-context / 3 single-context-retaining-globals） | `IA32_VMX_EPT_VPID_CAP bit 32（指令），bits 40/41/42/43（各类型）` |
| mode-based execute control for EPT（MBEC，影响叶项 bit 2 与 bit 10 的含义及 present 判据） | `IA32_VMX_PROCBASED_CTLS2 bit 54（次级控制 bit 22）。Vol 3C 表 27-7` |
| EPTP switching VM function（VMFUNC 0），即运行时在 EPTP list 里切换多个 EPTP | `IA32_VMX_VMFUNC (MSR 491H) bit 0，且必须 IA32_VMX_PROCBASED_CTLS2 bit 45（次级 bit 13 "enable VM functions"）可置 1。Vol 3D A.11，Vol 3C 27.6.14 / 28.5.7.3` |
| IA32_VMX_EPT_VPID_CAP 保留位（读为 0，不要当特性用） | `bits 5:1、bits 13:9、bit 15、bits 19:18、bit 24、bits 31:27、bits 39:33、bits 47:44、bits 63:54。bits 53:48 是 HLAT prefix size，不是 EPT 能力` |


### 相关 VMCS 字段

| 字段 | 编码 | 含义 |
|---|---|---|
| EPT pointer (EPTP)，64 位 VM-execution control 字段 | `full = 0000201AH，high = 0000201BH（index 000001101B）` | bits 2:0 = EPT paging-structure memory type（0 = UC，6 = WB，其余保留）；bits 5:3 = EPT page-walk length 减 1（3 = 4 级，4 = 5 级）；bit 6 = 启用 EPT 的 accessed/dirty flags；bit 7 = 启用 supervisor shadow-stack 访问权限强制；bits 11:8 = 保留；bits M-1:12 = 4KB 对齐的 EPT 根表物理地址（4 级为 EPT PML4，5 级为 EPT PML5），M = MAXPHYADDR；bits 63:M = 保留。见 Vol 3C 表 27-9（27.6.11） |
| EPTRTA（EPT root-table address，非独立 VMCS 字段，是 EPTP 的一个切片） | `EPTP[51:12]（40 位）` | 所有 guest-physical mapping 与 combined mapping 的缓存 tag。INVEPT single-context 的匹配依据、"当前 EPTRTA" 的定义都用它。EPTP 低 12 位不参与 tag。Vol 3C 31.4.2 |
| EPTP-list address（EPTP 列表基址，64 位 VM-execution control） | `full = 00002024H，high = 00002025H` | 4KB 结构，512 个 8 字节项，每项一个候选 EPTP，供 VMFUNC 0（EPTP switching）从中选。Vol 3C 27.6.14 / 28.5.7.3 |
| EPTP index（16 位 VM-execution control） | `00000004H（index 000000010B）` | EPTP-switching VMFUNC 会把 ECX[15:0] 写入此字段；EPT violation 转成 #VE 时该值写入 virtualization-exception information area。只在支持 "EPT-violation #VE"（次级 bit 18）的处理器上存在。Vol 3D 表 B-1，Vol 3C 27.6.19 |
| Virtual-processor identifier (VPID)，16 位 VM-execution control | `00000000H` | combined mapping 的第二个 tag 维度。使用不同 EPTP 的多个 guest 可以复用同一个 VPID —— 因为 EPTRTA 已经把它们分开了（Vol 3C 31.4.3.3）。enable VPID = 1 时该字段不得为 0000H |
| VM-function controls（64 位 VM-execution control） | `full = 00002018H，high = 00002019H` | bit 0 = EPTP switching。置 1 时 "enable EPT" 必须也为 1，否则 VM entry 失败。Vol 3C 27.6.14、29.2.1.1 |
| PML address（64 位 VM-execution control） | `full = 0000200EH` | page-modification log 基址，512 个 64 位项；配 PML index（16 位控制字段）。只有 EPTP[6] = 1（A/D 使能）时 PML 才有意义。Vol 3C 31.3.6 |
| Guest-physical address（64 位只读 VM-exit information） | `full = 00002400H，high = 00002401H` | EPT violation（exit reason 48）、EPT misconfiguration（exit reason 49）、SPP 相关退出时报告的 GPA。Vol 3C 30.2.x |


### 架构约束

- 【EPTP 合法性 / VM-entry 检查，Vol 3C 29.2.1.1】若 "enable EPT" = 1，EPTP 必须同时满足：(a) bits 2:0 的内存类型是 IA32_VMX_EPT_VPID_CAP 报告支持的（UC 需 bit 8，WB 需 bit 14）；(b) bits 5:3 的值比某个受支持的 page-walk length 小 1（4 级需 CAP bit 6，5 级需 CAP bit 7）；(c) 若 CAP bit 21 = 0 则 bit 6 必须为 0；(d) 保留位 bits 11:7 必须全 0；(e) bits 63:12 定义的 4KB 对齐地址必须满足 29.2.1 的物理地址宽度检查（MAXPHYADDR 之上的位必须为 0）。任一不满足 → VM entry 失败（VMfail，VM-instruction error "VM entry with invalid control field(s)"）。
- 【SDM 内部不一致，实现时必须保守】表 27-9 把 EPTP bit 7 定义为 supervisor shadow-stack control（能力位 = IA32_VMX_EPT_VPID_CAP bit 23），但同一版 SDM 的 29.2.1.1 仍写 "Reserved bits 11:7 must all be 0"，没有给出 bit 7 的条件放行子句。Linux KVM 的 nested_vmx_check_eptp() 也按 `(new_eptp >> 7) & 0x1f` 全 0 校验。结论：除非确认 CAP bit 23 = 1 并在目标机器上实测 VM entry 通过，否则 EPTP[7] 一律写 0。
- 【缓存 tag 只有 40 位】所有 guest-physical mapping 都与"当前 EPTRTA"（EPTP[51:12]）关联；所有 combined mapping 与 (VPID, PCID, EPTRTA) 三元组关联；linear mapping 不含任何 EPT 信息，且 EPT 启用期间不会新建 linear mapping。EPTP 的 memory type / walk length / A/D / shadow-stack 位都不参与 tag。Vol 3C 31.4.1、31.4.2。
- 【多 EPTP 并存的直接推论】两个 EPTP 只要 bits 51:12 相同，硬件就认为是同一份缓存上下文，哪怕 walk length、A/D、memory type 不同。因此：Y[6]=0 → X[6]=1 且 Y[51:12]=X[51:12] 时，VM entry 前必须做 single-context INVEPT；Y[5:3] ≠ X[5:3] 且 Y[51:12]=X[51:12] 时，同样必须做。Vol 3C 31.4.3.4。
- 【INVEPT type 1（single-context）语义】失效与 INVEPT descriptor 中 EPTP 的 bits 51:12 关联的**全部** guest-physical mapping 和 combined mapping；combined 部分对该 EPTRTA 下的所有 VPID、所有 PCID 都失效（包括 SEAM 用的 VPID 10000H-1FFFFH）。允许（但不保证）连带失效其它 EPTRTA。它是"整个 EPT 上下文"粒度，没有按 GPA 的细粒度型别。Vol 3C 31.4.3.1，Vol 3C Ch.33 INVEPT。
- 【INVEPT type 2（all-context / global）语义】失效所有 EPTRTA 的 guest-physical mapping 和 combined mapping（combined 对所有 VPID 与 PCID）。不需要读 descriptor 里的 EPTP 值，但 SDM 规定内存操作数**仍然会被读取**（因此地址必须可访问，否则 #PF/#GP/#SS）。Vol 3C Ch.33 INVEPT。
- 【INVEPT 的 VMfail 条件】type 1 时，若描述符里的 EPTP 是一个"会导致 VM entry 失败"的值，指令 VMfail(Invalid operand to INVEPT/INVVPID)，不是静默成功。所以用于 shootdown 的 EPTP 必须是完整合法值，不能只填根表地址。若 CAP 没报告该 type（bit 25 / bit 26），同样 VMfail。若 CAP bit 20 = 0 或 CTLS2 bit 33 = 0，执行 INVEPT 触发 #UD。CPL > 0 触发 #GP(0)；在 VMX non-root 中执行则产生 VM exit。
- 【INVEPT 与 INVVPID 不可互换】INVEPT 不要求失效任何 linear mapping；INVVPID 不要求失效任何 guest-physical mapping；架构级 TLB 失效指令（INVLPG/INVPCID/MOV to CR3/CR4.PGE 翻转）只失效 linear 与 combined mapping，不要求失效 guest-physical mapping。Vol 3C 31.4.3.2。
- 【VMX transition 不救你】只有当 "enable VPID" = 0 时，VM entry/VM exit 才失效 VPID 0000H 的 linear 与 combined mapping（对所有 PCID、所有 EPTRTA）。VMX transition 从不保证失效 guest-physical mapping；enable VPID = 1 时连 linear/combined 也不保证失效。VMXON/VMXOFF 同样不保证失效任何东西。Vol 3C 31.4.3.1、31.4.3.2。
- 【per-LP 语义：这是多 EPTP 场景最容易踩的】缓存是每个逻辑处理器独立的。SDM 明确要求："software must account for the fact that information from an EPT paging-structure entry may be cached on logical processors other than the one that modifies that entry"，即必须做 EPT 版的 TLB shootdown（IPI 到所有可能加载过该 EPTRTA 的 LP，各自本地执行 INVEPT）。Vol 3C 31.4.3.4 末段，交叉引用 Vol 3A 5.10.5。
- 【什么时候必须 INVEPT（type 1）】修改 EPT 项后出现下列任一情况：privilege bits 2:0 由 1 改 0（MBEC = 1 时还包括 bit 10 由 1 改 0）；改 bits 51:12 的物理地址；在将启用 A/D 的前提下清 bit 8（accessed）；对 EPT PDPTE/PDE 改 bit 7（是否映射大页）；对最后一级项改 bits 5:3 或 bit 6（影响 effective memory type）；在将启用 A/D 的前提下对最后一级项清 bit 9（dirty）。Vol 3C 31.4.3.4。
- 【什么时候可以不 INVEPT】权限位 2:0 由 0 改 1（提权）只需要"可以"做，不做最多多一次 EPT violation，而 EPT violation 本身就会失效引发它的那条 guest-physical mapping（以及对应线性地址的 combined mapping），所以重试即可通过。修改此前 not-present 或 misconfigured 的项也不需要 INVEPT，因为处理器根本不会缓存这类项的信息。Vol 3C 31.4.3.1、31.4.3.4。
- 【EPTP switching（VMFUNC 0）的额外约束】候选 EPTP 有效当且仅当：(1) bits 5:3 与当前 EPTP 完全相同（page-walk length 不允许被 guest 改），且 (2) 该值不会导致 VM entry 失败。ECX ≥ 512 或值无效 → VM exit（basic exit reason 59 VMFUNC，无附加 exit 信息）。切换后处理器立刻开始用新 EPTP[51:12] 建/用 mapping，VPID 与 PCID 不变；若 enable VPID = 0，切换会失效 VPID 0000H 的 combined mapping（所有 PCID、所有 EPTRTA）。若新 EPTP 的 bit 6 = 1 而此前用过同一根表且 bit 6 = 0 的 EPTP，且期间没做过 INVEPT，则 A/D 位可能不按规范置位。"Intel PT uses guest physical addresses" = 1 且 TraceEn = 1 时任何 VMFUNC 0 都强制 VM exit。Vol 3C 28.5.7.3。
- 【execute-only 叶项的合法编码】CAP bit 0 = 1 时，允许叶项 bits 1:0 = 0（禁读禁写）而 bit 2 = 1（允许取指）；MBEC = 1 时还允许 bits 1:0 = 0 而 bit 10 = 1。CAP bit 0 = 0 时这两种编码都是 **EPT misconfiguration**（exit reason 49），不是 EPT violation。与能力无关、恒为 misconfiguration 的是：bit 0 = 0 且 bit 1 = 1（不可读但可写）。Vol 3C 31.3.3.1，Vol 3D A.10。
- 【EPT 项的 present 判据】bits 2:0 任一为 1 即 present；MBEC = 1 时 bits 2:0 或 bit 10 任一为 1 即 present（bits 2:0 全 0 但 bit 10 = 1 时该项正常参与遍历）。not-present 时处理器忽略 bits 62:3，访问触发 EPT violation；"EPT-violation #VE" = 1 时该 violation 是否可转 #VE 取决于 bit 63（suppress #VE）。Vol 3C 31.3.2。
- 【其它必然导致 misconfiguration 的编码】任何保留位置位（含 bits 51:12 中 MAXPHYADDR 及以上的位）；最后一级项（PDPTE bit7=1 / PDE bit7=1 / PTE）的 bits 5:3（EPT memory type）取值 2、3 或 7；"EPT paging-write control" = 1 且映射页的项 bit 58 = 1 而 bit 0 = 0。Vol 3C 31.3.3.1。
- 【enable EPT 的连带要求】下列控制任一为 1 时，"enable EPT" 必须为 1：enable PML、unrestricted guest、mode-based execute control for EPT、sub-page write permissions for EPT、Intel PT uses guest physical addresses、PEBS uses guest physical addresses、enable HLAT、EPT paging-write control、guest-paging verification。另："EPTP switching" VM-function 控制为 1 时，"enable EPT" 也必须为 1。Vol 3C 29.2.1.1。
- 【EPTP 内存类型的作用范围】EPTP[2:0] 只决定访问 **EPT 分页结构本身** 时用的内存类型，且仅当 CR0.CD = 0；CR0.CD = 1 时一律 UC。MTRR 对 EPT 分页结构访问和对 GPA 访问都无效。被翻译 GPA 的 effective memory type 由叶项 bits 5:3（0=UC,1=WC,4=WT,5=WP,6=WB）、叶项 bit 6（IPAT，1 表示忽略 PAT）与 PAT 组合决定。Vol 3C 31.3.7.1、31.3.7.2。
- 【supervisor shadow-stack 语义（EPTP[7] = 1 时）】supervisor shadow-stack 访问被拒当且仅当：翻译路径上任一 EPT 项 bit 0（read）为 0；或翻译路径上任一**引用下级结构**的 EPT 项 bit 1（write）为 0（映射页的那一项 bit 1 = 0 不阻止 shadow-stack 读写）；或映射页的那一项 bit 60（supervisor shadow-stack）为 0。该机制不影响其它访问，也不影响 user shadow-stack 访问。EPTP[7] = 0 时叶项 bit 60 被忽略。Vol 3C 31.3.3.2、Figure 31-1 note 8。
- 【章节号跨版本会变，引用时要带版本】本答案基于 325462-092（2026 年 6 月）：Vol 3C Ch.27 = VMCS，Ch.28 = VMX Non-Root Operation，Ch.29 = VM Entries，Ch.30 = VM Exits，Ch.31 = VMX Support for Address Translation，Ch.33 = VMX Instruction Reference；Vol 3D App. A = VMX Capability Reporting，App. B = VMCS Field Encoding。较老的常见版本（rev 070 前后）对应为 Ch.24 / 25 / 26 / 27 / 28 / 30 与同名附录；felixcloutier 抓取的 2023-12 版本里 INVEPT 在 Ch.31。跨版本引用 EPT 时务必写清 revision。


### 失败模式

- 只在改 EPT 表的那颗 CPU 上执行 INVEPT。其它 LP 继续用旧的 guest-physical / combined mapping，表现为"权限降级不生效"：本应触发 EPT violation 的写入被静默放行，隐藏页/保护页失守，且难复现（取决于 vCPU 落在哪个 LP）。设计上避免：把 EPT 修改封装成一个必须走 shootdown 的操作——先改表，再向所有曾加载过该 EPTRTA 的 LP 发 IPI，每个 LP 本地执行 single-context INVEPT，等全部确认后才认为修改生效；简单起见可对所有在 VMX 操作中的 LP 无差别广播。
- 误以为"换了 EPTP 就换了缓存上下文"。只有 bits 51:12 变了才换 tag。复用同一根表物理地址而只改 walk length（bits 5:3）或 A/D（bit 6），缓存不换 tag，旧条目会被继续使用：A/D 位不再被置位（PML/脏页跟踪整片漏记），或按错误层数解释 GPA。设计上避免：把 EPTP 视为 (根表地址, 配置位) 二元组，任何配置位变化而根表地址不变的路径，强制在 VMENTRY 前插一条针对该 EPTRTA 的 single-context INVEPT；更省事的做法是每套配置各分配一份独立根表页。
- 用 INVVPID 代替 INVEPT（或反过来）。架构上 INVVPID 不要求失效任何 guest-physical mapping，INVEPT 不要求失效任何 linear mapping；在某些微架构上碰巧有效会掩盖 bug，换代 CPU 后爆炸。设计上避免：在代码里把两者绑定到不同的失效目的（EPT 表改动 → INVEPT；guest 页表/VPID 语义改动 → INVVPID），不允许互相替代；改 EPT 后如果还担心 combined mapping，注意 INVEPT type 1 已经覆盖了该 EPTRTA 下所有 VPID/PCID 的 combined mapping，不需要再补 INVVPID。
- 不探测就发 INVEPT。CAP bit 20 = 0 或 CTLS2 bit 33 = 0 时执行 INVEPT 直接 #UD（在 VMM 的 ring0 上下文里就是蓝屏 / kernel panic）；type 1 未被 bit 25 报告、type 2 未被 bit 26 报告时是 VMfail 而不是异常，若代码不检查 RFLAGS.CF/ZF 就会误以为失效成功。设计上避免：初始化阶段一次性读 IA32_VMX_EPT_VPID_CAP 并缓存到全局能力结构；封装一个 invept() 包装函数，内部断言 type 已被支持，并强制检查 VMsucceed/VMfailValid 返回。
- INVEPT type 1 的描述符里只填根表物理地址、其余位留 0。若当前 EPTP 用的是 WB(6) 而描述符写 0(UC)，或 walk length 位为 0，这个值"会导致 VM entry 失败"，指令 VMfail 而不是失效缓存 —— 失效实际上没发生。设计上避免：shootdown 时直接复用保存下来的完整 EPTP 原值（VMREAD 201AH 或从自己的 EPT 上下文结构里取），绝不现场拼装。
- 假设 execute-only 可用。在 CAP bit 0 = 0 的处理器上写下 R=0/W=0/X=1 的叶项，取指与数据访问都会变成 EPT misconfiguration（exit reason 49）而非 EPT violation（48）：GPA 会被报告但没有 violation 的 exit qualification 语义，也不能走 #VE 路径，通常在 VMM 里落到"未预期退出"分支导致 guest 崩溃或 VMM 死循环。设计上避免：初始化时读 CAP bit 0，若为 0 则把 X-only 策略降级为 R+X（bit0=1, bit2=1）＋依赖 EPT violation 上的单步/影子页切换来模拟"只可执行不可读"，并在退出处理里同时实现 48 和 49 两个 reason 的处理路径。
- 把 EPTP[7]（supervisor shadow-stack）当成可以随便置的位。SDM 29.2.1.1 目前仍把 bits 11:7 整体列为保留必须为 0，KVM 也这么校验；在不支持或按保守规则校验的环境（尤其嵌套虚拟化）里，置位会让 VM entry 失败并返回 VM-instruction error 7（invalid control field），而这个错误往往被上层笼统当成"EPTP 非法"，排查方向被带偏。设计上避免：EPTP[11:7] 默认硬编码为 0；确需 shadow-stack 强制时，先查 CAP bit 23，再在目标平台做一次"试探性 VMLAUNCH"验证，失败就回退到 0，并且把这个判定结果缓存起来而不是每次重试。
- 依赖 VM exit / VM entry 自动清缓存。只有 enable VPID = 0 时进出才失效 VPID 0000H 的 linear/combined mapping；guest-physical mapping 从不由 VMX transition 保证失效。开了 VPID 之后，"退出到 VMM 改表、重新进入"这个直觉上安全的序列其实什么都没失效。设计上避免：把 INVEPT 放在 EPT 表修改函数的出口（而不是 VMENTRY 路径上顺手做），使得"改表"与"失效"在代码上不可分离。
- 清 A/D 位（叶项 bit 8/9 由 1 改 0）后不做 INVEPT。SDM 明说处理器可能不再对受影响的 GPA 重新置位，于是 PML 日志和脏页位图整片丢数据——热迁移/快照场景下表现为静默的数据不一致，而不是崩溃，最难查。设计上避免：把"清 A/D"和"针对该 EPTRTA 的 INVEPT + 全 LP shootdown"做成一个原子操作，任何清位路径都不允许绕过。
- 把 EPTP-switching VMFUNC 当成廉价的上下文切换。guest 可以自行执行 VMFUNC 0，切换到 EPTP list 里任意一项；只要 bits 5:3 一致且能通过 VM-entry 检查就成功，VMM 不会收到通知。若 list 里放了权限更宽的视图，等于把提权原语交给了 guest。设计上避免：EPTP list 里只放同等或更严格的视图；不需要 guest 主动切换时干脆不开 "enable VM functions"；需要 #VE 联动时记得 VMFUNC 会覆写 EPTP index 字段，VMM 侧的镜像变量必须同步刷新。
- 以为 all-context INVEPT（type 2）比 single-context 更安全所以到处用。它确实覆盖所有 EPTRTA，但代价是把该 LP 上所有 guest 的 EPT 缓存全清；在多 vCPU / 多 VM 场景下会造成明显的 TLB 抖动。SDM 给出的正当用途是 VMXON 之后、VMXOFF 之前各来一次，防止跨 VMX 使用期残留。设计上避免：常规表改动一律用 type 1，type 2 只保留在 VMXON/VMXOFF 边界与不可恢复的兜底路径上。


### 来源

- Intel® 64 and IA-32 Architectures Software Developer's Manual, Combined Volumes 1, 2A-2D, 3A-3D, 4 — 文档号 325462-092，2026 年 6 月版（本次实际下载并逐节核对的一手来源）：https://cdrdv2.intel.com/v1/dl/getContent/671200 （重定向到 https://cdrdv2-public.intel.com/922475/325462-092-sdm-vol-1-2abcd-3abcd-4.pdf ）
- SDM Vol. 3C, §27.6.11 "Extended-Page-Table Pointer (EPTP)" 与 Table 27-9 "Format of Extended-Page-Table Pointer" —— EPTP 位域完整定义（memory type / walk length / A/D / supervisor shadow-stack / 地址 / 保留位）
- SDM Vol. 3C, §27.6.14 "VM-Function Controls" 与 Table 27-10 —— EPTP switching VM function 与 EPTP-list address
- SDM Vol. 3C, §27.6.2 Table 27-7 "Definitions of Secondary Processor-Based VM-Execution Controls" —— enable EPT = bit 1、EPT-violation #VE = bit 18、MBEC = bit 22、SPP = bit 23
- SDM Vol. 3C, §28.5.7.3 "EPTP Switching" —— VMFUNC 0 的有效性判据（bits 5:3 必须与当前一致 + 必须能通过 VM entry）、切换后的缓存行为、A/D 位与 INVEPT 的相互作用
- SDM Vol. 3C, §29.2.1.1 "VM-Execution Control Fields"（VM entry 对控制字段的检查）—— EPTP 的五条检查，含 "Reserved bits 11:7 must all be 0"
- SDM Vol. 3C, §31.3 "The Extended Page Table Mechanism (EPT)"：31.3.1 概述、31.3.2 翻译机制（4 级/5 级、present 判据）、31.3.3.1 EPT Misconfigurations、31.3.3.2 EPT Violations（含 supervisor shadow-stack 规则）、31.3.5 Accessed and Dirty Flags、31.3.6 Page-Modification Logging、31.3.7 EPT and Memory Typing；Figure 31-1 "Formats of EPTP and EPT Paging-Structure Entries"，Table 31-1 ~ Table 31-7
- SDM Vol. 3C, §31.4 "Caching Translation Information"：31.4.1 可缓存信息的三类（linear / guest-physical / combined mapping）、31.4.2 创建与使用（EPTRTA = EPTP[51:12] 的 tag 语义）、31.4.3.1 会失效缓存的操作（INVEPT type 1/2、INVVPID 四型、EPT violation、VMX transition）、31.4.3.2 无需失效的操作、31.4.3.3 INVVPID 使用指南、31.4.3.4 INVEPT 使用指南与多处理器 TLB shootdown
- SDM Vol. 3C, Chapter 33 "VMX Instruction Reference" —— INVEPT / INVVPID 指令定义（描述符格式、伪代码、VMfail 与异常条件）
- SDM Vol. 3D, Appendix A.10 "VPID and EPT Capabilities" —— IA32_VMX_EPT_VPID_CAP（MSR 48CH）逐位定义；A.11 "VM Functions" —— IA32_VMX_VMFUNC（MSR 491H）；A.3.3 —— IA32_VMX_PROCBASED_CTLS2
- SDM Vol. 3D, Appendix B.1.1 / B.2.x "Field Encoding in VMCS" —— EPTP = 201AH/201BH，EPTP-list address = 2024H/2025H，EPTP index = 00000004H，VPID = 00000000H，PML address = 200EH，Guest-physical address = 2400H/2401H
- SDM Vol. 3A, §5.10 "Caching Translation Information" 与 §5.10.5 "Propagation of Paging-Structure Changes to Multiple Processors" —— EPT 之外的基础 TLB/paging-structure cache 模型与 TLB shootdown（31.4 反复交叉引用）
- felixcloutier x86 参考（SDM 2023-12 版机械抽取，用于交叉核对 INVEPT 文本与异常条件）：https://www.felixcloutier.com/x86/invept
- Linux KVM 源码（第三方独立实现，用于交叉验证 EPTP 校验与 INVEPT 语义）：arch/x86/kvm/vmx/nested.c 的 nested_vmx_check_eptp()（内存类型/walk length/保留位 bits 11:7/A/D 四类检查）与 handle_invept()；arch/x86/include/asm/vmx.h 的 VMX_EPT_* / VMX_EPTP_* 位定义；arch/x86/kvm/vmx/capabilities.h。https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/kvm/vmx/nested.c 、https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/vmx.h


---

## Intel VMX 嵌套虚拟化：L0 正确支持 L1 运行 L2 的规范要求（VMCS shadowing / vmcs02 合成 / VM-entry 检查 / VM-exit 反射）

硬件只提供一层 VMX。L0 要让 L1 跑 L2，必须做"多路复用"：把 L1 用 VMWRITE 建立的 vmcs12 当成纯软件数据结构（L1 眼中的"VMCS"），自己再合成一份真实硬件 VMCS（vmcs02 = vmcs01 ∪ vmcs12），VMLAUNCH/VMRESUME 时装载 vmcs02 进入 L2。四条主线：(1) vmcs12 读写拦截——L1 的 VMREAD/VMWRITE 默认无条件 VM-exit（SDM Vol 3C §26.1.3），L0 解码后读写内存中的 vmcs12；开启 "VMCS shadowing"（secondary control bit 14）并把 VMCS link pointer 指向一份 shadow VMCS，热字段可让硬件直接放行，只有 VMREAD/VMWRITE bitmap 中置 1 的字段才退出（§25.6.15、§25.10、§31.3）。(2) vmcs02 合成——凡是 L0 用于保住自身控制权的控制位（EPT/EPTP、VPID、MSR bitmap、I/O 拦截、NMI/外部中断退出、preemption timer、PML、host-state 区、CR0/CR4 guest/host mask 的 L0 位）必须由 L0 强制，不能被 vmcs12 覆盖；L1 的控制位只能"求并"收紧，绝不能放宽。(3) VM-entry 检查——L0 必须在软件里复刻 §27.1（basic）、§27.2（controls + host-state）、§27.3（guest-state），并且是对照自己虚拟给 L1 的 IA32_VMX_* 能力 MSR，而不是对照真实硬件；失败要用正确的 VMfailValid 错误码或"exit reason 33/34 + bit 31"回给 L1。(4) VM-exit 反射——决定该退给 L0 还是 L1；反射给 L1 时必须把 guest-state 区（§28.3）和 VM-exit information 区（§28.2）完整写回 vmcs12，再按 vmcs12 的 host-state 区（§28.5）恢复 L1。注意：题目里的 26.2/26.3 是旧版编号，现行 SDM 中 VM Entries 已是第 27 章。


### 能力探测

| 探测什么 | 在哪读 |
|---|---|
| VMX 基本支持与 VMXON 使能（前置条件，非嵌套特有） | `CPUID.01H:ECX.VMX[bit 5]；IA32_FEATURE_CONTROL (MSR 3AH) bit 0 lock + bit 2 (VMXON outside SMX)。SDM Vol 3C §24.6、§24.7` |
| VMCS revision identifier（bits 30:0）、VMCS/VMXON region 大小（bits 44:32）、指针是否被限制为 32 位（bit 48）、是否支持 TRUE_* 能力 MSR（bit 55）、是否允许任意向量带/不带 error code 注入（bit 56） | `IA32_VMX_BASIC (MSR 480H)。SDM Vol 3D Appendix A.1` |
| 是否支持 secondary controls（决定 VMCS shadowing 是否可能存在） | `IA32_VMX_PROCBASED_CTLS (MSR 482H) 高 32 位（allowed-1）bit 31 = "activate secondary controls"；或 IA32_VMX_TRUE_PROCBASED_CTLS (48EH)。SDM Vol 3D Appendix A.3.2` |
| VMCS shadowing 特性本身 | `IA32_VMX_PROCBASED_CTLS2 (MSR 48BH) 高 32 位 bit 14 = "VMCS shadowing"。SDM Vol 3C Table 25-7（Definitions of Secondary Processor-Based VM-Execution Controls）、Vol 3D Appendix A.3.3` |
| VMWRITE 是否能写 VM-exit information（只读）字段——L0 想把 exit info 直接写进 shadow VMCS 时需要它 | `IA32_VMX_MISC (MSR 485H) bit 29。SDM Vol 3D Appendix A.6` |
| VM exit 时是否把 IA32_EFER.LMA 存回 "IA-32e mode guest" VM-entry 控制位（影响写回 vmcs12 的语义） | `IA32_VMX_MISC (MSR 485H) bit 5。SDM Vol 3C §28.2、Vol 3D Appendix A.6` |
| 支持的 activity state（HLT / shutdown / wait-for-SIPI）与 CR3-target 值数量——vmcs12 guest 非寄存器状态检查要用 | `IA32_VMX_MISC (MSR 485H) bits 8:6（activity states）、bits 24:16（CR3-target count）。SDM Vol 3D Appendix A.6` |
| pin/primary/exit/entry 控制位的 allowed-0 与 allowed-1 掩码（L0 必须据此构造要暴露给 L1 的"虚拟能力 MSR"，并用虚拟值校验 vmcs12） | `IA32_VMX_PINBASED_CTLS(481H)/PROCBASED_CTLS(482H)/EXIT_CTLS(483H)/ENTRY_CTLS(484H)，以及 TRUE 变体 48DH-490H。SDM Vol 3D Appendix A.2–A.5` |
| EPT / VPID 能力（嵌套 EPT 是否可做 shadow-on-EPT 或 EPT-on-EPT，是否支持 INVEPT/INVVPID 各类型、accessed/dirty 位） | `IA32_VMX_EPT_VPID_CAP (MSR 48CH)。SDM Vol 3D Appendix A.10` |
| VM-function 支持（EPTP switching，L1 若开 VMFUNC 需要 L0 模拟） | `IA32_VMX_VMFUNC (MSR 491H) bit 0 = EPTP switching。SDM Vol 3C §26.5.6、Vol 3D Appendix A.11` |
| 处理器支持的最高 VMCS 字段索引（决定 VMREAD/VMWRITE bitmap 中哪些索引有效、哪些必须 exit） | `IA32_VMX_VMCS_ENUM (MSR 48AH) bits 9:1。SDM Vol 3D Appendix A.9` |
| 物理地址宽度（所有 vmcs12 里的指针字段合法性检查都要用） | `CPUID.80000008H:EAX[7:0]。SDM Vol 3C §27.3.1.5 脚注` |


### 相关 VMCS 字段

| 字段 | 编码 | 含义 |
|---|---|---|
| VMREAD-bitmap address (full/high) | `00002026H / 00002027H` | 4KB 位图（32K 位）。"VMCS shadowing"=1 时，L2/L1 执行 VMREAD 且 bit n（n=源操作数 bits 14:0）为 1 则 VM exit；为 0 则硬件直接从 VMCS link pointer 指向的 shadow VMCS 中读取。SDM Vol 3C §25.6.15、§26.1.3 |
| VMWRITE-bitmap address (full/high) | `00002028H / 00002029H` | 同上，控制 VMWRITE 是否 exit。bit=1 → exit 由 L0 模拟；bit=0 → 硬件直接写 shadow VMCS。SDM Vol 3C §25.6.15、§26.1.3 |
| VMCS link pointer (full/high) | `00002800H / 00002801H` | 在 vmcs01/vmcs02 中指向 shadow VMCS 的物理地址。非 FFFFFFFF_FFFFFFFFH 时必须 4KB 对齐、不超物理地址宽度，且被指向区域前 4 字节 bits 30:0 = 处理器 VMCS revision id、bit 31 必须等于 "VMCS shadowing" 控制位。SDM Vol 3C §27.3.1.5 |
| Secondary processor-based VM-execution controls | `0000401EH` | bit 14 = "VMCS shadowing"。同时承载 enable EPT(1)、enable VPID(5)、unrestricted guest(7)、enable VM functions(13)、enable PML(17)、EPT-violation #VE(18) 等 L0 必须仲裁的位。SDM Vol 3C §25.6.2 / Table 25-7 |
| Primary processor-based VM-execution controls | `00004002H` | bit 31 = "activate secondary controls"；若为 0，VM entry 按 secondary 全 0 处理（合成 vmcs02 时必须显式处理这一层）。还含 use I/O bitmaps、use MSR bitmaps、use TPR shadow、interrupt/NMI-window exiting 等。SDM Vol 3C §25.6.2、§27.2.1.1 脚注 |
| Pin-based VM-execution controls | `00004000H` | external-interrupt exiting、NMI exiting、virtual NMIs、activate VMX-preemption timer、process posted interrupts。L0 通常必须强制置位前两项并独占 preemption timer。SDM Vol 3C §25.6.1 |
| Primary VM-exit controls / VM-entry controls | `0000400CH / 00004012H` | vmcs02 的 exit controls 必须按 L0 的 host 需求置位（如 host address-space size、load host EFER/PAT）；entry controls 的 "IA-32e mode guest"、load EFER 需按 vmcs12 语义合成。SDM Vol 3C §25.7.1、§25.8.1、§27.2.1.2、§27.2.1.3 |
| VM-entry interruption-information field | `00004016H` | 事件注入。L0 必须把 vmcs12 的注入请求转成 vmcs02 的注入，并在 VM exit 时按 §28.2 清 valid 位后写回 vmcs12。SDM Vol 3C §25.8.3、§27.6 |
| Exit reason | `00004402H` | 反射给 L1 时必写。bits 15:0 = basic exit reason；bit 31=1 表示 VM-entry failure（配合 33=invalid guest state、34=MSR loading、41=machine-check）。SDM Vol 3C §28.2.1、§27.8 |
| Exit qualification | `00006400H` | 退出附加信息；VM-entry failure 时用值 2/3/4 分别表示 PDPTE 问题、NMI 注入被 STI blocking 拦、VMCS link pointer 非法。SDM Vol 3C §28.2.1、§27.8 |
| VM-exit interruption information / error code | `00004404H / 00004406H` | 因向量事件退出时的向量、类型、error code 有效位。反射时必须写回 vmcs12。SDM Vol 3C §25.9.2、§28.2.2 |
| IDT-vectoring information field / error code | `00004408H / 0000440AH` | 事件投递过程中发生 VM exit 时记录被打断的事件，L1 依赖它重新投递。L0 必须把自己/ L1 待投递事件正确折算进来。SDM Vol 3C §25.9.3、§28.2.4 |
| VM-exit instruction length / VMX-instruction information | `0000440CH / 0000440EH` | 指令导致的退出的长度与操作数解码信息。SDM Vol 3C §25.9.4、§28.2.5 |
| Guest-physical address | `00002400H` | EPT violation/misconfiguration 退出时的 GPA。嵌套 EPT 下反射给 L1 前必须换算成 L1 视角的地址。SDM Vol 3C §25.9.1、§28.2.1 |
| Guest-linear address | `0000640AH` | 部分退出（EPT violation、部分指令退出）记录的线性地址。SDM Vol 3C §25.9.1 |
| VM-instruction error | `00004400H` | VMfailValid 时的错误号；L0 模拟 L1 的 VMX 指令失败必须写进 vmcs12 这个字段。注意它通常不放进 shadow 字段集合，否则 L0 模拟时需强制同步。SDM Vol 3C §25.9.5、Chapter 31 |
| EPT pointer (EPTP) | `0000201AH` | vmcs02 中必须是 L0 掌控的 EPT（shadow-on-EPT 或 L0 合成的 EPT01∘EPT12），绝不能直接使用 vmcs12 的 EPTP。SDM Vol 3C §25.6.11、§29.3 |
| Virtual-processor identifier (VPID) | `00000000H` | L0 必须给 L2 分配独立 VPID（或在切换时 INVVPID），不能沿用 vmcs12 的值，否则 L1/L2 TLB 项互相污染。SDM Vol 3C §25.6.12、§29.1。**编码曾在本行误记为 `00000002H`（那是 posted-interrupt notification vector），与本文件 234 行、291 行冲突；以 `00000000H` 为准。** |
| Address of MSR bitmaps | `00002004H` | vmcs02 必须用 L0 合成的位图 = L0 位图 OR L1 位图（L1 想拦的加上 L0 必须拦的），不能直接指向 L1 的页。SDM Vol 3C §25.6.9 |
| Address of I/O bitmap A / B | `00002000H / 00002002H` | 同理需合并；KVM 的做法是干脆置 "unconditional I/O exiting" 而清掉 use I/O bitmaps。SDM Vol 3C §25.6.4 |
| CR0/CR4 guest/host mask 与 read shadow | `00006000H / 00006002H / 00006004H / 00006006H` | vmcs02 的 mask 必须是 L0 mask 与 L1 mask 的按位或；read shadow 要能同时满足 L1 看到的值与 L0 强制位（如 CR0.PG/PE、CR4.VMXE）。SDM Vol 3C §25.6.6 |
| TSC offset / TSC multiplier | `00002010H / 00002032H` | vmcs02 的 offset 必须是 L0 offset 与 vmcs12 offset 的复合（scaling 时为 L1_offset*L0_mult + L0_offset），不能直接抄。SDM Vol 3C §25.6.5 |
| Executive-VMCS pointer | `0000200CH` | SMM dual-monitor treatment 用；嵌套实现若不支持 dual-monitor 必须显式拒绝/忽略 L1 的相关请求。SDM Vol 3C §25.6.10、§32.15 |


### 架构约束

- vmcs12 不是硬件 VMCS，L1 绝不能拿到真实 VMCS 的物理页。L1 执行 VMPTRLD/VMCLEAR/VMREAD/VMWRITE/VMLAUNCH/VMRESUME/VMXON/VMXOFF/INVEPT/INVVPID/VMFUNC 全部无条件 VM exit 到 L0（SDM Vol 3C §26.1.2、§26.1.3），由 L0 解码后操作内存中的 vmcs12。vmcs12 的布局对 L1 必须保持不透明——只有 revision_id 与 abort 两个字段是架构可见的（§25.2）。
- 开 VMCS shadowing 的硬约束：(a) 处理器支持 IA32_VMX_PROCBASED_CTLS2 bit 14；(b) primary control bit 31 "activate secondary controls" 必须为 1，否则 VM entry 按 shadowing=0 处理（§27.2.1.1 脚注、§27.3.1.5 脚注 4）；(c) VMREAD/VMWRITE bitmap 各 4KB、bits 11:0 必须为 0、不得超出物理地址宽度（§27.2.1.1）；(d) VMCS link pointer 若不是全 1，则 4KB 对齐、不超物理宽度，且被指向的 4 字节 bits 30:0 必须等于处理器的 VMCS revision id，bit 31 必须等于 "VMCS shadowing" 控制位——也就是说开了 shadowing 时 link pointer 必须指向 shadow VMCS（§27.3.1.5）。
- shadow VMCS 不能用于 VM entry：当前 VMCS 是 shadow VMCS 时 VMLAUNCH/VMRESUME 直接 VMfail（RFLAGS.CF=1），见 §27.1 第 4 步与 §25.10。同一份 VMCS 不能既作 shadow 又作 entry 用。
- 修改某个 VMCS region 的 shadow-VMCS indicator（bit 31 of first dword）之前必须先对它执行 VMCLEAR，否则该 VMCS 可能损坏（§25.10、§25.11.1）。同一物理 VMCS 不能在两个逻辑处理器上同时 active。
- VMREAD/VMWRITE 源操作数 bits 63:15（非 64 位模式下 bits 31:15）非 0 时无条件 VM exit，位图只覆盖 bits 14:0 共 32K 个索引（§26.1.3）。因此 bitmap 的粒度是"字段编码的低 15 位"，full/high 两半字段是两个独立位。
- shadow 字段集合的选择约束：任何被 L0 在模拟 L1 的 VMX 指令时会改动的字段（典型是 VM_INSTRUCTION_ERROR、launch_state 相关语义）都不应放进 shadow 集合；否则每次 L0 模拟后都必须强制把 vmcs12 同步回 shadow VMCS。KVM 在 arch/x86/kvm/vmx/vmcs_shadow_fields.h 顶部明确写了这条。
- vmcs02 的控制位只能收紧不能放宽：pin/primary/secondary 控制 = L0 的需求 OR vmcs12 的需求（对"拦截类"位），对"能力类"位（unrestricted guest、VMFUNC、APIC 虚拟化、INVPCID、RDTSCP、XSAVES 等）则取 vmcs12 的值但必须先被 L0 的能力 MSR 允许。L0 必须无条件强制的至少包括：external-interrupt exiting、NMI exiting、EPTP（L0 的）、VPID（L0 分配的）、MSR bitmap（L0 合成的）、host-state 全区、VM-exit controls 的 host 相关位、VMX-preemption timer（若 L0 自用）；必须无条件清除的包括 secondary bit 17 "enable PML"（软件模拟）与 bit 14 "VMCS shadowing"（L2 的 shadowing 只能软件模拟）。
- host-state 区（vmcs02 的 HOST_*）必须完全是 L0 自己的：L1 写在 vmcs12 里的 host-state 只在"反射 VM exit 给 L1"时被 L0 用来恢复 L1 的 guest 上下文（§28.5 的角色由 L0 软件扮演），绝不能装进 vmcs02。
- VM-entry 检查必须按 SDM 分类完整复刻：§27.1 basic checks（无 current VMCS / current 是 shadow VMCS / MOV-SS blocking / launch state 与 VMLAUNCH-VMRESUME 匹配）→ §27.2 controls + host-state（§27.2.1.1 VM-execution、§27.2.1.2 VM-exit、§27.2.1.3 VM-entry 控制；§27.2.2 host CR/MSR/SSP；§27.2.3 host 段与描述符表寄存器；§27.2.4 地址空间大小一致性）→ §27.3 guest-state（§27.3.1.1 控制/调试寄存器与 MSR、§27.3.1.2 段寄存器、§27.3.1.3 描述符表寄存器、§27.3.1.4 RIP/RFLAGS/SSP、§27.3.1.5 非寄存器状态含 VMCS link pointer、§27.3.1.6 PDPTE）→ §27.4 MSR 装载。注意题目里的 26.2/26.3 是旧版编号，现行 SDM（rev 081 起，Vol 3C）为 §27.2/§27.3。
- 检查依据必须是 L0 虚拟给 L1 的能力 MSR，不是真实硬件的。L0 要合成一整套 IA32_VMX_*（BASIC、PINBASED/PROCBASED/EXIT/ENTRY_CTLS 及 TRUE 变体、PROCBASED_CTLS2、MISC、CR0/CR4_FIXED0/1、VMCS_ENUM、EPT_VPID_CAP、VMFUNC）并拦截 L1 对它们的 RDMSR。vmcs12 的控制位必须落在这套虚拟 MSR 的 allowed-0/allowed-1 区间内（§27.2.1.1 各条 + Vol 3D Appendix A.2–A.5）。这套虚拟能力集必须是真实硬件能力的子集，否则 vmcs02 装载时会真的 VM-entry fail。
- 失败语义分两类，不能混：§27.1/§27.2 阶段失败 → VMfailValid，RFLAGS.ZF=1 且把错误号写进 vmcs12 的 VM-instruction error 字段，不产生 VM exit 给 L1；§27.3.1/§27.4 阶段失败 → 表现为一次 VM exit 给 L1：exit reason bit 31=1，basic reason = 33（invalid guest state）/ 34（MSR loading）/ 41（machine-check），exit qualification 按 §27.8 取 0/2/3/4 或 MSR 条目序号，且 guest-state 区不被修改、VM-entry interruption-information 的 valid 位不清、不保存 MSR store 区（§27.8）。
- 反射 VM exit 给 L1 时必须写回 vmcs12 的字段分两组。VM-exit information（§28.2）：exit reason、exit qualification、VM-exit interruption information + error code、IDT-vectoring information + error code、VM-exit instruction length、VMX-instruction information、guest-linear address、guest-physical address；同时按 §28.2 清掉 VM-entry interruption-information 的 valid 位（bit 31），若 IA32_VMX_MISC bit 5 为 1 还要把 IA32_EFER.LMA 存回 vmcs12 的 "IA-32e mode guest" entry 控制位。Guest-state（§28.3）：CR0/CR3/CR4、DR7（受 VM_EXIT_SAVE_DEBUG_CONTROLS 控制）、IA32_SYSENTER_CS/ESP/EIP、RSP/RIP/RFLAGS、全部段选择子/基址/limit/AR、GDTR/IDTR 基址与 limit、interruptibility state、activity state、pending debug exceptions、PDPTE（PAE 时）、VMX-preemption timer（受 VM_EXIT_SAVE_VMX_PREEMPTION_TIMER 控制）、EFER/PAT（受对应 save 控制位控制），并按 vmcs12 的 VM-exit MSR-store area 存 MSR（§28.4）。之后按 vmcs12 的 host-state 区把 L1 的 guest 状态恢复（§28.5）并处理 VM-exit MSR-load area（§28.6）。
- 失败到无法维持一致状态时的语义是 VMX abort（§28.7），例如保存 MSR 失败。L0 必须把这条路径也模拟出来（KVM 有 nested_vmx_abort / VMX_ABORT_SAVE_GUEST_MSR_FAIL），而不是静默继续。
- 每次 L2 exit 都要先判定归属：是 L0 自己要处理（EPT violation/misconfig、external interrupt、NMI、MCE-during-VM-entry、preemption timer、PML full、L0 自己插的 #PF 拦截等），还是 L1 要拦（按 vmcs12 的 exception bitmap / MSR bitmap / I/O bitmap / CR mask / 各控制位判定）。两者都不要才直接恢复 L2。KVM 对应 nested_vmx_l0_wants_exit() 与 nested_vmx_l1_wants_exit()。
- 嵌套 EPT：L2 使用的必须是 L0 合成的地址翻译（shadow-on-EPT，或把 EPT12 与 EPT01 合并成的 EPT02），vmcs02 的 EPTP 永远是 L0 的。EPT violation 一律先退给 L0；若发现是 EPT12 里缺项，再由 L0 向 L1 注入一次 EPT violation。
- VMCS shadowing 只是性能优化，不是正确性来源：即使不用 shadowing，靠 VMREAD/VMWRITE 全退出也能正确工作。反过来，用了 shadowing 就必须维护 vmcs12（内存结构）与 shadow VMCS（硬件结构）之间的双向同步——进入 L2 前把 shadow 字段从 vmcs12 刷进 shadow VMCS，L1 通过 VMPTRLD 换 vmcs12 或 L0 模拟改了字段时都要重新同步。


### 失败模式

- 把 vmcs12 的控制位直接抄进 vmcs02：L1 清掉 "external-interrupt exiting" 或 "NMI exiting" 后，L2 的外部中断/NMI 不再退给 L0，L0 丢失调度权与中断投递能力，等价于 L1 越权。避免：合成时对所有"L0 自保"控制位用 OR 强制置位，写成一张显式的 must-set / must-clear 表并在 vmcs02 写入后断言校验，不要靠散落的 if。
- 把 vmcs12 的 EPTP/VPID/MSR bitmap/I-O bitmap 物理地址直接写进 vmcs02：这些地址是 L1 的 GPA 而非 HPA，硬件会按 HPA 解释，直接造成 L0 内核内存被当作页表/位图使用——任意物理地址读写。避免：所有 vmcs12 中的指针字段一律视作 GPA，必须经过 GPA→HPA 转换 + 页边界与物理宽度校验后才能落到 vmcs02，且位图类必须是 L0 新分配并与 L0 自身位图求并的副本。
- VM-entry 检查漏项或"检查了但用真实硬件能力当基准"：漏项会让非法 vmcs12 进入 vmcs02，硬件在 VMLAUNCH 时返回 VMfailValid，而 L0 此时已经切走上下文，典型表现是 L0 自己卡在 VM-entry 失败路径或直接死机；基准用错会让 L1 配了一个 L0 声称支持、硬件其实不支持的控制位。避免：把 §27.2/§27.3 的检查写成表驱动、和"生成虚拟能力 MSR"用同一份数据源；在真正 VMLAUNCH 前对 vmcs02 再跑一遍自检，任何 VMfail 都当作 L0 的 bug 打印字段快照。
- VM-entry 失败的两种语义搞混：本该 VMfailValid（写 VM-instruction error，不产生 exit）的却造出一次假 VM exit，或本该报 exit reason 33/34 且 bit 31=1 的却报成普通退出。L1 hypervisor（尤其 KVM/Hyper-V）会据此走完全不同的错误路径，表现为 L1 内核 panic 或无限重试。避免：严格按 §27.1/§27.2（→VMfailValid）与 §27.3.1/§27.4（→exit reason 33/34 + bit 31）分界，并保证 §27.8 的"guest-state 不修改、entry interruption valid 位不清、不存 MSR"这三条也一并模拟。
- 反射 VM exit 时只写 exit reason 而漏写 exit qualification / interruption info / IDT-vectoring info：L1 拿到不完整信息后按 0 值处理，典型后果是投递中被打断的中断/异常永久丢失，或 L2 收到错误的 #PF 地址。避免：把"写回 vmcs12"实现成一个覆盖 §28.2 全部五小节 + §28.3 全部四小节的单一函数（KVM 的 prepare_vmcs12 + sync_vmcs02_to_vmcs12），任何新增 exit reason 都必须走它。
- shadow VMCS 与 vmcs12 不同步：L0 在模拟 L1 的 VMX 指令时改了某个字段（例如 VM-instruction error 或控制位），但该字段在 shadow 集合里且没强制回刷，L1 下次用硬件 VMREAD 读到陈旧值。避免：shadow 字段集合固定成一张静态表，并遵守"L0 会写的字段不放进 shadow 集合"这条规则；每次 L1 换 vmcs12（VMPTRLD）或 L0 模拟写入后都置 dirty 并在下次 entry 前整表刷新。
- VMCS link pointer 检查漏做 bit 31 一致性：link pointer 指向的区域 bit 31 必须等于 "VMCS shadowing" 控制位（§27.3.1.5）。忘了这条会导致真实 VM-entry 以 exit reason 33 / exit qualification 4 失败，且症状出现在 L0 自己的 VMLAUNCH 上，很难定位。避免：在设置 shadow VMCS 时用 VMCLEAR + 显式写 revision_id | (1<<31) 的固定序列，且这段代码只有一处。
- 忘记为 L2 分配独立 VPID 或在 vmcs01/vmcs02 切换时不做 INVEPT/INVVPID：L1 与 L2 共用 TLB 项，产生随机的错误翻译——最难复现的一类嵌套 bug。避免：把 VPID 分配与失效放在 vmcs02 加载/卸载的同一处，并在开发期用"每次切换都无条件 INVVPID all-context"跑一轮对照测试。
- TSC offset/multiplier 直接取 vmcs12 的值：L2 看到的时间会漏掉 L0 那一层偏移，导致 L2 内时钟倒流或 watchdog 误触发。避免：offset 一律按复合公式计算（L1_offset * L0_multiplier + L0_offset），并写单元测试覆盖 scaling 开/关两种情况。
- 把 VMREAD/VMWRITE bitmap 的"位=1 表示放行"记反：SDM 语义是位为 1 → VM exit，位为 0 → 硬件直接访问 shadow VMCS。记反会让所有热字段都退出（只是慢），或更糟——让本该被 L0 拦截的敏感字段被 L1 直接改写 shadow VMCS。避免：位图初始化默认全 1（全部拦截），再按显式白名单逐个清位；每清一位都要能说出"这个字段被 L1 直接改为什么是安全的"。


### 来源

- Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3 (3A/3B/3C/3D), Order Number 325384-081US, September 2023 — 本次实际下载并逐节核对的版本：https://cdrdv2-public.intel.com/789582/325384-sdm-vol-3abcd.pdf
- SDM Vol 3C §24.6 Discovering Support for VMX；§24.7 Enabling and Entering VMX Operation
- SDM Vol 3C §25.2 Format of the VMCS Region（revision id bits 30:0，bit 31 = shadow-VMCS indicator）
- SDM Vol 3C §25.6.2 Processor-Based VM-Execution Controls / Table 25-7 Definitions of Secondary Processor-Based VM-Execution Controls（bit 14 = VMCS shadowing）
- SDM Vol 3C §25.6.15 VMCS Shadowing Bitmap Addresses（VMREAD/VMWRITE bitmap，各 4KB / 32K 位）
- SDM Vol 3C §25.9 VM-Exit Information Fields（§25.9.1 基本信息、§25.9.2 向量事件、§25.9.3 事件投递中退出、§25.9.4 指令退出、§25.9.5 VM-instruction error）
- SDM Vol 3C §25.10 VMCS Types: Ordinary and Shadow
- SDM Vol 3C §25.11.1 Software Use of Virtual-Machine Control Structures；§25.11.2 VMREAD, VMWRITE, and Encodings of VMCS Fields
- SDM Vol 3C §26.1.2 Instructions That Cause VM Exits Unconditionally；§26.1.3 Instructions That Cause VM Exits Conditionally（VMREAD/VMWRITE 的三条退出条件）
- SDM Vol 3C §26.5.6 VM Functions（EPTP switching）；§26.5.7 Virtualization Exceptions
- SDM Vol 3C Chapter 27 VM ENTRIES：§27.1 Basic VM-Entry Checks；§27.2 Checks on VMX Controls and Host-State Area（§27.2.1.1/§27.2.1.2/§27.2.1.3/§27.2.2/§27.2.3/§27.2.4）；§27.3 Checking and Loading Guest State（§27.3.1.1–§27.3.1.6，其中 §27.3.1.5 含 VMCS link pointer 检查）；§27.4 Loading MSRs；§27.6 Event Injection；§27.8 VM-Entry Failures During or After Loading Guest State。注意：SDM 早期版本中这一章编号为 Chapter 26（即提问中的 26.2/26.3）
- SDM Vol 3C Chapter 28 VM EXITS：§28.1 Architectural State Before a VM Exit；§28.2 Recording VM-Exit Information and Updating VM-Entry Control Fields（§28.2.1–§28.2.5）；§28.3 Saving Guest State（§28.3.1–§28.3.4）；§28.4 Saving MSRs；§28.5 Loading Host State；§28.6 Loading MSRs；§28.7 VMX Aborts
- SDM Vol 3C Chapter 29 VMX Support for Address Translation（EPT，§29.3）；Chapter 31 VMX Instruction Reference（§31.3 含 VMREAD/VMWRITE 在非根操作下访问 shadow VMCS 的伪代码）
- SDM Vol 3D Appendix A VMX Capability Reporting Facility：A.1 IA32_VMX_BASIC；A.2 Reserved Controls and Default Settings；A.3 VM-Execution Controls（A.3.1–A.3.4）；A.4 VM-Exit Controls；A.5 VM-Entry Controls；A.6 IA32_VMX_MISC（bit 5、bit 29）；A.9 VMCS Enumeration；A.10 VPID and EPT Capabilities；A.11 VM Functions。Appendix B VMCS 字段编码（B.1–B.4）；Appendix C VM Exit Reasons
- Linux 内核文档 Nested VMX（vmcs01/vmcs02/vmcs12 术语与 struct vmcs12 布局）：https://www.kernel.org/doc/html/latest/virt/kvm/x86/nested-vmx.html
- Linux 内核源码 arch/x86/kvm/vmx/nested.c：prepare_vmcs02_early()（控制位合成，含 exec_control &= ~SECONDARY_EXEC_SHADOW_VMCS、&= ~SECONDARY_EXEC_ENABLE_PML、|= CPU_BASED_UNCOND_IO_EXITING）、sync_vmcs02_to_vmcs12()/prepare_vmcs12()（写回 vmcs12）、nested_vmx_l0_wants_exit()/nested_vmx_l1_wants_exit()（退出归属判定）、load_vmcs12_host_state()：https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kvm/vmx/nested.c
- Linux 内核源码 arch/x86/kvm/vmx/vmcs_shadow_fields.h：shadow 字段白名单及"L0 会写的字段不得 shadow"的注释：https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kvm/vmx/vmcs_shadow_fields.h
- Ben-Yehuda et al., "The Turtles Project: Design and Implementation of Nested Virtualization", OSDI 2010（vmcs12/vmcs02 多路复用模型的原始论文，KVM 文档明确引用）：https://www.usenix.org/events/osdi10/tech/full_papers/Ben-Yehuda.pdf


---

## Windows 上 Hyper-V / VBS / HVCI 已运行时，第三方 hypervisor 的加载与共存（CPUID hypervisor 位、root partition 嵌套限制、enlightened VMCS / VP assist page、业界做法）

Hyper-V/VBS/HVCI 任一开启，Windows 自身就是 hypervisor 之上的 root partition：CPUID.1:ECX[31]=1，且 VMX 位 CPUID.1:ECX[5] 被清零（本机实测 ECX=FFFAF38B，VBS 状态=2 运行中），第三方 hypervisor 在宿主上根本执行不了 VMXON（#UD）。微软 TLFS 明写嵌套虚拟化只面向 guest partition：“Nested virtualization is not supported in a Windows root partition”，所以第三方 hypervisor 不能在宿主做 L1，只能跑在 Hyper-V 虚拟机内部当 L1（微软不测试、不支持非微软 hypervisor）。enlightened VMCS + VP assist page 是给“VM 内的 L1”省掉 VMREAD/VMWRITE 陷入的优化通道，对 root partition 完全不开放（本机 leaf 0x4000000A 全 0、leaf 0x40000004 bit14=0）。业界只有两条路：关掉 hypervisorlaunchtype+VBS 独占 VT-x，或改用 WHP 用户态 API 与 Hyper-V 共存（放弃自有 ring -1）。


### 能力探测

| 探测什么 | 在哪读 |
|---|---|
| 是否有 hypervisor 存在（含 Windows 自身作为 root partition 的情况）。TLFS：“check bit 31 of register ECX (the hypervisor present bit)... In a non-virtualized environment, the bit will be clear.” 本机 VBS/HVCI 开启，实测 CPUID.1 ECX=FFFAF38B → bit31=1 | `CPUID.01h:ECX[31]（hypervisor present bit）` |
| 硬件 VMX 是否还给你用——这才是能否 VMXON 的判据。Hyper-V 不把 VMX 暴露给 root partition：本机 ECX=FFFAF38B → bit5=0，即 VT-x 在宿主 OS 里“消失”，VMXON 直接 #UD | `CPUID.01h:ECX[5] (VMX)；配合 IA32_FEATURE_CONTROL (MSR 0x3A) bit0 Lock / bit2 VMXON outside SMX` |
| 识别是哪家 hypervisor 及接口版本。本机 leaf 0x40000000 EAX=0x4000000C，EBX/ECX/EDX="Microsoft Hv" | `CPUID 0x40000000（EAX=最大叶、EBX/ECX/EDX=vendor）与 0x40000001（EAX="Hv#1"=0x31237648）` |
| 自己是不是被嵌套在 Hyper-V 之下（即“我是 VM 里的 L1”）。本机 root partition 实测 leaf 0x40000004 EAX=0x00960E14 → bit12=0（非嵌套） | `CPUID 0x40000004:EAX[12] “Indicates that the hypervisor is nested within a Hyper-V partition”` |
| L0 是否建议本 L1 使用 enlightened VMCS（用它才有意义去用 eVMCS）。本机 bit14=0 | `CPUID 0x40000004:EAX[14] “Recommend a nested hypervisor using the enlightened VMCS interface”` |
| 具体的嵌套增强能力集：eVMCS 版本、direct virtual flush、FlushGuestPhysicalAddress* hypercall、enlightened MSR bitmap、GuestIa32DebugCtl 非零支持、AMD enlightened TLB、PerfGlobalCtrl。本机 root partition 实测全为 0（未开放） | `CPUID 0x4000000A：EAX[7:0]/[15:8]=eVMCS 版本高低位，EAX[17] direct flush，EAX[18] FlushGuestPhysicalAddressSpace/List，EAX[19] enlightened MSR bitmap，EAX[20] VE 合并入 #PF 类，EAX[21] GuestIa32DebugCtl，EAX[22] AMD enlightened TLB，EBX[0] Guest/HostPerfGlobalCtrl` |
| 当前 guest 处在第几层 hypervisor 之下（0=非嵌套）。本机 leaf 0x40000006 EAX=0x098200AF → bits13:10=0 | `CPUID 0x40000006:EAX[13:10] “The hypervisor level of the current guest - '0' if non-nested”；同叶 EAX[3]=SLAT 在用、EAX[1]=MSR bitmap 在用` |
| VBS/HVCI 是否真的在跑（比 CPUID 更直接的“为什么我的 VT-x 没了”判据）。本机实测 VirtualizationBasedSecurityStatus=2（enabled and running）、SecurityServicesRunning={2}（memory integrity 运行中） | `WMI root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard 的 VirtualizationBasedSecurityStatus / SecurityServicesConfigured / SecurityServicesRunning；或 msinfo32 显示 “A hypervisor has been detected. Features required for Hyper-V will not be displayed.”` |
| 共存路线的能力探测：Windows Hypervisor Platform 是否可用（第三方虚拟化栈唯一受支持的共存入口） | `WHvGetCapability(WHvCapabilityCodeHypervisorPresent=0x00000000)；WinHvPlatform.dll，Windows 10 1803+(x64)/Win11 24H2 26100.3915(Arm64)` |
| 若目标是把自家 hypervisor 跑在 WHP 分区里再做嵌套：WHP 直接把 VMX 能力 MSR 以 capability 形式暴露 | `WHvCapabilityCodeVmxBasic 0x00002000 ~ WHvCapabilityCodeVmxTrueEntryCtls 0x00002010（VmxProcbasedCtls2=0x0000200B、VmxEptVpidCap=0x0000200C 等）` |
| VP assist page（eVMCS 与嵌套增强的开关页）是否已映射/启用 | `MSR 0x40000073（Virtual VP Assist MSR）：bit0=Enable，bits63:12=Page PFN；页内 HV_VP_ASSIST_PAGE.EnlightenVmEntry / CurrentNestedVmcs / NestedEnlightenmentsControl` |


### 相关 VMCS 字段

| 字段 | 编码 | 含义 |
|---|---|---|
| VersionNumber（合成字段，非物理 VMCS 编码） | `HV_VMX_ENLIGHTENED_VMCS 偏移 0x000` | enlightened VMCS 结构版本；TLFS 目前“The only VMCS version currently supported is 1”。整页 4KB、使用前必须清零，且不得用 VMPTRLD 使其生效 |
| CleanFields（合成字段） | `无物理编码；位定义 HV_VMX_ENLIGHTENED_CLEAN_FIELD_*（IO_BITMAP=1<<0、MSR_BITMAP=1<<1、CONTROL_GRP2=1<<2、CONTROL_GRP1=1<<3、CONTROL_PROC=1<<4、CONTROL_EVENT=1<<5、CONTROL_ENTRY=1<<6、CONTROL_EXCPN=1<<7、CRDR=1<<8、CONTROL_XLAT=1<<9、GUEST_BASIC=1<<10、GUEST_GRP1=1<<11、GUEST_GRP2=1<<12、HOST_POINTER=1<<13、HOST_GRP1=1<<14、ENLIGHTENMENTSCONTROL=1<<15）` | L0 可缓存 eVMCS 的一部分；L1 每次修改对应组字段后必须清掉相应 clean 位，否则 L0 会用旧值——这是 eVMCS 最常见的踩坑点 |
| EnlightenmentsControl（合成字段） | `位域：NestedFlushVirtualHypercall:1、MsrBitmap:1` | 分别打开“把 L2 的 flush hypercall 直接交给 L0 处理”和“enlightened MSR bitmap”（L0 不再监视 MSR bitmap 变更，改由 L1 清 clean 位） |
| VpId / VmId / PartitionAssistPage（合成字段） | `无物理编码` | 启用 direct virtual flush 的前置：本 eVMCS 对应的 VP/VM 标识与 partition assist page 的 GPA（页内仅 UINT32 TlbLockCount；非零时 L0 会投递合成 VM-Exit HV_VMX_SYNTHETIC_EXIT_REASON_TRAP_AFTER_FLUSH=0x10000031） |
| ProcessorControls / SecondaryProcessorControls / PinControls / ExitControls / EntryControls | `0x00004002 / 0x0000401E / 0x00004000 / 0x0000400C / 0x00004012` | 主/次/pin/退出/进入控制；在 eVMCS 下用普通内存写代替 VMWRITE，clean 组分别为 CONTROL_PROC、CONTROL_GRP1、CONTROL_GRP1、CONTROL_GRP1、CONTROL_ENTRY |
| MsrBitmap / IoBitmapA / IoBitmapB | `0x00002004 / 0x00002000 / 0x00002002` | MSR/IO 拦截位图 GPA；对应 clean 位 MSR_BITMAP、IO_BITMAP，配合 enlightened MSR bitmap 使用 |
| EptRoot（EPTP）/ Vpid | `0x0000201A / 0x00000000` | 二级地址转换根与 VPID；TLFS 说明嵌套下该 64 位值即 L1 的 EPT pointer（AMD 侧等价于 VMCB 的 nCR3），L0 用它标识 L2 GPA→GPA 地址空间。clean 组 CONTROL_XLAT |
| GuestWorkingVmcsPtr（VMCS link pointer） | `0x00002800` | eVMCS 中仍保留链接指针字段（clean 组 GUEST_GRP1） |
| GuestIa32DebugCtl | `0x00002802` | 嵌套下该字段能否取非零值需由 CPUID 0x4000000A:EAX[21] 显式声明；不声明就当作不支持 |
| ExitReason / ExitQualification / ExitInstructionError | `0x00004402 / 0x00006400 / 0x00004400` | 只读退出信息，clean 字段为 NONE；eVMCS 下直接读内存获取，无需 VMREAD |
| TertiaryProcessorControls / TscMultiplier / HostPerfGlobalCtrl | `0x00002034 / 0x00002032 / 0x00002C04` | 较新扩展字段也已纳入 eVMCS 映射；凡架构上支持但 eVMCS 未定义映射的字段，L1 若启用 eVMCS 就不应再启用该特性 |


### 架构约束

- 同一逻辑处理器上 VMX root 只能有一个主人。微软 KB 3204980 原文：“only one software component at a time can use this hardware. Virtualization applications can't share the hardware.”
- Hyper-V 一旦启动（含仅因 VBS/HVCI/Credential Guard/WSL2/Sandbox/WDAG 而启动），Windows 就成为 root partition，硬件虚拟化扩展不再暴露给它。TLFS 明文：“This capability is only available to guest partitions... Nested virtualization is not supported in a Windows root partition.”
- 因此宿主上的第三方 hypervisor 无法 VMXON：本机实测 CPUID.1:ECX[5]=0（VMX 位被清），执行 VMXON/VMPTRLD 等 VMX 指令会 #UD，而不是 VMfail——不能靠检查 RFLAGS 来判断。
- 第三方 hypervisor 只能作为 Hyper-V 虚拟机内的 L1 运行，且需宿主逐 VM 开启：VM 关机状态下 Set-VMProcessor -VMName <VM> -ExposeVirtualizationExtensions $true。Intel 需 VT-x+EPT、宿主 WS2016/Win10 1607+、VM 配置版本 ≥8.0；AMD 需宿主 WS2022/Win11+、配置版本 ≥9.3。
- 即便如此，微软对非微软 hypervisor 嵌套是“不测试、不支持”：“Virtualization applications other than Hyper-V aren't supported in Hyper-V virtual machines, and are likely to fail.”“Non-Microsoft virtualization on Hyper-V virtualization isn't supported.”
- 嵌套下的运行期限制：Hyper-V 在 VM 内运行时内存必须关机才能调整（动态内存不再浮动）；网络需要 L1 虚拟交换机开 MAC address spoofing 或走 NAT。
- eVMCS 使用约束：每个 eVMCS 恰好 4KB、首次使用前清零；通过 VP assist page 的 EnlightenVmEntry=1 打开、CurrentNestedVmcs 指定当前 eVMCS；同一时刻只能在一个处理器上 active；active 期间执行 VMREAD/VMWRITE 属未定义行为；VMCLEAR 用来使其失活；修改后必须清对应 CleanFields 位。
- direct virtual flush 还需额外前置：VP assist page 的 NestedEnlightenmentsControl.Features.DirectHypercall=1、eVMCS 的 EnlightenmentsControl.NestedFlushVirtualHypercall=1，并填好 VpId/VmId/PartitionAssistPage，且 L1 必须向自己的 guest 报告 UseHypercallForLocalFlush/UseHypercallForRemoteFlush。
- 走共存路线时，WHP 只是用户态分区管理 API（WinHvPlatform.dll，Win10 1803+），调用前必须先 WHvGetCapability 查询能力；它不给你自己的 VMX root，也就没有自定义 VMCS 控制位、自建 EPT hook、VT-d 直通这类能力。
- VBS/HVCI 可能被 UEFI 锁（Locked=1，需进 UEFI 关 Secure Boot 才能撤销）；Mandatory=1 时 hypervisor/Secure Kernel 加载失败系统直接拒绝启动——“要求用户关 VBS”在受管企业机上未必可行。


### 失败模式

- 把 CPUID.1:ECX[31]=1 当作“检测到虚拟机/被人抢了 VT-x”：在所有开了 VBS/HVCI 的普通 Windows 桌面上该位恒为 1（本机即是），反虚拟机检测据此判定会全量误报；判断“还能不能开 VMX”必须看 ECX[5]，不是 bit31。
- 反过来把 ECX[31]=0 当作“可以直接 VMXON”：仍需检查 ECX[5]、IA32_FEATURE_CONTROL(0x3A) 的 Lock 与 VMXON-outside-SMX 位、CR4.VMXE 以及 CR0/CR4 的 FIXED0/FIXED1 约束。
- 驱动里不判断能力就直接 VMXON：VMX 位为 0 时是 #UD 而非 VMfail，内核态未处理异常 → 蓝屏（KMODE_EXCEPTION_NOT_HANDLED 0x1E）。正确做法是 CPUID 门禁 + 明确报错“请先关闭 Hyper-V/VBS”，而不是靠 SEH 兜底。
- 以为“Hyper-V 角色没装就没有 hypervisor”：Memory Integrity(HVCI)、Credential Guard、WSL2、Windows Sandbox、Application Guard 任一都会拉起 hypervisor。要真正让出硬件必须 bcdedit /set hypervisorlaunchtype off 并同时关掉 HVCI/Credential Guard/VBS 再重启，只关一个功能会“看起来关了其实还在跑”。
- 尝试从驱动里绕过/关闭 VBS（改 CI 选项、打补丁腾 VT-x）：HVCI 下 SLAT 权限由 hypervisor 保证，写不进去；即使得手也会撞 PatchGuard，并且 UEFI 锁定场景根本无法撤销。这条路不是“难”，是“不通”。
- 在 root partition 里去用 enlightened VMCS：leaf 0x40000004:EAX[14] 与整个 0x4000000A 都是 0（本机实测），此时构造 eVMCS、写 MSR 0x40000073 只会得到未定义行为；eVMCS 只有在“自己就是 Hyper-V VM 内的 L1”时才有意义。
- eVMCS 用法错误：改完字段忘清 CleanFields → L0 用陈旧值，表现为莫名其妙的 VM-entry 失败或 L2 行为诡异；在 eVMCS active 期间还混用 VMREAD/VMWRITE → 未定义行为；用了架构上支持但 eVMCS 无映射字段的特性 → 该特性静默失效。
- 把 WHP 当成“带 Hyper-V 的 ring -1 替代品”：WHP 给不了 EPT violation 级别的内存 hook、自定义 VMCS 控制、设备直通；安全研究/EDR 类 hypervisor 迁到 WHP 上会直接丢掉核心能力，还要吃用户态往返的性能。
- 把“让用户关 VBS”写进安装流程当默认方案：新 Windows 11 设备 VBS/Memory Integrity 默认开启且 Windows 安全中心会持续告警，企业还可能用 Intune/GPO 锁定；产品化上这等于要求用户降低系统安全等级，越来越站不住。
- 嵌套路线上误判支持面：AMD 平台需要宿主 Win11/WS2022 + VM 配置版本 ≥9.3，老宿主上 Set-VMProcessor -ExposeVirtualizationExtensions 会失败；且必须在 VM 关机时设置。


### 来源

- Microsoft TLFS — Nested Virtualization（关键结论“Nested virtualization is not supported in a Windows root partition”，eVMCS/clean fields/direct virtual flush/partition assist page/合成退出原因 0x10000031）: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/nested-virtualization
- Microsoft TLFS — Feature and Interface Discovery（CPUID.01h:ECX[31] hypervisor present bit；leaf 0x40000000/0x40000001/0x40000004 bit12/bit14/0x40000006 bits13:10/0x4000000A 全部位定义）: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
- Microsoft TLFS — Virtual Processor（VP assist page 的 MSR 0x40000073 格式：bit0 Enable、bits63:12 PFN）: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vp-properties
- Microsoft TLFS — HV_VP_ASSIST_PAGE（NestedEnlightenmentsControl / EnlightenVmEntry / CurrentNestedVmcs 字段）: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_vp_assist_page
- Microsoft TLFS — HV_VMX_ENLIGHTENED_VMCS（完整结构 + 物理 VMCS 编码到 enlightened 字段的映射表 + CleanFields 位定义）: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_vmx_enlightened_vmcs
- Microsoft KB 3204980 — Virtualization applications can't run alongside Hyper-V and its dependent features（“only one software component at a time can use this hardware”；VMware/VirtualBox 与 Hyper-V/Memory Integrity/Credential Guard 不共存；给出关闭步骤）: https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/virtualization-apps-not-work-with-hyper-v
- Microsoft — What is Nested Virtualization for Hyper-V?（“Virtualization applications other than Hyper-V aren't supported in Hyper-V virtual machines, and are likely to fail.”；非微软虚拟化在 Hyper-V 上不受支持）: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/nested-virtualization
- Microsoft — Run Hyper-V in a Virtual Machine with Nested Virtualization（Set-VMProcessor -ExposeVirtualizationExtensions、Intel/AMD 前置条件与 VM 配置版本 8.0/9.3、MAC spoofing/NAT）: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization
- Microsoft — Windows Hypervisor Platform API Definitions（第三方虚拟化栈的共存入口，Windows 2018 年 4 月更新起提供）: https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform
- Microsoft — Hyper-V APIs 总览（“a client such as QEMU can run on the hypervisor... all while running alongside a Hyper-V managed partition with no overlap”）: https://learn.microsoft.com/en-us/virtualization/api/
- Microsoft — WHvGetCapability（WHvCapabilityCodeHypervisorPresent；以及 WHvCapabilityCodeVmxBasic 0x2000～VmxTrueEntryCtls 0x2010 这组嵌套相关能力码；最低 Win10 1803）: https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvgetcapability
- Microsoft — Enable memory integrity (HVCI)（VBS 用 Windows hypervisor 建隔离环境；UEFI Lock、Mandatory 模式、Win32_DeviceGuard 各字段含义、22H2 起未开启会持续告警）: https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- Microsoft — Hyper-V Architecture（root/parent partition 位于 hypervisor 之上，只有它直接访问物理设备）: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/architecture
- Intel SDM（VMXON/CR4.VMXE/IA32_FEATURE_CONTROL 条件、CPUID.1:ECX[5] VMX 位；SDM 把 CPUID.1:ECX[31] 定义为处理器恒返回 0，hypervisor-present 是各家 hypervisor 的约定用法）: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- 本机实测（2026-09-05，Windows 11 26300，VBS 运行中）：Win32_DeviceGuard VirtualizationBasedSecurityStatus=2、SecurityServicesRunning={2}（memory integrity 在跑）；CPUID.1 ECX=0xFFFAF38B → bit31=1、bit5(VMX)=0；leaf 0x40000000 EAX=0x4000000C/"Microsoft Hv"；leaf 0x40000004 EAX=0x00960E14（bit12=0、bit14=0）；leaf 0x40000006 EAX=0x098200AF（bits13:10=0，SLAT 在用）；leaf 0x4000000A 全 0。即：root partition 既拿不到 VMX，也拿不到任何嵌套增强。
- 业界产品做法（本次会话未能打开厂商站点验证：WebSearch 与非 learn.microsoft.com 的 WebFetch 都因后端模型配额报错，以下按厂商公开文档的既有结论陈述，链接为站点根，建议二次核对）：VMware Workstation 15.5.5+/16+ 增加基于 Windows Hypervisor Platform 的 ULM 模式以在 Hyper-V/VBS 开启时共存（旧的不兼容说明见 VMware KB 2146361，现已迁至 Broadcom 知识库 https://knowledge.broadcom.com/ ）；VirtualBox 6.0 起提供 Hyper-V 后端、7.x 沿用（性能显著低于原生 VT-x 模式，见 https://www.virtualbox.org/manual/ ）；QEMU 提供 -accel whpx，Android Emulator 亦走 WHPX。安全研究型 hypervisor（EPT hook 类，如 hvpp / Hypervisor-From-Scratch / MiniVisor 等项目）无共存方案，其文档一律要求先关闭 Hyper-V 与 VBS。


---

## Intel EPT 分离视图（execute/read 走不同物理页）隐蔽 hook 的已知陷阱：多核竞态、MTF 恢复窗口原子性、INVEPT 时机

EPT 在 GPA→HPA 层独立于客户机页表施加 R/W/X，并可改写页帧号。分离视图靠这两点：同一 GPA 取指时映射到含 hook 的影子页（X=1、R=W=0），读写时映射回干净原页（R/W=1、X=0）。SDM 不提供"按访问类型自动选页"的原子机制，只能 EPT violation 退出→翻转条目→单步→翻回，或用 VMFUNC/多 EPTP 在每个 vCPU 上切换整张视图。执行-only 需 IA32_VMX_EPT_VPID_CAP[0]；R=0 且 W=1 恒为 EPT misconfiguration。翻转窗口本身没有任何架构级原子性保证，这是全部陷阱的根源。


### 能力探测

| 探测什么 | 在哪读 |
|---|---|
| EPT 执行-only 页（X=1,R=0），分离视图的基础前提；不支持时 R=0&X=1 直接是 misconfiguration 而非 violation | `IA32_VMX_EPT_VPID_CAP (MSR 0x48C) bit 0` |
| INVEPT 指令可用性 | `IA32_VMX_EPT_VPID_CAP (0x48C) bit 20` |
| single-context INVEPT 类型（翻转条目后应使用的类型） | `IA32_VMX_EPT_VPID_CAP (0x48C) bit 25` |
| all-context INVEPT 类型 | `IA32_VMX_EPT_VPID_CAP (0x48C) bit 26` |
| EPT accessed/dirty 标志（启用后 CPU 会写 EPT 条目，与翻转交织） | `IA32_VMX_EPT_VPID_CAP (0x48C) bit 21` |
| 2MB EPT 大页支持（决定挂钩前是否必须拆页）；1GB 为 bit 17 | `IA32_VMX_EPT_VPID_CAP (0x48C) bit 16` |
| EPT violation 高级退出信息（GLA valid、是否为 guest page-walk 访问） | `IA32_VMX_EPT_VPID_CAP (0x48C) bit 22` |
| Monitor Trap Flag 是否允许置 1 | `IA32_VMX_PROCBASED_CTLS (0x482) 或 IA32_VMX_TRUE_PROCBASED_CTLS (0x48E) allowed-1 部分 bit 27` |
| 是否支持 secondary processor-based controls（EPT 相关控制都在其中） | `IA32_VMX_PROCBASED_CTLS (0x482) bit 63` |
| enable EPT | `IA32_VMX_PROCBASED_CTLS2 (0x48B) bit 1` |
| enable VM functions（VMFUNC 总开关） | `IA32_VMX_PROCBASED_CTLS2 (0x48B) bit 13` |
| EPTP switching（VM function 0），每 vCPU 无退出切视图的关键 | `IA32_VMX_VMFUNC (MSR 0x491) bit 0` |
| EPT-violation #VE（把 EPT violation 变成客户机内 #VE，可省 VM exit） | `IA32_VMX_PROCBASED_CTLS2 (0x48B) bit 18` |
| mode-based execute control for EPT (MBEC)，可分离 supervisor/user 取指权限（bit 2 / bit 10） | `IA32_VMX_PROCBASED_CTLS2 (0x48B) bit 22` |


### 相关 VMCS 字段

| 字段 | 编码 | 含义 |
|---|---|---|
| EPT pointer (EPTP) | `0x201A (full) / 0x201B (high)` | 当前 EPT 层级根。bits 5:3 为页walk长度，bit 6 启用 A/D。每 vCPU 独立视图方案就是让每个 VMCS 装不同的 EPTP |
| EPTP index | `0x0004 (16 位控制字段)` | VMFUNC EPTP switching 时处理器把 ECX[15:0] 写入此字段（需支持 EPT-violation #VE）；#VE 信息区据此告知客户机当前视图号 |
| EPTP-list address | `0x2024 (full) / 0x2025 (high)` | 4KB 结构，512 个 8 字节 EPTP 候选值，VMFUNC 0 用 ECX 选一项 |
| VM-function controls | `0x2018 (full) / 0x2019 (high)` | bit 0 = EPTP switching 使能 |
| Primary processor-based VM-execution controls | `0x4002` | bit 27 = Monitor Trap Flag；翻转窗口的单步开关就在这里 |
| Secondary processor-based VM-execution controls | `0x401E` | bit 1 enable EPT、bit 13 enable VM functions、bit 18 EPT-violation #VE、bit 22 MBEC |
| Pin-based VM-execution controls | `0x4000` | bit 0 = external-interrupt exiting。MTF 窗口必须置 1 才能防止中断投递把 MTF 挤到 ISR 里 |
| Guest-physical address | `0x2400 (full) / 0x2401 (high)` | EPT violation/misconfiguration 时的故障 GPA，用来在 hook 表里定位是哪个影子页 |
| Exit qualification | `0x6400` | EPT violation 时 bit0/1/2 = 读/写/取指访问类型，bit3/4/5 = 该 GPA 当前是否可读/写/执行，bit7 GLA valid，bit8 区分最终访问与 guest page-walk |
| VM-exit reason | `0x4402` | 37 = Monitor Trap Flag，48 = EPT violation，49 = EPT misconfiguration，59 (0x3B) = VMFUNC |
| Exception bitmap | `0x4004` | bit 3 拦截 #BP，用于影子页里 0xCC 型 hook（DdiMon/DRAKVUF 模型） |
| Virtualization-exception information address | `0x202A (full) / 0x202B (high)` | 启用 #VE 时投递给客户机的信息区，含 EPTP index |
| Guest interruptibility state | `0x4824` | STI/MOV-SS 阻塞状态；在 MTF 窗口里判断能否安全注入或延后事件 |


### 架构约束

- EPT 条目权限组合硬约束：R=0 且 W=1 恒为 EPT misconfiguration（不是 violation）；R=0 且 X=1 需要 IA32_VMX_EPT_VPID_CAP[0]，否则同样是 misconfiguration。misconfiguration 是 exit reason 49，通常不可优雅恢复。(SDM 31.3.3.1)
- EPT 条目必须以一次 64 位对齐存储整体写入，绝不能逐位改。Sina Karvandi 在 Hypervisor From Scratch Part 8 明确记录：先清 R 再清 W 的中间态会让别的核走到 R=0/W=1 从而触发 EPT misconfiguration。正确写法是 TargetPage->Flags = NewEntry.Flags 一条指令完成，并用自旋锁包住写入+INVEPT。
- 改条目后必须 INVEPT single-context 的情形（SDM 31.4.3.4）：权限位 2:0 从 1 改 0、改 bits 51:12 的物理地址、清 A 位（A/D 已启用）、改 PDPTE/PDE 的 bit 7（大页位）、改最终条目的 bits 5:3 或 bit 6（内存类型）、清 D 位。分离视图的两个方向翻转同时命中'降权限'和'改 PFN'两条，所以两次翻转都必须 INVEPT。
- 反方向（权限 0→1）可以不 INVEPT：SDM 说明 EPT violation 本身会使该次访问用到的映射失效，重做同一访问不会重复 violation。这条可以省一次 INVEPT，但不能反过来省降权限那次。
- INVEPT 是 VMX root 指令，且只作用于执行它的那个逻辑处理器。SDM 31.4.3.4 结尾明确：多处理器系统中软件必须考虑其他逻辑处理器也缓存了该 EPT 条目的信息，需要做 TLB shootdown。驱动在非根态无法直接执行 INVEPT，必须逐核 VMCALL / KeGenericCallDpc 进根态。
- VMFUNC EPTP switching 前置条件（SDM 28.5.7.3）：目标 EPTP 与当前 EPTP 的 bits 5:3（页walk长度）必须相同，且必须是能通过 VM entry 检查的合法值；ECX >= 512 或值非法则产生 VM exit（reason 59）而不是切换。EPTP list 固定 4KB / 512 项。
- 启用 EPT-violation #VE 时，VMFUNC 会把 ECX[15:0] 写进 VMCS 的 EPTP-index 字段，后续 #VE 用它标识视图号——这条会把视图号暴露给客户机，隐蔽性设计要注意。
- 目标 GPA 若落在 2MB/1GB 大页映射内，必须先拆成 4KB 再挂钩；拆页本身要 INVEPT，且会改变该页邻域的 TLB 与性能特征（可被时序检测观察）。
- MTF 是当前 VMCS / 当前逻辑处理器的属性，不是全局属性。它保证的是'下一个指令边界'，不是'下一条你想要的那条指令'。
- MTF 与事件的交互（SDM 28.5.2）：VM entry 注入向量事件且 MTF=1 时，MTF 在 VM entry 后第一条指令之前就 pending；若 MTF=1 且有 pending 事件（#DB 或中断）先于指令投递，MTF 落在事件投递之后的边界（即落进 ISR 第一条指令后）；指令产生 fault 时同样落在 fault 投递之后。
- REP 前缀串指令：MTF 在第一次迭代之后就 pending，而不是整条指令执行完之后（SDM 28.5.2）。XBEGIN 则 pending 在 fallback 地址。
- 优先级与丢失条件（SDM 28.5.2）：SMI、INIT 及更高优先级事件优先于 MTF VM exit；处理器处于 shutdown 或 wait-for-SIPI 活动状态时不产生 MTF exit；若在到达 MTF pending 的指令边界之前发生了别的 VM exit（异常、triple fault 等），MTF exit 根本不会发生。
- 影子页与原页的 EPT memory type 必须与真实后备范围的 MTRR/PAT 一致，否则出现缓存与一致性异常——这类异常比字节内容更容易被探测到。
- 启用 EPT A/D（EPTP bit 6）后，处理器对 guest 页表结构的访问被当作写处理（SDM 31.3.3）；若被 hook 的页恰好承载客户机页表，读写视图翻转会与 A/D 写相互干扰。
- AMD NPT 没有 execute-only（X 蕴含 R），该技术无法等价移植到 AMD；这也是 momo5502 指出的平台限制。


### 失败模式

- 【核心：翻转窗口内其他核看到错误视图】共享 EPT 层级时，核 A 因读访问把条目换成'干净可读不可执行'，同一瞬间核 B 正在该页取指，B 要么执行到未被 hook 的原始代码（hook 静默失效、或被对手用来绕过），要么因 X=0 陷入 violation 风暴。Xen 官方博客对此的表述是：单 EPT 被多个 vCPU 共享时，为让一个 vCPU 继续而放松权限，会无意中让另一个 vCPU 完成本应被拦截的访问；正常情况罕见，但恶意代码可以刻意利用它来隐藏行为。避免：每逻辑处理器独立 EPT 层级/独立 EPTP。
- 【业界主流答案确实是每核独立 EPTP，但有两种形态】形态一：每个逻辑处理器一份完整 EPT 页表（HyperPlatform 把 EPT 数据放进 ProcessorData；HyperDbg 的 EptLogicalProcessorInitialize 按 KeQueryActiveProcessorCount 循环给每核分配 g_GuestState[i].EptPageTable；gbhv 同样按处理器建表；illusion-rs 每逻辑处理器一份 EPT）。形态二：一组共享的多视图 EPT + 每 vCPU 在自己 VMCS 里选视图（Xen altp2m，最多 10 个视图，硬件自 Haswell 起支持 512 个 EPTP；Phrack 69 与 matrix-rs 用双 EPT + 切 EPTP）。二者本质相同：让视图选择成为 per-vCPU 状态，翻转就不再是全局可见事件，窗口消失。
- 【per-core EPT 不是免费的】代价是每次装/卸 hook 都要把条目复制到所有 EPT 上下文，并在每个逻辑处理器上分别执行 INVEPT。secret.club 明确指出：无论共享还是每核 EPT，因为 TLB 是每逻辑处理器的，INVEPT 都必须在每个核上执行。同步不当会在线程迁移或指令重放时产生竞态与陈旧映射。
- 【只在本核 INVEPT】其他核继续使用缓存的旧 GPA→HPA 映射，产生跨核视图漂移。momo5502 的写检测直接利用这点：在一个核上把函数间填充的 0xCC 改成 0xC3 再在另一个核上执行它——写没有传播到别的核维护的影子页时立刻暴露。
- 【MTF 落在别处】中断或异常在目标指令之前被投递，MTF exit 发生在 ISR 第一条指令之后，于是在'目标指令尚未执行'时就把 hook 装了回去，同一条指令再次 violation，形成活锁 / 取指风暴。HyperDbg 源码里有原话记录这个现象：执行耗时过长时执行流可能切到别的例程，MTF 会在别的例程上结束，然后同一条指令很快（而且一定会）再次触发。修法是 HvEnableMtfAndChangeExternalInterruptState：置 MTF 的同时把 external-interrupt exiting 置 1、关掉 interrupt-window exiting，到 MTF 退出时再恢复。
- 【MTF 丢失导致 hook 永久失效】按 SDM，若在到达 MTF pending 边界前发生了别的 VM exit，或处理器进入 shutdown / wait-for-SIPI，MTF exit 不会发生。恢复点永远不执行，页面永久停在'干净可读可写'状态：hook 失效，而且写会落到原页上。避免：恢复状态存在 per-vCPU 结构里，并在其他退出路径上做兜底恢复，不要假设 MTF 一定会到。
- 【REP 串指令把单步计数打乱】完整性扫描常用 rep movsb/rep cmpsb 读该页，MTF 每次迭代都退出；若按'一条指令'语义在第一次 MTF 就重新武装，扫描会读到半页干净半页 hook 的混合内容，或陷入 violation 风暴造成可见卡顿。
- 【逐位改 EPT 条目触发 misconfiguration】先清 R 再清 W 的瞬间产生 R=0/W=1，其他核此刻走到该条目就是 exit reason 49，表现为随机不可恢复退出/蓝屏。必须整条 64 位一次写入。
- 【发布顺序反了】先把 0xCC 写进影子页、或先把条目切成 hook 态，再登记 hook 元数据——另一个核会在元数据可见之前命中 hook，处理器在查找表里找不到该 GPA，走到'未知 violation'分支或空指针。HyperDbg 源码里有两处注释专门为此：hook 细节必须先插进 g_EptState->HookedPagesList 再改条目；0xCC 必须在所有细节保存完毕之后才写入，否则别的核先触发就会因细节尚不可用而出错。同理 detour 的返回结构必须在改写原函数之前建好，否则'会在其他核上看到蓝屏'。
- 【写不回传到执行视图】读写视图给的是原页/干净副本，执行视图是影子副本；客户机对该页的写（自修改代码、重定位、热补丁）不同步到影子页，一是功能错误，二是 momo5502 的 write-check 直接判定存在 EPT hook。DdiMon 在 Caveats 里自己承认不处理自修改代码。
- 【执行视图下的同页数据读造成死循环】hook 页上的 RIP 相对寻址、常量池、跳转表在 X-only 视图下触发 violation；恢复时若不给完整 RWX 就形成 VM-exit 死循环。illusion-rs 的做法是单步窗口内临时给完整 RWX，执行一条后再重新武装。
- 【纯 EPTP 切换而不单步】Phrack 69 与 matrix-rs 模型在 violation 时直接切到另一张 EPT，不设 MTF；问题是没有可靠的回切触发点，同页混合 RWX 访问模式处理不了——secret.club 明确指出 matrix 不处理同页 RWX 混合，而 illusion 用 MTF 才能安全重放。
- 【大页未拆】直接在 2MB 条目上改权限会让整个 2MB 范围（含无关热代码/数据）产生 violation 风暴，性能塌陷且极易被时序检测。
- 【时序天然可观测】翻转必然产生 VM exit。momo5502 实测：读/执行交替的模式相比纯读的耗时差可达 10~100 倍。RDTSC 可以被虚拟化补偿，但跨线程计数器竞速（把两个线程绑到不同物理核，一个计数一个测量）很难掩盖，他认为这是三种检测里最好的一种。
- 【暂停所有 vCPU 单步：正确但昂贵】Xen 博客直接评价这是为了规避一个罕见竞态而引入沉重开销。HyperDbg 的 instrumentation step-in 用 NMI 广播把其他核冻结在 VMX root 来实现'保证式单步'，正确性好但不能长期开启。
- 【用模拟器代替单步：彻底消除窗口但有别的坑】Xen 的 vm_event 支持返回干净 i-cache 供模拟（SET_EMUL_INSN），Tamas K Lengyel 的原始 patch 说明就是为了 side-step 这个多 vCPU 竞态。但他本人更推荐 altp2m，理由是 Xen 的指令模拟器不完整、会导致客户机不稳定，且模拟器历来是安全漏洞高发区（VENOM 类）。性能上他给的数据是 altp2m 断点与模拟器基本持平——altp2m 切换足够快，抵消了多一次单步往返。
- 【新平台阻断】VBS/HVCI 会阻止第三方 hypervisor 加载或破坏 EPT 重定向；Intel VT-rp（HLAT/分页写保护）进一步限制这类技术。另外 Intel 已就 CVE-2024-36242 / CVE-2024-38660 建议 VMM 停止在虚拟化环境中使用 sub-page permissions (SPP)，并计划在未来处理器上取消 SPP——不要把细粒度写控制押在 SPP 上。


### 来源

- Intel 64 and IA-32 Architectures SDM（合订本，本次实际下载核对）https://cdrdv2.intel.com/v1/dl/getContent/671200 — 关键章节：28.5.2 Monitor Trap Flag（MTF pending/丢失/优先级/REP 语义）、28.5.7.3 EPTP Switching（VMFUNC 0 的合法性检查、512 项 EPTP list、EPTP-index 写回）、31.3.3.1 EPT Misconfigurations（R=0&W=1、执行-only 能力）、31.4.3.4 Guidelines for Use of the INVEPT Instruction（何时必须 INVEPT + 多处理器 TLB shootdown 要求）、附录 A.10（IA32_VMX_EPT_VPID_CAP 位定义）、附录 B（VMCS 字段编码）
- Tamas K Lengyel, "Stealthy monitoring with Xen altp2m", Xen Project Blog, 2016-04-13 — 最直接回答本题：共享单 EPT 放松权限会让别的 vCPU 溜过监控；三种解法（暂停所有 vCPU 单步 / 指令模拟 / altp2m 每 vCPU 切视图）的取舍；altp2m 还能让同一 GPA 在不同视图映射到不同物理页，从而每 vCPU 隐藏 INT3。https://xenproject.org/blog/stealthy-monitoring-with-xen-altp2m/
- DRAKVUF PR #38 "Use Xen altp2m to allow multi-vCPU tracing" — 原文：断点命中时不再移除断点，而是切到默认视图并开单步，之后切回；这可以按每个 vCPU 分别进行，因此执行期间不存在竞态。https://github.com/tklengyel/drakvuf/pull/38
- DRAKVUF issue #667 "Faster breakpoints with VMI_EVENT_RESPONSE_SET_EMUL_INSN?" — altp2m 与指令模拟两条路线的完整讨论，含 Tamas 的结论：Xen 模拟器不完整所以更偏好 altp2m；altp2m 断点性能与模拟器基本持平。https://github.com/tklengyel/drakvuf/issues/667
- Tamas K Lengyel, xen-devel [PATCH 2/2] x86/vm_event: Allow returning i-cache for emulation (2016-09-13) — 竞态的权威表述：移除 INT3 → 单步 → 放回 INT3 这一流程在多 vCPU 客户机上存在竞态；返回干净 i-cache 供模拟可以绕开。https://lists.xenproject.org/archives/html/xen-devel/2016-09/msg01373.html
- memN0ps / secret.club, "Hypervisors for Memory Introspection and Reverse Engineering" (2025-06-02) — illusion-rs（每逻辑处理器 EPT + MTF 重放）与 matrix-rs（共享双 EPT + EPTP 切换）的 Per-Core vs Shared 对比；明确指出共享 EPT 会跨处理器产生竞态，且无论哪种模型 INVEPT 都必须在每个逻辑处理器上执行；以及 hypervisor 检测向量清单。https://secret.club/2025/06/02/hypervisors-for-memory-introspection-and-reverse-engineering.html
- Sina Karvandi, "Hypervisor From Scratch – Part 8: How To Do Magic With HYPERVISOR!" — "An Important Note When Modifying EPT Entries"：多核系统上 EPT 条目必须一条指令改完，逐位改会导致 EPT Misconfiguration；EptSetPML1AndInvalidateTLB 的自旋锁 + INVEPT 模式；MTF 与隐藏 hook 的完整实现；"each core has a separate TLB and separate Monitor Trap Flag"。https://rayanfam.com/topics/hypervisor-from-scratch-part-8/
- HyperDbg 设计文档 Design of !epthook（execute-only + MTF 的经典分离视图）https://docs.hyperdbg.org/design/features/vmm-module/design-of-epthook 与 Design of !epthook2（隐藏 inline detour）https://docs.hyperdbg.org/design/features/vmm-module/design-of-epthook2
- HyperDbg 源码 EptHook.c — 竞态相关注释的一手证据：hook 细节必须先入 HookedPagesList 再改条目（because the hook might be simultaneously triggered from other cores）；0xCC 必须最后写（否则别的核先触发时细节尚不可用）；detour 返回结构必须提前建好（否则 we probably see BSOD on other cores）；EPT violation 处理里恢复原条目 + 设 MtfEptHookRestorePoint + HvEnableMtfAndChangeExternalInterruptState。https://github.com/HyperDbg/HyperDbg/blob/master/hyperdbg/hyperhv/code/hooks/ept-hook/EptHook.c
- HyperDbg 源码 Ept.c — EptLogicalProcessorInitialize 按逻辑处理器数循环为每核分配独立 EPT 页表（g_GuestState[i].EptPageTable），是'每核独立 EPT'的实证。https://github.com/HyperDbg/HyperDbg/blob/master/hyperdbg/hyperhv/code/vmm/ept/Ept.c
- HyperDbg 源码 Hv.c — HvEnableMtfAndChangeExternalInterruptState：置 MTF 的同时打开 external-interrupt exiting、关闭 interrupt-window exiting，注释明确说明是因为执行耗时过长会让 MTF 在别的例程上结束并导致同一指令重复触发。https://github.com/HyperDbg/HyperDbg/blob/master/hyperdbg/hyperhv/code/vmm/vmx/Hv.c
- M. S. Karvandi et al., "HyperDbg: Reinventing Hardware-Assisted Debugging" (ACM CCS 2022, 扩展版) — instrumentation step-in：用 MTF 保证只执行下一条指令，并用 NMI 让其他核停住、同时关本核外部中断，以此消除中断对单步的干扰。https://arxiv.org/abs/2207.05676
- Maurice Heumann (momo5502), "Detecting Hypervisor-assisted Hooking" (2022-05-02) — 三种用户态检测法：write-check（并明确指出在一个核上写、在另一个核上执行可暴露 per-core hypervisor 的不一致）、RDTSC 时序、跨线程竞速计时；以及 AMD 无 execute-only 的限制。https://momo5502.com/posts/2022-05-02-detecting-hypervisor-assisted-hooking/
- Satoshi Tanda, DdiMon — 三页模型（0xa000 执行视图含 0xCC、0xb000 读写视图干净、原页给 hypervisor）+ MTF 恢复；Caveats 自陈不处理自修改代码（写不回传到执行视图）。https://github.com/tandasat/DdiMon
- Satoshi Tanda, HyperPlatform ept.cpp — EPT 数据存放于 ProcessorData（每处理器一份），并在初始化时校验 INVEPT 全部类型受支持。https://github.com/tandasat/HyperPlatform/blob/master/HyperPlatform/ept.cpp
- uty & saman, "How to hide a hook: A hypervisor for rootkits", Phrack #69 — EPT 隐藏 hook 方法论的源头；实现上不反复改条目，而是准备两张几乎相同的 EPT 表，在 violation 时整表切换（早期的双视图/切 EPTP 思路）。https://phrack.org/issues/69/how-to-hide-a-hook-a-hypervisor-for-rootkits.html
- Gbps, gbhv — 为每个处理器建立 EPT 页表，默认 2MB 大页并按需拆成 4KB；README 明确以 Phrack 69 为 EPT hooking 方法论基础。https://github.com/Gbps/gbhv
- kernullist blog, "Hypervisor Cheats Part 2: EPT/NPT Split Views and Second-Stage Fault Evidence"（防守/取证视角）— 归纳失效模式表：per-vCPU 视图变更不得当作全局状态否则'另一个核会看到不可能的视图混合'；SMP 协调要求所有逻辑处理器对当前视图达成一致，per-core 采样可暴露漂移；并提醒 Intel 已建议停用 SPP（CVE-2024-36242 / CVE-2024-38660）。https://kernullist.github.io/kernullist-blog/posts/hypervisor-cheats-part-2-ept-npt-split-views-and-second-stage-fault-evidence/
- Z. Deng, X. Zhang, D. Xu, "SPIDER: Stealthy Binary Program Instrumentation and Debugging via Hardware Virtualization", ACSAC 2013 — EPT 分离视图/隐形断点的经典学术源头（ACM DL 收费，未能取得全文，仅列作出处）。https://doi.org/10.1145/2523649.2523675



---

# 附录：对一份第三方实现的规范审查

下面是以上面的规范为准绳，对 `ARK-master/KernelImplementation/VirtualizationModule`
（一份第三方 nested VMX 实现，约 26k 行）做的审查。

记录它的目的不是照抄，而是把"某种做法可行"与"某种做法正确"分开：
一份能跑的实现里，哪些是架构要求、哪些是它为自己的特性子集做的选择，
不查规范是分不出来的。凡是它做了而规范没要求的，我们要自己判断值不值得跟；
凡是规范要求而它没做的，我们不能因为"人家也没做"就跳过。

核实结果与逐条发现如下。

---

## 关于已知线索的核实

**线索不成立**：execute-only 的能力探测是存在的。

- `C:\Users\Felix\Downloads\ARK-master\KernelImplementation\VirtualizationModule\HvmNestedEpt.c:457-460` —— 影子 EPT walker 在 `HvmpNeptEntryMisconfigured()` 中显式判断 `!Read && !Write && executable && (caps & HVM_EPT_VPID_CAP_EXECUTE_ONLY) == 0 → misconfiguration`，与 SDM 31.3.3.1 一致（不支持 X-only 时该编码是 exit reason 49 而非 48）。
- 能力位定义在 `HvmArch.h:929`，取值来源 `HvmNestedCaps.c:445-448`（直通硬件 bit 0，只屏蔽 5 级页表 bit 7 与 supervisor shadow stack bit 23）。
- 因为 caps 直通硬件，EPT12 的 X-only 叶项只有在硬件真支持时才能通过检查并被 `HvmpNeptLeaf()`（`HvmNestedEpt.c:363-366`）复制进 EPT02，所以没有"在不支持的机器上写出 X-only EPT02 叶项"的路径。

但**同一族的问题在 INVEPT 上确实存在**（见下 §1.2）。

---

## (1) 规范之外的特定假设 / 无降级路径

**1.1 `HvmNestedCaps.c:445` 无条件 RDMSR IA32_VMX_EPT_VPID_CAP（0x48C）** — 最高危

```c
caps->EptVpidCap = __readmsr(HVM_MSR_IA32_VMX_EPT_VPID_CAP);
```
SDM Vol 3D A.10：该 MSR 仅当 `IA32_VMX_PROCBASED_CTLS[63]=1` 且 `PROCBASED_CTLS2` 的 EPT(bit 33) 或 VPID(bit 37) 之一为 1 时才存在，否则 RDMSR `#GP`。

同一文件对其它条件 MSR 都做了门禁：`HvmNestedCaps.c:349-355`（CTLS2 门禁 `SecondaryControlsSupported`）、`466-470`（VMFUNC）、`486-490`（CTLS3）；`HvmContext.c:115-133` 甚至写了注释"Reading it on parts that lack it would #GP"。唯独 0x48C 漏了。

`HvmNestedCapsInitialize()` 在 `HvmContext.c:478` 被**无条件**调用，早于任何 EPT 可用性分支（`HvmContext.c:515` 才判断 `EptSupported`）。在支持 secondary controls 但既无 EPT 也无 VPID 的 CPU 上，驱动加载即 `#GP` → 0x1E 蓝屏。
注意读取路径本身是对的（`HvmNestedCaps.c:723-729` 正确按 EPT|VPID 门禁返回 `Unavailable`→注入 #GP），坏的只有初始化。

**1.2 INVEPT 未探测 cap bit 20 / bit 25，且返回值被丢弃**

- `HvmEpt.c:289-296` `HvmEptInvalidate()`：直接 `HvmAsmInvept(HVM_INVEPT_SINGLE_CONTEXT, ...)`，返回值丢弃。
- `HvmNestedEpt.c:228-234` `HvmpNeptInvept()`：同上；调用点 `HvmNestedEpt.c:281`（invalidate）与 `2062`（每次影子叶项安装后）。
- `HvmEpt.c:166-174` 的能力门禁只查了 `PAGE_WALK_4 / MEMORY_TYPE_WB / 2MB_PAGE`，**没查 bit 20（INVEPT 存在）和 bit 25（single-context 型）**。

后果分两级：bit 20=0 → VMX root 态 `#UD`（内核未处理异常，蓝屏）；bit 20=1 但 bit 25=0 → `VMfailValid`，因返回值被丢弃而静默，影子 EPT 改完不失效 → 陈旧 GPA→HPA 映射（"钩子时有时无"类问题）。

对照组说明这不是"作者不知道"：`HvmVmx.c:89-111` 的 `HvmVmxInvalidateTranslations()` 做得完全正确（先读 cap，优先 all-context，回退 single-context，无可用型别时返回 FALSE，且逐条检查返回值）。这是同一模块内部标准不一致。

**1.3 `HvmNestedCaps.c:389-394` 广告了 IA32_VMX_MISC bit 5 但未实现**

```c
caps->Misc = __readmsr(HVM_MSR_IA32_VMX_MISC);
caps->Misc &= ~((1ULL << 14) | (1ULL << 15) | (1ULL << 28) | (1ULL << 29) |
                0xFFFFFFFF00000000ULL);
```
bit 14/15/28/29 与 MSEG 都被屏蔽，**bit 5 被原样透传**。bit 5 = "VM exit 把 IA32_EFER.LMA 存回 VM-entry 控制位 IA32E_MODE_GUEST"。

全模块搜不到该行为的实现：`HvmNestedReflect.c:213-345`（`HvmpSaveL2ExitState`，SDM 28.2/28.3 的写回集合）里没有任何对 `v12->VmEntryControls` 的 `IA32E_MODE_GUEST` 位回写；`IA32E_MODE_GUEST` 在 .c 文件中的全部出现（`HvmNestedEntryCheck.c:492/619`、`HvmNestedVmcs02.c:54`、`HvmVmcs.c:392`）都是读取。KVM 在 `prepare_vmcs12()` 里对应做了这件事。

这直接违反该文件自己的设计原则（`HvmNestedCaps.c:9-23`："Adding a feature to the mask requires that Hvm's nested engine actually implement the corresponding shadow semantics"）。

**1.4 `HvmNestedCaps.c:186-198` `HvmpCapPair()` 会重新放行自己不支持的特性，且注释承诺的日志不存在**

```c
if ((mustBeOne & ~mayBeOne) != 0) {
    mayBeOne |= mustBeOne;      /* 无任何 HvmLog* 调用 */
}
```
注释（`188-194` 行）写的是"log and force it into mayBeOne anyway"，代码里没有 log。语义上：任何被硬件强制为 1、却被 `HVM_CAPS_*_SUPPORTED` 掩码排除的控制位，会被静默重新加入 allowed-1，于是 L1 可以（且必须）设置一个嵌套引擎并未 shadow 的控制位——正是该文件开头声明要避免的"silent-correctness bug"。

**1.5 `HvmNestedCaps.c:437` VMCS_ENUM 原样透传**

```c
caps->VmcsEnum = __readmsr(HVM_MSR_IA32_VMX_VMCS_ENUM);
```
注释自承"subsystem S3 owes strict validation"。L1 用它枚举最高字段编号后探测字段，凡 `HvmVmcs12IsSupportedField()` 不认的都会得到 `VMfailValid(UNSUPPORTED_VMCS_FIELD)`（`HvmNestedInstr.c:2564-2576`、`2668-2679`），与广告值不自洽。属已知债务，但仍是"广告 > 实现"。

**1.6 影子 EPT 假设 L0 EPT 恒为恒等映射**

`HvmNestedEpt.c:296-299`：
```c
HVM_HPA Pa;  /* L1's PA = HPA under identity L0 EPT, aligned to LeafSize. */
```
EPT12 叶项的 PFN 被直接当作 HPA 写进 EPT02（`HvmNestedEpt.c:379`）。同时 `HvmEpt.c:405 HvmEptSplit4K()` 是公开导出的，`HvmEpt.h:47` 明确写它的用途是"shadowing, page-level R/W/X policy"（即 EPT hook）。一旦 L0 自己在 EPT01 上做了重定向，L2 走的是绕过 EPT01 的独立 EPT02，会直接看到被 hook 页的真实后备物理页。当前配置下不触发，但这是一个未被断言、也未被注释警示的耦合。

**1.7 `HvmNestedInstr.c:2224-2310` VMXON 未做 CR0/CR4 fixed-bit 检查**

`HvmpVmxPreconditions()`（`1854-1898`）只查 CR0.PE / CR4.VMXE / VMX operation / CPL，VMXON 处理只补了 `IA32_FEATURE_CONTROL`（`2247-2258`）与区域指针/revision（`2268-2282`）。SDM VMXON 还要求 CR0/CR4 满足 `IA32_VMX_CRn_FIXED0/1` 否则 `#GP(0)`；另外 `RFLAGS.VM=1` 与兼容模式（`IA32_EFER.LMA=1 && CS.L=0`）应 `#UD`，也未实现。影响面小（L1 已在 VMX 下运行），但属规范缺项。

---

## (2) 覆盖不全（规范要求但未实现）

**2.1 SDM §27.2.2 / §27.2.3 host-state 检查几乎全缺——且被 reflection 直接消费，可被 L1 打死 L0** — 最高危

`HvmpNestedCheckHostState()`（`HvmNestedEntryCheck.c:844-940`）只覆盖：HostRip/HostRsp 规范性、CR0/CR4 fixed bits、CET+CR0.WP、EFER、PKRS、FRED。

**未做的**（grep 全文件确认这些字段名在 `HvmNestedEntryCheck.c` 中零出现）：
- `HostCr3` 的 MAXPHYADDR 宽度检查
- 全部 host 段选择子的 RPL=0 / TI=0 / CS≠0 / TR≠0 / 非 ia32e 时 SS≠0
- `HostGdtrBase / HostIdtrBase / HostTrBase / HostFsBase / HostGsBase` 的规范地址检查
- `HostIa32SysenterEsp / Eip` 的规范地址检查
- `HostIa32Pat`（LOAD_IA32_PAT 时）的合法性
- 非 ia32e 时 `HostCr4.PCIDE` 必须为 0、`HostRip[63:32]` 必须为 0

这些字段在反射路径上被**逐个直接写进 VMCS01 的 guest 区**：
`HvmNestedReflect.c:418`（`GUEST_CR3 ← v12->HostCr3`）、`435-441`（各 GUEST_*_SELECTOR ← Host*Selector）、`472-474`（FS/GS/TR base）、`478-481`（GDTR/IDTR base）、`484-486`（SYSENTER）、`502`（PAT）。

失效链是闭合的：L1 写一个非规范的 `HostGdtrBase`（或 RPL≠0 的 `HostSsSelector`、超 MAXPHYADDR 的 `HostCr3`）→ 反射写入 VMCS01 guest 区 → `HvmAsm.asm:287` 的 `vmresume` 失败 → `HvmAsm.asm:318` → `HvmVmEntryFailure()`（`HvmExit.c:1655`）此时 `NestedRunPending == FALSE`，走到 `HvmExit.c:1715 return FALSE` → `HvmAsm.asm:355 jz HvmAsmVmEntryInstructionFatal` → **`HvmAsm.asm:374-375` `int 3`**（VMX root、IF=0）。

架构上正是 §27.2.2/27.2.3 这组检查在保证"host-state 加载不会失败"，跳过它就把 L1 的输入变成了 L0 的自杀开关。

**2.2 SDM §27.3.1.2 / .3 / .4 / .6 guest-state 检查整体缺失**

`HvmpNestedCheckGuestState()`（`HvmNestedEntryCheck.c:609-842`）覆盖 CR0/CR4 fixed bits、CET/CR0.WP、PG-without-PE、EFER 一致性、IA-32e 分页、activity state、interruptibility、VMCS link pointer、CET/PKRS/UINV/FRED 状态。

未覆盖：段寄存器（选择子/基址/limit/AR 全套，§27.3.1.2）、描述符表基址规范性（§27.3.1.3）、RIP/RFLAGS 保留位与宽度（§27.3.1.4，只有 `572-575` 那条 IF 检查）、PDPTE（§27.3.1.6）、`GuestCr3` 宽度、`GuestDr7[63:32]`、`GuestIa32Debugctl` 保留位、`GuestIa32Pat`、`GuestPendingDbgExceptions` 保留位与一致性。

grep 确认：`GuestCr3|GuestDr7|Guest*Selector|GuestGdtrBase|GuestIdtrBase|GuestPdpte*|GuestSysenterEsp|GuestIa32Pat|GuestPendingDbg` 在 `HvmNestedEntryCheck.c` 中只出现 2 次，均为无关用途（`823` 的 FRED 模式判定、`974` 的调试日志）。

这些字段全部被 `HvmNestedVmcs02.c:756-843` 原样写进 VMCS02。后果比 2.1 轻——因为有 1.5 节的兜底（见 (3).11）——但语义仍错：本应是 "exit reason 33 + bit31，guest-state 不修改、entry interruption valid 位不清、不存 MSR store"（§27.8），实际变成 `HvmExit.c:1697-1700` 把**任何**硬件错误码一律改写成 `VMfailValid(VMENTRY_INVALID_CONTROL=7)`。L1（KVM/Hyper-V）对这两条路径的错误处理完全不同。

**2.3 合并 MSR 位图未 OR 进 L0 自身的强制拦截**

`HvmNestedBitmap.c:141-152`：
```c
/* Start every merged bitmap from L0's L2-intercept template. Today that
 * template is all-zeros ... Any future L0 mandatory intercepts get OR'd in here. */
RtlZeroMemory(pN->MergedMsrBitmap.VirtualAddress, PAGE_SIZE);
```
`HvmNestedBitmap.c:66-69` 的注释甚至点名了应该加什么："IA32_FEATURE_CONTROL to keep L2 from disabling VMX"。

实际只有两处补拦截：`HvmNestedBitmap.c:192`（x2APIC）与 `193-200`（FRED RSP0/SSP0）。

而 VMCS01 的位图（`HvmNestedCapsSetupIntercepts()`，`HvmNestedCaps.c:633-683`）强制拦截了三组，并各自写明了理由：
- `647-651`：整段 VMX 能力 MSR（0x480–0x493）读
- `659-660`：IA32_FEATURE_CONTROL 读写
- `668-669`：IA32_EFER 读写（注释：不拦截则"valid writes update hardware behind the VMCS abstraction and reserved writes bypass Hvm's CPUID-based validator entirely"）

L2 运行期这三组全部不生效。最实在的一条：**L2 `RDMSR 0x480–0x493` 直接返回真实硬件值**，与 L0 给 L1 的合成能力集（`HvmNestedCapsReadShadow`）不一致。

**2.4 CR3-target 匹配的 exit 没有本地模拟器，被错误地反射给 L1**

`HvmNestedVmcs02.c:724` 把 VMCS02 的 `CR3_TARGET_COUNT` 硬写为 0，改由软件过滤：`HvmNestedExitRoute.c:144-151` 的 `HvmpNestedExitCr3TargetMatch()` 正确判定"L1 不要这个 exit"。

但 `HvmNestedExitHandleUnwanted()` 的 CR_ACCESS 分支只实现了 CR0（`584-613`）、CR4（`615-636`）、CR8（`638-639`），CR3 落到 `641-647 default: break; → goto reflect_fallback`，注释自承"CR3 and malformed accesses retain the diagnostic reflection fallback"，最终 `HvmNestedExitRoute.c:693 return HvmNestedReflectL1`。

于是：L1 设了 CR3-load exiting + CR3 目标值，L2 写了一个命中目标值的 CR3 —— 硬件上 L1 永远不会看到这次 exit，这里 L1 却收到了。同时 `caps->Misc` 的 `Cr3TargetCount`（透传硬件，`HvmNestedCaps.c:389`）在广告这个功能，入口检查 `HvmNestedEntryCheck.c:245-249` 也在按它校验。

**2.5 `HvmNestedInstr.c:3320` INVVPID 返回值丢弃后无条件 VMsucceed**

```c
(VOID)HvmAsmInvvpid(hardwareType, &descriptor);
...
HvmpVmSucceed();
```
`HvmpHandleInvept()` 同样（`3236-3239`：`HvmNestedEptInvalidate()` 内部的 INVEPT 也不检查结果）。若硬件 VMfail，L1 得到的是"成功"，而映射并未失效。

**2.6 #VE 转换条件缺两条**

`HvmpNeptTryConvertViolationToVe()`（`HvmNestedEpt.c:627-697`）实现得相当忠实：suppress-#VE bit 63（`660-666`，且正确区分 not-present 用 FaultEntry / present 用 LeafEntry）、CR0.PE（`668-671`）、事件投递中（`673-678`，查 IDT-vectoring）、busy 字段 CAS（`602-608`，`HVM_VE_DELIVERY_COMPLETE = -1` 即 0xFFFFFFFF，正确）、异常位图 bit 20（`688-693`）、shadow-stack 过早置忙（`649-658`）。

缺 SDM 28.5.8.1 的两条：Intel PT 输出引发、PEBS 引发。实际影响可忽略（PT-in-VMX 已在 `HvmNestedCaps.c:390` 屏蔽 bit 14），列出以求完整。

---

## (3) 规范之外但工程上明显正确、值得借鉴

1. **`HvmNestedCaps.c:206-216` `HvmpCapRequire()`** —— 把"跨 MSR 的依赖关系"显式编码。单个能力 MSR 无法表达"pin-based preemption timer 需要 exit-control SAVE_PREEMPTION_TIMER"（`276-285`）、"posted interrupts 需要 ACK_INTR_ON_EXIT + VID + TPR shadow"（`362-381`）。规范里没有这个概念，但这是唯一能保证"广告的每一位都有运行时后端"的做法。

2. **`HvmNestedCaps.c:408-425`** —— 当某个必须隐藏的 CR4 特性恰好被硬件 FIXED0 强制为 1 时，**直接 `return STATUS_NOT_SUPPORTED` 拒绝加载**，而不是生成一个 FIXED0/FIXED1 不可满足的合成对。宁可不跑也不给 L1 一个自相矛盾的契约。

3. **`HvmNestedRuntime.c:54-86` `HvmNestedValidateEptp()`** —— 把 EPTP bit 7（supervisor shadow stack）无条件拒绝（`76`）。这正是 SDM 自身不一致处（Table 27-9 定义了 bit 7，§29.2.1.1 仍写"bits 11:7 must all be 0"）的正确保守解，与 KVM `nested_vmx_check_eptp()` 一致。同一函数完整覆盖了内存类型/走表层数/AD/保留位/MAXPHYADDR 五条检查，且被三处复用（entry check `HvmNestedEntryCheck.c:336`、INVEPT `HvmNestedInstr.c:3230`、VMFUNC `HvmNestedRuntime.c:186`）——单一判据源。

4. **每 vCPU 独立影子 EPT** —— `HvmNested.c:93-97` 每个 vCPU 一份 `NestedEpt`。这使得跨核 INVEPT shootdown 在架构上不必要，直接消灭了共享 EPT 多视图方案里最难查的那一类竞态。配合 `HvmNestedEpt.c:2062` 每次叶项安装后立即 INVEPT，语义自洽。

5. **`HvmNestedEpt.c:2027-2058` 影子表容量耗尽的处理** —— 回收整表 + 重试一次，而不是"编造一个 EPT violation 反射给 L1"。注释点破了关键："reflecting an invented EPT violation to L1 cannot make the access repairable"。规范没说该怎么办，但这是唯一不会把资源问题伪装成架构事件的做法。

6. **`HvmNestedEpt.c:129-138`** —— 预分配页复用前强制清零，注释解释了不清零会让硬件"follow a ghost pointer to arbitrary memory"。

7. **`HvmNestedVmcs02.c:463-489` 不强制 OR #DB/#MC 进 VMCS02 异常位图** —— 附完整的活锁推导（forced EB.DB → 重注入 → BS 位未清 → DISPATCH_LEVEL/IF=0 死循环 → 0x101），并引 KVM 只在显式 attach 调试器时才设 EB.DB 作旁证。这是"少设一个 L0 拦截反而更正确"的反直觉结论。

8. **`HvmNestedVmcs02.c:504-539` UG 下从 VMCS02 CR0 mask 中剥掉 PE|PG** —— SDM 26.7.6 说 UG 下 CR0.PE/PG 不必为 1，但 `IA32_VMX_CR0_FIXED0` 仍报告它们必需。不剥掉的话 L2 实模式启动的每次 CR0 写都会产生 L1 眼中"架构上不可能"的 exit。入口检查（`HvmNestedEntryCheck.c:631-633`）与本地 CR 模拟器（`HvmNestedExitRoute.c:576-582`）三处用同一条剥离规则，保持一致。

9. **`HvmNestedReflect.c:298-315` 写回 VMCS12 时严格按 VM-exit SAVE_* 控制位门禁** —— DR7/DEBUGCTL/EFER/PAT 只在 L1 请求了对应 save 位时才回写。注释给了具体故障案例（GVM：IA32E_MODE_GUEST=1 且 SAVE_IA32_EFER=0 时无条件回写会把长模式 EFER 换成 0x801，下次 entry 失败）。很多实现在这里是无条件 copy。

10. **`HvmNestedExitRoute.c:650-693` 的 fallback 策略** —— 遇到无本地模拟器的 L0-forced exit 时反射而**绝不推进 RIP**，并注释明写"never 'fix' the loop by skipping guest instructions"；同时维护 per-reason 直方图 + 连续计数（`664-681`）用于定位缺失的 handler。把"诊断可观测性"当成正确性的一部分。

11. **`HvmExit.c:1655-1716` `HvmVmEntryFailure()` 的 VMCS02 回滚** —— 硬件拒绝 VMCS02 entry 时，回滚到 VMCS01、复原 MSR 列表、给 L1 一个 `VMfailValid` 而不是让 L0 崩。这实质上是 (2).2 的兜底网，也是全模块唯一让不完整的 guest-state 检查不致命的原因。（对比 2.1：host-state 路径**没有**等价兜底，这正是 2.1 危险而 2.2 不危险的原因。）

12. **`HvmNestedInstr.c:1994-2007` VMCS12 影子按 GPA 做 LRU 缓存而非 VMPTRLD 时清零** —— SDM 25.11.1 要求 VMCS 字段跨 VMPTRLD/VMCLEAR 持久；注释记录了清零导致 VMware/KVM vCPU 迁移时 HOST_CR0/CR4/RFLAGS 丢失 → VMLAUNCH FIXED-bit 失败 → 0x101 的完整事故。

13. **`HvmNestedBitmap.c:49-62` L1 位图页不可映射时 OR 全 1** —— fail-closed（拦截一切）而不是 fail-open。

14. **`HvmNestedVmcs02.c:604-612` VMFUNC 的 trap-and-emulate 布局** —— secondary control 放行 `ENABLE_VMFUNC`，但 `VMFUNC_CONTROLS` 写 0，使 L2 的 VMFUNC 必然以 reason 59 退到 L0，再由 `HvmNestedRuntime.c:142-218` 对着 VMCS12 完整模拟 EPTP switching。该模拟本身也很忠实：EAX>63→#UD（`168-171`）、控制位未置→反射（`172-174`）、ECX≥512 / list 未对齐→反射（`178-182`）、页遍历层数必须与当前 EPTP 相同（`190-194`）、`EptpIndex` 仅在硬件存在该字段时更新（`197-200`）。

15. **`HvmNestedRuntime.c:206-213`** —— EPTP 切换后**仅当 VPID 未启用**才执行 INVVPID。这精确对应 SDM 28.5.7.3 的 TLB 规则（VPID=1 时硬件不做额外失效），既没有漏刷也没有多余刷新。

16. **`HvmNestedInstr.c:2761-2905` VMCS shadowing 的纯软件模拟** —— VMCS02 里 `VMCS_SHADOWING` 被清掉（`HvmNestedVmcs02.c:385-387`），改由 L0 在 VMREAD/VMWRITE exit 上查 L1 的 VMREAD/VMWRITE bitmap（`2793-2797`）、校验 link pointer 的 revision + shadow bit（`2732-2752`）、拒绝只读字段（`2886-2892`）、对 AR 字节做 `& 0x1F0FF` 掩码（`2893-2896`）。指令语义顺序也对：bitmap 决定的 VM exit 判定**先于** CPL 检查（`2793` 在 `2799` 之前），与 SDM VMREAD 伪代码一致。

17. **`HvmNestedEntryCheck.c:156-188` VMCS link pointer 检查** —— 完整实现了 §27.3.1.5 里最容易漏的那条：被指向页首 dword 的 bit 31 必须**等于** `VMCS_SHADOWING` 控制位（`186-187`），而不只是校验 revision id。

---

## 优先级建议

| # | 位置 | 问题 | 严重度 |
|---|---|---|---|
| 2.1 | `HvmNestedEntryCheck.c:844-940` + `HvmNestedReflect.c:415-512` | host-state 检查缺失 → L1 可用一个非法 `HostGdtrBase`/`HostCr3` 把 L0 打到 `HvmAsm.asm:374` 的 `int 3` | 高（可触发的 L0 崩溃） |
| 1.1 | `HvmNestedCaps.c:445` | 无门禁 RDMSR 0x48C → 无 EPT/VPID 的 CPU 上加载即 #GP | 高（平台兼容性，确定性崩溃） |
| 1.2 | `HvmEpt.c:295`、`HvmNestedEpt.c:233` | INVEPT 无能力探测、返回值丢弃 → #UD 或静默陈旧映射 | 高 |
| 2.3 | `HvmNestedBitmap.c:141-152` | 合并位图缺 L0 强制拦截；L2 可直读真实 VMX 能力 MSR | 中 |
| 1.3 / 1.4 / 1.5 | `HvmNestedCaps.c:389-394 / 195-197 / 437` | 广告超出实现 | 中 |
| 2.4 | `HvmNestedExitRoute.c:641-647` | CR3-target 命中却反射给 L1 | 中 |
| 2.2 | `HvmNestedEntryCheck.c:609-842` | guest-state 检查缺失（有 `HvmExit.c:1655` 兜底，但错误码语义错） | 中低 |
| 1.7 / 2.5 / 2.6 | 见上 | 规范细节缺项 | 低 |

上述每条均已在源码中定位并核实；没有找到问题的地方（execute-only 探测、EPTP 校验、VMFUNC 模拟、#VE 主体转换逻辑、VMCS shadowing、link pointer 检查、exit routing 表）已在 (3) 中如实标注为正确。
