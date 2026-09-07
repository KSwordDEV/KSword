# EPT 分离视图：从「写叶 + MTF」到「切 EPTP」

来源：对照公开项目 `noahware/Hyper-reV` 的 SLAT hook 机制，重读 KSword 现有实现后得出。
本文只讨论**翻转机制**；Hyper-reV 的投递方式（替换 `bootmgfw.efi` 注入 Hyper-V）不在范围内，
那是 bootkit 式安装，与 KSword 的部署模型和产品定位都不相容。

---

## 1. 现状：写叶 + monitor-trap

`hvm_ept_view.c` 的分离视图给一个 guest-physical 页两个后备帧，按访问类型二选一：

- **CLOAK**：执行留在真页，读写导到影子 → 代码正常跑，内存扫描器看到的是影子内容
- **HOOK**：读看到真页，执行走影子（影子上是打了补丁的指令）→ 字节比较找不到的断点

机制是「leaf flip」：主值拒绝要重定向的那种访问 → EPT violation → 装次值 → 武装 MTF →
guest 退休一条指令 → MTF 退出里恢复主值。

多核安全由 `hvm_ept_local.c` 的**每处理器私有层次**保证。它的文件头写得很清楚：

> Both flip mechanisms in this driver write one EPT leaf and let the guest retire a single
> instruction. With one shared hierarchy that write is visible to every other processor for
> the whole window, which is why both features refuse any topology but a single processor.
> A private hierarchy removes that window by construction rather than by timing.

## 1.5 实测：嵌套环境下现有后端**根本装不上 hook**

2026-09-05 在 Hyper-V 嵌套 L1（Windows 11 Home 22621，4 vCPU，`ExposeVirtualizationExtensions`
已开）真实加载 `KswordARK.sys` 并查询 `hvm-status`，得到：

```
state=0x80001, features=0x1003f30ffffff, processors=0/0, vmExits=0
```

解码后 33 项能力位置位（`INTEL` `VMX` `EPT` `EPT_WB` `EPT_4_LEVEL` `EPT_2MB` `EPT_AD`
`INVEPT` `INVEPT_SINGLE` `INVEPT_ALL` `VPID` `HYPERVISOR_PRESENT` `NESTED_VMX_EXPOSED`
`EPT_4KB_SPLIT` `EPT_RULES` `EPT_EVENT_RING` `MTRR_AWARE_EPT` `MSR_BITMAP` `EXIT_EMULATION`
`HYPERV_EVMCS_CAPABLE` `HYPERV_EVMCS_V1` 等），状态位是
`STATE_INITIALIZED | STATE_EVMCS_PARTIAL`。

**但 `FEATURE_MONITOR_TRAP_FLAG` 没有置位。**

该位来自 `IA32_VMX_PROCBASED_CTLS` 的 allowed-one 掩码 bit 27（`hvm_runtime.c:622-626`），
读能力 MSR 即可得到，不需要 VMXON。它没置位意味着 **Hyper-V 的嵌套虚拟化不向 L1 暴露
Monitor Trap Flag**。

而两个 EPT 后端都把它列为硬前提：

| 位置 | 条件 | 不满足时 |
|---|---|---|
| `hvm_ept_view.c:626` | `INVEPT_SINGLE \| MONITOR_TRAP_FLAG` 必须全有 | 返回 `VIEW_STATUS_MULTIPROCESSOR_UNSAFE` + `STATUS_NOT_SUPPORTED` |
| `hvm_ept.c:1024` | 同上 | 直接 `return FALSE`（fail-closed） |
| `hvm_resident.c:1418` | 同上，否则 `LocalEptArmed` 恒为 FALSE | 私有层次不武装 |

实测中 `INVEPT_SINGLE` 是有的，**只缺 MTF**。

### 这条实测把本方案的性质改了

原本的定位是「性能优化：2N 次退出降到 1 次」。实测之后是：

> **在 Hyper-V 嵌套虚拟化里，现有的「写叶 + MTF」后端一个 hook 都装不上。
> EPTP 切换方案不需要 MTF，它是让 EPT hook 在这个环境下可用的唯一途径。**

顺带说明了为什么值得做：嵌套环境是开发和验证 EPT hook 最安全的地方（错了只是虚拟机蓝屏，
有检查点可回滚），而现在那条路在嵌套里是堵死的 —— 只能上真机试，代价高得多。

其余未置位的能力位也一并记录（共 20 项）：`VM_FUNCTIONS` / `EPTP_SWITCHING` /
`EPTP_LIST_READY` 都没有，所以第 4 节「不要用 VMFUNC」的结论在这个环境里**连选择权都没有**；
`EPT_VIOLATION_VE` / `VE_INFO_READY` 没有，与仓库既有的「#VE 这条路走不通」论证一致；
`SHADOW_EPT` / `NESTED_VMX_DISPATCH` / `NESTED_VMX_ACTIVE` / `VMX_INSTRUCTION_EMULATION`
没有（那些是 KSword 自己再嵌套一层 guest 用的，本任务不需要）；`HYPERV_EVMCS_ACTIVE`
没有而 `_CAPABLE`/`_V1` 有 —— 与 `KswordARKHvmEvmcsValidate` 刻意只报 PARTIAL 完全一致。

## 2. 三条被实测修正的认知

开工时我的假设是「MTF 要两次退出，改成切 EPTP 省一次」。读完代码后三条都要修正：

### 2.1 收益是 2N → 1，不是 2 → 1

MTF 退出会把叶**立刻**改回主值（`hvm_ept_view.c:764` 的恢复目标是 `PrimaryEntry`）。
所以**连续 N 次同类访问是 2N 次退出**，不是 2 次。切 EPTP 之后，连续 N 次同类访问只有
第一次退出，后面全部命中 —— 这才是主要收益。

放大这个收益的还有一件事：**本驱动没有启用 VPID**（`hvm_vmcs.c` 里没有任何 VPID 字段写入），
于是每次 VM exit/entry 都会刷 VPID 0 的线性映射。单次退出本身就比有 VPID 时贵，
省掉退出的边际收益因此更高。

### 2.2 私有层次不是要保住的东西，是变得多余的东西

我原本设想「每处理器两套私有 EPTP，同时拿到每核隔离与单次退出」。实际上：

**私有层次存在的唯一理由是运行期要写叶。** 切 EPTP 把那次写彻底去掉 —— 运行期只写自己
VMCS 的一个字段，不碰任何 EPT 表 —— 于是「一个处理器的翻转被别的处理器看见」这个危险
按构造消失，而隔离由 VMCS 字段本身提供（VMCS 本来就是每处理器一份）。

结果是次层次**可以被所有处理器共享**，内存代价从 O(处理器数) 掉到 O(1)：

| 拓扑 | 私有层次（今天） | 共享次层次 |
|---|---|---|
| 256 核 × 8 叶 | 5504 页 | **32 页** |

### 2.3 Hyper-reV 的两套层次不能直接照搬

它只有两套（全主值 / 全次值），因为它只有一组统一的 hook 状态。KSword 允许**同时安装多个
视图**，而 EPTP 是每处理器**一个**值 —— 处理器同一时刻只能在一套层次里。

用「全次值」那一套去服务某一页的读，会顺带把**其它 view 页**也换成次值：
一个从没被碰过的 CLOAK 页在这段时间里**对读者暴露影子内容**。那是语义改变，不是性能改变。

所以层次编号必须是 **1 + L**（索引 0 = 基座，全部主值；索引 k = 只有第 k−1 号叶取次值）。
代价可接受：一套次层次只有 4 页（根 + PDPT + PD + 叶表），因为一个叶只落在一个 PML4 槽、
一个 GiB 窗口里。

```
KSWORD_ARK_HVM_EPTP_PATH_PAGES = 4
次层次页数 = BaseCount × LeafCount × 4
```

共享基座模式下 `BaseCount = 1`，且基座本身新增零页 —— 它就是已经存在的共享恒等层次。

## 3. 不可表示的组合

层次数少于 2^L 时，一定存在「一条指令同时需要两个叶的次值」的组合：取指落在 HOOK 页、
操作数读落在 CLOAK 页；或者一个 CLOAK 代码页里的 RIP 相对数据引用。

这类组合**由前进性/环检测兜住并 fail-closed**，不是由单次决策拒绝 —— 决策函数一次只看一次
违规，每一半单独看都可服务。今天的 MTF 路径遇到同一情形也是 fail-closed（撞上 `Armed` →
强制 FALSE → devirtualize），所以不是新问题；但切 EPTP 会在另一些组合上多出一些 fail-closed
（跨两个 view 页的 REP 串操作、取指在 HOOK 页而读在 CLOAK 页）。

## 4. VMFUNC：明确不要用

**结论：一条也不要。** 不是「暂缓」或「v2 再说」，是这条路在本产品的威胁模型下方向就是反的。

先说事实：**本仓库已经实现了 VMFUNC / EPTP switching** —— `FEATURE_VM_FUNCTIONS`、
`FEATURE_EPTP_SWITCHING`、`FEATURE_EPTP_LIST_READY`，VMCS 侧 `hvm_vmcs.c:1057-1062` 写
`EPTP_LIST_ADDRESS 0x2024` 与 `VM_FUNCTION_CONTROLS 0x2018`，域后端在 `hvm_ept_domain.c`。
默认关闭，且 `KswordArkHvmIoctl.h:124-136` 已经把安全论证写死了：**VMFUNC 不做 CPL 检查**，
任何 ring-3 代码都能一条指令切到 list 里的任意一项，不产生退出、驱动完全不知情。
因此「list 里的域**永远不得**授予默认视图没有的权限」是一条安装期强制检查。

为什么 view 的次层次不能进这个 list：

1. **HOOK 的次层次是完全绕过原语。** 攻击者执行一条 `VMFUNC(0, 0)` 切回基座，跑的就是
   **未打补丁的原始代码**。一条指令、零退出、零证据。如果这个 hook 是安全检测手段，它就此报废。
2. **CLOAK 的次层次直接违反 list 的准入判据。** 它授予影子页 R|W，而基座对那一页是 `--x`；
   「域不得比默认视图更宽」这条检查会正确地拒绝它。
3. **没有人会去执行那条 VMFUNC。** 这里的 guest 是正在运行的 Windows 本身，它不会在合适的
   时机替我们切层次。让它切的唯一途径是 #VE，而本仓库已经论证过这条路走不通
   （`hvm_internal.h:101-113`、`KswordArkHvmIoctl.h:103-116`）：Windows 的 IDT[20] 是
   `KiVirtualizationException`，不认识我们造的 #VE；而且 suppress-#VE 的语义是反的，
   清掉它就是 `#GP → #DF → triple fault`。
4. **收益是零。** 宿主机侧 VMWRITE 方案已经把「N 次连续同类访问」降到 1 次退出。

## 5. 降级路径

分两个层级，不要混。

**层级一：能力不足 → 拒绝，不静默降级**（start / view add 时）。沿用 `ENABLE_LOCAL_EPT`
的先例：调用方要的是「每核隔离 + 单次退出」，给它一个悄悄退回 MTF 的东西，它会在多核机器上
按错误的前提安装 view。所以未请求该能力时走今天的 MTF 路径、**逐字节等价**；请求了但缺
`KSW_EPT_CAP_EXECUTE_ONLY` / `KSW_EPT_CAP_INVEPT_SINGLE` / 页预算不够 / 已装规则 /
与 `LOCAL_EPT|VMFUNC|NESTED_VMX` 同时请求 → **拒绝 start**，返回精确的状态码。

**层级二：单次违规不可表示 → 按今天的 fail-closed 走**（运行期）：publish telemetry →
`DeactivateCurrent(Faulted=TRUE)` → DEVIRTUALIZE。

> **这条降级路径同时就是拆除路径。** `DeactivateCurrent` 传 `InstructionLength=0`
> ⇒ RIP 不推进 ⇒ VMXOFF ⇒ 那条访问原地重执行、而本核已无 EPT ⇒ **读到真页**。
> 而"不可表示"的组合（取指落 HOOK 页、读操作数落 CLOAK 页）是**知道地址就能构造**的，
> 所以分离视图**不是安全边界**。这一点在两种后端下完全相同，与本文的选型无关。
> 已于 2026-09-06 定案为选项 A，理由、另外两条拆除配方、以及做成边界所需的前置链
> 见 `隐蔽Hook安全边界决策.md`。**接线时不要把层级二写成"拒绝"。**

## 6. 未解决的不确定处（如实记录）

1. **AD 位让「运行期零写」不严格成立**：基座 EPTP 在硬件支持时会开 accessed/dirty
   （`hvm_ept_builder.c:414-418`），硬件走表时会往叶里写 A/D。共享次层次被多处理器同时走时，
   A/D 写落在同一物理页上 —— 语义无害（原子置位、值相同），但会在那张叶表页上制造
   cache line 争用。**未量化。**
2. **EPT violation 的 qualification 能否同时报 read 与 execute** 未确认。若硬件报成两次各带
   一位的违规，环检测会先起作用，结局同样是 fail-closed。
3. **不可表示组合在真实 Windows 上的发生率**未测。
4. **长环上限 8 是拍的**（取指 + 三个内存操作数 = 4，留一倍余量）。x86 单条指令能产生的最大
   内存访问数未查确切上界。周期 1 / 周期 2 的精确判据不依赖它，风险有限。
5. **VMCS 重配路径的完整清单**：确认了 `ConfigureResidentVmcsFromAsm`（`hvm_resident.c:437-445`）
   是唯一选择每处理器 EPT 指针的地方、`hvm_vmcs.c:935` 是唯一写 `0x201A` 的地方；
   但 power transition / evmcs / nested 三条路径会不会在别处导致 VMCS 被 VMCLEAR/VMPTRLD 重载
   **未逐一确认**。
6. **硬件行为本身未验证**。宿主机测试只能证明我们按 SDM 编码了这些字段，
   不能证明这块硅片接受某个 EPTP，也不能证明 EP4TA 真的按预期隔离缓存。
   「切 EPTP 之后不需要 INVEPT」在这里是**被编码成可检查判据的论证，不是被实测的事实**。

## 7. 交付状态

**只做了纯算术与状态机的共享头 + 宿主机单测。驱动侧一行未改。**

- `shared/driver/KswordArkHvmEptSwitch.h` —— 位布局构造/校验、层次索引编码、切换决策状态机、
  INVEPT descriptor、页预算
- `KswordARKLightTests/HvmEptSwitchTests.cpp` —— 宿主机单测

真正的层次构建/复核/释放、`VMWRITE 0x201A`、INVEPT 指令发射、每 VCPU `ActiveEptpIndex` 与
VMCS 字段的一致性复位 —— 全是带副作用的驱动侧代码，**一行没写**。

独立对抗性评审：注入 30 条逻辑损坏，**11 条存活**（主要模式是架构常量只被符号化引用，
交换 `INVEPT_SINGLE/ALL` 的值、交换 A/D 位、挪 `IGNORE_PAT`/`USER_EXECUTE`/`CAP_EXECUTE_ONLY`
都能全过），另有 1 条真实 blocker（`EntryAddress` 掩码只清了 bits 11:0，没清 bit63 的
suppress-#VE）。评审确认**干净**的类别：位布局对照 SDM、CLOAK/HOOK 方向、状态机完备性与穷举、
测试期望值独立性、索引移位与掩码算术。修复进行中。
