# HVM 常驻生命周期保护

2026-10-01：准入门与 GUI 已统一为 Intel/AMD 分支，以下电源与返回链细节仍以 Intel 历史基线为主。AMD 实验实现和未完成的硬件验收见 [AMD 实验续接](ksword-hvm-amd-lab.md)；不能把 Intel 历史运行证据用于 AMD。

## 能力发布原则

`START_RESIDENT` 不是 UI 布尔开关。只有 `KswordARKHvmEnableResidentLifecycle` 在 `WdfDriverCreate` 之后成功捕获 KMDF 最终 `DriverUnload`，并完成电源与 processor-change 回调注册，才能同时发布：

- `KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM`
- `KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS`
- `KSWORD_ARK_HVM_FEATURE_EPT_RULES`（仅 Intel）
- `KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED`

注册失败只关闭常驻 HVM，不能让整个 KswordARK 驱动加载失败。`capability-only` 表示保护链可用但尚未进入 VMX non-root；只有完整全 CPU rendezvous 成功才标记 `active`。

## Intel/AMD 硬件门与嵌套发布

生命周期注册按已识别后端检查硬件条件，未知后端继续拒绝。Intel 的条件为：

- VMX 与已锁定的 `IA32_FEATURE_CONTROL`；
- VMX outside SMX；
- EPT、WB、四级 walk、2 MiB leaf；
- INVEPT 与 single-context INVEPT；
- 外层 Hypervisor 必须通过现有嵌套硬件准入，并显式允许作为来宾运行；偏好不能绕过 Hyper-V/VBS 拒绝；
- 准备数、自检通过数、活动 CPU 数和每 CPU `RESOURCE_READY | SELF_TESTED | VMXON_SUCCEEDED` 必须完全一致；
- EPT 不得为 `EPT_TRUNCATED`。

AMD 检查 AMD/SVM/NPT/NRIP、ASID >= 2、完整 MSR 证据与 `rejectReason=NONE`；仍保留全核自检、电源、拓扑、卸载、回滚和状态准入。AMD 外层仅接受显式允许的 `VMwareVMware`，未知外层及 Hyper-V/VBS 继续拒绝。GUI 的共同准入与请求过滤在 `shared/driver/KswordArkHvmRequest.h`，标题栏、Dock 控制页和证据页通过 `KvmState` 读取同一判定。

共享查询协议布局与版本未变，featureFlags 新增 bit 54..58：`NESTED_SVM_DISPATCH`、`NESTED_SVM_PREPARED`、`NESTED_SVM_ARMED`、`NESTED_VMX_ARMED`、`HYPERVISOR_IDENTITY_HIDDEN`。支持、资源模式、全核运行证据分别发布；未支持这些位的旧 AMD 驱动不能开放来宾嵌套。AMD PREPARE/START_RESIDENT 发送 `ENABLE_NESTED_SVM`，SELF_TEST 使用已准备模式；Intel 偏好在 AMD 上保留但过滤出请求。准备模式与请求不同，要求明确停止、释放、重新准备，不能自动替换资源。

Intel 已有 vmcs12、退出反射和影子 EPT 路径，不能再用“Nested 一律不运行 L2”的早期描述。`NESTED_VMX_ARMED` 表示全核派发已武装，独立于瞬时 L2 状态；AMD 的实际武装也不提升实验成熟度或证明内层 OS 启动。eVMCS 仍没有 VP-assist/clean-field 接管，能力检查不能解释为 active。

## 电源、拓扑与卸载互锁

- 使用系统 `\Callback\PowerState` 的 `PO_CB_SYSTEM_STATE_LOCK`。`Argument2=FALSE` 时先置位 `POWER_TRANSITION_PENDING`，再同步执行全核 VMXOFF；只有 `Argument2=TRUE`、resident count 为零且无 `ROLLBACK_REQUIRED` 时才解除门闩。恢复时必须清除睡眠前的逐 CPU self-test/VMXON 成功证据，要求重新 self-test 后才能再次启动。
- resident start/stop、self-test、one-shot guest 与电源回调共用原子 transition phase。`ResidentTransitionStateLock` 只保护 phase 位和预初始化 idle event 的短提交，绝不能跨 `KeIpiGenericCall`、VMXON/VMXOFF 或回滚持有。`IRQL <= APC_LEVEL` 的竞争者等待 event；系统定义回调可能位于 `DISPATCH_LEVEL`，此时不得等待或轮询被抢占的 phase owner，而要返回 busy。离开 S0 的回调遇到 busy 必须按 HVM 生命周期故障直接 bugcheck fail closed，避免瞬态 VMX 窗口跨越电源边界。电源回调仍先原子置 pending，再取得 phase；正常可等待路径中，正在提交的 start 会看到 pending 并立即回滚，回调返回前系统中不保留 resident VCPU。
- host stack 分配调用动态 nonpaged-pool 解析路径，必须留在 `PASSIVE_LEVEL`，并在 transition phase 之外完成。分配前置 `ResidentContextPreparing`；电源回调撞上该阶段只置 pending 且不释放上下文。内部 pending 值 `2` 表示系统已回到 S0、但仍等待 in-flight HVM 控制收尾；该控制不得继续 VMX entry，清除 `BUSY` 后由统一 helper 失效睡眠前证据并重新开门。
- pending 可能在一次完整睡眠周期后重新变成零，因此自检、one-shot guest 和 resident start 还要捕获 `PowerTransitionGeneration`；真正 VMXON 或最终发布时代次不一致即按 power-transition blocked 退出，禁止拼接睡眠前后的逐 CPU 成功证据。
- self-test 与 one-shot guest 在取得 transition phase 后单独提升到 `DISPATCH_LEVEL`，仅用于固定当前逻辑处理器上的短 VMX root 窗口；phase 互斥本身不得依赖这个 IRQL 提升，清理 VMX/CR4 后先释放 phase，再恢复原 IRQL 和线程 affinity。
- `KeRegisterProcessorChangeCallback` 在资源准备、自检、start/active/stop 期间拒绝 `KeProcessorAddStartNotify`。仅当传入的 `OperationStatus` 仍为成功时才写入错误，不能覆盖其它 callback 的失败。
- 进入 resident 前只把捕获到的精确 `DriverObject->DriverUnload` 原子替换为 `NULL`；完整 VMXOFF 且槽位仍由本保护拥有时才恢复。若发现第三方/异常指针，不覆盖它并报告 lifecycle guard failure。
- 电源转换导致的停止会把 unload guard 保持到重新进入 S0，避免回调仍在执行时并发卸载。停止不完整必须保留 host stack、卸载锁和 `ROLLBACK_REQUIRED`。
- 电源回调或异常卸载完成同步 Stop 后若 resident count 仍非零，不能返回到睡眠/映像卸载路径；离开 S0 的 DISPATCH-level 回调若无法取得 transition phase 也不能等待。两类路径都使用既有 HVM `0x20001` bugcheck fail closed，并把 power/unload 签名、resident count（phase 冲突时可为零）、NTSTATUS 与 state flags 写入参数。

## VMCS 扩展状态与 CET 返回链

- 共享 VMCS builder 同时服务 one-shot 与 resident；任何新增的 VM-entry/VM-exit 状态切换都必须在两条 VMXOFF 路径成对恢复。resident 必须在 `VMCLEAR` 前保存 guest CET/SSP、PKRS、UINV、DEBUGCTL/DR7 等由 VM-exit 加载或清除的状态，非 CET MSR 在 VMXOFF 后恢复，CET/SSP 与调试状态留到最终汇编 continuation 恢复。
- resident 的初始 SSP 只能在所有 VMCS 配置调用都返回、紧邻最终 `VMLAUNCH` 时由汇编捕获，再回写 guest-SSP VMCS 字段；不能在嵌套 C builder 中按固定 CALL 深度推导。
- CET shadow stack 开启时，反虚拟化汇编使用普通栈上的 synthetic `RET` 跳到 guest RIP，就必须在 `GuestSsp-8` 写入同一 synthetic shadow return，并通过 `GuestSsp-16` 的 restore token 让该 RET 只消费临时槽位；完成后 SSP 回到原始 `GuestSsp`，不得丢掉 guest 原有调用链顶层返回地址。

## 验证边界

macOS 上的 JSON、i18n、IOCTL registry、位值唯一性和源码静态检查不证明 WDK/MSVC 编译或真实 Intel 多核 VMX、电源转换、Processor Group、Hyper-V/VBS 冲突和 SCM unload 行为。最终验收必须在 Windows Intel 机器上完成驱动构建、加载、prepare/self-test/start/stop、睡眠/Modern Standby（设备支持时）、CPU 拓扑策略和卸载恢复测试。

## 2026-11-13 用户态 native-return 边界

- 指定 26H2-11-Pro、ntoskrnl 26100.9974 的独立 HVM 首轮测试产生 7F/8。匹配本轮驱动 PDB 的小转储显示 CPL0 在 `hvm_entry.asm` 把 RSP 切为 `0000002B F0EEF758` 后，首次 `push r10` 触发故障；不能把这条内核栈 RET 路径宣称为任意 CPL3 返回已验证。CDB 的 ntoskrnl 缺符号提示不作为根因证据。
- 独立 NoAttach `NaFail` 已改为先恢复 TF/临时控制和普通 EPT 根，撤销执行发布、保留引用与 VMX 资源，等待控制面在内核 IPI/VMCALL 边界 Close；恢复不了体系结构字段则保留致命错误。此修改不等于其它通用 fault-stop 来源的所有用户态 VMXOFF 路径均已整改。
- 无 MTF 的来宾现在可使用明确的 VMX TF/#DB 备用边界：只读代码、保守指令类别、异常/IRQ 投递前退休 TF、同一指令有界 IRQ 重试，RF 从停止身份比较中单独排除。MTF 路径保留并优先，不能把 VMX TF 验收写成物理 MTF 验收。
- 最终 0BEDB0407F525BBF9FBEB16C4CFDC639FCB12E687FEB53CE37808C2DA76B7C60 候选完成 CE/Titan HVM 各 48、停点中 Close 26、普通后端后再开 HVM 48 项；最后 processors=0/0，所有测试目标退出 0。119 项生产 VMCS 夹具覆盖 RF/IRQ/资源保留等回归；准确记录见 `docs/无附加调试执行后端.md`。
- 本用户禁止创建检查点。验收后已恢复 Secure Boot、VBS/HVCI 运行与原 BCD，删除仅本任务服务/暂存；VM Off、启动 4 GB、nested False、Checkpoint Disabled/Automatic False/Count 0，宿主安全设置未变。
