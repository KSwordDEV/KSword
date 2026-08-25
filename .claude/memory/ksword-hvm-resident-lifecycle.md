# HVM 常驻生命周期保护

## 能力发布原则

`START_RESIDENT` 不是 UI 布尔开关。只有 `KswordARKHvmEnableResidentLifecycle` 在 `WdfDriverCreate` 之后成功捕获 KMDF 最终 `DriverUnload`，并完成电源与 processor-change 回调注册，才能同时发布：

- `KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM`
- `KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS`
- `KSWORD_ARK_HVM_FEATURE_EPT_RULES`
- `KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED`

注册失败只关闭常驻 HVM，不能让整个 KswordARK 驱动加载失败。`capability-only` 表示保护链可用但尚未进入 VMX non-root；只有完整全 CPU rendezvous 成功才标记 `active`。

## Intel-only 与硬件门

常驻启动必须精确匹配 `GenuineIntel`。AMD 与其它 CPU vendor 在 `KswordARKHvmReadCapabilities` 返回 unsupported，不得由 UI、确认偏好或控制 flag 绕过。还必须满足：

- VMX 与已锁定的 `IA32_FEATURE_CONTROL`；
- VMX outside SMX；
- EPT、WB、四级 walk、2 MiB leaf；
- INVEPT 与 single-context INVEPT；
- CPUID 不得报告已有 Hypervisor；
- 准备数、自检通过数、活动 CPU 数和每 CPU `RESOURCE_READY | SELF_TESTED | VMXON_SUCCEEDED` 必须完全一致；
- EPT 不得为 `EPT_TRUNCATED`。

Nested VMX/eVMCS 的 partial 状态不是隐藏锁。未实现完整 vmcs02、L2 exit reflection、shadow EPT 和 VP-assist/clean-field 所有权时，验证入口可以开放，但不得显示 active 或宣称可运行 L2。

## 电源、拓扑与卸载互锁

- 使用系统 `\Callback\PowerState` 的 `PO_CB_SYSTEM_STATE_LOCK`。`Argument2=FALSE` 时先置位 `POWER_TRANSITION_PENDING`，再同步执行全核 VMXOFF；只有 `Argument2=TRUE`、resident count 为零且无 `ROLLBACK_REQUIRED` 时才解除门闩。恢复时必须清除睡眠前的逐 CPU self-test/VMXON 成功证据，要求重新 self-test 后才能再次启动。
- resident start/stop 与电源回调共用 `ResidentTransitionLock`。电源回调先原子置 pending，再等待 transition spin gate；这样正在提交的 start 会看到 pending 并立即回滚，回调返回前系统中不保留 resident VCPU。
- host stack 分配调用动态 nonpaged-pool 解析路径，必须留在 `PASSIVE_LEVEL`，不能包在 transition spin lock 中。分配前置 `ResidentContextPreparing`；电源回调撞上该阶段只置 pending 且不释放上下文。内部 pending 值 `2` 表示系统已回到 S0、但仍等待 in-flight HVM 控制收尾；该控制不得继续 VMX entry，清除 `BUSY` 后由统一 helper 失效睡眠前证据并重新开门。
- pending 可能在一次完整睡眠周期后重新变成零，因此自检、one-shot guest 和 resident start 还要捕获 `PowerTransitionGeneration`；真正 VMXON 或最终发布时代次不一致即按 power-transition blocked 退出，禁止拼接睡眠前后的逐 CPU 成功证据。
- `KeRegisterProcessorChangeCallback` 在资源准备、自检、start/active/stop 期间拒绝 `KeProcessorAddStartNotify`。仅当传入的 `OperationStatus` 仍为成功时才写入错误，不能覆盖其它 callback 的失败。
- 进入 resident 前只把捕获到的精确 `DriverObject->DriverUnload` 原子替换为 `NULL`；完整 VMXOFF 且槽位仍由本保护拥有时才恢复。若发现第三方/异常指针，不覆盖它并报告 lifecycle guard failure。
- 电源转换导致的停止会把 unload guard 保持到重新进入 S0，避免回调仍在执行时并发卸载。停止不完整必须保留 host stack、卸载锁和 `ROLLBACK_REQUIRED`。
- 电源回调或异常卸载完成同步 Stop 后若 resident count 仍非零，不能返回到睡眠/映像卸载路径；使用既有 HVM `0x20001` bugcheck fail closed，并把 power/unload 签名、resident count、NTSTATUS 与 state flags 写入参数。

## 验证边界

macOS 上的 JSON、i18n、IOCTL registry、位值唯一性和源码静态检查不证明 WDK/MSVC 编译或真实 Intel 多核 VMX、电源转换、Processor Group、Hyper-V/VBS 冲突和 SCM unload 行为。最终验收必须在 Windows Intel 机器上完成驱动构建、加载、prepare/self-test/start/stop、睡眠/Modern Standby（设备支持时）、CPU 拓扑策略和卸载恢复测试。
