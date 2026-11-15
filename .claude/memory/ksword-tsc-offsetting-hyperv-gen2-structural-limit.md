---
name: ksword-tsc-offsetting-hyperv-gen2-structural-limit
description: 在 Hyper-V Gen2 来宾里 TSC_OFFSETTING 结构性无法消除 CPUID+RDTSC timing fingerprint。本机无 HPET（Gen2 不暴露）、Hyper-V 参考 TSC 页会周期重写撕开累积偏置、CPL=3 可直接读共享参考页旁路驱动。接受这个边界。
metadata:
  type: feedback
---

**在 Hyper-V Gen2 来宾作为 L1 hypervisor 跑的 KSword 上，不要再试图用 TSC_OFFSETTING 消除 `rdtsc()+cpuid()+rdtsc()` 的 timing fingerprint。**

## 关键事实（本会话 Workflow wf_8214871c-a5c 三份并行调研确认）

1. **本机没有 HPET**。Hyper-V Gen2 Guest 明确不暴露 HPET/legacy PIT。花时间调研 `HalpTimerDriftCorrection` 对比 HPET 的问题方向错了。该函数名在 ntoskrnl 26100.9022 **不存在**，真正的 Windows 多核 TSC sync 走 `HalpTsc*`，单 vCPU 不触发。
2. **真正的交叉核验预言机是 Hyper-V 参考 TSC 页** + `HV_X64_MSR_TIME_REF_COUNT`。KSword 自己的 `system_time_hyperv.c` 已在用这个页做 10ms 容差比对；页以 `SystemHypervisorSharedPageInformation` (class 197) 暴露给 CPL=3。**用户态 detector 可直接读共享页**，完全绕过驱动 CPUID/RDTSC 拦截。
3. **数字自相矛盾**：10K cycles 总预算仅够掩盖一次 CPUID exit (~15K cycles)。detect_probe 每秒 ~100K 次迭代 × 每次 ~15K cycles = 需累积几 billion cycles bias，远超 Hyper-V 参考页周期重写容忍度。页被 `HalpTimerPropagateQpcBiasUpdate` 回调观察到会产生**可见时间台阶**（不是平滑漂移）。
4. **跨线程 race detector 结构性无解**。momo5502 式两线程 "counter race" 可绕过任何单线程 TSC offset。项目自己在 `docs/虚拟化规范要点.md:576` 已经写过 "RDTSC 可虚拟化补偿，但跨线程竞速...很难掩盖"。

## 本机实测基线（commit 252361248 CPUID cache + 90ca1e0ec HIDE_HV）

N=30 detect_probe during HVM session active:
- rdtsc_cpuid_timing avg_cycles: **min 7985, P50 8842, P95 15319, max 18302**
- **30/30 全部 > 1000 cycles threshold** → detected=true
- detected count 固定 1/17 (剩余唯一 fingerprint = timing)

结论：当前软件栈下此 fingerprint 不能消除。要让 timing <1000 cycles 必须让 CPUID 不经 VM-exit — 架构上意味着 KSword 必须不激活 HVM，但那就没有 KSword 的意义。

## 另一张否决票

未查 bug [[ksword-l1-clock-runs-fast-todo]]：常驻开启时 L1 Windows 20 分钟跑成 5 小时 18 分（15.9× 漂移）。候选根因之一是 "IDT-vectoring 补投多投时钟中断"。在此 bug 定因前加负 TSC 偏置可能**掩盖**真正的中断过投而不是修它。

## 允许哪些做法

- **CPUID cache**（已 land, commit 252361248）: 对 CPUID-dense workloads defense-in-depth，不消除 detect_probe fingerprint 但减少 L0 exit count
- **HIDE_HYPERVISOR flag**（已 land, commit 90ca1e0ec）: 消除 CPUID 内容 fingerprint (hv31+vendor+interface)，不消除 timing
- **在 bare metal 或 VMware 下跑**：Hyper-V 参考 TSC 页问题就不存在，TSC_OFFSETTING 可能可行
- **ENABLE_HVM 以外的低开销后端**（如 Kernel no-attach via DR+TF）：没有 CPUID VM-exit round-trip 所以没有 timing fingerprint；代价是其他能力限制

## 禁止的做法

- 在 Hyper-V Gen2 来宾下做 USE_TSC_OFFSETTING + VMCS TSC_OFFSET 累积偏置 — Hyper-V 参考页重写会撕开
- 假设可以拦截 HPET MMIO 在 0xFED00000 — Hyper-V Gen2 根本没有这个 BAR
- 做 CPUID exit-cost-based-bias 更新 — 几秒内累积会越过 Hyper-V 参考页 drift 容限

## 下一步（后续 session 可选）

如果用户仍坚持试 TSC_OFFSETTING，先做 verification 四条（synthesis 要求的，全部零代码）：

1. 关 VMware 单独复现 15.9× 漂移，用 `L2TimerArmCount`/`L2EoiMmioCount`/`L2EoiMsrCount` 除以墙上时间判中断原因
2. **已完成**: 本记忆的 N=30 统计
3. 内核态循环读 class=197 共享页 60 秒，测 Hyper-V 重写 `QpcMultiplier`/`QpcBias` 真实节奏
4. 项目离线 PDB 流程 (ksword-no-online-symbols) 反汇编 26100.9022 `HalpTimerCalculateMaximumAllowableDrift` / `HalpTimerPropagateQpcBiasUpdate` / `HalpTscFallbackToPlatformSource`，抽阈值常数

只有 (1) 排除中断过投、(3) 证明时窗足够、(4) 给出可量化上界后才可考虑 minimal TSC_OFFSETTING。即便如此也只能骗单线程 detector。
