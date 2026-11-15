---
name: ksword-backend3-idt-ro-pte-blocks-poc
description: Backend 3 直接 RtlCopyMemory 写 IDT 在 26300 HVCI off 下立即 BugCheck 0xBE（PTE bit1=0）。但 **MDL + MmBuildMdlForNonPagedPool + MmMapLockedPagesSpecifyCache(MmCached, KernelMode) 建立的 alias VA 可写**，v3 实测 6/6 PASS。v4 实测 CPU 0 的 IDT[0x2F].IstAndType 从 0x8E00 flip 到 0x8F00（Type 0xE→0xF），**25+ 分钟未触发 PatchGuard，修改保持**；但每 CPU 有独立 IDT，其它核未受影响。
metadata:
  type: project
---

## PoC 实测结论

2026-11-15 Backend 3 PoC Stage A 实测，`26H2-11-Pro` Hyper-V VM，build 26300.x，**VBS=0 / HVCI=off / TestSigning=on**：

- **QueryOnly 读 IDT PASS**：`__sidt` + `RtlCopyMemory(&entry_copy, &IDT[vector], 16)` 在 PASSIVE_LEVEL + `KeSetSystemGroupAffinityThread` pin 当前 CPU 下 OK，`SehFired=False`。本次重启 IDT base = `0xFFFFF8000C1BD000`，IDT[1] handler = `0xFFFFF80079CC7280`（KiDebugTrapOrFault）。
- **NoopWrite 写 IDT FAIL**：同样 PASSIVE_LEVEL + CPU affinity + `__try/__except` 包裹的 `RtlCopyMemory(&IDT[0x2F], &original_16bytes, 16)` 写**原值**（no-op 内容），**立刻 BugCheck 0xBE** `ATTEMPTED_WRITE_TO_READONLY_MEMORY`。SEH 没触发。
- **两次独立 crash 两个 minidump 都是 0xBE**，证据链封闭（`dev/backend3-dumps/111526-{5937,6140}-01.dmp`）。

## 根因：IDT 页 PTE 就是 RO，与 HVCI 无关

Minidump 0xBE Arg 解码：
- `Arg1 = 0xFFFFD1816EBE32F0` = IDT[0x2F] 虚拟地址（IDT base + 0x2F × 16）
- **`Arg2 = 0x8A000001024D8121` = 该 VA 的 PTE 内容**：
  - bit 0 (Present) = 1
  - **bit 1 (R/W) = 0** ← 写保护
  - bit 2 (U/S) = 0 (supervisor)
  - top bit (NX) = 1
- `Arg4 = 0xB` (保留)

**PTE bit1=0 由 Windows 11 26300 kernel 自己的 memory hardening 施加**（Mi 或 KDP static set），不依赖 VBS/HVCI。实验时 `Win32_DeviceGuard.VirtualizationBasedSecurityStatus = 0`、`SecurityServicesRunning = 0`，HVCI 完全没跑。

## 推翻 workflow #3 的预期

Workflow `hvci-compat-noattach-debug-research` (run `wf_6cb063bc-79d`) 的 next_experiments 第 3 条原文：

> Verify HVCI's EPT coverage of KiInterruptDescriptorTable: use the driver to attempt a plain MmCopyMemory write to &KiInterruptDescriptorTable[1] under HVCI on. **Success means PatchGuard is the only blocker for Backend 3** (confirms Bitdefender HVMI's inference). Failure (EPT violation / 0x139) means Microsoft extended the EPT-RO set and Backend 3 needs to route the write through an alternate primitive before PatchGuard even becomes relevant.

实测结果：
- 不需要开 HVCI，**HVCI off 下写就 crash**
- crash 不是 EPT violation 或 0x139，是 0xBE PTE RO
- **PatchGuard 远不是唯一 blocker**：PTE 本身的 R/W=0 更底层

这把 Backend 3 "原地 RtlCopyMemory 写 IDT" 变体**从 go/no-go gate 直接判死**，HVCI 讨论都轮不到。

## SEH 挡不住 0xBE

即使在 PASSIVE_LEVEL + `__try/__except (EXCEPTION_EXECUTE_HANDLER)` 包裹，写 RO kernel 页触发的是 `BugCheck 0xBE` 而不是 `EXCEPTION_ACCESS_VIOLATION`。`KeBugCheckEx` 不走 SEH chain，`__try` 完全挡不住。

所以不能用"试着写 + SEH 捕异常"的探针模式验证 IDT 可写性 — 任何写入立即 crash，没有 "capture-and-report" 的第二次机会。

## 对 Backend 3 架构的影响

Workflow synthesis 给的 ranked path #1 "IDT remap + DR hardware breakpoints (signed driver, short-window probe)" 原路径（直接 RtlCopyMemory 写 IDT）**在 Windows 11 26300 上结构性不可行**，但 **MDL alias 变体打开新通路**：

| 变体 | 结果 | 实证 |
|---|---|---|
| PASSIVE_LEVEL + CPU affinity + `RtlCopyMemory` 直写 | **死** 0xBE | 两份 minidump (v1/v2) |
| DISPATCH_LEVEL + 同上 | 更糟，先 0xA (IRQL_NOT_LESS_OR_EQUAL) | v1 实证 |
| `MmCopyMemory` with `MM_COPY_MEMORY_VIRTUAL` | 预期同 0xBE | 未测，同 VA 路径 |
| CR0.WP=0 临时禁用 + 写 + CR0.WP=1 | **死** 0xA/0x1AA | 见 [[ksword-cet-breaks-cr0-wp-trick]] |
| **MDL + MmBuildMdlForNonPagedPool + MmMapLockedPagesSpecifyCache(MmCached, KernelMode) → alias 写** | **PASS** | v3 实证，6/6 稳定，3 分钟 PG 未触发 |
| `MmMapIoSpaceEx(PFN, PAGE_READWRITE)` 别名 | 未测，预期同 MDL 路径 | — |
| 修改 IDT 页 PTE bit1=1 + 写 + 复原 | 未测 | KDP/HVPT 可能覆盖 |
| VMX root (Backend 2) 写 EPT 别名 | 架构性和 HVCI 冲突 | 不考虑 |

## v3 MDL alias 实测细节 (2026-11-15)

Driver v3 hash `FDC900675B1E6A89...`，在同一 `26H2-11-Pro` VM `VBS=0 / HVCI=off / TestSigning=on` 环境：

- **Vector=1 (#DB entry) AliasWrite**：`AliasVa=0xFFFF9080C5377010`, `StatusFlags=0x5` (COMPLETED | READBACK_MATCH), `SehFired=False`, IDT[1] handler = `0xFFFFF803CFEC7280` (KiDebugTrapOrFault)。
- **Vector=0x2F × 5 次 round AliasWrite**：每次 AliasVa 不同（MDL 每次分配新 kernel VA 范围 `0xFFFF9080C5xxx2F0` ~ `0xFFFF9080C67E22F0`），全部 `StatusFlags=0x5`, `SehFired=False`。
- **稳定性**：no-op 写（写回原值）6 轮无一例 crash。
- **PatchGuard 观察**：写完后 180s wall-clock，VM 存活（uptime=278s）。因为内容没变，PG 的 IDT content checksum 看到的还是原值。

## 关于 PatchGuard 对真实 handler 修改的预期

**No-op 写**（本次测）PG 不触发，因为 PG 比对的是内容 checksum。

**真实修改**（Backend 3 产品路径要改 handler offset 指到 driver .text trampoline）：内容会变，PG 读到新 checksum 触发 `0x109 (CRITICAL_STRUCTURE_CORRUPTION)`。节奏是分钟级（Tetrane RS4 分析 + 2026-era PatchGuard 写入）。这是**唯一** 剩下的 blocker，workflow 对 "短窗口探针 (seconds to a few minutes)" 的定位**现在真实可操作**。

## 推翻 workflow #3 的原假设

Workflow `hvci-compat-noattach-debug-research` (run `wf_6cb063bc-79d`) 的 next_experiments 第 3 条原文：

> Verify HVCI's EPT coverage of KiInterruptDescriptorTable: use the driver to attempt a plain MmCopyMemory write to &KiInterruptDescriptorTable[1] under HVCI on. **Success means PatchGuard is the only blocker for Backend 3** (confirms Bitdefender HVMI's inference). Failure (EPT violation / 0x139) means Microsoft extended the EPT-RO set and Backend 3 needs to route the write through an alternate primitive before PatchGuard even becomes relevant.

Workflow 把 "plain write" 当成单一动作，没区分直接 VA 写和 alias 写。实测细化为：

- **直接 VA RtlCopyMemory/MmCopyMemory (VA 路径)**：**HVCI off 就死** (0xBE PTE RO)，不需要开 HVCI，KDP/HVCI 甚至不参与。
- **MDL alias 写 (PFN 路径)**：**HVCI off 下 PASS**，PatchGuard **是** 唯一 blocker（node 内容修改时）。

所以 workflow 原假设 "Success means PatchGuard is the only blocker" 对 **alias 路径** 成立，对 **VA 直写** 不成立。

## How to apply

- 任何涉及 "VTL0 kernel driver 修改 IDT/GDT/SSDT/其它 Mi-protected kernel data" 的 feature 建议，**不能**假设 HVCI off 就能直接 RtlCopyMemory 写。Windows 11 24H2+ 已默认把这些页 PTE 标 RO。**要走 MDL alias**（`IoAllocateMdl` + `MmBuildMdlForNonPagedPool` + `MmMapLockedPagesSpecifyCache(MmCached, KernelMode)`），alias VA 是独立 PTE 默认 RW。
- Backend 3 的 workflow rank 1 **不降级**：MDL alias 路径打开了可行性。剩下的 blocker 是 PatchGuard IDT checksum。产品定位 "signed driver short-window probe" 真实可操作。
- 下一轮 PoC（workflow next_experiment #2 升级版）：用 MDL alias 把 IDT[0x2F] 的某字节改 1（必非 no-op），定时器每秒读回，记录 install 到 PG 0x109 的 wall-clock。决定短窗口窗口期。
- 测试直写路径不能用 "SEH 包写 + 看捕没捕" 的套路 — 0xBE 挡不住，VM 直接 crash。MDL alias 下 SEH 可用（本次 __try 成功捕所有错误场景）。
- 相关：[[ksword-vbs-hvci-kdp-hvpt-distinction]]（KDP 与 HVPT 各自保护面）、[[ksword-cet-breaks-cr0-wp-trick]]（CR0.WP 技巧在 CET 下爆）、[[ksword-rxpf-is-half-useless-without-shadow-idt]]（RXPF 影子 IDT 路线被 LIDT 拦截）。

## 证据链

### 直写变体（v1/v2，blocked by 0xBE）
- 驱动 build v2 hash `E9F4F2C3FE777AE6...`，含 PASSIVE_LEVEL + `KeSetSystemGroupAffinityThread` + `__try/__except` PoC 代码。
- QueryOnly 完整响应：`IdtLimit=0xFFF, IdtBase=0xFFFFF8000C1BD000, EntryLow=0x79CC8E0400107280, EntryHigh=0xFFFFF800, Completed=True, SehFired=False`。
- NoopWrite Vector=0x2F → BugCheck 0xBE，Arg1 对齐 IDT entry 边界，Arg2 PTE bit1=0。
- Minidump: `dev/backend3-dumps/111526-5937-01.dmp` (v2) + `111526-6140-01.dmp` (v1 DISPATCH_LEVEL)，均 bugcheck `0xBE`。

### MDL alias 变体（v3，PASS）
- 驱动 build v3 hash `FDC900675B1E6A89...`，含 `KnapProbeAliasWrite` 实现。
- AliasWrite Vector=1：`AliasVa=0xFFFF9080C5377010`, StatusFlags=0x5 (COMPLETED|READBACK_MATCH), SehFired=False。
- AliasWrite Vector=0x2F × 5 轮：每次 AliasVa 新（0xFFFF9080C5xx～0xFFFF9080C67E 范围），全部 PASS。
- 3 分钟后 VM 存活 uptime=278s，PG 对 no-op 写不敏感。

### PoC 代码
- `KswordARKDriver/src/features/kernel_noattach_probe/kernel_noattach_probe.c`：核心 KnapReadIdtAndEntry / KnapProbeNoopWrite / KnapProbeAliasWrite / KnapProbeChecksumTrip。
- `shared/driver/KswordArkKernelNoAttachProbeIoctl.h`：IOCTL 0x940，四个 op (QUERY_IDT / PROBE_IDT_NOOP_WRITE / STATUS / PROBE_IDT_ALIAS_WRITE / PROBE_IDT_CHECKSUM_TRIP)。
- `tools/kernel_noattach_probe/{Test,Deploy}-Backend3Probe.ps1`：R3 测试 + VM 部署脚本。

## v4 Trip 实测 (2026-11-15)

Driver v4 hash `077BCCA38A64E63F...`，加入 `KnapProbeChecksumTrip`：`IstAndType ^= 0x0100` 把 Type 0xE (Interrupt Gate) flip 到 0xF (Trap Gate)。Vector=0x2F (APIC Spurious)。

**单核 Trip 后 25+ 分钟未触发 PatchGuard**：
- **install_walltime** = 2026-11-15T15:44:59-05:00，Trip IOCTL 返回 `StatusFlags=0x5` (COMPLETED | READBACK_MATCH)，`ReadbackLow=0xB5CC8F0000102C80`（原 `0xB5CC8E0000102C80`），`AliasVa=0xFFFFD08134F292F0`。
- **monitor loop** 轮询 Get-VM `HeartBeat/Uptime` 每 2s，`MonitorTimeoutSec=1500`。实测 1502.1s（25 分钟）内 VM 持续 `State=Running`, `HeartBeat=OkApplicationsUnknown`，Uptime 单调递增，无 BugCheck。
- **Deploy 脚本 bug**：PS Remoting 把 `ServiceControllerStatus` enum 反序列化成 int（4），`"$($state)" -ne 'Running'` 永远真。第一次 harness 跑 25 分钟其实根本没发 Trip 就 throw 了（但 `sc start` 成功，所以 driver 已启）。修法是让 VM 侧提前 `.ToString()` 并返回 bool。第二次 harness 直接 Invoke-Command 把 Test-Backend3Probe 的 Trip body 投到已加载 driver 上。

**per-CPU IDT 的关键发现**：
- Hyper-V VM 4 vCPU，4 个独立 IDT base：
  - CPU 0: `0xFFFFF800481DD000`（高低不同的 region，疑似 BSP boot-time 分配）
  - CPU 1: `0xFFFFD0812FFE3000`
  - CPU 2: `0xFFFFD08130060000`
  - CPU 3: `0xFFFFD081300AD000`
- Trip IOCTL 恰好由 CPU 0 的线程处理 → **只改到 CPU 0 的 IDT**；CPUs 1-3 保持原 `EntryLow=0xB5CC8E...`。
- Trip 25 分钟后用 ProcessorAffinity 把 QueryOnly 轮流打到四个核：CPU 0 仍显示 `0xB5CC8F...`（trip 保持），CPUs 1-3 显示 `0xB5CC8E...`（未改）。
- **判据差点被 per-CPU IDT 骗翻**：第一次 QueryOnly 刚好打在某非 CPU 0 的核，看到原值，一度以为 "IDT 被静默 restore"。得 per-CPU 遍历才证伪。

**解读**：
- 修改**保持 25+ 分钟**，不是被某种自愈机制复原；只是查询时读错了 CPU。
- PG 对 vector 0x2F 的 IstAndType flip 在当前 window 内**未触发 0x109**。可能原因（未落地证据，列出不作决策）：PG IDT 覆盖范围不含 vector 0x2F / 不含 IstAndType.Type 字段 / 检查 cadence 远超 25 分钟 / 只覆盖 CPU N 的 IDT 而我们改的恰好是 CPU 0 以外。
- Backend 3 任何依赖 "把所有调用捕到探针 handler" 的产品路径都要**同时改所有 CPU 的 IDT**，因此 IOCTL 需要能 broadcast (`KeGenericCallDpc` 或 affinity 遍历) 而不是只打当前核。

## How to apply（追加）

- MDL alias 写在 "VBS=0 / HVCI=off / TestSigning=on" 签名驱动下**结构性可行**：trip 25+ 分钟保持，PG 未触发（vector 0x2F / IstAndType flip 这个特定组合，不代表其它字段/向量 PG 也不覆盖）。
- 任何 "改 IDT 做拦截" 的 PoC 下一步必须 broadcast 到所有 CPU，然后多核同步 verify。单核 trip 的 "25 分钟未触发" 不能推广到多核 trip。
- PS Remoting 的 enum 反序列化：host 侧 `$obj.EnumField -eq 'Name'` 对任何 ServiceControllerStatus / ProcessPriorityClass 等 enum 恒失败（返回 int），必须在 VM 侧完成字符串化再回传。
