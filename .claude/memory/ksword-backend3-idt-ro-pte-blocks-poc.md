---
name: ksword-backend3-idt-ro-pte-blocks-poc
description: Backend 3 "VTL0 kernel 直接写 IDT 建立 #DB trampoline" 在 Windows 11 26300 (24H2) **HVCI off / VBS off** 下就已经 BugCheck 0xBE。原因是 IDT 页 PTE bit1=0 (RO)，Windows 自己的 kernel memory hardening 把 IDT lock，不需要 HVCI 参与。SEH 挡不住 0xBE。推翻 workflow #3 实验的预期（它假设 HVCI off → 写 IDT success / PatchGuard 唯一 blocker）。
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

Workflow synthesis 给的 ranked path #1 "IDT remap + DR hardware breakpoints (signed driver, short-window probe)"，其核心前提 "write IDT[1] 到 driver 自己的 #DB trampoline" **在 Windows 11 26300 上结构性不可行**：

| 变体 | 可行性 |
|---|---|
| PASSIVE_LEVEL + CPU affinity + `RtlCopyMemory` 直写 | **死** (0xBE，本次实证) |
| DISPATCH_LEVEL + 同上 | 更糟，先 0xA (IRQL_NOT_LESS_OR_EQUAL) |
| `MmCopyMemory` with `MM_COPY_MEMORY_VIRTUAL` | 预期同 0xBE（相同 VA 写路径） |
| CR0.WP=0 临时禁用 + 写 + CR0.WP=1 | **死**（见 [[ksword-cet-breaks-cr0-wp-trick]]，CET 下老写法 0xA/0x1AA） |
| `MmMapIoSpaceEx(PFN, PAGE_READWRITE)` 别名 + 新 VA 写 | 未测，可能被 KDP 覆盖 PFN-level 保护；下一轮 PoC 候选 |
| 修改 IDT 页 PTE bit1=1 + 写 + 复原 | 未测，但 KDP/HVPT 覆盖页表修改路径，也可能 crash |
| VMX root (Backend 2) 写 EPT 别名 | **work 但是 Backend 2，与 HVCI 冲突** |

**唯一尚未排除的 VTL0 kernel 写 IDT 路径**：PFN remap 到 RW 别名（走 `MmMapIoSpaceEx` 或自建 MDL）。但 2025-11 Windows 11 KDP static set 可能已覆盖 IDT PFN，所以此路径的成功率存疑。

## How to apply

- 任何涉及 "VTL0 kernel driver 修改 IDT/GDT/SSDT/其它 Mi-protected kernel data" 的 feature 建议，**不能假设 HVCI off 就能直接 RtlCopyMemory 写**。Windows 11 24H2+ 已默认把这些页 PTE 标 RO。
- Backend 3 的 workflow 排名要降级：Rank 1 从 "research-only" 降 "reject"，除非后续 PFN remap 变体实验成功。
- 测试这类改动不能用 "SEH 包写 + 看捕没捕" 的套路 — 0xBE 挡不住，VM 直接 crash。改用离线签名验证 / 静态页表检查。
- 相关：[[ksword-vbs-hvci-kdp-hvpt-distinction]]（KDP 与 HVPT 各自保护面）、[[ksword-cet-breaks-cr0-wp-trick]]（CR0.WP 技巧在 CET 下爆）、[[ksword-rxpf-is-half-useless-without-shadow-idt]]（RXPF 影子 IDT 路线被 LIDT 拦截）。

## 证据链

- 驱动 build v2 hash `E9F4F2C3FE777AE6...`，含 PASSIVE_LEVEL + `KeSetSystemGroupAffinityThread` + `__try/__except` PoC 代码。
- QueryOnly 完整响应：`IdtLimit=0xFFF, IdtBase=0xFFFFF8000C1BD000, EntryLow=0x79CC8E0400107280, EntryHigh=0xFFFFF800, Completed=True, SehFired=False`。
- NoopWrite Vector=0x2F → BugCheck 0xBE，Arg1 对齐 IDT entry 边界，Arg2 PTE bit1=0。
- Minidump: `dev/backend3-dumps/111526-5937-01.dmp` (v2) + `111526-6140-01.dmp` (v1 DISPATCH_LEVEL)，均 bugcheck `0xBE`。
- PoC 代码：`KswordARKDriver/src/features/kernel_noattach_probe/`、`shared/driver/KswordArkKernelNoAttachProbeIoctl.h`、`tools/kernel_noattach_probe/{Test,Deploy}-Backend3Probe.ps1`。
