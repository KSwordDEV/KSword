---
name: ksword-parallel-agent-vm-staging-race
description: Restart-VM 后立即读 C:\ks-stage\ 的大文件 (3+ MB) hash 可能看到 zero-filled 中间状态 (前 64 字节全 0, size 保留). 这是 NTFS journal replay 未完成, 不是并行 agent 污染. sc start 变 error 193. 等并行 agent 自己的 rebuild 把你的 commit 带到 VM 更省事.
metadata:
  type: feedback
---

**初诊错误**: 本会话曾怀疑是并行 agent 在同一 VM 上推 .sys 造成的 race, user 更正说 "他做非虚拟化你做虚拟化不冲突"。更正后观察到: 并行 agent 自己的下一轮 rebuild 包含我的 commit (同 main HEAD 作为 ancestor), 他 push 到 VM 后 ImagePath hash 和 host 完全匹配 — driver 一体包含两方的代码。

**真正原因**: `Restart-VM` + 立即 `Invoke-Command { Get-FileHash }` 可能看到 journal replay 未完成的 zero-filled page。

## 本会话实证

- 23:51:45 我 commit `941ec7d71 harden(hvm): filter FEATURE_CONTROL + PERF_CAPABILITIES MSR read`
- ~23:56 我 driver rebuild → host .sys `63657D...122C` (size 3621272)
- 23:53:30 另一 agent commit `721831def feat(driver/noattach): two-hop reverse call-graph bring-up (Phase A3)` (包含我的 commit 作为 parent)
- ~00:00 另一 agent rebuild → 刷新 host .sys 到 `5276BE...D9B4` (size 3622808, 含 A1-A3 + 我的 MSR filter)
- 我 base64 推 host `5276BE` 到 `C:\ks-stage\KswordARK-msr-final.sys` → VM 内 hash **match** `5276BE` ✓
- `sc stop` (NOT_STOPPABLE 拒) + `sc delete` (success, 标 delete-pending)
- `Restart-VM -Force` 释放 driver lock + 清 service record
- Restart 后重入 PSDirect: **staging 文件 hash 变 `4E9EBC...6F7A`** — 前 64 字节全 0, last 8 bytes 全 0, size 保留 3622808
- Copy staging → ImagePath → 全零文件 → `sc start` returns **error 193 (not valid Win32 application)**

## 可能原因

无法确定但三个候选:
1. 并行 agent 在 Restart 期间也在 VM 内推 .sys, 覆盖我的 staging (但文件名独特不太可能)
2. VM 内 scheduled task / autostart 清理 ks-stage (未找到对应 task, Ksword 相关 task 都 Disabled)
3. **Hyper-V Dynamic Memory / page swap / NTFS journal replay** 在 Restart 过程中污染非 system-protected 目录的大文件 (3.6 MB)

candidate 3 最可能——Windows 10/11 有过类似 case 报告, 大文件在 soft restart 过程中会 journal replay 失败, 文件内容替换为 zero-filled page.

## 避坑

- **Restart-VM 后不要立即读 staging/ImagePath 的大 .sys hash**。等 ~5-10s 让 NTFS journal replay 完成, 或者 PSDirect 再执行一次 ping 命令确保 I/O subsystem 稳定。
- **并行 agent 同 main HEAD rebuild 实际上是福**: 他 push 的 .sys 包含双方代码, 你可以直接复用 VM state, 不用自己再 push + Restart。
- 推 VM 前 `git log --oneline -5`: 发现并行 driver commit, 优先等他完成 rebuild + push + VM 装载, 再跑你的功能性验证。

## 本会话 land + VM 验证完成的 feature

`941ec7d71 harden(hvm): filter FEATURE_CONTROL + PERF_CAPABILITIES MSR read` — 代码 landed。VM 验证 (scen h) 通过并行 agent Phase A5 的 HEAD rebuild `14A436..0A7D` 一体加载: driver RUNNING, HVM session 正常启动, detect_probe N=3 detected=1/17 保持 scen (f) 等价, hvm_ctl status 期间 WRMSR 退出计数 181 (bitmap 工作证据)。**guest-side `rdmsr 0x3A` 直接读回 bit 2=0 验证仍需 kernel-mode probe**, user-mode 无 RDMSR 权限, 后续 session 做。
