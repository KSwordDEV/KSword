---
name: ksword-parallel-agent-vm-staging-race
description: 两个 agent 同时向 Hyper-V 测试 VM 推 .sys 时, VM 内 C:\ks-stage\ 下任意独特文件名都可能在 Restart-VM 过程中被清零 (前 64 字节全 0, size 保留). sc start 变 error 193. 本会话代码 landed 但 VM 验证放弃.
metadata:
  type: feedback
---

**同一时间只有一个 agent 推 VM**. 共享 Hyper-V 测试 VM 时 Restart-VM 跨 agent race 会污染 staging 文件。

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

**本机 (Felix 的 Hyper-V 26H2-11-Pro VM)** 多 agent 并行推 .sys 的禁区:
- 不要同时开两个 agent 都 driver rebuild + 推同一 VM
- **优先**: 开新 agent 前 check `git log --oneline -5` 看是否有并行推进
- 看到并行 commit 立即**停止 VM 推送**, 让代码 commit 即可, VM 验证等并行 session 结束

## 本会话 land 的但未 VM 验证的 feature

`941ec7d71 harden(hvm): filter FEATURE_CONTROL + PERF_CAPABILITIES MSR read` — 代码 landed, 驱动 rebuild 成功 (host 侧 .sys hash `5276BE...D9B4` 含该 feature), 但 VM 装载 + guest-side `rdmsr 0x3A` 验证**未完成**. 下轮或并行 agent 结束后补验证:
1. 推 host .sys 到 VM (base64 分块绕 PSDirect binary corruption, 见 [[ksword-psdirect-copy-item-binary-corruption]])
2. sc create + start 成功 RUNNING
3. 启 HVM session (CE autorun)
4. VM 内 kernel-mode 工具 (hvm_ctl status 或类似) 读 `MsrBitmapInterceptCount`, 应该 +2
5. VM 内 kernel-mode RDMSR 0x3A — bit 2 = 0, bit 0 (LOCK) = physical value
