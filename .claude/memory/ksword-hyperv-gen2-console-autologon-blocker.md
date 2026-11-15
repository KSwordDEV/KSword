---
name: ksword-hyperv-gen2-console-autologon-blocker
description: Hyper-V Gen2 VM 的 console autologon 在 PSDirect-only CLI 环境下结构性不可触发。GUI 端前端自动化 (x64dbg UIAutomation / scheduled task Interactive LogonType) 本会话无法实时验证。CE autorun lua 可以 bypass (不依赖 session 1 window station)。
metadata:
  type: feedback
---

**在 Hyper-V Gen2 VM 上做任何需要 session 1 interactive window station 的自动化前，先确认 PSDirect-only 环境能否让 autologon 真触发。实测不能。**

## 实测证据 (2026-11-15 本会话)

VM: `26H2-11-Pro` (Windows 11 Pro 26H2), Gen2 Hyper-V guest, PSDirect via `felix:f` credentials.

尝试了四种 autologon 启用方法, **全部 failed**:

1. **Registry autologon** (`AutoAdminLogon=1` + `DefaultUserName=felix` + `DefaultPassword=f` REG_SZ + `DefaultDomainName=DESKTOP-N12QB6P`):
   - Restart-VM 后等 187s, `qwinsta` 始终显示 `console  Conn` 无 USERNAME
   - 没有 Winlogon 失败事件 log
   - autologon 根本不进 trigger phase

2. **vmconnect.exe localhost VMName**:
   - 启动 host-side vmconnect window
   - 等 120s, VM console 状态 unchanged
   - vmconnect 停在 Enhanced Session chooser (Gen2 默认), 需要 user click Connect

3. **Msvm_Keyboard WMI 注入 CAD + Enter**:
   - `Invoke-CimMethod $kbd -MethodName TypeCtrlAltDel` ✓ 执行
   - `Invoke-CimMethod $kbd -MethodName TypeKey -Arguments @{ keyCode = 0x0D }` ✓ 执行
   - console 状态 unchanged — Gen2 下 console 虚拟键盘可能发到 VM 但没登录 UI 等待输入

4. **LsaStorePrivateData 加密 DefaultPassword** (via P/Invoke):
   - `LsaOpenPolicy rc=0xC0000022 (STATUS_ACCESS_DENIED)` — WinRM user context 没 LSA secret write 权限
   - 即使提权 (RunLevel Highest) 也 fail — PSDirect 的 session 0 本身不足

## 真因假设

Hyper-V Gen2 Enhanced Session Mode 的 console 在 `vmconnect` 未真实"用户点击 Connect"前不进入 Winlogon normal flow。或者 Windows 11 26H2 新 secure sign-in policy 阻挡 plain-text `DefaultPassword` autologon。

未验证的额外可能:
- `DisableCAD=0` 可能要求 user press Ctrl+Alt+Del first
- "Interactive logon: Require Windows Hello for Business or smart card" GPO
- Secure Boot + Credential Guard 相关

## 能做什么 (PSDirect-only)

| 场景 | 可行性 |
| --- | --- |
| `Start-Process` from PSDirect (session 0): CE autorun lua | ✓ 本会话实测 20 操作 PASS (lua 不需要 window station) |
| `Start-Process` from PSDirect: x64dbg GUI | ✗ 窗口不显示, UIAutomation `FindFirst` 返回 null |
| `Register-ScheduledTask LogonType=Interactive` + `Start-ScheduledTask` | ✗ `LastTaskResult=267011` (SCHED_S_TASK_HAS_NOT_RUN), session 1 没 interactive user |
| `Register-ScheduledTask LogonType=S4U` 跑 PowerShell/CLI script | 推测 ✓ 但无 interactive UI, 适合 headless automation 不适合 x64dbg sweep |

## 对后续会话建议

- **验证 x64dbg 前端 end-to-end 需要** user 在 host 实际 `vmconnect` → GUI 点 Connect → 让 autologon 完成 → 再 scheduled task
- 或**用 CE 作为前端代理**: Kernel no-attach backend 的所有 IOCTL 都走 `IOCTL_KSWORD_ARK_KERNEL_NOATTACH`, CE autorun 跑完 10 操作 = backend 完整可用, x64dbg 是"另一前端 UI wrapper", 不是后端功能
- **避免** 手动触发 autologon 的时间投资 — 四种方法全 fail, 结构性不可行 in PSDirect-only CLI

## Cross-reference

- [[ksword-parallel-agent-vm-staging-race]] - NTFS journal replay 另一边界
- [[ksword-psdirect-copy-item-binary-corruption]] - PSDirect 另一结构限制
- [[ksword-vm-vnc-screen-keys]] - VMware VNC 对比 (不同 hypervisor)
