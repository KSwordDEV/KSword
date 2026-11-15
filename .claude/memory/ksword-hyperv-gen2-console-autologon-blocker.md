---
name: ksword-hyperv-gen2-console-autologon-blocker
description: Hyper-V Gen2 VM 的 console autologon 在 PSDirect-only CLI 环境下 4 种被动方法 (registry autologon / vmconnect / Msvm_Keyboard CAD-only / LsaStorePrivateData) 都不触发。**第 5 方法 work**：Msvm_Keyboard CAD + TypeText(password) + Enter 模拟手动登录，console 9s 内变 Active，之后 scheduled task Interactive + x64dbg UIAutomation 可跑。
metadata:
  type: feedback
---

**在 Hyper-V Gen2 VM 上做 session 1 interactive 自动化，用 Msvm_Keyboard 模拟手动登录，不要指望 autologon 自己触发。**

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

## 真因 (修订 2026-11-15)

Hyper-V Gen2 Windows 11 26H2 需要 **DisableCAD=0 (真要求 CAD)** 才能进入 login screen 后接受凭证。Registry autologon 的 `DefaultPassword=f` plain-text 被新 secure sign-in policy 忽略或阻挡。**真正 work 的方式**是模拟 user physical login：发送 CAD 唤醒 login screen → 密码框预填 `DefaultUserName=felix` 已出现 → TypeText 密码字符 → Enter 提交。

## 已验证 work 的方法 (第 5)

```powershell
# Prerequisites: registry AutoAdminLogon=1 + DefaultUserName=felix (已设)
Restart-VM -Name '26H2-11-Pro' -Force
Start-Sleep -Seconds 30  # wait Winlogon loads login screen

$svc = Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='26H2-11-Pro'"
$kbd = Get-CimAssociatedInstance -InputObject $svc -ResultClassName Msvm_Keyboard

Invoke-CimMethod -InputObject $kbd -MethodName TypeCtrlAltDel | Out-Null
Start-Sleep -Seconds 8  # login screen shows password prompt
Invoke-CimMethod -InputObject $kbd -MethodName TypeText -Arguments @{ asciiText = 'f' } | Out-Null
Start-Sleep -Seconds 1
Invoke-CimMethod -InputObject $kbd -MethodName TypeKey -Arguments @{ keyCode = [uint16]0x0D } | Out-Null

# 9s 内 qwinsta 显示 'console felix Active'
```

本会话 2026-11-15 02:12 实测 9s 成功; 之后 scheduled task Interactive + x64dbg UIAutomation sweep **全 PASS** (02:14:08 Result=0).

**要点**:
- CAD 发完**等 8s** (login screen 实际显示需要时间)
- `DefaultUserName` 已预填, 不需要重新输入用户名
- 密码 'f' 单字符用 `TypeText asciiText='f'`, Enter 用 `TypeKey keyCode=0x0D`
- 如密码用户名都要输入: `TypeText 'felix'` + `TypeKey 0x09` (Tab) + `TypeText 'f'` + `TypeKey 0x0D`

## 能做什么 (PSDirect-only)

| 场景 | 可行性 |
| --- | --- |
| `Start-Process` from PSDirect (session 0): CE autorun lua | ✓ 本会话实测 20 操作 PASS (lua 不需要 window station) |
| `Start-Process` from PSDirect: x64dbg GUI | ✗ 窗口不显示, UIAutomation `FindFirst` 返回 null |
| `Register-ScheduledTask LogonType=Interactive` + `Start-ScheduledTask` | ✗ `LastTaskResult=267011` (SCHED_S_TASK_HAS_NOT_RUN), session 1 没 interactive user |
| `Register-ScheduledTask LogonType=S4U` 跑 PowerShell/CLI script | 推测 ✓ 但无 interactive UI, 适合 headless automation 不适合 x64dbg sweep |

## 对后续会话建议

- **验证 x64dbg 前端 end-to-end**: 用上面第 5 方法 (Msvm_Keyboard CAD + TypeText password + Enter) → scheduled task Interactive → `ks-x64dbg-fullsweep.ps1` 跑完整 11 ksna × 2 backend sweep
- **不要先试** 1-4 方法 (registry/vmconnect/CAD-only/LsaStorePrivateData), 全不 work
- CE 作为前端代理仍然可用 (lua 不依赖 window station, PSDirect session 0 Start-Process 即可), 速度快

## Cross-reference

- [[ksword-parallel-agent-vm-staging-race]] - NTFS journal replay 另一边界
- [[ksword-psdirect-copy-item-binary-corruption]] - PSDirect 另一结构限制
- [[ksword-vm-vnc-screen-keys]] - VMware VNC 对比 (不同 hypervisor)
