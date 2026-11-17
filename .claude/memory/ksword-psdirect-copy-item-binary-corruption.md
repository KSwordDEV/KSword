---
name: ksword-psdirect-copy-item-binary-corruption
description: Restart-VM 后立即读 staging 的大 .sys hash 可能看到 journal replay 中间状态 (前 64 字节全 0, size 保留)。曾被误判为 Copy-Item -ToSession binary corruption，修订后真因是 NTFS journal replay 未完成。base64 分块传输之所以生效，是多次 Add-Content 间隔给 journal replay 时间，不是 bypass Copy-Item bug。
metadata:
  type: feedback
---

## 修订说明 (2026-11-15)

本记忆最初归因为 `Copy-Item -ToSession` 的 binary corruption bug，**修订后真因**是 **NTFS journal replay 在 Restart-VM 后未完成**，参见 [[ksword-parallel-agent-vm-staging-race]] (commit be99acdb8 user correction)。下面保留原始观察作故障排查参考，归因章节整体更正。

## 原始观察 (客观事实)

PSDirect 的 `Copy-Item -ToSession` 推 3.6 MB kernel driver .sys，host hash 与 **后续** 读到的 VM hash 不一致。

**可复现场景**: Hyper-V PSDirect session，`Copy-Item -ToSession $sess -Path <KswordARK.sys 3.6 MB> -Destination C:\ks-stage\ -Force`。

**判据**: host 侧 Get-FileHash 与 VM 侧 Get-FileHash 不一致。本会话实测:
- host SHA256: `67ED71DAE879158B9C42C74693658A7E354543C0C47DBFA0E6CB8F3E0CBE6F95`
- VM 侧同名文件 SHA256: `708241C8D10C1A5CB360A2AEBD09C3670B6D8AD60D0D606425EABD7538211250`
- Length 相同 (3615640), 都是 Copy 后立即读的

**症状**: 后续 `sc start KswordARK` 失败 `error 193 (0xC1 is not a valid Win32 application)` — PE header 已损坏，内核无法加载。

**Why (已修订)**: ~~WinRM/SOAP 层对大 binary 传输 bug~~ **真因是 NTFS journal replay 在 Restart-VM 后未完成**。具体时序:
1. Copy-Item 到 staging — 立刻读 hash **与 host 一致** ✓
2. sc delete + Restart-VM — VM 重启
3. Restart 后 PSDirect 重入, 读 staging hash **看到前 64 字节全 0** ← 这里被误判
4. Copy staging → ks-vm → sc start error 193

小文件 (.lua / .ps1 < 1 MB, CheatEnginePlugin.dll 460 KB) 没观察到, 因为 journal replay 对小文件很快完成。3.6 MB .sys 处于边界。

**How to apply**: 推 kernel driver .sys 或其他 ≥1-2 MB binary 到 Hyper-V VM 时，先推 base64 encode 的 text 文件，VM 侧 decode:

```powershell
$bytes = [System.IO.File]::ReadAllBytes($hostPath)
$b64 = [Convert]::ToBase64String($bytes)
$chunks = @()  # 分块 512KB 每块
for ($i=0; $i -lt $b64.Length; $i += 524288) {
  $chunks += $b64.Substring($i, [Math]::Min(524288, $b64.Length - $i))
}
$sess = New-PSSession -VMName $vm -Credential $cred
Invoke-Command -Session $sess -ScriptBlock { Set-Content -Path $tmpB64 -Value '' -Encoding Ascii -NoNewline }
foreach ($c in $chunks) {
  Invoke-Command -Session $sess -ScriptBlock {
    param($c, $tmpB64) Add-Content -Path $tmpB64 -Value $c -Encoding Ascii -NoNewline
  } -ArgumentList $c, $tmpB64
}
Invoke-Command -Session $sess -ScriptBlock {
  param($tmpB64, $outPath)
  $b64 = Get-Content $tmpB64 -Raw
  [System.IO.File]::WriteAllBytes($outPath, [Convert]::FromBase64String($b64))
  Remove-Item $tmpB64 -Force
} -ArgumentList $tmpB64, $outPath
```

本会话 3.6 MB .sys 分 10 chunks (base64 ~4.8 MB), 全部成功, 推送后 VM hash 与 host 完全一致。

**为什么 base64 分块 workaround 生效 (修订)**:
~~~bypass Copy-Item bug~~ **真实机制**: `Add-Content` 10 次分块每次 ~0.3-0.5s, 中间隔 PSDirect 往返延迟, 10 次合计 5-10 秒。这段时间足够 NTFS journal replay 完成, 所以最后 Base64 decode + WriteAllBytes 时看到的 staging page 已经稳定, 不再是 zero-filled 中间状态。

**判据记忆**: **Restart-VM 后不要立即读 staging 大文件 hash — 等 5-10 秒**。

## 更可靠的替代: Copy-VMFile (Hyper-V Guest Service Interface)

2026-11-15 新实证: `Copy-VMFile -Name <vm> -SourcePath ... -DestinationPath ... -FileSource Host` 走 Hyper-V Guest Service Interface (VMBus), **传输忠实无 PSDirect base64 corruption**:

```powershell
# 前置: 启用 VM 的 Guest Service Interface
Enable-VMIntegrationService -VMName '26H2-11-Pro' -Name 'Guest Service Interface'

# 推 .sys (host 3.6 MB → VM staging)
Copy-VMFile -Name '26H2-11-Pro' `
    -SourcePath (Resolve-Path 'Ksword5.1\x64\Release\KswordARK.sys').Path `
    -DestinationPath 'C:\ks-stage\KswordARK.sys' `
    -CreateFullPath -FileSource Host -Force
```

实测本会话 driver 硬化版 3.6 MB .sys 走 Copy-VMFile **一次推送 hash 完全一致**。相比 PSDirect base64 分块 (需 10 次 Add-Content + decode + 可能传输 corruption)，Copy-VMFile 单条命令完成。

**适用场景**:
- 大 binary (3+ MB) 推 VM
- 对完整性有强要求 (kernel driver signature verification)

**限制**:
- VM 必须启用 Guest Service Interface (默认通常 off, 需先 Enable-VMIntegrationService)
- host sandbox 可能挡 (部分 Claude Code 环境 refuse)
- 单方向 Host → VM (或 VM → Host 用 -FileSource VirtualMachine); 不支持双向 batch

- 相关 [[ksword-parallel-agent-vm-staging-race]] — 同一现象的完整分析
- 相关 [[ksword-build-output-raced]] — 另一类 hash mismatch (并行 rebuild 覆盖), 判据相同但成因不同
