---
name: ksword-psdirect-copy-item-binary-corruption
description: WinRM/PSDirect 的 Copy-Item -ToSession 对 kernel driver .sys 这类 ≥3 MB binary 产生 silent corruption，表现为 host hash 与推送后 VM hash 不一致、sc start error 193。用 base64 encode + Add-Content 分块 512KB/块绕过。
metadata:
  type: feedback
---

PSDirect 的 `Copy-Item -ToSession` 对较大的 kernel driver .sys 会产生**静默 binary corruption**——不是报错，而是推送成功后 hash 变了。

**可复现场景**: Hyper-V PSDirect session，`Copy-Item -ToSession $sess -Path <KswordARK.sys 3.6 MB> -Destination C:\ks-stage\ -Force`。

**判据**: host 侧 Get-FileHash 与 VM 侧 Get-FileHash 不一致。本会话实测:
- host SHA256: `67ED71DAE879158B9C42C74693658A7E354543C0C47DBFA0E6CB8F3E0CBE6F95`
- VM 侧同名文件 SHA256: `708241C8D10C1A5CB360A2AEBD09C3670B6D8AD60D0D606425EABD7538211250`
- Length 相同 (3615640), 都是 Copy 后立即读的

**症状**: 后续 `sc start KswordARK` 失败 `error 193 (0xC1 is not a valid Win32 application)` — PE header 已损坏，内核无法加载。

**Why**: WinRM/SOAP 层对大 binary 传输可能触发编码/反编码 bug（可能与 PS 5.1 的 PowerShell Remoting Serialization 相关）。小文件 (.lua / .ps1) 没观察到，CheatEnginePlugin.dll 460 KB 没观察到；3.6 MB .sys 观察到。

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

**判据记忆**: **推 binary 永远在 VM 侧 Get-FileHash 核验与 host 一致**。记忆 [[ksword-build-output-raced]] 记录了产物被并行会话重写的问题，判据相同（hash mismatch）但成因不同——该条是 concurrent rebuild 覆盖，本条是 transit corruption。
