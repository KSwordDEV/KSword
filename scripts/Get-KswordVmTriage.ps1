<#
.SYNOPSIS
    测试机失去响应时的现场判读。只读，不改任何状态。

.DESCRIPTION
    必须以**管理员**运行，可以在另一个窗口跑，不会打扰正在执行的测试脚本。

    黑屏 + 无响应有三种完全不同的成因，处置方式相反，所以先判类型再动手：

      Paused-Critical  宿主磁盘满，Hyper-V 主动暂停了虚拟机。**不是崩溃。**
                       腾出空间后 Resume-VM 即可原地恢复，不要回滚、不要断电。
      Running + 无心跳  guest 内核挂死或正在写崩溃转储。转储可能要几分钟，
                       **这期间断电会毁掉转储**。
      Off / Saved      已经停了。

    脚本只读取状态，任何恢复动作都由你确认后手动执行。
#>
[CmdletBinding()]
param(
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [int]    $ProbeSeconds  = 25
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$vm = Get-VM -Name $VMName -ErrorAction Stop
Write-Host "=== 虚拟机 ===" -ForegroundColor Cyan
Write-Host ("  状态      : {0}" -f $vm.State) -ForegroundColor $(
    if ("$($vm.State)" -match 'Critical') { 'Red' } elseif ($vm.State -eq 'Running') { 'Yellow' } else { 'White' })
Write-Host ("  Status    : {0}" -f $vm.Status)
Write-Host ("  运行时长  : {0}" -f $vm.Uptime)
Write-Host ("  内存分配  : {0} MB" -f [math]::Round($vm.MemoryAssigned / 1MB))
Write-Host ("  CPU 使用  : {0}%" -f $vm.CPUUsage)

Write-Host "`n=== CPU 采样（判断是空转还是在干活）===" -ForegroundColor Cyan
$samples = @()
for ($i = 0; $i -lt 5; $i++) {
    $samples += (Get-VM -Name $VMName).CPUUsage
    Start-Sleep -Milliseconds 800
}
Write-Host ("  五次采样: {0}" -f ($samples -join ', '))
if (($samples | Measure-Object -Maximum).Maximum -eq 0) {
    Write-Host "  全零 —— 没有任何指令在执行" -ForegroundColor Red
} else {
    Write-Host "  非零 —— 确实有代码在跑（写转储、或某个核在自旋）" -ForegroundColor Yellow
}

Write-Host "`n=== 集成服务 ===" -ForegroundColor Cyan
# 不要用 -Name 过滤：不同版本/语言下组件名不一样，写死名字会报
# "找不到具有给定名称的集成组件"，那是查询方式的错，不是虚拟机的状态。
try {
    Get-VMIntegrationService -VMName $VMName -ErrorAction Stop |
        Select-Object Name, Enabled, PrimaryStatusDescription |
        Format-Table -AutoSize
} catch { Write-Host "  查询失败：$($_.Exception.Message)" -ForegroundColor Yellow }

Write-Host "=== PowerShell Direct 探活（决定性判据）===" -ForegroundColor Cyan
# 这是唯一能区分"guest 操作系统还活着，只是控制台黑屏"与"内核挂死"的检查。
# 它走 VMBus，不依赖网络，也不依赖显示。
$psDirect = 'UNKNOWN'
try {
    $cred = New-Object System.Management.Automation.PSCredential(
        $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))
    $job = Start-Job -ScriptBlock {
        param($n, $u, $p)
        $c = New-Object System.Management.Automation.PSCredential(
            $u, (ConvertTo-SecureString $p -AsPlainText -Force))
        Invoke-Command -VMName $n -Credential $c -ScriptBlock {
            "$env:COMPUTERNAME|$([Environment]::TickCount64)"
        }
    } -ArgumentList $VMName, $GuestUser, $GuestPassword
    if (Wait-Job $job -Timeout $ProbeSeconds) {
        $r = Receive-Job $job -ErrorAction SilentlyContinue
        if ($r) { $psDirect = 'ALIVE'; Write-Host ("  响应: {0}" -f $r) -ForegroundColor Green }
        else    { $psDirect = 'ERROR'; Write-Host "  连上了但没有返回值" -ForegroundColor Yellow }
    } else {
        $psDirect = 'TIMEOUT'
        Write-Host ("  {0} 秒内无响应" -f $ProbeSeconds) -ForegroundColor Red
    }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
} catch {
    $psDirect = 'ERROR'
    Write-Host ("  探活失败：{0}" -f $_.Exception.Message) -ForegroundColor Yellow
}

Write-Host "`n=== 宿主磁盘 ===" -ForegroundColor Cyan
$root = [IO.Path]::GetPathRoot($vm.Path)
Get-PSDrive -PSProvider FileSystem |
    Where-Object { $null -ne $_.Used } |
    Select-Object Name,
        @{ n = '已用GB'; e = { [math]::Round($_.Used / 1GB, 1) } },
        @{ n = '剩余GB'; e = { [math]::Round($_.Free / 1GB, 2) } } |
    Format-Table -AutoSize
Write-Host ("  虚拟机在 {0}" -f $root)

Write-Host "=== 检查点 ===" -ForegroundColor Cyan
Get-VMSnapshot -VMName $VMName | Sort-Object CreationTime |
    Format-Table Name, CreationTime -AutoSize

# ---------------------------------------------------------------------------
Write-Host "=== 判读 ===" -ForegroundColor Cyan
if ("$($vm.State)" -match 'Critical' -or "$($vm.Status)" -match 'Critical|critical') {
    Write-Host @"
  【宿主磁盘满，不是崩溃】
  Hyper-V 在动态 VHDX 无法继续增长时会主动暂停虚拟机。guest 内部什么也没发生。

  处置（按顺序，不要回滚、不要断电）：
    1. .\scripts\Clear-KswordVmCheckpoints.ps1 -KeepLast 0 -Confirm
    2. Resume-VM -Name '$VMName'
  恢复后 guest 从暂停处原地继续，之前的 resident 结果仍然有效。
"@ -ForegroundColor Yellow
}
elseif ($vm.State -eq 'Running' -and $psDirect -eq 'ALIVE') {
    Write-Host @"
  【guest 操作系统还活着】
  PowerShell Direct 有响应，说明内核没有挂死 —— 黑屏只是控制台/显示的表象。
  常见成因：VMLAUNCH 之后 guest 在 VMX non-root 里继续跑，但图形栈或
  会话被打断；也可能只是 VMConnect 窗口本身需要重连。

  处置：
    1. 直接读状态，不要回滚：
       .\scripts\Invoke-KswordAutomatedAcceptance.ps1 -Stage status
       每处理器行会告诉你 VMLAUNCH 到底成没成（看 GUEST_LAUNCHED 位）。
    2. 关掉再重开 VMConnect 窗口看黑屏是否只是显示问题。
"@ -ForegroundColor Green
}
elseif ($vm.State -eq 'Running') {
    Write-Host @"
  【仍在运行但可能已挂死或正在写转储】
  部署脚本已开启内核转储（CrashDumpEnabled=2, AutoReboot=1）。如果是蓝屏，
  guest 会先把转储写进 C:\Windows\MEMORY.DMP 再自动重启 —— 8 GiB 内存的
  内核转储通常要几分钟，期间黑屏、无心跳都是正常的。

  **这期间断电会毁掉转储**，而那份转储是唯一能说明 VMLAUNCH 之后发生了什么的证据。

  处置：
    1. 再等 5-10 分钟，重复跑本脚本看 Uptime 是否归零（归零 = 已重启，转储写好了）
    2. 一直不动且 CPU 使用为 0，才考虑回滚：
       Restore-VMCheckpoint -VMName '$VMName' -Name '<before-resident-*>' -Confirm:`$false
       注意回滚会丢掉转储。
"@ -ForegroundColor Yellow
}
else {
    Write-Host ("  虚拟机处于 {0}，不在运行。" -f $vm.State)
}
