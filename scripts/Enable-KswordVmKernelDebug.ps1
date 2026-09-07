<#
.SYNOPSIS
    给 KSword 测试机接上串口（命名管道）内核调试器，用来定位无转储的挂死。

.DESCRIPTION
    必须以**管理员**运行。

    为什么需要它：START_RESIDENT 在嵌套下把 guest 挂死的形态是**多个核在高 IRQL
    自旋、中断全关**。这种失败：
      * 不蓝屏 —— 没有任何代码能走到 KeBugCheckEx；
      * 不写转储 —— 同上；
      * 连时钟看门狗（CLOCK_WATCHDOG_TIMEOUT 0x101）都跑不起来；
      * 事后读状态查不出来 —— 现场在挂死那一刻就没有出口了。
    唯一能看到四个核各自停在哪的办法就是内核调试器。

    为什么走串口命名管道而不是 KDNET：
    命名管道走 Hyper-V 自己的串口模拟，**不经过宿主的网络驱动栈**。之前用
    KDNET-over-VMware-NAT 把宿主整机搞死过两次，那条路径要穿宿主内核的 vmnet 驱动。
    这一条没有那个风险。

    **break-in 必须靠 NMI。** 串口 break-in 依赖目标响应串口中断，而挂死时中断是
    关着的，敲 Ctrl+Break 没有任何反应。Hyper-V 的 `Debug-VM -InjectNonMaskableInterrupt`
    注入的是**不可屏蔽**中断，中断全关也能送达。脚本末尾会把这条命令打出来。

    对 guest 的改动（都在这台一次性隔离测试机内部，宿主不受影响）：
      1. 加一个虚拟串口 COM1，映射到宿主的命名管道；
      2. bcdedit /dbgsettings serial debugport:1 baudrate:115200
      3. bcdedit /set {current} debug on
      4. 重启使其生效
    改之前会先导出 BCD 备份并打检查点，每一项改完都回读校验。

    **不会**自动连调试器 —— 那是交互操作，命令由你手动执行。

.PARAMETER Disable
    反向操作：关掉 guest 的调试并移除串口映射。

.EXAMPLE
    .\Enable-KswordVmKernelDebug.ps1
    .\Enable-KswordVmKernelDebug.ps1 -Disable
#>
[CmdletBinding()]
param(
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [string] $PipeName      = 'KSword-HVM-Target-kd',
    [switch] $Disable
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$pipePath = "\\.\pipe\$PipeName"
$cred = New-Object System.Management.Automation.PSCredential(
    $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

function Show-Check {
    param([string] $Name, [bool] $Ok, [string] $Detail = '')
    if ($Ok) { Write-Host ("  [OK]   {0}{1}" -f $Name, $(if ($Detail) { "  $Detail" })) -ForegroundColor Green }
    else     { Write-Host ("  [FAIL] {0}{1}" -f $Name, $(if ($Detail) { "  $Detail" })) -ForegroundColor Red }
    return [bool]$Ok
}

function Wait-GuestReady {
    param([int] $TimeoutSeconds = 300)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $null = Invoke-Command -VMName $VMName -Credential $cred `
                        -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            return $true
        } catch { Start-Sleep -Seconds 5 }
    }
    return $false
}

$vm = Get-VM -Name $VMName -ErrorAction Stop
Write-Host ("虚拟机 {0}  状态 {1}" -f $vm.Name, $vm.State) -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. 改引导配置之前先留退路
# ---------------------------------------------------------------------------
if (-not $Disable) {
    Write-Host "`n--- 1. 改引导配置前的退路 ---" -ForegroundColor Cyan
    if ($vm.State -eq 'Running') {
        $stamp = 'before-kdebug-' + (Get-Date -Format 'MMdd-HHmmss')
        Checkpoint-VM -Name $VMName -SnapshotName $stamp
        Show-Check "检查点 '$stamp'" $true | Out-Null
    } else {
        Write-Host "  虚拟机未运行，跳过检查点" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 2. 串口映射（需要虚拟机关机）
# ---------------------------------------------------------------------------
Write-Host "`n--- 2. 虚拟串口 COM1 ---" -ForegroundColor Cyan
$vm = Get-VM -Name $VMName
if ($vm.State -ne 'Off') {
    Write-Host "  Set-VMComPort 需要虚拟机处于关机状态，正在优雅关机..." -ForegroundColor Yellow
    Stop-VM -Name $VMName -Force:$false -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddMinutes(5)
    while ((Get-Date) -lt $deadline -and (Get-VM -Name $VMName).State -ne 'Off') {
        Start-Sleep -Seconds 5
    }
    if ((Get-VM -Name $VMName).State -ne 'Off') {
        # 挂死的 guest 关不掉。这里**不**自动强制断电 —— 由你确认后再决定。
        throw @"
虚拟机没能在 5 分钟内关机（可能仍处于挂死状态）。
强制断电会丢掉当前内存现场，所以不自动执行。确认可以丢弃后手动跑：
  Stop-VM -Name '$VMName' -TurnOff -Force
然后重新运行本脚本。
"@
    }
}

if ($Disable) {
    Set-VMComPort -VMName $VMName -Number 1 -Path $null
    Show-Check 'COM1 映射已移除' ((Get-VMComPort -VMName $VMName -Number 1).Path -in @($null, '')) | Out-Null
} else {
    Set-VMComPort -VMName $VMName -Number 1 -Path $pipePath
    $now = (Get-VMComPort -VMName $VMName -Number 1).Path
    Show-Check 'COM1 -> 命名管道' ($now -eq $pipePath) $now | Out-Null
}

Write-Host "`n--- 3. 启动并等待 guest 就绪 ---" -ForegroundColor Cyan
Start-VM -Name $VMName -ErrorAction SilentlyContinue | Out-Null
if (-not (Wait-GuestReady)) { throw 'guest 在 5 分钟内没有响应 PowerShell Direct。' }
Show-Check 'guest 已就绪' $true | Out-Null

# ---------------------------------------------------------------------------
# 4. guest 内的引导配置
# ---------------------------------------------------------------------------
Write-Host "`n--- 4. guest 引导配置 ---" -ForegroundColor Cyan
$result = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    param($off)
    $out = [ordered]@{}

    # 先导出一份 BCD 备份。改引导配置没有"撤销"按钮，备份是唯一的退路。
    $backup = "C:\ksword\bcd-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').bcd"
    New-Item -ItemType Directory -Force -Path 'C:\ksword' | Out-Null
    $out.Backup = (& bcdedit.exe /export $backup 2>&1 | Out-String).Trim()
    $out.BackupPath = $backup

    if ($off) {
        $out.Debug = (& bcdedit.exe /set '{current}' debug off 2>&1 | Out-String).Trim()
    } else {
        # debugport:1 对应刚才映射的 COM1；波特率对命名管道无实际意义，
        # 但两端必须一致，写死 115200 省得对不上。
        $out.DbgSettings = (& bcdedit.exe /dbgsettings serial debugport:1 baudrate:115200 2>&1 | Out-String).Trim()
        $out.Debug = (& bcdedit.exe /set '{current}' debug on 2>&1 | Out-String).Trim()
    }

    # 回读校验：命令返回成功不等于配置真的写进去了。
    $out.CurrentEnum = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
    $out.DbgEnum     = (& bcdedit.exe /enum '{dbgsettings}' 2>&1 | Out-String)
    $out.DebugOn     = [bool]($out.CurrentEnum -match '(?im)^\s*debug\s+Yes')
    $out.SerialSet   = [bool]($out.DbgEnum -match '(?im)^\s*debugtype\s+Serial')
    $out.PortSet     = [bool]($out.DbgEnum -match '(?im)^\s*debugport\s+1')
    $out
} -ArgumentList ([bool]$Disable)

Write-Host ("  BCD 备份 : {0}" -f $result.BackupPath)
if ($Disable) {
    Show-Check 'debug 已关闭' (-not $result.DebugOn) | Out-Null
} else {
    $ok = $true
    $ok = (Show-Check 'debug = Yes'        $result.DebugOn)   -and $ok
    $ok = (Show-Check 'debugtype = Serial' $result.SerialSet) -and $ok
    $ok = (Show-Check 'debugport = 1'      $result.PortSet)   -and $ok
    if (-not $ok) {
        Write-Host "`n{dbgsettings} 原文：`n$($result.DbgEnum)" -ForegroundColor Yellow
        throw '引导配置回读失败 —— 不要当成配置成功。'
    }
}

# ---------------------------------------------------------------------------
# 5. 重启使配置生效
# ---------------------------------------------------------------------------
Write-Host "`n--- 5. 重启 guest ---" -ForegroundColor Cyan
Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    Start-Process -FilePath 'shutdown.exe' -ArgumentList @('/r', '/t', '0') -NoNewWindow
} -ErrorAction SilentlyContinue
Start-Sleep -Seconds 15
if (-not (Wait-GuestReady)) { throw 'guest 重启后 5 分钟内没有响应。' }
Show-Check 'guest 已重启并就绪' $true | Out-Null

if ($Disable) {
    Write-Host "`n调试已关闭，串口映射已移除。" -ForegroundColor Green
    return
}

# ---------------------------------------------------------------------------
Write-Host "`n=== 怎么用 ===" -ForegroundColor Cyan
$kd = @(
    "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
    "C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $kd) { $kd = 'kd.exe（未找到，需装 WDK/Debugging Tools）' }

Write-Host @"

1) 连调试器（**在跑测试之前先连上**，否则挂死后再连接不上）：

     & "$kd" -k com:pipe,port=$pipePath,resets=0,reconnect

   参数是 `resets=0,reconnect`，**不是** `resync` —— 后者只对真实串口有效，
   命名管道上会被判成非法参数（"COM parameters: resync is not a valid parameter"，
   Win32 error 0n87）。实测踩过。

   连上后先 `g` 让 guest 继续跑，不要停在初始断点上。

2) 另开一个窗口跑常驻测试：

     .\scripts\Invoke-KswordAutomatedAcceptance.ps1 -Stage resident

3) **挂死之后用 NMI 打进去** —— 这是关键的一步：

     Debug-VM -Name '$VMName' -InjectNonMaskableInterrupt

   为什么不能敲 Ctrl+Break：串口 break-in 要目标响应串口中断，而挂死时
   四个核的中断都是关着的，敲了没有任何反应。NMI 是**不可屏蔽**的，能送达。

4) 断进去之后先看这三条：

     !running -it        每个核当前在跑什么（-it 连带栈）
     ~*k                 全部处理器的调用栈
     !irql               各核的 IRQL —— 预期看到 IPI_LEVEL 上的自旋

   要找的是：哪个核没有到达 rendezvous 的汇合点，以及其余核卡在哪个等待循环。

没接调试器时的备用手段：同样注入 NMI，guest 会因 NMI_HARDWARE_FAILURE (0x80)
蓝屏并写出 C:\Windows\MEMORY.DMP。信息量不如实时调试，但总比什么都没有强。

关掉调试：.\scripts\Enable-KswordVmKernelDebug.ps1 -Disable
"@ -ForegroundColor Yellow
