<#
.SYNOPSIS
    把测试机的 vCPU 数改成指定值并重新部署驱动，用来二分"挂死是不是多处理器
    rendezvous 造成的"。

.DESCRIPTION
    必须以**管理员**运行。

    为什么是这个实验：START_RESIDENT 在 4 vCPU 下把 guest 挂死，而且挂死到
    **连 NMI 都打不进调试器**（kd 报 "Retry sending the same data packet" /
    "transport connection seems lost"），所以事后调试这条路走不通。

    1 个处理器时**根本没有 rendezvous 屏障可以死锁**：
      * 常驻成功  -> 问题确定在多处理器汇合逻辑里，搜索范围缩到一个函数；
      * 仍然挂死  -> 问题在"当前上下文变成 guest"的构造或 VMRESUME 退出循环里，
                     同样缩掉一大半，而且单核挂死比四核挂死好调试得多。

    脚本做的事（每步都回读校验）：
      1. 可选：把当前（可能已挂死的）内存现场存成检查点 —— 这是唯一还能留下的
         证据，强制断电会把它毁掉；
      2. 强制断电（挂死的 guest 无法优雅关机）；
      3. 改 vCPU 数；
      4. 启动并等待 guest 就绪；
      5. 调用 Deploy-KswordDriverToVm.ps1 重新加载驱动
         （驱动服务是 start= demand，重启后不会自动加载）。

    脚本**不跑** resident —— 那一步由你在确认调试器就位之后手动执行。

.PARAMETER Count
    目标 vCPU 数。默认 1。恢复原样用 -Count 4。

.PARAMETER PreserveHungState
    断电前先把当前内存现场存成检查点。默认开启；确定不需要时用 -PreserveHungState:$false 跳过。

.EXAMPLE
    .\Invoke-KswordVmCpuBisect.ps1              # 降到 1 核并重新部署
    .\Invoke-KswordVmCpuBisect.ps1 -Count 4     # 恢复 4 核
#>
[CmdletBinding()]
param(
    [string] $VMName            = 'KSword-HVM-Target',
    [ValidateRange(1, 64)]
    [int]    $Count             = 1,
    [bool]   $PreserveHungState = $true,
    [string] $GuestUser         = 'felix',
    [string] $GuestPassword     = 'password'
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

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
$before = (Get-VMProcessor -VMName $VMName).Count
Write-Host ("虚拟机 {0}  状态 {1}  当前 {2} vCPU  ->  目标 {3} vCPU" -f
    $vm.Name, $vm.State, $before, $Count) -ForegroundColor Cyan

if ($before -eq $Count -and $vm.State -eq 'Running') {
    Write-Host "  已经是目标核数且在运行；只重新部署驱动。" -ForegroundColor Yellow
} else {
    # ---- 1. 留下现场 --------------------------------------------------------
    if ($vm.State -ne 'Off' -and $PreserveHungState) {
        Write-Host "`n--- 1. 保存当前内存现场 ---" -ForegroundColor Cyan
        $snap = 'hung-' + (Get-Date -Format 'MMdd-HHmmss')
        try {
            Checkpoint-VM -Name $VMName -SnapshotName $snap
            Show-Check "检查点 '$snap'" $true '强制断电会毁掉内存现场，这是唯一留下的证据' | Out-Null
        } catch {
            # 挂死的 guest 有时连检查点都打不了。这不该阻断整个实验。
            Write-Host ("  [跳过] 检查点失败：{0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }

    # ---- 2. 断电 ------------------------------------------------------------
    if ($vm.State -ne 'Off') {
        Write-Host "`n--- 2. 强制断电 ---" -ForegroundColor Cyan
        Write-Host "  挂死的 guest 无法优雅关机，只能 TurnOff。" -ForegroundColor Yellow
        Stop-VM -Name $VMName -TurnOff -Force
        $deadline = (Get-Date).AddMinutes(3)
        while ((Get-Date) -lt $deadline -and (Get-VM -Name $VMName).State -ne 'Off') {
            Start-Sleep -Seconds 3
        }
        if (-not (Show-Check '已关机' ((Get-VM -Name $VMName).State -eq 'Off'))) {
            throw '虚拟机没能关机。'
        }
    }

    # ---- 3. 改核数 ----------------------------------------------------------
    Write-Host "`n--- 3. 设置 vCPU 数 ---" -ForegroundColor Cyan
    Set-VMProcessor -VMName $VMName -Count $Count
    $now = (Get-VMProcessor -VMName $VMName).Count
    if (-not (Show-Check "vCPU = $Count" ($now -eq $Count) "实际 $now")) {
        throw 'vCPU 数回读不符。'
    }
    # 嵌套虚拟化开关是按虚拟机的，改核数不应该动它 —— 但还是回读一次，
    # 因为它一旦被关掉，后面所有 VMX 操作都会以看不懂的方式失败。
    $nested = (Get-VMProcessor -VMName $VMName).ExposeVirtualizationExtensions
    if (-not (Show-Check '嵌套虚拟化仍然开启' ([bool]$nested))) {
        throw '嵌套虚拟化被关掉了 —— Set-VMProcessor -ExposeVirtualizationExtensions $true'
    }

    # ---- 4. 启动 ------------------------------------------------------------
    Write-Host "`n--- 4. 启动并等待就绪 ---" -ForegroundColor Cyan
    Start-VM -Name $VMName
    if (-not (Wait-GuestReady)) { throw 'guest 在 5 分钟内没有响应 PowerShell Direct。' }
    Show-Check 'guest 已就绪' $true | Out-Null
}

# ---- 5. 重新部署驱动 --------------------------------------------------------
Write-Host "`n--- 5. 重新加载驱动 ---" -ForegroundColor Cyan
Write-Host "  驱动服务是 start= demand，重启后不会自动加载。" -ForegroundColor DarkGray
& (Join-Path $PSScriptRoot 'Deploy-KswordDriverToVm.ps1') -VMName $VMName `
    -GuestUser $GuestUser -GuestPassword $GuestPassword | Out-Host

Write-Host "`n=== 接下来 ===" -ForegroundColor Cyan
Write-Host @"

**在跑 resident 之前先把断点下好** —— 这次的挂死连 NMI 都打不进调试器
（kd 报 transport connection lost），所以事后再断入是不可能的。
但调试器在挂死**之前**完全可用，把断点提前下好就能看到它走到哪一步为止。

1) 连调试器：

     & "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe" -k com:pipe,port=\\.\pipe\KSword-HVM-Target-kd,resets=0,reconnect

2) 断进去之后先把我们的符号加载好（否则栈里只有 KswordARK+0x1234）：

     .symfix+ C:\symbols
     .sympath+ C:\Users\Felix\CLionProjects\KSword\Ksword5.1\x64\Release\KswordARKDriver
     .reload /f KswordARK.sys
     x KswordARK!KswordARKHvmResident*

   最后一条能验证符号是否真的加载了 —— 列不出符号就别往下走，
   下出来的断点不会命中。

3) 在常驻路径上下断点。**从最外层开始**，先确认它进没进来：

     bp KswordARK!KswordARKHvmResidentStart
     bp KswordARK!KswordARKHvmResidentStartCurrent
     bp KswordARK!KswordARKHvmConfigureResidentVmcsFromAsm
     bl

4) g 放行，另一个窗口跑：

     .\scripts\Invoke-KswordAutomatedAcceptance.ps1 -Stage resident

5) 每次命中断点，记下是哪个，然后 g 继续。**最后一个命中的断点就是挂死的上界** ——
   走到它之后再没有命中，说明 wedge 发生在它和下一个断点之间。
   逐步把断点往里加细，二分到具体那几行。

注意：断点命中在 IPI_LEVEL 上时整机会被调试器冻住，这是正常的。

跑完恢复 4 核：.\scripts\Invoke-KswordVmCpuBisect.ps1 -Count 4
"@ -ForegroundColor Yellow
