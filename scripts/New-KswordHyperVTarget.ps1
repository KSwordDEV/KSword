<#
.SYNOPSIS
    创建一台用于 KSword HVM/EPT HOOK 开发的 Hyper-V 测试机，并按嵌套虚拟化的要求配好。

.DESCRIPTION
    必须以**管理员**运行，且宿主已启用 Hyper-V 角色。

    嵌套虚拟化不是打开一个开关就行，下面每一项都是硬要求，缺一项 KSword 的 HVM 就
    VMXON 不了或者行为异常。脚本把它们全部固化并在最后逐项回读校验：

      * ExposeVirtualizationExtensions = $true —— 把 VT-x/EPT 透传给 L1 guest。
        只能在虚拟机**关机**时设置。
      * 动态内存必须关闭 —— Hyper-V 明确规定：开着动态内存时嵌套虚拟化不可用。
      * MAC 地址欺骗打开 —— L2 guest 的网络包源 MAC 与 L1 网卡不同，不开的话
        虚拟交换机会直接丢弃，L2 完全没网。
      * 检查点（快照）设为标准型并默认关闭自动检查点 —— 生产检查点依赖 guest 内的
        VSS，会和正在运行的 hypervisor 打架。
      * 第 2 代虚拟机 —— UEFI，Windows 11 需要。

    脚本**不做**的事：不装系统、不改宿主安全配置、不动 Secure Boot（装完系统后
    另行关闭，见输出提示）。

.PARAMETER VMName
    虚拟机名。

.PARAMETER Path
    虚拟机与虚拟磁盘的存放目录。

.PARAMETER IsoPath
    Windows 安装 ISO。

.PARAMETER MemoryGB
    固定内存大小（不使用动态内存）。

.PARAMETER CpuCount
    虚拟处理器数。

.PARAMETER DiskGB
    虚拟磁盘大小（动态扩展）。

.PARAMETER SwitchName
    要连接的虚拟交换机。留空则自动选第一个 External，没有就选 Default Switch。

.EXAMPLE
    .\New-KswordHyperVTarget.ps1 -IsoPath 'D:\Users\felix\Downloads\Windows11_InsiderPreview_Client_x64_en-us_22621.iso'
#>
[CmdletBinding()]
param(
    [string] $VMName     = 'KSword-HVM-Target',
    [string] $Path       = 'C:\Hyper-V',
    [Parameter(Mandatory)][string] $IsoPath,
    [int]    $MemoryGB   = 8,
    [int]    $CpuCount   = 4,
    [int]    $DiskGB     = 80,
    [string] $SwitchName = ''
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '必须以管理员身份运行。'
    }
}

Assert-Admin

if (-not (Get-Module -ListAvailable Hyper-V)) {
    throw @'
Hyper-V 角色还没装。先以管理员运行：

    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All

然后重启，再跑本脚本。
'@
}
Import-Module Hyper-V -ErrorAction Stop

if (-not (Test-Path -LiteralPath $IsoPath)) { throw "找不到 ISO：$IsoPath" }
if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
    throw "虚拟机 '$VMName' 已存在。要重建请先手工删除，脚本不替你删。"
}

# ---------------------------------------------------------------------------
# 虚拟交换机
# ---------------------------------------------------------------------------
if (-not $SwitchName) {
    $sw = Get-VMSwitch -ErrorAction SilentlyContinue |
          Sort-Object @{ e = { switch ($_.SwitchType) { 'External' { 0 } 'Internal' { 1 } default { 2 } } } } |
          Select-Object -First 1
    if (-not $sw) {
        throw @'
宿主上一个虚拟交换机都没有。先在 Hyper-V 管理器里建一个（虚拟交换机管理器 →
外部 → 绑定到你的物理网卡），或者：

    New-VMSwitch -Name 'External' -NetAdapterName '<你的网卡名>' -AllowManagementOS $true
'@
    }
    $SwitchName = $sw.Name
}
Write-Host "虚拟交换机 : $SwitchName" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 建机
# ---------------------------------------------------------------------------
$vhdDir = Join-Path $Path 'Virtual Hard Disks'
New-Item -ItemType Directory -Force -Path $vhdDir | Out-Null
$vhdPath = Join-Path $vhdDir "$VMName.vhdx"
if (Test-Path -LiteralPath $vhdPath) { throw "虚拟磁盘已存在：$vhdPath" }

Write-Host "`n创建虚拟机 $VMName ..." -ForegroundColor Cyan
$vm = New-VM -Name $VMName -Generation 2 -Path $Path `
             -MemoryStartupBytes ($MemoryGB * 1GB) `
             -NewVHDPath $vhdPath -NewVHDSizeBytes ($DiskGB * 1GB) `
             -SwitchName $SwitchName

# --- 嵌套虚拟化的三条硬要求 -------------------------------------------------
# 1) 动态内存必须关。Hyper-V 规定：开着动态内存时不允许暴露虚拟化扩展。
Set-VMMemory  -VMName $VMName -DynamicMemoryEnabled $false -StartupBytes ($MemoryGB * 1GB)
# 2) 透传 VT-x/EPT。只能在关机时设。
Set-VMProcessor -VMName $VMName -Count $CpuCount -ExposeVirtualizationExtensions $true
# 3) L2 guest 的源 MAC 与 L1 网卡不同，不开欺骗就会被虚拟交换机丢包。
Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing On

# --- 检查点：标准型 ---------------------------------------------------------
# 生产检查点走 guest 内的 VSS，和正在运行的 hypervisor 冲突；这里用标准型，
# 并关掉自动检查点（否则每次启动都会生成一个，做实验时很碍事）。
Set-VM -Name $VMName -CheckpointType Standard -AutomaticCheckpointsEnabled $false
Set-VM -Name $VMName -AutomaticStopAction ShutDown

# --- 固件：ISO 优先启动 -----------------------------------------------------
$dvd = Add-VMDvdDrive -VMName $VMName -Path $IsoPath -Passthru
Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd

# --- vTPM：Windows 11 安装检查需要 -----------------------------------------
# 与 VMware 不同，Hyper-V 的 vTPM 不会因此加密整台虚拟机的配置，
# 也就不会出现"忘了口令就再也打不开"的局面。
try {
    $hgs = Get-HgsGuardian -Name 'UntrustedGuardian' -ErrorAction SilentlyContinue
    if (-not $hgs) { $hgs = New-HgsGuardian -Name 'UntrustedGuardian' -GenerateCertificates }
    $kp = New-HgsKeyProtector -Owner $hgs -AllowUntrustedRoot
    Set-VMKeyProtector -VMName $VMName -KeyProtector $kp.RawData
    Enable-VMTPM -VMName $VMName
    $tpmOk = $true
} catch {
    $tpmOk = $false
    Write-Warning "vTPM 配置失败（$($_.Exception.Message)）。Windows 11 安装程序可能会拒绝，届时用 Shift+F10 → regedit 绕过检查，或手工配 vTPM。"
}

# ---------------------------------------------------------------------------
# 回读校验 —— 不要只看"命令没报错"
# ---------------------------------------------------------------------------
Write-Host "`n--- 回读校验 ---" -ForegroundColor Cyan
$p  = Get-VMProcessor -VMName $VMName
$m  = Get-VMMemory    -VMName $VMName
$na = Get-VMNetworkAdapter -VMName $VMName
$fw = Get-VMFirmware  -VMName $VMName
$v  = Get-VM -Name $VMName

$checks = @(
    @{ N = '第 2 代虚拟机（UEFI）';       O = ($v.Generation -eq 2) }
    @{ N = '嵌套虚拟化已暴露 VT-x/EPT';   O = ($p.ExposeVirtualizationExtensions -eq $true) }
    @{ N = "虚拟处理器 = $CpuCount";      O = ($p.Count -eq $CpuCount) }
    @{ N = '动态内存已关闭（嵌套必需）';   O = ($m.DynamicMemoryEnabled -eq $false) }
    @{ N = "固定内存 = $MemoryGB GB";     O = ($m.Startup -eq ($MemoryGB * 1GB)) }
    @{ N = 'MAC 欺骗已开启（L2 联网必需）'; O = ($na.MacAddressSpoofing -eq 'On') }
    @{ N = '检查点为标准型';              O = ($v.CheckpointType -eq 'Standard') }
    @{ N = '自动检查点已关闭';            O = ($v.AutomaticCheckpointsEnabled -eq $false) }
    @{ N = 'ISO 已挂载并设为首选启动项';   O = ($fw.BootOrder[0].Device -is [Microsoft.HyperV.PowerShell.DvdDrive]) }
    @{ N = 'vTPM 已启用';                 O = $tpmOk }
)
$bad = 0
foreach ($c in $checks) {
    if ($c.O) { Write-Host ("  [OK]   " + $c.N) -ForegroundColor Green }
    else      { Write-Host ("  [FAIL] " + $c.N) -ForegroundColor Red; $bad++ }
}
if ($bad -gt 0) { throw "$bad 项回读校验没通过 —— 不要当成创建成功。" }

Write-Host @"

虚拟机已就绪：$VMName
  位置    : $Path
  磁盘    : $vhdPath  ($DiskGB GB 动态扩展)
  内存    : $MemoryGB GB 固定
  处理器  : $CpuCount  已暴露 VT-x/EPT

接下来：
  1. 启动并装系统：  Start-VM -Name '$VMName'
                     然后在 Hyper-V 管理器里连上去（或 vmconnect localhost '$VMName'）
  2. 装完系统后**关机**，关掉 Secure Boot（testsigning 的前提）：
         Set-VMFirmware -VMName '$VMName' -EnableSecureBoot Off
  3. 打基线快照：
         Checkpoint-VM -Name '$VMName' -SnapshotName 'clean-install'
  4. 在 guest 内开测试签名，并**确认 guest 自己的 VBS/内存完整性是关的** ——
     否则 guest 里的 Hyper-V 会抢走 VT-x，KSword HVM 就 VMXON 不了：
         bcdedit /set testsigning on
         bcdedit /set hypervisorlaunchtype off
     （内存完整性另在 设置 → 隐私和安全性 → Windows 安全中心 → 设备安全性 →
       内核隔离 里关闭，然后重启）
"@ -ForegroundColor Yellow
