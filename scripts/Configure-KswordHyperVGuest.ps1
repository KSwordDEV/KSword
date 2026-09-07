<#
.SYNOPSIS
    把已装好系统的 KSword Hyper-V 测试机配成可加载测试签名驱动、且 VT-x 归 KSword HVM 所有。

.DESCRIPTION
    必须以**管理员**运行（Hyper-V cmdlet 与 PowerShell Direct 都要求）。

    做四件事，每一步都回读校验，任何一项对不上就中止而不是继续：

      1. 关机 → 关闭 Secure Boot（testsigning 的前提）→ 打基线检查点
      2. 开机 → 通过 PowerShell Direct 在 guest 内：
           - bcdedit /set testsigning on          让测试签名驱动能加载
           - bcdedit /set hypervisorlaunchtype off 不让 guest 自己的 hypervisor 启动
           - 关闭 VBS 与 HVCI（内存完整性）        否则它们会抢走 VT-x
      3. 重启 guest
      4. 重启后逐项回读确认，并报告 KSword HVM 能否拿到 VT-x

    为什么第 2 步的后两项是硬要求：这台虚拟机是 L1，KSword 的 HVM 要在 L1 里 VMXON。
    如果 guest 自己的 Hyper-V / VBS / HVCI 起来了，VT-x 会先被它们占住，
    KSword HVM 就只能报"已有 hypervisor"而拒绝启动。

.PARAMETER VMName
    虚拟机名。

.PARAMETER GuestCredential
    guest 内的管理员凭据。不传则交互提示。

.PARAMETER GrantHyperVAccess
    顺便把当前用户加入本机 Hyper-V Administrators 组，之后非提权会话也能操作虚拟机
    （需要注销重登才生效）。默认不加。

.EXAMPLE
    .\Configure-KswordHyperVGuest.ps1
#>
[CmdletBinding()]
param(
    [string] $VMName = 'KSword-HVM-Target',
    [System.Management.Automation.PSCredential] $GuestCredential,
    [switch] $GrantHyperVAccess
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '必须以管理员身份运行（Hyper-V cmdlet 与 PowerShell Direct 都要求提权）。'
    }
}

function Show-Check {
    param([string] $Name, [bool] $Ok)
    if ($Ok) { Write-Host ("  [OK]   " + $Name) -ForegroundColor Green }
    else     { Write-Host ("  [FAIL] " + $Name) -ForegroundColor Red }
    return [bool]$Ok
}

Assert-Admin
Import-Module Hyper-V -ErrorAction Stop

$vm = Get-VM -Name $VMName -ErrorAction Stop
Write-Host "=== $VMName ===" -ForegroundColor Cyan
Write-Host ("  状态 {0}  第 {1} 代  {2} vCPU  {3:N0} MB" -f `
    $vm.State, $vm.Generation, $vm.ProcessorCount, ($vm.MemoryAssigned / 1MB))

# 嵌套虚拟化是本次的全部意义所在，先确认它还在
$proc = Get-VMProcessor -VMName $VMName
if (-not $proc.ExposeVirtualizationExtensions) {
    throw '这台虚拟机没有暴露 VT-x/EPT。先关机后执行：Set-VMProcessor -VMName ' +
          $VMName + ' -ExposeVirtualizationExtensions $true'
}
Write-Host "  嵌套虚拟化：已暴露 VT-x/EPT" -ForegroundColor Green

if (-not $GuestCredential) {
    Write-Host "`n请输入 guest 内的管理员凭据（用户名可写 .\<用户名>）" -ForegroundColor Yellow
    $GuestCredential = Get-Credential -Message "guest 管理员凭据"
}

# ---------------------------------------------------------------------------
# 1) 关机 → 关 Secure Boot → 基线检查点
# ---------------------------------------------------------------------------
Write-Host "`n--- 1. 关闭 Secure Boot 并建基线检查点 ---" -ForegroundColor Cyan

if ((Get-VM -Name $VMName).State -ne 'Off') {
    Write-Host "  正在关机..."
    Stop-VM -Name $VMName -Force
    while ((Get-VM -Name $VMName).State -ne 'Off') { Start-Sleep -Seconds 2 }
}
Write-Host "  已关机"

Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
$fw = Get-VMFirmware -VMName $VMName
if (-not (Show-Check 'Secure Boot 已关闭' ($fw.SecureBoot -eq 'Off'))) {
    throw 'Secure Boot 没关掉 —— 继续下去 testsigning 会被静默忽略，中止。'
}

$snapName = 'clean-install'
if (-not (Get-VMSnapshot -VMName $VMName -Name $snapName -ErrorAction SilentlyContinue)) {
    Checkpoint-VM -Name $VMName -SnapshotName $snapName
    Write-Host "  已建检查点 '$snapName'"
} else {
    Write-Host "  检查点 '$snapName' 已存在，跳过"
}

# ---------------------------------------------------------------------------
# 2) 开机并等 PowerShell Direct 可用
# ---------------------------------------------------------------------------
Write-Host "`n--- 2. 开机并配置 guest ---" -ForegroundColor Cyan
Start-VM -Name $VMName
Write-Host "  等待 PowerShell Direct 就绪（最长 10 分钟）..."

$deadline = (Get-Date).AddMinutes(10)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $null = Invoke-Command -VMName $VMName -Credential $GuestCredential `
                    -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        $ready = $true
        break
    } catch { Start-Sleep -Seconds 10 }
}
if (-not $ready) { throw 'PowerShell Direct 一直连不上。确认 guest 已登录到桌面、凭据正确。' }
Write-Host "  PowerShell Direct 已就绪" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 在 guest 内改配置。这些都只作用于这台一次性测试虚拟机。
# ---------------------------------------------------------------------------
$applied = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $out = [ordered]@{}
    $out.Computer = $env:COMPUTERNAME
    $os = Get-CimInstance Win32_OperatingSystem
    $out.Os = "$($os.Caption) build $($os.BuildNumber)"

    # 备份当前启动项，检查点之外的第二道保险
    $backup = Join-Path $env:SystemRoot 'Temp\bcd-before-ksword.txt'
    & bcdedit.exe '/enum' '{current}' | Out-File $backup -Encoding utf8
    $out.Backup = $backup

    # 测试签名：让 CN=KswordARK Test Signing Certificate 签的驱动能加载
    & bcdedit.exe '/set' 'testsigning' 'on'  | Out-Null
    # 不让 guest 自己的 hypervisor 启动，否则 VT-x 会被它先占住
    & bcdedit.exe '/set' 'hypervisorlaunchtype' 'off' | Out-Null

    # 关 VBS 与 HVCI。UI 路径是"内核隔离 → 内存完整性"，这里直接写注册表。
    $dgRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $dgHvci = Join-Path $dgRoot 'Scenarios\HypervisorEnforcedCodeIntegrity'
    New-Item -Path $dgRoot -Force | Out-Null
    New-Item -Path $dgHvci -Force | Out-Null
    New-ItemProperty -Path $dgRoot -Name 'EnableVirtualizationBasedSecurity' `
        -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $dgHvci -Name 'Enabled' `
        -PropertyType DWord -Value 0 -Force | Out-Null

    $out.Dbg = (& bcdedit.exe '/enum' '{current}' | Out-String)
    $out
}

Write-Host "  guest : $($applied.Computer)  $($applied.Os)"
Write-Host "  已备份启动项到 $($applied.Backup)"

# ---------------------------------------------------------------------------
# 3) 重启 guest
# ---------------------------------------------------------------------------
Write-Host "`n--- 3. 重启 guest 使配置生效 ---" -ForegroundColor Cyan
Invoke-Command -VMName $VMName -Credential $GuestCredential `
    -ScriptBlock { Restart-Computer -Force } -ErrorAction SilentlyContinue
Start-Sleep -Seconds 20

$deadline = (Get-Date).AddMinutes(10)
$back = $false
while ((Get-Date) -lt $deadline) {
    try {
        $null = Invoke-Command -VMName $VMName -Credential $GuestCredential `
                    -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        $back = $true
        break
    } catch { Start-Sleep -Seconds 10 }
}
if (-not $back) { throw '重启后 PowerShell Direct 没回来。到 Hyper-V 管理器里看看 guest 的状态。' }
Write-Host "  guest 已重启并回到可控状态" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4) 回读校验 —— 不要只看"命令没报错"
# ---------------------------------------------------------------------------
Write-Host "`n--- 4. 回读校验 ---" -ForegroundColor Cyan

$state = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $cur = (& bcdedit.exe '/enum' '{current}' | Out-String)
    $dg  = Get-CimInstance -ClassName Win32_DeviceGuard `
             -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    $cs  = Get-CimInstance Win32_ComputerSystem
    [ordered]@{
        TestSigning       = [bool]($cur -match '(?im)^\s*testsigning\s+Yes')
        HypervisorOff     = [bool]($cur -match '(?im)^\s*hypervisorlaunchtype\s+Off')
        VbsStatus         = if ($dg) { [int]$dg.VirtualizationBasedSecurityStatus } else { -1 }
        VbsRunningSvc     = if ($dg) { @($dg.SecurityServicesRunning) -join ',' } else { '' }
        HypervisorPresent = [bool]$cs.HypervisorPresent
        VmxInCpuid        = $null
        Raw               = $cur
    }
}

$allOk = $true
$allOk = (Show-Check 'testsigning = Yes'                     $state.TestSigning)       -and $allOk
$allOk = (Show-Check 'hypervisorlaunchtype = Off'            $state.HypervisorOff)     -and $allOk
$allOk = (Show-Check 'VBS 已关闭（状态 0）'                   ($state.VbsStatus -eq 0)) -and $allOk

Write-Host ""
Write-Host ("  VBS 状态码            : {0}  (0=关 1=已配置未运行 2=正在运行)" -f $state.VbsStatus)
Write-Host ("  仍在运行的安全服务    : {0}" -f $(if ($state.VbsRunningSvc) { $state.VbsRunningSvc } else { '（无）' }))
Write-Host ("  HypervisorPresent     : {0}   <- 这是 CPUID.1:ECX[31]，报的是" -f $state.HypervisorPresent)
Write-Host  "                                     '我上面有 hypervisor'。这台是 L1 虚拟机，"
Write-Host  "                                     上面就是 L0 的 Hyper-V，所以它必然是 True，"
Write-Host  "                                     **不是**故障。它和'guest 内部有没有东西抢 VT-x'"
Write-Host  "                                     是两回事，后者由上面三项判定。"
Write-Host  ""
Write-Host  "  能不能 VMXON 要看 CPUID.1:ECX[5]，用 tools\hvm_probe\hvm_probe.exe 在 guest 内测。" -ForegroundColor Yellow

if ($GrantHyperVAccess) {
    Write-Host "`n--- 附加：把当前用户加入 Hyper-V Administrators ---" -ForegroundColor Cyan
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    try {
        Add-LocalGroupMember -SID 'S-1-5-32-578' -Member $me -ErrorAction Stop
        Write-Host "  已加入 $me。**需要注销重登才生效。**" -ForegroundColor Yellow
    } catch {
        if ("$($_.Exception.Message)" -match '已经|already') { Write-Host "  已经是成员" }
        else { Write-Warning "  加入失败：$($_.Exception.Message)" }
    }
}

if (-not $allOk) {
    throw '有回读校验没通过 —— 不要当成配置成功。上面标 [FAIL] 的项需要处理。'
}

Write-Host @"

全部就绪。这台 L1 虚拟机现在：
  * 能加载测试签名的 KswordARK.sys
  * VT-x/EPT 由 Hyper-V 透传进来，且 guest 内没有别的 hypervisor 抢占

下一步（把驱动送进去）：
    Copy-VMFile -Name '$VMName' -SourcePath '<仓库>\Ksword5.1\x64\Release\KswordARK.sys' ``
                -DestinationPath 'C:\ksword\KswordARK.sys' -CreateFullPath -FileSource Host

回滚：
    Restore-VMCheckpoint -VMName '$VMName' -Name '$snapName' -Confirm:`$false
"@ -ForegroundColor Yellow
