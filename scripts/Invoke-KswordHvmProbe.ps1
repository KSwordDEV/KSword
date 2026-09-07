<#
.SYNOPSIS
    把 CPUID 探针送进 Hyper-V 测试机并运行，回答"KSword HVM 在这台 L1 里能不能 VMXON"。

.DESCRIPTION
    需要管理员（Copy-VMFile 与 PowerShell Direct 都要求），除非当前用户已在
    Hyper-V Administrators 组且已重新登录。

    为什么需要这个探针：Win32_ComputerSystem.HypervisorPresent 读的是 CPUID.1:ECX[31]，
    它只说明"我上面有 hypervisor"。任何虚拟机里这一位都是 1，拿它判断"guest 内部有没有
    东西抢 VT-x"是错的。真正的判据是 CPUID.1:ECX[5]（VMX 是否可见）。

    探针的检查项与驱动里 hvm_evmcs.c 的判定链逐条对应，所以不加载驱动就能预告
    KswordARKHvmEvmcsDiscover 会走到哪一步、为什么停下。

.EXAMPLE
    .\Invoke-KswordHvmProbe.ps1
#>
[CmdletBinding()]
param(
    [string] $VMName = 'KSword-HVM-Target',
    [System.Management.Automation.PSCredential] $GuestCredential,
    [string] $ProbePath = (Join-Path $PSScriptRoot '..\tools\hvm_probe\hvm_probe.exe')
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$ProbePath = (Resolve-Path $ProbePath).Path
if (-not (Test-Path $ProbePath)) { throw "探针不存在：$ProbePath（先编译 tools\hvm_probe\hvm_probe.c）" }

$vm = Get-VM -Name $VMName -ErrorAction Stop
if ($vm.State -ne 'Running') { throw "虚拟机不在运行状态（当前 $($vm.State)）。先 Start-VM。" }

if (-not $GuestCredential) {
    $GuestCredential = Get-Credential -Message "guest 管理员凭据"
}

# Copy-VMFile 依赖"来宾服务接口"集成服务，默认是关的。
$svc = Get-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
if ($svc -and -not $svc.Enabled) {
    Write-Host "启用来宾服务接口（Copy-VMFile 需要）..."
    Enable-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface'
    Start-Sleep -Seconds 3
}

$dest = 'C:\ksword\hvm_probe.exe'
Write-Host "拷贝探针到 guest：$dest"
try {
    Copy-VMFile -Name $VMName -SourcePath $ProbePath -DestinationPath $dest `
                -CreateFullPath -FileSource Host -Force -ErrorAction Stop
} catch {
    # 集成服务不可用时退回 PowerShell Direct 传字节，慢但不依赖来宾服务。
    Write-Warning "Copy-VMFile 失败（$($_.Exception.Message)），改用 PowerShell Direct 传输。"
    $bytes = [IO.File]::ReadAllBytes($ProbePath)
    $b64 = [Convert]::ToBase64String($bytes)
    Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
        param($data, $target)
        New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
        [IO.File]::WriteAllBytes($target, [Convert]::FromBase64String($data))
    } -ArgumentList $b64, $dest
}

Write-Host "`n在 guest 内运行探针：`n"
Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    param($exe)
    & $exe
} -ArgumentList $dest
