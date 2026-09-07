<#
.SYNOPSIS
    把一台 VMware 虚拟机配成 KSword 的授权测试机：开测试签名 + 网络内核调试（KDNET）。

.DESCRIPTION
    只改这台虚拟机自己的启动配置（BCD），不碰宿主机，不安装任何东西，不加载驱动。
    执行前请确保：
      1. 已经给这台虚拟机打过快照；
      2. 虚拟机固件里 Secure Boot 是关闭的 —— 开着的话 testsigning 会被静默忽略，
         你会得到"命令成功"但驱动依然加载不了的假象。

    改完必须重启才生效。重启后桌面右下角会出现"测试模式 / Test Mode"水印。

.PARAMETER HostIp
    宿主机在 VMware 虚拟网段上的地址。NAT(VMnet8) 默认 192.168.80.1。

.PARAMETER Port
    KDNET 端口。宿主机防火墙需要放行该端口的入站 UDP。

.PARAMETER Key
    KDNET 密钥，四段点分。两侧必须完全一致。

.PARAMETER Revert
    撤销：关掉调试与测试签名，恢复成普通启动。

.EXAMPLE
    # 在虚拟机内，以管理员身份：
    powershell -ExecutionPolicy Bypass -File .\Setup-KswordVmDebugTarget.ps1

.EXAMPLE
    # 撤销
    powershell -ExecutionPolicy Bypass -File .\Setup-KswordVmDebugTarget.ps1 -Revert
#>
[CmdletBinding()]
param(
    [string] $HostIp = '192.168.80.1',
    [int]    $Port   = 50000,
    [string] $Key    = 'ksw.ark.dbg.1',
    [switch] $Revert
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '必须以管理员身份运行。'
    }
}

function Get-SecureBootState {
    # 非 UEFI 机器上 Confirm-SecureBootUEFI 会抛异常，那种情况等价于"没开"。
    try { return [bool](Confirm-SecureBootUEFI) } catch { return $false }
}

Assert-Admin

Write-Host "=== KSword 测试机配置 ===" -ForegroundColor Cyan
Write-Host "计算机名 : $env:COMPUTERNAME"
Write-Host "系统     : $((Get-CimInstance Win32_OperatingSystem).Caption) build $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

if ($Revert) {
    Write-Host "`n--- 撤销模式 ---" -ForegroundColor Yellow
    bcdedit /debug off
    bcdedit /set testsigning off
    Write-Host "`n已关闭调试与测试签名。重启后生效。" -ForegroundColor Yellow
    bcdedit /enum "{current}" | Select-String 'testsigning|debug'
    return
}

# ---------------------------------------------------------------------------
# 1) Secure Boot 必须是关的
# ---------------------------------------------------------------------------
$secureBoot = Get-SecureBootState
Write-Host "`nSecure Boot : $secureBoot" -NoNewline
if ($secureBoot) {
    Write-Host "  <-- 必须先关掉" -ForegroundColor Red
    throw 'Secure Boot 开着时 bcdedit /set testsigning on 会被静默忽略。请先在虚拟机固件里关闭 Secure Boot（VMware：虚拟机设置 → 选项 → 高级 → 取消勾选"启用安全引导"），然后重跑本脚本。'
}
Write-Host "  OK" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2) 备份当前启动项（快照之外的第二道保险）
#    以 SYSTEM 运行时（计划任务提权）Desktop 可能不存在，回退到 Windows\Temp。
# ---------------------------------------------------------------------------
$desktop = [Environment]::GetFolderPath('Desktop')
$backupDir = if ($desktop -and (Test-Path $desktop)) { $desktop } else { Join-Path $env:SystemRoot 'Temp' }
$backup = Join-Path $backupDir 'bcd-before-ksword.txt'
bcdedit /enum "{current}" | Out-File -FilePath $backup -Encoding utf8
bcdedit /dbgsettings   | Out-File -FilePath $backup -Encoding utf8 -Append
Write-Host "已备份当前启动项到 $backup"

# ---------------------------------------------------------------------------
# 3) 网络内核调试（KDNET）
#    e1000e = Intel 82574L，在 KDNET 支持的网卡列表内。
# ---------------------------------------------------------------------------
Write-Host "`n--- 配置 KDNET ---" -ForegroundColor Cyan
Write-Host "hostip=$HostIp port=$Port key=$Key"
& bcdedit /dbgsettings net "hostip:$HostIp" "port:$Port" "key:$Key"
if ($LASTEXITCODE -ne 0) { throw "bcdedit /dbgsettings 失败，退出码 $LASTEXITCODE" }

& bcdedit /debug on
if ($LASTEXITCODE -ne 0) { throw "bcdedit /debug on 失败，退出码 $LASTEXITCODE" }

# ---------------------------------------------------------------------------
# 4) 测试签名 —— 让 CN=KswordARK Test Signing Certificate 签的驱动可以加载
# ---------------------------------------------------------------------------
Write-Host "`n--- 开启测试签名 ---" -ForegroundColor Cyan
& bcdedit /set testsigning on
if ($LASTEXITCODE -ne 0) { throw "bcdedit /set testsigning on 失败，退出码 $LASTEXITCODE" }

# ---------------------------------------------------------------------------
# 5) 回读确认 —— 不要只看"操作成功完成"这句话
# ---------------------------------------------------------------------------
Write-Host "`n--- 回读确认 ---" -ForegroundColor Cyan
$dbg = (bcdedit /dbgsettings | Out-String)
$cur = (bcdedit /enum "{current}" | Out-String)

Write-Host $dbg.Trim()

$checks = @(
    @{ Name = 'debugtype=NET'; Ok = $dbg -match '(?im)^\s*debugtype\s+NET' }
    @{ Name = "hostip=$HostIp"; Ok = $dbg -match [regex]::Escape($HostIp) }
    @{ Name = "port=$Port";     Ok = $dbg -match "(?im)^\s*port\s+$Port" }
    @{ Name = 'key 已设置';      Ok = $dbg -match [regex]::Escape($Key) }
    @{ Name = 'debug=Yes';      Ok = $cur -match '(?im)^\s*debug\s+Yes' }
    @{ Name = 'testsigning=Yes';Ok = $cur -match '(?im)^\s*testsigning\s+Yes' }
)

Write-Host ""
$bad = 0
foreach ($c in $checks) {
    if ($c.Ok) { Write-Host ("  [OK]   " + $c.Name) -ForegroundColor Green }
    else       { Write-Host ("  [FAIL] " + $c.Name) -ForegroundColor Red; $bad++ }
}

if ($bad -gt 0) {
    throw "$bad 项回读校验没通过 —— 不要当成配置成功。"
}

Write-Host "`n全部就绪。现在重启虚拟机：" -ForegroundColor Yellow
Write-Host "    shutdown /r /t 0"
Write-Host "`n重启后应看到桌面右下角出现'测试模式'水印。宿主机侧连接命令：" -ForegroundColor Yellow
Write-Host "    windbg.exe -k net:port=$Port,key=$Key"
