<#
.SYNOPSIS
    把 KswordARK 驱动部署进 Hyper-V 测试机并查询 HVM 能力状态。

.DESCRIPTION
    必须以**管理员**运行（Hyper-V cmdlet 与 PowerShell Direct 都要求）。

    顺序是刻意的：

      1. 先确认 guest 的前提（testsigning / VMX 可见 / 无别的 hypervisor 抢 VT-x）——
         前提不成立就**不加载驱动**，否则只会得到一个看不懂的失败。
      2. 打开 guest 的内核转储（万一蓝屏，那份 dump 就是一份来源明确的真实样本，
         正好给 C 模块用；不开的话蓝屏就只剩一个停止码）。
      3. **加载前打检查点。** 这是 hypervisor 驱动，一个 VMXON 路径上的错误就是蓝屏。
      4. 拷文件 → 建服务 → 启动 → 查设备 → 跑 hvm-status。

    每步都回读校验；前提检查不过就中止而不是硬着头皮往下走。

    脚本**不启动 HVM**（不 VMXON），只加载驱动并读取能力状态。VMXON 是单独一步，
    确认能力报告正常之后再做。

.PARAMETER VMName
    虚拟机名。

.PARAMETER GuestCredential
    guest 内的管理员凭据。不传则交互提示。

.PARAMETER SkipCheckpoint
    跳过加载前的检查点。**不建议**，只在你刚打过检查点时用。

.EXAMPLE
    .\Deploy-KswordDriverToVm.ps1
#>
[CmdletBinding()]
param(
    [string] $VMName = 'KSword-HVM-Target',
    [System.Management.Automation.PSCredential] $GuestCredential,
    # 这台是一次性隔离测试机，按约定写死默认凭据，与同目录其它脚本保持一致，
    # 省掉每次重新部署都要手工敲一遍密码。
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [switch] $SkipCheckpoint
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$repo    = Split-Path $PSScriptRoot -Parent
$sysPath = Join-Path $repo 'Ksword5.1\x64\Release\KswordARK.sys'
$cliPath = Join-Path $repo 'Ksword5.1\x64\Release\KswordCLI.exe'
$prbPath = Join-Path $repo 'tools\hvm_probe\hvm_probe.exe'

foreach ($p in @($sysPath, $cliPath)) {
    if (-not (Test-Path $p)) { throw "缺少产物：$p" }
}

# ---------------------------------------------------------------------------
# 发车前先在宿主上确认 .sys 带签名。
#
# guest 开着 testsigning 也**不等于**放行未签名驱动：内核仍然要求 .sys 至少带
# 测试签名，缺了就是 `sc start` 返回 577。而 577 的文案说的是"数字签名无法验证"，
# 看上去像证书信任问题，实际可能只是根本没签 —— 两者的修法完全不同。
#
# 未签名的常见来源：用 /p:KswordArkSkipAutoVariantSign=true 构建。那个属性同时
# 关掉了 vcxproj 里的测试签名与变体签名两个 target（两个 target 的 Condition 都
# 同时检查 SkipAutoVariantSign 与 SkipAutoTestSign），所以"只是跳过变体签名"
# 这个直觉是错的。
#
# 这里只检查、不自动签名：签名要动证书，属于单独一步。
# ---------------------------------------------------------------------------
$sysSig = Get-AuthenticodeSignature $sysPath
if ($sysSig.Status -eq 'NotSigned') {
    throw @"
$sysPath 未签名，送进 guest 只会得到 sc start 577。
先补签（不改宿主安全配置）：
  .\scripts\Sign-KswordArkDriverTest.ps1 -DriverPath '$sysPath' -SkipMachineTrust
该脚本末尾的 `signtool verify /pa` 退出码 1 是预期的 —— 那是宿主不信任自签根，
与 guest 能否加载无关。只要看到 "Successfully signed" 即可。
"@
}
Write-Host ("驱动签名（宿主侧）：{0} / {1}" -f $sysSig.Status, $sysSig.SignerCertificate.Subject) -ForegroundColor DarkGray

function Show-Check {
    param([string] $Name, [bool] $Ok, [string] $Detail = '')
    if ($Ok) { Write-Host ("  [OK]   " + $Name + $(if ($Detail) { "  $Detail" })) -ForegroundColor Green }
    else     { Write-Host ("  [FAIL] " + $Name + $(if ($Detail) { "  $Detail" })) -ForegroundColor Red }
    return [bool]$Ok
}

# 把一个本地文件送进 guest。Copy-VMFile 需要来宾服务接口，不可用时退回
# PowerShell Direct 传 base64（慢，但不依赖集成服务）。
function Send-ToGuest {
    param([string] $Local, [string] $Remote)
    try {
        Copy-VMFile -Name $VMName -SourcePath $Local -DestinationPath $Remote `
                    -CreateFullPath -FileSource Host -Force -ErrorAction Stop
    } catch {
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Local))
        Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
            param($data, $target)
            New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
            [IO.File]::WriteAllBytes($target, [Convert]::FromBase64String($data))
        } -ArgumentList $b64, $Remote
    }
}

$vm = Get-VM -Name $VMName -ErrorAction Stop
if ($vm.State -ne 'Running') { throw "虚拟机不在运行状态（$($vm.State)）。先 Start-VM。" }
if (-not (Get-VMProcessor -VMName $VMName).ExposeVirtualizationExtensions) {
    throw '嵌套虚拟化没开 —— 关机后 Set-VMProcessor -ExposeVirtualizationExtensions $true'
}
if (-not $GuestCredential) {
    $GuestCredential = New-Object System.Management.Automation.PSCredential(
        $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))
}

# ---------------------------------------------------------------------------
# 1. 前提检查：不成立就不加载
# ---------------------------------------------------------------------------
Write-Host "`n--- 1. guest 前提检查 ---" -ForegroundColor Cyan
$pre = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $cur = (& bcdedit.exe '/enum' '{current}' | Out-String)
    $dg  = Get-CimInstance -ClassName Win32_DeviceGuard `
             -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    [ordered]@{
        TestSigning   = [bool]($cur -match '(?im)^\s*testsigning\s+Yes')
        HypervisorOff = [bool]($cur -match '(?im)^\s*hypervisorlaunchtype\s+Off')
        # 把观测到的值也带回来。检查项的名字是 "hypervisorlaunchtype = Off"，
        # 单看 [FAIL] 那一行会读成"它是 Off 而这算失败"，正好反了。
        HypervisorRaw = $(
            if ($cur -match '(?im)^\s*hypervisorlaunchtype\s+(\S+)') { $Matches[1] }
            else { '(bcdedit 里没有这一行 —— 等于默认值 Auto)' })
        VbsStatus     = if ($dg) { [int]$dg.VirtualizationBasedSecurityStatus } else { -1 }
        Build         = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    }
}
$ok = $true
$ok = (Show-Check 'testsigning = Yes'          $pre.TestSigning)          -and $ok
$ok = (Show-Check 'hypervisorlaunchtype = Off' $pre.HypervisorOff `
            "实际读到：$($pre.HypervisorRaw)")                            -and $ok
$ok = (Show-Check 'VBS 已关闭'                  ($pre.VbsStatus -eq 0) "状态码 $($pre.VbsStatus)") -and $ok
if (-not $ok) {
    $hint = ''
    if (-not $pre.HypervisorOff) {
        # 这一项最常见的成因：guest 里被开了 Hyper-V/VBS/WSL2 之类的东西，
        # 或者某次强制断电之后 BCD 回到了默认。它不是 Off 的话，我们的驱动
        # 会在**两层 hypervisor 之下**跑，整轮读数都不可归因。
        $hint = @"

hypervisorlaunchtype 现在是「$($pre.HypervisorRaw)」，需要 Off。
在 guest 里（管理员）改回去，然后重启 guest：
  bcdedit /set hypervisorlaunchtype off
或者直接跑 .\scripts\Configure-KswordHyperVGuest.ps1（它会一并处理 testsigning 与 VBS）。
"@
    }
    throw "前提不成立 —— 不加载驱动。$hint"
}

# VMX 是否真的可见：用探针，别用 HypervisorPresent（那读的是"上面有没有 hypervisor"）
if (Test-Path $prbPath) {
    Write-Host "`n  CPUID 探针（VMX 是否透传进来）："
    Send-ToGuest $prbPath 'C:\ksword\hvm_probe.exe'
    # 探针用 SetConsoleOutputCP(CP_UTF8) 输出 UTF-8。直接 `& exe | Out-String`
    # 会让 PowerShell 按 guest 的 OEM 代码页解码，中文全变成 σÅ»τö¿ 那种乱码 ——
    # 看起来像编码坏了，其实是解码方式选错了。重定向到文件再按 UTF-8 读回。
    $probe = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
        $o = 'C:\ksword\probe_out.txt'
        Remove-Item $o -ErrorAction SilentlyContinue
        $p = Start-Process -FilePath 'C:\ksword\hvm_probe.exe' -NoNewWindow -Wait -PassThru `
                 -RedirectStandardOutput $o -RedirectStandardError 'C:\ksword\probe_err.txt'
        if (Test-Path $o) {
            [IO.File]::ReadAllText($o, [Text.Encoding]::UTF8)
        } else {
            "（无输出，退出码 $($p.ExitCode)）"
        }
    }
    $vmxOk = [bool]($probe -match 'VMX')
    ($probe -split "`n" | Where-Object { $_ -match '\[OK \]|\[NO \]' }) | ForEach-Object { Write-Host "   $_" }
    if ($probe -match '\[NO \].*ECX\[5\]') {
        # 「看不到 VMX」有两个完全不同的成因，报错必须分开，否则会把人引到
        # 宿主的嵌套虚拟化设置上白折腾一轮。
        #
        # 我们自己的常驻 hypervisor **按设计**会把 CPUID.1:ECX[5] 抹掉
        # （hvm_exit.c 的 CPUID 处理：Nested.Enabled 为假时清 VMX 位）。
        # 所以「VMX 看不见，但 eVMCS/嵌套特性叶又都读得到」这个组合不是
        # 嵌套没开 —— 恰恰相反，那是上一轮的常驻还在跑。
        $nestedLeavesOk = ($probe -match '\[OK \].*eVMCS') -or
                          ($probe -match '\[OK \].*0x4000000A')
        if ($nestedLeavesOk) {
            throw @'
CPUID 看不到 VMX，但嵌套特性叶读得到 —— 这两条只有一种解释：
**上一轮的常驻 hypervisor 还在跑，是它按设计抹掉了 VMX 位。**

先停掉它再部署：
  .\scripts\Invoke-KswordHvmControl.ps1 -Stage stop

（常驻会活过发起它的进程，所以一轮跑到一半失败退出时它不会自己停。）
'@
        }
        throw 'CPUID 里看不到 VMX，且嵌套特性叶也读不到 —— 嵌套虚拟化没生效，不加载驱动。'
    }
}

# ---------------------------------------------------------------------------
# 2. 打开 guest 的内核转储
# ---------------------------------------------------------------------------
Write-Host "`n--- 2. 打开 guest 内核转储 ---" -ForegroundColor Cyan
$dump = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    # 2 = 内核内存转储。够 C 模块用，又比完整转储小得多。
    Set-ItemProperty -Path $cc -Name CrashDumpEnabled -Value 2 -Type DWord
    Set-ItemProperty -Path $cc -Name AutoReboot       -Value 1 -Type DWord
    Set-ItemProperty -Path $cc -Name LogEvent         -Value 1 -Type DWord
    $now = Get-ItemProperty -Path $cc
    [ordered]@{ Enabled = [int]$now.CrashDumpEnabled; File = $now.DumpFile; Auto = [int]$now.AutoReboot }
}
Show-Check '内核转储已启用（CrashDumpEnabled=2）' ($dump.Enabled -eq 2) "-> $($dump.File)" | Out-Null

# ---------------------------------------------------------------------------
# 3. 加载前检查点
# ---------------------------------------------------------------------------
if (-not $SkipCheckpoint) {
    Write-Host "`n--- 3. 加载前检查点 ---" -ForegroundColor Cyan
    $stamp = 'before-driver-load-' + (Get-Date -Format 'MMdd-HHmm')
    Checkpoint-VM -Name $VMName -SnapshotName $stamp
    Write-Host "  已建 '$stamp'" -ForegroundColor Green
    Write-Host "  回滚：Restore-VMCheckpoint -VMName '$VMName' -Name '$stamp' -Confirm:`$false"
} else {
    Write-Host "`n--- 3. 已跳过检查点（-SkipCheckpoint）---" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 4. 送文件、建服务、启动
# ---------------------------------------------------------------------------
Write-Host "`n--- 4. 部署并加载驱动 ---" -ForegroundColor Cyan

# **先卸载再拷贝。** 顺序反过来会在重新部署时撞上
# "The process cannot access the file ... because it is being used by another
# process" —— 已加载的驱动映像是被内核持有的，只要服务还在跑就覆盖不了那个
# .sys。首次部署时文件不存在，所以这个顺序问题只在第二次部署才暴露。
$unload = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $before = (& sc.exe query KswordARK 2>&1 | Out-String)
    $wasPresent = ($before -notmatch '1060')     # 1060 = 服务不存在
    if ($wasPresent) {
        & sc.exe stop   KswordARK 2>&1 | Out-Null
        & sc.exe delete KswordARK 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }
    $after = (& sc.exe query KswordARK 2>&1 | Out-String)
    [ordered]@{
        WasPresent = [bool]$wasPresent
        StillThere = [bool]($after -notmatch '1060')
    }
}
if ($unload.WasPresent) {
    Show-Check '旧驱动已卸载（拷贝前）' (-not $unload.StillThere) | Out-Null
    if ($unload.StillThere) {
        throw '旧驱动仍在运行，无法覆盖 .sys。可能有句柄未释放；重启 guest 后再试。'
    }
} else {
    Write-Host "  [OK]   之前没有已注册的 KswordARK 服务" -ForegroundColor Green
}

Send-ToGuest $sysPath 'C:\Windows\System32\drivers\KswordARK.sys'
Send-ToGuest $cliPath 'C:\ksword\KswordCLI.exe'
Write-Host "  文件已送达"

# 送达之后立刻比对哈希。
#
# 在这之前，整条脚本链里**没有任何一环**能保证 guest 跑的就是刚构建的那份
# 驱动：Copy-VMFile 静默失败、退回 PowerShell Direct 分块传输时截断、或者
# 旧服务其实没卸干净而映像仍被内核持有 —— 三种情况都会让下一轮读数落在
# 一份不知道是哪个版本的驱动上。已经因此浪费过两轮归因。
#
# 哈希打印出来还有第二个用处：在机记录里可以对着它确认"那一轮跑的是哪份"。
$hostHash = (Get-FileHash $sysPath -Algorithm SHA256).Hash
$guestHash = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    (Get-FileHash 'C:\Windows\System32\drivers\KswordARK.sys' -Algorithm SHA256).Hash
}
Write-Host ("  宿主 SHA256 : {0}" -f $hostHash) -ForegroundColor DarkGray
Write-Host ("  guest SHA256: {0}" -f $guestHash) -ForegroundColor DarkGray
if ($hostHash -ne $guestHash) {
    throw @"
送进 guest 的驱动与宿主上的不是同一份 —— 本轮任何读数都不可归因，已中止。
  宿主 : $hostHash
  guest: $guestHash
常见成因：旧服务未真正卸载（映像仍被内核持有，覆盖被静默丢弃）。
处置：重启 guest 后重跑本脚本。
"@
}
Write-Host "  [OK]   哈希一致，guest 上就是刚构建的那份" -ForegroundColor Green

$load = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $out = [ordered]@{}
    $sig = Get-AuthenticodeSignature 'C:\Windows\System32\drivers\KswordARK.sys'
    $out.SigStatus = "$($sig.Status)"
    $out.Signer    = "$($sig.SignerCertificate.Subject)"

    # 已存在就先停再删，保证这次加载的是刚送进来的那个文件
    & sc.exe stop   KswordARK 2>&1 | Out-Null
    & sc.exe delete KswordARK 2>&1 | Out-Null
    Start-Sleep -Seconds 1

    $create = (& sc.exe create KswordARK type= kernel start= demand `
                  binPath= 'C:\Windows\System32\drivers\KswordARK.sys' 2>&1 | Out-String)
    $out.Create = $create.Trim()

    $start = (& sc.exe start KswordARK 2>&1 | Out-String)
    $out.Start = $start.Trim()
    $out.StartExit = $LASTEXITCODE

    $q = (& sc.exe query KswordARK 2>&1 | Out-String)
    $out.Query = $q.Trim()
    $out.Running = [bool]($q -match 'RUNNING')

    # 设备存在才说明 DriverEntry 真的跑完并建了符号链接。
    # 必须用 CreateFileW：.NET 的 [IO.File]::Open 会在类型检查上直接拒绝设备对象
    # （"FileStream was asked to open a device that was not a file"），那条报错
    # 说明的是宿主脚本用错 API，与设备存不存在无关 —— 上一版就是这样报了一个
    # 假的 FAIL。
    $out.DeviceOpen = $false
    try {
        Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KswDev {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share,
        IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);
    public static int Probe(string path) {
        // GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|WRITE, OPEN_EXISTING
        IntPtr h = CreateFileW(path, 0xC0000000u, 3u, IntPtr.Zero, 3u, 0x80u, IntPtr.Zero);
        if (h == new IntPtr(-1)) { return Marshal.GetLastWin32Error(); }
        CloseHandle(h);
        return 0;
    }
}
'@ -ErrorAction SilentlyContinue | Out-Null
        $win32 = [KswDev]::Probe('\\.\KswordARKLog')
        $out.DeviceOpen = ($win32 -eq 0)
        if ($win32 -ne 0) {
            # 2 = 设备名不存在；5 = 存在但拒绝访问。两者含义完全不同。
            $out.DeviceError = "win32=$win32"
        }
    } catch { $out.DeviceError = "$($_.Exception.Message)" }
    $out
}

Write-Host ("  驱动签名 : {0} / {1}" -f $load.SigStatus, $load.Signer)
Write-Host ("  sc create: {0}" -f ($load.Create -replace '\s+', ' '))
Write-Host ("  sc start : {0}" -f ($load.Start  -replace '\s+', ' '))
$loaded = Show-Check '服务处于 RUNNING' $load.Running
$dev    = Show-Check '设备 \\.\KswordARKLog 可打开' $load.DeviceOpen $load.DeviceError

if (-not $loaded) {
    Write-Host "`nsc query 原文：`n$($load.Query)" -ForegroundColor Yellow
    throw '驱动没能进入 RUNNING —— 不要当成加载成功。上面的 sc start 输出是第一手线索。'
}

# ---------------------------------------------------------------------------
# 5. 查询 HVM 能力状态（**不 VMXON**）
# ---------------------------------------------------------------------------
Write-Host "`n--- 5. HVM 能力状态（只读，不启动 HVM）---" -ForegroundColor Cyan
$status = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    & 'C:\ksword\KswordCLI.exe' r0 hvm-status 2>&1 | Out-String
}
Write-Host $status

Write-Host @"
驱动已加载，HVM **尚未启动**（没有 VMXON）。

下一步是单独的一步，确认上面的能力报告正常之后再做：
  * 从 Qt 主程序的内核页启动 HVM，或
  * 用对应的 IOCTL 启动

出了问题回滚：
  Get-VMSnapshot -VMName '$VMName' | Select-Object Name,CreationTime
  Restore-VMCheckpoint -VMName '$VMName' -Name '<检查点名>' -Confirm:`$false

蓝屏的话，转储在 guest 的 $($dump.File)，取出来：
  Copy-VMFile 反向不可用，用 PowerShell Direct 读取，或在 guest 内共享出来。
"@ -ForegroundColor Yellow
