<#
.SYNOPSIS
    诊断已加载的 KswordARK 驱动：设备是否真的可打开、CLI 能否通讯、HVM 能力状态。

.DESCRIPTION
    必须以**管理员**运行。

    两处与上一版的区别（上一版这两处都是我用错了方法，不是驱动的问题）：

      * 设备检查改用 **CreateFileW**。.NET 的 [IO.File]::Open 打不开设备对象，
        它自己会报 "FileStream was asked to open a device that was not a file"。
        那条报错说明的是宿主脚本用错 API，不是 \\.\KswordARKLog 不存在。

      * 原生 exe 的输出改为**在 guest 内重定向到文件再读回**。
        `& exe | Out-String` 穿过 PowerShell Direct 时，原生进程的 stdout/stderr
        会被吞掉，看到的是一片空白 —— 那不代表命令没输出。

.PARAMETER GuestPassword
    guest 管理员密码。这台是一次性的隔离测试机，按约定写死默认值以省去每次提示。

.EXAMPLE
    .\Test-KswordDriverInVm.ps1
#>
[CmdletBinding()]
param(
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [string[]] $CliCommands = @('r0 hvm-status', 'r0 capabilities', 'help')
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$cred = New-Object System.Management.Automation.PSCredential(
    $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

function Invoke-Guest {
    # 注意：参数名不能叫 $Args —— 那是 PowerShell 的自动变量，会和内置的冲突，
    # 表现是 -ArgumentList 收到空值而报 "argument is null or empty"。
    param([scriptblock] $Script, [object[]] $ScriptArgs)
    if ($null -eq $ScriptArgs -or $ScriptArgs.Count -eq 0) {
        # -ArgumentList 不接受空数组，所以无参时干脆不传这个参数。
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script
    } else {
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script -ArgumentList $ScriptArgs
    }
}

Write-Host "=== 1. 服务与设备 ===" -ForegroundColor Cyan

$svc = Invoke-Guest {
    $q = (& sc.exe query KswordARK 2>&1 | Out-String)
    $c = (& sc.exe qc    KswordARK 2>&1 | Out-String)
    [ordered]@{ Running = [bool]($q -match 'RUNNING'); Query = $q.Trim(); Config = $c.Trim() }
}
Write-Host ("  服务 RUNNING : {0}" -f $svc.Running)

# 用 CreateFileW 开设备。这是唯一正确的做法 —— 设备对象不是文件，
# .NET 的文件 API 会在类型检查上直接拒绝，跟设备存不存在无关。
$dev = Invoke-Guest {
    $sig = @'
using System;
using System.Runtime.InteropServices;
public static class Dev {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share,
        IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);
    public static string Probe(string path) {
        // GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|WRITE, OPEN_EXISTING
        IntPtr h = CreateFileW(path, 0xC0000000u, 3u, IntPtr.Zero, 3u, 0x80u, IntPtr.Zero);
        if (h == new IntPtr(-1)) {
            return "FAIL win32=" + Marshal.GetLastWin32Error();
        }
        CloseHandle(h);
        return "OK";
    }
}
'@
    Add-Type -TypeDefinition $sig -Language CSharp | Out-Null
    [ordered]@{
        Log = [Dev]::Probe('\\.\KswordARKLog')
    }
}
Write-Host ("  \\.\KswordARKLog : {0}" -f $dev.Log)
if ($dev.Log -ne 'OK') {
    Write-Host "  （win32=2 表示设备名不存在；win32=5 表示存在但拒绝访问 —— 两者含义完全不同）" -ForegroundColor Yellow
}

Write-Host "`n=== 1b. CLI 运行库 ===" -ForegroundColor Cyan
# KswordCLI.exe 是动态链接 CRT 的（dumpbin 显示依赖 MSVCP140 / VCRUNTIME140 /
# VCRUNTIME140_1），而全新安装的 Windows 没有 VC++ 运行库。缺了的表现是进程
# 根本起不来、退出码 0xC0000135 (STATUS_DLL_NOT_FOUND)，stdout/stderr 全空 ——
# 看上去像"命令没输出"，其实是 exe 没跑起来。
$crtNames = @('MSVCP140.dll', 'VCRUNTIME140.dll', 'VCRUNTIME140_1.dll')

foreach ($dll in $crtNames) {
    # 直接取宿主 System32 里的那份 —— 它就是 VC++ 可再发行组件装上去的同一个文件，
    # 版本与本机编译器一致。放到 exe 同目录即可：应用程序目录先于 System32 被搜索。
    $src = Join-Path $env:SystemRoot ('System32\' + $dll)
    if (-not (Test-Path $src)) { Write-Host "  [FAIL] 宿主上找不到 $dll" -ForegroundColor Red; continue }
    $already = Invoke-Guest { param($n) Test-Path "C:\ksword\$n" } -ScriptArgs @($dll)
    if ($already) { Write-Host "  [OK]   $dll 已在 guest" -ForegroundColor Green; continue }
    try {
        Copy-VMFile -Name $VMName -SourcePath $src -DestinationPath "C:\ksword\$dll" `
                    -CreateFullPath -FileSource Host -Force -ErrorAction Stop
    } catch {
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($src))
        Invoke-Guest {
            param($data, $target)
            New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
            [IO.File]::WriteAllBytes($target, [Convert]::FromBase64String($data))
        } -ScriptArgs @($b64, "C:\ksword\$dll")
    }
    Write-Host ("  [OK]   已送 {0}（宿主 System32）" -f $dll) -ForegroundColor Green
}

Write-Host "`n=== 2. CLI 通讯 ===" -ForegroundColor Cyan
Write-Host "  （原生 exe 的输出在 guest 内重定向到文件再读回，避免被 PowerShell Direct 吞掉）"

foreach ($cmd in $CliCommands) {
    Write-Host "`n  --- KswordCLI.exe $cmd ---" -ForegroundColor Cyan
    $r = Invoke-Guest {
        param($arguments)
        $exe = 'C:\ksword\KswordCLI.exe'
        if (-not (Test-Path $exe)) { return [ordered]@{ Missing = $true } }
        $o = 'C:\ksword\out.txt'
        $e = 'C:\ksword\err.txt'
        Remove-Item $o, $e -ErrorAction SilentlyContinue
        $split = $arguments -split ' '
        $p = Start-Process -FilePath $exe -ArgumentList $split -NoNewWindow -Wait -PassThru `
                 -RedirectStandardOutput $o -RedirectStandardError $e
        [ordered]@{
            Missing = $false
            Exit    = $p.ExitCode
            Out     = if (Test-Path $o) { Get-Content $o -Raw -Encoding UTF8 } else { '' }
            Err     = if (Test-Path $e) { Get-Content $e -Raw -Encoding UTF8 } else { '' }
        }
    } -ScriptArgs @($cmd)

    if ($r.Missing) { Write-Host "  CLI 不在 C:\ksword\KswordCLI.exe" -ForegroundColor Red; continue }
    Write-Host ("  退出码 : {0}" -f $r.Exit)
    if ($r.Out) { Write-Host "  --- stdout ---"; Write-Host $r.Out }
    if ($r.Err) { Write-Host "  --- stderr ---" -ForegroundColor Yellow; Write-Host $r.Err }
    if (-not $r.Out -and -not $r.Err) { Write-Host "  （两个流都为空）" -ForegroundColor Yellow }
}

Write-Host "`n=== 3. 驱动侧事件日志（若有）===" -ForegroundColor Cyan
$evt = Invoke-Guest {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddMinutes(-30) } `
        -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match 'Ksword|KswordARK' } |
      Select-Object -First 10 TimeCreated, Id, LevelDisplayName,
                    @{ n = 'Msg'; e = { ($_.Message -split "`n")[0] } }
}
if ($evt) { $evt | Format-Table -AutoSize } else { Write-Host "  （最近 30 分钟无 Ksword 相关系统事件）" }
