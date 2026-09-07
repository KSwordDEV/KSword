<#
.SYNOPSIS
    连上测试机的内核调试器，并自动加载符号、下好常驻路径的断点。

.DESCRIPTION
    前面几轮在手敲 kd 命令上耗掉很多时间，而且断点必须**在挂死之前**下好 ——
    挂死之后 NMI 与 Ctrl+C 都进不去（kd 报 transport connection lost），
    所以"先跑测试再想办法断入"这条路不存在。这个脚本把整套准备一次做完。

    它做的事：
      1. 定位 kd.exe；
      2. 校验命名管道映射与驱动符号文件确实存在；
      3. 用 -c "$$><scripts\kd-ksword-resident.txt" 启动 kd，
         自动加载符号、自检符号、下断点、然后 g 放行。

    kd 会**接管当前控制台**，所以在一个专门的窗口里跑它。

.PARAMETER ScriptFile
    要执行的 kd 脚本。默认 scripts\kd-ksword-resident.txt。

.PARAMETER NoAutoScript
    只连接，不执行任何脚本。手工探索时用。

.EXAMPLE
    .\Start-KswordVmDebugger.ps1
    .\Start-KswordVmDebugger.ps1 -NoAutoScript
#>
[CmdletBinding()]
param(
    [string] $VMName     = 'KSword-HVM-Target',
    [string] $PipeName   = 'KSword-HVM-Target-kd',
    [string] $ScriptFile,
    [switch] $NoAutoScript
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent

# --- kd.exe -----------------------------------------------------------------
$kd = @(
    "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
    "C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $kd) { throw '找不到 kd.exe（需要 WDK 或 Debugging Tools for Windows）。' }
Write-Host ("kd     : {0}" -f $kd) -ForegroundColor DarkGray

# --- 前提校验：宁可现在失败，也别连上之后发现断点不命中 ----------------------
$pdb = Join-Path $repo 'Ksword5.1\x64\Release\KswordARKDriver\KswordARK.pdb'
$sys = Join-Path $repo 'Ksword5.1\x64\Release\KswordARK.sys'
if (-not (Test-Path $pdb)) { throw "缺少驱动符号：$pdb" }
if (-not (Test-Path $sys)) { throw "缺少驱动产物：$sys" }
$pdbTime = (Get-Item $pdb).LastWriteTime
$sysTime = (Get-Item $sys).LastWriteTime
Write-Host ("符号   : {0}  ({1})" -f $pdb, $pdbTime) -ForegroundColor DarkGray
if ([math]::Abs(($pdbTime - $sysTime).TotalMinutes) -gt 5) {
    # 符号与二进制不同期时，断点会下在错误的地址上 —— 那种失败看起来像
    # "断点不命中"，很容易被误读成"代码没走到"。
    Write-Host ("  [警告] .pdb 与 .sys 时间相差 {0:N1} 分钟，可能不是同一次构建。" -f
        ($pdbTime - $sysTime).TotalMinutes) -ForegroundColor Yellow
    Write-Host "         符号对不上时断点会下错地址，表现是'不命中'，别读成'代码没走到'。" -ForegroundColor Yellow
}

# 命名管道映射
try {
    $com = Get-VMComPort -VMName $VMName -Number 1 -ErrorAction Stop
    $want = "\\.\pipe\$PipeName"
    if ($com.Path -ne $want) {
        throw "COM1 当前映射到 '$($com.Path)'，不是 '$want'。先跑 Enable-KswordVmKernelDebug.ps1。"
    }
    Write-Host ("管道   : {0}" -f $com.Path) -ForegroundColor DarkGray
} catch [Microsoft.HyperV.PowerShell.VirtualizationException] {
    throw "查询 COM1 失败（需要管理员）：$($_.Exception.Message)"
}

# --- 组装命令行 -------------------------------------------------------------
$conn = "com:pipe,port=\\.\pipe\$PipeName,resets=0,reconnect"
# 参数是 resets=0,reconnect —— **不是** resync。后者只对真实串口有效，
# 命名管道上会被判非法参数（Win32 error 0n87）。实测踩过。

# -b：连上就请求断入。
# 没有它的话，在**引导期**连上的 kd 会一路跟着目标跑、永远拿不到 kd> 提示符，
# 而 -c 脚本只在第一个提示符处执行 —— 表现就是"连上了但断点一个没下、
# 脚本毫无输出"。实测踩过：先前那次能出提示符只是因为它是主动 break-in 连的。
$kdArgs = @('-b', '-k', $conn)
if (-not $NoAutoScript) {
    if (-not $ScriptFile) { $ScriptFile = Join-Path $PSScriptRoot 'kd-ksword-resident.txt' }
    if (-not (Test-Path $ScriptFile)) { throw "找不到 kd 脚本：$ScriptFile" }
    # 必须是 $$< （逐行执行），**不能**用 $$>< 。
    # $$>< 会把文件里所有换行替换成分号、拼成**一条**命令，而 .sympath+ 后面的
    # 分号是路径分隔符 —— 结果它把后续所有命令都当成路径吞掉，符号路径被污染成
    # 一堆 "Error: ... attempts to access 'bu KswordARK!...' failed"，
    # 一个断点都下不上。实测踩过。
    $kdArgs += @('-c', "`$`$<$ScriptFile")
    Write-Host ("脚本   : {0}" -f $ScriptFile) -ForegroundColor DarkGray
}

Write-Host @"

--- 先开 kd，再启动虚拟机 ---

Hyper-V 的命名管道串口只在虚拟机**初始化 COM 口那一刻**握手。guest 已经跑起来
之后再连，kd 会一直停在 "no_debuggee / Waiting to reconnect"，接不进去。
上一个 kd 断开之后同样需要重启虚拟机才能再接。

所以：让本窗口挂着，到另一个管理员窗口执行

    Restart-VM -Name '$VMName' -Force

kd 会在引导过程中自动接上。（guest 健康时 -Force 只是跳过确认，不是强制断电。）

--- 接上之后的顺序（不能颠倒）---

脚本用的是**延迟断点** bu：驱动服务是 start= demand，连调试器时它还没加载，
普通 bp 会因符号无法解析而下不上。bu 会挂起，等模块加载再解析。
所以 bl 这时显示 "u"（未解析）是**正常的**，不是出错。

放行之后到另一个窗口，按这个顺序：

  1) .\scripts\Deploy-KswordDriverToVm.ps1
     驱动加载时 kd 会因 sxe ld:KswordARK.sys 断一次。断下来敲：
         .reload /f KswordARK.sys
         bl                      <- 断点应该变成已解析（不再是 u）
         g

  2) .\scripts\Invoke-KswordAutomatedAcceptance.ps1 -Stage resident

看 [1][2][3][4] 打到哪一步为止，以及 GuestResume / VmExitEntry 有没有命中。
把 kd 窗口的全部输出贴回来。

"@ -ForegroundColor Cyan

& $kd @kdArgs
